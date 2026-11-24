"""E4 adapter: Claude Sonnet 4.6 for IRIS v1 (iris-sast/iris @ 67140e8), written 2026-11-18.

Drop-in sibling of IRIS's src/models/gpt.py: same predict()/_predict() interface, same call shape (one system + one user
message), same sampling as IRIS's GPT-4 setting where the Claude API allows it:
  temperature 0 (GPT: 0), max_tokens 4096 (GPT: 4096), n = 1 (implicit), no seed (Claude API has none),
  no response_format (IRIS only passes expect_json=True to GPTModel instances; other models get plain predict()).
Thinking is not requested. Official `anthropic` SDK, default retry policy (2 retries, as the OpenAI client).

Per call it appends one JSON line to $E4_LLM_LOG (default e4_llm_calls.jsonl) and enforces a hard budget
($E4_BUDGET_USD, default 15): before each call the logged cost is summed, and at or above the cap it raises
E4BudgetExceeded. Restart-safe: the running total is rebuilt from the log at start-up.
Project context for the log comes from env vars set by the runner: E4_PROJECT, E4_CVE, E4_CWE.
"""
import json
import os
import threading
import time
from datetime import datetime, timezone

import anthropic
from tqdm.contrib.concurrent import thread_map

try:                                   # IRIS imports models both as `models.*` and `src.models.*`
    from models.llm import LLM
except ImportError:                    # pragma: no cover
    from src.models.llm import LLM

_model_name_map = {"claude-sonnet-4-6": "claude-sonnet-4-6"}
_CLAUDE_DEFAULT_PARAMS = {"temperature": 0, "max_tokens": 4096}
# USD per million tokens, Claude API list price (checked 2026-11-18; reconfirm on the run day). Cache multipliers unused
# (no cache_control is sent), kept for completeness.
E4_PRICES = {"claude-sonnet-4-6": {"input": 3.0, "output": 15.0, "cache_write": 3.75, "cache_read": 0.30}}


class E4BudgetExceeded(RuntimeError):
  pass


def _stage_of(system_prompt):
  """Name the IRIS stage from its system prompt (exact match against IRIS's prompts module)."""
  try:
    try:
      import prompts as P
    except ImportError:
      import src.prompts as P
    for name in ("API_LABELLING_SYSTEM_PROMPT", "FUNC_PARAM_LABELLING_SYSTEM_PROMPT", "POSTHOC_FILTER_SYSTEM_PROMPT"):
      if system_prompt == getattr(P, name, None):
        return {"API_LABELLING_SYSTEM_PROMPT": "external_api_labelling",
                "FUNC_PARAM_LABELLING_SYSTEM_PROMPT": "internal_func_labelling",
                "POSTHOC_FILTER_SYSTEM_PROMPT": "contextual_filtering"}[name]
  except Exception:
    pass
  return "other"


def _json_ok(text):
  t = (text or "").strip()
  if t.startswith("```"):
    t = t.split("\n", 1)[1] if "\n" in t else ""
    t = t.rsplit("```", 1)[0]
  try:
    json.loads(t)
    return True
  except Exception:
    return False


def _cost(model, u):
  p = E4_PRICES[model]
  return (u.get("input_tokens", 0) * p["input"] + u.get("output_tokens", 0) * p["output"]
          + u.get("cache_creation_input_tokens", 0) * p["cache_write"]
          + u.get("cache_read_input_tokens", 0) * p["cache_read"]) / 1e6


class ClaudeModel(LLM):
  """Does not call LLM.__init__ (that would load a Hugging Face model); sets the same attributes instead."""

  def __init__(self, model_name, logger=None, **kwargs):
    self.log = (lambda x: print(x)) if logger is None else (lambda x: logger.log(x))
    if model_name.lower() not in _model_name_map:
      self.log(">>>Model not found:" + model_name); self.log(list(_model_name_map)); exit(1)
    self.model_name, self.model_id, self.kwargs = model_name, _model_name_map[model_name.lower()], kwargs
    self.model_name_map = _model_name_map
    self.params = dict(_CLAUDE_DEFAULT_PARAMS)
    for k in self.params:
      if k in kwargs:
        self.params[k] = kwargs[k]
    self.model_hyperparams = dict(self.params)
    api_key = kwargs.get("anthropic_api_key") or os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")
    self.client = anthropic.Anthropic(api_key=api_key, base_url=os.getenv("E4_ANTHROPIC_BASE_URL") or None)
    self.logprobs = None
    self.log_path = os.getenv("E4_LLM_LOG", "e4_llm_calls.jsonl")
    self.budget = float(os.getenv("E4_BUDGET_USD", "15"))
    self._lock = threading.Lock()
    self._spent = 0.0
    if os.path.exists(self.log_path):
      for line in open(self.log_path):
        try:
          self._spent += json.loads(line).get("cost_usd", 0.0)
        except Exception:
          pass

  def predict(self, prompt, expect_json=False, batch_size=0, no_progress_bar=False):
    if batch_size == 0:
      return self._predict(prompt, expect_json)
    return thread_map(lambda x: self._predict(prompt[x], expect_json), range(0, len(prompt)),
                      max_workers=batch_size, disable=no_progress_bar)

  def _predict(self, main_prompt, expect_json=False):
    system_prompt, user_prompt = main_prompt[0]["content"], main_prompt[1]["content"]   # as gpt.py: 0 system, 1 user
    with self._lock:
      if self._spent >= self.budget:
        raise E4BudgetExceeded(f"E4 budget reached: ${self._spent:.2f} >= ${self.budget:.2f}")
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "project": os.getenv("E4_PROJECT"),
           "cve": os.getenv("E4_CVE"), "cwe": os.getenv("E4_CWE"), "stage": _stage_of(system_prompt),
           "model": self.model_id, "temperature": self.params["temperature"], "max_tokens": self.params["max_tokens"],
           "expect_json_requested": bool(expect_json), "sdk_version": anthropic.__version__,
           "user_prompt_chars": len(user_prompt), "system_prompt_chars": len(system_prompt)}
    t0 = time.time()
    try:
      resp = self.client.messages.create(model=self.model_id, max_tokens=self.params["max_tokens"],
                                         temperature=self.params["temperature"], system=system_prompt,
                                         messages=[{"role": "user", "content": user_prompt}])
    except Exception as e:
      rec.update(latency_ms=int((time.time() - t0) * 1000), error=f"{type(e).__name__}: {str(e)[:300]}", cost_usd=0.0)
      self._write(rec)
      raise
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    u = {k: (getattr(resp.usage, k, 0) or 0) for k in
         ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")}
    rec.update(latency_ms=int((time.time() - t0) * 1000), usage=u, stop_reason=resp.stop_reason, response_id=resp.id,
               request_id=getattr(resp, "_request_id", None), json_parse_ok=_json_ok(text), output_chars=len(text),
               cost_usd=round(_cost(self.model_id, u), 6), error=None)
    self._write(rec)
    return text

  def _write(self, rec):
    with self._lock:
      self._spent += rec.get("cost_usd", 0.0)
      rec["spent_usd_after"] = round(self._spent, 6)
      with open(self.log_path, "a") as f:
        f.write(json.dumps(rec) + "\n")
