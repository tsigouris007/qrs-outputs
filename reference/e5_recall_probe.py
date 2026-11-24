#!/usr/bin/env python3
"""E5 recall probe v2 (contamination control), created 2026-11-22. Binary design (user decision, same day): for each
model x each of the 8 Top100 CVEs, ONE call, no code, no tools, no system prompt, provider-default temperature:

  "Do you know the security vulnerability <CVE id>? Answer with exactly one word: yes or no."

Recorded answer per (CVE, model): yes / no, or `unclear` (anything else; raw reply kept) / `empty` (no text).
The 4 acknowledged issues are not probed: they have no CVE id and were mostly documentation fixes (user).
In the paper, each E5 detection of a CVE is then marked "known before" if that model answered yes. The Dec 2025 models
still served (Sonnet 4.5 until 2026-11-30, Haiku 4.5, gpt-5.1, gpt-4.1) are the baseline: they predate the 2026 CVEs,
so their "yes" rate shows how often a model says yes to an id it cannot know.
Supersedes e5_recall_probe_v1_open.py (open question per package; too long and costly for the benefit).

Not run by verify.py (paid API calls). Usage (artifact root, LiteLLM and provider keys in .env):
  python3 reference/e5_recall_probe.py --models deepseek/deepseek-v4-pro deepseek/deepseek-flash
Output: data/reference_outputs/e5_recall_probe.json (raw replies + answers, accumulated per model). The CVE ids below are
masked in this release (CVE-ID-1..8); the probe was run with the real ids.
"""
import argparse, json, os, re, sys, time
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT_J = os.path.join(ROOT, "data/reference_outputs/e5_recall_probe.json")

PROMPT = "Do you know the security vulnerability {cve}? Answer with exactly one word: yes or no."
# 32000: thinking models spend their reasoning inside max_tokens (v1: 8000 ran out on 4/10 DeepSeek V4 Pro replies).
MAX_TOKENS = 32000
CVES = [  # (CVE id, scanned package) -- data/ground_truth/top100_issues.json
  ("CVE-ID-1", "filelock-3.20.0"), ("CVE-ID-2", "filelock-3.20.0"),
  ("CVE-ID-3", "virtualenv-20.35.4"), ("CVE-ID-4", "setuptools-80.9.0"),
  ("CVE-ID-5", "pyasn1-0.6.1"), ("CVE-ID-6", "aiohttp-3.13.2"),
  ("CVE-ID-7", "python_dotenv-1.2.1"), ("CVE-ID-8", "click-8.3.0"),
]


def answer_of(text):
  t = re.sub(r"[^a-z ]", " ", (text or "").lower()).split()
  if not t:
    return "empty"
  return t[0] if t[0] in ("yes", "no") and len(t) <= 3 else "unclear"


def call(model, cve):
  """One call through LiteLLM (the run used the pipeline's LiteLLM wrapper with prompt caching off)."""
  import litellm
  t0 = time.time()
  r = litellm.completion(model=model, messages=[{"role": "user", "content": PROMPT.format(cve=cve)}], max_tokens=MAX_TOKENS)
  u = getattr(r, "usage", None)
  reply = (r.choices[0].message.content or "").strip()
  return {"cve": cve, "prompt": PROMPT.format(cve=cve), "reply": reply, "answer": answer_of(reply),
          "input_tokens": getattr(u, "prompt_tokens", None), "output_tokens": getattr(u, "completion_tokens", None),
          "seconds": round(time.time() - t0, 1), "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--models", nargs="*", default=[])
  a = ap.parse_args()
  data = json.load(open(OUT_J)) if os.path.exists(OUT_J) else {"prompt": PROMPT, "max_tokens": MAX_TOKENS, "models": {}}
  if a.models:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT, ".env"))
    for model in a.models:
      m = data["models"].setdefault(model, {"answers": {}})
      for cve, _pkg in CVES:
        if cve in m["answers"]:
          continue
        r = call(model, cve)
        m["answers"][cve] = r
        json.dump(data, open(OUT_J, "w"), indent=1)   # saved after every call
        print(f"{model} {cve}: {r['answer']} ({r['output_tokens']} out tok, {r['seconds']} s)", flush=True)
  for model, m in data["models"].items():
    print(model, {c: x["answer"] for c, x in m["answers"].items()})


if __name__ == "__main__":
  main()
