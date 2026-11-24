"""Offline test of the E4 Claude adapter (no API calls, no cost). 2026-11-18.
A local fake Messages endpoint records every request. Checks:
  1. request shape: model, system, single user message, temperature 0, max_tokens 4096, no thinking / top_p / tools;
  2. IRIS's real prompts → stage names in the log; batch mode (thread_map, 3 workers) returns answers in order;
  3. per-call log fields, usage and cost; json_parse_ok true for JSON and fenced JSON, false for prose;
  4. API error (HTTP 500 after the SDK's retries) is logged with an error and re-raised;
  5. budget guard raises E4BudgetExceeded once the logged spend reaches the cap, also after a restart.
Usage: ../venv/bin/python adapter/test_offline.py   (from iris/)"""
import json, os, sys, tempfile, threading, types
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
IRIS_SRC = os.path.join(HERE, "..", "src", "src")
REQS, MODE = [], {"reply": "json", "fail": False}


class Fake(BaseHTTPRequestHandler):
  def log_message(self, *a): pass

  def do_POST(self):
    body = json.loads(self.rfile.read(int(self.headers["content-length"])))
    REQS.append(body)
    if MODE["fail"]:
      self.send_response(500); self.send_header("content-type", "application/json"); self.end_headers()
      self.wfile.write(b'{"type":"error","error":{"type":"api_error","message":"boom"}}'); return
    user = body["messages"][0]["content"]
    text = {"json": '[{"package":"java.io","class":"File","method":"<init>","type":"sink"}]',
            "fenced": '```json\n{"is_vulnerable": false}\n```', "prose": "I think this is a sink."}[MODE["reply"]]
    text = text if "ECHO" not in user else user[-12:]
    out = {"id": "msg_fake", "type": "message", "role": "assistant", "model": body["model"],
           "content": [{"type": "text", "text": text}], "stop_reason": "end_turn", "stop_sequence": None,
           "usage": {"input_tokens": 1000, "output_tokens": 200, "cache_creation_input_tokens": 0,
                     "cache_read_input_tokens": 0}}
    self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers()
    self.wfile.write(json.dumps(out).encode())


def main():
  srv = HTTPServer(("127.0.0.1", 0), Fake)
  threading.Thread(target=srv.serve_forever, daemon=True).start()
  tmp = tempfile.mkdtemp()
  os.environ.update(E4_ANTHROPIC_BASE_URL=f"http://127.0.0.1:{srv.server_port}", ANTHROPIC_API_KEY="test-key",
                    E4_LLM_LOG=os.path.join(tmp, "calls.jsonl"), E4_BUDGET_USD="0.02",
                    E4_PROJECT="demo__proj_1.0", E4_CVE="CVE-0000-0001", E4_CWE="022")
  # IRIS's models.llm imports torch/transformers at module level; the adapter only needs the LLM base class.
  stub = types.ModuleType("models.llm"); stub.LLM = type("LLM", (), {})
  sys.modules["models"] = types.ModuleType("models"); sys.modules["models.llm"] = stub
  sys.path.insert(0, IRIS_SRC)          # real IRIS prompts module
  sys.path.insert(0, HERE)
  import prompts as P
  import claude as C

  m = C.ClaudeModel("claude-sonnet-4-6", None)
  ok = lambda c, msg: print(("PASS " if c else "FAIL ") + msg) or c
  res = []

  # 1-3: one call per IRIS stage
  for sysname in ("API_LABELLING_SYSTEM_PROMPT", "FUNC_PARAM_LABELLING_SYSTEM_PROMPT", "POSTHOC_FILTER_SYSTEM_PROMPT"):
    m.predict([{"role": "system", "content": getattr(P, sysname)}, {"role": "user", "content": "x"}])
  r = REQS[0]
  res.append(ok(r["model"] == "claude-sonnet-4-6" and r["temperature"] == 0 and r["max_tokens"] == 4096
                and r["system"] == P.API_LABELLING_SYSTEM_PROMPT and r["messages"] == [{"role": "user", "content": "x"}],
                "request: model, system, one user message, T=0, max_tokens 4096"))
  res.append(ok(not any(k in r for k in ("thinking", "top_p", "top_k", "tools", "stop_sequences")),
                f"request has no thinking/top_p/top_k/tools/stop (keys: {sorted(r)})"))
  log = [json.loads(l) for l in open(os.environ["E4_LLM_LOG"])]
  res.append(ok([x["stage"] for x in log] == ["external_api_labelling", "internal_func_labelling", "contextual_filtering"],
                "stage names from IRIS prompts"))
  x = log[0]
  res.append(ok(x["usage"]["input_tokens"] == 1000 and abs(x["cost_usd"] - 0.006) < 1e-9 and x["project"] == "demo__proj_1.0"
                and x["cve"] == "CVE-0000-0001" and x["json_parse_ok"] and x["response_id"] == "msg_fake"
                and x["sdk_version"] and x["error"] is None, "log fields, usage, cost ($0.006 = 1000 in + 200 out)"))

  # batch mode keeps order
  m.budget = 100
  outs = m.predict([[{"role": "system", "content": "s"}, {"role": "user", "content": f"ECHO item-{i:06d}"}] for i in range(9)],
                   batch_size=3, no_progress_bar=True)
  res.append(ok(outs == [f"ECHO item-{i:06d}"[-12:] for i in range(9)], "batch mode (3 threads) returns answers in order"))

  # json_parse_ok on fenced JSON and prose
  MODE["reply"] = "fenced"; m.predict([{"role": "system", "content": "s"}, {"role": "user", "content": "y"}])
  MODE["reply"] = "prose"; m.predict([{"role": "system", "content": "s"}, {"role": "user", "content": "y"}])
  log = [json.loads(l) for l in open(os.environ["E4_LLM_LOG"])]
  res.append(ok(log[-2]["json_parse_ok"] is True and log[-1]["json_parse_ok"] is False, "json_parse_ok: fenced True, prose False"))

  # 4: API error logged and raised
  MODE["fail"] = True; m.client = m.client.with_options(max_retries=1)
  try:
    m.predict([{"role": "system", "content": "s"}, {"role": "user", "content": "z"}]); raised = False
  except Exception as e:
    raised = "InternalServerError" in type(e).__name__ or "500" in str(e)
  last = json.loads(open(os.environ["E4_LLM_LOG"]).read().splitlines()[-1])
  res.append(ok(raised and last["error"] and last["cost_usd"] == 0.0, f"HTTP 500 logged and re-raised ({last['error'][:40]})"))
  MODE["fail"] = False

  # 5: budget guard, also after restart (spend rebuilt from the log)
  spent = sum(json.loads(l)["cost_usd"] for l in open(os.environ["E4_LLM_LOG"]))
  m2 = C.ClaudeModel("claude-sonnet-4-6", None)          # cap $0.02 from env, log already holds `spent`
  res.append(ok(abs(m2._spent - spent) < 1e-9, f"restart rebuilds spend from the log (${spent:.3f})"))
  n_before = len(REQS)
  try:
    m2.predict([{"role": "system", "content": "s"}, {"role": "user", "content": "q"}]); stopped = False
  except C.E4BudgetExceeded:
    stopped = True
  res.append(ok(stopped and len(REQS) == n_before, "budget guard stops before sending a request"))
  srv.shutdown()
  print(f"\n{sum(res)}/{len(res)} passed")
  sys.exit(0 if all(res) else 1)


if __name__ == "__main__":
  main()
