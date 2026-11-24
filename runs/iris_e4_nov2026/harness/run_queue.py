#!/usr/bin/env python3
"""E4 queue runner (2026-11-20): IRIS v1 + Claude Sonnet 4.6 on CWE-Bench-Java, one project at a time, inside iris-e4:v1.

Run in the container through e4_entry.sh (the proxy trust, conda env, CodeQL on PATH):
  python3 /e4bin/run_queue.py --queue /e4/queue.txt          # lines: <project_slug>,<CWE-0XX>,<CVE>
  python3 /e4bin/run_queue.py --summarize-only <slug>,<CWE>,<CVE>   # (re)build one project's summary
Per project (IRIS README steps, IRIS defaults: seed 1234, batches 30/20, 3 threads):
  1. fetch_build  data/cwe-bench-java/scripts/setup.py --filter <slug>
  2. codeql_db    scripts/build_codeql_dbs.py --project <slug>
  3. iris         src/neusym_vul.py --query cwe-XXXwLLM --run-id e4 --llm claude-sonnet-4-6 <slug>
Each stage runs under a small wrapper that records wall time, CPU time and peak RSS of the stage's process tree.
Summary per project: /e4/projects/<slug>.json, also appended to /e4/e4_projects.jsonl. Restart-safe: projects with an
"ok" summary are skipped. Stops the queue when the adapter's budget guard fires, or before the next project if /e4/STOP exists; /e4/budget_usd
(if present) overrides E4_BUDGET_USD per project. If free disk < E4_MIN_FREE_GB (default
30) after a successful project, its CodeQL DB is deleted (reproducible; outputs are kept) and the summary says so.
"""
import argparse
import glob
import json
import os
import re
import resource
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

E4, IRIS = "/e4", "/iris"
CB = f"{IRIS}/data/cwe-bench-java"
RUN_ID, LLM = "e4", "claude-sonnet-4-6"
PLAN = {}  # second pass (2026-11-21): --plan /e4/second_pass/plan.json; per-project fixes, all disclosed in iris/README


def apply_bench_rows(spec):
  """Append the plan's benchmark rows (698fb72 rows, xstream fix_info alias) to the container-local CSVs, once."""
  for name, files in spec.items():
    dst = f"{CB}/data/{name}.csv"
    have = set(open(dst).read().splitlines())
    add = [l for f in files for l in open(f).read().splitlines() if l.strip() and l not in have]
    if add:
      body = open(dst).read()
      with open(dst, "a") as out:
        out.write(("" if body.endswith("\n") else "\n") + "\n".join(add) + "\n")
    print(f"[run_queue] {now()} bench_rows {name}: +{len(add)} rows", flush=True)


def now():
  return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stage_wrap(out_json, log_path, cmd):
  """Child-process mode: run cmd, write wall/CPU/peak-RSS of its process tree to out_json, exit with its rc."""
  t0 = time.time()
  with open(log_path, "w") as log:
    rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT).returncode
  ru = resource.getrusage(resource.RUSAGE_CHILDREN)
  json.dump({"rc": rc, "seconds": round(time.time() - t0, 1), "cpu_user_s": round(ru.ru_utime, 1),
             "cpu_sys_s": round(ru.ru_stime, 1), "max_rss_mb": round(ru.ru_maxrss / 1024, 1)}, open(out_json, "w"))
  sys.exit(rc)


def run_stage(slug, name, cmd, env):
  d = f"{E4}/{slug}"
  os.makedirs(d, exist_ok=True)
  out = f"{d}/{name}.metrics.json"
  print(f"[run_queue] {now()} {slug}: {name} ...", flush=True)
  subprocess.run([sys.executable, __file__, "--stage-wrap", out, f"{d}/{name}.log", "--"] + cmd, cwd=IRIS, env=env)
  m = json.load(open(out)) if os.path.exists(out) else {"rc": -1}
  with open(f"{E4}/runs.jsonl", "a") as f:
    f.write(json.dumps({"ts": now(), "project": slug, "stage": name, **m}) + "\n")
  print(f"[run_queue] {now()} {slug}: {name} rc={m.get('rc')} {m.get('seconds')} s, peak {m.get('max_rss_mb')} MB",
        flush=True)
  return m


def du_bytes(path):
  if not os.path.exists(path):
    return None
  try:
    return int(subprocess.run(["du", "-sb", path], capture_output=True, text=True).stdout.split()[0])
  except Exception:
    return None


def java_stats(src):
  n = loc = 0
  for root, _, files in os.walk(src):
    if "/.git" in root:
      continue
    for fn in files:
      if fn.endswith(".java"):
        n += 1
        try:
          with open(os.path.join(root, fn), "rb") as fh:
            loc += sum(1 for _ in fh)
        except Exception:
          pass
  return n, loc


def iris_log_metrics(slug):
  logs = sorted(glob.glob(f"{IRIS}/output/{slug}/{RUN_ID}/log/log*.txt"))
  if not logs:
    return {}
  txt = open(logs[-1], errors="ignore").read()
  ts = [(int(n), datetime.strptime(t, "%Y-%m-%d %H:%M:%S"))
        for t, n in re.findall(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\] ==> Stage (\d+):", txt)]
  end = re.findall(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]", txt)
  end_t = datetime.strptime(end[-1], "%Y-%m-%d %H:%M:%S") if end else None
  stages = {}
  for i, (n, t) in enumerate(ts):
    t_next = ts[i + 1][1] if i + 1 < len(ts) else end_t
    stages[f"stage{n}"] = (t_next - t).total_seconds() if t_next else None
  m = re.search(r"#Candidates: (\d+), #To Query APIs: (\d+), #Cached: (\d+)", txt)
  return {"log_file": os.path.basename(logs[-1]), "stage_seconds": stages,
          "api_label_cache": dict(zip(("candidates", "to_query", "cached"), map(int, m.groups()))) if m else None,
          "budget_exceeded": "E4BudgetExceeded" in txt or "E4 budget reached" in txt}


def llm_metrics(slug):
  calls = []
  for f in sorted(glob.glob(f"{E4}/e4_llm_calls*.jsonl")):
    for line in open(f):
      try:
        c = json.loads(line)
      except Exception:
        continue
      if c.get("project") == slug:
        calls.append(c)

  def agg(cs):
    lat = [c["latency_ms"] for c in cs if c.get("latency_ms") is not None]
    u = lambda k: sum((c.get("usage") or {}).get(k, 0) for c in cs)
    return {"calls": len(cs), "input_tokens": u("input_tokens"), "output_tokens": u("output_tokens"),
            "cache_read_tokens": u("cache_read_input_tokens"), "cache_write_tokens": u("cache_creation_input_tokens"),
            "cost_usd": round(sum(c.get("cost_usd", 0) for c in cs), 4),
            "errors": sum(1 for c in cs if c.get("error")),
            "stop_reasons": {r: sum(1 for c in cs if c.get("stop_reason") == r) for r in {c.get("stop_reason") for c in cs}},
            "strict_json_ok": sum(1 for c in cs if c.get("json_parse_ok")),
            "latency_ms_mean": round(statistics.mean(lat)) if lat else None,
            "latency_ms_p95": round(sorted(lat)[int(0.95 * (len(lat) - 1))]) if lat else None,
            "latency_ms_max": max(lat) if lat else None}
  by = {}
  for st in sorted({c.get("stage") for c in calls}):
    by[st] = agg([c for c in calls if c.get("stage") == st])
  first = min((c["ts"] for c in calls), default=None)
  last = max((c["ts"] for c in calls), default=None)
  return {"total": agg(calls), "by_stage": by, "first_call": first, "last_call": last,
          "model": calls[0].get("model") if calls else None, "sdk_version": calls[0].get("sdk_version") if calls else None,
          "temperature": calls[0].get("temperature") if calls else None,
          "max_tokens": calls[0].get("max_tokens") if calls else None}


def iris_results(slug, q):
  base = f"{IRIS}/output/{slug}/{RUN_ID}"
  res = {}
  p = f"{base}/{q}-final/results.json"
  if os.path.exists(p):
    r = json.load(open(p))
    res["statistics"] = r.get("statistics")
    for k in ("vanilla_result", "posthoc_filter_result"):
      v = r.get(k) or {}
      n, tp = v.get("num_results"), v.get("num_tp_results_method")
      prec = (tp / n) if n else None
      rec = 1.0 if v.get("recall_method") else 0.0
      v = dict(v, precision_method=prec, f1_method=(2 * prec * rec / (prec + rec)) if prec and rec else 0.0)
      res[k] = v
  s = f"{base}/{q}-posthoc-filter/stats.json"
  if os.path.exists(s):
    res["posthoc_stats"] = json.load(open(s))
  return res


def cgroup_mem_peak_mb():
  for p in ("/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/memory/memory.max_usage_in_bytes"):
    try:
      return round(int(open(p).read().strip()) / 2**20, 1)
    except Exception:
      pass
  return None


def summarize(slug, cwe, cve, stages, status, note=None, pruned=False, db_bytes=None):
  if PLAN.get("projects", {}).get(slug, {}).get("why"):
    note = "; ".join(x for x in (note, "second pass: " + PLAN["projects"][slug]["why"]) if x)
  q = query_of(cwe)
  src = f"{CB}/project-sources/{slug}"
  n_java, loc = java_stats(src) if os.path.isdir(src) else (None, None)
  bi = f"{CB}/build-info/{slug}.json"
  s = {
      "project": slug, "cve": cve, "cwe": cwe, "query": q, "status": status, "note": note, "summarized_at": now(),
      "settings": {"llm": LLM, "run_id": RUN_ID, "seed": 1234, "label_api_batch_size": 30,
                   "label_func_param_batch_size": 20, "num_threads": 3, "iris_version": "v1 @ 67140e8",
                   "image": os.environ.get("E4_IMAGE"), "host_nproc": os.cpu_count()},
      "stages": stages,
      "wall_seconds_total": round(sum((m or {}).get("seconds") or 0 for m in stages.values()), 1),
      "build": json.load(open(bi)) if os.path.exists(bi) else None,
      "source": {"bytes": du_bytes(src), "java_files": n_java, "java_loc": loc},
      "codeql_db": {"bytes": db_bytes if db_bytes is not None else du_bytes(f"{IRIS}/data/codeql-dbs/{slug}"),
                    "pruned_after_run": pruned},
      "iris_log": iris_log_metrics(slug),
      "iris_eval": iris_results(slug, q),
      "llm": llm_metrics(slug),
      "container_mem_peak_mb_cumulative": cgroup_mem_peak_mb(),
      "disk_free_gb_after": round(shutil.disk_usage(E4).free / 2**30, 1),
  }
  os.makedirs(f"{E4}/projects", exist_ok=True)
  json.dump(s, open(f"{E4}/projects/{slug}.json", "w"), indent=1)
  with open(f"{E4}/e4_projects.jsonl", "a") as f:
    f.write(json.dumps(s) + "\n")
  return s


NETWORK_MARKERS = ("Could not resolve host", "Temporary failure in name resolution", "APIConnectionError",
                   "Connection refused", "Network is unreachable", "Connection timed out", "UnknownHostException")


def network_failure(slug):
  for stage in ("fetch_build", "codeql_db", "iris"):
    p = f"{E4}/{slug}/{stage}.log"
    if os.path.exists(p):
      txt = open(p, errors="ignore").read()
      if any(m in txt for m in NETWORK_MARKERS):
        return True
  return False


def query_of(cwe):
  return f"cwe-{int(cwe.split('-')[1]):03d}wLLM"


def budget_override():
  """2026-11-20: /e4/budget_usd (host-editable) overrides E4_BUDGET_USD for the next project, so the cap can change
  between projects without restarting the container."""
  try:
    return str(float(open(f"{E4}/budget_usd").read().strip()))
  except Exception:
    return None


def run_project(slug, cwe, cve):
  env = dict(os.environ, E4_PROJECT=slug, E4_CVE=cve, E4_CWE=cwe)
  b = budget_override()
  if b:
    env["E4_BUDGET_USD"] = b
  stages = {}
  fix = PLAN.get("projects", {}).get(slug, {})
  env.update(fix.get("env", {}))
  if fix.get("fresh"):  # second pass: fresh clone, no stale/false build-info
    shutil.rmtree(f"{CB}/project-sources/{slug}", ignore_errors=True)
    if os.path.exists(f"{CB}/build-info/{slug}.json"):
      os.remove(f"{CB}/build-info/{slug}.json")
  if fix.get("post_fetch"):
    if fix["post_fetch"].startswith("TBD"):
      return summarize(slug, cwe, cve, stages, "build_failed", "second-pass fix not defined (TBD) - not run")
    stages["fetch"] = run_stage(slug, "fetch", ["python3", f"{CB}/scripts/setup.py", "--no-build", "--filter", slug], env)
    stages["post_fetch"] = run_stage(slug, "post_fetch", ["bash", "-c", f"cd {CB}/project-sources/{slug} && {fix['post_fetch']}"], env)
    if stages["post_fetch"].get("rc") != 0:
      return summarize(slug, cwe, cve, stages, "build_failed", "second-pass post_fetch failed")
  if fix.get("reuse_db") and os.path.isdir(f"{IRIS}/data/codeql-dbs/{slug}") and os.path.exists(f"{CB}/build-info/{slug}.json"):
    # 2026-11-22 follow-ups: the DB from this second pass is valid (built with the final fixes); only IRIS is rerun.
    print(f"[run_queue] {now()} {slug}: reuse_db (fetch_build + codeql_db skipped)", flush=True)
    stages["fetch_build"] = stages["codeql_db"] = {"rc": 0, "seconds": 0, "skipped": "reuse_db"}
    return run_iris_stages(slug, cwe, cve, stages, env, fix)
  stages["fetch_build"] = run_stage(slug, "fetch_build", ["python3", f"{CB}/scripts/setup.py", "--filter", slug], env)
  if not os.path.exists(f"{CB}/build-info/{slug}.json"):
    return summarize(slug, cwe, cve, stages, "build_failed", "no build-info (all build attempts failed)")
  stages["codeql_db"] = run_stage(slug, "codeql_db", ["python3", "scripts/build_codeql_dbs.py", "--project", slug], env)
  if stages["codeql_db"].get("rc") != 0 or not os.path.isdir(f"{IRIS}/data/codeql-dbs/{slug}"):
    return summarize(slug, cwe, cve, stages, "db_failed")
  return run_iris_stages(slug, cwe, cve, stages, env, fix)


def run_iris_stages(slug, cwe, cve, stages, env, fix):
  # 2026-11-20 (#35 hapifhir): 5 of the 90 projects have no data/cwe-bench-java/package-names/<slug>.txt in the pinned
  # benchmark copy; IRIS's Stage 1 needs it. Generate it with IRIS's own documented script (README: "python
  # scripts/get_packages_codeql.py [project slug]"; needs the CodeQL DB) and keep a copy under /e4/package-names-generated/.
  pn = f"{CB}/package-names/{slug}.txt"
  if not os.path.exists(pn):
    stages["package_names"] = run_stage(slug, "package_names", ["python3", "scripts/get_packages_codeql.py", slug]
                                        + fix.get("package_names_args", []), env)
    if os.path.exists(pn) and not open(pn).read().strip():
      # 2026-11-22 (#35 hapifhir): the groupId-based detection can exclude every package -> refuse to run IRIS.
      return summarize(slug, cwe, cve, stages, "iris_failed", "generated package-names file is EMPTY (internal package mismatch)")
    if os.path.exists(pn):
      os.makedirs(f"{E4}/package-names-generated", exist_ok=True)
      shutil.copy(pn, f"{E4}/package-names-generated/{slug}.txt")
    else:
      return summarize(slug, cwe, cve, stages, "iris_failed", "package-names file missing and generation failed")
  stages["iris"] = run_stage(slug, "iris", ["python3", "src/neusym_vul.py", "--query", query_of(cwe), "--run-id", RUN_ID,
                                            "--llm", LLM, slug], env)
  ok = stages["iris"].get("rc") == 0 and os.path.exists(f"{IRIS}/output/{slug}/{RUN_ID}/{query_of(cwe)}-final/results.json")
  db = f"{IRIS}/data/codeql-dbs/{slug}"
  db_bytes, pruned = du_bytes(db), False
  min_free = float(os.environ.get("E4_MIN_FREE_GB", "30"))
  if ok and shutil.disk_usage(E4).free / 2**30 < min_free:
    shutil.rmtree(db, ignore_errors=True)
    pruned = True
  return summarize(slug, cwe, cve, stages, "ok" if ok else "iris_failed", pruned=pruned, db_bytes=db_bytes)


def main():
  if len(sys.argv) > 1 and sys.argv[1] == "--stage-wrap":
    out, log = sys.argv[2], sys.argv[3]
    stage_wrap(out, log, sys.argv[sys.argv.index("--") + 1:])
  ap = argparse.ArgumentParser()
  ap.add_argument("--queue")
  ap.add_argument("--summarize-only")
  ap.add_argument("--retry-failed", action="store_true", help="second pass: rerun projects whose summary is not ok")
  ap.add_argument("--plan", help="second-pass plan JSON (per-project fixes + benchmark rows)")
  a = ap.parse_args()
  if a.plan:
    PLAN.update(json.load(open(a.plan)))
    apply_bench_rows(PLAN.get("bench_rows", {}))
  if a.summarize_only:
    slug, cwe, cve = a.summarize_only.split(",")
    stages = {}
    for line in open(f"{E4}/runs.jsonl"):
      r = json.loads(line)
      if r.get("project") == slug:
        stages[r["stage"]] = {k: v for k, v in r.items() if k not in ("ts", "project", "stage")}  # last attempt wins
    s = summarize(slug, cwe, cve, stages, "ok", note="summary rebuilt from runs.jsonl (no CPU/RSS metrics)")
    print(json.dumps({k: s[k] for k in ("project", "status", "wall_seconds_total")}))
    return
  for line in open(a.queue):
    line = line.strip()
    if not line or line.startswith("#"):
      continue
    slug, cwe, cve = line.split(",")
    if os.path.exists(f"{E4}/STOP"):
      print(f"[run_queue] {now()} STOP file found: stopping before {slug}", flush=True)
      break
    p = f"{E4}/projects/{slug}.json"
    if os.path.exists(p):
      st = json.load(open(p)).get("status")
      # First pass: skip every project that already has a summary (ok or failed). Second pass (--retry-failed):
      # rerun only the failed ones (user OK 2026-11-20; the fix is applied by the caller and disclosed).
      if st == "ok" or not a.retry_failed:
        print(f"[run_queue] skip {slug} (summary {st})", flush=True)
        continue
    s = run_project(slug, cwe, cve)
    if s["status"] != "ok" and network_failure(slug):
      # 2026-11-21 (09:03 UTC DNS outage burned through 14 projects in seconds): stop instead of cascading.
      print(f"[run_queue] {now()} NETWORK FAILURE in {slug} ({s['status']}): stopping the queue", flush=True)
      os.makedirs(f"{E4}/attempts", exist_ok=True)
      os.replace(f"{E4}/projects/{slug}.json", f"{E4}/attempts/{slug}.network_{now().replace(':', '')}.json")
      break
    t = s["llm"]["total"]
    ev = s["iris_eval"].get("posthoc_filter_result", {})
    print(f"[run_queue] {now()} DONE {slug}: status={s['status']} wall={s['wall_seconds_total']} s "
          f"cost=${t['cost_usd']} calls={t['calls']} recall_method={ev.get('recall_method')} "
          f"alerts={ev.get('num_results')} paths={ev.get('num_paths')}", flush=True)
    if s["iris_log"].get("budget_exceeded"):
      print("[run_queue] budget guard fired: stopping the queue", flush=True)
      break
  print(f"[run_queue] {now()} QUEUE END", flush=True)


if __name__ == "__main__":
  main()
