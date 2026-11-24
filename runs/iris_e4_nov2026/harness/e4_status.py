#!/usr/bin/env python3
"""E4 run status + ETA (host side, read-only). Usage: python3 iris/e4_status.py
Reads iris/runs/full/logs/{queue_meta.json, projects/*.json, e4_llm_calls.jsonl}. ETA and remaining cost are linear in
the dataset's file counts (java_dataset_stats.json total_files), fitted on completed projects: time = a + b*files,
cost = c + d*files (least squares; falls back to ratios with < 3 points)."""
import glob
import json
import os

L = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs/full/logs")
meta = json.load(open(f"{L}/queue_meta.json"))
summ = {}
for f in glob.glob(f"{L}/projects/*.json"):
  s = json.load(open(f))
  summ[s["project"]] = s
spent = sum(json.loads(l).get("cost_usd", 0) for l in open(f"{L}/e4_llm_calls.jsonl"))
done = [m for m in meta if summ.get(m["slug"], {}).get("status") == "ok"]
failed = [m for m in meta if m["slug"] in summ and summ[m["slug"]]["status"] != "ok"]
todo = [m for m in meta if m["slug"] not in summ]


def fit(xs, ys):
  n = len(xs)
  if n < 3:
    r = sum(ys) / max(sum(xs), 1)
    return 0.0, r
  mx, my = sum(xs) / n, sum(ys) / n
  sxx = sum((x - mx) ** 2 for x in xs)
  b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx else 0
  a = my - b * mx
  return max(a, 0.0), max(b, 0.0)


xs = [m["files"] for m in done]
a, b = fit(xs, [summ[m["slug"]]["wall_seconds_total"] for m in done])
c, d = fit(xs, [summ[m["slug"]]["llm"]["total"]["cost_usd"] for m in done])
eta_s = sum(a + b * m["files"] for m in todo)
cost_left = sum(c + d * m["files"] for m in todo)
found = sum(1 for m in done if summ[m["slug"]]["iris_eval"].get("posthoc_filter_result", {}).get("recall_method"))
print(f"done {len(done)}/90 (failed {len(failed)}, remaining {len(todo)}); IRIS Recall@Method found {found}/{len(done)}")
guard = open(f"{L}/budget_usd").read().strip() if os.path.exists(f"{L}/budget_usd") else "200"
print(f"spent ${spent:.2f} of the ${guard} guard; est. remaining ${cost_left:.0f} → total ≈ ${spent + cost_left:.0f}")
print(f"ETA ≈ {eta_s / 3600:.1f} h for the remaining {sum(m['files'] for m in todo)} dataset files "
      f"(fit: {a:.0f} s + {b:.2f} s/file; ${c:.2f} + ${d * 1000:.2f}/1k files)")
if todo:
  print(f"next: #{todo[0]['i']} {todo[0]['slug']} ({todo[0]['files']} files)")
for m in failed:
  print(f"FAILED #{m['i']} {m['slug']}: {summ[m['slug']]['status']} {summ[m['slug']].get('note') or ''}")
