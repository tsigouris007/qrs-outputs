#!/usr/bin/env python3
"""E4: re-evaluate IRIS v1 posthoc filtering with the JSON-parse bug fixed, using IRIS's OWN pipeline and evaluator
(created 2026-11-22; free, offline, no LLM call). IRIS's files are not modified: this script imports IRIS and replaces
two methods at runtime only:
  * ContextualAnalysisPipeline.query_gpt_on_posthoc_filter_prompt -> reads the stored raw reply of the original e4 run
    (output/<slug>/e4/<query>-posthoc-filter/logs/raw_llm_response_<result>_<flow>.txt) and parses it;
  * ContextualAnalysisPipeline.parse_posthoc_filter_json_result -> variant:
      orig  = IRIS's parser unchanged (control: must reproduce the e4 final result exactly)
      fix1  = IRIS's parser; on failure retry without the `re.sub("//.*")` comment strip (failure mode 1)
      fix12 = fix1; on failure scan every '{' with raw_decode for a dict with is_vulnerable (failure mode 2)
  get_model() raises, so no LLM can be reached. A fixed parse only adds information, so the replay's caches only gain
  hits: every path the replay sends to the "LLM" was also queried in the original run (missing replies are counted).
Each variant runs as run_id e4reeval_<variant> in a folder whose inputs are symlinks to the e4 folder (posthoc-filter,
final and log are fresh). Only Stage 8 (posthoc) and Stage 9 (evaluation) run.

Run INSIDE the IRIS container (iris-e4:v1, /iris/output = runs/iris_e4_nov2026/output):
  python3 /metrics/e4_posthoc_reeval.py <slug> [<slug> ...] --out /e4/posthoc_reeval.json
"""
import argparse, json, os, re, sys

sys.path.insert(0, "/iris/src")
sys.path.insert(0, "/iris")
from src.config import OUTPUT_DIR                                     # noqa: E402
from src.modules import contextual_analysis_pipeline as cap           # noqa: E402
from src.neusym_vul import SAPipeline                                  # noqa: E402
from src.queries import QUERIES                                        # noqa: E402

ORIG_PARSE = cap.ContextualAnalysisPipeline.parse_posthoc_filter_json_result
STATE = {"missing": 0, "replayed": 0, "fixed": 0}


def _finish(self, result):
  for k in ("is_vulnerable", "source_is_false_positive", "sink_is_false_positive"):
    if k in result:
      result[k] = self.parse_boolean(result[k])
  return result


def parse_fix1(self, s):
  r = ORIG_PARSE(self, s)
  if r:
    return r
  try:
    t = s.replace("\\n", "").replace("\\\n", "")
    t = re.sub("\"\"", "\"", t)
    r = json.loads(re.findall(r"\{[\s\S]*\}", t)[0])
    if isinstance(r, dict):
      STATE["fixed"] += 1
      return _finish(self, r)
  except Exception:
    pass
  return {}


def parse_fix12(self, s):
  r = parse_fix1(self, s)
  if r:
    return r
  dec = json.JSONDecoder(strict=False)
  for m in re.finditer(r"\{", s):
    try:
      r, _ = dec.raw_decode(s[m.start():])
      if isinstance(r, dict) and "is_vulnerable" in r:
        STATE["fixed"] += 1
        return _finish(self, r)
    except Exception:
      continue
  return {}


def _stored(self, orig_log_dir, result_id, code_flow_id):
  f = f"{orig_log_dir}/raw_llm_response_{result_id}_{code_flow_id}.txt"
  if not os.path.exists(f):
    STATE["missing"] += 1
    self.project_logger.error(f"[reeval] missing stored reply {f}")
    return ""                       # = IRIS's own handling of a failed predict() ("Error during querying; skipping")
  STATE["replayed"] += 1
  return open(f).read()


def make_replay(orig_log_dir):
  """Non-batched path (query_gpt_on_posthoc_filter_prompt)."""
  def replay(self, result_id, code_flow_id, path_user_prompt):
    return self.parse_posthoc_filter_json_result(_stored(self, orig_log_dir, result_id, code_flow_id))
  return replay


def make_batched_replay(orig_log_dir):
  """Batched path (the one IRIS v1 uses): a line-for-line copy of ContextualAnalysisPipeline.
  batched_query_gpt_on_code_flow in which `self.get_model().predict(prompts, ...)` is replaced by the stored replies of
  the same (result_id, code_flow_id) entries; prompts are rebuilt (as IRIS does) but not written; cache updates unchanged."""
  def batched(self, entries, enclosing_class_locs, enclosing_func_locs, grouped_path_cache,
              false_positive_source_cache, false_positive_sink_cache):
    prompts = [self.build_prompt_for_code_flow(path, enclosing_class_locs, enclosing_func_locs) for (_, _, path) in entries]
    results = [_stored(self, orig_log_dir, rid, cid) for (rid, cid, _) in entries]
    results_json = []
    for ((result_id, code_flow_id, path), prompt, result_str) in zip(entries, prompts, results):
      try:
        result_json = self.parse_posthoc_filter_json_result(result_str)
      except Exception:
        result_json = {}
      source = self.path_location_to_enclose_func_and_msg(path[0], enclosing_func_locs)
      sink = self.path_location_to_enclose_func_and_msg(path[-1], enclosing_func_locs)
      group_id = (source, sink)
      grouped_path_cache[group_id] = result_json
      if "source_is_false_positive" in result_json and result_json["source_is_false_positive"]:
        false_positive_source_cache[source] = True
      if "sink_is_false_positive" in result_json and result_json["sink_is_false_positive"]:
        false_positive_sink_cache[sink] = True
      results_json.append((result_id, code_flow_id, {"path": path, "using_cache": False,
                                                      "prompt": prompt[1]["content"], "result": result_json}))
    return results_json
  return batched


def no_llm(self):
  raise RuntimeError("e4_posthoc_reeval: LLM access is disabled")


def query_of(slug):
  # same mapping as iris/run_queue.py: the e4 folder holds exactly one <query>-final directory
  base = f"{OUTPUT_DIR}/{slug}/e4"
  q = [d[:-len("-final")] for d in os.listdir(base) if d.endswith("-final")]
  assert len(q) == 1, q
  return q[0]


def run(slug, variant):
  query = query_of(slug)
  src = f"{OUTPUT_DIR}/{slug}/e4"
  dst = f"{OUTPUT_DIR}/{slug}/e4reeval_{variant}"
  os.makedirs(dst, exist_ok=True)
  for d in os.listdir(src):
    if d in (f"{query}-posthoc-filter", f"{query}-final", "log"):
      continue
    if not os.path.lexists(f"{dst}/{d}"):
      os.symlink(f"../e4/{d}", f"{dst}/{d}")
  cap.ContextualAnalysisPipeline.parse_posthoc_filter_json_result = {"orig": ORIG_PARSE, "fix1": parse_fix1,
                                                                     "fix12": parse_fix12}[variant]
  logs = f"{src}/{query}-posthoc-filter/logs"
  cap.ContextualAnalysisPipeline.query_gpt_on_posthoc_filter_prompt = make_replay(logs)
  cap.ContextualAnalysisPipeline.batched_query_gpt_on_code_flow = make_batched_replay(logs)
  cap.ContextualAnalysisPipeline.get_model = no_llm
  SAPipeline.get_model = no_llm
  for k in STATE:
    STATE[k] = 0
  p = SAPipeline(slug, query, run_id=f"e4reeval_{variant}", llm="claude-sonnet-4-6", use_exhaustive_qll=True)
  p.query_gpt_for_posthoc_filtering()
  p.evaluate_result()
  res = json.load(open(f"{dst}/{query}-final/results.json"))
  stats = json.load(open(f"{dst}/{query}-posthoc-filter/stats.json"))
  return {"variant": variant, "query": query, **{f"replay_{k}": v for k, v in STATE.items()}, "stats": stats,
          "kept_paths": kept_paths(f"{dst}/{query}-posthoc-filter/results.sarif"),
          "posthoc": res["posthoc_filter_result"], "vanilla": res["vanilla_result"]}


def kept_paths(sarif):
  """(result index, ruleId, sink location, #flows) per retained result: identical sets = identical filtering."""
  out = []
  for i, r in enumerate(json.load(open(sarif))["runs"][0]["results"]):
    loc = r["locations"][0]["physicalLocation"]
    out.append([r.get("ruleId"), loc["artifactLocation"]["uri"], loc.get("region", {}).get("startLine"),
                len(r.get("codeFlows", []))])
  return sorted(out)


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("slugs", nargs="+")
  ap.add_argument("--variants", nargs="+", default=["orig", "fix1", "fix12"])
  ap.add_argument("--out", required=True)
  a = ap.parse_args()
  out = json.load(open(a.out)) if os.path.exists(a.out) else {}
  for slug in a.slugs:
    q = query_of(slug)
    e4 = json.load(open(f"{OUTPUT_DIR}/{slug}/e4/{q}-final/results.json"))["posthoc_filter_result"]
    out[slug] = {"e4_posthoc": e4, "variants": {}}
    for v in a.variants:
      r = run(slug, v)
      out[slug]["variants"][v] = r
      ph = r["posthoc"]
      print(f"{slug} {v}: recall_method={ph['recall_method']} paths={ph['num_paths']} tp_paths={ph['num_tp_paths_method']} "
            f"replayed={r['replay_replayed']} missing={r['replay_missing']} fixed={r['replay_fixed']}", flush=True)
      json.dump(out, open(a.out, "w"), indent=1)
    ctrl = out[slug]["variants"].get("orig")
    if ctrl is not None:
      e4_stats = json.load(open(f"{OUTPUT_DIR}/{slug}/e4/{q}-posthoc-filter/stats.json"))
      e4_kept = kept_paths(f"{OUTPUT_DIR}/{slug}/e4/{q}-posthoc-filter/results.sarif")
      same = (all(ctrl["posthoc"][k] == e4[k] for k in ("num_paths", "recall_method", "num_tp_paths_method", "recall_file"))
              and ctrl["stats"] == e4_stats and ctrl["kept_paths"] == e4_kept and ctrl["replay_missing"] == 0)
      out[slug]["e4_stats"] = e4_stats
      out[slug]["control_reproduces_e4"] = same
      print(f"{slug}: control reproduces e4 = {same}", flush=True)
      json.dump(out, open(a.out, "w"), indent=1)


if __name__ == "__main__":
  main()
