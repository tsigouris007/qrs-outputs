#!/usr/bin/env python3
"""QRS artifact: recompute every number of the paper from the raw scan outputs and compare it with the paper.

    python3 verify.py            # about 10 seconds, Python >= 3.9, standard library only

1. Rebuilds the result databases in memory from runs/ (scan order and row ids from data/manifests/) and the expert
   labels in data/labels/.
2. Computes every table, figure and in-text number of the paper (one function per paper element below).
3. Writes results.json (same keys as paper_numbers.json) and prints one line per paper element; any number that
   differs from paper_numbers.json is printed with both values. Exit code 0 when everything matches.

Rules used throughout (see README.md):
  kept       a stage keeps a finding unless its verdict is fp (mr = manual review counts as kept);
  delivered  an issue is delivered by a scan when R and S keep a finding at the issue's location;
  labels     Top100: the expert label; for the 124 findings both blind judges contested, the expert's re-examination
             (data/label_audit.csv) is the final label. Duplicates count once (final_labels()).
"""
import ast, collections, csv, decimal, glob, json, math, os, random, re, sqlite3, statistics, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
P = lambda *a: os.path.join(ROOT, *a)
J = lambda *a: json.load(open(P(*a)))
ORDER = ["C0", "C1", "DC0", "DC1", "DR0", "DR1", "G0", "G1", "GPT0", "GPT1"]
KEEP = ("tp", "mr")
# List prices per 1M tokens (input, output), uncached input, at scan time.
PRICES = {"claude-sonnet-4-5-20250929": (3.0, 15.0), "claude-haiku-4-5-20251001": (1.0, 5.0),
          "gemini/gemini-3-pro-preview": (2.0, 12.0), "gemini/gemini-2.5-pro": (1.25, 10.0), "gpt-5.1": (1.25, 10.0),
          "gpt-4.1": (2.0, 8.0), "deepseek/deepseek-chat": (0.28, 0.42), "deepseek/deepseek-reasoner": (0.28, 0.42)}
GT = J("data/ground_truth/top100_issues.json")["issues"]          # the 12 confirmed Top100 issues
ISSUES = {i["id"]: i for i in GT}


# ============================================================================ databases (in memory)
SCHEMA = """
create table scan_master (scan_id integer primary key, package_name text, package_version text,
  codeql_session_id integer, reviewer_session_id integer, sanity_session_id integer);
create table codeql_session (codeql_session_id integer primary key, session_id text, package_name text, model text,
  temperature real, max_tokens integer, iterations integer, total_input_tokens integer, total_output_tokens integer,
  total_tokens integer, elapsed_time_seconds real, estimated_cost_usd real, tool_calls text, queries_executed_total integer);
create table codeql_findings (codeql_finding_id integer primary key, codeql_session_id integer, codeql_query_uuid text,
  hypothesis text, cwe_ids text, results_count integer);
create table reviewer_session (reviewer_session_id integer primary key, session_id text, model text, temperature real,
  max_tokens integer, iterations integer, total_input_tokens integer, total_output_tokens integer, total_tokens integer,
  elapsed_time_seconds real, estimated_cost_usd real, tool_calls text);
create table reviewer_findings (reviewer_finding_id integer primary key, reviewer_session_id integer,
  codeql_query_uuids text, finding_id text, verdict text, severity text, cwe_ids text, description text,
  file_path text, start_line integer, end_line integer);
create table sanity_session (sanity_session_id integer primary key, session_id text, model text, temperature real,
  max_tokens integer, total_input_tokens integer, total_output_tokens integer, total_tokens integer,
  elapsed_time_seconds real, estimated_cost_usd real, total_findings_validated integer);
create table sanity_findings (sanity_finding_id integer primary key, sanity_session_id integer,
  reviewer_finding_id integer, finding_id text, verdict text);
create table labels (finding_id text primary key, label text);
"""
LABELS = {"top100": "top100", "hist20": "hist20", "iris": "cwe_bench_java", "e2_sa": "single_agent"}
_DB = {}


def ins(cur, table, row):
  cur.execute(f"insert into {table} ({','.join(row)}) values ({','.join('?' * len(row))})", list(row.values()))
  return cur.lastrowid


def insert_scan(cur, s, sid, ids, cq, rv, sn, version=None):
  """One scan, with the field mapping of the pipeline's own importer and the original row ids."""
  model = lambda m: m.split("anthropic.", 1)[1] if s == "iris" and m and "anthropic." in m else m
  cid = ins(cur, "codeql_session", dict(
      codeql_session_id=ids.get("codeql_session_id"), session_id=cq.get("session_id"), package_name=cq.get("package_name"),
      model=model(cq.get("model")), temperature=cq.get("temperature"), max_tokens=cq.get("max_tokens"),
      iterations=cq.get("iterations"), total_input_tokens=cq.get("total_input_tokens"),
      total_output_tokens=cq.get("total_output_tokens"), total_tokens=cq.get("total_tokens"),
      elapsed_time_seconds=cq.get("elapsed_time_seconds"), estimated_cost_usd=cq.get("estimated_cost_usd"),
      tool_calls=json.dumps(cq.get("tool_calls", {})),
      queries_executed_total=cq.get("queries_executed", {}).get("total_executed", 0)))
  qids, rids, sids = (list(ids.get(k) or []) for k in ("codeql_finding_ids", "reviewer_finding_ids", "sanity_finding_ids"))
  nxt = lambda l: l.pop(0) if l else None
  for f in cq.get("findings", []):
    ins(cur, "codeql_findings", dict(codeql_finding_id=nxt(qids), codeql_session_id=cid, codeql_query_uuid=f.get("codeql_query_uuid"),
        hypothesis=f.get("hypothesis"), cwe_ids=json.dumps(f.get("cwe_ids", [])), results_count=f.get("results_count", 0)))
  rid = ins(cur, "reviewer_session", dict(
      reviewer_session_id=ids.get("reviewer_session_id"), session_id=rv.get("session_id"), model=model(rv.get("model")),
      temperature=rv.get("temperature"), max_tokens=rv.get("max_tokens"), iterations=rv.get("iterations"),
      total_input_tokens=rv.get("total_input_tokens"), total_output_tokens=rv.get("total_output_tokens"),
      total_tokens=rv.get("total_tokens"), elapsed_time_seconds=rv.get("elapsed_time_seconds"),
      estimated_cost_usd=rv.get("estimated_cost_usd"), tool_calls=json.dumps(rv.get("tool_calls", {}))))
  fmap = {}
  for f in rv.get("findings", []):
    r = ins(cur, "reviewer_findings", dict(
        reviewer_finding_id=nxt(rids), reviewer_session_id=rid, codeql_query_uuids=json.dumps(f.get("codeql_query_uuids", [])),
        finding_id=f.get("finding_id"), verdict=f.get("verdict"), severity=f.get("severity"),
        cwe_ids=json.dumps(f.get("cwe_ids", [])), description=f.get("description"), file_path=f.get("file_path"),
        start_line=f.get("start_line"), end_line=f.get("end_line")))
    if f.get("finding_id"):
      fmap[f["finding_id"]] = r
  md = sn.get("sanity_check_metadata", {})
  ssid = ins(cur, "sanity_session", dict(
      sanity_session_id=ids.get("sanity_session_id"), session_id=md.get("session_id"), model=model(md.get("model")),
      temperature=md.get("temperature"), max_tokens=md.get("max_tokens"), total_input_tokens=md.get("total_input_tokens"),
      total_output_tokens=md.get("total_output_tokens"), total_tokens=md.get("total_tokens"),
      elapsed_time_seconds=md.get("elapsed_time_seconds"), estimated_cost_usd=md.get("estimated_cost_usd"),
      total_findings_validated=md.get("total_findings_validated", 0)))
  for f in sn.get("findings", []):
    sc = f.get("sanity_check") or {}
    if sc and fmap.get(f.get("finding_id")):
      ins(cur, "sanity_findings", dict(sanity_finding_id=nxt(sids), sanity_session_id=ssid, reviewer_finding_id=fmap[f["finding_id"]],
                                       finding_id=f["finding_id"], verdict=sc.get("verdict", "mr")))
  ins(cur, "scan_master", dict(scan_id=sid, package_name=cq.get("package_name"), package_version=version,
                               codeql_session_id=cid, reviewer_session_id=rid, sanity_session_id=ssid))


def reports(d):
  return [json.load(open(P(d, f"agent_{x}_report.json"))) for x in ("codeql", "reviewer", "sanity")]


def single_agent_scans():
  """One agent did Q, R and S: its R/S session ids get suffixes and the R/S fields come from the findings."""
  for run, tag in (("claude-0-sa-r1", "text"), ("claude-0-sa-native-r1", "native")):
    for pkg in sorted(os.listdir(P("runs/single_agent_nov2026", run))):
      d = f"runs/single_agent_nov2026/{run}/{pkg}"
      if not all(os.path.exists(P(d, f"agent_{x}_report.json")) for x in ("codeql", "reviewer", "sanity")):
        continue
      cq, rv, sn = reports(d)
      rv.update(session_id=f"{cq['session_id']}-sa-R")
      sn["sanity_check_metadata"] = {"session_id": f"{cq['session_id']}-sa-S", "model": sn.get("model"),
                                     "temperature": sn.get("temperature"), "max_tokens": sn.get("max_tokens"),
                                     "total_findings_validated": len(sn["findings"])}
      yield cq, rv, sn, tag


def db(s):
  """In-memory result database of one experiment: top100, hist20, iris, e1_nov2026, e5, e2_sa."""
  if s in _DB:
    return _DB[s]
  con = sqlite3.connect(":memory:"); con.executescript(SCHEMA); cur = con.cursor()
  if s == "e2_sa":
    for i, (cq, rv, sn, tag) in enumerate(single_agent_scans(), 1):
      insert_scan(cur, s, i, {}, cq, rv, sn, tag)
  else:
    for m in J("data/manifests", f"{s}.json"):
      insert_scan(cur, s, m["scan_id"], m, *reports(m["dir"]))
  if s in LABELS:
    for r in csv.DictReader(open(P("data/labels", f"{LABELS[s]}.csv"))):
      cur.execute("insert into labels values (?, ?)", (r["finding_id"], r["label"] or None))
  con.commit(); _DB[s] = con
  return con


CFG = """case when cs.model like 'claude%' then 'C' when cs.model like '%deepseek-chat%' then 'DC'
  when cs.model like '%deepseek-reasoner%' then 'DR' when cs.model like 'gemini%' then 'G' else 'GPT' end
  || cast(cs.temperature as int)"""


def list_cost(m, i, o):
  pi, po = PRICES[m]
  return ((i or 0) * pi + (o or 0) * po) / 1e6


# ============================================================================ final Top100 labels
def _cwe(s):
  return frozenset(re.sub(r"cwe-0*", "", c) for c in re.findall(r"cwe-\d+", str(s).lower()))


_FINAL = None


def final_labels():
  """finding_id -> tp|fp for every counted Top100 finding. Labels as released (data/labels/top100.csv, the
  re-examination of the contested findings already applied). A dup counts once: if the same scan has a tp/fp finding in
  the same file with an overlapping CWE it is already counted; otherwise one representative per (scan, file, CWEs)
  inherits the majority label of the same mechanism elsewhere in Top100 (same package and file, lines within 2,
  overlapping CWE; tp on a tie), and is left out when there is nothing to inherit."""
  global _FINAL
  if _FINAL is not None:
    return _FINAL
  data = [dict(zip(("scan_id", "package", "finding_id", "label", "file", "a", "b", "cwe"), r)) for r in db("top100").execute(
      """select sm.scan_id, sm.package_name, r.finding_id, h.label, r.file_path, r.start_line,
                coalesce(r.end_line, r.start_line), r.cwe_ids
         from labels h join reviewer_findings r using(finding_id)
         join scan_master sm on sm.reviewer_session_id = r.reviewer_session_id""")]
  for d in data:
    d["cwe"] = _cwe(d["cwe"]); d["final"] = d["label"] if d["label"] in ("tp", "fp") else None
  lab = [d for d in data if d["final"]]
  by_scan_file, by_pkg_file = collections.defaultdict(list), collections.defaultdict(list)
  for d in lab:
    by_scan_file[(d["scan_id"], d["file"])].append(d); by_pkg_file[(d["package"], d["file"])].append(d)
  groups = collections.defaultdict(list)
  for d in data:
    if d["label"] == "dup" and not any(x["cwe"] & d["cwe"] for x in by_scan_file[(d["scan_id"], d["file"])]):
      groups[(d["scan_id"], d["file"], d["cwe"])].append(d)
  for g in groups.values():
    votes = collections.Counter(x["final"] for d in g if d["a"] is not None for x in by_pkg_file[(d["package"], d["file"])]
                                if x["a"] is not None and x["a"] <= d["b"] + 2 and x["b"] >= d["a"] - 2 and x["cwe"] & d["cwe"])
    rep = min(g, key=lambda d: (d["a"] is None, d["a"] or 0, d["finding_id"]))
    if votes:
      rep["final"] = "tp" if votes["tp"] >= votes["fp"] else "fp"
  _FINAL = {d["finding_id"]: d["final"] for d in data if d["final"]}
  return _FINAL


def labelled_top100():
  """(config, scan_id, package, finding_id, label, R verdict, S verdict) for every counted Top100 finding."""
  fin = final_labels()
  rows = db("top100").execute(f"""select {CFG}, sm.scan_id, sm.package_name, r.finding_id, r.verdict, s.verdict
      from reviewer_findings r join scan_master sm on sm.reviewer_session_id = r.reviewer_session_id
      join codeql_session cs on cs.codeql_session_id = sm.codeql_session_id
      left join sanity_findings s using(finding_id)""").fetchall()
  return [(c, sid, pkg, f, fin[f], rv, sv) for c, sid, pkg, f, rv, sv in rows if f in fin]


# ============================================================================ formatting
def f1(x): return f"{x:.1f}"
def f2(x): return f"{x:.2f}"
def f3(x): return f"{x:.3f}"
def pct(x, d=1): return f"{100 * x:.{d}f}"
def dot3(x): return f"{x:.3f}"[1:] if 0 <= x < 1 else f"{x:.2f}"          # .920, 1.00
def thou(n): return f"{n:,}"
def mins(s): m, s = divmod(round(s), 60); return f"{m}m{s:02d}s"
def rng(a, b, fmt=str, sep="--"): return f"{fmt(a)}{sep}{fmt(b)}" if fmt(a) != fmt(b) else fmt(a)


def metrics(tp, fp, fn, tn):
  n, pos = tp + fp + fn + tn, tp + fn
  den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
  return {"acc": (tp + tn) / n, "prec": tp / (tp + fp) if tp + fp else None, "ret": tp / pos if pos else None,
          "f1": 2 * tp / (2 * tp + fp + fn), "mcc": (tp * tn - fp * fn) / den if den else None, "baseline": max(pos, n - pos) / n}


# ============================================================================ Top100: issues delivered (Tab 3, 6)
def window_hit(issue, fp, a, b, key="match"):
  return any(fp.endswith(w) and a <= hi and b >= lo for w, lo, hi in issue[key])


def top100_delivered():
  """config -> set of issue ids delivered: R and S keep a finding at the issue's location (tab:top100-confirmed)."""
  out = collections.defaultdict(set)
  for c, pkg, f, fp, a, b, rv, sv in db("top100").execute(f"""select {CFG}, sm.package_name, r.finding_id, r.file_path,
      r.start_line, coalesce(r.end_line, r.start_line), r.verdict, s.verdict from reviewer_findings r
      join scan_master sm on sm.reviewer_session_id = r.reviewer_session_id
      join codeql_session cs on cs.codeql_session_id = sm.codeql_session_id left join sanity_findings s using(finding_id)"""):
    if a is None or (rv or "") == "fp" or (sv or "") == "fp":
      continue
    for i in GT:
      if pkg == i["package"] and window_hit(i, fp, a, b):
        out[c].add(i["id"])
  return out


def close(issue_id, cfg, run):
  return [cfg, run] in ISSUES[issue_id].get("close_candidates", [])


def table3_6():
  dl = top100_delivered()
  t3 = {i["id"]: f"{sum(i['id'] in dl[c] for c in ORDER)}" + ("†" if any(close(i["id"], c, "dec") for c in ORDER if i["id"] in dl[c]) else "") + "/10"
        for i in GT}
  rows = labelled_top100()
  cost = top100_scan_costs()
  t6, R, S = {}, collections.Counter(), collections.Counter()
  for c in ORDER:
    rr = [r for r in rows if r[0] == c]
    tp = sum(1 for r in rr if r[4] == "tp" and (r[5] or "") != "fp" and (r[6] or "") != "fp")
    fp = sum(1 for r in rr if r[4] == "fp" and (r[5] or "") != "fp" and (r[6] or "") != "fp")
    pos = sum(1 for r in rr if r[4] == "tp")
    m = metrics(tp, fp, pos - tp, len(rr) - pos - fp)
    R[c] = sum(1 for r in rr if (r[5] or "") != "fp"); S[c] = tp + fp
    cves = sorted(i for i in dl[c] if ISSUES[i]["kind"] == "cve"); acks = [i for i in dl[c] if ISSUES[i]["kind"] == "ack"]
    t6[c] = [f"{len(cves)}" + ("†" if any(close(i, c, "dec") for i in cves) else ""), f"{len(acks)}", f"{R[c]} → {S[c]}",
             dot3(m["acc"]), dot3(m["prec"]), dot3(m["ret"]), dot3(m["f1"]), dot3(m["mcc"]),
             f2(sum(cost[c]) / tp)]
  st = stage_ablation()["Q+R+S"]
  allc = set().union(*dl.values())
  t6["All"] = [str(sum(ISSUES[i]["kind"] == "cve" for i in allc)), str(sum(ISSUES[i]["kind"] == "ack" for i in allc)),
               f"{thou(sum(R.values()))} → {thou(sum(S.values()))}", dot3(st["acc"]), dot3(st["prec"]), dot3(st["ret"]),
               dot3(st["f1"]), dot3(st["mcc"]), f2(sum(sum(v) for v in cost.values()) / st["tp"])]
  return t3, t6, dl


# ============================================================================ costs and runtime (Tab 4)
def per_scan(con, where="1=1"):
  out = collections.defaultdict(list)
  for r in con.execute(f"""select {CFG}, sm.scan_id, cs.model, cs.total_input_tokens, cs.total_output_tokens,
      rs.model, rs.total_input_tokens, rs.total_output_tokens, ss.model, ss.total_input_tokens, ss.total_output_tokens,
      coalesce(cs.elapsed_time_seconds,0)+coalesce(rs.elapsed_time_seconds,0)+coalesce(ss.elapsed_time_seconds,0),
      coalesce(cs.total_tokens,0)+coalesce(rs.total_tokens,0)+coalesce(ss.total_tokens,0), cs.iterations, rs.iterations
      from scan_master sm join codeql_session cs using(codeql_session_id) left join reviewer_session rs using(reviewer_session_id)
      left join sanity_session ss using(sanity_session_id) where {where}"""):
    cost = sum(list_cost(m, i, o) for m, i, o in ((r[2], r[3], r[4]), (r[5], r[6], r[7]), (r[8], r[9], r[10])) if m and i is not None)
    out[r[0]].append({"cost": cost, "secs": r[11], "tokens": r[12], "q": r[13] or 0, "r": r[14] or 0})
  return out


def top100_scan_costs():
  return {c: [s["cost"] for s in v] for c, v in per_scan(db("top100")).items()}


def row4(scans, cached=None):
  n = len(scans)
  return [mins(sum(s["secs"] for s in scans) / n), f"{round(sum(s['tokens'] for s in scans) / n / 1e3)}k",
          f"{f1(sum(s['q'] for s in scans) / n)} + {f1(sum(s['r'] for s in scans) / n)}",
          f3(sum(s["cost"] for s in scans) / n), "--" if cached is None else f3(cached)]


def cache_summaries(pattern):
  wc = nc = 0.0; n = 0
  for f in glob.glob(P(pattern)):
    t = json.load(open(f))["total"]; wc += t["cost_usd_with_cache"]; nc += t["cost_usd_no_cache"]; n += 1
  return wc, nc, n


def table4():
  top = per_scan(db("top100"))
  h = db("hist20")
  hd, hn = per_scan(h, "sm.scan_id <= 100"), per_scan(h, "sm.scan_id > 100 and sm.scan_id != 121")
  # Cached cost, estimated where caching was not recorded: list cost per scan x (1 - measured saving of the same model):
  # Top100 Claude from the E1 reruns, every other estimate from the Hist20 N arm of the same model (both rounded to 3 decimals).
  e1 = e1_costs()
  nmeas = {}
  for c in hn:
    wc, nc, n = cache_summaries(f"runs/nov2026/hist20/{c}N-r1/*/cache_usage_summary.json")
    nmeas[c] = {"cached": wc / n, "nocache": nc / n, "saving": 1 - wc / nc, "nocache_total": nc}
  saving = {("Top100", "C0"): e1["C0"]["saving"], ("Top100", "C1"): e1["C1"]["saving"],
            **{("Top100", c): nmeas["GPT0"]["saving"] for c in ("GPT0", "GPT1")}, **{("Top100", c): nmeas["DR0"]["saving"] for c in ("DR0", "DR1")},
            ("Hist20 D", "C0"): nmeas["C0"]["saving"], ("Hist20 D", "GPT0"): nmeas["GPT0"]["saving"]}
  est = lambda blk, c, v: round(round(sum(s["cost"] for s in v) / len(v), 3) * (1 - round(saving[(blk, c)], 3)), 3) if (blk, c) in saving else None
  t = {"Top100": {c: row4(top[c], est("Top100", c, top[c])) for c in ORDER},
       "Hist20 D": {c: row4(hd[c], est("Hist20 D", c, hd[c])) for c in ("C0", "GPT0", "G0", "DR0")},
       "Hist20 N": {}}
  for c in ("C0", "GPT0", "DR0"):
    r = row4(hn[c], nmeas[c]["cached"]); r[3] = f3(nmeas[c]["nocache"]); t["Hist20 N"][c] = r
  every = [s for v in top.values() for s in v] + [s for v in hd.values() for s in v] + [s for v in hn.values() for s in v]
  secs = sum(s["secs"] for s in every)
  total = (sum(s["cost"] for v in top.values() for s in v) + sum(s["cost"] for v in hd.values() for s in v)
           + sum(m["nocache_total"] for m in nmeas.values()))
  t["Total"] = [f"{int(secs // 3600)}h{int(secs % 3600 // 60):02d}m", f"{sum(s['tokens'] for s in every) / 1e6:.1f}M", "--", f2(total), "--"]
  text = {"scans in the Total row": thou(len(every)),
          "measured caching saving, Claude (E1 reruns; Hist20 C0 N)": "{}--{}%".format(*sorted({pct(x, 0) for x in (e1["C0"]["saving"], e1["C1"]["saving"], nmeas["C0"]["saving"])})),
          "measured caching saving, GPT (Hist20 GPT0 N)": f"{pct(nmeas['GPT0']['saving'], 0)}%",
          "measured caching saving, DeepSeek (Hist20 DR0 N)": f"{pct(nmeas['DR0']['saving'], 0)}%",
          "GPT stops Q early (iterations of 20)": f"{round(statistics.mean([sum(s['q'] for s in top[c]) / 100 for c in ('GPT0', 'GPT1')]))}/20"}
  return t, text


# ============================================================================ label audit (Tab 5)
def kappa(pairs):
  n = len(pairs); po = sum(a == b for a, b in pairs) / n
  pa = sum(a == "tp" for a, _ in pairs) / n; pb = sum(b == "tp" for _, b in pairs) / n
  pe = pa * pb + (1 - pa) * (1 - pb)
  return None if pe == 1 else (po - pe) / (1 - pe)


def boot(pairs, n=2000, seed=7):
  rnd = random.Random(seed); ks = []
  for _ in range(n):
    k = kappa([pairs[rnd.randrange(len(pairs))] for _ in pairs])
    if k is not None:
      ks.append(k)
  ks.sort(); return ks[int(0.025 * len(ks))], ks[int(0.975 * len(ks)) - 1]


def table5():
  rows = list(csv.DictReader(open(P("data/label_audit.csv"))))
  t = {}
  for name, col in (("Sonnet 5.5", "judge_sonnet_5_5"), ("GPT-5.6 Sol", "judge_gpt_5_6_sol")):
    pairs = [(r["expert_final"], r[col]) for r in rows if r[col] in ("tp", "fp")]
    pos = [p for p in pairs if p[0] == "tp"]; neg = [p for p in pairs if p[0] == "fp"]
    lo, hi = boot(pairs)
    t[name] = [pct(sum(a == b for a, b in pairs) / len(pairs)) + "%", f"{kappa(pairs):.2f} [{lo:.2f}, {hi:.2f}]",
               pct(sum(a == b for a, b in pos) / len(pos)) + "%", pct(sum(a == b for a, b in neg) / len(neg)) + "%"]
  contested = [r for r in rows if r["judge_sonnet_5_5"] != r["expert"] and r["judge_gpt_5_6_sol"] != r["expert"]]
  text = {"sampled findings": thou(len(rows)),
          "contested by both judges": str(len(contested)),
          "changed by the expert's re-examination": str(sum(r["expert_final"] != r["expert"] for r in rows)),
          "re-examined findings are exactly the contested ones": str(all(r["expert_final"] == r["expert"] for r in rows if r not in contested)),
          "expert TPs / FPs in the sample (final labels)": f"{sum(r['expert_final'] == 'tp' for r in rows)} / {sum(r['expert_final'] == 'fp' for r in rows)}",
          "kappa judge vs judge": f"{kappa([(r['judge_sonnet_5_5'], r['judge_gpt_5_6_sol']) for r in rows]):.2f}"}
  return t, text


# ============================================================================ stage ablation (Tab 10)
_STAGES = None


def stage_ablation():
  global _STAGES
  if _STAGES:
    return _STAGES
  rows = [(lab, rv, sv) for _, _, _, _, lab, rv, sv in labelled_top100()]
  N, Pn = len(rows), sum(l == "tp" for l, _, _ in rows)
  R = lambda rv, sv: (rv or "") != "fp"
  var = {"Q": lambda rv, sv: True, "Q+R": R, "Q+R+S": lambda rv, sv: R(rv, sv) and (sv or "") != "fp",
         "Q+R+S, S mr = reject": lambda rv, sv: R(rv, sv) and (sv or "") not in ("fp", "mr")}
  out = {"n": N, "pos": Pn}
  for k, f in var.items():
    tp = sum(1 for l, rv, sv in rows if l == "tp" and f(rv, sv)); fp = sum(1 for l, rv, sv in rows if l == "fp" and f(rv, sv))
    out[k] = {"kept": tp + fp, "tp": tp, "fp": fp, "fn": Pn - tp, **metrics(tp, fp, Pn - tp, N - Pn - fp)}
  _STAGES = out
  return out


def table10():
  s = stage_ablation()
  t = {k: [thou(v["kept"]), thou(v["tp"]), thou(v["fp"]), str(v["fn"]), dot3(v["acc"]), dot3(v["prec"]),
           f"{v['ret']:.3f}".lstrip("0") if v["ret"] < 1 else "1.000", dot3(v["f1"]), "--" if k == "Q" else dot3(v["mcc"])]
       for k, v in s.items() if k.startswith("Q") and "mr" not in k}
  q, r, a, m = s["Q"], s["Q+R"], s["Q+R+S"], s["Q+R+S, S mr = reject"]
  text = {"labelled findings / positives": f"{thou(s['n'])} / {s['pos']}", "majority-baseline accuracy": f"{1 - s['pos'] / s['n']:.3f}",
          "raw Q precision": pct(q["prec"]) + "%", "R keeps / precision": f"{pct(r['ret'])}% / {pct(r['prec'])}%",
          "S removes of the FPs that reach it": pct(1 - a["fp"] / r["fp"]) + "%",
          "confirmed findings S rejects (share of R's)": f"{r['tp'] - a['tp']} ({pct((r['tp'] - a['tp']) / r['tp'])}%)",
          "precision / MCC after S": f"{pct(a['prec'])}% / {a['mcc']:.3f}", "MCC after R": f"{r['mcc']:.3f}",
          "analyst queue": f"{thou(q['kept'])} → {a['kept']} (-{pct(1 - a['kept'] / q['kept'])}%)",
          "retention after S": pct(a["ret"]) + "%",
          "S MR as rejection: precision / retention": f"{pct(m['prec'])}% / {pct(m['ret'])}%",
          "R rejects / S rejects another / confirmed": f"{pct(1 - r['kept'] / q['kept'], 0)}% / {pct((r['kept'] - a['kept']) / q['kept'], 0)}% / {a['tp']} ({pct(a['tp'] / q['kept'])}%)"}
  return t, text


# ============================================================================ Q logs: query generation (Tab 7)
LINE = re.compile(r"^\S+ \S+ - Agent_(\d+) - (?:INFO|ERROR|WARNING|DEBUG) - (.*)$")
ERRCLS = [("metadata", re.compile(r"NO_KIND_SPECIFIED|INVALID_RESULT_PATTERNS|@kind|metadata", re.I)),
          ("api_member", re.compile(r"cannot be resolved for type")),
          ("unresolved_name", re.compile(r"could not resolve (module|type|predicate|variable)")),
          ("type_mismatch", re.compile(r"incompatible with|not compatible with")),
          ("syntax", re.compile(r"missing one of|unexpected input|expected an? |syntax error|mismatched|unterminated", re.I))]


def errclass(line):
  return next((n for n, rx in ERRCLS if rx.search(line)), "other")


def parse_q_log(path, session):
  """Counts of one Q session (only lines of that session: some logs were appended by reruns)."""
  if not os.path.exists(path):
    return None
  c, errs = collections.Counter(), collections.Counter()
  cur, pending, in_fix, fix_ok, seen = None, False, False, False, False
  for raw in open(path, errors="ignore"):
    m = LINE.match(raw.rstrip("\n"))
    if m:
      cur, s = m.group(1), m.group(2); pending = False
      if cur != session:
        continue
      seen = True
      if s.startswith("[*] Processing tool call: execute_codeql_query"):
        c["exec"] += 1
      elif s.startswith("[*] Processing tool call: fixup_codeql_query"):
        if in_fix:
          c["fix_ok" if fix_ok else "fix_fail"] += 1
        c["fix_calls"] += 1; in_fix, fix_ok = True, False
      elif s.startswith("[+] CodeQL query found "):
        c["ran"] += 1; c["ran_nz" if int(re.search(r"found (\d+)", s).group(1)) else "ran_zero"] += 1
      elif s.startswith("[-] CodeQL query execution failed"):
        c["exec_failed"] += 1
      elif s.startswith("[+] Query is valid"):
        fix_ok = True
      elif s.startswith("[-] Query is invalid"):
        pending = True
      continue
    if cur == session and pending and raw.startswith("ERROR:"):
      errs[errclass(raw)] += 1; pending = False
  if in_fix:
    c["fix_ok" if fix_ok else "fix_fail"] += 1
  return (c, errs) if seen else None


def kind_of(src):
  m = re.search(r"@kind\s+([\w-]+)", src or "")
  return m.group(1) if m else "none"


def query_capability(dirs, labels):
  """Execution outcomes, fix-ups, query kinds and the confirmed findings each kind leads to, over scan directories."""
  T, K, ERR, Y = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
  for d in dirs:
    qp = os.path.join(d, "agent_codeql_report.json")
    if not os.path.exists(qp):
      continue
    q = json.load(open(qp)); T["scans"] += 1
    parsed = parse_q_log(os.path.join(d, "agent_codeql_run.log"), str(q.get("session_id")))
    if parsed is None:
      T["scans_no_log"] += 1
    else:
      T.update(parsed[0]); ERR.update(parsed[1])
    qk = {}
    for f in q.get("findings", []):
      k = kind_of(f.get("codeql_raw_query")); K[k] += 1
      if (f.get("results_count") or 0) > 0:
        qk[f["codeql_query_uuid"]] = k; K[k + ">=1"] += 1
    rp = os.path.join(d, "agent_reviewer_report.json")
    tp_q = set()
    for f in (json.load(open(rp)).get("findings", []) if os.path.exists(rp) else []):
      uus = f.get("codeql_query_uuids") or []
      uus = re.findall(r"[\w-]{14,}", uus) if isinstance(uus, str) else uus
      if labels.get(f.get("finding_id")) == "tp":
        tp_q.update(u for u in uus if u in qk)
    for u in tp_q:
      Y[qk[u]] += 1
  return {"T": T, "K": K, "ERR": ERR, "TP": Y}


QDIRS = {"Top100": {c: f"runs/top100_dec2025/{d}/*/" for c, d in zip(ORDER, (
             "claude-0", "claude-1", "deepseek-chat-0", "deepseek-chat-1", "deepseek-reasoner-0", "deepseek-reasoner-1",
             "gemini-0", "gemini-1", "gpt-0", "gpt-1"))},
         "Hist20 D": {"C0": "runs/hist20_jan2026/claude-0/*/", "GPT0": "runs/hist20_jan2026/gpt-0/*/",
                      "G0": "runs/hist20_jan2026/gemini-0/*/", "DR0": "runs/hist20_jan2026/deepseek-reasoner-0/*/"},
         "Hist20 N": {"C0": "runs/nov2026/hist20/C0N-r1/*/", "GPT0": "runs/nov2026/hist20/GPT0N-r1/*/",
                      "DR0": "runs/nov2026/hist20/DR0N-r1/*/"}}


def table7():
  fin = final_labels()
  qc = {blk: {c: query_capability(sorted(glob.glob(P(g))), fin if blk == "Top100" else {}) for c, g in v.items()}
        for blk, v in QDIRS.items()}
  t = {}
  for blk, v in qc.items():
    t[blk] = {}
    for c, o in v.items():
      T, K = o["T"], o["K"]; e = T["exec"]
      t[blk][c] = [f1(e / (T["scans"] - T["scans_no_log"])), pct(T["ran_nz"] / e), pct(T["ran_zero"] / e), pct(T["exec_failed"] / e),
                   (lambda x: "100" if x == 1 else pct(x))(T["fix_ok"] / T["fix_calls"]),
                   pct(K["problem>=1"] / K["problem"]), pct(K["path-problem>=1"] / K["path-problem"])]
  top = qc["Top100"]
  S = lambda cs, k, sub="T": sum(top[c][sub][k] for c in cs)
  CG = ("C0", "C1", "G0", "G1")
  err = sum((top[c]["ERR"] for c in ORDER), collections.Counter())
  fixr = lambda cs: statistics.mean(top[c]["T"]["fix_ok"] / top[c]["T"]["fix_calls"] for c in cs)
  text = {"fixup errors: classes or predicates that do not exist (printed: 82%)": pct((err["api_member"] + err["unresolved_name"]) / sum(err.values())) + "%",
          "fixups repaired, mean of the configurations: Claude / Gemini (printed: about 92% / 98%)": f"{pct(fixr(('C0', 'C1')))}% / {pct(fixr(('G0', 'G1')))}%",
          "fixups repaired, mean of the configurations: GPT and DeepSeek (printed: about 2/3)": pct(fixr(("DC0", "DC1", "DR0", "DR1", "GPT0", "GPT1"))) + "%",
          "most failed executions (share)": t["Top100"]["GPT1"][3] + "%",
          "Top100 executions with 0 results (printed: about half)": pct(S(ORDER, "ran_zero") / S(ORDER, "exec")) + "%",
          "path-problem share of queries that ran / with results": f"{pct(S(ORDER, 'path-problem', 'K') / (S(ORDER, 'path-problem', 'K') + S(ORDER, 'problem', 'K')))}% / "
                                                                  f"{pct(S(ORDER, 'path-problem>=1', 'K') / (S(ORDER, 'path-problem>=1', 'K') + S(ORDER, 'problem>=1', 'K')))}%",
          "path-problem queries with results: Claude and Gemini / all": f"{S(CG, 'path-problem>=1', 'K')} / {S(ORDER, 'path-problem>=1', 'K')}",
          "path-problem queries leading to a confirmed finding: Claude and Gemini / all": f"{S(CG, 'path-problem', 'TP')} / {S(ORDER, 'path-problem', 'TP')}",
          "Hist20 C0 empty runs D / N": f"{t['Hist20 D']['C0'][2]}% / {t['Hist20 N']['C0'][2]}%",
          "Hist20 C0 problem result rate D / N": f"{pct(qc['Hist20 D']['C0']['K']['problem>=1'] / qc['Hist20 D']['C0']['K']['problem'], 0)}% / "
                                                 f"{pct(qc['Hist20 N']['C0']['K']['problem>=1'] / qc['Hist20 N']['C0']['K']['problem'], 0)}%"}
  return t, text


# ============================================================================ tool calls (Tab 8), agent cost shares
def table8():
  acc, n = collections.defaultdict(collections.Counter), collections.Counter()
  cost, tok = collections.Counter(), collections.Counter()
  for qm, t, qtc, rtc, vf, *u in db("top100").execute("""select cs.model, cs.temperature, cs.tool_calls, rs.tool_calls,
      ss.total_findings_validated, cs.model, cs.total_input_tokens, cs.total_output_tokens, rs.model, rs.total_input_tokens,
      rs.total_output_tokens, ss.model, ss.total_input_tokens, ss.total_output_tokens from scan_master sm
      join codeql_session cs using(codeql_session_id) join reviewer_session rs using(reviewer_session_id)
      join sanity_session ss using(sanity_session_id)"""):
    m = qm.lower()
    c = next(v for k, v in (("deepseek-chat", "DC"), ("deepseek-reasoner", "DR"), ("claude", "C"), ("gemini", "G"), ("gpt", "GPT")) if k in m) + str(int(t))
    n[c] += 1; q, r = json.loads(qtc or "{}"), json.loads(rtc or "{}")
    acc[c].update(eq=q.get("execute_codeql_query", 0), fq=q.get("fixup_codeql_query", 0), ecs=r.get("extract_code_snippet", 0),
                  gs=r.get("grep_search", 0), tf=r.get("trace_dataflow_path", 0), sf=r.get("submit_finding", 0), vf=vf or 0)
    for agent, (mm, i, o) in zip("QRS", (u[0:3], u[3:6], u[6:9])):
      if mm:
        cost[agent] += list_cost(mm, i, o); tok[agent] += (i or 0) + (o or 0)
  cols = ("eq", "fq", "ecs", "gs", "tf", "sf", "vf")
  t = {c: [f1(round(acc[c][k] / n[c], 1)) for k in cols] for c in ORDER}
  tc, tt = sum(cost.values()), sum(tok.values())
  per = lambda c, k: acc[c][k] / n[c]
  text = {"configurations that never call the tracer": f"{sum(acc[c]['tf'] == 0 for c in ORDER)}/10",
          "Gemini fixups per scan": rng(f1(per("G0", "fq")), f1(per("G1", "fq"))),
          "Claude snippet extractions per scan": f"{round(min(per(c, 'ecs') for c in ('C0', 'C1')))}--{round(max(per(c, 'ecs') for c in ('C0', 'C1')))}",
          "others' snippet extractions per scan": f"{round(min(per(c, 'ecs') for c in ORDER[2:]))}--{round(max(per(c, 'ecs') for c in ORDER[2:]))}",
          "Q share of cost / tokens": f"{pct(cost['Q'] / tc, 0)}% / {pct(tok['Q'] / tt, 0)}%",
          "R and S share of cost": pct((cost["R"] + cost["S"]) / tc, 0) + "%"}
  return t, text


# ============================================================================ R logs: code read (Tab 9), first tool
EXTRACT = re.compile(r"\[\*\] Extracting (.+):(\d+)-(\d+)")
SIZES = [(0, 1_000, "<1K"), (1_000, 5_000, "1K--5K"), (5_000, 20_000, "5K--20K"), (20_000, 100_000, "20K--100K"), (100_000, float("inf"), ">100K")]


def profile(scan_dir):
  for p in [os.path.join(scan_dir, "package_profile.json")] + sorted(glob.glob(os.path.join(os.path.dirname(os.path.dirname(scan_dir)), "*", os.path.basename(scan_dir), "package_profile.json"))):
    try:
      d = json.load(open(p)); return d.get("total_lines"), d.get("total_files")
    except (OSError, ValueError):
      continue
  return None, None


def union_lines(ranges):
  by = collections.defaultdict(list)
  for p, s, e in ranges:
    by[p].append((s, e))
  tot = 0
  for ivs in by.values():
    ivs.sort(); merged = []
    for s, e in ivs:
      if merged and s <= merged[-1][1] + 1:
        merged[-1][1] = max(merged[-1][1], e)
      else:
        merged.append([s, e])
    tot += sum(e - s + 1 for s, e in merged)
  return tot


GROUP = re.compile(r"\[\+\] Starting review for group (\S+)")
TOOL = re.compile(r"\[\*\] Tool call: (\w+)")


def r_log(scan_dir):
  """Extracted ranges (whole log) and, per R review group, the first tool call; R tool-call totals."""
  path = os.path.join(scan_dir, "agent_codeql_run.log")
  ranges, groups, tools = [], [], collections.Counter()
  if not os.path.exists(path):
    return ranges, groups, tools
  lines = open(path, errors="ignore").readlines()
  for l in lines:
    m = EXTRACT.search(l)
    if m and int(m.group(3)) >= int(m.group(2)):
      ranges.append((m.group(1), int(m.group(2)), int(m.group(3))))
  r0 = next((i for i, l in enumerate(lines) if " Security Review Session: " in l), None)
  if r0 is not None:
    s0 = next((i for i in range(r0 + 1, len(lines)) if " Sanity Check Session: " in lines[i]), len(lines))
    cur = None
    for l in lines[r0:s0]:
      if GROUP.search(l):
        cur = [None]; groups.append(cur); continue
      m = TOOL.search(l)
      if cur is not None and m:
        tools[m.group(1)] += 1
        if cur[0] is None:
          cur[0] = m.group(1)
  return ranges, groups, tools


def table9():
  scans = []
  for d in sorted(glob.glob(P("runs/top100_dec2025/*/*/"))):
    d = d.rstrip("/"); cfg = os.path.basename(os.path.dirname(d))
    ranges, groups, tools = r_log(d)
    tl, tf = profile(d)
    scans.append({"model": cfg.rsplit("-", 1)[0], "tl": tl, "tf": tf, "uniq": union_lines(ranges), "calls": len(ranges),
                  "files": len({p for p, _, _ in ranges}), "groups": groups, "tools": tools})

  def agg(ss):
    w = [s for s in ss if s["tl"]]
    avg_tl, avg_tf = sum(s["tl"] for s in w) / len(w), sum(s["tf"] or 0 for s in w) / len(w)
    return {"n": len(ss), "total": avg_tl, "uniq": sum(s["uniq"] for s in ss) / len(ss),
            "macro": sum(100 - 100 * s["uniq"] / s["tl"] for s in w) / len(w),
            "micro": 100 - 100 * sum(s["uniq"] for s in w) / sum(s["tl"] for s in w),
            "files": sum(s["files"] for s in ss) / len(ss) / avg_tf * 100, "avg_files": sum(s["files"] for s in ss) / len(ss),
            "avg_tf": avg_tf, "calls": sum(s["calls"] for s in ss) / len(ss)}
  row = lambda a: [thou(a["n"]), thou(round(a["total"])), str(round(a["uniq"])), f1(a["macro"]), f1(a["micro"]), f1(a["files"])]
  t = {"By package size": {lab: row(agg([s for s in scans if s["tl"] and lo <= s["tl"] < hi])) for lo, hi, lab in SIZES},
       "By model": {}}
  for m, lab in (("claude", "C0,1"), ("deepseek-chat", "DC0,1"), ("deepseek-reasoner", "DR0,1"), ("gemini", "G0,1"), ("gpt", "GPT0,1")):
    t["By model"][lab] = row(agg([s for s in scans if s["model"] == m]))
  a = agg(scans); t["All"] = row(a)
  groups = [g for s in scans for g in s["groups"]]
  raw_first = sum(1 for g in groups if g[0] in ("extract_code_snippet", "grep_search"))
  tools = sum((s["tools"] for s in scans), collections.Counter())
  cm = {m: agg([s for s in scans if s["model"] == m])["uniq"] for m in ("claude", "deepseek-chat")}
  text = {"unique lines read / files read of all / mean package size": f"{round(a['uniq'])} / {f1(a['avg_files'])} of {round(a['avg_tf'])} / {int(a['total'] / 1e3)}k",
          "snippet extractions per scan": f1(a["calls"]),
          "reduction below 1K / above 100K lines": f"{t['By package size']['<1K'][3]}% / {t['By package size']['>100K'][3]}%",
          "macro reduction": f1(a["macro"]) + "%",
          "Claude reads x more unique code than DeepSeek-chat": str(round(cm["claude"] / cm["deepseek-chat"])),
          "R's first action is raw (snippet or grep): share of review groups": f"{pct(raw_first / len(groups))}% of {thou(len(groups))}",
          "raw reads : structured traces": f"{round((tools['extract_code_snippet'] + tools['grep_search']) / tools['trace_dataflow_path'])} to 1"}
  return t, text


# ============================================================================ severity and CWE spread (Fig 2, 3)
NAMES = {"CWE-502": "Deserialization", "CWE-94": "Code injection", "CWE-22": "Path traversal", "CWE-78": "OS command inj.",
         "CWE-1333": "ReDoS", "CWE-611": "XXE", "CWE-327": "Broken crypto", "CWE-918": "SSRF", "CWE-377": "Insecure temp file",
         "CWE-89": "SQL injection"}


def first_cwe(c):
  try:
    L = json.loads(c) if c else []
  except Exception:
    L = re.findall(r"cwe-?\d+", c or "", re.I)
  for x in L:
    m = re.search(r"(\d+)", str(x))
    if m:
      return f"CWE-{int(m.group(1))}"
  return "none"


def outcomes():
  """Per counted finding: (config, severity, outcome, targeted CWE of the query that produced it)."""
  fin = final_labels(); con = db("top100")
  qcwe = {u: first_cwe(c) for u, c in con.execute("select codeql_query_uuid, cwe_ids from codeql_findings")}
  out = []
  for c, sev, rv, sv, f, uu in con.execute(f"""select {CFG}, r.severity, r.verdict, s.verdict, r.finding_id, r.codeql_query_uuids
      from reviewer_findings r join scan_master sm on sm.reviewer_session_id = r.reviewer_session_id
      join codeql_session cs on cs.codeql_session_id = sm.codeql_session_id left join sanity_findings s using(finding_id)"""):
    if f not in fin:
      continue
    t = next((qcwe[u] for u in re.findall(r"[\w-]{14,}", uu or "") if u in qcwe), "not traceable")
    o = "rrej" if (rv or "") == "fp" else ("srej" if (sv or "") == "fp" else ("tp" if fin[f] == "tp" else "kfp"))
    sev = (sev or "low").lower()
    out.append((c, sev if sev in ("low", "medium", "high", "critical") else "low", o, t))
  return out, collections.Counter(qcwe.values())


def figures2_3():
  rows, qn = outcomes()
  stage = {"Submitted by R": [r for r in rows], "Kept by S": [r for r in rows if r[2] in ("tp", "kfp")], "Confirmed TP": [r for r in rows if r[2] == "tp"]}
  f2_ = {f"{k} ({thou(len(v))})": {s: f"{round(100 * sum(r[1] == s for r in v) / len(v))}%" for s in ("low", "medium", "high", "critical")}
         for k, v in stage.items()}
  tgt = collections.defaultdict(collections.Counter)
  for r in rows:
    tgt[r[3]][r[2]] += 1
  f3_ = {f"{k} {NAMES[k]}": f"{thou(n)} q; confirmed/labelled {tgt[k]['tp']}/{sum(tgt[k].values())}" for k, n in qn.most_common(11) if k in NAMES}
  top4 = sum(n for _, n in qn.most_common(4)); ran = sum(qn.values())
  tp = stage["Confirmed TP"]
  text = {"submitted findings of low severity (printed: over half)": f"{pct(sum(r[1] == 'low' for r in rows) / len(rows))}%",
          "confirmed findings of high or critical severity": f"{pct(sum(r[1] in ('high', 'critical') for r in tp) / len(tp), 0)}%",
          "distinct targeted CWEs (queries without a CWE counted as one) / queries that ran": f"{len(qn)} / {thou(ran)}",
          "share of the queries of the top 4 CWEs": f"{pct(top4 / ran, 0)}%"}
  return f2_, f3_, text


# ============================================================================ single agent (Tab 11)
def jl(p):
  return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def detect(findings, issues):
  """issue id -> counted (R and S keep a finding in one of the issue's E1 windows)."""
  out = {}
  for i in issues:
    hit = False
    for f in findings:
      a = f.get("start_line")
      if a is None:
        continue
      b = f["end_line"] if f.get("end_line") is not None else a
      if window_hit(i, f.get("file_path") or "", a, b, "e1") and f.get("verdict") in KEEP and (f.get("sanity_check") or {}).get("verdict") in KEEP:
        hit = True
    out[i["id"]] = hit
  return out


def arm_stats(d, pipeline=False):
  cs = jl(os.path.join(d, "llm_calls.jsonl"))
  if pipeline:
    t = json.load(open(os.path.join(d, "cache_usage_summary.json")))["total"]; cost, nc = t["cost_usd_with_cache"], t["cost_usd_no_cache"]
  else:
    s = json.load(open(os.path.join(d, "sa_summary.json"))); cost, nc = s["cost_usd_with_cache"], s["cost_usd_no_cache"]
  return {"prompt": sum(c.get("prompt_tokens_total") or 0 for c in cs), "ctx": max(c.get("prompt_tokens_total") or 0 for c in cs),
          "cost": cost, "nc": nc}


def table11():
  pkgs = sorted({i["package"] for i in GT})
  base = "runs/single_agent_nov2026"
  arms = {"Pipeline": [], "Single (text)": [], "Single (native)": []}
  onset, text_turns = [], {"Single (text)": [0, 0], "Single (native)": [0, 0]}
  tracer = {"Pipeline": 0, "Single (text)": 0, "Single (native)": 0}
  for p in pkgs:
    issues = [i for i in GT if i["package"] == p]
    reps = []
    for rep in (1, 2, 3, 4):
      d = P(f"runs/nov2026/claude-0-r{rep}", p)
      s = json.load(open(os.path.join(d, "agent_sanity_report.json")))["findings"]
      det = detect(s, issues)
      reps.append({**arm_stats(d, True), "cve": sum(v for k, v in det.items() if ISSUES[k]["kind"] == "cve"),
                   "ack": sum(v for k, v in det.items() if ISSUES[k]["kind"] == "ack"),
                   "kept": sum(1 for f in s if f.get("verdict") in KEEP and (f.get("sanity_check") or {}).get("verdict") in KEEP)})
      tracer["Pipeline"] += json.load(open(os.path.join(d, "agent_reviewer_report.json")))["tool_calls"].get("trace_dataflow_path", 0) / 4
    arms["Pipeline"].append({k: statistics.mean(r[k] for r in reps) for k in reps[0]})
    for name, run in (("Single (text)", "claude-0-sa-r1"), ("Single (native)", "claude-0-sa-native-r1")):
      d = P(base, run, p)
      s = json.load(open(os.path.join(d, "agent_sanity_report.json")))["findings"]
      val = [f for f in s if f.get("verdict") != "dup" and f.get("sanity_check")]
      det = detect(s, issues)
      trace = jl(os.path.join(d, "sa_trace.jsonl"))
      tools = [t["name"] for r in trace for t in r["tools"]]
      tracer[name] += tools.count("trace_dataflow_path") + tools.count("trace_flow")
      text_turns[name][0] += sum(1 for r in trace if not r["tools"])
      text_turns[name][1] += json.load(open(os.path.join(d, "sa_summary.json")))["turns"]
      if name == "Single (text)":
        onset.append(next((r["turn"] for r in trace if not r["tools"]), None))
      arms[name].append({**arm_stats(d), "cve": sum(v for k, v in det.items() if ISSUES[k]["kind"] == "cve"),
                         "ack": sum(v for k, v in det.items() if ISSUES[k]["kind"] == "ack"),
                         "kept": sum(1 for f in val if f["verdict"] in KEEP and f["sanity_check"]["verdict"] in KEEP)})
  prec = single_agent_precision()
  T = {a: {k: sum(x[k] for x in v) for k in v[0]} for a, v in arms.items()}
  g = lambda x: f"{x:g}"
  t = {"CVEs (of 8) / Acks (of 4)": [f"{g(T[a]['cve'])} / {g(T[a]['ack'])}" for a in arms],
       "Findings kept": [f1(T["Pipeline"]["kept"])] + [g(T[a]["kept"]) for a in list(arms)[1:]],
       "Precision of kept findings": [f"{pct(prec['C0'][0] / prec['C0'][1])}--{pct(prec['C1'][0] / prec['C1'][1])}%",
                                      f"{prec['text'][0]}/{prec['text'][1]}", pct(prec["native"][0] / prec["native"][1]) + "%"],
       "Turns without a tool call": ["--"] + [f"{pct(text_turns[a][0] / text_turns[a][1], 0)}%" for a in list(arms)[1:]],
       "Data-flow tracer calls": [g(round(tracer[a], 2)) for a in arms],
       "Prompt tokens (M)": [f1(T[a]["prompt"] / 1e6) for a in arms],
       "Peak context (k tokens)": [f"{min(x['ctx'] for x in arms[a]) / 1e3:.0f}--{max(x['ctx'] for x in arms[a]) / 1e3:.0f}" for a in arms],
       "Cost with / without caching ($)": [f"{f1(T[a]['cost'])} / {f1(T[a]['nc'])}" for a in arms]}
  text = {"text history: most turns without a tool call from turn (median)": g(statistics.median(onset)),
          "native vs pipeline: prompt tokens / cost with caching / without": f"{f1(T['Single (native)']['prompt'] / T['Pipeline']['prompt'])}x / "
              f"{f1(T['Single (native)']['cost'] / T['Pipeline']['cost'])}x / {f1(T['Single (native)']['nc'] / T['Pipeline']['nc'])}x",
          "native precision": f"{pct(prec['native'][0] / prec['native'][1])}% ({prec['native'][0]}/{prec['native'][1]})"}
  return t, text


def single_agent_precision():
  """Precision of kept findings (R not fp, S tp/mr): single agent (its own labels) and the Dec 2025 C0/C1 scans."""
  e2 = db("e2_sa"); lab = dict(e2.execute("select finding_id, label from labels"))
  out = {}
  for tag in ("text", "native"):
    fs = [f for (f,) in e2.execute("""select r.finding_id from scan_master sm join reviewer_findings r
        on r.reviewer_session_id = sm.reviewer_session_id join sanity_findings s using(finding_id)
        where sm.package_version = ? and coalesce(r.verdict,'') != 'fp' and s.verdict in ('tp','mr')""", (tag,))]
    ls = [lab.get(f) for f in fs if lab.get(f) in ("tp", "fp")]
    out[tag] = (ls.count("tp"), len(ls))
  fin = final_labels(); pkgs = sorted({i["package"] for i in GT})
  for temp in (0, 1):
    fs = [f for (f,) in db("top100").execute(f"""select r.finding_id from scan_master sm join codeql_session cs using(codeql_session_id)
        join reviewer_findings r on r.reviewer_session_id = sm.reviewer_session_id join sanity_findings s using(finding_id)
        where cs.model like 'claude%' and cast(cs.temperature as int) = {temp} and sm.package_name in ({','.join('?' * len(pkgs))})
          and coalesce(r.verdict,'') != 'fp' and s.verdict in ('tp','mr')""", pkgs)]
    ls = [fin[f] for f in fs if f in fin]
    out[f"C{temp}"] = (ls.count("tp"), len(ls))
  return out


# ============================================================================ repeatability (Fig 4)
def e1_scans():
  """(config, rep, package) -> scan_id and cache summary, for completed, non-excluded reruns."""
  con = db("e1_nov2026"); excl = {e["scan_id"] for e in J("data/exclusions/excluded_scans.json")["excluded"]}
  pkgs = sorted({i["package"] for i in GT}); out = {}
  for cfg in ("C0", "C1"):
    for rep in (1, 2, 3, 4):
      rdir = P(f"runs/nov2026/claude-{cfg[1]}-r{rep}")
      log = open(os.path.join(rdir, "runner.log")).read() if os.path.exists(os.path.join(rdir, "runner.log")) else ""
      for pkg in pkgs:
        sdir = os.path.join(rdir, pkg)
        ends = re.findall(rf"\[E1\] (\S+) END\s+{cfg} r{rep} {re.escape(pkg)} rc=(\d+)", log)
        files = [os.path.join(sdir, f"agent_{k}_report.json") for k in ("codeql", "reviewer", "sanity")]
        if not ends or ends[-1][1] != "0" or not all(map(os.path.exists, files)):
          continue
        sid = json.load(open(files[0])).get("session_id")
        row = con.execute("""select sm.scan_id from scan_master sm join codeql_session cs using(codeql_session_id)
                             where cs.session_id=? and sm.package_name=?""", (str(sid), pkg)).fetchone()
        if not row or row[0] in excl:
          continue
        summ = os.path.join(sdir, "cache_usage_summary.json")
        t = json.load(open(summ))["total"] if os.path.exists(summ) else {}
        out[(cfg, rep, pkg)] = {"scan_id": row[0], "cache": t.get("cost_usd_with_cache"), "nocache": t.get("cost_usd_no_cache")}
  return out


def e1_costs():
  sc = e1_scans()
  return {c: {"saving": 1 - sum(v["cache"] for (cc, _, _), v in sc.items() if cc == c) / sum(v["nocache"] for (cc, _, _), v in sc.items() if cc == c)}
          for c in ("C0", "C1")}


def scan_state(con, scan_id, issue):
  hits = [(rv, sv) for f, a, b, rv, sv in con.execute("""select rf.file_path, rf.start_line, coalesce(rf.end_line, rf.start_line),
      rf.verdict, sf.verdict from scan_master sm join reviewer_findings rf on rf.reviewer_session_id = sm.reviewer_session_id
      left join sanity_findings sf on sf.reviewer_finding_id = rf.reviewer_finding_id and sf.sanity_session_id = sm.sanity_session_id
      where sm.scan_id=?""", (scan_id,)) if f and a is not None and window_hit(issue, f, a, b, "e1")]
  if any(rv in KEEP and sv in KEEP for rv, sv in hits):
    return "D"
  if any(rv in KEEP or rv == "dup" for rv, _ in hits):
    return "S"
  return "R" if hits else "."


def figure4():
  e1 = e1_scans(); top = db("top100"); e1db = db("e1_nov2026")
  dec = {}
  for sid, temp, pkg in top.execute("select sm.scan_id, cs.temperature, sm.package_name from scan_master sm join codeql_session cs using(codeql_session_id) where cs.model='claude-sonnet-4-5-20250929'"):
    dec[(f"C{int(temp)}", pkg)] = sid
  grid = {}
  for i in GT:
    grid[i["id"]] = {}
    for cfg in ("C0", "C1"):
      cells = ""
      for run in ("dec", 1, 2, 3, 4):
        st = scan_state(top, dec[(cfg, i["package"])], i) if run == "dec" else (
             scan_state(e1db, e1[(cfg, run, i["package"])]["scan_id"], i) if (cfg, run, i["package"]) in e1 else "?")
        cells += "†" if st == "D" and close(i["id"], cfg, str(run)) else st
      grid[i["id"]][cfg] = cells
  counted = lambda cfg, k, kind: sum(grid[i["id"]][cfg][k] in "D†" for i in GT if i["kind"] == kind)
  f = {"cells": grid, "CVEs (of 8)": {c: " ".join(str(counted(c, k, "cve")) for k in range(5)) for c in ("C0", "C1")},
       "Acks (of 4)": {c: " ".join(str(counted(c, k, "ack")) for k in range(5)) for c in ("C0", "C1")}}
  per = {c: [counted(c, k, "cve") for k in range(1, 5)] for c in ("C0", "C1")}
  every = {c: sum(all(grid[i["id"]][c][k] in "D†" for k in range(1, 5)) for i in GT) for c in ("C0", "C1")}
  only_dec_c0 = sum(grid[i["id"]]["C0"][0] in "D†" and not any(grid[i["id"]][c][k] in "D†" for c in ("C0", "C1") for k in range(1, 5))
                    and grid[i["id"]]["C1"][0] not in "D†" for i in GT)
  union = {k: sum(any(grid[i["id"]][c][r] in "D†" for c in ("C0", "C1") for r in range(1, 5)) for i in GT if i["kind"] == k) for k in ("cve", "ack")}
  text = {"CVEs per rerun C0 / C1": f"{rng(min(per['C0']), max(per['C0']))} / {rng(min(per['C1']), max(per['C1']))}",
          "December run CVEs C0 / C1": f"{counted('C0', 0, 'cve')} / {counted('C1', 0, 'cve')}",
          "issues in every rerun C0 / C1": f"{every['C0']} / {every['C1']}",
          "issues only in the December C0 run": str(only_dec_c0),
          "union of the eight reruns": f"{union['cve']} CVEs, {union['ack']} acks"}
  return f, text


# ============================================================================ current models (Tab 12)
E5CFG = {"deepseek/deepseek-v4-pro": "DS4", "gemini/gemini-4-carbon": "G4", "openai/gpt-6.2-sol": "GPT6", "claude-sonnet-5-5": "C5"}


def table12(t4, t6):
  ex = {e["scan_id"] for e in J("data/exclusions/excluded_scans_e5.json")["excluded"] if e.get("scan_id")}
  res = {c: {"del": set(), "srej": set()} for c in E5CFG.values()}
  for sid, pkg, m, fp, a, b, rv, sv in db("e5").execute("""select sm.scan_id, sm.package_name, cs.model, r.file_path, r.start_line,
      coalesce(r.end_line, r.start_line), r.verdict, s.verdict from reviewer_findings r
      join scan_master sm on sm.reviewer_session_id = r.reviewer_session_id join codeql_session cs using(codeql_session_id)
      left join sanity_findings s on s.reviewer_finding_id = r.reviewer_finding_id"""):
    if sid in ex or a is None:
      continue
    for i in GT:
      if pkg == i["package"] and window_hit(i, fp, a, b):
        if rv in KEEP:
          res[E5CFG[m]]["del" if sv in KEEP else "srej"].add(i["id"])
  cost, filt, refused, empty = {}, {}, {}, {}
  for c in E5CFG.values():
    wc, n = 0.0, 0; stop = collections.Counter(); ref = 0; no_r = 0
    for d in sorted(glob.glob(P("runs/nov2026/e5", f"{c}-r1", "*/"))):
      pkg = os.path.basename(d.rstrip("/")); n += 1
      f = os.path.join(d, "cache_usage_summary.json")
      if os.path.exists(f):
        wc += json.load(open(f))["total"]["cost_usd_with_cache"]
      rr = os.path.join(d, "agent_reviewer_report.json")
      no_r += (not os.path.exists(rr)) or not json.load(open(rr)).get("findings")
      for r in jl(os.path.join(d, "llm_calls.jsonl")):
        stop[(r.get("agent"), r.get("stop_reason"))] += 1
      logs = "".join(open(x, errors="ignore").read() for x in (os.path.join(d, "agent_codeql_run.log"),
                     P("runs/nov2026/e5", f"{c}-r1", f"{pkg}.stdout.log")) if os.path.exists(x))
      ref += "cyber_policy" in logs or "ContentPolicyViolation" in logs
    rc = sum(v for (a, _), v in stop.items() if a == "reviewer")
    cost[c], filt[c], refused[c], empty[c] = wc / n, (stop[("reviewer", "content_filter")] / rc if rc else None), ref, no_r
  kind = lambda s, k: sum(ISSUES[i]["kind"] == k for i in s)
  probe = J("data/reference_outputs/e5_recall_probe.json")["models"]
  knows = {m: {c for c, a in v["answers"].items() if a["answer"] == "yes"} for m, v in probe.items()}
  t = {"C1 (2025)": [t6["C1"][0], t6["C1"][1], f2(float(t4["Top100"]["C1"][3])) + "ˡ"]}
  for c, lab in (("C5", "C5 (2026)"), ("DS4", "DS4 (2026)"), ("G4", "G4 (2026)")):
    t[lab] = [str(kind(res[c]["del"], "cve")) + ("ᵏ" if c == "C5" else ""), str(kind(res[c]["del"], "ack")), f2(cost[c])]
  t["GPT6 (2026)"] = [f"refused ({refused['GPT6']}/10)", f2(cost["GPT6"])]
  srej_only = res["C5"]["srej"] - res["C5"]["del"]
  text = {"models that claim to know the 2025 CVE (CVE-ID-1) / any 2026 CVE": f"{sum('CVE-ID-1' in v for v in knows.values())} / {sum(bool(v - {'CVE-ID-1'}) for v in knows.values())}",
          "Sonnet 5.5 claims to know CVE-ID-1, which C5 delivers": str("CVE-ID-1" in knows.get("claude-sonnet-5-5", set()) and "CVE-ID-1" in res["C5"]["del"]),
          "December C1 cost with caching (estimated)": "$" + str(decimal.Decimal(t4["Top100"]["C1"][4]).quantize(decimal.Decimal("0.01"), decimal.ROUND_HALF_UP)),
          "issues C5's S rejected that its R surfaced": str(len(srej_only)),
          "G4: R calls content-filtered / packages without a reviewed finding": f"{pct(filt['G4'], 0)}% / {empty['G4']}",
          "GPT6: packages whose Q was refused": f"{refused['GPT6']}/10"}
  return t, text


# ============================================================================ SAST tools (Tab 13)
def spans(path):
  try:
    tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
  except Exception:
    return []
  return [(n.lineno, getattr(n, "end_lineno", n.lineno)) for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def innermost(sp, line):
  c = [s for s in sp if s[0] <= line <= s[1]]
  return min(c, key=lambda s: s[1] - s[0]) if c else None


def table13(t6):
  alerts = collections.defaultdict(list); vol = {"bandit": collections.Counter(), "opengrep": 0, "codeql": 0}
  for s in J("runs/sast_jan2026/bandit_scan.json")["scans"]:
    pkg = os.path.basename(s["package_path"].rstrip("/"))
    for r in s["results"]:
      vol["bandit"][r["issue_severity"]] += 1; lr = r.get("line_range") or [r["line_number"]]
      alerts[pkg].append(("bandit", r["filename"].lstrip("/"), min(lr), max(lr), r["test_id"], r["issue_severity"]))
  for s in J("runs/sast_jan2026/opengrep_scan.json")["scans"]:
    pkg = os.path.basename(s["package_path"].rstrip("/"))
    for r in s["results"]:
      vol["opengrep"] += 1
      alerts[pkg].append(("opengrep", r["path"].split(pkg + "/", 1)[-1], r["start"]["line"], r["end"]["line"], r["check_id"].split(".")[-1], ""))
  for s in J("runs/sast_jan2026/codeql_scan.json")["scans"]:
    for r in s["findings"]:
      vol["codeql"] += 1; loc = r["locations"][0]["physicalLocation"]; reg = loc.get("region", {})
      alerts[s["package_name"]].append(("codeql", loc["artifactLocation"]["uri"], reg.get("startLine"), reg.get("endLine", reg.get("startLine")), r["ruleId"], ""))
  # an alert is near an issue when it overlaps an issue window or sits in the same function (Python ast over sources/)
  near = collections.defaultdict(set)
  for i in GT:
    for tool, rel, s0, e0, rule, sev in alerts.get(i["package"], []):
      for suf, lo, hi in i["match"]:
        if not rel.endswith(suf):
          continue
        ok = s0 <= hi and (e0 or s0) >= lo
        src = P("sources", i["package"], rel)
        if not ok and os.path.exists(src):
          sp = spans(src); fa = innermost(sp, s0)
          ok = bool(fa) and fa in {innermost(sp, l) for l in range(lo, hi + 1)}
        if ok:
          near[(tool, i["id"])].add((rule, sev))
  dec = J("data/ground_truth/sast_decisions.json")["counted"]
  t, check = {}, {}
  for tool, lab, n in (("opengrep", "Opengrep (Semgrep rules)", vol["opengrep"]),
                       ("bandit", "Bandit (medium, high)", vol["bandit"]["MEDIUM"] + vol["bandit"]["HIGH"]),
                       ("codeql", "CodeQL default suite", vol["codeql"])):
    counted = dec[tool]
    for iid, rule in counted.items():   # every counted alert must exist near the issue (Bandit: medium or high)
      check[f"{tool}: {iid}"] = any(r == rule and (tool != "bandit" or s in ("MEDIUM", "HIGH")) for r, s in near[(tool, iid)])
    t[lab] = [thou(n), str(sum(ISSUES[i]["kind"] == "cve" for i in counted)), str(sum(ISSUES[i]["kind"] == "ack" for i in counted))]
  t["QRS C1 (kept by S)"] = [t6["C1"][2].split(" → ")[1], t6["C1"][0], t6["C1"][1]]
  hit = {i for d in dec.values() for i in d} | set(J("data/ground_truth/sast_decisions.json")["low_severity_only"])
  text = {"issues Opengrep / Bandit fire at": f"{len(dec['opengrep'])}/12 / {len(dec['bandit'])}/12",
          "Bandit low-severity alerts": thou(vol["bandit"]["LOW"]),
          "issues with no matching alert in any tool": f"{12 - len(hit)}/12",
          "every counted alert is present in the raw output at the issue": str(all(check.values()))}
  return t, text


# ============================================================================ CWE-Bench-Java (Tab 14)
def table14():
  stats = J("data/cwe_bench_java/java_dataset_stats.json")
  ins = {x["cve_id"]: x for x in stats if not x["result"].startswith("OUT_OF_SCOPE")}
  cwe = {c: x["cwe"] for c, x in ins.items()}
  det = {"QRS": {c for c, x in ins.items() if x["result"] == "SUCCESS"}, "Graded": {c for c, x in ins.items() if x["result"].startswith("SUCCESS")}}
  e4 = {}
  for line in open(P("runs/iris_e4_nov2026/logs/e4_projects.jsonl")):
    x = json.loads(line)
    if x.get("status") == "ok":
      e4[x["cve"]] = x
  ph = {c: x["iris_eval"]["posthoc_filter_result"] for c, x in e4.items() if c in ins}
  det["IRIS + Sonnet 4.6"] = {c for c, r in ph.items() if r["recall_method"]}
  flips = set()
  for proj, v in J("runs/iris_e4_nov2026/logs/posthoc_reeval.json").items():
    c = next((k for k in ins if k in proj), None)
    if c and ((v.get("variants", {}).get("fix12") or {}).get("posthoc") or {}).get("recall_method") and c not in det["IRIS + Sonnet 4.6"]:
      flips.add(c)
  pub = {}
  for name in ("IRIS+GPT-4", "CodeQL"):
    pub[name] = {r["CVE"].strip(): r for r in csv.DictReader(open(P("data/cwe_bench_java/iris_v1_results", f"{name}.csv")))}
  det["IRIS + GPT-4"] = {c for c in ins if pub["IRIS+GPT-4"].get(c, {}).get("Recall", "").strip() == "1"}
  det["CodeQL"] = {c for c in ins if pub["CodeQL"].get(c, {}).get("Recall", "").strip() == "1"}
  med = lambda v: statistics.median(v)
  alerts = lambda name: med([int(pub[name][c]["Alerts"]) for c in ins if pub[name].get(c, {}).get("Alerts", "").strip().isdigit()])
  con = db("iris")
  n, cost = con.execute("""select count(*), sum(coalesce(c.estimated_cost_usd,0)+coalesce(r.estimated_cost_usd,0)+coalesce(z.estimated_cost_usd,0))
      from scan_master s join codeql_session c using(codeql_session_id) left join reviewer_session r using(reviewer_session_id)
      left join sanity_session z using(sanity_session_id)""").fetchone()
  kept = [k for (k,) in con.execute("""select (select count(*) from reviewer_findings r join sanity_findings z
      on z.reviewer_finding_id=r.reviewer_finding_id where r.reviewer_session_id=s.reviewer_session_id
      and coalesce(r.verdict,'')!='fp' and coalesce(z.verdict,'')!='fp') from scan_master s""")]
  e4c = [e4[c] for c in ins if c in e4]
  fmt = lambda x: f"{x:g}"
  per = lambda k: [str(sum(1 for x in det[k] if cwe[x] == w)) for w in ("cwe-022", "cwe-078", "cwe-079", "cwe-094")]
  t = {"CodeQL": [str(len(det["CodeQL"]))] + per("CodeQL") + [fmt(alerts("CodeQL")), "--"],
       "IRIS + GPT-4": [str(len(det["IRIS + GPT-4"]))] + per("IRIS + GPT-4") + [fmt(alerts("IRIS+GPT-4")), "--"],
       "IRIS + Sonnet 4.6": [f"{len(det['IRIS + Sonnet 4.6'])}ᵃ"] + per("IRIS + Sonnet 4.6") +
                            [fmt(med([r["num_results"] for r in ph.values()])), f2(sum(x["llm"]["total"]["cost_usd"] for x in e4c) / len(e4c))],
       "QRS C3 (Sonnet 4.6)": [str(len(det["QRS"]))] + per("QRS") + [fmt(med(kept)), f2(cost / n)],
       "Graded": [str(len(det["Graded"]))] + per("Graded")}
  ql = {r["CVE ID"].strip(): r for r in csv.DictReader(open(P("data/cwe_bench_java/qlcoder_iclr2026_results/QLCoder.csv")))}
  shared = {c for c in ins if c in ql}
  S, I = det["QRS"], det["IRIS + Sonnet 4.6"]
  N = len(ins)
  oos = collections.Counter(x["result"] for x in stats if x["result"].startswith("OUT_OF_SCOPE"))
  n_src = sum(v for k, v in oos.items() if re.search(r"VULN IN|DEPENDENCY", k))
  n_cwe = sum(v for k, v in oos.items() if re.search(r"NO CWE|MISCATEGORIZED|\(CWE-", k))
  text = {"CVEs in the benchmark / excluded before scanning": f"{len(stats)} / {len(stats) - N}",
          "in-scope CVEs / projects": f"{N} / {len({ins[c]['package'] for c in ins})}",
          "excluded: version not available / outside Java sources / does not build / CWE outside the 4 classes":
              f"{oos['OUT_OF_SCOPE (VERSION NOT AVAILABLE)']} / {n_src} / {oos['OUT_OF_SCOPE (CANNOT BUILD)']} / {n_cwe}",
          "in-scope CVEs per CWE class (022 / 078 / 079 / 094)": " / ".join(str(sum(1 for c in ins if cwe[c] == w)) for w in ("cwe-022", "cwe-078", "cwe-079", "cwe-094")),
          "QRS / IRIS + Sonnet 4.6 / CodeQL detection rate": f"{pct(len(S) / N)}% / {pct(len(I) / N)}% / {pct(len(det['CodeQL']) / N)}%",
          "partial hits added by manual grading / graded rate": f"{len(det['Graded']) - len(S)} / {pct(len(det['Graded']) / N)}%",
          "IRIS + Sonnet 4.6 with the reply-parsing bug fixed": str(len(I | flips)),
          "QRS and IRIS + Sonnet 4.6: both / QRS only / IRIS only": f"{len(S & I)} / {len(S - I)} / {len(I - S)}",
          "QLCoder on the shared CVEs: detected / shared (QRS, IRIS + Sonnet 4.6)":
              f"{sum(1 for c in shared if ql[c]['vuln_recall_method'].strip().upper() == 'TRUE')} / {len(shared)} ({len(S & shared)}, {len(I & shared)})"}
  return t, text


# ============================================================================ Hist20 (Tab 2)
H20CFG = {"claude-sonnet-4-5-20250929": "C0", "gpt-5.1": "GPT0", "gemini/gemini-3-pro-preview": "G0",
          "gemini/gemini-3.1-pro-preview": "G0", "deepseek/deepseek-reasoner": "DR0"}


def table2():
  ref = J("data/ground_truth/hist20_targets.json")
  targets = {t["package"]: t for t in ref["targets"]}
  con = db("hist20"); cells, arms = {}, collections.defaultdict(collections.Counter)
  for sid, pkg, model in con.execute("select sm.scan_id, sm.package_name, cs.model from scan_master sm join codeql_session cs using(codeql_session_id) order by sm.scan_id"):
    if sid == 121:   # Gemini 3.1 Pro refused the task: G0 has no N arm
      continue
    cfg, arm = H20CFG[model], "D" if sid <= 100 else "N"
    kept = con.execute("""select r.file_path, r.start_line, r.end_line from reviewer_findings r join scan_master s
        on s.reviewer_session_id=r.reviewer_session_id join sanity_findings z on z.reviewer_finding_id=r.reviewer_finding_id
        where s.scan_id=? and r.verdict in ('tp','mr') and z.verdict in ('tp','mr')""", (sid,)).fetchall()
    hyps = [h or "" for (h,) in con.execute("select f.hypothesis from codeql_findings f join scan_master s using(codeql_session_id) where s.scan_id=?", (sid,))]
    t = targets[pkg]
    hit = any(a is not None and (fp.endswith(wf) or wf.endswith(fp)) and a <= wb and (b or a) >= wa
              for fp, a, b in kept if fp for wf, wa, wb in t["locs"])
    k = f"{cfg}|{arm}|{pkg}"
    dec = ref["decisions"].get(k, {})
    hit = dec.get("credit", hit)
    cells[(pkg, cfg, arm)] = "D" if hit and arm == "D" else "N" if hit else ("D†" if arm == "D" else "N†") if dec.get("close_candidate") else "-"
    arms[(cfg, arm)].update(scans=1, kept=len(kept), named=any(cve in h for h in hyps for cve in t["cves"]),
                            det=cells[(pkg, cfg, arm)] != "-")
  CF = ("C0", "GPT0", "G0", "DR0")
  t = {}
  for pkg in sorted(targets, key=lambda p: (p.split("-")[0], [int(x) if x.isdigit() else x for x in p.split("-")[1].split(".")])):
    t[re.sub(r"^(.*-\d+\.\d+)\.0$", r"\1", pkg)] = {c: cells[(pkg, c, "D")] + ("" if c == "G0" else " " + cells[(pkg, c, "N")]) for c in CF}
  both = lambda f, c: f"{f(c, 'D')} / {f(c, 'N') if (c, 'N') in arms else '--'}"
  t["Detected (D / N)"] = {c: both(lambda c, a: arms[(c, a)]["det"], c) for c in CF}
  t["Kept per scan (D / N)"] = {c: both(lambda c, a: f1(arms[(c, a)]["kept"] / arms[(c, a)]["scans"]), c) for c in CF}
  t["Q names the CVE (D / N)"] = {c: both(lambda c, a: arms[(c, a)]["named"], c) for c in CF}
  dn = {c: arms[(c, "D")]["det"] for c in CF}
  kps = [arms[k]["kept"] / arms[k]["scans"] for k in arms]
  text = {"packages / CVEs / CWEs": f"{len(targets)} / {sum(len(x['cves']) for x in targets.values())} / {len({w for x in targets.values() for w in x['cwes']})}",
          "targets detected with directives by any configuration": f"{sum(any(cells[(p, c, 'D')] != '-' for c in CF) for p in targets)}/20",
          "detected per configuration with directives": f"{min(dn.values())}--{max(dn.values())}",
          "targets lost without directives C0 / GPT0": f"{arms[('C0', 'D')]['det'] - arms[('C0', 'N')]['det']} / {arms[('GPT0', 'D')]['det'] - arms[('GPT0', 'N')]['det']}",
          "findings kept per scan, every arm": f"{round(min(kps))}--{round(max(kps))}"}
  return t, text


# ============================================================================ datasets and configurations
def datasets():
  top = J("data/datasets/top100_dataset.json")
  dl = sorted(top, key=lambda x: x["downloads_last_month"])
  gh = [x for x in top if "github.com" in (x.get("github_url") or "")]
  num = lambda k: [x for x in top if isinstance(x.get(k), int) and x.get(k)]
  pk = lambda k: (min(num(k), key=lambda x: x[k]), max(num(k), key=lambda x: x[k]))
  cve_pk = {i["package"] for i in GT if i["kind"] == "cve"}; all_pk = {i["package"] for i in GT}
  by = {x["full_name"]: x for x in top}
  (c0, c1), (m0, m1) = pk("contributors"), pk("commits")
  fam = {re.sub(r"\d$", "", c) for (c,) in db("top100").execute(f"select distinct {CFG} from scan_master sm join codeql_session cs using(codeql_session_id)")}
  nscans, ncfg = db("top100").execute(f"select count(*), count(distinct {CFG}) from scan_master sm join codeql_session cs using(codeql_session_id)").fetchone()
  return {"Top100 scans / configurations / models (5 models x 2 temperatures)": f"{thou(nscans)} / {ncfg} / {len(fam)}",
          "downloads per month: min (package) / max (package) (printed: 144 million / 1.4 billion)": f"{dl[0]['downloads_last_month'] / 1e6:.1f}M ({dl[0]['full_name']}) / {dl[-1]['downloads_last_month'] / 1e9:.1f}B ({dl[-1]['full_name']})",
          "packages with a GitHub repository": f"{len(gh)}%",
          "contributors: min (package) / max (package)": f"{c0['contributors']} ({c0['full_name']}) / {c1['contributors'] / 1e3:.1f}k ({c1['full_name']})",
          "commits: min (package) / max (package)": f"{m0['commits']} ({m0['full_name']}) / {m1['commits'] / 1e3:.1f}k ({m1['full_name']})",
          "packages with a CVE: count / monthly downloads (B) / dependent repositories (printed: almost 3 billion; 18k to 2.3 million)": f"{len(cve_pk)} / {sum(by[p]['downloads_last_month'] for p in cve_pk) / 1e9:.2f} / "
              f"{min(by[p]['used_by'] for p in cve_pk) / 1e3:.0f}k--{max(by[p]['used_by'] for p in cve_pk) / 1e6:.1f}M",
          "all affected packages: count / monthly downloads (B) (printed: over 3 billion)": f"{len(all_pk)} / {sum(by[p]['downloads_last_month'] for p in all_pk) / 1e9:.2f}"}


def table15():
  short = lambda m: re.sub(r"^(gemini|deepseek|openai)/", "", re.sub(r"-\d{8}$", "", m or ""))
  out = {}
  sets = (("top100", None), ("iris", None), ("e2_sa", None), ("e5", J("data/exclusions/excluded_scans_e5.json")["excluded"]))
  for s, ex in sets:
    exs = {e["scan_id"] for e in ex or [] if e.get("scan_id")}
    for sid, qm, rm, t, mt in db(s).execute("""select sm.scan_id, cs.model, rs.model, cs.temperature, cs.max_tokens from scan_master sm
        join codeql_session cs using(codeql_session_id) left join reviewer_session rs using(reviewer_session_id)"""):
      if sid in exs:
        continue
      key = {"top100": None, "iris": "C3", "e2_sa": "Single", "e5": E5CFG.get(qm)}[s]
      if s == "top100":
        key = next(v for k, v in (("claude", "C"), ("deepseek-chat", "DC"), ("deepseek-reasoner", "DR"), ("gemini", "G"), ("gpt", "GPT")) if k in qm) + "0,1"
      o = out.setdefault(key, {"q": set(), "r": set(), "t": set(), "out": set()})
      o["q"].add(short(qm)); o["r"].add(short(rm)); o["t"].add("def." if t is None else f"{t:g}"); o["out"].add(f"{round(mt / 1000)}k")
  j = lambda s: ", ".join(sorted(s, key=lambda x: (len(x), x)))
  return {k: [j(v["q"]), j(v["r"]), j(v["t"]), j(v["out"])] for k, v in out.items()}


# ============================================================================ appendix figures (Fig 5-7)
def appendix(t4, dl):
  rows, _ = outcomes()
  fin = final_labels()
  tps = [(c, pkg, (fp or "").lstrip("./"), a or 0) for c, _, pkg, f, lab, rv, sv in labelled_top100()
         if lab == "tp" and (rv or "") != "fp" and (sv or "") != "fp"
         for fp, a in db("top100").execute("select file_path, start_line from reviewer_findings where finding_id=?", (f,))]
  clusters = []
  for c, pkg, f, ln in sorted(tps, key=lambda t: (t[1], t[2], t[3])):
    for cl in clusters:
      if cl[0] == pkg and cl[1] == f and any(abs(ln - x) <= 10 for x in cl[2]):
        cl[2].append(ln); cl[3].add(c); break
    else:
      clusters.append([pkg, f, [ln], {c}])
  only = collections.Counter(next(iter(cl[3])) for cl in clusters if len(cl[3]) == 1)
  tp = collections.Counter(r[0] for r in rows if r[2] == "tp")
  fig5 = {c: f"{tp[c]} {only[c]}" for c in ORDER}
  fig6 = {c: f"{len([i for i in dl[c] if ISSUES[i]['kind'] == 'cve'])}+{len([i for i in dl[c] if ISSUES[i]['kind'] == 'ack'])}, ${f2(float(t4['Top100'][c][3]))}" for c in ORDER}
  con = db("top100"); focus = collections.defaultdict(collections.Counter)
  for c, w in con.execute(f"select {CFG}, q.cwe_ids from codeql_findings q join codeql_session cs using(codeql_session_id)"):
    focus[c][first_cwe(w)] += 1
  tot = sum((collections.Counter({k: v for k, v in focus[c].items() if k != "none"}) for c in ORDER), collections.Counter())
  cw = [k for k, _ in tot.most_common(8)]
  fig7 = {}
  for c in ORDER:
    n = sum(focus[c].values()); row = [focus[c][k] for k in cw] + [n - sum(focus[c][k] for k in cw)]
    fig7[c] = " ".join(f"{100 * x / n:.0f}" for x in row)
  text = {"distinct confirmed locations / found by one configuration": f"{len(clusters)} / {sum(len(cl[3]) == 1 for cl in clusters)}",
          "Fig 7 columns (top 8 targeted CWEs)": ", ".join(cw)}
  return fig5, fig6, fig7, text


# ============================================================================ main
def metrics_baseline(c):
  rows = [r for r in labelled_top100() if r[0] == c]
  pos = sum(r[4] == "tp" for r in rows)
  return max(pos, len(rows) - pos) / len(rows)


def empty_scans(c):
  return db("top100").execute(f"""select count(*) from scan_master sm join codeql_session cs using(codeql_session_id)
      where {CFG} = ? and not exists (select 1 from reviewer_findings r where r.reviewer_session_id = sm.reviewer_session_id)""", (c,)).fetchone()[0]


def compare(paper, comp, path="", cols=None):
  """(path, paper value, computed value) for every number; table rows are compared cell by cell."""
  if isinstance(paper, dict):
    out = []
    for k, v in paper.items():
      if not k.startswith("_"):
        out += compare(v, comp.get(k, "<missing>") if isinstance(comp, dict) else "<missing>",
                       f"{path} / {k}" if path else k, paper.get("_columns", cols))
    return out
  if isinstance(paper, list):
    comp = comp if isinstance(comp, list) and len(comp) == len(paper) else ["<missing>"] * len(paper)
    return [(f"{path} / {cols[i] if cols and i < len(cols) else i}", a, b) for i, (a, b) in enumerate(zip(paper, comp))]
  return [(path, paper, comp)]


def main():
  print("Rebuilding the result databases from runs/ ...", flush=True)
  res = {}
  t3, t6, dl = table3_6()
  t4, t4x = table4()
  t10, t10x = table10()
  res["Table 2: Hist20"], res["Text: Hist20"] = table2()
  res["Table 3: Top100 confirmed issues"] = t3
  res["Table 4: Average scan metrics"], res["Text: average scan metrics"] = t4, t4x
  res["Table 5: Judge agreement"], res["Text: labels"] = table5()
  res["Table 6: Performance per configuration"] = t6
  s6 = {c: 1 - int(t6[c][2].split(" → ")[1]) / int(t6[c][2].split(" → ")[0]) for c in ORDER}
  res["Text: performance"] = {
      "union of all configurations: CVEs / acks; most CVEs by one configuration": f"{t6['All'][0]} / {t6['All'][1]}; {max(int(t6[c][0].rstrip('†')) for c in ORDER)}",
      "best configurations deliver (CVEs / acks)": f"{t6['C1'][0]} / {t6['C1'][1]}",
      "precision after S ranges": f"{pct(min(float(t6[c][4]) for c in ORDER))}--{pct(max(float(t6[c][4]) for c in ORDER))}%",
      "most precise configuration: precision / MCC / CVEs": f"G1: {pct(float(t6['G1'][4]))}% / {float(t6['G1'][7]):.2f} / {t6['G1'][0].rstrip('†')}",
      "C0 and C1 precision": f"{pct(float(t6['C1'][4]))}--{pct(float(t6['C0'][4]))}%",
      "majority baseline per configuration": "{}--{}".format(*[f"{x:.3f}" for x in (min(metrics_baseline(c) for c in ORDER), max(metrics_baseline(c) for c in ORDER))]),
      "S rejects of R's positives: Claude Haiku and DeepSeek-chat / GPT-4.1 / Gemini 2.5 Pro and DeepSeek-reasoner":
          f"{pct(min(s6[c] for c in ('C0', 'C1', 'DC0', 'DC1')), 0)}--{pct(max(s6[c] for c in ('C0', 'C1', 'DC0', 'DC1')), 0)}% / "
          f"{pct(min(s6[c] for c in ('GPT0', 'GPT1')), 0)}--{pct(max(s6[c] for c in ('GPT0', 'GPT1')), 0)}% / "
          f"{pct(min(s6[c] for c in ('G0', 'G1', 'DR0', 'DR1')), 0)}--{pct(max(s6[c] for c in ('G0', 'G1', 'DR0', 'DR1')), 0)}%",
      "cost per TP, Claude and Gemini": f"${min(float(t6[c][8]) for c in ('C0', 'C1', 'G0', 'G1')):.2f}--${max(float(t6[c][8]) for c in ('C0', 'C1', 'G0', 'G1')):.2f}",
      "DeepSeek-chat scans with nothing to submit (of 100)": "{}--{}".format(*sorted(empty_scans(c) for c in ("DC0", "DC1"))),
      "DeepSeek cost per scan": f"${min(float(t4['Top100'][c][3]) for c in ORDER[2:6]):.2f}--${max(float(t4['Top100'][c][3]) for c in ORDER[2:6]):.2f}"}
  res["Table 7: Query generation"], res["Text: query generation"] = table7()
  res["Table 8: Tool calls per scan"], res["Text: tool calls"] = table8()
  f2_, f3_, f23x = figures2_3()
  res["Figure 2: Severity per stage"], res["Figure 3: Top 10 CWEs from Q"], res["Text: severity and CWEs"] = f2_, f3_, f23x
  res["Table 9: Code read by R"], res["Text: code reduction"] = table9()
  res["Table 10: Stage ablation"], res["Text: stage ablation"] = t10, t10x
  res["Table 11: Single agent"], res["Text: single agent"] = table11()
  res["Figure 4: Repeatability"], res["Text: repeatability"] = figure4()
  res["Table 12: Current models"], res["Text: current models"] = table12(t4, t6)
  res["Table 13: SAST tools"], res["Text: SAST tools"] = table13(t6)
  res["Table 14: CWE-Bench-Java"], res["Text: CWE-Bench-Java"] = table14()
  res["Text: datasets"] = datasets()
  res["Table 15: Configurations"] = table15()
  f5, f6, f7, fx = appendix(t4, dl)
  res["Figure 5: Outcome per configuration (TP, Only)"], res["Figure 6: Cost vs issues"], res["Figure 7: Query focus (%)"], res["Text: appendix figures"] = f5, f6, f7, fx
  json.dump(res, open(P("results.json"), "w"), indent=1, ensure_ascii=False)
  paper = J("paper_numbers.json")
  total = bad = 0
  for el, v in paper.items():
    if el.startswith("_"):
      continue
    cells = compare(v, res.get(el, {}))
    d = [c for c in cells if c[1] != c[2]]
    total += len(cells); bad += len(d)
    print(f"{'OK  ' if not d else 'DIFF'} {el}  ({len(cells) - len(d)}/{len(cells)})")
    for path, a, b in d:
      print(f"       {path}: paper {a!r}, computed {b!r}")
  print(f"\n{total - bad}/{total} numbers of the paper reproduced. Computed values: results.json")
  sys.exit(1 if bad else 0)


if __name__ == "__main__":
  main()
