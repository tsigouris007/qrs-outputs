#!/bin/bash
# E4: run IRIS v1 (Claude Sonnet 4.6 adapter) on ONE CWE-Bench-Java project, inside iris-e4:v1 via e4_entry.sh.
# Usage (in container): run_one.sh <project_slug> <cwe e.g. CWE-022> <cve>
# Steps as in IRIS's README: fetch+build (cwe-bench-java setup.py --filter), CodeQL DB (scripts/build_codeql_dbs.py),
# IRIS (src/neusym_vul.py --query cwe-XXXwLLM --run-id e4 --llm claude-sonnet-4-6, all other options at IRIS defaults:
# seed 1234, API batch 30, func-param batch 20, 3 threads). Stage timings + rc appended to /e4/runs.jsonl;
# per-stage stdout/stderr in /e4/<slug>/.
set -uo pipefail
SLUG=$1; CWE=$2; CVE=$3
Q="cwe-$(echo "$CWE" | sed -E 's/CWE-0*//; s/^/000/; s/.*(...)$/\1/')wLLM"
L=/e4/$SLUG; mkdir -p "$L"
export E4_PROJECT=$SLUG E4_CVE=$CVE E4_CWE=$CWE
cd /iris
rec() { python - "$@" <<'EOF'
import json, sys, time
slug, stage, rc, t0, t1 = sys.argv[1:6]
with open("/e4/runs.jsonl", "a") as f:
  f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "project": slug, "stage": stage, "rc": int(rc),
                      "seconds": round(float(t1) - float(t0), 1)}) + "\n")
EOF
}
stage() {  # stage <name> <cmd...>
  local name=$1; shift; local t0; t0=$(date +%s.%N)
  echo "[run_one] $(date '+%F %T') $SLUG: $name ..."
  "$@" > "$L/$name.log" 2>&1; local rc=$?
  rec "$SLUG" "$name" "$rc" "$t0" "$(date +%s.%N)"
  echo "[run_one] $(date '+%F %T') $SLUG: $name rc=$rc"
  return $rc
}
stage fetch_build python3 data/cwe-bench-java/scripts/setup.py --filter "$SLUG" || exit 1
# setup.py returns 0 even if the build fails; build_one.py writes build-info/<slug>.json only on success.
[ -f "data/cwe-bench-java/build-info/$SLUG.json" ] || { echo "[run_one] build not successful (see $L/fetch_build.log)"; exit 2; }
stage codeql_db python3 scripts/build_codeql_dbs.py --project "$SLUG" || exit 3
[ -d "data/codeql-dbs/$SLUG" ] || { echo "[run_one] no CodeQL DB"; exit 3; }
stage iris python3 src/neusym_vul.py --query "$Q" --run-id e4 --llm claude-sonnet-4-6 "$SLUG" || exit 4
echo "[run_one] done $SLUG ($Q)"
