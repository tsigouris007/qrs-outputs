# QRS: artifact for auditing the paper's numbers

This repository holds the raw outputs of every scan reported in the paper *QRS: Agentic CodeQL Synthesis for
Vulnerability Discovery in Open-Source Packages*, the expert labels, the inputs the agents received, and one script that
recomputes every number of the paper from the raw outputs and compares it with the paper.

## Quick start

Requirements: Python 3.9 or newer, standard library only.

```bash
python3 verify.py
```

`verify.py` rebuilds the result databases in memory from `runs/` (no database is shipped), computes every table, figure
and in-text number, writes them to `results.json` and compares each one with `paper_numbers.json` (the values as printed
in the paper). It prints one line per paper element and every value that differs; it takes about 10 seconds.

## Layout

| Path | Content |
|---|---|
| `verify.py` | The verification engine: one function per paper element (`table2`, ..., `table15`, `figure4`, ...) |
| `paper_numbers.json` | Every number of the paper as printed, keyed by paper element; `results.json` has the same keys |
| `runs/` | Raw scan outputs, one folder per scan (see [runs/README.md](runs/README.md)) |
| `data/labels/` | Expert label per finding (`finding_id, label, severity, flags`), one file per experiment |
| `data/label_audit.csv` | The 1,000-finding label audit: the expert's label, both blind judges' labels and the final label |
| `data/label_audit_instructions.md` | The instructions the two judges received |
| `data/ground_truth/` | The 12 confirmed Top100 issues (locations, close candidates), the Hist20 targets and hand decisions, the SAST decisions |
| `data/manifests/` | Scan order and row ids of the original result databases, one file per experiment |
| `data/exclusions/` | Scans excluded from the reruns (toolchain or network failures, superseded runs), with the reason |
| `data/datasets/` | The three datasets (package lists, versions, CVEs) |
| `data/cwe_bench_java/` | CWE-Bench-Java scope and QRS results per CVE; IRIS v1 and QLCoder published results |
| `data/reference_outputs/` | Output of the recall probe, which cannot run offline |
| `pipeline/` | What the agents received: system prompts, the CodeQL knowledge schemas, strategy directives, tool code |
| `sources/` | 31 unmodified source files from the public PyPI packages (function spans for the SAST comparison) |
| `reference/` | The two scripts that cannot run offline (see below) |

## Labels

One expert labelled every finding R submitted (`tp`, `fp`, or `dup` for a repeat). Two LLM judges from different vendors
labelled a stratified sample of 1,000 findings, blind to every verdict and to each other; `data/label_audit.csv` lists, per
sampled finding, the expert's label, both judges' labels and the final label. The expert re-examined the 124 findings that
both judges contested and changed 93; that re-examination is the final label, and it is the label in `data/labels/top100.csv`.
A duplicate counts once (`final_labels()` in `verify.py`).

An issue is delivered by a scan when R and S keep a finding at the issue's location (`data/ground_truth/top100_issues.json`);
a delivered finding that states another or a similar weakness is a close candidate (†), decided by hand and recorded there.

## What was removed or changed for the release

- **Proof-of-concept exploits.** The `exploit_payload` field is removed from every finding (17,640 occurrences).
- **Agent free text in the logs.** The models' own messages in the run logs are replaced by
  `<agent text removed for release>`. Only the tokens that the parsers count (tool-call markers and finding ids) are
  kept. All structured log lines (iterations, tool calls, queries, errors, token usage) are unchanged.
- **Free-text label notes and judge rationales.** Verdicts, severities and flags are released.
- **SARIF files.** Their results are already inside each `agent_codeql_report.json`.
- **Host names and absolute paths** are replaced by relative paths.
- **Identifiers of the 8 Top100 CVEs** are replaced by `CVE-ID-1` to `CVE-ID-8`, as in the paper, everywhere
  (raw outputs, labels, ground truth), together with the one advisory ID that refers to them.
  Hist20 and CWE-Bench-Java CVEs are public and kept.

## What cannot be recomputed offline

- **Recall probe (current models):** one paid API call per model and CVE; `reference/e5_recall_probe.py`, output in
  `data/reference_outputs/e5_recall_probe.json`.
- **IRIS re-evaluation with the reply-parsing bug fixed (40/90):** replays IRIS's own filter in its container against the
  CodeQL databases; `reference/e4_posthoc_reeval.py`, output in `runs/iris_e4_nov2026/logs/posthoc_reeval.json`.
- **Scanning itself:** the scans call commercial model APIs. The prompts, schemas, directives and tool code in
  `pipeline/` and the configurations in Table 15 (checked by `verify.py`) document what each scan received.

## Experiments

| Folder | Experiment | Scans |
|---|---|---|
| `runs/top100_dec2025/<config>/<package>` | Top100: 10 configurations × 100 packages, no directives (Dec 2025) | 1,000 |
| `runs/hist20_jan2026/<config>/<package>` | Hist20 with directives, D arm (Jan 2026) | 80 |
| `runs/nov2026/hist20/<config>N-r1/<package>` | Hist20 without directives, N arm (Nov 2026); G0N: refused | 61 |
| `runs/cwe_bench_java_apr2026/<project>` | CWE-Bench-Java, C3 (Mar–Apr 2026) | 85 |
| `runs/nov2026/claude-{0,1}-r{1..4}/<package>` | Reruns of C0 and C1 on the 10 packages with confirmed issues | 80 (+5 excluded) |
| `runs/single_agent_nov2026/<arm>/<package>` | One agent with every tool, text and native history | 20 |
| `runs/iris_e4_nov2026/` | IRIS v1 with Sonnet 4.6 on the 90 CVEs (summaries per project) | 90 |
| `runs/nov2026/e5/<config>-r1/<package>` | The setting with November 2026 models | 40 (+14 excluded) |
| `runs/sast_jan2026/` | Bandit, Opengrep and CodeQL default-suite outputs on Top100, with the scanner scripts | 3 tools |

## AI Usage

This repository was created via Claude Opus 5.5 to help reviewers quickly verify all metrics mentioned in the paper
via single verification script.
