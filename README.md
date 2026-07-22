# About

This repository contains artifacts produced by QRS.

```
qrs-outputs/
├── ablation/
│   ├── ablation_findings_aggregate.md
│   ├── ablation_load_aggregate.md
│   ├── ablation_tool_aggregate.md
│   └── code_reduction_aggregate.md
├── configs/
│   ├── agent-config-claude-4.5-0.yml
│   ├── agent-config-claude-4.5-1.yml
│   ├── agent-config-claude-4.6-1.yml
│   ├── agent-config-deepseek-chat-0.yml
│   ├── agent-config-deepseek-chat-1.yml
│   ├── agent-config-deepseek-reasoner-0.yml
│   ├── agent-config-deepseek-reasoner-1.yml
│   ├── agent-config-gemini-3-pro-0.yml
│   ├── agent-config-gemini-3-pro-1.yml
│   ├── agent-config-gpt-5.1-0.yml
│   └── agent-config-gpt-5.1-1.yml
├── datasets/
│   ├── cwe_bench_java_dataset.json
│   ├── cwe_bench_java_dataset.md
│   ├── hist20_dataset.json
│   ├── hist20_dataset.md
│   ├── top100_dataset.json
│   └── top100_dataset.md
├── instructions/
│   ├── agents/
│   │   ├── q_agent.md
│   │   ├── r_agent.md
│   │   └── s_agent.md
│   ├── cwe_templates/
│   │   ├── q_agent/
│   │   │   ├── cwe-022.md
│   │   │   ├── cwe-078.md
│   │   │   ├── cwe-079.md
│   │   │   └── cwe-094.md
│   │   └── r_agent/
│   │       ├── cwe-022.md
│   │       ├── cwe-078.md
│   │       ├── cwe-079.md
│   │       └── cwe-094.md
│   └── hist20_extra_strategy_preprompts/
│       ├── <package>_codeql_prompt.md    (20 packages)
│       └── <package>_reviewer_prompt.md  (20 packages)
├── knowledge/
│   ├── java/
│   │   └── knowledge.md
│   └── python/
│       └── knowledge.md
├── metrics/
│   ├── cwe_bench_java.txt
│   ├── cwe_bench_java.md
│   ├── hist20.txt
│   ├── hist20.md
│   ├── top100.txt
│   └── top100.md
├── reports/
│   ├── cwe_java_workbench/
│   │   └── <vendor>__<package>_<version>/
│   │       ├── <timestamp>_results.sarif  (per-CWE SARIF outputs)
│   │       ├── agent_codeql_report.json
│   │       ├── agent_codeql_run.log
│   │       ├── agent_reviewer_groups.json
│   │       ├── agent_reviewer_report.json
│   │       ├── agent_sanity_report.json
│   │       └── package_profile.json
│   ├── hist20/
│   │   └── <config>/                     (claude-0, deepseek-reasoner-0, gemini-0, gpt-0)
│   │       └── <package>-<version>/
│   │           ├── <timestamp>_results.sarif
│   │           ├── agent_codeql_report.json
│   │           ├── agent_codeql_run.log
│   │           ├── agent_reviewer_groups.json
│   │           ├── agent_reviewer_report.json
│   │           ├── agent_sanity_report.json
│   │           └── package_profile.json
│   └── top100_samples/
│       └── <config>/                     (claude-0, claude-1, deepseek-reasoner-1, gemini-0, gemini-1, gpt-0)
│           └── <package>-<version>/
│               ├── <timestamp>_results.sarif
│               ├── agent_codeql_report.json
│               ├── agent_codeql_run.log
│               ├── agent_reviewer_groups.json
│               ├── agent_reviewer_report.json
│               ├── agent_sanity_report.json
│               └── package_profile.json
├── tools/
│   ├── java/
│   │   └── profiler_minimal.py
│   ├── python/
│   │   └── profiler_minimal.py
│   ├── mitre_helper.py
│   ├── q_agent_query_tools.py
│   ├── r_agent_review_tools.py
│   └── search_cve.py
├── sast_reports/
│   ├── bandit_scan.json
│   ├── codeql_scan.json
│   └── opengrep_scan.json
└── visualizations/
    ├── cwe_java_bench/    (8 PDF charts)
    ├── hist20/            (8 PDF charts)
    └── top100/            (8 PDF charts)
```

## Ablation

Ablation studies mined from the existing 1000-scan production logs (no new LLM calls), evaluating the QRS pipeline design choices across all 10 model/run configurations:

- `ablation_findings_aggregate.md` — Per-configuration and aggregate findings comparison across pipeline stages (Q / Q+R / Q+R+S), reporting TP/FP/TN/FN and accuracy/precision/recall/F1 against the human-reviewed ground truth.
- `ablation_load_aggregate.md` — Single-agent load and tool-preference ablation: evidence that a single agent cannot absorb the combined Q+R+S workload, and that models default to raw code reading over structured/symbolic tools when given the choice.
- `ablation_tool_aggregate.md` — Per-configuration, per-tool average usage (calls, tokens, cost, execution time) broken down by agent (Query / Review / Sanity) and tool.
- `code_reduction_aggregate.md` — Code reduction ablation quantifying how much of a package's source the Reviewer agent actually reads (via `extract_code_snippet`) versus total package size, demonstrating the benefit of CodeQL-first triage.

## Datasets

Includes the 3 datasets: Hist20, Top100, and CWE Bench Java.

| Dataset | JSON | Markdown |
|---------|------|----------|
| Hist20 | [datasets/hist20_dataset.json](datasets/hist20_dataset.json) | [datasets/hist20_dataset.md](datasets/hist20_dataset.md) |
| Top100 | [datasets/top100_dataset.json](datasets/top100_dataset.json) | [datasets/top100_dataset.md](datasets/top100_dataset.md) |
| CWE Bench Java | [datasets/cwe_bench_java_dataset.json](datasets/cwe_bench_java_dataset.json) | [datasets/cwe_bench_java_dataset.md](datasets/cwe_bench_java_dataset.md) |

- `hist20_dataset.json` — 20 historical Python packages with known CVEs.
- `top100_dataset.json` — Top 100 PyPI packages.
- `cwe_bench_java_dataset.json` — Java packages from the CWE Bench.

## Knowledge

Language-specific CodeQL knowledge files used to guide the Q agent.

- `knowledge/python/knowledge.md` — Python CodeQL instructions.
- `knowledge/java/knowledge.md` — Java CodeQL instructions.

## Configs

Minimal YAML configurations for all scanned model/strategy combinations (11 configs total), covering: Claude 4.5, Claude 4.6, DeepSeek Chat, DeepSeek Reasoner, Gemini 2.5 Pro, and GPT-5.1 — each with strategy variants 0 and/or 1.

## Instructions

- `agents/` — Base system instructions for the Q, R, and S agents.
- `cwe_templates/` — Per-CWE template prompts for Q and R agents (CWE-022, 078, 079, 094).
- `hist20_extra_strategy_preprompts/` — Package-specific CodeQL and reviewer preprompts used in the extra strategy (strategy 1) on the Hist20 dataset (20 packages × 2 prompt types).

## Reports

Per-package scan artifacts organized by dataset and model configuration. Each package directory contains:

- `<timestamp>_results.sarif` — Raw CodeQL SARIF result files (one per query run).
- `agent_codeql_report.json` — Q agent findings report.
- `agent_codeql_run.log` — Execution log of the Q agent CodeQL run.
- `agent_reviewer_groups.json` — Grouped findings for review.
- `agent_reviewer_report.json` — R agent reviewer report.
- `agent_sanity_report.json` — S agent sanity/validation report.
- `package_profile.json` — Package metadata and profile.

### cwe_java_workbench

Reports for 80+ Java packages from the CWE Bench workbench, covering vendors such as Apache, Alibaba, Jenkins, Keycloak, Spring, XWiki, and others.

### hist20

Reports for 4 model configurations (claude-0, deepseek-reasoner-0, gemini-0, gpt-0), each covering 20 Python packages.

Note: Includes anonymized artifacts for 4 configurations on the Hist20 dataset.

### top100_samples

Sample reports for 6 model configurations (claude-0, claude-1, deepseek-reasoner-1, gemini-0, gemini-1, gpt-0) across select Top100 packages.

Note: Regarding Top100 we include public knowledge that has already been addressed or patched. We cannot publicly disclose all of the scans, as they contain package internals and exploitation snippets. Contact in private if more artifacts are needed for this purpose.

## SAST Reports

Consolidated SAST scan result files used as baselines or comparisons in QRS:

- `bandit_scan.json` — Bandit static analysis scan results.
- `codeql_scan.json` — CodeQL scan results.
- `opengrep_scan.json` — Opengrep scan results.

## Metrics

Aggregated evaluation metrics for each dataset, available as both plain-text and GitHub-compatible Markdown:

| Dataset | Plain Text | Markdown |
|---------|-----------|----------|
| CWE Bench Java | [metrics/cwe_bench_java.txt](metrics/cwe_bench_java.txt) | [metrics/cwe_bench_java.md](metrics/cwe_bench_java.md) |
| Hist20 | [metrics/hist20.txt](metrics/hist20.txt) | [metrics/hist20.md](metrics/hist20.md) |
| Top100 | [metrics/top100.txt](metrics/top100.txt) | [metrics/top100.md](metrics/top100.md) |

Each metrics file contains six sections:

1. **Overall Summary** — total runtime, cost, tokens, and iterations across all configurations.
2. **Average Metrics by Model Family and Temperature** — per-model averages for runtime, cost, tokens, and agent iteration counts.
3. **Q Agent Query Efficiency** — query totals broken down by results, no-results, and failures.
4. **Average Tool Call Counts** — mean invocation counts for every Q, R, and S agent tool.
5. **Performance Metrics** — prediction counts with accuracy, precision, recall, and F1 score.
6. **TP/MR Finding Reduction** — finding count delta between the Reviewer (R) and Sanity (S) agents.

## Visualizations

PDF chart artifacts for each dataset, including 8 plots per dataset:

- CWE heatmap by template
- Package findings (overall and by template)
- Package flags breakdown
- Resource metrics boxplots
- Sanity/S flag distribution (TP/MR)
- Severity distribution
- Verdict transitions

## Tools

A subset of core utility scripts used in QRS:

- `mitre_helper.py` — MITRE CVE/CWE lookup helper.
- `q_agent_query_tools.py` — Tools used by the Q agent for querying.
- `r_agent_review_tools.py` — Tools used by the R agent for reviewing.
- `search_cve.py` — CVE search utility.
- `java/profiler_minimal.py` — Minimal Java package profiler.
- `python/profiler_minimal.py` — Minimal Python package profiler.

---

QRS used:
- `configs`
- `datasets`
- `instructions`
- `knowledge`
- `tools`

QRS produced:
- `reports`

SAST scans produced:
- `sast_reports`

QRS evaluations:
- `metrics`
- `visualizations`
- `ablation`

_This README file has been generated via Claude Sonnet 4.6_
