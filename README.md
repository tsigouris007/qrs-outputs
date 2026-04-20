# About

This repository contains artifacts produced by QRS.

```
qrs-outputs/
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
│   ├── hist20_dataset.json
│   └── top100_dataset.json
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
└── visualizations/
    ├── cwe_java_bench/    (8 PDF charts)
    ├── hist20/            (8 PDF charts)
    └── top100/            (8 PDF charts)
```

## Datasets

Includes the 3 datasets: Hist20, Top100, and CWE Bench Java.

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
