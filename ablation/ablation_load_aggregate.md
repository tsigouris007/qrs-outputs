# Single-Agent Load / Tool-Preference Ablation

Evidence mined from the existing 1000-scan production logs (no new LLM calls) for two design-motivation claims: **(1)** a single agent cannot absorb the combined Q+R+S workload, and **(2)** given the choice between reading raw code and running a structured/symbolic tool, the model defaults to raw code reading.

## Legend

- **Q hit cap** — the Query agent (single-purpose: write/execute/fix-up CodeQL queries only) reached its fixed 20-iteration whole-session budget.
- **R hit cap** — the Review agent reached its fixed 10-iteration budget for an individual finding-group (R is already internally decomposed: it gets a *fresh* budget per group rather than one shared budget for the whole session).
- **R first = raw** — across all finding-group reviews, the fraction where R's very first tool call was raw code reading (`extract_code_snippet` / `grep_search`) rather than the structured, CodeQL-like `trace_dataflow_path` tool.
- **raw\:structured** — overall call-volume ratio of raw code reads to structured dataflow traces.

## Per-Configuration

| Config | Q hit cap | R hit cap (groups) | R first = raw | raw:structured |
|---|---|---|---|---|
| claude-0 | 29/100 (29.0%) | 15/253 (5.9%) | 251/253 (99.2%) | 3025 : 176 (17.2:1) |
| claude-1 | 37/100 (37.0%) | 14/230 (6.1%) | 230/230 (100.0%) | 2866 : 164 (17.5:1) |
| deepseek-chat-0 | 33/100 (33.0%) | 17/105 (16.2%) | 105/105 (100.0%) | 486 : 0 |
| deepseek-chat-1 | 40/100 (40.0%) | 8/98 (8.2%) | 98/98 (100.0%) | 403 : 0 |
| deepseek-reasoner-0 | 40/99 (40.4%) | 36/115 (31.3%) | 115/115 (100.0%) | 907 : 2 (453.5:1) |
| deepseek-reasoner-1 | 41/100 (41.0%) | 38/125 (30.4%) | 124/125 (99.2%) | 965 : 0 |
| gemini-0 | 80/100 (80.0%) | 0/258 (0.0%) | 251/258 (97.3%) | 621 : 0 |
| gemini-1 | 84/100 (84.0%) | 1/226 (0.4%) | 221/226 (97.8%) | 561 : 0 |
| gpt-0 | 0/100 (0.0%) | 0/117 (0.0%) | 117/117 (100.0%) | 753 : 0 |
| gpt-1 | 0/99 (0.0%) | 1/127 (0.8%) | 125/127 (98.4%) | 635 : 9 (70.6:1) |

## Aggregate Across All Configurations (1000 scans)

| Metric | Value |
|---|---|
| Q hit its 20-iteration cap | 384/998 scans (38.5%) |
| R hit its per-group iteration cap | 130/1654 review-groups (7.9%) |
| R's first tool call was raw code reading | 1637/1654 review-groups (99.0%) |
| R's first tool call was the structured tool (`trace_dataflow_path`) | 0/1654 review-groups (0.0%) |
| Overall raw vs. structured call volume | 11222 raw vs. 351 structured (32.0 : 1) |

## Takeaways

- Even the narrowest-scoped agent (Q, restricted to CodeQL query authoring for one package) exhausts its fixed iteration budget in **38.5% of scans**, with strong per-model variance (0% for gpt-0 up to 84% for gemini-1). A single agent absorbing the full Q+R+S workload in one shared context would face a substantially larger, compounding budget requirement than any individual specialized sub-agent already needs.
- R is the only agent offered both a raw code-reading toolset and a structured, CodeQL-like dataflow-tracing tool for the same job (justifying a finding). Its first action is raw code reading in **99.0%** of 1654 finding-group reviews. Raw-code calls outnumber structured calls **32.0:1** overall.
- This confirms that, absent structural constraints, the model defaults to unsystematic code inspection rather than systematic, query-driven verification — motivating why Q's tool palette is deliberately restricted to CodeQL-only (no raw-file-read escape hatch).
