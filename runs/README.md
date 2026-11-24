# Raw scan outputs

One folder per scan (`<experiment>/<config>/<package>/`). Files:

| File | Written by | Content |
|---|---|---|
| `agent_codeql_report.json` | Q | model, temperature, token counts, cost at run time, tool calls, every query that returned results (QL text, hypothesis, severity, CWEs, results) |
| `agent_reviewer_report.json` | R | token counts, tool calls, review groups, every submitted finding (location, CWEs, verdict, confidence, reasoning, evidence) |
| `agent_sanity_report.json` | S | the R findings with S's verdict (`sanity_check`) and S's session totals (`sanity_check_metadata`) |
| `agent_reviewer_groups.json` | R | the MITRE-based groups R reviewed |
| `agent_codeql_run.log` | all agents | the run log: iterations, every tool call, every query execution and its errors, token usage |
| `package_profile.json` | Q | files and line counts of the package (used for code reduction) |
| `llm_calls.jsonl`, `cache_usage_summary.json` | client (Nov 2026 runs) | one row per model call (tokens, cache reads and writes, stop reason) and the per-scan cost with and without caching |
| `<package>.stdout.log` | client (Nov 2026 runs) | CodeQL's own error text for failed executions |
| `sa_trace.jsonl`, `sa_summary.json`, `sa_tools.json`, `sa_system_prompt.md` | single agent (E2) | per-turn trace, totals, tool definitions and system prompt |

Release changes: `exploit_payload` is removed from every finding; the agents' free-text messages in logs and traces are
replaced by `<agent text removed for release>` followed only by the tool-call markers and finding ids that the parsers
count; SARIF files are dropped (their results are in `agent_codeql_report.json`); absolute paths are made relative.

`_excluded/` folders hold scans that are in the result databases but excluded from the analyses, for the reason given in
`data/exclusions/*.json` (network or toolchain failures, a superseded configuration).

`iris_e4_nov2026/` holds the IRIS comparison run (E4): per-project summaries (`logs/projects/*.json`, build and CodeQL
timings, IRIS's own evaluation), the queue log, the offline re-evaluation with the reply-parsing bug fixed, the harness
notes with every deviation from a plain IRIS run (`README_iris_harness.md`), and the harness code (`harness/`: container
definition, entry script, queue runner, the Claude adapter for IRIS v1). IRIS itself is not redistributed: the harness
pins IRIS v1 at commit 67140e8 of its public repository.
