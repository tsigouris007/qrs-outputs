# Security finding audit: instructions for the reviewing model

You are auditing **1,000 findings** produced by an automated vulnerability scanner on 100 popular Python packages. For
each finding, decide from the **code** whether the flagged location really contains the weakness it was flagged for.
Work only inside this folder. Do not use the web, do not search for CVEs or advisories, and do not modify anything
except files under `outputs/`.
You **MUST** always verify the code yourself and not rely solely on the snippets as they are incomplete.

## What you get
- `batches/batch_001.md` … `batch_050.md`: 20 findings each. Each finding has an id (`E0-0001` …), the package, the
  flagged location, the weakness class (CWE), the **hypothesis** that made the scanner look there, the source code around
  the location (flagged lines marked `>>`), and sometimes dataflow steps reported by the scanner (these may be incomplete
  or imprecise).
- `sources/<package>/`: the full source of each package exactly as scanned. Open other files when you need to check
  callers, inputs, sanitisers, or whether the code is reachable from the package's public API.

The hypothesis is a starting question, not a conclusion. The scanner is often wrong. Judge every finding independently.

## Labels (use exactly these definitions)
- **`tp`**: the flagged location (or the code it directly belongs to) **does contain a real instance of the stated
  weakness class**: the dangerous operation is present and data that a caller, a user, a file, the network or the
  environment can influence can reach it in some realistic use of the package. **Still `tp`** when exploitation needs
  prerequisites (e.g. a local attacker, a malicious file the victim must open, a specific configuration), when the
  behaviour is documented, or when it is "by design". Record those circumstances in `flags`.
- **`fp`**: anything else, e.g.
  - the code at the location does not do what the hypothesis suggests (wrong location, wrong API, misread code);
  - only constants or values fully controlled by the package itself reach the operation;
  - an effective check, sanitiser, allow-list, safe API variant, or type restriction prevents the weakness;
  - the code is dead, or is only test/example code that is not part of the installed library;
  - the "weakness" is only a style or code-quality concern, with no security impact.

If you are unsure, choose the more likely label and lower `confidence`.

## Output (strict)
For `batches/batch_NNN.md`, write `outputs/batch_NNN.jsonl`: **exactly one JSON object per line, one line per finding,
in the order of the batch**, with these keys:

```json
{"id": "E0-0001", "label": "tp", "exploitable": "unclear", "flags": ["needs_prerequisites"], "confidence": 70, "rationale": "One or two sentences on the deciding evidence (file:line)."}
```

- `label`: `"tp"` or `"fp"`.
- `exploitable`: `"yes"`, `"no"` or `"unclear"`. Your view of practical exploitability **in addition to** the label: a
  `tp` may well be `"no"` or `"unclear"`.
- `flags`: zero or more of `"by_design"`, `"documented"`, `"needs_prerequisites"`, `"test_or_example_code"`,
  `"location_mismatch"`, `"mitigated"`, `"constant_input"`, `"not_reachable"`.
- `confidence`: an integer from 0 to 100.
- `rationale`: at most 2 sentences, citing the evidence (`file:line`).

## Procedure
1. Process batches in order: `batch_001`, `batch_002`, ….
2. For each batch, read every finding, inspect `sources/` as needed, then write the whole `outputs/batch_NNN.jsonl`.
3. After writing a batch, run `python3 tools/validate.py NNN`. If it reports errors, fix that file before moving on.
4. Continue to the next batch. Run `python3 tools/validate.py` (no argument) at any time to see overall progress.
5. Never skip a finding. Never change a label you already wrote because of a later batch: each finding stands alone.
