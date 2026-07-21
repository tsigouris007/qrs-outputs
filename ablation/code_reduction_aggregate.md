# Code Reduction Ablation: extract_code_snippet vs. Total Package Size

How much of a package's source code the Reviewer (R) agent actually reads via `extract_code_snippet`, compared to the package's total line count (`total_lines` from `package_profile.json`), across **all packages and all 10 run configurations** (1000 scans total). This quantifies the benefit of CodeQL-first triage: R only inspects the handful of locations CodeQL flagged, not the whole codebase.

## Legend

- **avg_lines** — mean package size (`total_lines`) per scan.
- **avg_raw_rd** — mean lines *read* per scan, summed across all `extract_code_snippet` calls (includes re-reads of overlapping ranges — total reading effort).
- **avg_uniq_rd** — mean *unique* lines covered per scan (overlapping ranges merged — actual code coverage).
- **%read (macro)** — mean, over scans, of `unique_lines / total_lines`.
- **%reduction (macro)** — mean, over scans, of `100% - %read`; every scan weighted equally.
- **%reduction (micro)** — `100% - (Σ unique_lines / Σ total_lines)`; pooled, weighted by package size.
- **%files touched** — mean files touched by `extract_code_snippet` divided by mean `total_files` in the package.

## Per-Configuration (model-temperature)

| Config | Scans | avg_lines | avg_raw_rd | avg_uniq_rd | %read (macro) | %reduction (macro) | %reduction (micro) | %files touched |
|---|---|---|---|---|---|---|---|---|
| claude-0 | 100 | 16545 | 1055 | 430 | 24.51% | 75.49% | 97.40% | 8.88% |
| claude-1 | 100 | 16545 | 926 | 404 | 19.66% | 80.34% | 97.56% | 8.12% |
| deepseek-chat-0 | 100 | 16545 | 106 | 61 | 5.21% | 94.79% | 99.63% | 2.59% |
| deepseek-chat-1 | 100 | 16545 | 88 | 58 | 2.88% | 97.12% | 99.65% | 2.43% |
| deepseek-reasoner-0 | 100 | 16545 | 197 | 101 | 8.39% | 91.61% | 99.39% | 3.39% |
| deepseek-reasoner-1 | 100 | 16545 | 196 | 101 | 4.62% | 95.38% | 99.39% | 3.71% |
| gemini-0 | 100 | 16545 | 188 | 109 | 11.08% | 88.92% | 99.34% | 4.64% |
| gemini-1 | 100 | 16545 | 234 | 169 | 11.50% | 88.50% | 98.98% | 4.21% |
| gpt-0 | 100 | 16545 | 140 | 66 | 4.51% | 95.49% | 99.60% | 3.46% |
| gpt-1 | 100 | 16545 | 128 | 64 | 3.25% | 96.75% | 99.61% | 3.68% |

## Per-Model (temperatures merged)

| Model | Scans | avg_lines | avg_raw_rd | avg_uniq_rd | %read (macro) | %reduction (macro) | %reduction (micro) | %files touched |
|---|---|---|---|---|---|---|---|---|
| claude | 200 | 16545 | 990 | 417 | 22.08% | 77.92% | 97.48% | 8.50% |
| deepseek-chat | 200 | 16545 | 97 | 59 | 4.05% | 95.95% | 99.64% | 2.51% |
| deepseek-reasoner | 200 | 16545 | 197 | 101 | 6.51% | 93.49% | 99.39% | 3.55% |
| gemini | 200 | 16545 | 211 | 139 | 11.29% | 88.71% | 99.16% | 4.43% |
| gpt | 200 | 16545 | 134 | 65 | 3.88% | 96.12% | 99.61% | 3.57% |

## By Package Size (all configurations pooled)

Shows how the reduction percentage scales with codebase size: small packages get read at a much higher fraction than huge ones.

| Package size | Scans | avg_lines | avg_raw_rd | avg_uniq_rd | %read (macro) | %reduction (macro) | %reduction (micro) | %files touched |
|---|---|---|---|---|---|---|---|---|
| <1K lines | 240 | 490 | 258 | 101 | 29.03% | 70.97% | 79.44% | 28.23% |
| 1K-5K lines | 310 | 2978 | 310 | 156 | 6.39% | 93.61% | 94.77% | 10.67% |
| 5K-20K lines | 310 | 10356 | 336 | 163 | 1.77% | 98.23% | 98.43% | 6.53% |
| 20K-100K lines | 90 | 39331 | 406 | 223 | 0.65% | 99.35% | 99.43% | 2.63% |
| >100K lines | 50 | 175083 | 540 | 261 | 0.15% | 99.85% | 99.85% | 1.36% |

## Aggregate Across All Configurations

| Metric | Value |
|---|---|
| Scans | 1000 |
| Scans with a usable `package_profile.json` | 1000/1000 |
| Package size range (`total_lines`) | 46 – 245973 |
| Avg. package size per scan | 16545 lines |
| Avg. raw lines read per scan (incl. re-reads) | 326 lines |
| Avg. unique lines covered per scan | 156 lines |
| Avg. `extract_code_snippet` calls per scan | 13.73 |
| Avg. files touched per scan | 2.53 of 56.0 (4.51%) |
| % of package read (macro mean) | 9.56% |
| **Code reduction (macro mean)** | **90.44%** |
| **Code reduction (micro, pooled)** | **99.06%** |

## Takeaway

Across 1000 scans spanning all 10 run configurations and every benchmark package, R covers on average only 9.56% of a package's source code (macro mean; 99.06% pooled reduction), reading a mean of 156 unique lines across 2.53 files, out of an average package size of 16545 lines across 56.0 files. The reduction grows sharply with package size (see the size-bucket table above): CodeQL-driven triage lets the review stage focus narrowly on the flagged locations instead of reading the entire codebase, and the benefit compounds as packages get larger.
