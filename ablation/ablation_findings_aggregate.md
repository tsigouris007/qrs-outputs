# Per-Configuration Findings Ablation (Q / Q+R / Q+R+S)

Ground-truth comparison of raw CodeQL alerts (**Q**, all-positive by construction), reviewer-filtered findings (**Q+R**), and sanity-verified findings (**Q+R+S**), for each of the 10 model/run configurations, plus the aggregate across all 1000 scans.

## Legend

- **Q** — Query agent stage. CodeQL performs no TP/FP verdict analysis, so its row shows a single total (TP+FP = the full ground-truth universe) with `-` elsewhere.
- **Q+R** — Query + Review agent stages
- **Q+R+S** — Query + Review + Sanity agent stages
- **TP / FP / TN / FN** — True/False Positives, True/False Negatives vs. the human-reviewed ground-truth universe
- **acc / prec / rec / f1** — Accuracy, Precision, Recall, F1 score (pooled/micro)
- **macroF1** — Macro-averaged F1 score (mean of per-scan F1, every scan equal weight)

## claude-0

scans=100, human-reviewed (with universe)=89, ground-truth universe=952 (pos=50, neg=902, dup excluded=111)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 952 | - | - | - | - | - | - | - | - |
| Q+R | 50 | 264 | 638 | 0 | 0.723 | 0.159 | 1.000 | 0.275 | 0.130 |
| Q+R+S | 46 | 58 | 844 | 4 | 0.935 | 0.442 | 0.920 | 0.597 | 0.175 |

## claude-1

scans=100, human-reviewed (with universe)=82, ground-truth universe=942 (pos=47, neg=895, dup excluded=48)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 942 | - | - | - | - | - | - | - | - |
| Q+R | 46 | 234 | 661 | 1 | 0.751 | 0.164 | 0.979 | 0.281 | 0.180 |
| Q+R+S | 41 | 50 | 845 | 6 | 0.941 | 0.451 | 0.872 | 0.594 | 0.224 |

## deepseek-chat-0

scans=100, human-reviewed (with universe)=32, ground-truth universe=105 (pos=6, neg=99, dup excluded=0)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 105 | - | - | - | - | - | - | - | - |
| Q+R | 6 | 67 | 32 | 0 | 0.362 | 0.082 | 1.000 | 0.152 | 0.079 |
| Q+R+S | 6 | 21 | 78 | 0 | 0.800 | 0.222 | 1.000 | 0.364 | 0.128 |

## deepseek-chat-1

scans=100, human-reviewed (with universe)=36, ground-truth universe=90 (pos=17, neg=73, dup excluded=1)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 90 | - | - | - | - | - | - | - | - |
| Q+R | 17 | 43 | 30 | 0 | 0.522 | 0.283 | 1.000 | 0.442 | 0.199 |
| Q+R+S | 17 | 18 | 55 | 0 | 0.800 | 0.486 | 1.000 | 0.654 | 0.206 |

## deepseek-reasoner-0

scans=100, human-reviewed (with universe)=56, ground-truth universe=131 (pos=19, neg=112, dup excluded=12)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 131 | - | - | - | - | - | - | - | - |
| Q+R | 19 | 68 | 44 | 0 | 0.481 | 0.218 | 1.000 | 0.358 | 0.182 |
| Q+R+S | 19 | 59 | 53 | 0 | 0.550 | 0.244 | 1.000 | 0.392 | 0.192 |

## deepseek-reasoner-1

scans=100, human-reviewed (with universe)=62, ground-truth universe=143 (pos=19, neg=124, dup excluded=9)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 143 | - | - | - | - | - | - | - | - |
| Q+R | 19 | 77 | 47 | 0 | 0.462 | 0.198 | 1.000 | 0.330 | 0.156 |
| Q+R+S | 19 | 60 | 64 | 0 | 0.580 | 0.241 | 1.000 | 0.388 | 0.167 |

## gemini-0

scans=100, human-reviewed (with universe)=87, ground-truth universe=318 (pos=35, neg=283, dup excluded=20)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 318 | - | - | - | - | - | - | - | - |
| Q+R | 33 | 61 | 222 | 2 | 0.802 | 0.351 | 0.943 | 0.512 | 0.201 |
| Q+R+S | 30 | 49 | 234 | 5 | 0.830 | 0.380 | 0.857 | 0.526 | 0.199 |

## gemini-1

scans=100, human-reviewed (with universe)=88, ground-truth universe=266 (pos=32, neg=234, dup excluded=13)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 266 | - | - | - | - | - | - | - | - |
| Q+R | 31 | 48 | 186 | 1 | 0.816 | 0.392 | 0.969 | 0.559 | 0.197 |
| Q+R+S | 31 | 41 | 193 | 1 | 0.842 | 0.431 | 0.969 | 0.596 | 0.202 |

## gpt-0

scans=100, human-reviewed (with universe)=58, ground-truth universe=283 (pos=25, neg=258, dup excluded=26)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 283 | - | - | - | - | - | - | - | - |
| Q+R | 25 | 127 | 131 | 0 | 0.551 | 0.164 | 1.000 | 0.282 | 0.183 |
| Q+R+S | 25 | 63 | 195 | 0 | 0.777 | 0.284 | 1.000 | 0.442 | 0.201 |

## gpt-1

scans=100, human-reviewed (with universe)=62, ground-truth universe=252 (pos=33, neg=219, dup excluded=24)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 252 | - | - | - | - | - | - | - | - |
| Q+R | 32 | 154 | 65 | 1 | 0.385 | 0.172 | 0.970 | 0.292 | 0.175 |
| Q+R+S | 31 | 87 | 132 | 2 | 0.647 | 0.263 | 0.939 | 0.411 | 0.191 |

## Aggregate Across All Configurations

scans=1000, human-reviewed (with universe)=652, ground-truth universe=3482 (pos=283, neg=3199, dup excluded=264)

| Stage | TP | FP | TN | FN | acc | prec | rec | f1 | macroF1 |
|---|---|---|---|---|---|---|---|---|---|
| Q | 3482 | - | - | - | - | - | - | - | - |
| Q+R | 278 | 1143 | 2056 | 5 | 0.670 | 0.196 | 0.982 | 0.326 | 0.172 |
| Q+R+S | 265 | 506 | 2693 | 18 | 0.850 | 0.344 | 0.936 | 0.503 | 0.192 |
