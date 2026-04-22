# Hist20 — Metrics

## Overall Summary

| Total Runtime | Total Cost | Total Tokens | Total Iterations |
|---------------|------------|--------------|------------------|
| 17h29m41s | $78.6107 | 43.2M | 3231 |

---

## Average Metrics by Model Family and Temperature

| Model Family | Temp | Avg Runtime | Avg Cost | Avg Tokens | Q Iter | R Iter | S Iter | Scans |
|--------------|------|-------------|----------|------------|--------|--------|--------|-------|
| claude | 0.0 | 11m15s | $1.6243 | 851.3k | 19.4 | 24.4 | 8.2 | 20 |
| deepseek-reasoner | 0.0 | 22m7s | $0.1252 | 429.8k | 19.4 | 15.6 | 3.1 | 20 |
| gemini | 0.0 | 10m50s | $1.3073 | 566.6k | 19.7 | 18.5 | 4.5 | 20 |
| gpt | 0.0 | 8m14s | $0.8738 | 311.3k | 13.5 | 10.8 | 6.7 | 20 |

---

## Q Agent Query Efficiency by Model Family and Temperature

| Model Family | Temp | Total | With Results | Without Results | Failed (*) | Success % | No Results % | Failure % (*) |
|--------------|------|-------|--------------|-----------------|------------|-----------|--------------|---------------|
| claude | 0.0 | 268 | 169 | 99 | 91 | 63.06% | 36.94% | 33.96% |
| deepseek-reasoner | 0.0 | 277 | 71 | 206 | 283 | 25.63% | 74.37% | 102.17% |
| gemini | 0.0 | 228 | 136 | 92 | 81 | 59.65% | 40.35% | 35.53% |
| gpt | 0.0 | 285 | 83 | 202 | 342 | 29.12% | 70.88% | 120.00% |

---

## Average Tool Call Counts by Model Family and Temperature

### Q Tools

| Model Family | Temp | exec query | final report | fixup query | package profile |
|--------------|------|------------|--------------|-------------|-----------------|
| claude | 0.0 | 11.55 | 1.00 | 2.05 | 1.00 |
| deepseek-reasoner | 0.0 | 12.45 | 1.00 | 2.90 | 1.00 |
| gemini | 0.0 | 10.75 | 1.00 | 0.65 | 1.00 |
| gpt | 0.0 | 13.05 | 1.00 | 3.70 | 1.00 |

### R Tools

| Model Family | Temp | complete review | extract snippet | grep | submit find | trace flow |
|--------------|------|-----------------|-----------------|------|-------------|-----------|
| claude | 0.0 | 2.80 | 26.75 | 6.30 | 11.10 | 2.70 |
| deepseek-reasoner | 0.0 | 0.30 | 10.35 | 3.25 | 2.80 | 0.00 |
| gemini | 0.0 | 2.05 | 7.25 | 2.45 | 4.55 | 0.00 |
| gpt | 0.0 | 1.20 | 15.65 | 1.65 | 6.20 | 0.05 |

### S Reviews & Iterations

| Model Family | Temp | Findings | Q Iter | R Iter |
|--------------|------|----------|--------|--------|
| claude | 0.0 | 8.15 | 19.40 | 24.40 |
| deepseek-reasoner | 0.0 | 3.12 | 19.40 | 15.55 |
| gemini | 0.0 | 4.53 | 19.70 | 18.50 |
| gpt | 0.0 | 6.69 | 13.50 | 10.80 |

---

## Performance Metrics by Model Family and Temperature

| Model Family | Temp | Predictions | Correct | Incorrect | Accuracy | Precision | Recall | F1 Score |
|--------------|------|-------------|---------|-----------|----------|-----------|--------|----------|
| claude | 0.0 | 118 | 102 | 16 | 86.44% | 75.76% | 75.76% | 0.7576 |
| deepseek-reasoner | 0.0 | 32 | 29 | 3 | 90.62% | 86.96% | 100.00% | 0.9302 |
| gemini | 0.0 | 67 | 57 | 10 | 85.07% | 69.70% | 100.00% | 0.8214 |
| gpt | 0.0 | 93 | 69 | 24 | 74.19% | 44.12% | 75.00% | 0.5556 |

---

## TP/MR Finding Reduction from Reviewer (R) to Sanity (S) Agent

| Model Family | Temp | R Count | S Count | Reduction | Reduction % |
|--------------|------|---------|---------|-----------|-------------|
| claude | 0.0 | 96 | 64 | 32 | 33.3% |
| deepseek-reasoner | 0.0 | 42 | 41 | 1 | 2.4% |
| gemini | 0.0 | 53 | 52 | 1 | 1.9% |
| gpt | 0.0 | 56 | 48 | 8 | 14.3% |
