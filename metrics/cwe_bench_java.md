# CWE Bench Java — Metrics

## Overall Summary

| Total Runtime | Total Cost | Total Tokens | Total Iterations |
|---------------|------------|--------------|------------------|
| 42h22m48s | $1059.2538 | 338.3M | 5641 |

---

## Average Metrics by Model Family and Temperature

| Model Family | Temp | Avg Runtime | Avg Cost | Avg Tokens | Q Iter | R Iter | S Iter | Scans |
|--------------|------|-------------|----------|------------|--------|--------|--------|-------|
| claude | 1.0 | 29m54s | $12.4618 | 4.0M | 15.7 | 37.2 | 13.4 | 85 |

---

## Q Agent Query Efficiency by Model Family and Temperature

| Model Family | Temp | Total | With Results | Without Results | Failed (*) | Success % | No Results % | Failure % (*) |
|--------------|------|-------|--------------|-----------------|------------|-----------|--------------|---------------|
| claude | 1.0 | 1944 | 1530 | 414 | 412 | 78.70% | 21.30% | 21.19% |

---

## Average Tool Call Counts by Model Family and Temperature

### Q Tools

| Model Family | Temp | exec query | final report | fixup query | package profile |
|--------------|------|------------|--------------|-------------|-----------------|
| claude | 1.0 | 22.42 | 1.00 | 0.46 | 1.01 |

### R Tools

| Model Family | Temp | complete review | extract snippet | grep | submit find | trace flow |
|--------------|------|-----------------|-----------------|------|-------------|-----------|
| claude | 1.0 | 1.98 | 34.15 | 8.33 | 15.35 | 0.20 |

### S Reviews & Iterations

| Model Family | Temp | Findings | Q Iter | R Iter |
|--------------|------|----------|--------|--------|
| claude | 1.0 | 13.41 | 15.74 | 37.21 |

---

## Performance Metrics by Model Family and Temperature

| Model Family | Temp | Predictions | Correct | Incorrect | Accuracy | Precision | Recall | F1 Score |
|--------------|------|-------------|---------|-----------|----------|-----------|--------|----------|
| claude | 1.0 | 1097 | 961 | 136 | 87.60% | 75.70% | 98.79% | 0.8571 |

---

## TP/MR Finding Reduction from Reviewer (R) to Sanity (S) Agent

| Model Family | Temp | R Count | S Count | Reduction | Reduction % |
|--------------|------|---------|---------|-----------|-------------|
| claude | 1.0 | 620 | 580 | 40 | 6.5% |
