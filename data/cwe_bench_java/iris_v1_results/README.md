# IRIS v1 published per-project results (ICLR 2025)

Source: https://github.com/iris-sast/iris/tree/v1/results (raw files, branch v1), downloaded 2026-11-17; checksums in
SHA256SUMS.txt. Only the two rows of tab:java-comparison are kept: IRIS + GPT-4 and CodeQL. Columns:
`CWE ID, CVE, Author, Package, Tag, Recall, Alerts, Paths, TP Alerts, TP Paths, Precision, F1`; Recall = 1 when a reported
path passes through a method the fix changes.
