# CG evaluation (2026-11-23)

22 labelled Python samples: 12 with one known vulnerability each, 10 safe lookalikes using the same libraries correctly. Uploaded as one ZIP to `http://localhost:8080` by `eval/run_eval.py`; 3 run(s). Numbers are from run 1.

| | Scanners only | Scanners + LLM labels |
|---|---|---|
| Vulnerable files caught (recall) | 100% | 100% |
| Findings that are real (precision) | 75% | 86% |
| Safe files with any finding (false-positive rate) | 10% | 0% |
| Noise findings shown | 4 | 2 |

- Findings: 16; with an AI explanation: 16; LLM status: DONE.
- The LLM labelled **2 of 4** noise findings as likely false positives and wrongly dismissed **0** real vulnerabilities.
- Findings pointing at a missing file or an impossible line: 0. Duplicates on the same line: 0.
- Missed vulnerabilities: none.
- Scan time (worker start to finish, all samples): 10 s, 8 s, 4 s.
- Tool errors: none.
- LLM label consistency across runs: not measurable

Limits: small, textbook Python samples with one vulnerability each. This shows the pipeline works and what the LLM labels change, not how CG performs on large real-world code. LLM cost is not measured: CG does not record token usage.
