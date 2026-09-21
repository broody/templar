| Inputs/outputs/withdrawals | Outcome | Request | Peak memory | Proof bytes | Public spend felts | Virtual OS steps |
|---|---|---:|---:|---:|---:|---:|
| 1/2/0 | PASS | 20.529 s | 13.62 GiB | 235,372 | 41 | 114,367 |
| 4/4/2 | PASS | 20.027 s | 14.47 GiB | 229,603 | 72 | 129,986 |
| 8/8/4 | PASS | 19.116 s | 14.27 GiB | 229,464 | 128 | 151,769 |
| 16/16/8 | PASS | 19.851 s | 15.38 GiB | 226,325 | 240 | 196,470 |
| 32/32/16 | FAILED | — | ≥16 GiB cgroup | — | — | 290,245 |
| 64/64/32 | FAILED | — | ≥16 GiB cgroup | — | — | 495,408 |
| 32/2/0 | FAILED | — | ≥16 GiB cgroup | — | — | 270,731 |
| 1/32/0 | PASS | 20.209 s | 14.45 GiB | 233,344 | 401 | 131,122 |
