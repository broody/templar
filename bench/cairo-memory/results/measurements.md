# Native PROOF1 memory measurements

| Run | Result | RSS peak GiB | Rust requested peak GiB | Proving seconds | Requests |
| --- | --- | ---: | ---: | --- | ---: |
| 8-8-4-repeat-10 | FAILED | 9.95 | — | 16.65 | 1 |
| 8-8-4-repeat-11 | PASS | 9.71 | — | 16.98, 16.30, 16.20 | 3 |
| 8-8-4-repeat-11-release | PASS | 10.00 | — | 16.60, 16.27, 16.33 | 3 |
| controlled-repeat-10 | PASS | 9.64 | — | 16.06, 16.01, 15.92 | 3 |
| invalid-intent | REJECTED | 0.04 | — |  | 0 |
| ordinary-baseline | PASS | 10.62 | — | 14.38 | 1 |
| ordinary-keep-trees | PASS | 10.62 | — | 14.56 | 1 |
| ordinary-recompute | PASS | 9.27 | — | 16.88 | 1 |
| ordinary-recompute-8 | FAILED | 7.87 | — |  | 0 |
| ordinary-recompute-no-coefficients | PASS | 9.25 | — | 21.98 | 1 |
| ordinary-recompute-release | PASS | 9.39 | — | 16.14 | 1 |
| ordinary-repeat-10 | PASS | 9.41 | — | 16.31, 15.84, 15.69 | 3 |
| return-repeat-10 | PASS | 9.47 | — | 16.01, 15.53, 15.46 | 3 |
