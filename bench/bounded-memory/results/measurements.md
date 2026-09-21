# Native PROOF1 memory measurements

| Run | Result | RSS peak GiB | Rust requested peak GiB | Proving seconds | Requests |
| --- | --- | ---: | ---: | --- | ---: |
| 8-8-4-repeat-8g | PASS | 6.31 | — | 23.92, 23.41, 23.46 | 3 |
| controlled-repeat-8g | PASS | 5.91 | — | 23.23, 22.82, 23.09 | 3 |
| invalid-intent | REJECTED | 0.04 | — |  | 0 |
| ordinary-baseline-12g | PASS | 8.95 | — | 16.64 | 1 |
| ordinary-bounded-12g | PASS | 5.69 | — | 23.07 | 1 |
| ordinary-bounded-4g | FAILED | 4.02 | — |  | 0 |
| ordinary-bounded-4g-traced | FAILED | 4.01 | — |  | 0 |
| ordinary-in-build-baseline | PASS | 9.00 | — | 16.74 | 1 |
| ordinary-repeat-8g | PASS | 6.12 | — | 23.08, 22.69, 22.79 | 3 |
| return-repeat-8g | PASS | 5.84 | — | 22.73, 22.78, 22.76 | 3 |
