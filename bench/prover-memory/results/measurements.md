# Native PROOF1 memory measurements

| Run | Result | RSS peak GiB | Rust requested peak GiB | Proving seconds | Requests |
| --- | --- | ---: | ---: | --- | ---: |
| 8-8-4-release-fresh-a | PASS | 11.25 | — | 15.14 | 1 |
| 8-8-4-release-fresh-b | PASS | 11.28 | — | 15.40 | 1 |
| 8-8-4-release-fresh-c | PASS | 11.18 | — | 15.50 | 1 |
| 8-8-4-release-native-allocator | PASS | 10.92 | — | 20.65, 20.57, 20.84 | 3 |
| 8-8-4-release-repeat | FAILED | 12.04 | — | 15.50, 14.95 | 2 |
| 8-8-4-staged-repeat | PASS | 11.43 | 10.79 | 15.71, 14.89, 15.03 | 3 |
| 8-8-4-stock | PASS | 14.37 | — | 14.00 | 1 |
| controlled-release-repeat | PASS | 11.45 | — | 14.38, 13.73, 14.58 | 3 |
| controlled-staged-repeat | PASS | 11.02 | 10.28 | 15.18, 15.05, 14.86 | 3 |
| controlled-stock | PASS | 13.86 | — | 12.90 | 1 |
| invalid-intent-staged | REJECTED | — | 0.01 |  | 0 |
| ordinary-cached-profile | PASS | 13.79 | 12.98 | 13.30 | 1 |
| ordinary-final-profile-smoke | PASS | 10.61 | 10.27 | 15.72 | 1 |
| ordinary-no-coeff | FAILED | 0.04 | 0.01 |  | 0 |
| ordinary-no-coeff-profile | PASS | 10.48 | 9.89 | 20.60 | 1 |
| ordinary-one-thread | PASS | 10.60 | 10.27 | 47.89 | 1 |
| ordinary-release-repeat | PASS | 11.33 | — | 14.40, 14.23, 13.89 | 3 |
| ordinary-staged-10 | FAILED | 10.08 | 9.83 |  | 0 |
| ordinary-staged-12 | PASS | 10.72 | 10.27 | 14.80 | 1 |
| ordinary-staged-8-cap | FAILED | 8.05 | 8.53 |  | 0 |
| ordinary-staged-repeat | PASS | 11.02 | 10.27 | 14.91, 14.30, 14.33 | 3 |
| ordinary-stock | PASS | 14.07 | — | 12.51 | 1 |
| return-release-repeat | PASS | 11.05 | — | 14.68, 14.12, 14.06 | 3 |
| return-staged-repeat | PASS | — | 10.28 | 14.87, 14.26, 14.19 | 3 |
| return-stock | PASS | 14.04 | — | 12.66 | 1 |
