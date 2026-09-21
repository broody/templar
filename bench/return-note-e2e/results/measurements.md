# Native proof measurements

Single runs on the larger host, four cores, 16 GiB process cap, no swap. Not physical-desktop qualification.

| Case | Prover request (s) | Peak RSS (GiB) | Proof bytes | L2 gas | Actual fee (test STRK) |
| --- | ---: | ---: | ---: | ---: | ---: |
| upstream-ekubo-swap | 19.110 | 13.813 | 237926 | 103155120 | 1.813773 |
| restored-return-payment | 19.692 | 13.876 | 232162 | 93014000 | 1.635438 |

The unchanged upstream Ekubo adapter returned 999 synthetic token-B units for 1,000 token-A units.

Both returned proofs were independently verified locally and accepted on Sepolia.

Setup/declaration fees are reported separately in `evidence.json`; they are not recurring swap fees.
