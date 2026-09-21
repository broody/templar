# Native proof measurements

Single runs on the larger host, four cores, 16 GiB process cap, no swap. Not physical-desktop qualification.

| Case | Prover request (s) | Peak RSS (GiB) | Proof bytes | L2 gas | Actual fee (test STRK) |
| --- | ---: | ---: | ---: | ---: | ---: |
| mock-swap | 21.174 | 13.845 | 235068 | 95930800 | 1.728882 |
| restored-return-payment | 20.023 | 13.989 | 236156 | 93014000 | 1.667447 |
| ekubo-swap | 21.427 | 13.949 | 238059 | 102381920 | 1.835414 |
| restored-ekubo-withdrawal | 21.699 | 13.792 | 234432 | 78332880 | 1.403147 |

The mock fill moved from 950 to 977 after proving; the real Ekubo return was 999 synthetic token-B units for 1,000 token-A units.

All four returned proofs were independently verified locally and accepted on Sepolia.

Setup/declaration fees are reported separately in `evidence.json`; they are not recurring swap fees.
