# Cairo complete-proof negative report

Status: **pass**

Completed 29/29; controls 2/2; explicit negatives 27/27.

Each case used MemoryMax=8G, MemorySwapMax=0, CPUQuota=100%, RuntimeMaxSec=120 and `/usr/bin/time -v`.

- `valid-single`: PASS — exact Span length and public8
- `valid-batch`: PASS — exact Span length and public8
- `chain-id`: PASS — explicit Cairo/verifier rejection
- `pool`: PASS — explicit Cairo/verifier rejection
- `old-count`: PASS — explicit Cairo/verifier rejection
- `new-count`: PASS — explicit Cairo/verifier rejection
- `old-root`: PASS — explicit Cairo/verifier rejection
- `new-root`: PASS — explicit Cairo/verifier rejection
- `noncanonical-m31-word`: PASS — explicit Cairo/verifier rejection
- `statement-commitment`: PASS — explicit Cairo/verifier rejection
- `sibling`: PASS — explicit Cairo/verifier rejection
- `request-domain`: PASS — explicit Cairo/verifier rejection
- `request-wiring`: PASS — explicit Cairo/verifier rejection
- `request-padding`: PASS — explicit Cairo/verifier rejection
- `unused-permutation-output`: PASS — explicit Cairo/verifier rejection
- `interaction-nonce`: PASS — explicit Cairo/verifier rejection
- `interaction-sum`: PASS — explicit Cairo/verifier rejection
- `proof-config`: PASS — explicit Cairo/verifier rejection
- `populated-pcs-commitment`: PASS — explicit Cairo/verifier rejection
- `populated-sample`: PASS — explicit Cairo/verifier rejection
- `empty-preprocessing-root`: PASS — explicit Cairo/verifier rejection
- `nonempty-preprocessing-sample`: PASS — explicit Cairo/verifier rejection
- `nonempty-preprocessing-query`: PASS — explicit Cairo/verifier rejection
- `nonempty-preprocessing-witness`: PASS — explicit Cairo/verifier rejection
- `trailing-data`: PASS — explicit Cairo/verifier rejection
- `truncated-data`: PASS — explicit Cairo/verifier rejection
- `batch-commitment-order`: PASS — explicit Cairo/verifier rejection
- `batch-commitment-omitted`: PASS — explicit Cairo/verifier rejection
- `batch-commitment-extra`: PASS — explicit Cairo/verifier rejection
