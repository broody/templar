# M31-append native summary v2

Status: **passed**.

Scope: public append arithmetic and canonical fixture reconstruction only; no private-payment/browser qualification, outer proving, or OS rejection claim.

## Retained v1 measurements

These six measurements use frozen v1 (`8acbab…`) and were not rerun. V2 is a serializer-only compatibility change; no v2 repetition measurements are claimed.

| Run | Proof bytes | Complete s | Cgroup peak GiB | Verified |
|---|---:|---:|---:|---|
| `native-single-1` | 192143 | 4.085298 | 0.014297 | yes |
| `native-single-2` | 192143 | 4.073443 | 0.014542 | yes |
| `native-single-3` | 192143 | 4.063303 | 0.014755 | yes |
| `native-batch-1` | 223098 | 1.988121 | 0.027172 | yes |
| `native-batch-2` | 223098 | 2.102855 | 0.027416 | yes |
| `native-batch-3` | 223098 | 1.988242 | 0.031277 | yes |

## V2 compatibility

- Saved collision proof: full Cairo bridge passed with 22 distinct openings from 23 draws; exact canonical `[8,*public8]` match.
- Regenerated branch12 is byte-identical to the saved collision proof.
- Branch12, branch13, and refresh123 all proved and verified under 1 GiB, one CPU, zero swap.

Five outer-ready proof directories:

- `bench/m31-append/results/native-single-1/proof` — `955bfb38e456678966def815a9d1c3096c0f4258972006a4a2b1c5692d6f5615`
- `bench/m31-append/results/native-batch-1/proof` — `7ed80c51ad5a0fd05239675903b515d8b0c46d7e7cfb69ad5f2840902592646e`
- `bench/m31-append/results/native-branch12-v2/proof` — `ecbd472612240d87ae55051d494f15050ee2e8f987300223006f940810d0fd30`
- `bench/m31-append/results/native-branch13/proof` — `33b22fcd732935f9122e7c34ae157eaafdb54dd595d964e813a60cd8691c9bf5`
- `bench/m31-append/results/native-refresh123/proof` — `ac8aad19e3874b28ae553c1071d021f2b1cf9c2f15f046918a223b232562c665`

The first outer candidate is `bench/m31-append/results/native-single-1/proof`, bound to SN_SEPOLIA (`0x534e5f5345504f4c4941`) and pool `0x456`.

## Controls

- Three combined valid-verification/rejection suites passed: 70 mutation rejections plus 6 boundary controls.
- Canonical state fixture: 1 positive reconstruction and 16/16 rejected independent mutations. These are validator controls, not OS rejection evidence.
- The base fixture remained byte-identical.

Fixed fixtures and deterministic grinding establish byte stability, not a payment-latency distribution. No pure-verification memory, outer proof, or node-attachment claim is made.
