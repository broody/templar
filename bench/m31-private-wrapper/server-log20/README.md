# Server on the log20 small path: lever 1 (FRI queries)

2026-09-23. **Trading blowup for queries alone cannot fit log20.** The Blake budget is 8,192
compressions, and the bootloader (1,914) plus the virtual OS (7,829) already take 9,743 before
our bridge hashes anything. The OS part is hashing the statement account's executed bytecode.

`sweep.py` runs each configuration locally on a synthetic fixture, with nothing on chain:
1. an R0 V2 transfer proved by the wallet;
2. its own bridge and account, validated (17/17 in every run);
3. the virtual-OS capture;
4. the component trace (`capacity trace`) and Blake attribution (`blake_sites`).

The 2²/35 baseline reproduces the live Sepolia transfer: 13,608 Blake compressions against
13,616, with the same three components over the limit.

| FRI (blowup, queries, PoW 26) | Security bits | Client, bounded | Blinding rows | Calldata felts | OS Poseidon | Bridge steps | Blake: account / total | Over log20 |
| --- | ---: | --- | ---: | ---: | ---: | ---: | --- | --- |
| 2², 35 (current) | 96 | 0.31 GiB, 2.7 s | 2,390 | 29,811 | 14,965 | 1.99M | 3,865 / 13,608 | blake_g, cube_252, rc_252_w27 |
| 2³, 24 | 98 | 0.47 GiB, 3.2 s | 1,642 | 23,197 | 11,658 | 1.56M | 2,992 / 12,735 | same |
| 2⁴, 18 | 98 | 0.79 GiB, 4.3 s | 1,234 | 18,961 | 9,540 | 1.28M | 2,436 / 12,179 | same |
| 2⁵, 14 | 96 | 1.45 GiB, 8.1 s | 962 | 16,729 | 8,424 | 1.11M | 2,139 / 11,882 | same |

Client times are single runs on 4 threads and noisy. The wallet always uses the bounded
prover (16 FRI columns).

## Budget

- **Blake (`blake_g` ≤ 2²⁰ needs ≤ 8,192 compressions).** The fixed part is 9,743:
  - bootloader 1,914;
  - OS 7,829, of which 7,355 hash the account's executed bytecode (~55k of 60.6k CASM felts).

  Fewer queries shrink only the account's Merkle share (3,865 → 2,139), so the OS share must
  come down. For 2⁴/18 the account's executed code must drop to about 26k felts; for 2⁵/14,
  about 28k.
- **Poseidon (`cube_252` ≤ 2²⁰ needs ≤ 8,192 instances).** It is almost all the OS hashing
  the calldata (~n/2 permutations). 2⁵/14 gets to 8,424, just over the limit. Packing the
  calldata (several M31 values per felt) fixes it at any configuration.
- **Other components.** `assert_eq_opcode_double_deref` and `memory_id_to_small` stay at 2²⁰
  in every run; the rest are ≤ 2¹⁹.

## Lever 3 (verifier size), scoped and dropped

The statement account's executed functions hash 54,945 felts, and only 24,660 of them run
(`results/account-function-coverage.json`). The rest is inline construction and
error-propagation code: `CircuitAirNewImpl::new` runs 349 of its 4,122 felts, and our
`verify_payment` runs 1,021 of 4,206. Starknet's libfunc list rejects `unsafe-panic`, which
would remove the unwinding code, so a contract cannot use it. At 2⁴/18, bytecode hashing may
use about 25.2k felts: even with every cold felt removed, we would be within 2% of the limit.
**Dropped 2026-09-23.** Large-path batching (one PROOF2 over k client proofs, amortizing the
log25 floor and bytecode hashing) is the better server lever if server cost matters again.

## Next (superseded)

Log20 needs the account's executed bytecode roughly halved: a verifier specialized to the
fixed R0 circuit (lever 3). Combined with 2⁴/18 (client 0.79 GiB) and calldata packing, that
would fit. Without it, the large PROOF2 path stays.
