# Spike: blinded upstream stwo-circuits client proof

2026-09-23. **The membership relation proves as a standard stwo-circuits proof with
upstream blinding, and the existing Cairo bridge verifies it unchanged. Client
memory is 2.75 GiB, and 95% of that is fixed lookup tables the relation never uses.**

The relation is `air::witness`: a Poseidon2-M31 leaf sponge and 32 levels. It is
built from the client's own permutation source (`src/membership.rs`) and outputs
the nine root words. Tests: `tests/spike_membership.rs`. The permutation equals
`hash::record`, the root equals the client witness, and the topology is
witness-independent. Blinding is `add_zk_blinding` with 35 + NON_QUERY_INFO_LEAK = 45
rows per component, as upstream. The PCS config is the bridge's (blowup 2, 35 queries,
PoW 26). Runs used a 16 GiB cap, zero swap and a development host, not a phone.

| Run | Threads | Peak RSS | Prove | Trace log | Proof felts |
| --- | ---: | ---: | ---: | ---: | ---: |
| Membership, blinded | 1 | 2.75 GiB | 21.3 s | 20 | 45,700 |
| Membership, blinded | 4 | 2.83 GiB | 7.3 s | 20 | 46,304 |
| Membership, no blinding | 1 | 2.75 GiB | 19.3 s | 20 | 46,020 |
| Trivial circuit (floor), blinded | 1 | 2.60 GiB | 14.3 s | 20 | 46,112 |

The relation needs 253,225 arithmetic rows (log18). The proof is nonetheless log20,
set by the always-present `verify_bitwise_xor_12` table (log20). The other xor tables
are log18/16/14/8. Blinding adds about 2 s and no measurable memory. For comparison,
the TMPZK002 client proves the same relation in ~1 s and 53 MiB.

The bridge was built from this proof's trusted manifest with the unchanged
generator and vendor. It accepts the proof in 4.23M Cairo steps and returns
exactly the public root. An altered output, altered proof data and trailing data
are rejected. Server cost on this route is bridge + virtual OS + PROOF2 (~62 GiB
peak); circuit A disappears.

## Where the 2.75 GiB goes (follow-up, same day)

| Client proof, 1 thread | Peak RSS | Time | Verifiable by the bridge |
| --- | ---: | ---: | --- |
| Stock, default | 2.75 GiB | 21.3 s | yes |
| Stock, bounded FRI materialization (`prove_circuit_with_precompute_bounded`, k=4) | 1.44 GiB | 27 s | yes (same format) |
| Floor circuit, bounded, k = 16 / 4 / 1 | 1.39 GiB | 24–29 s | yes |
| Eq + QM31 only (XOR/range tables and their components removed), default | 0.53 GiB | 8.3 s | no (measurement only) |
| Eq + QM31 only, bounded k=4 | **0.26 GiB** | 8.5 s | no (measurement only) |

The last two rows use a measurement-only patch of a separate stwo-circuits copy
(`noxor-measurement.patch`, driver `noxor-spike/`, flag `TEMPLAR_NOXOR`). It keeps
only the `eq` and `qm31_ops` components and their columns. It skips padding for
the removed gates and applies upstream-style blinding (45 random rows) to the two
remaining components. Each proof is natively verified as that two-component
statement, the lookup sum balances, and the outputs equal the client root. The
trace drops to log18 with 10 preprocessed columns (from log20 and 45). No deployed
verifier accepts this profile: using it needs an arithmetic-only component set in
both the Rust and the Cairo verifier, from upstream or as a reviewed local change.

Conclusion: about 90% of the stock client cost is the fixed XOR tables. Bounded
mode halves it with no format change. Without the tables the membership proof costs
about 260 MiB and 8.5 s on one host thread (TMPZK002: 53 MiB, 1 s).

Open: (1) whether the upstream blinding argument covers circuits built from these
components (StarkWare question); (2) an arithmetic-only component profile in
the Rust and Cairo verifiers (measured above at ~260 MiB), from upstream or as a
reviewed local change; (3) the cost of the full 2-in/2-out payment relation; (4) WASM portability of the circuit
prover.
