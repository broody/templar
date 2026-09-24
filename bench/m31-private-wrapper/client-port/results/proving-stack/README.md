# Pipeline on `starkware-libs/proving@5a7c5ed`

2026-09-23. **The complete pipeline now runs on the upstream monorepo: circuit A, the
unmodified upstream Cairo `circuit_air` verifier (one two-number FRI change), the virtual OS
and PROOF2.** All 19 circuit tests pass on the new stack. The old-pin runs remain in
`../log25-baseline/`, `../circuit-a/`, `../proof2/` (manifests in `../../pins/direct-air/`).

| Stage | Old pins (log23) | proving@5a7c5ed | Evidence |
| --- | ---: | ---: | --- |
| Circuit A proving | 69.6 s / 39.7 GiB | 67.1 s / 39.9 GiB | `circuit-a/` |
| Bridge, standalone Cairo | 4.93M steps | 5.80M steps | `bridge-validation/` (8/8) |
| Virtual OS execution | 6.88M steps | 8.13M steps | `os-capture/` (exact message) |
| PROOF2 large (log25 leaf) | 141 s / 62.6 GiB | 142 s / 66.0 GiB | `proof2/` (verified, 3/3 rejections) |

All runs used four pinned workers and zero swap. The PROOF2 input PIE (`f60ca20c…`) is the
checked capture's.

## What changed

- **Circuit A statement.** Upstream circuits expose one 8-word digest (`N_RESERVED`).
  Circuit A now outputs `Blake2s(x || root LE u32)`. Hashing the constraint root beside `x`
  binds it to the root written in `x`. The pool recomputes it with
  `templar_membership_bridge::statement_digest(chain, self, root)`. The account emits
  `(class, 'TMPZK002_MEMBERSHIP_V2', chain, digest)`; the root is no longer in the message.
- **Circuit hash pin.** Upstream's Cairo verifier mixes `circuit_hash = H(blowup, component
  sizes, preprocessed root)` into the transcript and leaves pinning to the consumer. The
  bridge asserts it equals circuit A's hash (`bridge/src/pinned.cairo`, generated from
  `circuit-a/trusted-config.json`). A proof of any other circuit is rejected before
  verification (`not circuit A`).
- **Upstream Cairo verifier.** `bounded_int`, `constraint_framework`, `verifier_core`,
  `verifier_utils` and `circuit_air` are copied byte-for-byte (hashes in
  `bridge-build-record.json`). Circuit A is padded with upstream `pad_to_targets` to the
  production multiverifier shape read from `multiverifier_consts.cairo`, so the generated
  column constants are upstream's own. The one vendor change is `circuit_fri_config()`:
  blowup 1 to 2 and queries 70 to 35 (the same 26 + 2·35 = 96 bits). With production FRI,
  circuit A proves in 49.3 s / 24.7 GiB (`circuit-a-production-fri/`), but the bridge
  needs 10.07M standalone steps and the account runs out of gas at the 1.1B L2 gas block
  limit.
- **Typed API.** Guesses use upstream `guess_m31` and U32 guesses, which range-check both
  16-bit limbs. Blake2s is upstream `blake2s_u32s`. Proof serialization is upstream
  `prepare_circuit_proof_for_cairo_verifier`, so our `serialize_full_config.rs` workaround
  is gone. Native verification follows upstream's `stwo_verify` flow, with the trusted root
  and circuit hash taken from the topology. It rejects altered output, trace root, topology
  root, circuit hash and config.
- **Oracle.** The unchanged client verifier stays on its original stwo pin (upstream
  changed `fold_line`, which the frozen prover calls). Circuit A compiles the client's
  `air.rs`, `hash.rs` and `constants.rs` directly against upstream stwo.

## Not carried over

- Checked M31 inversion (about 15% of bridge steps). Upstream's `naive.cairo` is unchanged, so
  the patch still applies; left out to keep the verifier byte-identical for now.
- Templar's bounded-memory prover patch (not upstream). The spike tool that used it moved to
  `../../pins/direct-air/examples/`.
