# stwo-circuits client route, end to end (stock components)

2026-09-23. **The membership relation, proved on the client as a standard blinded
stwo-circuits proof, is verified by the Cairo bridge inside the virtual OS and wrapped as a
verified PROOF2.** No circuit A and no custom proof protocol are involved. This uses the stock
component set, so the client still pays for the fixed XOR tables. The arithmetic-only profile
(~0.26 GiB measured) is step 2.

| Stage | Where | Time | Peak memory | Evidence |
| --- | --- | ---: | ---: | --- |
| Client proof (membership + statement digest, 45-row blinding) | client, 1 thread | 15.5 s | 2.75 GiB | `client/` |
| Bridge, standalone Cairo | server | — | — | 5.06M steps, 8/8 checks (`bridge-validation/`) |
| Virtual OS execution of the account | server | ~13 s | < 16 GiB | 7.22M steps, exact message (`os-capture/`) |
| PROOF2 large path | server | 140 s | 63.1 GiB | verified, 3/3 rejections (`proof2/`) |

- **Client circuit** (`examples/prove_client_sc.rs`, `src/membership.rs`): the client's own
  Poseidon2-M31 path relation, plus the statement digest
  `Blake2s("TMPZSC01" || serde_json(Public) || root LE u32)` as the 8 public output words.
  It is blinded with upstream `add_zk_blinding(seed, 35 + 10)`, proved with the bridge FRI
  config (PoW 26, blowup 2, 35 queries) on `proving@5a7c5ed`, and verified natively. Five tamper
  controls are rejected (output, trace root, preprocessed root, circuit hash, config).
- **Bridge**: the same upstream Cairo `circuit_air`. Its two GENERATED sections are regenerated
  for this circuit's shape by `examples/gen_cairo_consts.rs`, which ports upstream's rendering
  and reproduces upstream's committed constants for the production shape. It pins this
  circuit's hash and emits `(class, 'TMPZSC01_MEMBERSHIP_V1', chain, digest)`. The account is
  79,481 felts.
- The PROOF2 input PIE (`f718f06d…`) is the checked capture's. The chain state is a synthetic
  local fixture; nothing was submitted.

Hiding rests on upstream row padding, which is unproven for this circuit (see the guide page
"Two ways to build the client proof" and broody/templar#2). The client's 2.75 GiB is almost all
fixed XOR tables.
