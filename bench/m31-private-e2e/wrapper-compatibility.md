# Wrapper compatibility for the private membership experiment

2026-09-22. Source assessment only: the proposed proof is **not directly
accepted** by the existing recursive verifier. No wrapper run was performed.
K3 gathered an interface inventory; Astra checked the selected dependency
paths and the concrete interfaces below. The compact-recursion Cargo manifest
selects `target/direct-air/stwo-circuits`; similarly named other checkouts are
not assumed authoritative.

| Candidate change | Current recursive verifier | Consequence |
|---|---|---|
| 768-bit RO roots, private leaf salts | `HashValue<T>(T,T)`, two QM31 values representing a32-byte Blake hash | New hash/leaf verification and transcript implementation required |
| Separate trace, four unsplit Q columns, R, claim/final messages and FRI roots | Fixed trace/interaction/composition roots, plus externally bound preprocessing | New proof structure and native-to-circuit conversion required |
| Two OOD samples per private trace column | Conversion uses `as_single_row` for base trace; extra previous-row sample exists only on selected interaction columns | New base-column sample representation and checks required |
| Four unsplit base-field Q_j, original constraint domain H distinct from polynomial capacity | Hard-coded two composition halves times four coordinates | New composition/zerofier adapter required |
| BCS state/coin schedule and single-fold FRI | Blake-based channel and current STARK schedule | Existing serializer/channel cannot be reused unchanged |

Source anchors under `target/direct-air/stwo-circuits/crates/`:

- `circuits/src/blake.rs:19` fixes the hash representation;
  `:29-35` converts32-byte native hashes.
- `stark_verifier/src/channel.rs:16` and `:56-67` fix the channel to that
  Blake circuit.
- `stark_verifier/src/proof.rs:379-404` fixes the recursive proof fields.
- `stark_verifier/src/proof_from_stark_proof.rs:22-28` accepts specifically
  `ExtendedStarkProof<Blake2sM31MerkleHasher>`;
  `:45-60` selects the roots and sample shapes.
- `stark_verifier/src/oods.rs:19-20` fixes eight composition columns.
- `stark_verifier/src/statement.rs:33-52` supplies compiled AIR and expected
  preprocessing identity; a new adapter must preserve this trust boundary.

The existing [Cairo bridge](../direct-air/cairo/bridge/src/lib.cairo) verifies
serialized **circuit proofs**. Its entry point is not a generic byte verifier
for an arbitrary inner STARK. Native acceptance of the new membership proof
therefore cannot be labeled PROOF1 compatibility.

Two future implementation routes are possible in principle: implement the new
verifier as a circuit behind that bridge, or implement it directly in a Cairo
program that the server proves. Neither has been implemented, reviewed or
costed for this format. The wider hash may materially increase server cost.
The current milestone's native privacy and memory evidence will inform whether
that adapter investment is justified; successful server verification in Rust
is a distinct result from actual Starknet PROOF1 production.
