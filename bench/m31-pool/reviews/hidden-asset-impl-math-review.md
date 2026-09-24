# Math review: R0 V4 relation implementation (hidden asset, dummy input)

2026-09-24. Independent Math Reviewer. I did not write this code. The review covers the relation
only, at commit `049df4b` on `feat/hidden-assets`, against `docs/hidden-asset-spec.md`
revision 3, §4.1–4.4. The bridge, account and pool are not implemented yet and are out of scope.

## Scope

**Read:**
- `bench/m31-private-wrapper/client-port/src/payment4.rs`, all 520 lines: `statement_limbs`,
  native `statement`, `sparse_paths`, `fresh_shape`, `Tamper`, `bit` and `build`;
- the reused gadgets in `src/payment.rs`: `amount` :538, `amount_unchecked` :547,
  `nonzero_vector` :523, `conservation` :571, `hash_batch` :618, and the V3 `build` for the
  diff;
- `src/merkle.rs:13-23` (`guess_bits`);
- the tests `tests/payment_r4.rs` and `tests/payment_r4_malicious.rs`;
- `examples/prove_payment_r4.rs` and `examples/support/mod.rs` (`native_verify`, `negatives`);
- the changes to `Cargo.toml` and `src/lib.rs`.

**Ran:**
- `cargo test --release --features tamper --test payment_r4 --test payment_r4_malicious`:
  7 + 6 tests pass.
- `prove_payment_r4 ~/.local/share/templar/runs/r4-review/nft-compress --compress-nodes --shape
  nft`: a real blinded proof.
  - Trace 2^18, proving 0.23 s, 29,458 felts.
  - 2,390 blinding rows against 1,692 revealed FRI values.
  - It verifies natively, and the five native negatives (output, trace, topology, circuit hash,
    config) are rejected.
  - `token_out = 0x0`.
  - The "pcs config" panic in the log is the caught `config` negative.
- Throwaway strict probes in `~/.local/share/templar/runs/r4-review/probe/tests/strict.rs`,
  a separate crate with a path dependency; nothing was written to the repo. All pass:
  - For every shape and both tree formats, each of these makes the circuit **invalid** (not
    merely a different statement): conservation +1 or −1, a zero output receiver, a zero output
    `rho`, and a dummy carrying value.
  - `amount₀ = 0` and `token = 0` on **consistent** trees, with input 0 re-placed as a member of
    the published root, are invalid. The controls `amount₀ = 1` and `token = 0x5` are valid.
  - `e₁ = 2` on an enabled zero-value member is rejected by booleanity alone. On the same
    witness, `e₁ = 0` is valid.
  - The same leaf in both slots is circuit-valid, with equal published nullifiers.
  - These are circuit-valid, so they are left to the bridge: identity without an intent, a zero
    delivery digest, and a recipient without an amount.

## Verdict

**CONDITIONAL GO.** The circuit implements §4.2–4.3 exactly, and I found no missing or weakened
constraint. My probes confirm that every §4.4 constraint rejects on its own. So the circuit, and
its circuit hash, can be pinned.

The condition is **HA-IM1**: a test-only fix. Five of the committed "broken witness" checks
would still pass if their target constraint were deleted, conservation included. The V4 suite
therefore does not guard the inflation-critical wiring against regression. HA-IM2 and HA-IM3 are
Low; HA-IM4 is Info.

## Conformance to §4.2–4.3

| Spec item | Implementation | Status |
| --- | --- | --- |
| `pub_ctx` = chain ‖ pool, guessed, published | `payment4.rs:371`, published at :517 | ✓ |
| One private `token`, `nonzero_vector` (4.3.1) | :373-375 | ✓ |
| `context = pub_ctx ‖ token` for all four NOTE hashes | :376, :426-431 | ✓ The single `context` is the only one built, so an output under a different asset cannot be expressed. |
| `skᵢ`, `rhoᵢ`: `nonzero_vector`; 32 position bits | :381-389 | ✓ |
| Input 0: `amount()`, nonzero (4.3.2) | :393; `cms[0]` :427; conservation :496 | ✓ Same `amt0` variables throughout. |
| Input 1: `amount_unchecked`, `sum₁·(1−e₁) = 0` (4.3.3) | :394-397; `cms[1]` :428; conservation :496 | ✓ Same `amt1`/`sum1` and one `e1` throughout. |
| `e₁` boolean | `bit` :354-360 (`b·(b−1) = 0`, identical to `guess_bits(…,1)`) | ✓ |
| `e₁·(cur₁,ℓ − cur₀,ℓ) = 0`; V3 unconditional equality removed | :466-469 | ✓ |
| Published root is `cur₀` | :517 (`cur[0]`) | ✓ |
| Nullifiers as V3 (4.3.4) | :478-484 | ✓ |
| Outputs: `nonzero_vector` receiver/rho, `amount_unchecked`, unmasked, no `active` (4.3.5) | :402-412, :486-490 | ✓ |
| Conservation `[amt₀, amt₁] = [out₀, out₁, withdrawn]` (4.3.6) | :494-500 | ✓ |
| `x` boolean; `(1−x)·withdrawnₖ = 0`, `(1−x)·intentₗ = 0`, `token_outₗ = x·tokenₗ` (4.3.7) | :504-510 | ✓ It reuses the `withdrawn` variables fed to conservation and the published `intent` variables. |
| Identity as V3, `sk₀` (4.3.8) | :511-514 | ✓ |
| Published order `[tag, pub_ctx, token_out, cur₀, nf₀, nf₁, cm₀, d₀, cm₁, d₁, recipient, withdrawn, intent, identity]`, padded to 128 | :516-519 vs `statement_limbs` :94-111 | ✓ 127 limbs; the equality is also tested for every shape. |
| Tags `R0V4`/`R0C4` | :38-40 | ✓ They differ from V3 (test `tags_differ_from_v3`). |

**Hints.** The witness hints (`e1` from `w.dummy`, `x` from `exit`, and the one-hot selectors in
`nonzero_vector`) never affect soundness. The `Tamper` hook is read only under
`cfg!(feature = "tamper")` (:349-351), and the malicious tests use it to show that the
constraints, not the hint code, do the rejecting.

**ZK-relevant uniformity.** The topology is identical across all eight shapes on both trees
(`payment_r4.rs:61-66`). The dummy input still runs its full 32-level path, so the circuit does
not depend on the shape.

**Native reference versus circuit.** The two agree on every relation rule, and the output limbs
match for 48 random witnesses. The native `statement` is stricter than the circuit in the ways
HA-IM3 lists.

## Findings

### HA-IM1 (Medium): `broken_witnesses_are_rejected` accepts "different statement" as rejection, which is vacuous for five mutations

**Location.** `tests/payment_r4.rs:142-145`. The check is
`assert!(!valid || limbs != want)`, applied to the mutations at :149-174.

**Problem.** Most of these mutations change a commitment, and so change the published limbs, and
so the check passes whether or not the circuit rejects. That is fine for "wrong sibling of input
0" (:147), because an unknown root is rejected by the pool. It is wrong for mutations where a
valid proof of a *different* statement *is* the attack:

- **conservation ±1** (:158-165): an inflated `cm₀` is exactly what a minting prover wants;
- **zero output receiver** (:166-168);
- **zero input 0** (:149-151) and **zero asset** (:152-154): the root changes too, so the
  targeted constraint is never isolated;
- **dummy input with value** (:169-174).

**Failure scenario.** Delete `conservation(...)` (`payment4.rs:494-500`) or `nonzero_vector(c,
&token, …)` (:375). Every V4 test still passes:
- honest witnesses stay valid;
- every broken case still yields `limbs != want`;
- no malicious test touches these constraints.

The dummy-value rule is the exception: `e1_zero_on_real_input`
(`payment_r4_malicious.rs:48-53`) asserts `!valid` and would catch its removal. The constraints
*are* present today; my strict probes show each of these cases is circuit-invalid.

**Required change** (tests only; no circuit or circuit-hash change):
- Assert `!valid` for conservation ±1, zero output receiver or rho, and dummy with value.
- For `amount₀ = 0` and `token = 0`, rebuild the tree so input 0 is a member of the published
  root (as `asset_just_below_2_251` does with `sparse_paths`). Assert `!valid`, with a control
  (`amount₀ = 1`, `token = 0x5`) that is valid. Otherwise the test cannot tell the targeted
  constraint from a root change.
- Keep the disjunction only for mutations whose sole effect is an unknown root.

### HA-IM2 (Low): two §4.4 tests do not isolate what they claim

**Location.** `tests/payment_r4.rs:216-231`; `tests/payment_r4_malicious.rs:32-38`.

**Problem.**
- (a) `same_leaf_twice_publishes_equal_nullifiers` never asserts that the circuit is valid. The
  §4.4 claim is that the circuit accepts and the bridge and pool reject the duplicate. My probe
  confirms the circuit is valid, but the test would also pass if the circuit rejected for an
  unrelated reason.
- (b) `e1_non_boolean` applies `e₁ = 2` to a dummy (the membership product also fails) and to a
  real nonzero input (the dummy product also fails). Neither case shows that booleanity itself is
  enforced. `e₁ ∉ {0,1}` is not exploitable, as the design review noted, but the test name
  over-claims.
- (c) "An output under a different asset" (§4.4) cannot be expressed through `Private`, which
  has one `token`. It is guaranteed by construction (`payment4.rs:376, 426-431`), and the test
  suite should say so rather than imply coverage.

**Failure scenario.** A later refactor gives outputs their own context, or drops `bit`'s
booleanity. No test notices.

**Required change.**
- (a) Assert `c.is_circuit_valid()`.
- (b) Add the isolating case: `e₁ = 2` on an **enabled zero-value member**, with
  `amount₁ = 0`, a real path and `outputs = [amount₀, 0]`. Only booleanity can reject it; the
  control `e₁ = 0` on the same witness is valid.
- (c) Add a comment in the tests, or a structural assertion that `build` creates exactly one
  context vector.

### HA-IM3 (Low): the native `statement` mixes relation rules with bridge rules without saying which is which

**Location.** `payment4.rs:115-198`, doc comment at :115.

**Problem.** The native reference rejects a duplicate nullifier (:152), a zero delivery (:160),
recipient ⇎ amount (:166) and identity without an intent (:170). The circuit accepts all four;
my probe confirms it for all but the first, which is tested above. These are §4.5 bridge checks.
The native reference also does not model the bridge-only rules at all:
- the voluntary-reveal rejection (native `token_out` is derived from `exit`, :184-188, so `x`
  is never free);
- `token_out`, `recipient` and `pool` being below 2^251;
- the zero padding limb;
- nonzero chain and pool.

The doc comment ("The public statement a valid witness proves") therefore overstates what a
proof implies.

**Failure scenario.** The V4 bridge is written to "match the native reference" and omits
identity ⇒ intent, or the exit rule. The circuit accepts a statement with a public identity
handle and no intent, or a voluntary reveal on a pure transfer, and nothing downstream rejects
it. This is a privacy failure. It is not an inflation.

**Required change.**
- Document in `statement` which checks are relation-level and which are §4.5 bridge-level, or
  split out a `bridge_checks(&Public)` that mirrors §4.5 in full, the exit rule included.
- Add tests asserting the circuit *accepts* each bridge-only violation, as the voluntary-reveal
  test already does. That test list then becomes the bridge's required negative-test list.

### HA-IM4 (Info): minor observations; no change required

- `bit` (:354-360) duplicates `guess_bits(…, 1)` so that `Tamper` can inject raw values. The
  constraint is identical. The spec's "`guess_bits`" is satisfied in substance.
- `fresh_shape` draws "just below 2^251" assets as `0x7` followed by 62 hex digits of a u64
  (:265-266). That exercises the top limb but leaves the middle limbs zero.
  `asset_just_below_2_251` covers 2^251 − 1 exactly, so coverage is adequate.
- `circuit_statement_matches_native_and_topology_is_fixed` also covers the §4.4 positive
  cases:
  - a random-path dummy (`Single`, `Nft`);
  - a pure transfer with `token_out = 0` (the bridge half is pending);
  - a single-input ERC721 spend (`Nft`: 1 → 1 + 0).

  The asset just below 2^251 is covered separately by `asset_just_below_2_251`.
- The five native negatives in `prove_payment_r4` concern the proof and configuration, not the
  relation. They are adequate for this example.
