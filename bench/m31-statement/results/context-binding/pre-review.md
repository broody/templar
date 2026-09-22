# Context encoding repair: independent pre-implementation review

Reviewed baseline: `0f5448bafe2885199482b8d5a512dc98745c5692`.

Scope: the proposed context encoder/canonical parsing/domain/version repair in
`bench/m31-statement/client/src/statement.rs` and corresponding native proof
mutation regressions in `client/src/lib.rs`. No hiding, padding, rank, AIR, PCS,
or cryptographic algorithm review was performed. No tests were run by this
reviewer, and this is not a post-implementation approval.

Verdict: **GO**, subject to the conditions below.

## Encoding and canonicality

The append implementation's consecutive 28-bit extractor returns precisely
`w_i = floor(x / 2^(28i)) mod 2^28`, for `i = 0..8`. Thus
`x = sum_i w_i * 2^(28i)` for every `0 <= x < 2^252`. Every Starknet field
element lies in this range: its modulus is `2^251 + 17*2^192 + 1 < 2^252`.
Consequently the mapping is injective across the complete Felt domain,
including values with bit 251 set. Every word is below `2^28`, hence below
the M31 modulus `2^31 - 1`; conversion to M31 cannot introduce reduction
collisions. Nine fixed limbs per context field also preserve field boundaries.

The original encoder consumes 32 bits per word but retains 28. It drops
positions 28..31, 60..63, 92..95, 124..127, 156..159, 188..191, and 220..223.
The next such interval starts at bit 252, outside the Felt domain. The
proposed extractor removes these losses, including both reported collisions.

Checking `format!("{f:#x}") == input` after parsing defines a unique textual
representation. If parsing reduces an out-of-field integer, its formatted
field representative differs from the original input and is rejected. This
also rejects alternate capitalization, prefixes, and leading-zero aliases
whenever they differ from the library's canonical formatter. The old bit-255
test is not a valid test of a 2^251 bound and should be removed.

## Semantic domain

Use distinct checks: chain is a canonical, nonzero full Felt; pool is a
canonical integer satisfying `0 < pool < 2^251 - 256`. The pool check must
use exact integer arithmetic after canonical parsing. This pool policy
matches the append path. Nonzero chain is an explicit new semantic policy;
append currently does not impose nonzero chain. Neither policy changes the
encoding proof above. Pool boundary rejection must not be confused with
proof-level binding.

## Version and compatibility

Changing the fixed transcript VERSION from 1 to 2 changes the initial channel
input before commitments, interaction PoW, lookup challenges, and proof
verification. This separates legacy proofs cryptographically under the
existing channel/hash and proof soundness assumptions. Keep VERSION fixed by
the verifier; do not add a fallback accepting version 1. Because Envelope has
no new discriminant, old envelopes can still deserialize. Rejection is
cryptographic, not a deterministic format/version parse error. Preserve old
measurement artifacts and identify new evidence as transcript version 2.

## Acceptance conditions for implementation review

1. Copy the contiguous extractor exactly, enforce canonical parsing and the
   separate domain checks, and use VERSION 2 on both prove and verify paths.
2. Test BigUint reconstruction independently of the extractor for zero,
   all 252 single-bit values (0 through 251), limb transitions, `p-1`,
   representative upper-domain values, and deterministic random canonical
   values. Check each word's range as well as full reconstruction.
3. Reject noncanonical aliases, field modulus/reduction inputs, zero chain,
   and zero/out-of-range pools. Accept `2^251-257` as the largest valid pool
   and reject `2^251-256`; demonstrate a full-field chain with bit 251 set.
4. Use one fresh valid proof to test all 28 formerly dropped bit positions
   in each context field plus the two reported concrete collisions. Assert
   that each mutated statement still passes semantic validation and changes
   the initial transcript words before asserting that native proof
   verification fails. Otherwise rejection could be unrelated to binding.
   Keep the existing negative battery.
5. If a preserved V1 artifact is available, verify that the repaired verifier
   rejects it. Do not regenerate or overwrite that artifact. Evidence from
   a version-only challenge mismatch is useful but should not be described
   as an actual legacy artifact verification run.

One post-change review of the exact diff is still required before final
acceptance. No broader benchmark sweep is needed for this encoding repair.
