# Context encoding repair: independent post-change source review

Verdict: **APPROVE, contingent on the execution evidence listed below.**
There are no blocking source findings in the reviewed diff.

Reviewed `git diff -- bench/m31-statement/client/src/statement.rs
bench/m31-statement/client/src/lib.rs` against baseline
`0f5448bafe2885199482b8d5a512dc98745c5692`. Reviewed file SHA-256 values:

- `statement.rs`: `ec9bdc993e3d0e6a527c546f313b6ce58ef306e94ae132731f817b97db3e4b59`
- `lib.rs`: `d1bd0f0eba9ba9f57a3dbab5ca5d1b0b630fbec05c6e398a7a37301022bb65e7`

The source now extracts nine consecutive 28-bit limbs exactly as the append
path does. The radix reconstruction argument in the pre-review applies to
every Felt, including bit 251. Every limb is strictly below the M31 modulus,
so the channel input conversion adds no field-reduction collision. Canonical
parse/format equality rejects textual aliases and reduced out-of-field
representations. Chain nonzero/full-field and pool nonzero/strict integer
address bounds are separate and match the agreed policy.

VERSION is fixed at 2 and enters the initial transcript through the same
validation path for prover and verifier. There is no legacy fallback. The
unchanged Envelope can deserialize old proofs, but their cryptographic
transcripts do not match. The summary now records `statement_version`, which
helps distinguish new measurements from preserved V1 artifacts.

The three new unit tests independently reconstruct encoded values using
BigUint, cover all 252 single-bit inputs, radix transitions, zero, one, maximum
Felt, deterministic random field elements, parser aliases and field overflow,
and separate chain/pool boundary behavior. The native mutation loop covers
exactly seven groups of four formerly discarded bits for each field, 56 new
cases total. Every case must validate and change transcript words before
the native verifier rejects the otherwise unchanged proof. Existing 16
named negative checks remain present. No findings were made about the existing
omission control; it is outside this review's substantive scope.

## Pending execution conditions

This reviewer did not run builds, tests, or proofs and has not inspected K3's
pending execution results. Integration approval requires all of the following:

1. A successful patched build and passing unit tests:
   `context_encoding_preserves_every_felt_bit`,
   `canonical_context_parser_rejects_aliases_and_field_overflow`, and
   `chain_and_pool_have_distinct_numeric_bounds`.
2. One fresh V2 proof verifies natively and its summary records version 2.
3. That fresh proof passes the mutation battery: all 72 named mutations
   reject, including all 56 formerly discarded bit mutations. The existing
   omission control also reports success.
4. On a fresh proof with original context `chain=0x434841494e` and
   `pool=0x456`, changing only chain to `0x435841494e` or only pool to
   `0x10000456` rejects. Each changed statement must remain semantically
   valid and have different transcript words. These are bit-28 instances
   already covered by the loop when using this exact original context;
   explicit execution records should identify the values.
5. An actual preserved V1 proof known to verify with the baseline verifier
   is rejected by the repaired V2 verifier. Keep its old artifacts unchanged.
   If baseline collision reproduction is reported, its two mutated proofs
   must retain the same cryptographic suffix as the original proof.

The mutation harness is intended for the selected synthetic fixture. Its
requirement that every toggled context stay valid can cause the harness itself
to fail on other legitimate contexts near semantic boundaries; that is not a
verifier defect and does not weaken the selected fixture's binding evidence.

Scope remains the context encoding, canonical parsing, semantic context
bounds, and transcript version repair. This review does not approve hiding,
padding construction, rank experiments, AIR, PCS, or any cryptographic
algorithm changes. Root may check the named execution conditions and accept
this source without a further reviewer round if the reviewed source remains
unchanged. Source changes require review of the new diff.
