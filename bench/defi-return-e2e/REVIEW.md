# Design and qualification boundaries

This experiment addresses ordinary notes only. It adds no controller dependency.
Its native proof pipeline and ownership construction come from the earlier
controlled-push experiment, but controller/policy fields are reserved zero and
nonzero controllers are rejected. The primary packages are unchanged.

## Authorization and settlement

The ownership statement binds `intent` inside the public spend binding. That
intent is a hash over version, chain, pool, input token, zero controller, adapter,
output token, input amount, minimum received, block deadline, return `inner`, zero
policy, ciphertext digest, route length, and route words. The pool reconstructs
it from the actual call. Its native verifier checks the expected statement class,
message, context, and proof age as in the baseline.

`execute_swap` requires exactly one withdrawal, to the bound adapter for the exact
input amount. It runs the spend, adapter, funding transfer, and publication under
one reentrancy lock. `apply_spend` only accepts a zero intent. Removing the intent
and recomputing the call's public binding still requires a different ownership
proof. An intentionally authored plain withdrawal remains possible; the swap
guarantee applies to an owner-authorized swap intent.

The pool checks actual output funding by comparing its token balance before and
after pulling the adapter's reported proceeds. No note is published for a merely
promised amount. An adapter failure rolls back input transfers, nullifiers, and
any private change outputs too. Network gas is still charged for reverted calls.

The native proof does not predict or prove the AMM price. Public execution
enforces the minimum against the real state at settlement. One token leaves the
pool under the private spend equation, and another enters through a funded
deposit; the system never equates raw units of different tokens.

## Return receipts and ownership

The wallet seals a version-3, fixed-size ownership payload before proving. Its
amount bytes must be zero. Settlement supplies the actual positive u128 amount,
and stores `H(DFI_RETURN_V1, amount, ciphertext_digest)` at the new leaf index.
The final note commitment includes that amount, output token, pool/chain context,
zero controller/policy, and the precommitted opaque `inner`.

Recovery requires the authenticated leaf and stored delivery digest. The wallet
decrypts the ownership material, combines it with the settled amount, reconstructs
the commitment, and checks the receiving identity. It then holds the same Note
object and uses the same ownership/nullifier statement as a normal receipt.
Version-2 full note payloads and version-3 return payloads cannot be interchanged.
Missing public history produces an incomplete result, not a zero balance.

The proof does not establish ciphertext decryptability. The spending wallet must
construct and validate its own return template correctly, just as ordinary push
delivery requires correct recipient encryption. Production interoperability needs
independent review of these formats and explicit version negotiation.

## Adapter and token assumptions

The Ekubo adapter is callable only by its immutable pool and uses an immutable
router. It allows one hop with no extensions, sends the specified input amount,
rejects partial fills, measures its output balance increase, and approves only
that output amount for the pool to pull. It gives no party access to the pool's
other token balances or an unlimited allowance.

The live pair uses synthetic ERC20s with unrestricted test faucets, both seeded
with liquidity in the existing Ekubo Sepolia deployment. This establishes call
compatibility with the deployed Core, Router, and Positions contracts. It does
not qualify fee-on-transfer, rebasing, malicious, or production ERC20s. Ekubo Core
and Positions are upgradeable dependencies; recorded class hashes identify this
run's environment. Adapter choice and protocol/route compatibility remain wallet
responsibilities.

## What each evidence layer establishes

- Python tests exercise receipt validation, fresh key derivation, viewing,
  recovery, owner-only spending, and intent-field binding.
- Cairo tests exercise the real statement against Python vectors. Separate
  contract tests use an explicitly mocked proof verdict to isolate settlement
  behavior and assert the specific rejection reason and state rollback.
- Live native tests must independently verify each proof locally and record its
  Sepolia receipt. A successful mock-adapter swap alone does not establish real
  DeFi interoperability. Fresh-process recovery and subsequent native spending
  are required to establish that the return is usable.
- Public evidence export is allowlisted and checked against fixture seed,
  spending-key, and viewing-key representations. Private witnesses, backups,
  signed requests, and recovered note caches remain in the private runtime.

## Remaining work before shipping

Review the format and contracts independently, integrate the maintained SDK,
qualify wallet proof transport/fees and address authentication, and reduce desktop
proving memory. Provide durable, private wallet synchronization. The current
scanner relies on two trusted RPC providers and exposes candidate-nullifier
queries. The test relayer's public account pays gas; that does not demonstrate
anonymous transaction submission.

The swap, amounts, timing, and return deposit are publicly linked. The intended
privacy boundary hides the earlier private input's membership and the receiving
identity, subject to the proof construction and anonymity set. Amount/timing
correlation remains possible. This experiment is not an independent privacy or
security audit.

The prototype permits one funded return in addition to private change outputs;
production batching limits must account for both. Multiple routes, partial-fill
refunds, vaults, persistent lending positions, borrowing/liquidation, and NFTs
require separate qualification. No general DeFi capability is claimed from a
single swap experiment.
