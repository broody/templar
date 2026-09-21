# Pre-deployment review of the isolated POC2 experiment

Scope: implementation self-review and executable checks, not an independent
cryptographic audit or approval for production funds. The new test pool supports
ordinary POC2 notes only; the existing invoice pool and earlier evidence stay intact.

The spending witness must contain the preimage `sk` of both separately tagged
authority and nullifier-key hashes. The receiving identity binds both hashes;
the full viewing export cannot replace the nullifier key while retaining the
expected address. Key derivation includes chain and pool context. Input membership
binds that receiving identity, token, amount and randomness at a bounded position.
The position used in the nullifier is exactly the one used by membership. These
checks rely on Poseidon preimage/collision resistance and the required keyed-hash
properties; tests do not establish those cryptographic assumptions. Independent
review remains necessary before format adoption.

The contract recomputes the same POC2 binding as the private Cairo statement.
It includes token, ordered nullifiers, each commitment and the digest of its actual
ciphertext, plus withdrawal recipient/amount pairs. Counts and zero padding match
the reference. Canonical ciphertext encoding is nine 31-byte words and one 25-byte
word, exactly 304 bytes. Leading zero bytes survive decoding; high bits and wrong
lengths are rejected. Encryption correctness is not proved, so malformed intended
payments remain possible and must never be credited without successful decryption
and commitment matching.

Each inserted leaf writes an immutable delivery digest indexed by the same tree
position, and publishes the ciphertext in its event. This additional storage is
an explicit experiment tradeoff: an archive's payload can be checked against
contract state without separately proving historical receipt inclusion. It adds
storage/data cost and is not claimed to be the optimal final representation.
The tree component remains byte-identical to the earlier pool. Root history,
nullifier replay prevention, owner-gated verifier/fee configuration, reentrancy
locking and atomic token movement are retained. Deposits bind chain/pool, token,
actual amount and supplied inner commitment; the funding source is the caller.

The native adapter still requires transaction-level PROOF1 facts, the pinned V1
virtual OS, one expected message, exact statement address/class and chain/pool,
and bounded proof age. The statement account pins the POC2 protocol identifier
and its configured pool. No old leaves or nullifiers are reinterpreted, and no
existing deployment's verifier is changed. Unit tests with mock verdicts establish
contract guard behavior only; live proof-bearing transactions are required to
qualify the cryptographic integration.

Recovery reads one accepted block and verifies the expected pool class. Two
explicitly trusted RPC providers must agree on that block's hash and contract
state. All indexed commitments and delivery digests are fetched, the tree is
rebuilt, and every downloaded ciphertext is checked against those digests before
decryption. Missing payloads produce an incomplete result even if known unspent
value is zero. Full viewing queries candidate nullifiers at the same block and
checks provider agreement. Canonical identity is checked again at the end to
detect a reorg during synchronization.

This is not a light client: a malicious/colluding pair of RPC providers could
misrepresent chain state. Candidate-nullifier queries also reveal wallet access
patterns to RPC operators. Complete public-nullifier synchronization or another
privacy-preserving query method needs a separate design. The current small-pool
scanner makes per-position state reads and must not be treated as scalable cold
sync. L2 acceptance can still be reorganized; restored balances are explicitly
as of their checkpoint, not a claim of irreversible L1 finality.

Seeds, viewing exports, witnesses and signed requests remain in a mode-0700
temporary runtime. Public results are archived through an explicit allowlist.
This token is an unrestricted faucet fixture with no real value. Production
token behavior, controlled notes, governance, key storage/export UX, versioned
migration, desktop RAM qualification and independent security review remain open.
The experiment uses sncast; Controller CLI is not involved.
