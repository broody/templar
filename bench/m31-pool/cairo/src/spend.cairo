//! R0 spend data and its binding. The binding is the one the R0 bridge account emits
//! (`client-port/cairo-r0/bridge/src/lib.cairo`, `binding`):
//! `Poseidon('TMR0_BIND_V3', chain, pool, token, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
//! recipient, amount, intent, identity₉)`, where `dᵢ` is the reference delivery digest of output
//! `i`'s ciphertext, or 0 for an inactive output slot (zero commitment, empty ciphertext). The
//! intent is zero for an ordinary spend; with an open-note execution it is the Poseidon felt the
//! pool recomputes (`open_note::hash_intent`).
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

#[derive(Drop, Serde)]
pub struct Output {
    /// Nine canonical M31 words.
    pub commitment: Span<felt252>,
    pub ciphertext: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
pub struct Withdrawal {
    /// Zero, with a zero amount, when the spend withdraws nothing.
    pub recipient: ContractAddress,
    pub amount: u128,
}

/// R0 (V3): two inputs, up to two outputs (a zero commitment marks an inactive slot), at most
/// one withdrawal, one token, no controller; an optional execution intent and identity handle.
#[derive(Drop, Serde)]
pub struct Spend {
    pub chain: felt252,
    pub pool: ContractAddress,
    pub token: ContractAddress,
    /// Nine words: an M31 root in the pool's history.
    pub root: Span<felt252>,
    /// Two nullifiers, nine words each.
    pub nullifiers: Span<felt252>,
    pub outputs: Span<Output>,
    pub withdrawal: Withdrawal,
    /// Zero for an ordinary spend; the execution intent otherwise.
    pub intent: felt252,
    /// Nine words: the shadow-account identity handle, zero when unused.
    pub identity: Span<felt252>,
    pub binding: felt252,
}

/// Whether an output slot is active: its commitment is not all zero.
pub fn is_active(commitment: Span<felt252>) -> bool {
    let mut active = false;
    for w in commitment {
        if *w != 0 {
            active = true;
        }
    }
    active
}

/// Canonical 304 bytes = nine 31-byte big-endian words + one 25-byte word (the reference pool's
/// `delivery_digest`, unchanged).
pub fn delivery_digest(ciphertext: Span<felt252>) -> felt252 {
    assert(ciphertext.len() == 10, 'PAYLOAD_LENGTH');
    let mut data = array!['CTRL_DELIVERY_V1', 304];
    for i in 0..10_usize {
        let word = *ciphertext.at(i);
        let integer: u256 = word.into();
        let limit: u256 = if i == 9 {
            0x100000000000000000000000000000000000000000000000000
        } else {
            0x100000000000000000000000000000000000000000000000000000000000000
        };
        assert(integer < limit, 'PAYLOAD_WORD');
        data.append(word);
    }
    poseidon_hash_span(data.span())
}

pub fn compute_binding(s: @Spend) -> felt252 {
    assert(s.root.len() == 9, 'ROOT_LENGTH');
    assert(s.nullifiers.len() == 18, 'INPUT_COUNT');
    assert(s.outputs.len() == 2, 'OUTPUT_COUNT');
    assert(s.identity.len() == 9, 'IDENTITY_LENGTH');
    let mut cms = array![];
    let mut deliveries = array![];
    for output in *s.outputs {
        assert(output.commitment.len() == 9, 'COMMITMENT_LENGTH');
        cms.append_span(*output.commitment);
        if is_active(*output.commitment) {
            deliveries.append(delivery_digest(*output.ciphertext));
        } else {
            assert(output.ciphertext.len() == 0, 'INACTIVE_PAYLOAD');
            deliveries.append(0);
        }
    }
    let w = *s.withdrawal;
    binding_of(
        *s.chain, (*s.pool).into(), (*s.token).into(), *s.root, *s.nullifiers, cms.span(),
        deliveries.span(), w.recipient.into(), w.amount, *s.intent, *s.identity,
    )
}

/// `Poseidon('TMR0_BIND_V3', chain, pool, token, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
/// recipient, amount, intent, identity₉)` over already-computed delivery digests.
pub fn binding_of(
    chain: felt252, pool: felt252, token: felt252, root: Span<felt252>, nullifiers: Span<felt252>,
    commitments: Span<felt252>, deliveries: Span<felt252>, recipient: felt252, amount: u128,
    intent: felt252, identity: Span<felt252>,
) -> felt252 {
    let mut data = array!['TMR0_BIND_V3', chain, pool, token];
    data.append_span(root);
    data.append_span(nullifiers);
    data.append_span(commitments.slice(0, 9));
    data.append(*deliveries.at(0));
    data.append_span(commitments.slice(9, 9));
    data.append(*deliveries.at(1));
    data.append(recipient);
    data.append(amount.into());
    data.append(intent);
    data.append_span(identity);
    poseidon_hash_span(data.span())
}

#[starknet::interface]
pub trait IVerifier<TState> {
    fn verify(self: @TState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool;
}

#[starknet::interface]
pub trait IERC20<TState> {
    fn approve(ref self: TState, spender: ContractAddress, amount: u256) -> bool;
    fn transfer(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(ref self: TState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
    fn balance_of(self: @TState, account: ContractAddress) -> u256;
}

/// Stand-in for the fact check (whatever authenticates the PROOF2 facts carrying the binding);
/// the verdict is fixed at deployment. Measured separately; not part of the tree cost.
#[starknet::contract]
pub mod MockVerifier {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        verdict: bool,
    }

    #[constructor]
    fn constructor(ref self: ContractState, verdict: bool) {
        self.verdict.write(verdict);
    }

    #[abi(embed_v0)]
    impl VerifierImpl of super::IVerifier<ContractState> {
        fn verify(self: @ContractState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool {
            self.verdict.read()
        }
    }
}
