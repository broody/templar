//! R0 spend data and its binding. The binding is the one the R0 bridge account emits
//! (`client-port/cairo-r0/bridge/src/lib.cairo`, `binding`):
//! `Poseidon('TMR0_BIND_V1', chain, pool, token, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁)`, where
//! `dᵢ` is the reference delivery digest of output `i`'s ciphertext.
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

#[derive(Drop, Serde)]
pub struct Output {
    /// Nine canonical M31 words.
    pub commitment: Span<felt252>,
    pub ciphertext: Span<felt252>,
}

/// R0: two inputs, two outputs, one token, no withdrawals or controller.
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
    pub binding: felt252,
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
    let mut data = array!['TMR0_BIND_V1', *s.chain, (*s.pool).into(), (*s.token).into()];
    data.append_span(*s.root);
    data.append_span(*s.nullifiers);
    for output in *s.outputs {
        assert(output.commitment.len() == 9, 'COMMITMENT_LENGTH');
        data.append_span(*output.commitment);
        data.append(delivery_digest(*output.ciphertext));
    }
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
