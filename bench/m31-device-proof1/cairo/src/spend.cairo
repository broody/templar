//! Copied verbatim from `bench/m31-pool/cairo/src/spend.cairo` (lines 8-23 and 45-73: the types and
//! helpers `spend5.cairo` uses); the R0 V3 `Spend`, its binding and the test contracts are left out.
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
