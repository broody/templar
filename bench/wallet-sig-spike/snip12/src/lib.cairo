//! P0b spike (THROWAWAY, measurement only): SNIP-12 revision-1 message hashes for Templar
//! account-bound notes.
//!
//! The prover-server bridge will call the note owner's account `is_valid_signature(hash, sig)`
//! with `hash = spend_message_hash(...)`. Everything is hand-written Poseidon over pinned type
//! hashes; the reference encoding is starknet.js `typedData.getMessageHash(td, account)`
//! (see `gen_kat.cjs`, `kat.json`, `typed-data.json`).
//!
//! message_hash = poseidon_hash_many([
//!     'StarkNet Message',
//!     domain_hash(chain_id),   // StarknetDomain { 'Templar', version 1, chain_id, revision 1 }
//!     account,                 // SNIP-12 "account" slot: the signing account
//!     struct_hash,             // TemplarSpend or TemplarKeyDerivation
//! ])

use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

pub const STARKNET_MESSAGE: felt252 = 'StarkNet Message';

/// sn_keccak of the rev-1 encodeType string
/// "StarknetDomain"("name":"shortstring","version":"shortstring","chainId":"shortstring","revision":"shortstring")
pub const STARKNET_DOMAIN_TYPE_HASH: felt252 =
    0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210;

/// sn_keccak of the rev-1 encodeType string
/// "TemplarSpend"("pool":"ContractAddress","binding_commitment":"felt","token_out":"ContractAddress",
/// "withdrawal_recipient":"ContractAddress","withdrawal_amount":"u128","intent":"felt",
/// "valid_until":"u128")  (no line breaks in the real string)
pub const TEMPLAR_SPEND_TYPE_HASH: felt252 =
    0x345e1c67b3674e509394d35a1a2f6205c217586359fe5c5c729bd3cfd64710e;

/// sn_keccak of the rev-1 encodeType string
/// "TemplarKeyDerivation"("purpose":"shortstring","chain":"shortstring","account":"ContractAddress")
pub const TEMPLAR_KEY_DERIVATION_TYPE_HASH: felt252 =
    0x2c12ffa63c6a1e80ff60bf73eef3bf52feb22e5cf5b4c75a4d5df70a8245e1;

pub const DOMAIN_NAME: felt252 = 'Templar';
/// The typed-data value is the string '1', but starknet.js encodes a numeric-looking shortstring
/// as a number (`getHex('1') = 0x1`), NOT ASCII 0x31. Same for `revision`.
pub const DOMAIN_VERSION: felt252 = 1;
pub const DOMAIN_REVISION: felt252 = 1;

/// StarknetDomain struct hash for the Templar domain on `chain_id` (e.g. 'SN_SEPOLIA').
pub fn domain_hash(chain_id: felt252) -> felt252 {
    poseidon_hash_span(
        [STARKNET_DOMAIN_TYPE_HASH, DOMAIN_NAME, DOMAIN_VERSION, chain_id, DOMAIN_REVISION].span(),
    )
}

/// binding_commitment = poseidon_hash_many([binding, salt]). The salt is given only to the bridge.
pub fn binding_commitment(binding: felt252, salt: felt252) -> felt252 {
    poseidon_hash_span([binding, salt].span())
}

/// TemplarSpend struct hash (members in declaration order; u128 widened to felt).
pub fn spend_struct_hash(
    pool: ContractAddress,
    binding_commitment: felt252,
    token_out: ContractAddress,
    withdrawal_recipient: ContractAddress,
    withdrawal_amount: u128,
    intent: felt252,
    valid_until: u128,
) -> felt252 {
    poseidon_hash_span(
        [
            TEMPLAR_SPEND_TYPE_HASH, pool.into(), binding_commitment, token_out.into(),
            withdrawal_recipient.into(), withdrawal_amount.into(), intent, valid_until.into(),
        ]
            .span(),
    )
}

/// TemplarKeyDerivation struct hash.
pub fn derivation_struct_hash(purpose: felt252, chain: felt252, account: ContractAddress) -> felt252 {
    poseidon_hash_span([TEMPLAR_KEY_DERIVATION_TYPE_HASH, purpose, chain, account.into()].span())
}

/// SNIP-12 rev-1 envelope: poseidon('StarkNet Message', domain_hash, account, struct_hash).
pub fn message_hash(chain_id: felt252, account: ContractAddress, struct_hash: felt252) -> felt252 {
    poseidon_hash_span([STARKNET_MESSAGE, domain_hash(chain_id), account.into(), struct_hash].span())
}

/// The hash the bridge passes to `account.is_valid_signature`. Equals starknet.js
/// `typedData.getMessageHash(TemplarSpend typedData, account)` with
/// `binding_commitment = poseidon_hash_many([binding, salt])`.
pub fn spend_message_hash(
    chain_id: felt252,
    account: ContractAddress,
    pool: ContractAddress,
    binding: felt252,
    salt: felt252,
    token_out: ContractAddress,
    withdrawal_recipient: ContractAddress,
    withdrawal_amount: u128,
    intent: felt252,
    valid_until: u128,
) -> felt252 {
    let struct_hash = spend_struct_hash(
        pool,
        binding_commitment(binding, salt),
        token_out,
        withdrawal_recipient,
        withdrawal_amount,
        intent,
        valid_until,
    );
    message_hash(chain_id, account, struct_hash)
}

/// Key-derivation message: TemplarKeyDerivation { purpose, chain, account } signed by `account`
/// (the message's `account` member and the envelope's account slot are the same address).
pub fn derivation_message_hash(
    chain_id: felt252, account: ContractAddress, purpose: felt252, chain: felt252,
) -> felt252 {
    message_hash(chain_id, account, derivation_struct_hash(purpose, chain, account))
}
