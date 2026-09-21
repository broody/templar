// Client-phase workload benchmark for the Templar trustless privacy pool.
//
// Cryptographic primitives are faithful copies from
// starkware-libs/starknet-privacy (Apache-2.0):
//   - packages/privacy/src/hashes.cairo  (Poseidon domain-separated hashes)
//   - packages/privacy/src/utils.cairo   (ECDH helpers, encryption, pack)
//
// This models exactly what the transaction prover executes in the virtual
// Starknet block for one user transaction (the `compile_actions` client
// phase), and therefore what a client-side prover would have to prove.

use core::ec::stark_curve::{GEN_X, GEN_Y};
use core::ec::{EcPoint, EcPointTrait};
use core::num::traits::{WrappingAdd, Zero};
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

// ---------------------------------------------------------------------------
// Domain separation tags (verbatim from hashes.cairo)
// ---------------------------------------------------------------------------

pub mod domain_separation {
    pub const CHANNEL_MARKER_TAG: felt252 = 'CHANNEL_MARKER_TAG:V1';
    pub const CHANNEL_KEY_TAG: felt252 = 'CHANNEL_KEY_TAG:V1';
    pub const SUBCHANNEL_MARKER_TAG: felt252 = 'SUBCHANNEL_MARKER_TAG:V1';
    pub const SUBCHANNEL_ID_TAG: felt252 = 'SUBCHANNEL_ID_TAG:V1';
    pub const NULLIFIER_TAG: felt252 = 'NULLIFIER_TAG:V1';
    pub const ENC_CHANNEL_KEY_TAG: felt252 = 'ENC_CHANNEL_KEY_TAG:V1';
    pub const ENC_SENDER_ADDR_TAG: felt252 = 'ENC_SENDER_ADDR_TAG:V1';
    pub const NOTE_ID_TAG: felt252 = 'NOTE_ID_TAG:V1';
    pub const ENC_AMOUNT_TAG: felt252 = 'ENC_AMOUNT_TAG:V1';
    pub const ENC_TOKEN_TAG: felt252 = 'ENC_TOKEN_TAG:V1';
    pub const ENC_PRIVATE_KEY_TAG: felt252 = 'ENC_PRIVATE_KEY_TAG:V1';
    pub const ENC_USER_ADDR_TAG: felt252 = 'ENC_USER_ADDR_TAG:V1';
    pub const ENC_RECIPIENT_ADDR_TAG: felt252 = 'ENC_RECIPIENT_ADDR_TAG:V1';
    pub const OUTGOING_CHANNEL_ID_TAG: felt252 = 'OUTGOING_CHANNEL_ID_TAG:V1';
}
use domain_separation::*;

// ---------------------------------------------------------------------------
// Poseidon hashes (verbatim from hashes.cairo)
// ---------------------------------------------------------------------------

pub fn hash(data: Span<felt252>) -> felt252 {
    poseidon_hash_span(data)
}

pub fn compute_channel_key(
    sender_addr: ContractAddress,
    sender_private_key: felt252,
    recipient_addr: ContractAddress,
    recipient_public_key: felt252,
) -> felt252 {
    hash(
        [
            CHANNEL_KEY_TAG, sender_addr.into(), sender_private_key, recipient_addr.into(),
            recipient_public_key,
        ]
            .span(),
    )
}

pub fn compute_outgoing_channel_id(
    sender_addr: ContractAddress, sender_private_key: felt252, index: usize,
) -> felt252 {
    hash(
        [
            OUTGOING_CHANNEL_ID_TAG, sender_addr.into(), sender_private_key, index.into(),
            Zero::zero(),
        ]
            .span(),
    )
}

pub fn compute_channel_marker(
    channel_key: felt252,
    sender_addr: ContractAddress,
    recipient_addr: ContractAddress,
    recipient_public_key: felt252,
) -> felt252 {
    hash(
        [
            CHANNEL_MARKER_TAG, channel_key, sender_addr.into(), recipient_addr.into(),
            recipient_public_key,
        ]
            .span(),
    )
}

pub fn compute_subchannel_id(channel_key: felt252, index: usize) -> felt252 {
    hash([SUBCHANNEL_ID_TAG, channel_key, index.into(), Zero::zero()].span())
}

pub fn compute_subchannel_marker(
    channel_key: felt252,
    recipient_addr: ContractAddress,
    recipient_public_key: felt252,
    token: ContractAddress,
) -> felt252 {
    hash(
        [
            SUBCHANNEL_MARKER_TAG, channel_key, recipient_addr.into(), recipient_public_key,
            token.into(),
        ]
            .span(),
    )
}

pub fn compute_note_id(
    channel_key: felt252, token: ContractAddress, index: usize,
) -> felt252 {
    hash([NOTE_ID_TAG, channel_key, token.into(), index.into(), Zero::zero()].span())
}

pub fn compute_enc_amount_hash(
    channel_key: felt252, token: ContractAddress, index: usize, salt: u128,
) -> felt252 {
    hash(
        [ENC_AMOUNT_TAG, channel_key, token.into(), index.into(), Zero::zero(), salt.into()].span(),
    )
}

pub fn compute_enc_token_hash(channel_key: felt252, index: usize, salt: felt252) -> felt252 {
    hash([ENC_TOKEN_TAG, channel_key, index.into(), Zero::zero(), salt].span())
}

pub fn compute_enc_channel_key_hash(shared_x: felt252) -> felt252 {
    hash([ENC_CHANNEL_KEY_TAG, shared_x].span())
}

pub fn compute_enc_sender_addr_hash(shared_x: felt252) -> felt252 {
    hash([ENC_SENDER_ADDR_TAG, shared_x].span())
}

pub fn compute_enc_private_key_hash(shared_x: felt252) -> felt252 {
    hash([ENC_PRIVATE_KEY_TAG, shared_x].span())
}

pub fn compute_enc_user_addr_hash(shared_x: felt252) -> felt252 {
    hash([ENC_USER_ADDR_TAG, shared_x].span())
}

pub fn compute_enc_recipient_addr_hash(
    sender_addr: ContractAddress, sender_private_key: felt252, index: usize, salt: felt252,
) -> felt252 {
    hash(
        [
            ENC_RECIPIENT_ADDR_TAG, sender_addr.into(), sender_private_key, index.into(),
            Zero::zero(), salt,
        ]
            .span(),
    )
}

pub fn compute_nullifier(
    channel_key: felt252, token: ContractAddress, index: usize, owner_private_key: felt252,
) -> felt252 {
    hash(
        [NULLIFIER_TAG, channel_key, token.into(), index.into(), Zero::zero(), owner_private_key]
            .span(),
    )
}

// ---------------------------------------------------------------------------
// ECDH helpers and encryption (verbatim from utils.cairo)
// ---------------------------------------------------------------------------

pub fn GEN_P() -> EcPoint {
    EcPointTrait::new(x: GEN_X, y: GEN_Y).unwrap()
}

fn _compute_shared_x(ephemeral_secret: felt252, public_key: felt252) -> (felt252, felt252) {
    let ephemeral_pub_point = GEN_P().mul(scalar: ephemeral_secret);
    let ephemeral_pub_x = ephemeral_pub_point
        .try_into()
        .expect('ZERO_EPHEMERAL_PUBLIC')
        .x();
    let public_point = EcPointTrait::new_from_x(x: public_key).expect('INVALID_PUBLIC_KEY');
    let shared_point = public_point.mul(scalar: ephemeral_secret);
    let shared_x = shared_point.try_into().expect('ZERO_SHARED').x();
    (ephemeral_pub_x, shared_x)
}

pub fn derive_public_key(private_key: felt252) -> felt252 {
    let private_key_point = GEN_P().mul(scalar: private_key);
    private_key_point.try_into().expect('ZERO_DERIVED_PUBLIC_KEY').x()
}

pub fn encrypt_channel_info(
    ephemeral_secret: felt252,
    recipient_public_key: felt252,
    channel_key: felt252,
    sender_addr: ContractAddress,
) -> (felt252, felt252, felt252) {
    let (ephemeral_pub_x, shared_x) = _compute_shared_x(
        :ephemeral_secret, public_key: recipient_public_key,
    );
    let enc_channel_key = compute_enc_channel_key_hash(:shared_x) + channel_key;
    let enc_sender_addr = compute_enc_sender_addr_hash(:shared_x) + sender_addr.into();
    (ephemeral_pub_x, enc_channel_key, enc_sender_addr)
}

pub fn encrypt_subchannel_info(
    channel_key: felt252, index: usize, token: ContractAddress, salt: felt252,
) -> felt252 {
    compute_enc_token_hash(:channel_key, :index, :salt) + token.into()
}

pub fn encrypt_outgoing_channel_info(
    sender_addr: ContractAddress,
    sender_private_key: felt252,
    index: usize,
    recipient_addr: ContractAddress,
    salt: felt252,
) -> felt252 {
    compute_enc_recipient_addr_hash(:sender_addr, :sender_private_key, :index, :salt)
        + recipient_addr.into()
}

pub fn encrypt_private_key(
    ephemeral_secret: felt252, auditor_public_key: felt252, private_key: felt252,
) -> (felt252, felt252) {
    let (ephemeral_pub_x, shared_x) = _compute_shared_x(
        :ephemeral_secret, public_key: auditor_public_key,
    );
    let enc_private_key = compute_enc_private_key_hash(:shared_x) + private_key;
    (ephemeral_pub_x, enc_private_key)
}

pub fn encrypt_user_addr(
    ephemeral_secret: felt252, auditor_public_key: felt252, user_addr: ContractAddress,
) -> (felt252, felt252) {
    let (ephemeral_pub_x, shared_x) = _compute_shared_x(
        :ephemeral_secret, public_key: auditor_public_key,
    );
    let enc_user_addr = compute_enc_user_addr_hash(:shared_x) + user_addr.into();
    (ephemeral_pub_x, enc_user_addr)
}

pub fn pack(value_1: u128, value_2: u128) -> felt252 {
    let packed = u256 { high: value_1, low: value_2 };
    packed.try_into().expect('PACK_OVERFLOW')
}

pub fn enc_note_packed_value(
    channel_key: felt252, token: ContractAddress, index: usize, salt: u128, amount: u128,
) -> felt252 {
    let enc_amount_hash: u256 = compute_enc_amount_hash(:channel_key, :token, :index, :salt)
        .into();
    let enc_amount: u128 = enc_amount_hash.low.wrapping_add(amount);
    pack(value_1: salt, value_2: enc_amount)
}

// ---------------------------------------------------------------------------
// Workloads — one `transfer` mirrors one real user transaction's client
// phase: open a channel to a fresh recipient, spend 2 notes, create 2
// encrypted notes, withdraw to a public address.
// `registration` mirrors the one-time SetViewingKey action.
// ---------------------------------------------------------------------------

/// Deterministic pseudo-random scalar from a counter (models SDK-side fresh
/// randomness; cost of generation is outside the proven program anyway).
fn prng(seed: usize) -> felt252 {
    hash([seed.into()].span())
}

fn address(seed: usize) -> ContractAddress {
    hash([seed.into(), 'ADDR'].span()).try_into().unwrap()
}

/// SetViewingKey: 3 EC scalar multiplications + 2 poseidon.
fn registration(seed: usize) -> felt252 {
    let user_private_key = prng(seed);
    let auditor_public_key = derive_public_key(prng(seed + 1));
    let (eph_pub_x, enc) = encrypt_private_key(prng(seed + 2), auditor_public_key,
        user_private_key);
    let public_key = derive_public_key(user_private_key);
    hash([eph_pub_x, enc, public_key].span())
}

/// One representative transfer = OpenChannel + OpenSubchannel (1 each),
/// 2 × UseNote, 2 × CreateEncNote, 1 × Withdraw.
fn transfer(seed: usize) -> felt252 {
    let sender_addr = address(seed);
    let sender_private_key = prng(seed + 1);
    let recipient_addr = address(seed + 2);
    let recipient_public_key = derive_public_key(prng(seed + 3));
    let token = address(seed + 4);
    let auditor_public_key = derive_public_key(prng(seed + 5));

    // OpenChannel + OpenSubchannel
    let channel_key = compute_channel_key(
        sender_addr, sender_private_key, recipient_addr, recipient_public_key,
    );
    let channel_marker = compute_channel_marker(channel_key, sender_addr, recipient_addr,
        recipient_public_key);
    let subchannel_id = compute_subchannel_id(channel_key, 0);
    let subchannel_marker = compute_subchannel_marker(channel_key, recipient_addr,
        recipient_public_key, token);
    let (eph_pub_x, enc_channel_key, enc_sender_addr) = encrypt_channel_info(
        prng(seed + 6), recipient_public_key, channel_key, sender_addr,
    );
    let enc_token = encrypt_subchannel_info(channel_key, 0, token, prng(seed + 7));
    let outgoing_channel_id = compute_outgoing_channel_id(sender_addr, sender_private_key, 0);
    let enc_out_recipient = encrypt_outgoing_channel_info(sender_addr, sender_private_key, 0,
        recipient_addr, prng(seed + 8));

    // 2 × UseNote (spend 2 incoming notes -> nullifiers)
    let n0 = compute_nullifier(channel_key, token, 0, sender_private_key);
    let n1 = compute_nullifier(channel_key, token, 1, sender_private_key);
    let id0 = compute_note_id(channel_key, token, 0);
    let id1 = compute_note_id(channel_key, token, 1);

    // 2 × CreateEncNote
    let note0 = enc_note_packed_value(channel_key, token, 2, 0x111, 350);
    let note1 = enc_note_packed_value(channel_key, token, 3, 0x222, 650);

    // Withdraw (encrypt user address, 2 EC muls)
    let (w_eph_x, enc_user_addr) = encrypt_user_addr(prng(seed + 9), auditor_public_key,
        sender_addr);

    hash(
        [
            channel_key, channel_marker, subchannel_id, subchannel_marker, eph_pub_x,
            enc_channel_key, enc_sender_addr, enc_token, outgoing_channel_id, enc_out_recipient,
            n0, n1, id0, id1, note0, note1, w_eph_x, enc_user_addr,
        ]
            .span(),
    )
}

#[executable]
fn main(transfers: usize) -> felt252 {
    let mut sink = registration(0);
    let mut i = 0;
    while i < transfers {
        sink = hash([sink, transfer(1000 + i * 16)].span());
        i += 1;
    }
    sink
}
