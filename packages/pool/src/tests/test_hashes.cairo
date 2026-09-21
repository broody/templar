//! Reference vectors and property tests for the TemplarPool v2 derivation
//! family (spec §3.1, revised 2026-09-20 by ADR-0011/0012 — V3 note tags).
//!
//! Vectors generated from the frozen derivations with inputs:
//! salt=0x5678, owner_private_key=0x321, token=0x1234, controller=0x4242,
//! policy_commitment=0x99, amount=1000 — via a Python model cross-validated
//! against all six prior golden vectors (incl. the odd-length sponge tail).
//!
//! The M2 circuit must reproduce these vectors byte-for-byte (over BN254 via
//! non-native felt252 arithmetic).

use pool::hashes::{
    compute_inner, compute_note_commitment, compute_note_id, compute_note_secret,
    compute_nullifier,
};
use starknet::ContractAddress;

fn addr(v: felt252) -> ContractAddress {
    v.try_into().unwrap()
}

const SALT: u128 = 0x5678;
const OWNER_PRIVATE_KEY: felt252 = 0x321;
const TOKEN: felt252 = 0x1234;
const CONTROLLER: felt252 = 0x4242;
const POLICY: felt252 = 0x99;
const AMOUNT: u128 = 1000;

fn secret() -> felt252 {
    compute_note_secret(SALT, OWNER_PRIVATE_KEY)
}

#[test]
fn derivations_are_deterministic() {
    assert_eq!(secret(), compute_note_secret(SALT, OWNER_PRIVATE_KEY));
    assert_eq!(compute_inner(secret()), compute_inner(compute_note_secret(SALT, OWNER_PRIVATE_KEY)));
    assert_eq!(compute_nullifier(secret()), compute_nullifier(secret()));
}

#[test]
fn derivations_are_input_sensitive() {
    let s = secret();
    assert_ne!(s, compute_note_secret(SALT + 1, OWNER_PRIVATE_KEY));
    assert_ne!(s, compute_note_secret(SALT, OWNER_PRIVATE_KEY + 1));
    assert_ne!(compute_note_id(s), compute_note_id(s + 1));

    let inner = compute_inner(s);
    let base = compute_note_commitment(addr(TOKEN), AMOUNT, addr(0), 0, inner);
    assert_ne!(base, compute_note_commitment(addr(TOKEN), AMOUNT + 1, addr(0), 0, inner));
    assert_ne!(base, compute_note_commitment(addr(TOKEN), AMOUNT, addr(CONTROLLER), POLICY, inner));
    assert_ne!(base, compute_note_commitment(addr(TOKEN), AMOUNT, addr(0), POLICY, inner));
    assert_ne!(base, compute_note_commitment(addr(TOKEN), AMOUNT, addr(0), 0, inner + 1));
    assert_ne!(compute_nullifier(s), compute_nullifier(s + 1));
}

#[test]
fn inner_hides_the_spend_capability() {
    // A sender who paid an invoice (or watched a deposit) knows `inner` and
    // `note_id` but never `note_secret` — so they cannot derive the nullifier
    // or spend the note. (Receiver-only property, ADR-0009/0012.)
    let s = secret();
    let inner = compute_inner(s);
    assert_ne!(inner, s);
    assert_ne!(compute_nullifier(inner), compute_nullifier(s));
    assert_ne!(compute_note_id(inner), compute_note_id(s));
}

#[test]
fn reference_vectors() {
    let s = secret();
    let inner = compute_inner(s);
    assert_eq!(
        s,
        0x2ac748d34723f39a5488c586bd85eeef4f7d41c47adff1eca9d27b4a45eb64e,
        "note_secret",
    );
    assert_eq!(
        inner,
        0x3f3e2dbc6518d40c8db0da9adb4cc53697135e0f18b15c8733d632cc2a4c47a,
        "inner",
    );
    assert_eq!(
        compute_note_id(s),
        0x8aa719bc987c504a483f1ab2876889495b62b0839f781a7cc890cf56b26c01,
        "note_id",
    );
    assert_eq!(
        compute_note_commitment(addr(TOKEN), AMOUNT, addr(0), 0, inner),
        0x7577d1d0bc46c70917153f1a172e86656c328370dd2dbb0db553428b0f22a6e,
        "commitment_ordinary",
    );
    assert_eq!(
        compute_note_commitment(addr(TOKEN), AMOUNT, addr(CONTROLLER), POLICY, inner),
        0x4208e9724102fc6677ead30cb1a7a373b24c785fdc8603f886c357d4d32066b,
        "commitment_controlled",
    );
    assert_eq!(
        compute_nullifier(s),
        0x18c6c60531f57833d29b3c497fd84fcf8258e52c8d91a6b0fbc04b66d9e2ca,
        "nullifier",
    );
}
