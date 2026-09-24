//! Policy notes (ADR-0025, `docs/policy-note-spec.md` §6): the settlement statement the pool
//! receives from a P1 proof, its binding, the controller interface and the controller call.
//!
//! A policy note is an ordinary-format leaf whose receiver is `H(PRECV, pnk ‖ policy)`; it is
//! created by any deposit or R0 output. Settling it proves (P1) one committed outcome of its
//! policy. Before the deadline the pool calls the note's pinned-class controller with an
//! authorization built from proven fields; after it, only the refund (outcome 0) settles, without
//! the controller.
use core::poseidon::poseidon_hash_span;
use starknet::syscalls::{call_contract_syscall, get_class_hash_at_syscall};
use starknet::{ContractAddress, SyscallResultTrait};
use crate::hash::{Digest, is_zero, key, read_digest};
use crate::spend::Withdrawal;

pub const FIXED: u8 = 1;
pub const SPLIT: u8 = 2;
/// The controller's required return value.
pub const POLICY_OK: felt252 = 'TEMPLAR_POLICY_OK';
/// The most felts of controller data a settlement carries.
pub const MAX_POLICY_DATA: u32 = 256;

/// A P1 settlement statement, as decoded by the P1 bridge (`client-port/cairo-p1`).
#[derive(Drop, Serde)]
pub struct PolicySpend {
    pub chain: felt252,
    pub pool: ContractAddress,
    pub token: ContractAddress,
    /// Nine words each.
    pub root: Span<felt252>,
    pub nullifier: Span<felt252>,
    /// Eighteen words: commitment₀ then commitment₁ (zero when not published).
    pub commitments: Span<felt252>,
    pub delivery0: felt252,
    pub delivery1: felt252,
    pub withdrawal: Withdrawal,
    pub controller: ContractAddress,
    pub controller_class: felt252,
    pub handle: felt252,
    /// Nine words.
    pub policy_id: Span<felt252>,
    pub deadline: u64,
    pub not_before: u64,
    pub index: u8,
    pub kind: u8,
    pub x: u128,
    /// `Poseidon(data)` of the controller call's data.
    pub data: felt252,
    pub binding: felt252,
}

/// Implemented by policy controllers. The pool calls it under its lock, before the deadline,
/// after verifying the proof; any revert reverts the settlement. It must return
/// `['TEMPLAR_POLICY_OK']`.
#[starknet::interface]
pub trait ITemplarPolicyController<T> {
    fn templar_apply_policy(ref self: T, authorization: Span<felt252>, data: Span<felt252>) -> felt252;
}

/// Positions in the authorization (spec §6 step 4).
pub const AUTH_TAG: u32 = 0;
pub const AUTH_CHAIN: u32 = 1;
pub const AUTH_POOL: u32 = 2;
pub const AUTH_TOKEN: u32 = 3;
pub const AUTH_POLICY_ID: u32 = 4;
pub const AUTH_HANDLE: u32 = 5;
pub const AUTH_INDEX: u32 = 6;
pub const AUTH_KIND: u32 = 7;
pub const AUTH_X: u32 = 8;
pub const AUTH_NULLIFIER: u32 = 9;
pub const AUTH_LEN: u32 = 16;

/// `key(d)`, or zero for the zero digest (an unpublished output).
pub fn key_or_zero(d: Digest) -> felt252 {
    if is_zero(d) {
        0
    } else {
        key(d)
    }
}

/// `Poseidon('TMP1_BIND_V1', chain, pool, token, root₉, nullifier₉, commitment₀₉, commitment₁₉,
/// delivery₀, delivery₁, w_recipient, w_amount, controller, controller_class, handle,
/// policy_id₉, deadline, not_before, index, type, x, data)`, as the P1 bridge computes it.
pub fn policy_binding(s: @PolicySpend) -> felt252 {
    assert(s.root.len() == 9 && s.nullifier.len() == 9 && s.policy_id.len() == 9, 'DIGEST_LENGTH');
    assert(s.commitments.len() == 18, 'COMMITMENT_LENGTH');
    let w = *s.withdrawal;
    let mut b = array!['TMP1_BIND_V1', *s.chain, (*s.pool).into(), (*s.token).into()];
    b.append_span(*s.root);
    b.append_span(*s.nullifier);
    b.append_span(*s.commitments);
    b.append(*s.delivery0);
    b.append(*s.delivery1);
    b.append(w.recipient.into());
    b.append(w.amount.into());
    b.append((*s.controller).into());
    b.append(*s.controller_class);
    b.append(*s.handle);
    b.append_span(*s.policy_id);
    b.append((*s.deadline).into());
    b.append((*s.not_before).into());
    b.append((*s.index).into());
    b.append((*s.kind).into());
    b.append((*s.x).into());
    b.append(*s.data);
    poseidon_hash_span(b.span())
}

/// The controller authorization (spec §6 step 4).
pub fn authorization(s: @PolicySpend) -> Array<felt252> {
    let w = *s.withdrawal;
    let cms = *s.commitments;
    array![
        'TEMPLAR_POLICY_V1', *s.chain, (*s.pool).into(), (*s.token).into(), key(read_digest(*s.policy_id)), *s.handle,
        (*s.index).into(), (*s.kind).into(), (*s.x).into(), key(read_digest(*s.nullifier)), (*s.not_before).into(),
        (*s.deadline).into(), key_or_zero(read_digest(cms.slice(0, 9))), key_or_zero(read_digest(cms.slice(9, 9))),
        w.recipient.into(), w.amount.into(),
    ]
}

/// Calls the controller after checking its pinned class; reverts unless it returns exactly
/// `['TEMPLAR_POLICY_OK']`.
pub fn call_controller(s: @PolicySpend, this: ContractAddress, data: Span<felt252>) {
    let controller = *s.controller;
    assert(controller.into() != 0 && controller != this, 'POLICY_CONTROLLER');
    let class = get_class_hash_at_syscall(controller).unwrap_syscall();
    assert(class.into() != 0 && class.into() == *s.controller_class, 'CONTROLLER_CLASS');
    let mut calldata = array![];
    authorization(s).span().serialize(ref calldata);
    data.serialize(ref calldata);
    let ret = call_contract_syscall(controller, selector!("templar_apply_policy"), calldata.span()).unwrap_syscall();
    assert(ret.len() == 1 && *ret.at(0) == POLICY_OK, 'CONTROLLER_RETURN');
}
