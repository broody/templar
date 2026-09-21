//! Pool transport guards with mocked proof verdicts; live native proofs are separate.
use core::poseidon::poseidon_hash_span;
use starknet::{ContractAddress, contract_address_const, get_tx_info, SyscallResultTrait};
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, test_address,
    start_cheat_caller_address, spy_events, EventSpyAssertionsTrait};
use pool::pool::{IPoolDispatcher, IPoolDispatcherTrait};
use pool::pool::Pool::{NotePublished, Event};
use pool::spend::{Output, Withdrawal, Spend, PROTOCOL_VERSION, compute_binding, delivery_digest,
                  IERC20Dispatcher, IERC20DispatcherTrait};
use pool::tree::{ITreeDispatcher, ITreeDispatcherTrait};

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
fn payload() -> Span<felt252> { array![1,2,3,4,5,6,7,8,9,10].span() }
fn setup(verdict: bool) -> (IPoolDispatcher, IERC20Dispatcher) {
    let verifier = deploy("MockVerifier",array![verdict.into()]);
    let pool = deploy("Pool",array![test_address().into(),verifier.into()]);
    let token = deploy("E2EToken",array![test_address().into(),10000,0]);
    let p = IPoolDispatcher { contract_address: pool };
    let t = IERC20Dispatcher { contract_address: token };
    t.approve(pool,10000);
    p.deposit(token,100,0xbeef,payload());
    (p,t)
}
fn spend(p: @IPoolDispatcher, t: @IERC20Dispatcher) -> Spend {
    let mut s = Spend {
        version: PROTOCOL_VERSION, chain: get_tx_info().unbox().chain_id, pool: *p.contract_address,
        root: ITreeDispatcher { contract_address: *p.contract_address }.get_root(),
        token: *t.contract_address, binding: 0, nullifiers: array![123].span(),
        outputs: array![Output { commitment: 456,ciphertext: payload() }].span(),
        withdrawals: array![Withdrawal { recipient: contract_address_const::<0xb0b>(),amount: 40 }].span(),
    };
    s.binding = compute_binding(@s);
    s
}

#[test]
fn deposit_binds_funding_context_and_publishes_bytes() {
    let mut spy = spy_events();
    let (p,t) = setup(true);
    let cm = poseidon_hash_span(array!['PUSH_NOTE_V2',get_tx_info().unbox().chain_id,
        p.contract_address.into(),t.contract_address.into(),100,0,0,0xbeef].span());
    let tree = ITreeDispatcher { contract_address: p.contract_address };
    assert_eq!(tree.get_leaf_count(),1);
    assert_eq!(tree.get_node(0,0),cm);
    assert_eq!(p.get_delivery_digest(0),delivery_digest(payload()));
    spy.assert_emitted(@array![(p.contract_address,Event::NotePublished(NotePublished {
        index: 0,commitment: cm,digest: delivery_digest(payload()),ciphertext: payload() }))]);
}
#[test]
fn spend_publishes_bound_delivery_and_marks_nullifier() {
    let (p,t) = setup(true);
    p.set_fee(t.contract_address,5,contract_address_const::<0xfee>());
    p.apply_spend(spend(@p,@t),array![].span());
    assert(p.get_nullifier_spent(123),'NOT_SPENT');
    assert_eq!(ITreeDispatcher { contract_address: p.contract_address }.get_leaf_count(),2);
    assert_eq!(p.get_delivery_digest(1),delivery_digest(payload()));
}
#[test]
#[should_panic(expected: ('BAD_BINDING',))]
fn changed_ciphertext_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.outputs = array![Output { commitment: 456,ciphertext: array![2,2,3,4,5,6,7,8,9,10].span() }].span();
    p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('PAYLOAD_LENGTH',))]
fn omitted_ciphertext_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.outputs = array![Output { commitment: 456,ciphertext: array![].span() }].span();
    p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('PAYLOAD_WORD',))]
fn oversized_full_word_rejected() {
    delivery_digest(array![0x100000000000000000000000000000000000000000000000000000000000000,2,3,4,5,6,7,8,9,10].span());
}
#[test]
#[should_panic(expected: ('PAYLOAD_WORD',))]
fn oversized_tail_word_rejected() {
    delivery_digest(array![1,2,3,4,5,6,7,8,9,0x100000000000000000000000000000000000000000000000000].span());
}
#[test]
#[should_panic(expected: ('NULLIFIER_USED',))]
fn replay_rejected() {
    let (p,t) = setup(true); p.apply_spend(spend(@p,@t),array![].span());
    p.apply_spend(spend(@p,@t),array![].span());
}
#[test]
#[should_panic(expected: ('NULLIFIER_USED',))]
fn duplicate_nullifiers_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.nullifiers = array![123,123].span(); s.binding = compute_binding(@s); p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('BAD_BINDING',))]
fn redirected_withdrawal_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.withdrawals = array![Withdrawal { recipient: contract_address_const::<0xabc>(),amount: 40 }].span();
    p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('BAD_WITHDRAWAL',))]
fn rebound_zero_withdrawal_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.withdrawals = array![Withdrawal { recipient: contract_address_const::<0>(),amount: 40 }].span();
    s.binding = compute_binding(@s); p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('WRONG_VERSION',))]
fn legacy_version_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.version = 'TEMPLAR_V2'; s.binding = compute_binding(@s); p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('WRONG_CHAIN',))]
fn other_chain_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.chain = 9; s.binding = compute_binding(@s); p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('WRONG_POOL',))]
fn other_pool_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.pool = contract_address_const::<0x42>(); s.binding = compute_binding(@s); p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('UNKNOWN_ROOT',))]
fn unknown_root_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.root = 42; s.binding = compute_binding(@s); p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('INPUT_COUNT',))]
fn empty_inputs_rejected() {
    let (p,t) = setup(true); let mut s = spend(@p,@t);
    s.nullifiers = array![].span(); p.apply_spend(s,array![].span());
}
#[test]
#[should_panic(expected: ('PROOF_REJECTED',))]
fn rejecting_verifier_blocks_spend() {
    let (p,t) = setup(false); p.apply_spend(spend(@p,@t),array![].span());
}
#[test]
#[should_panic(expected: ('NOT_OWNER',))]
fn only_owner_can_change_verifier() {
    let (p,_) = setup(true);
    start_cheat_caller_address(p.contract_address,contract_address_const::<0x999>());
    p.set_verifier(contract_address_const::<0x888>());
}
#[test]
#[should_panic(expected: ('NOT_OWNER',))]
fn only_owner_can_change_fee() {
    let (p,t) = setup(true);
    start_cheat_caller_address(p.contract_address,contract_address_const::<0x999>());
    p.set_fee(t.contract_address,1,contract_address_const::<0x999>());
}
#[test]
#[should_panic(expected: ('UNKNOWN_INDEX',))]
fn uninserted_delivery_not_available() {
    let (p,_) = setup(true); p.get_delivery_digest(1);
}
