//! Baseline for bench/m31-pool: the reference felt252 pool, measured the same way (in-test L2
//! gas of one call on a warm pool). Ordinary spends, two inputs and two outputs, no withdrawals.
use core::testing::get_available_gas;
use starknet::{ContractAddress, contract_address_const, get_tx_info, SyscallResultTrait};
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, test_address};
use pool::pool::{IPoolDispatcher, IPoolDispatcherTrait};
use pool::spend::{Output, Spend, Withdrawal, PROTOCOL_VERSION, compute_binding, IERC20Dispatcher, IERC20DispatcherTrait};
use pool::tree::{ITreeDispatcher, ITreeDispatcherTrait};

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
fn payload() -> Span<felt252> { array![1,2,3,4,5,6,7,8,9,10].span() }
fn setup() -> (IPoolDispatcher, IERC20Dispatcher) {
    let verifier = deploy("MockVerifier", array![1]);
    let pool = deploy("Pool", array![test_address().into(), verifier.into()]);
    let token = deploy("E2EToken", array![test_address().into(), 1000000, 0]);
    let t = IERC20Dispatcher { contract_address: token };
    t.approve(pool, 1000000);
    (IPoolDispatcher { contract_address: pool }, t)
}
fn deposit(p: @IPoolDispatcher, t: @IERC20Dispatcher, inner: felt252) {
    (*p).deposit((*t).contract_address, 100, contract_address_const::<0>(), 0, inner, payload());
}
fn spend(p: @IPoolDispatcher, t: @IERC20Dispatcher, nf: felt252, cm: felt252) -> Spend {
    let mut s = Spend {
        version: PROTOCOL_VERSION, chain: get_tx_info().unbox().chain_id, pool: *p.contract_address,
        root: ITreeDispatcher { contract_address: *p.contract_address }.get_root(),
        token: *t.contract_address, binding: 0, controller: contract_address_const::<0>(), deadline: 0, nonce: 0,
        transition: 0, sig_r: 0, sig_s: 0, nullifiers: array![nf, nf + 1].span(),
        outputs: array![Output { commitment: cm, ciphertext: payload() }, Output { commitment: cm + 1, ciphertext: payload() }].span(),
        withdrawals: array![].span(),
    };
    s.binding = compute_binding(@s);
    s
}

const WARM: u32 = 4;

fn warm_pool() -> (IPoolDispatcher, IERC20Dispatcher) {
    let (p, t) = setup();
    let mut i = 0;
    while i < WARM { deposit(@p, @t, (i * 10 + 100).into()); i += 1; }
    p.apply_spend(spend(@p, @t, 1000, 2000), array![].span());
    (p, t)
}

#[test]
fn cost_base_felt() { warm_pool(); }

#[test]
fn cost_deposit_felt() {
    let (p, t) = warm_pool();
    let g = get_available_gas();
    deposit(@p, @t, 999);
    println!("GAS deposit felt warm={}", g - get_available_gas());
}

#[test]
fn cost_spend_felt() {
    let (p, t) = warm_pool();
    let s = spend(@p, @t, 3000, 4000);
    let g = get_available_gas();
    p.apply_spend(s, array![].span());
    println!("GAS apply_spend felt warm={}", g - get_available_gas());
}

/// Ordinary spend with `n_out` outputs and one withdrawal of 40 (the reference shape limits).
fn spend_shape(p: @IPoolDispatcher, t: @IERC20Dispatcher, nf: felt252, cm: felt252, n_out: u32) -> Spend {
    let mut outputs = array![];
    let mut j = 0;
    while j < n_out { outputs.append(Output { commitment: cm + j.into(), ciphertext: payload() }); j += 1; }
    let mut s = Spend {
        version: PROTOCOL_VERSION, chain: get_tx_info().unbox().chain_id, pool: *p.contract_address,
        root: ITreeDispatcher { contract_address: *p.contract_address }.get_root(),
        token: *t.contract_address, binding: 0, controller: contract_address_const::<0>(), deadline: 0, nonce: 0,
        transition: 0, sig_r: 0, sig_s: 0, nullifiers: array![nf, nf + 1].span(), outputs: outputs.span(),
        withdrawals: array![Withdrawal { recipient: contract_address_const::<0xb0b>(), amount: 40 }].span(),
    };
    s.binding = compute_binding(@s);
    s
}

fn measure_withdraw(n_out: u32) {
    let (p, t) = warm_pool();
    let s = spend_shape(@p, @t, 3000, 4000, n_out);
    let g = get_available_gas();
    p.apply_spend(s, array![].span());
    println!("GAS apply_spend felt outputs={} withdrawal=true warm={}", n_out, g - get_available_gas());
}

#[test]
fn cost_partial_felt() { measure_withdraw(1); }
#[test]
fn cost_full_felt() { measure_withdraw(0); }
