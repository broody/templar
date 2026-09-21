//! `apply_spend` + `deposit` gas snapshot for the SDK fee model (spec §9.4) —
//! measurement, not correctness. Every test shares an identical deployment
//! prefix (`bench_setup`), so deltas vs `bench_baseline_deploy` isolate the
//! bundle cost; `bench_build_only_noop` isolates bundle-construction overhead
//! from `bench_apply_noop`. Tree rehash dominates any multi-leaf bundle
//! (~11.5 M l2 gas per insert, spec §9.2). Withdrawal legs are funded by
//! faucet-crediting the pool directly, so bundle measurements stay clean of
//! deposit cost; `bench_deposit` measures the deposit entry point itself.

use core::starknet::{contract_address_const, ContractAddress};
use pool::pool::{IPoolDispatcher, IPoolDispatcherTrait};
use pool::spend::{ServerAction, SpendPublicInputs, TokenAmount, PROTOCOL_VERSION};
use pool::tree::{ITreeDispatcher, ITreeDispatcherTrait};
use snforge_std::test_address;
use super::test_pool::{apply, build_bundle, deploy};

#[starknet::interface]
trait IApprove<T> {
    fn approve(ref self: T, spender: ContractAddress, amount: u256) -> bool;
}

#[starknet::interface]
trait IFaucet<T> {
    fn faucet(ref self: T, to: ContractAddress, amount: u256);
}

fn bench_setup() -> (ContractAddress, ContractAddress) {
    let me = test_address();
    let verifier = deploy("MockVerifier", @true);
    let sig_verifier = deploy("MockSigVerifier", @true);
    let token_addr = deploy("MockERC20", @(me, 1000000_u256));
    let pool_addr = deploy("Pool", @(me, verifier, sig_verifier));
    (pool_addr, token_addr)
}

fn noop_bundle(pool_addr: ContractAddress) -> (SpendPublicInputs, Array<ServerAction>) {
    build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![],
        array![],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    )
}

#[test]
fn bench_baseline_deploy() {
    bench_setup();
}

#[test]
fn bench_build_only_noop() {
    let (pool_addr, _) = bench_setup();
    let (pi, actions) = noop_bundle(pool_addr);
    assert(pi.protocol_version == PROTOCOL_VERSION, 'BENCH');
    assert(actions.len() == 0, 'BENCH');
}

#[test]
fn bench_apply_noop() {
    let (pool_addr, _) = bench_setup();
    let (pi, actions) = noop_bundle(pool_addr);
    apply(@IPoolDispatcher { contract_address: pool_addr }, pi, actions);
}

#[test]
fn bench_apply_1_nullifier() {
    let (pool_addr, _) = bench_setup();
    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![0x1001],
        array![],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@IPoolDispatcher { contract_address: pool_addr }, pi, actions);
}

#[test]
fn bench_apply_1_leaf() {
    let (pool_addr, _) = bench_setup();
    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![],
        array![0xa001],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@IPoolDispatcher { contract_address: pool_addr }, pi, actions);
}

#[test]
fn bench_apply_controlled_small() {
    let (pool_addr, _) = bench_setup();
    let controller = contract_address_const::<0xc0>();
    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![0x1001],
        array![0xa001],
        array![],
        test_address(),
        controller,
        1000000,
        0x7c,
        array![ServerAction::ControllerApply((controller, 0x7c, 1000000, 0x1, 0x2))],
    );
    apply(@IPoolDispatcher { contract_address: pool_addr }, pi, actions);
}

#[test]
fn bench_apply_2x2_with_public_io() {
    let (pool_addr, token_addr) = bench_setup();
    IFaucetDispatcher { contract_address: token_addr }.faucet(pool_addr, 1000);

    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![0x1001, 0x1002],
        array![0xa001, 0xa002],
        array![TokenAmount { token: token_addr, amount: 40 }],
        contract_address_const::<0xb0b>(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@IPoolDispatcher { contract_address: pool_addr }, pi, actions);
}

#[test]
fn bench_apply_max() {
    let (pool_addr, token_addr) = bench_setup();
    let controller = contract_address_const::<0xc0>();

    // Fund the withdrawal legs (2 × 250) without polluting the measurement.
    IFaucetDispatcher { contract_address: token_addr }.faucet(pool_addr, 500);

    let mut nullifiers = array![];
    let mut commitments = array![];
    let mut withdrawals = array![];
    let mut i: u32 = 0;
    while i < 4 {
        nullifiers.append(0x1000 + i.into());
        commitments.append(0xa000 + i.into());
        i += 1;
    }
    i = 0;
    while i < 2 {
        withdrawals.append(TokenAmount { token: token_addr, amount: 250 });
        i += 1;
    }

    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        nullifiers,
        commitments,
        withdrawals,
        contract_address_const::<0xb0b>(),
        controller,
        1000000,
        0x7c,
        array![ServerAction::ControllerApply((controller, 0x7c, 1000000, 0x1, 0x2))],
    );
    apply(@IPoolDispatcher { contract_address: pool_addr }, pi, actions);
}


#[test]
fn bench_apply_4_leaves_only() {
    let (pool_addr, _) = bench_setup();
    let mut commitments = array![];
    let mut i: u32 = 0;
    while i < 4 {
        commitments.append(0xa000 + i.into());
        i += 1;
    }
    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![],
        commitments,
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@IPoolDispatcher { contract_address: pool_addr }, pi, actions);
}

#[test]
fn bench_apply_2_leaves_only() {
    let (pool_addr, _) = bench_setup();
    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![],
        array![0xa001, 0xa002],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@IPoolDispatcher { contract_address: pool_addr }, pi, actions);
}

#[test]
fn bench_deposit() {
    let (pool_addr, token_addr) = bench_setup();
    IApproveDispatcher { contract_address: token_addr }.approve(pool_addr, 100);
    IPoolDispatcher { contract_address: pool_addr }
        .deposit(token_addr, 100, contract_address_const::<0>(), 0, 0xbeef, 0xf00d);
}
