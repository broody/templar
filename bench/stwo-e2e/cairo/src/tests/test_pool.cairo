//! Pool tests: happy path + adversarial battery (PLAN M1) — replay, forged
//! actions, stale roots, controller mismatches, deadline/sig failures, fee,
//! and the standalone proofless deposit entry point (ADR-0011). Bundle shape
//! and the padded binding follow ADR-0014 (4/4/2, scalar verifier payload).

use core::starknet::{contract_address_const, ContractAddress};
use starknet::get_tx_info;
use pool::hashes::compute_note_commitment;
use pool::pool::{IPoolDispatcher, IPoolDispatcherTrait, Pool};
use pool::pool::Pool::{
    ControllerAuthorized, Deposited, NoteCommitted, NullifierSpent, Withdrawal,
};
use pool::tree::{ITreeDispatcher, ITreeDispatcherTrait};
use pool::spend::{
    compute_actions_hash, compute_statement_binding, ServerAction, SpendPublicInputs, TokenAmount,
    PROTOCOL_VERSION,
};
use pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
use snforge_std::{
    cheat_block_number, declare, spy_events, start_cheat_caller_address, CheatSpan,
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, EventSpyTrait, test_address,
};
use starknet::SyscallResultTrait;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

pub fn deploy<T, +Serde<T>>(name: ByteArray, ctor_args: @T) -> ContractAddress {
    let class = declare(name).unwrap_syscall().contract_class();
    let mut calldata = array![];
    Serde::serialize(ctor_args, ref calldata);
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

#[derive(Drop)]
struct Setup {
    pool: IPoolDispatcher,
    pool_addr: ContractAddress,
    token: IERC20Dispatcher,
    token_addr: ContractAddress,
}

/// Verifier + sig-verifier mocks default to accepting; tests that exercise the
/// reject paths deploy their own rejecting mocks.
fn setup() -> Setup {
    let verifier = deploy("MockVerifier", @true);
    let sig_verifier = deploy("MockSigVerifier", @true);
    let me = test_address();
    let token_addr = deploy("MockERC20", @(me, 10000_u256));
    let pool_addr = deploy("Pool", @(me, verifier, sig_verifier));
    Setup {
        pool: IPoolDispatcher { contract_address: pool_addr },
        pool_addr,
        token: IERC20Dispatcher { contract_address: token_addr },
        token_addr,
    }
}

pub fn default_actions(
    nullifiers: Span<felt252>,
    commitments: Span<felt252>,
    withdrawals: Span<TokenAmount>,
    withdraw_to: ContractAddress,
) -> Array<ServerAction> {
    let mut actions = array![];
    let mut i: usize = 0;
    while i < nullifiers.len() {
        actions.append(ServerAction::NullifierWrite(*nullifiers.at(i)));
        i += 1;
    }
    i = 0;
    while i < commitments.len() {
        let c = *commitments.at(i);
        actions.append(ServerAction::LeafInsert((c, c)));
        i += 1;
    }
    i = 0;
    while i < withdrawals.len() {
        let w = *withdrawals.at(i);
        actions.append(ServerAction::Withdrawal((w.token, w.amount, withdraw_to)));
        i += 1;
    }
    actions
}

/// Builds a bundle whose binding is computed over the final action list —
/// i.e., exactly what a (possibly malicious) SDK can do off-chain. Tests then
/// rely on on-chain checks to reject it.
#[allow(implicit_ordering)]
pub fn build_bundle(
    pool_addr: ContractAddress,
    root: felt252,
    nullifiers: Array<felt252>,
    commitments: Array<felt252>,
    withdrawals: Array<TokenAmount>,
    withdraw_to: ContractAddress,
    controller: ContractAddress,
    deadline: u64,
    transition_commitment: felt252,
    extra: Array<ServerAction>,
) -> (SpendPublicInputs, Array<ServerAction>) {
    let n_span = nullifiers.into();
    let c_span = commitments.into();
    let w_span = withdrawals.into();
    let mut actions = default_actions(n_span, c_span, w_span, withdraw_to);
    let mut i: usize = 0;
    while i < extra.len() {
        actions.append(*extra.at(i));
        i += 1;
    }
    let actions_span = actions.span();
    let mut pi = SpendPublicInputs {
        protocol_version: PROTOCOL_VERSION,
        chain_id: get_tx_info().unbox().chain_id,
        pool_address: pool_addr,
        tree_root: root,
        input_nullifiers: n_span,
        output_commitments: c_span,
        withdrawals: w_span,
        controller,
        deadline,
        transition_commitment,
        statement_binding: 0,
    };
    pi.statement_binding = compute_statement_binding(@pi, compute_actions_hash(@actions_span));
    (pi, actions)
}

pub fn apply(pool: @IPoolDispatcher, pi: SpendPublicInputs, actions: Array<ServerAction>) {
    pool.apply_spend(pi, array![0xdead].span(), actions.span());
}

// ---------------------------------------------------------------------------
// Deposit entry point (ADR-0011) + happy path
// ---------------------------------------------------------------------------

#[test]
fn happy_path_full_bundle() {
    let mut setup = setup();
    let me = test_address();
    let bob = contract_address_const::<0xb0b>();
    let inner = 0xbeef;
    let note_id = 0xf00d;

    // Standalone proofless deposit: the commitment is recomputed on-chain.
    setup.token.approve(setup.pool_addr, 100);
    let deposit_commitment = compute_note_commitment(
        setup.token_addr, 100, contract_address_const::<0>(), 0, inner,
    );

    let mut spy = spy_events();
    setup.pool.deposit(setup.token_addr, 100, contract_address_const::<0>(), 0, inner, note_id);

    assert_eq!(ITreeDispatcher { contract_address: setup.pool_addr }.get_leaf_count(), 1);
    assert_eq!(
        ITestBalanceDispatcher { contract_address: setup.token_addr }.balance_of(setup.pool_addr),
        100,
    );

    // Spend bundle: 2 nullifiers, 2 new leaves, 1 withdrawal to bob.
    let root = ITreeDispatcher { contract_address: setup.pool_addr }.get_root();
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        root,
        array![0x111, 0x222],
        array![0xaaa, 0xbbb],
        array![TokenAmount { token: setup.token_addr, amount: 40 }],
        bob,
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi, actions);

    // State: nullifiers spent, leaves inserted (1 deposit + 2 spend outputs).
    assert(setup.pool.get_nullifier_spent(0x111), 'N1_NOT_SPENT');
    assert(setup.pool.get_nullifier_spent(0x222), 'N2_NOT_SPENT');
    assert_eq!(ITreeDispatcher { contract_address: setup.pool_addr }.get_leaf_count(), 3);

    // Tokens moved: pool net +60 (100 in, 40 out to bob).
    assert_eq!(ITestBalanceDispatcher { contract_address: setup.token_addr }.balance_of(
        setup.pool_addr
    ), 60);
    assert_eq!(ITestBalanceDispatcher { contract_address: setup.token_addr }.balance_of(bob), 40);

    // Events (§8): Deposited has no depositor; NoteCommitted carries
    // discovery metadata; NullifierSpent carries the public controller (0).
    spy
        .assert_emitted(
            @array![
                (
                    setup.pool_addr,
                    Pool::Event::Deposited(
                        Deposited { token: setup.token_addr, amount: 100 },
                    ),
                ),
                (
                    setup.pool_addr,
                    Pool::Event::NoteCommitted(
                        NoteCommitted {
                            note_id, leaf_index: 0, commitment: deposit_commitment,
                            controller: contract_address_const::<0>(),
                        },
                    ),
                ),
                (
                    setup.pool_addr,
                    Pool::Event::NoteCommitted(
                        NoteCommitted {
                            note_id: 0xaaa, leaf_index: 1, commitment: 0xaaa,
                            controller: contract_address_const::<0>(),
                        },
                    ),
                ),
                (
                    setup.pool_addr,
                    Pool::Event::NoteCommitted(
                        NoteCommitted {
                            note_id: 0xbbb, leaf_index: 2, commitment: 0xbbb,
                            controller: contract_address_const::<0>(),
                        },
                    ),
                ),
                (
                    setup.pool_addr,
                    Pool::Event::NullifierSpent(
                        NullifierSpent {
                            nullifier: 0x111, controller: contract_address_const::<0>(),
                        },
                    ),
                ),
                (
                    setup.pool_addr,
                    Pool::Event::Withdrawal(
                        Withdrawal { to_addr: bob, token: setup.token_addr, amount: 40 },
                    ),
                ),
            ],
        );
}

#[test]
#[should_panic(expected: ('ZERO_AMOUNT',))]
fn deposit_zero_amount_reverts() {
    let setup = setup();
    setup
        .pool
        .deposit(setup.token_addr, 0, contract_address_const::<0>(), 0, 0xbeef, 0xf00d);
}

#[test]
#[should_panic(expected: ('ZERO_TOKEN',))]
fn deposit_zero_token_reverts() {
    let setup = setup();
    setup
        .pool
        .deposit(contract_address_const::<0>(), 100, contract_address_const::<0>(), 0, 0xbeef, 0xf00d);
}

#[test]
#[should_panic(expected: ('ZERO_INNER',))]
fn deposit_zero_inner_reverts() {
    let setup = setup();
    setup
        .pool
        .deposit(setup.token_addr, 100, contract_address_const::<0>(), 0, 0, 0xf00d);
}

#[test]
#[should_panic(expected: ('INSUFFICIENT_ALLOWANCE',))]
fn deposit_pulls_only_from_caller() {
    // The allowance-pull class (review §D.1) is dead by construction: deposit
    // always pulls from the caller. Here the caller never approved the pool,
    // so the pull fails — no third party's allowance can ever be targeted.
    let setup = setup();
    setup
        .pool
        .deposit(setup.token_addr, 100, contract_address_const::<0>(), 0, 0xbeef, 0xf00d);
}

#[test]
fn controlled_deposit_then_spend() {
    // The escrow flow (e.g. sealed-bid auction): one plain deposit funds a
    // controlled note; the controller authorizes the spend off-chain.
    let setup = setup();
    let controller = contract_address_const::<0xc0>();

    setup.token.approve(setup.pool_addr, 100);
    setup.pool.deposit(setup.token_addr, 100, controller, 0, 0xbeef, 0xf00d);
    assert_eq!(ITreeDispatcher { contract_address: setup.pool_addr }.get_leaf_count(), 1);

    let root = ITreeDispatcher { contract_address: setup.pool_addr }.get_root();
    let apply_action = ServerAction::ControllerApply((controller, 0x7c, 1000000, 0x1, 0x2));
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        root,
        array![0x999],
        array![0xccc],
        array![],
        test_address(),
        controller,
        1000000,
        0x7c,
        array![apply_action],
    );

    let mut spy = spy_events();
    apply(@setup.pool, pi, actions);
    assert(setup.pool.get_nullifier_spent(0x999), 'N_NOT_SPENT');
    spy
        .assert_emitted(
            @array![
                (
                    setup.pool_addr,
                    Pool::Event::ControllerAuthorized(
                        ControllerAuthorized { transition_commitment: 0x7c, controller },
                    ),
                ),
            ],
        );
}

#[test]
fn controlled_spend_happy_path() {
    let setup = setup();
    let controller = contract_address_const::<0xc0>();

    let root = ITreeDispatcher { contract_address: setup.pool_addr }.get_root();
    let apply_action = ServerAction::ControllerApply((
        controller,
        0x7c,
        1000000,
        0x1,
        0x2,
    ));

    let (pi, actions) = build_bundle(
        setup.pool_addr,
        root,
        array![0x999],
        array![0xccc],
        array![],
        test_address(),
        controller,
        1000000,
        0x7c,
        array![apply_action],
    );

    let mut spy = spy_events();
    apply(@setup.pool, pi, actions);
    spy
        .assert_emitted(
            @array![
                (
                    setup.pool_addr,
                    Pool::Event::ControllerAuthorized(
                        ControllerAuthorized { transition_commitment: 0x7c, controller },
                    ),
                ),
            ],
        );
}

// ---------------------------------------------------------------------------
// Replay / nullifier integrity
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected: ('NULLIFIER_USED',))]
fn replay_nullifier_reverts() {
    let mut setup = setup();

    // First spend of n1 succeeds (leaf-only bundle to establish a fresh root).
    let (pi1, actions1) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi1, actions1);

    // Second spend referencing the same nullifier with a fresh, known root.
    let (pi2, actions2) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xbbb],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi2, actions2);
}

#[test]
#[should_panic(expected: ('NULLIFIER_MISMATCH',))]
fn forged_extra_nullifier_reverts() {
    // The griefing vector: a bundle whose actions write one more nullifier
    // than the proven statement contains. The attacker recomputes the binding
    // over their tampered actions, so only the on-chain zip catches it.
    let setup = setup();
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111, 0x222],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![ServerAction::NullifierWrite(0x333)],
    );
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('NULLIFIER_MISMATCH',))]
fn missing_nullifier_action_reverts() {
    // Public inputs declare two nullifiers; actions write only one — the
    // unspent one would silently skip replay protection.
    let setup = setup();
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111, 0x222],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    // Drop one NullifierWrite: the last action is a LeafInsert.
    let mut trimmed = array![];
    let mut i: usize = 0;
    while i < actions.len() {
        if i != 1 {
            trimmed.append(*actions.at(i));
        }
        i += 1;
    }
    // Rebinding over the trimmed actions (attacker-side recompute).
    let mut tampered = pi;
    let s = trimmed.span();
    tampered.statement_binding = compute_statement_binding(@tampered, compute_actions_hash(@s));
    apply(@setup.pool, tampered, trimmed);
}

#[test]
#[should_panic(expected: ('ZERO_NULLIFIER',))]
fn zero_nullifier_reverts() {
    let setup = setup();
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi, actions);
}

// ---------------------------------------------------------------------------
// Gate: context, binding, verifier, root
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected: ('PROOF_REJECTED',))]
fn rejected_proof_reverts() {
    // Creator-spend class of attempts: no valid inner proof, verifier says no.
    let me = test_address();
    let verifier = deploy("MockVerifier", @false);
    let sig_verifier = deploy("MockSigVerifier", @true);
    let pool_addr = deploy("Pool", @(me, verifier, sig_verifier));
    let pool = IPoolDispatcher { contract_address: pool_addr };

    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@pool, pi, actions);
}

#[test]
#[should_panic(expected: ('BAD_BINDING',))]
fn tampered_binding_reverts() {
    let setup = setup();
    let (mut pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    pi.statement_binding = pi.statement_binding + 1;
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('WRONG_POOL',))]
fn wrong_pool_address_reverts() {
    let setup = setup();
    // Bundle addressed to another pool (binding recomputed consistently).
    let (pi, actions) = build_bundle(
        setup.token_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('WRONG_CHAIN',))]
fn wrong_chain_id_reverts() {
    let setup = setup();
    let (mut pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    // Attacker rebinds over a foreign chain id.
    pi.chain_id = get_tx_info().unbox().chain_id + 1;
    let s = actions.span();
    pi.statement_binding = compute_statement_binding(@pi, compute_actions_hash(@s));
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('WRONG_VERSION',))]
fn wrong_protocol_version_reverts() {
    let setup = setup();
    let (mut pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    pi.protocol_version = 'TEMPLAR_V3';
    let s = actions.span();
    pi.statement_binding = compute_statement_binding(@pi, compute_actions_hash(@s));
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('UNKNOWN_ROOT',))]
fn stale_root_reverts() {
    let setup = setup();
    let root_before = ITreeDispatcher { contract_address: setup.pool_addr }.get_root();

    // Spend bundle referencing the empty root; keep its root for later.
    let (pi1, actions1) = build_bundle(
        setup.pool_addr,
        root_before,
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi1, actions1);
    let root_after_first = ITreeDispatcher { contract_address: setup.pool_addr }.get_root();

    // Push 256 more roots through the ring — evicts root_after_first.
    let mut i: u64 = 2;
    while i <= 257 {
        let (pi, actions) = build_bundle(
            setup.pool_addr,
            ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
            array![],
            array![(1000 + i).into()],
            array![],
            test_address(),
            contract_address_const::<0>(),
            0,
            0,
            array![],
        );
        apply(@setup.pool, pi, actions);
        i += 1;
    }

    // Now replay a bundle against the evicted root.
    let (pi_stale, actions_stale) = build_bundle(
        setup.pool_addr,
        root_after_first,
        array![0x222],
        array![0xbbb],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi_stale, actions_stale);
}

// ---------------------------------------------------------------------------
// Action/public-input zipping
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected: ('COMMITMENT_MISMATCH',))]
fn leaf_commitment_mismatch_reverts() {
    let setup = setup();
    // Actions insert a different commitment than the proven one.
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    let mut forged = array![*actions.at(0)];
    let _ = forged.append(ServerAction::LeafInsert((0xfff, 0xfff)));
    let mut tampered = pi;
    let s = forged.span();
    tampered.statement_binding = compute_statement_binding(@tampered, compute_actions_hash(@s));
    apply(@setup.pool, tampered, forged);
}

// ---------------------------------------------------------------------------
// Controller authorization (§6)
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected: ('CONTROLLER_REQUIRED',))]
fn controlled_spend_without_apply_reverts() {
    let setup = setup();
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0xc0>(),
        1000000,
        0x7c,
        array![],
    );
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('CONTROLLER_MISMATCH',))]
fn controller_mismatch_reverts() {
    let setup = setup();
    let apply_action = ServerAction::ControllerApply((
        contract_address_const::<0xc9>(),
        0x7c,
        1000000,
        0x1,
        0x2,
    ));
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0xc0>(),
        1000000,
        0x7c,
        array![apply_action],
    );
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('DEADLINE_MISMATCH',))]
fn deadline_mismatch_reverts() {
    // The action's deadline must equal the public input the circuit bound
    // into the transition commitment (ADR-0014).
    let setup = setup();
    let apply_action = ServerAction::ControllerApply((
        contract_address_const::<0xc0>(),
        0x7c,
        999999,
        0x1,
        0x2,
    ));
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0xc0>(),
        1000000,
        0x7c,
        array![apply_action],
    );
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('DEADLINE_EXCEEDED',))]
fn expired_deadline_reverts() {
    let setup = setup();
    cheat_block_number(setup.pool_addr, 100, CheatSpan::TargetCalls(1));
    let apply_action = ServerAction::ControllerApply((
        contract_address_const::<0xc0>(),
        0x7c,
        99,
        0x1,
        0x2,
    ));
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0xc0>(),
        99,
        0x7c,
        array![apply_action],
    );
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('SIG_REJECTED',))]
fn rejected_controller_signature_reverts() {
    let me = test_address();
    let sig_verifier = deploy("MockSigVerifier", @false);
    let verifier = deploy("MockVerifier", @true);
    let pool_addr = deploy("Pool", @(me, verifier, sig_verifier));
    let pool = IPoolDispatcher { contract_address: pool_addr };

    let apply_action = ServerAction::ControllerApply((
        contract_address_const::<0xc0>(),
        0x7c,
        1000000,
        0x1,
        0x2,
    ));
    let (pi, actions) = build_bundle(
        pool_addr,
        ITreeDispatcher { contract_address: pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0xc0>(),
        1000000,
        0x7c,
        array![apply_action],
    );
    apply(@pool, pi, actions);
}

#[test]
#[should_panic(expected: ('UNEXPECTED_APPLY',))]
fn apply_on_ordinary_spend_reverts() {
    let setup = setup();
    let apply_action = ServerAction::ControllerApply((
        contract_address_const::<0>(),
        0x7c,
        1000000,
        0x1,
        0x2,
    ));
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![apply_action],
    );
    apply(@setup.pool, pi, actions);
}

#[test]
#[should_panic(expected: ('MULTIPLE_APPLY',))]
fn double_controller_apply_reverts() {
    let setup = setup();
    let mk = || {
        ServerAction::ControllerApply((
            contract_address_const::<0xc0>(),
            0x7c,
            1000000,
            0x1,
            0x2,
        ))
    };
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0xc0>(),
        1000000,
        0x7c,
        array![mk(), mk()],
    );
    apply(@setup.pool, pi, actions);
}

// ---------------------------------------------------------------------------
// Fee (upstream shape: STRK from caller)
// ---------------------------------------------------------------------------

#[test]
fn fee_is_collected_from_caller() {
    let setup = setup();
    let collector = contract_address_const::<0xf00>();
    IFaucetDispatcher { contract_address: setup.token_addr }.faucet(test_address(), 1000);
    setup.token.approve(setup.pool_addr, 1);
    setup.pool.set_fee(setup.token_addr, 1, collector);

    // Empty bundle is a valid (no-op) spend — binding over nothing.
    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![],
        array![],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi, actions);

    assert_eq!(
        ITestBalanceDispatcher { contract_address: setup.token_addr }.balance_of(collector),
        1
    );
}

// ---------------------------------------------------------------------------
// balanceOf peek (not part of the pool face)
// ---------------------------------------------------------------------------

#[starknet::interface]
trait ITestBalance<T> {
    fn balance_of(self: @T, account: ContractAddress) -> u256;
}

#[starknet::interface]
trait IFaucet<T> {
    fn faucet(ref self: T, to: ContractAddress, amount: u256);
}

#[test]
fn empty_root_known_from_genesis() {
    // Pool constructor seeds the zero chain + empty root — the first spend
    // bundle must have an acceptable root without a prior insert.
    let setup = setup();
    let tree = ITreeDispatcher { contract_address: setup.pool_addr };
    assert(tree.get_root() != 0, 'ROOT_NOT_SEEDED');
    assert(tree.root_is_known(tree.get_root()), 'EMPTY_ROOT_UNKNOWN');
    assert(tree.get_leaf_count() == 0, 'COUNT_DIRTY');
}

// ---------------------------------------------------------------------------
// M1 governance fix (review §B): owner guard over the trust anchors
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected: ('NOT_OWNER',))]
fn non_owner_cannot_set_fee() {
    let mut setup = setup();
    start_cheat_caller_address(setup.pool_addr, contract_address_const::<0x6ad>());
    setup
        .pool
        .set_fee(
            setup.token_addr,
            1,
            contract_address_const::<0xf00>(),
        );
}

#[test]
#[should_panic(expected: ('NOT_OWNER',))]
fn non_owner_cannot_replace_verifier() {
    let mut setup = setup();
    start_cheat_caller_address(setup.pool_addr, contract_address_const::<0x6ad>());
    setup
        .pool
        .set_verifier(contract_address_const::<0xdead>());
}

#[test]
#[should_panic(expected: ('NOT_OWNER',))]
fn non_owner_cannot_transfer_ownership() {
    let mut setup = setup();
    start_cheat_caller_address(setup.pool_addr, contract_address_const::<0x6ad>());
    setup
        .pool
        .transfer_ownership(contract_address_const::<0xdead>());
}

#[test]
fn owner_can_replace_verifier() {
    // The governance fix must be *usable*: the owner swaps the verifier for a
    // rejecting mock; the reject path is pinned by
    // `bundle_after_verifier_swap_reverts`.
    let mut setup = setup();
    let rejecting = deploy("MockVerifier", @false);
    setup.pool.set_verifier(rejecting);
    assert(setup.pool.get_verifier() == rejecting, 'VERIFIER_NOT_SET');
}

#[test]
#[should_panic(expected: ('PROOF_REJECTED',))]
fn bundle_after_verifier_swap_reverts() {
    let me = test_address();
    let mut setup = setup();
    let rejecting = deploy("MockVerifier", @false);
    setup.pool.set_verifier(rejecting);

    let (pi, actions) = build_bundle(
        setup.pool_addr,
        ITreeDispatcher { contract_address: setup.pool_addr }.get_root(),
        array![0x111],
        array![0xaaa],
        array![],
        test_address(),
        contract_address_const::<0>(),
        0,
        0,
        array![],
    );
    apply(@setup.pool, pi, actions);
}

#[test]
fn ownership_transfer_moves_owner() {
    let new_owner = contract_address_const::<0x9e9>();
    let mut setup = setup();
    setup.pool.transfer_ownership(new_owner);
    assert(setup.pool.get_owner() == new_owner, 'OWNER_NOT_MOVED');
}

#[test]
#[should_panic(expected: ('NOT_OWNER',))]
fn old_owner_loses_fee_control_after_transfer() {
    let new_owner = contract_address_const::<0x9e9>();
    let mut setup = setup();
    setup.pool.transfer_ownership(new_owner);
    setup
        .pool
        .set_fee(
            setup.token_addr,
            1,
            contract_address_const::<0xf00>(),
        );
}

/// The production ABI must not expose component mutation, even to the owner.
#[test]
fn direct_tree_insert_is_not_an_entrypoint() {
    let s = setup();
    let tree = ITreeDispatcher { contract_address: s.pool_addr };
    let old_root = tree.get_root();
    let result = starknet::syscalls::call_contract_syscall(
        s.pool_addr, selector!("insert_leaf"), array![0x123].span(),
    );
    assert!(result.is_err(), "unfunded insertion must be unavailable");
    assert_eq!(tree.get_leaf_count(), 0);
    assert_eq!(tree.get_root(), old_root);
}
