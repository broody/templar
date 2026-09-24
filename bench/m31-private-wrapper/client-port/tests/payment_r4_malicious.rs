//! Malicious enable and exit bits against the R0 V4 circuit (`docs/hidden-asset-spec.md` §4.4):
//! each case overrides a hint the honest builder derives (feature `tamper`) and checks the
//! constraints, not the hint code, reject it.
use circuits::context::Context;
use rand::{SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{Digest, Tree, commitment, felt_limbs, receiver_of};
use templar_client_verifier_circuit::payment4::{
    N_OUTPUTS, Private, Public, Shape, TAMPER, Tamper, build, fresh_shape, sparse_paths, statement_limbs,
};

const TREES: [Tree; 2] = [Tree::Sponge, Tree::Compress];

fn run(tree: Tree, public: &Public, private: &Private, t: Tamper) -> (Vec<u32>, bool) {
    TAMPER.with(|x| *x.borrow_mut() = t);
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, tree, public, private);
    TAMPER.with(|x| *x.borrow_mut() = Tamper::default());
    let limbs = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    (limbs, c.is_circuit_valid())
}

fn rejected(name: &str, tree: Tree, shape: Shape, t: Tamper) {
    let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(31));
    let (_, honest) = run(tree, &public, &private, Tamper::default());
    assert!(honest, "{tree:?} {name}: the untampered witness must be valid");
    let (_, valid) = run(tree, &public, &private, t);
    eprintln!("{tree:?} {name}: circuit valid = {valid}");
    assert!(!valid, "{tree:?} {name} accepted");
}

#[test]
fn e1_non_boolean() {
    for tree in TREES {
        rejected("e1 = 2 on a dummy", tree, Shape::Single, Tamper { e1: Some(2), ..Default::default() });
        rejected("e1 = 2 on a real input", tree, Shape::Transfer, Tamper { e1: Some(2), ..Default::default() });
    }
}

/// e₁ = 2 on an enabled zero-value member input: the amount and membership rules both hold for
/// any e₁, so only booleanity can reject it (implementation review HA-IM2).
#[test]
fn e1_non_boolean_isolated() {
    for tree in TREES {
        let (public, mut private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(33));
        // Input 1 becomes a real, enabled member note of amount 0.
        let total = private.inputs[0].amount;
        private.inputs[1].amount = 0;
        private.outputs[0].amount = 1;
        private.outputs[1].amount = total - 1;
        let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&private.token)].concat();
        let leaves: Vec<(u32, Digest)> = private
            .inputs
            .iter()
            .map(|i| (i.position, commitment(&context, i.amount, &receiver_of(&i.sk).0, &i.rho)))
            .collect();
        let (_, siblings) = sparse_paths(tree, &leaves, &mut StdRng::seed_from_u64(34));
        for (i, s) in private.inputs.iter_mut().zip(siblings) {
            i.siblings = s;
        }
        let (_, control) = run(tree, &public, &private, Tamper { e1: Some(1), ..Default::default() });
        assert!(control, "{tree:?}: control e1 = 1");
        let (_, zero) = run(tree, &public, &private, Tamper { e1: Some(0), ..Default::default() });
        assert!(zero, "{tree:?}: e1 = 0 is also consistent for a zero-value input");
        let (_, two) = run(tree, &public, &private, Tamper { e1: Some(2), ..Default::default() });
        assert!(!two, "{tree:?}: e1 = 2 accepted");
    }
}

#[test]
fn e1_one_on_dummy_path() {
    for tree in TREES {
        rejected("e1 = 1 on a dummy's random path", tree, Shape::Single, Tamper { e1: Some(1), ..Default::default() });
    }
}

#[test]
fn e1_zero_on_real_input() {
    // Disabling a real input 1 (nonzero amount) violates sum₁ · (1 − e₁) = 0.
    for tree in TREES {
        rejected("e1 = 0 with amount₁ ≠ 0", tree, Shape::Transfer, Tamper { e1: Some(0), ..Default::default() });
    }
}

#[test]
fn x_zero_with_exit() {
    for tree in TREES {
        rejected("x = 0 with a withdrawal", tree, Shape::Partial, Tamper { x: Some(0), ..Default::default() });
        rejected("x = 0 with everything withdrawn", tree, Shape::Full, Tamper { x: Some(0), ..Default::default() });
        rejected("x = 0 with an intent", tree, Shape::Invoke, Tamper { x: Some(0), ..Default::default() });
    }
}

#[test]
fn x_non_boolean() {
    for tree in TREES {
        rejected("x = 2 with no exit", tree, Shape::Transfer, Tamper { x: Some(2), ..Default::default() });
        rejected("x = 2 with an exit", tree, Shape::Partial, Tamper { x: Some(2), ..Default::default() });
    }
}

/// A voluntary reveal (x = 1 with neither withdrawal nor intent) satisfies the circuit; it
/// publishes the asset with no exit, which the bridge rejects (spec §4.5).
#[test]
fn voluntary_reveal_is_left_to_the_bridge() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(32));
        let (limbs, valid) = run(tree, &public, &private, Tamper { x: Some(1), ..Default::default() });
        assert!(valid, "{tree:?}");
        assert_ne!(limbs, statement_limbs(tree, &public));
        // token_out (limbs 20..29) is the asset; withdrawal and intent are zero.
        assert_eq!(limbs[20..29], felt_limbs(&private.token));
        assert_eq!(public.withdrawal_amount, 0);
        assert_eq!(public.intent, "0x0");
    }
}
