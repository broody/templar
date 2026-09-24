//! R0 V4 (`docs/hidden-asset-spec.md` §4): circuit outputs equal the native reference for every
//! shape and both tree formats, the topology is shape-independent, broken witnesses fail, and
//! V4 spends V3-format notes unchanged.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use rand::{Rng, SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{self, Digest, Tree, commitment, felt_limbs, receiver_of};
use templar_client_verifier_circuit::payment4::{
    self, N_OUTPUTS, Output, Private, Public, Shape, build, fresh_shape, sparse_paths, statement_limbs,
};

const TREES: [Tree; 2] = [Tree::Sponge, Tree::Compress];
const SHAPES: [Shape; 8] = [
    Shape::Transfer, Shape::Single, Shape::OneOut, Shape::Partial, Shape::Full, Shape::Invoke, Shape::Shadow, Shape::Nft,
];

fn outputs(tree: Tree, public: &Public, private: &Private) -> (Vec<u32>, bool) {
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, tree, public, private);
    let limbs = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    (limbs, c.is_circuit_valid())
}

fn redo(tree: Tree, public: &Public, p: &Private) -> Result<Public, String> {
    payment4::statement(
        tree,
        &public.chain,
        &public.pool,
        public.deliveries.clone(),
        (public.withdrawal_recipient.clone(), public.withdrawal_amount),
        &public.intent,
        p,
    )
}

fn exits(shape: Shape) -> bool {
    matches!(shape, Shape::Partial | Shape::Full | Shape::Invoke | Shape::Shadow)
}

#[test]
fn circuit_statement_matches_native_and_topology_is_fixed() {
    for tree in TREES {
        let mut topologies = vec![];
        for shape in SHAPES {
            for seed in 0..3 {
                let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(seed));
                let (limbs, valid) = outputs(tree, &public, &private);
                assert!(valid, "{tree:?} {shape:?}");
                assert_eq!(limbs, statement_limbs(tree, &public), "{tree:?} {shape:?}");
                // The asset is published exactly on exit.
                let hidden = felt_limbs(&public.token_out).iter().all(|l| *l == 0);
                assert_eq!(hidden, !exits(shape), "{tree:?} {shape:?}");
                if !hidden {
                    assert_eq!(public.token_out, private.token);
                }
                // Both output slots always publish a commitment and a delivery digest.
                assert!(public.commitments.iter().all(|cm| cm.iter().any(|w| *w != 0)));
                assert!(public.deliveries.iter().all(|d| d != "0x0"));
            }
            let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(7));
            let mut topo = Context::<NoValue>::new(N_OUTPUTS);
            build(&mut topo, tree, &public, &private);
            topologies.push(topo.circuit);
        }
        assert!(topologies.iter().all(|t| *t == topologies[0]), "shape changes the topology");
        let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(7));
        let mut real = Context::<QM31>::new(N_OUTPUTS);
        build(&mut real, tree, &public, &private);
        eprintln!("{tree:?}: qm31_ops {} eq {}", real.circuit.n_qm31_ops_rows(), real.circuit.eq.len());
    }
}

/// The V4 and V3 statement tags differ for both tree formats.
#[test]
fn tags_differ_from_v3() {
    for tree in TREES {
        assert_ne!(payment4::statement_tag(tree), payment::statement_tag(tree));
    }
    assert_ne!(payment4::statement_tag(Tree::Sponge), payment4::statement_tag(Tree::Compress));
}

/// Pre-V4 notes stay spendable: the same witness gives V3's root, nullifiers and commitments.
#[test]
fn v4_spends_v3_notes() {
    for tree in TREES {
        let (v3, w3) = payment::fresh_shape(tree, payment::Shape::Transfer, &mut StdRng::seed_from_u64(9));
        let w4 = Private {
            token: v3.token.clone(),
            inputs: w3.inputs.clone(),
            dummy: false,
            outputs: std::array::from_fn(|j| Output {
                receiver: w3.outputs[j].receiver,
                rho: w3.outputs[j].rho,
                amount: w3.outputs[j].amount,
            }),
            identity: w3.identity.clone(),
        };
        let v4 = payment4::statement(tree, &v3.chain, &v3.pool, v3.deliveries.clone(), ("0x0".into(), 0), "0x0", &w4)
            .expect("valid V4 witness");
        assert_eq!(v4.root, v3.root);
        assert_eq!(v4.nullifiers, v3.nullifiers);
        assert_eq!(v4.commitments, v3.commitments);
        assert_eq!(v4.token_out, "0x0");
        let (limbs, valid) = outputs(tree, &v4, &w4);
        assert!(valid);
        assert_eq!(limbs, statement_limbs(tree, &v4));
    }
}

/// The largest identifier the bridge admits (2^251 − 1) exits correctly.
#[test]
fn asset_just_below_2_251() {
    let tree = Tree::Compress;
    let (public, mut private) = fresh_shape(tree, Shape::Partial, &mut StdRng::seed_from_u64(11));
    private.token = format!("0x7{}", "f".repeat(62));
    // Re-place both notes under the new asset.
    let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&private.token)].concat();
    let leaves: Vec<(u32, Digest)> = private
        .inputs
        .iter()
        .map(|i| (i.position, commitment(&context, i.amount, &receiver_of(&i.sk).0, &i.rho)))
        .collect();
    let (_, siblings) = sparse_paths(tree, &leaves, &mut StdRng::seed_from_u64(12));
    for (i, s) in private.inputs.iter_mut().zip(siblings) {
        i.siblings = s;
    }
    let public = redo(tree, &public, &private).expect("valid");
    assert_eq!(public.token_out, private.token);
    let (limbs, valid) = outputs(tree, &public, &private);
    assert!(valid);
    assert_eq!(limbs, statement_limbs(tree, &public));
}

/// Re-plants the real inputs' leaves (input 0, and input 1 unless it is a dummy) under the
/// witness's current asset and amounts, so only the rule under test can fail.
fn replant(tree: Tree, public: &Public, mut p: Private, seed: u64) -> Private {
    let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&p.token)].concat();
    let real = if p.dummy { 1 } else { 2 };
    let leaves: Vec<(u32, Digest)> = p.inputs[..real]
        .iter()
        .map(|i| (i.position, commitment(&context, i.amount, &receiver_of(&i.sk).0, &i.rho)))
        .collect();
    let (_, siblings) = sparse_paths(tree, &leaves, &mut StdRng::seed_from_u64(seed));
    for (i, s) in p.inputs.iter_mut().zip(siblings) {
        i.siblings = s;
    }
    p
}

/// Mutations an attacker wants proved: each must make the circuit invalid, not merely change the
/// statement (implementation review HA-IM1).
#[test]
fn attacker_mutations_fail_the_circuit() {
    for tree in TREES {
        for shape in SHAPES {
            let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(8));
            assert!(outputs(tree, &public, &private).1, "{tree:?} {shape:?}: control");
            let invalid = |name: &str, p: Private| {
                let (_, valid) = outputs(tree, &public, &p);
                assert!(!valid, "{tree:?} {shape:?}: {name} satisfies the circuit");
            };
            let mut p = private.clone();
            p.outputs[0].amount += 1;
            invalid("conservation +1", p);
            if private.outputs[0].amount > 0 {
                let mut p = private.clone();
                p.outputs[0].amount -= 1;
                invalid("conservation -1", p);
            }
            let mut p = private.clone();
            p.outputs[1].receiver = [0; 9];
            invalid("zero output receiver", p);
            let mut p = private.clone();
            p.outputs[0].rho = [0; 9];
            invalid("zero output rho", p);
            if private.dummy {
                // A dummy that carries value would mint it.
                let mut p = private.clone();
                p.inputs[1].amount = 5;
                p.outputs[0].amount += 5;
                invalid("dummy input with value", p);
                // Enabling the dummy requires its random path to reach the root.
                let mut p = private.clone();
                p.dummy = false;
                invalid("enabled input off the tree", p);
            } else {
                let mut p = private.clone();
                p.inputs[1].siblings[9][3] ^= 1;
                invalid("wrong sibling of an enabled input 1", p);
                // Disabling a real input 1 forces its (nonzero) amount to zero.
                let mut p = private.clone();
                p.dummy = true;
                invalid("real input disabled", p);
            }
        }
    }
}

/// Mutations that change what is proved: the circuit either fails or publishes a different
/// statement, which the pool then rejects (an unknown root, another asset's notes).
#[test]
fn other_mutations_change_the_statement() {
    for tree in TREES {
        for shape in SHAPES {
            let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(8));
            let want = statement_limbs(tree, &public);
            let check = |name: &str, p: Private| {
                let (limbs, valid) = outputs(tree, &public, &p);
                assert!(!valid || limbs != want, "{tree:?} {shape:?}: {name} accepted with the same statement");
            };
            let mut p = private.clone();
            p.inputs[0].siblings[5][0] ^= 1;
            check("wrong sibling of input 0", p);
            let mut p = private.clone();
            p.token = "0x1234".into();
            check("other asset", p);
        }
    }
}

/// amount₀ = 0 on a consistent tree fails only the real-input nonzero check; amount₀ = 1 passes.
#[test]
fn zero_real_input_fails_on_a_consistent_tree() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Single, &mut StdRng::seed_from_u64(16));
        let mut p = private.clone();
        p.inputs[0].amount = 1;
        p.outputs[0].amount = 1;
        p.outputs[1].amount = 0;
        let control = replant(tree, &public, p.clone(), 17);
        assert!(outputs(tree, &public, &control).1, "{tree:?}: control amount₀ = 1");
        p.inputs[0].amount = 0;
        p.outputs[0].amount = 0;
        let zero = replant(tree, &public, p, 17);
        assert!(!outputs(tree, &public, &zero).1, "{tree:?}: amount₀ = 0 accepted");
    }
}

/// A zero asset on a consistent tree fails only the asset nonzero check; a small asset passes.
#[test]
fn zero_asset_fails_on_a_consistent_tree() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(18));
        let mut p = private.clone();
        p.token = "0x5".into();
        let control = replant(tree, &public, p.clone(), 19);
        assert!(outputs(tree, &public, &control).1, "{tree:?}: control asset 0x5");
        p.token = "0x0".into();
        let zero = replant(tree, &public, p, 19);
        assert!(!outputs(tree, &public, &zero).1, "{tree:?}: zero asset accepted");
    }
}

/// Outputs cannot be committed under another asset than the inputs: every NOTE hash reads the
/// single `token` witness, so the test interface cannot even express it (HA-IM2). What can be
/// checked is that the published output commitments use the spend's asset.
#[test]
fn outputs_use_the_inputs_asset() {
    let tree = Tree::Compress;
    let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(20));
    let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&private.token)].concat();
    for j in 0..2 {
        let o = &private.outputs[j];
        let inner_cm = commitment(&context, o.amount, &o.receiver, &o.rho);
        assert_eq!(public.commitments[j], inner_cm);
    }
}

/// Statements the circuit proves but the bridge must reject (HA-IM3): the circuit accepts each,
/// and `bridge_checks` names the rule.
#[test]
fn bridge_only_rules() {
    let tree = Tree::Compress;
    let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(21));
    let proved = |pb: &Public, p: &Private| -> Public {
        let (limbs, valid) = outputs(tree, pb, p);
        assert!(valid, "the circuit admits it");
        let mut q = pb.clone();
        q.nullifiers = [limbs[38..47].try_into().unwrap(), limbs[47..56].try_into().unwrap()];
        q.identity = limbs[118..127].try_into().unwrap();
        q
    };
    let mut pb = public.clone();
    pb.deliveries[1] = "0x0".into();
    assert_eq!(payment4::bridge_checks(&proved(&pb, &private)), Err("delivery".into()));
    let mut pb = public.clone();
    pb.withdrawal_recipient = "0x1234".into();
    assert_eq!(payment4::bridge_checks(&proved(&pb, &private)), Err("withdrawal".into()));
    let mut p = private.clone();
    p.identity = payment::Identity { active: true, scope: [7; 9] };
    assert_eq!(payment4::bridge_checks(&proved(&public, &p)), Err("identity intent".into()));
    let mut p = private.clone();
    p.inputs[1] = p.inputs[0].clone();
    let total = 2 * p.inputs[0].amount;
    p.outputs[0].amount = 1;
    p.outputs[1].amount = total - 1;
    assert_eq!(payment4::bridge_checks(&proved(&public, &p)), Err("duplicate nullifier".into()));
    let mut pb = public.clone();
    pb.token_out = private.token.clone();
    assert_eq!(payment4::bridge_checks(&pb), Err("exit rule".into()));
    let mut pb = public.clone();
    pb.pool = format!("0x8{}", "0".repeat(62));
    assert_eq!(payment4::bridge_checks(&pb), Err("address range".into()));
}

/// Input 1 committed under a different asset than input 0 cannot be spent with it.
#[test]
fn inputs_under_two_assets_are_rejected() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(13));
        let mut rng = StdRng::seed_from_u64(14);
        let other = format!("0x{:x}", rng.gen_range(1u64..u64::MAX));
        let ctx = |t: &str| [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(t)].concat();
        let leaf = |i: usize, t: &str| {
            let n = &private.inputs[i];
            (n.position, commitment(&ctx(t), n.amount, &receiver_of(&n.sk).0, &n.rho))
        };
        let (_, siblings) = sparse_paths(tree, &[leaf(0, &private.token), leaf(1, &other)], &mut rng);
        let mut p = private.clone();
        for (i, s) in p.inputs.iter_mut().zip(siblings) {
            i.siblings = s;
        }
        assert!(redo(tree, &public, &p).is_err());
        let (_, valid) = outputs(tree, &public, &p);
        assert!(!valid, "{tree:?}: inputs of two assets accepted");
    }
}

/// The same leaf in both input slots yields equal nullifiers, which the bridge and pool reject.
#[test]
fn same_leaf_twice_publishes_equal_nullifiers() {
    let tree = Tree::Compress;
    let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(15));
    let mut p = private.clone();
    p.inputs[1] = p.inputs[0].clone();
    let total = 2 * p.inputs[0].amount;
    p.outputs[0].amount = 1;
    p.outputs[1].amount = total - 1;
    let native = redo(tree, &public, &p).expect("the circuit rules admit it");
    assert_eq!(payment4::bridge_checks(&native), Err("duplicate nullifier".into()));
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, tree, &public, &p);
    assert!(c.is_circuit_valid(), "the circuit admits it; the bridge and pool reject it");
    let limbs: Vec<u32> = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    // Layout: tag 2, chain 9, pool 9, token_out 9, root 9, nf₀ 9, nf₁ 9.
    assert_eq!(limbs[38..47], limbs[47..56]);
}
