//! R0 payment relation (V2: optional outputs, one withdrawal), for both tree-node formats and
//! every shape: circuit outputs equal the native reference; broken witnesses fail.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use rand::{SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{
    self, N_OUTPUTS, Private, Public, Shape, Tree, build, fresh_shape, statement_limbs,
};

const TREES: [Tree; 2] = [Tree::Sponge, Tree::Compress];
const SHAPES: [Shape; 3] = [Shape::Transfer, Shape::Partial, Shape::Full];

fn outputs(tree: Tree, public: &Public, private: &Private) -> (Vec<u32>, bool) {
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, tree, public, private);
    let limbs = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    (limbs, c.is_circuit_valid())
}

fn redo(tree: Tree, public: &Public, p: &Private) -> Result<Public, String> {
    payment::statement(
        tree,
        &public.chain,
        &public.pool,
        &public.token,
        public.deliveries.clone(),
        (public.withdrawal_recipient.clone(), public.withdrawal_amount),
        p,
    )
}

#[test]
fn circuit_statement_matches_native_and_topology_is_fixed() {
    for tree in TREES {
        // One circuit for every shape: the topology must not depend on which slots are active.
        let mut topologies = vec![];
        for shape in SHAPES {
            let mut rng = StdRng::seed_from_u64(7);
            let (public, private) = fresh_shape(tree, shape, &mut rng);
            let (limbs, valid) = outputs(tree, &public, &private);
            assert!(valid, "{tree:?} {shape:?}");
            assert_eq!(limbs, statement_limbs(tree, &public));
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

/// The two formats give different roots for the same notes.
#[test]
fn tree_formats_differ() {
    let (public, _) = payment::fresh(Tree::Compress, &mut StdRng::seed_from_u64(7));
    let (other, _) = payment::fresh(Tree::Sponge, &mut StdRng::seed_from_u64(7));
    assert_ne!(public.root, other.root);
    assert_eq!(public.nullifiers, other.nullifiers, "same notes, same positions");
}

/// Each tampered witness or statement either fails the circuit or proves a different statement.
#[test]
fn broken_witnesses_are_rejected() {
    for tree in TREES {
        for shape in SHAPES {
            let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(8));
            let want = statement_limbs(tree, &public);
            let check = |name: &str, pb: &Public, p: Private| {
                let (limbs, valid) = outputs(tree, pb, &p);
                assert!(!valid || limbs != want, "{tree:?} {shape:?}: {name} accepted with the same statement");
            };
            let mut p = private.clone();
            p.inputs[0].siblings[5][0] ^= 1;
            check("wrong sibling", &public, p);
            let mut p = private.clone();
            p.inputs[1].position ^= 1 << 20;
            check("wrong position", &public, p);
            let mut p = private.clone();
            p.inputs[0].sk[3] ^= 1;
            check("wrong secret", &public, p);
            // Value created from nothing, through each outflow.
            if private.outputs[0].active {
                let mut p = private.clone();
                p.outputs[0].amount += 1;
                check("inflated output", &public, p);
            }
            let mut pb = public.clone();
            pb.withdrawal_amount += 1;
            check("inflated withdrawal", &pb, private.clone());
            // An inactive slot cannot carry value or a delivery digest.
            if !private.outputs[1].active {
                let mut p = private.clone();
                p.outputs[1].amount = 1;
                let mut pb = public.clone();
                pb.withdrawal_amount -= 1;
                check("value in an inactive slot", &pb, p);
                let mut pb = public.clone();
                pb.deliveries[1] = "0x1".to_string();
                check("delivery for an inactive slot", &pb, private.clone());
            }
        }
    }
}

#[test]
fn native_rules() {
    for tree in TREES {
        for shape in SHAPES {
            let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(9));
            assert_eq!(redo(tree, &public, &private).unwrap(), public);
            let mut p = private.clone();
            p.inputs[1] = p.inputs[0].clone();
            assert!(redo(tree, &public, &p).is_err(), "duplicate input");
            let mut pb = public.clone();
            pb.withdrawal_amount += 1;
            assert!(redo(tree, &pb, &private).is_err(), "conservation");
        }
        // A withdrawal needs both a recipient and an amount; something must leave the inputs.
        let (public, private) = fresh_shape(tree, Shape::Partial, &mut StdRng::seed_from_u64(9));
        let mut pb = public.clone();
        pb.withdrawal_recipient = "0x0".to_string();
        assert!(redo(tree, &pb, &private).is_err(), "withdrawal without recipient");
        let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(9));
        let mut p = private.clone();
        p.outputs[1].receiver = [0; 9];
        assert!(redo(tree, &public, &p).is_err(), "zero receiver");
    }
}

/// The full client pipeline's finalization (unused-variable lint included) accepts the circuit.
#[test]
fn circuit_finalizes_with_lint() {
    for tree in TREES {
        for shape in SHAPES {
            let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(10));
            let mut c = Context::<QM31>::new(N_OUTPUTS);
            let out = build(&mut c, tree, &public, &private);
            c.set_outputs(&out);
            let f = c.finalize(true);
            f.validate_circuit();
        }
    }
}

/// `tree_paths` (the wallet's path source) agrees with climbing from each leaf and with the
/// pool's golden roots (bench/m31-pool/vectors.json, same leaves in order).
#[test]
fn wallet_tree_paths_match_pool() {
    let v: serde_json::Value = serde_json::from_slice(
        &std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../m31-pool/vectors.json")).unwrap(),
    )
    .unwrap();
    let leaves: Vec<payment::Digest> = serde_json::from_value(v["leaves"].clone()).unwrap();
    for (tree, name) in [(Tree::Sponge, "Sponge"), (Tree::Compress, "Compress")] {
        let roots: Vec<payment::Digest> = serde_json::from_value(v["formats"][name]["roots"].clone()).unwrap();
        for n in 1..=leaves.len() {
            let positions: Vec<u32> = (0..n as u32).collect();
            let (root, paths) = payment::tree_paths(tree, &leaves[..n], &positions);
            assert_eq!(root, roots[n - 1], "{name} root after {n}");
            for (p, path) in paths.iter().enumerate() {
                assert_eq!(payment::climb(tree, &leaves[p], p as u32, path), root, "{name} path {p} of {n}");
            }
        }
    }
}
