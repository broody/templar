//! P1 policy-settlement relation (`docs/policy-note-spec.md` §5), for both tree formats and every
//! outcome shape: circuit outputs equal the native reference; broken witnesses fail.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use rand::{SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{self, P, Tree};
use templar_client_verifier_circuit::policy::{
    self, FIXED, N_OUTPUTS, Private, Public, SHAPES, SPLIT, Shape, build, fresh, orest, outcome_digest, statement_limbs,
};

const TREES: [Tree; 2] = [Tree::Sponge, Tree::Compress];

fn outputs(tree: Tree, public: &Public, private: &Private) -> (Vec<u32>, bool) {
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, tree, public, private);
    let limbs = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    (limbs, c.is_circuit_valid())
}

fn redo(tree: Tree, public: &Public, p: &Private) -> Result<Public, String> {
    policy::statement(tree, &public.chain, &public.pool, &public.token, public.x, &public.data, p)
}

#[test]
fn circuit_statement_matches_native_and_topology_is_fixed() {
    for tree in TREES {
        let mut topologies = vec![];
        for shape in SHAPES {
            let (public, private, _) = fresh(tree, shape, &mut StdRng::seed_from_u64(11));
            let (limbs, valid) = outputs(tree, &public, &private);
            assert!(valid, "{tree:?} {shape:?}");
            assert_eq!(limbs, statement_limbs(tree, &public), "{tree:?} {shape:?}");
            let mut topo = Context::<NoValue>::new(N_OUTPUTS);
            build(&mut topo, tree, &public, &private);
            topologies.push(topo.circuit);
        }
        assert!(topologies.iter().all(|t| *t == topologies[0]), "shape changes the topology");
        let (public, private, _) = fresh(tree, Shape::Settle, &mut StdRng::seed_from_u64(11));
        let mut real = Context::<QM31>::new(N_OUTPUTS);
        let outs = build(&mut real, tree, &public, &private);
        // Finalization rejects unused variables (as the prover's does).
        let mut fin = Context::<QM31>::new(N_OUTPUTS);
        let o = build(&mut fin, tree, &public, &private);
        fin.set_outputs(&o);
        let fin = fin.finalize(true);
        fin.validate_circuit();
        let _ = outs;
        eprintln!("{tree:?}: qm31_ops {} eq {}", real.circuit.n_qm31_ops_rows(), real.circuit.eq.len());
    }
}

#[test]
fn published_fields() {
    let tree = Tree::Compress;
    for shape in SHAPES {
        let (public, private, policy) = fresh(tree, shape, &mut StdRng::seed_from_u64(12));
        assert_eq!(public.policy_id, policy::policy_id(&public.chain, &public.pool, &public.token, private.amount, &policy.digest()));
        assert_eq!(public.index, private.index);
        assert_eq!(public.deadline, policy.header.deadline);
        match shape {
            Shape::SplitAll => {
                assert_eq!(public.x, private.amount);
                assert_eq!(public.commitments[1], [0; 9], "no remainder note");
                assert_eq!(public.deliveries[1], "0x0");
            }
            Shape::Refund => assert_eq!(public.commitments[1], [0; 9]),
            _ => assert_ne!(public.commitments[0], [0; 9]),
        }
    }
}

/// Each tampered witness or statement either fails the circuit or proves a different statement.
#[test]
fn broken_witnesses_are_rejected() {
    for tree in TREES {
        for shape in SHAPES {
            let (public, private, policy) = fresh(tree, shape, &mut StdRng::seed_from_u64(13));
            let want = statement_limbs(tree, &public);
            let check = |name: &str, pb: &Public, p: Private| {
                let (limbs, valid) = outputs(tree, pb, &p);
                assert!(!valid || limbs != want, "{tree:?} {shape:?}: {name} accepted with the same statement");
            };
            let split = private.selected.kind == SPLIT;
            let mut p = private.clone();
            p.cap[2] ^= 1;
            check("wrong capability", &public, p);
            let mut p = private.clone();
            p.siblings[7][1] ^= 1;
            check("wrong sibling", &public, p);
            let mut p = private.clone();
            p.position ^= 1 << 9;
            check("wrong position", &public, p);
            let mut p = private.clone();
            p.amount += 1;
            check("wrong note amount", &public, p);
            // Another slot's digest, or the refund's rest digest, changed.
            let mut p = private.clone();
            let other = (private.index as usize + 1) % 4;
            p.slots[other][0] = (p.slots[other][0] + 1) % P;
            p.rest[0] = (p.rest[0] + 1) % P;
            check("wrong other slot", &public, p);
            // The selected preimage altered: a different receiver, rho, delivery or not_before.
            let mut p = private.clone();
            p.selected.outputs[0].receiver[0] = (p.selected.outputs[0].receiver[0] + 1) % P;
            check("redirected output", &public, p);
            let mut p = private.clone();
            p.selected.not_before += 1;
            check("wrong not_before", &public, p);
            // A different delivery than the committed one (the published delivery is the
            // preimage's, so this changes the outcome digest and the note).
            let mut p = private.clone();
            p.selected.outputs[0].delivery = "0x1234".into();
            check("wrong delivery", &public, p);
            // Another outcome under this outcome's index (selector/slot mismatch).
            let mut p = private.clone();
            let other_outcome = policy.outcomes[(private.index as usize + 1) % 4].clone().unwrap();
            p.selected = other_outcome;
            check("outcome under another index", &public, p);
            // Value from nothing.
            if !split {
                let mut p = private.clone();
                p.selected.outputs[0].amount += 1;
                check("inflated output", &public, p);
            }
            // A larger withdrawal than committed (published from the preimage, so the statement
            // changes or conservation fails).
            let mut p = private.clone();
            p.selected.withdrawal_amount += 1;
            if p.selected.withdrawal_recipient == "0x0" {
                p.selected.withdrawal_recipient = "0x77".into();
            }
            check("inflated withdrawal", &public, p);
            // x: only a split has one, within the amount.
            let mut pb = public.clone();
            pb.x = if split { private.amount + 1 } else { 1 };
            check("wrong x", &pb, private.clone());
            if split {
                let mut pb = public.clone();
                pb.x = 0;
                check("zero split", &pb, private.clone());
            }
            let mut pb = public.clone();
            pb.data = "0x1234".into();
            let (limbs, valid) = outputs(tree, &pb, &private);
            assert!(valid && limbs != want, "data is carried into the statement");
        }
    }
}

/// The refund's rules hold in the circuit, not only natively: a split, a delay or a withdrawal
/// cannot sit in slot 0.
#[test]
fn refund_slot_rules() {
    let tree = Tree::Compress;
    for bad in ["split", "not_before", "withdrawal", "inactive"] {
        let (_, mut private, mut policy) = fresh(tree, Shape::Refund, &mut StdRng::seed_from_u64(14));
        let o = policy.outcomes[0].as_mut().unwrap();
        let amount = private.amount;
        match bad {
            "split" => {
                o.kind = SPLIT;
                o.outputs[0].amount = 0;
                o.outputs[1] = o.outputs[0].clone();
            }
            "not_before" => o.not_before = 1,
            "withdrawal" => {
                o.outputs[0].amount = amount - 1;
                o.withdrawal_recipient = "0x77".into();
                o.withdrawal_amount = 1;
            }
            _ => {
                o.outputs[0] = policy::inactive_out();
                o.withdrawal_recipient = "0x77".into();
                o.withdrawal_amount = amount;
            }
        }
        private = policy::private_for(&policy, 0, private.cap, private.rho, amount, private.position, private.siblings.clone());
        let x = if bad == "split" { amount } else { 0 };
        assert!(policy::statement(tree, "0x534e5f5345504f4c4941", "0x1", "0x2", x, "0x0", &private).is_err(), "{bad} native");
        // Build the statement a lenient native check would give, and show the circuit rejects it.
        let mut public = fresh(tree, Shape::Refund, &mut StdRng::seed_from_u64(14)).0;
        public.x = x;
        let (_, valid) = outputs(tree, &public, &private);
        assert!(!valid, "{bad} accepted by the circuit");
    }
}

/// An unused (zero) slot cannot be selected: no preimage hashes to the zero digest.
#[test]
fn unused_slot_cannot_be_selected() {
    let tree = Tree::Compress;
    let (public, private, mut policy) = fresh(tree, Shape::Settle, &mut StdRng::seed_from_u64(15));
    let settle = policy.outcomes[1].clone().unwrap();
    policy.outcomes[3] = None;
    let mut p = policy::private_for(&policy, 1, private.cap, private.rho, private.amount, private.position, private.siblings.clone());
    // Claim slot 3 with the settle outcome: the recomputed slot 3 is no longer zero.
    p.index = 3;
    p.selected = settle;
    let native = redo(tree, &public, &p).unwrap();
    assert_ne!(native.policy_id, public.policy_id);
    assert_ne!(outcome_digest(&p.selected), [0; 9]);
    assert_ne!(orest(&p.slots[1], &p.slots[2], &[0; 9]), orest(&p.slots[1], &p.slots[2], &outcome_digest(&p.selected)));
}

#[test]
fn native_rules() {
    let tree = Tree::Compress;
    for shape in SHAPES {
        let (public, private, _) = fresh(tree, shape, &mut StdRng::seed_from_u64(16));
        assert_eq!(redo(tree, &public, &private).unwrap(), public);
        let mut p = private.clone();
        p.selected.kind = 3;
        assert!(redo(tree, &public, &p).is_err(), "type 3");
        let mut p = private.clone();
        p.index = 4;
        assert!(redo(tree, &public, &p).is_err(), "index 4");
        let mut p = private.clone();
        p.cap = [0; 9];
        assert!(redo(tree, &public, &p).is_err(), "zero capability");
        let mut p = private.clone();
        p.selected.outputs[0].delivery = "0x0".into();
        assert!(redo(tree, &public, &p).is_err(), "active output without delivery");
        if private.selected.kind == FIXED {
            let mut pb = public.clone();
            pb.x = 1;
            assert!(redo(tree, &pb, &private).is_err(), "x on fixed");
        }
    }
}

/// A policy note's leaf is an ordinary-format commitment whose receiver is the policy receiver;
/// the policy id binds the token, pool and amount (review N-1).
#[test]
fn policy_id_binds_context_and_amount() {
    let (public, private, policy) = fresh(Tree::Compress, Shape::Settle, &mut StdRng::seed_from_u64(17));
    let d = policy.digest();
    let id = |token: &str, amount: u128| policy::policy_id(&public.chain, &public.pool, token, amount, &d);
    assert_eq!(id(&public.token, private.amount), public.policy_id);
    assert_ne!(id("0x1", private.amount), public.policy_id);
    assert_ne!(id(&public.token, private.amount - 1), public.policy_id);
    // The receiver is a PRECV hash: an R0 spend needs H(OWNER, ...) instead.
    let recv = policy::receiver(&private.cap, &d);
    let (owner_recv, _) = payment::receiver_of(&private.cap);
    assert_ne!(recv, owner_recv);
}
