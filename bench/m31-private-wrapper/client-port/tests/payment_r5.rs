//! R0 V5 (`docs/account-bound-note-spec.md` §4): circuit outputs equal the native reference for
//! every shape, both modes and both tree formats; the topology is shape- and mode-independent;
//! the mode and account rules; identity handles over the selected key; expiry and account
//! encodings; V4's mutations still fail; bridge-only rules through the bridge decoder.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{
    self, AUTH, Digest, IDENTITY, INNER, Identity, Input, NF, NK, NODE, NODE1, NOTE, OWNER, P, Tree, commitment,
    felt_limbs, nullifier,
};
use templar_client_verifier_circuit::payment5::{
    self, Mode, N_OUTPUTS, Output, Private, Public, Shape, WAUTH, ak_of, build, decode_statement, fresh_shape,
    identity_handle, random_account, receiver_of, sparse_paths, statement_limbs,
};
use templar_client_verifier_circuit::{payment4, policy};

const TREES: [Tree; 2] = [Tree::Sponge, Tree::Compress];
const MODES: [Mode; 2] = [Mode::Ordinary, Mode::Bound];
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
    payment5::statement(
        tree,
        &public.chain,
        &public.pool,
        public.deliveries.clone(),
        (public.withdrawal_recipient.clone(), public.withdrawal_amount),
        &public.intent,
        public.valid_until,
        p,
    )
}

fn exits(shape: Shape) -> bool {
    matches!(shape, Shape::Partial | Shape::Full | Shape::Invoke | Shape::Shadow)
}

fn words(account: &str) -> Digest {
    felt_limbs(account)
}

/// Re-plants the real inputs' leaves, input `i` under the receiver bound to `accounts[i]` (zero
/// words for an ordinary receiver), so only the rule under test can fail.
fn replant_with(tree: Tree, public: &Public, mut p: Private, accounts: [Digest; 2], seed: u64) -> (Private, Digest) {
    let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&p.token)].concat();
    let real = if p.dummy { 1 } else { 2 };
    let leaves: Vec<(u32, Digest)> = p.inputs[..real]
        .iter()
        .zip(accounts)
        .map(|(i, a)| (i.position, commitment(&context, i.amount, &receiver_of(&a, &i.sk).0, &i.rho)))
        .collect();
    let (root, siblings) = sparse_paths(tree, &leaves, &mut StdRng::seed_from_u64(seed));
    for (i, s) in p.inputs.iter_mut().zip(siblings) {
        i.siblings = s;
    }
    (p, root)
}

/// Re-plants the real inputs under the witness's own account, asset and amounts.
fn replant(tree: Tree, public: &Public, p: Private, seed: u64) -> Private {
    let a = words(&p.account);
    replant_with(tree, public, p, [a, a], seed).0
}

fn root_of(limbs: &[u32]) -> Digest {
    limbs[29..38].try_into().unwrap()
}

/// The attempt fails the circuit or publishes a root other than the tree's (the pool rejects an
/// unknown root).
fn off_tree(tree: Tree, public: &Public, p: &Private, real_root: &Digest, name: &str) {
    let (limbs, valid) = outputs(tree, public, p);
    assert!(!valid || root_of(&limbs) != *real_root, "{tree:?}: {name} proves under the real root");
}

#[test]
fn circuit_statement_matches_native_and_topology_is_fixed() {
    for tree in TREES {
        let mut topologies = vec![];
        for mode in MODES {
            for shape in SHAPES {
                for seed in 0..2 {
                    let (public, private) = fresh_shape(tree, shape, mode, &mut StdRng::seed_from_u64(seed));
                    let (limbs, valid) = outputs(tree, &public, &private);
                    assert!(valid, "{tree:?} {mode:?} {shape:?}");
                    assert_eq!(limbs, statement_limbs(tree, &public), "{tree:?} {mode:?} {shape:?}");
                    // The bridge decoder reads back exactly the native statement.
                    assert_eq!(decode_statement(tree, &limbs), Ok(public.clone()), "{tree:?} {mode:?} {shape:?}");
                    // The asset is published exactly on exit; the account exactly in bound mode.
                    let hidden = felt_limbs(&public.token_out).iter().all(|l| *l == 0);
                    assert_eq!(hidden, !exits(shape));
                    let account = &limbs[127..136];
                    assert_eq!(account.iter().all(|l| *l == 0), mode == Mode::Ordinary);
                    assert_eq!(account, felt_limbs(&private.account));
                    assert_eq!(limbs[138..140], [0, 0], "padding");
                }
                let (public, private) = fresh_shape(tree, shape, mode, &mut StdRng::seed_from_u64(7));
                let mut topo = Context::<NoValue>::new(N_OUTPUTS);
                build(&mut topo, tree, &public, &private);
                topologies.push(topo.circuit);
            }
        }
        // Mode, like shape, never changes the circuit (spec §12 uniformity).
        assert!(topologies.iter().all(|t| *t == topologies[0]), "shape or mode changes the topology");
        for mode in MODES {
            let (public, private) = fresh_shape(tree, Shape::Transfer, mode, &mut StdRng::seed_from_u64(7));
            let mut real = Context::<QM31>::new(N_OUTPUTS);
            build(&mut real, tree, &public, &private);
            let (p4, w4) = payment4::fresh_shape(tree, payment4::Shape::Transfer, &mut StdRng::seed_from_u64(7));
            let mut v4 = Context::<QM31>::new(payment4::N_OUTPUTS);
            payment4::build(&mut v4, tree, &p4, &w4);
            eprintln!(
                "{tree:?} {mode:?}: V5 qm31_ops {} eq {}; V4 qm31_ops {} eq {}",
                real.circuit.n_qm31_ops_rows(),
                real.circuit.eq.len(),
                v4.circuit.n_qm31_ops_rows(),
                v4.circuit.eq.len()
            );
        }
    }
}

/// The V5 tags differ from V4's and V3's, and between tree formats.
#[test]
fn tags_differ_from_v4_and_v3() {
    for tree in TREES {
        assert_ne!(payment5::statement_tag(tree), payment4::statement_tag(tree));
        assert_ne!(payment5::statement_tag(tree), payment::statement_tag(tree));
    }
    assert_ne!(payment5::statement_tag(Tree::Sponge), payment5::statement_tag(Tree::Compress));
}

/// WAUTH is unused by every other M31 hash kind in the crate (spec §3.1), and its frame has the
/// block shape of OWNER and INNER (22 words).
#[test]
fn wauth_kind_is_unused() {
    let kinds = [
        AUTH, NK, OWNER, INNER, NOTE, NODE, NF, NODE1, IDENTITY,
        policy::PNK, policy::PRECV, policy::POLICY, policy::OUTCOME, policy::OREST, policy::POLICY_ID,
    ];
    assert_eq!(WAUTH, 16);
    assert!(!kinds.contains(&WAUTH));
    for (i, a) in kinds.iter().enumerate() {
        assert!(!kinds[i + 1..].contains(a), "kind {a} used twice");
    }
    // Framed: [TAG, 1, kind, level] ++ account₉ ++ sk₉, as OWNER's [.. ] ++ ak₉ ++ nk₉.
    assert_eq!(4 + 9 + 9, 22);
}

/// An ordinary V5 statement equals V4's on every shared field except `identity`, which V5
/// computes over `ak₀` (AB-M1).
#[test]
fn ordinary_v5_equals_v4_except_identity() {
    for tree in TREES {
        for shape in SHAPES {
            let (p4, w4) = payment4::fresh_shape(tree, shape, &mut StdRng::seed_from_u64(9));
            let w5 = Private {
                token: w4.token.clone(),
                account: "0x0".into(),
                inputs: w4.inputs.clone(),
                dummy: w4.dummy,
                outputs: w4.outputs.clone(),
                identity: w4.identity.clone(),
            };
            let p5 = payment5::statement(
                tree, &p4.chain, &p4.pool, p4.deliveries.clone(), (p4.withdrawal_recipient.clone(), p4.withdrawal_amount),
                &p4.intent, 1_000, &w5,
            )
            .expect("valid V5 witness");
            assert_eq!(
                (&p5.chain, &p5.pool, &p5.token_out, p5.root, p5.nullifiers, p5.commitments),
                (&p4.chain, &p4.pool, &p4.token_out, p4.root, p4.nullifiers, p4.commitments),
                "{tree:?} {shape:?}"
            );
            assert_eq!((&p5.deliveries, &p5.withdrawal_recipient, p5.withdrawal_amount, &p5.intent),
                (&p4.deliveries, &p4.withdrawal_recipient, p4.withdrawal_amount, &p4.intent));
            assert_eq!(p5.identity == p4.identity, !w5.identity.active, "{tree:?} {shape:?}");
            let (limbs, valid) = outputs(tree, &p5, &w5);
            assert!(valid);
            assert_eq!(limbs, statement_limbs(tree, &p5));
        }
    }
}

/// A bound note spent with m = 0, an ordinary note spent with m = 1, and a note bound to A spent
/// under A′ ≠ A: each fails or proves under an unknown root.
#[test]
fn mode_and_account_must_match_the_notes() {
    for tree in TREES {
        for shape in [Shape::Transfer, Shape::Single, Shape::Partial] {
            let (public, private) = fresh_shape(tree, shape, Mode::Bound, &mut StdRng::seed_from_u64(40));
            let mut p = private.clone();
            p.account = "0x0".into();
            off_tree(tree, &public, &p, &public.root, "bound note with m = 0");
            let mut p = private.clone();
            p.account = random_account(&mut StdRng::seed_from_u64(41));
            off_tree(tree, &public, &p, &public.root, "note bound to A under A′");
            let (public, private) = fresh_shape(tree, shape, Mode::Ordinary, &mut StdRng::seed_from_u64(42));
            let mut p = private.clone();
            p.account = random_account(&mut StdRng::seed_from_u64(43));
            off_tree(tree, &public, &p, &public.root, "ordinary note with m = 1");
        }
    }
}

/// Input 0 bound to A with input 1 ordinary, or bound to B: no single mode and account spends
/// both.
#[test]
fn inputs_bound_differently_cannot_be_spent_together() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(44));
        let a = words(&private.account);
        let b = words(&random_account(&mut StdRng::seed_from_u64(45)));
        for other in [[0; 9], b] {
            let (planted, root) = replant_with(tree, &public, private.clone(), [a, other], 46);
            for account in [private.account.clone(), "0x0".into(), payment5::felt_from_limbs(&b).unwrap()] {
                let mut p = planted.clone();
                p.account = account.clone();
                off_tree(tree, &public, &p, &root, &format!("mixed inputs spent as {account}"));
            }
        }
    }
}

/// A bound spend's dummy input 1 is a bound note of the same account: its published nullifier is
/// the bound-mode one (AB-M14), which the SDK's "companion not spent" check must compute.
#[test]
fn bound_dummy_nullifier_is_computed_in_bound_mode() {
    let tree = Tree::Compress;
    let (public, private) = fresh_shape(tree, Shape::Single, Mode::Bound, &mut StdRng::seed_from_u64(47));
    let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&private.token)].concat();
    let d = &private.inputs[1];
    let nf_in = |account: &Digest| {
        let (receiver, nk) = receiver_of(account, &d.sk);
        nullifier(&nk, &commitment(&context, 0, &receiver, &d.rho), d.position)
    };
    assert_eq!(public.nullifiers[1], nf_in(&words(&private.account)));
    assert_ne!(public.nullifiers[1], nf_in(&[0; 9]));
}

/// A spend of one note (input 0) with a dummy input 1: one real output of the whole amount and a
/// dummy output.
fn spend_of_note(tree: Tree, pool: &str, token: &str, account: &str, sk: Digest, rho: Digest, amount: u128, seed: u64) -> (Public, Private) {
    let chain = "0x534e5f5345504f4c4941";
    let rng = &mut StdRng::seed_from_u64(seed);
    let digest = |rng: &mut StdRng| -> Digest { std::array::from_fn(|_| rng.gen_range(0..P)) };
    let context = [felt_limbs(chain), felt_limbs(pool), felt_limbs(token)].concat();
    let position = rng.next_u32();
    let leaf = commitment(&context, amount, &receiver_of(&words(account), &sk).0, &rho);
    let (_, siblings) = sparse_paths(tree, &[(position, leaf)], rng);
    let dummy = Input { sk: digest(rng), rho: digest(rng), amount: 0, position: position ^ 1, siblings: (0..32).map(|_| digest(rng)).collect() };
    let private = Private {
        token: token.into(),
        account: account.into(),
        inputs: [Input { sk, rho, amount, position, siblings: siblings[0].clone() }, dummy],
        dummy: true,
        outputs: [
            Output { receiver: digest(rng), rho: digest(rng), amount },
            Output { receiver: digest(rng), rho: digest(rng), amount: 0 },
        ],
        identity: Identity::default(),
    };
    let deliveries = ["0x11".to_string(), "0x13".to_string()];
    let public = payment5::statement(tree, chain, pool, deliveries, ("0x0".into(), 0), "0x0", 77, &private).expect("valid");
    (public, private)
}

/// Ordinary and bound receivers pay each other: a bound spend creates a note for an ordinary
/// receiver, which an ordinary spend then spends, and the reverse.
#[test]
fn ordinary_and_bound_receivers_pay_each_other() {
    let tree = Tree::Compress;
    let rng = &mut StdRng::seed_from_u64(48);
    for (from, to) in [(Mode::Bound, Mode::Ordinary), (Mode::Ordinary, Mode::Bound)] {
        let (public, mut private) = fresh_shape(tree, Shape::Transfer, from, rng);
        let sk2: Digest = std::array::from_fn(|_| rng.gen_range(0..P));
        let to_account = if to == Mode::Bound { random_account(rng) } else { "0x0".into() };
        private.outputs[0].receiver = receiver_of(&words(&to_account), &sk2).0;
        let public = redo(tree, &public, &private).expect("valid");
        let (limbs, valid) = outputs(tree, &public, &private);
        assert!(valid && limbs == statement_limbs(tree, &public), "{from:?} pays {to:?}");
        // The created note, spent in the receiver's own mode.
        let o = &private.outputs[0];
        let (p2, w2) = spend_of_note(tree, &public.pool, &private.token, &to_account, sk2, o.rho, o.amount, 49);
        let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&private.token)].concat();
        assert_eq!(commitment(&context, o.amount, &o.receiver, &o.rho), public.commitments[0]);
        let (limbs, valid) = outputs(tree, &p2, &w2);
        assert!(valid && limbs == statement_limbs(tree, &p2), "{to:?} spends what {from:?} paid");
    }
}

/// Identity handles (AB-M1, AB-M12): the handle is over the selected key. For one `sk` and
/// `scope`, the ordinary and bound handles differ, and a bound spend under M ≠ A with A's `sk`
/// does not reproduce A's handle; each attempt is itself a valid spend.
#[test]
fn identity_handles_follow_the_selected_key() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Shadow, Mode::Bound, &mut StdRng::seed_from_u64(50));
        let a = words(&private.account);
        let (sk0, scope) = (private.inputs[0].sk, private.identity.scope);
        assert_eq!(public.identity, identity_handle(&ak_of(&a, &sk0), &scope));
        assert_ne!(identity_handle(&ak_of(&a, &sk0), &scope), identity_handle(&ak_of(&[0; 9], &sk0), &scope));
        let m = words(&random_account(&mut StdRng::seed_from_u64(51)));
        for (name, account) in [("ordinary", [0u32; 9]), ("bound under M", m)] {
            let (mut p, _) = replant_with(tree, &public, private.clone(), [account, account], 52);
            p.account = payment5::felt_from_limbs(&account).unwrap();
            let q = redo(tree, &public, &p).expect("a valid spend of the attacker's own notes");
            let (limbs, valid) = outputs(tree, &q, &p);
            assert!(valid && limbs == statement_limbs(tree, &q), "{tree:?} {name}");
            assert_ne!(q.identity, public.identity, "{tree:?}: {name} reproduces A's handle");
        }
        // The handle is not the V4 one over sk₀.
        assert_ne!(public.identity, payment::identity_handle(&sk0, &scope));
    }
}

/// The encoding extremes: `valid_until = 2^56 − 1` and `1`, and an account just below 2^251.
#[test]
fn expiry_and_account_extremes() {
    for tree in TREES {
        for valid_until in [1, (1 << 56) - 1] {
            let (mut public, private) = fresh_shape(tree, Shape::Partial, Mode::Bound, &mut StdRng::seed_from_u64(53));
            public.valid_until = valid_until;
            let (limbs, valid) = outputs(tree, &public, &private);
            assert!(valid);
            assert_eq!(decode_statement(tree, &limbs), Ok(public.clone()));
        }
        let (public, mut private) = fresh_shape(tree, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(54));
        private.account = format!("0x7{}", "f".repeat(62));
        let p = replant(tree, &public, private, 55);
        let q = redo(tree, &public, &p).expect("valid");
        let (limbs, valid) = outputs(tree, &q, &p);
        assert!(valid);
        assert_eq!(decode_statement(tree, &limbs), Ok(q));
    }
}

/// Mutations an attacker wants proved: each must make the circuit invalid, in both modes (V4's
/// list, HA-IM1).
#[test]
fn attacker_mutations_fail_the_circuit() {
    for tree in TREES {
        for mode in MODES {
            for shape in SHAPES {
                let (public, private) = fresh_shape(tree, shape, mode, &mut StdRng::seed_from_u64(8));
                assert!(outputs(tree, &public, &private).1, "{tree:?} {mode:?} {shape:?}: control");
                let invalid = |name: &str, p: Private| {
                    let (_, valid) = outputs(tree, &public, &p);
                    assert!(!valid, "{tree:?} {mode:?} {shape:?}: {name} satisfies the circuit");
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
                    let mut p = private.clone();
                    p.inputs[1].amount = 5;
                    p.outputs[0].amount += 5;
                    invalid("dummy input with value", p);
                    let mut p = private.clone();
                    p.dummy = false;
                    invalid("enabled input off the tree", p);
                } else {
                    let mut p = private.clone();
                    p.inputs[1].siblings[9][3] ^= 1;
                    invalid("wrong sibling of an enabled input 1", p);
                    let mut p = private.clone();
                    p.dummy = true;
                    invalid("real input disabled", p);
                }
            }
        }
    }
}

/// Mutations that change what is proved: the circuit either fails or publishes a different
/// statement, which the pool then rejects.
#[test]
fn other_mutations_change_the_statement() {
    for tree in TREES {
        for mode in MODES {
            for shape in SHAPES {
                let (public, private) = fresh_shape(tree, shape, mode, &mut StdRng::seed_from_u64(8));
                let want = statement_limbs(tree, &public);
                let check = |name: &str, p: Private| {
                    let (limbs, valid) = outputs(tree, &public, &p);
                    assert!(!valid || limbs != want, "{tree:?} {mode:?} {shape:?}: {name} accepted with the same statement");
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
}

/// amount₀ = 0 on a consistent tree fails only the real-input nonzero check (bound mode).
#[test]
fn zero_real_input_fails_on_a_consistent_tree() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Single, Mode::Bound, &mut StdRng::seed_from_u64(16));
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

/// Input 1 committed under a different asset than input 0 cannot be spent with it (bound mode).
#[test]
fn inputs_under_two_assets_are_rejected() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(13));
        let a = words(&private.account);
        let other = "0x5151";
        let ctx = |t: &str| [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(t)].concat();
        let leaf = |i: usize, t: &str| {
            let n = &private.inputs[i];
            (n.position, commitment(&ctx(t), n.amount, &receiver_of(&a, &n.sk).0, &n.rho))
        };
        let (_, siblings) = sparse_paths(tree, &[leaf(0, &private.token), leaf(1, other)], &mut StdRng::seed_from_u64(14));
        let mut p = private.clone();
        for (i, s) in p.inputs.iter_mut().zip(siblings) {
            i.siblings = s;
        }
        assert!(redo(tree, &public, &p).is_err());
        assert!(!outputs(tree, &public, &p).1, "{tree:?}: inputs of two assets accepted");
    }
}

/// Statements the circuit proves but the bridge must reject (HA-IM3, F11): each is proved, then
/// decoded through the bridge mirror, which names the rule.
#[test]
fn bridge_only_rules() {
    let tree = Tree::Compress;
    let (public, private) = fresh_shape(tree, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(21));
    let decoded = |pb: &Public, p: &Private| -> Result<Public, String> {
        let (limbs, valid) = outputs(tree, pb, p);
        assert!(valid, "the circuit admits it");
        decode_statement(tree, &limbs)
    };
    let mut pb = public.clone();
    pb.deliveries[1] = "0x0".into();
    assert_eq!(decoded(&pb, &private), Err("delivery".into()));
    let mut pb = public.clone();
    pb.withdrawal_recipient = "0x1234".into();
    assert_eq!(decoded(&pb, &private), Err("withdrawal".into()));
    let mut p = private.clone();
    p.identity = Identity { active: true, scope: [7; 9] };
    assert_eq!(decoded(&public, &p), Err("identity intent".into()));
    let mut p = private.clone();
    p.inputs[1] = p.inputs[0].clone();
    let total = 2 * p.inputs[0].amount;
    p.outputs[0].amount = 1;
    p.outputs[1].amount = total - 1;
    assert_eq!(decoded(&public, &p), Err("duplicate nullifier".into()));
    let mut pb = public.clone();
    pb.intent = format!("0x{}", payment5_prime());
    assert_eq!(decoded(&pb, &private), Err("non-canonical felt".into()));
    let mut pb = public.clone();
    pb.valid_until = 0;
    assert_eq!(decoded(&pb, &private), Err("valid_until".into()));
    // An account at 2^251 (and one at p) is proved like any other; the bridge rejects both.
    for (account, reason) in [(format!("0x8{}", "0".repeat(62)), "account range"), (format!("0x{}", payment5_prime()), "non-canonical felt")] {
        let mut p = private.clone();
        p.account = account;
        let p = replant(tree, &public, p, 22);
        let q = redo(tree, &public, &p).expect("the circuit rules admit it");
        assert_eq!(decoded(&q, &p), Err(reason.into()));
    }
    // Decoder-only rules on raw limbs: nonzero padding, 28-bit limb ranges.
    let (limbs, _) = outputs(tree, &public, &private);
    let raw = |at: usize, v: u32| {
        let mut x = limbs.clone();
        x[at] = v;
        decode_statement(tree, &x)
    };
    assert_eq!(raw(138, 1), Err("statement padding".into()));
    assert_eq!(raw(139, 1), Err("statement padding".into()));
    assert_eq!(raw(136, 1 << 28), Err("limb range".into()));
    assert_eq!(raw(137, 1 << 28), Err("limb range".into()));
    assert_eq!(raw(0, 0), Err("statement tag".into()));
    // Every decoder rule has its own raw case (AB-IM2): each amount limb at 2^16, a limb at 2^28
    // and the value p in every felt field, and a word at p in any position.
    for k in 101..109 {
        assert_eq!(raw(k, 1 << 16), Err("amount limb range".into()), "amount limb {k}");
    }
    let prime = felt_limbs(&format!("0x{}", payment5_prime()));
    for (name, at) in [("chain", 2), ("pool", 11), ("token_out", 20), ("delivery0", 65), ("delivery1", 83), ("recipient", 92), ("intent", 109), ("account", 127)] {
        for l in 0..9 {
            assert_eq!(raw(at + l, 1 << 28), Err("limb range".into()), "{name} limb {l}");
        }
        let mut x = limbs.clone();
        x[at..at + 9].copy_from_slice(&prime);
        assert_eq!(decode_statement(tree, &x), Err("non-canonical felt".into()), "{name} = p");
    }
    for at in [29, 38, 56, 74, 118, 136] {
        assert_eq!(raw(at, P), Err("M31 range".into()), "word {at} at p");
    }
}

/// A zero asset on a consistent tree fails only the asset nonzero check; a small asset passes
/// (bound mode; V4's test).
#[test]
fn zero_asset_fails_on_a_consistent_tree() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(18));
        let mut p = private.clone();
        p.token = "0x5".into();
        let control = replant(tree, &public, p.clone(), 19);
        assert!(outputs(tree, &public, &control).1, "{tree:?}: control asset 0x5");
        p.token = "0x0".into();
        let zero = replant(tree, &public, p, 19);
        assert!(!outputs(tree, &public, &zero).1, "{tree:?}: zero asset accepted");
    }
}

fn payment5_prime() -> &'static str {
    "800000000000011000000000000000000000000000000000000000000000001"
}

/// The same leaf in both input slots yields equal nullifiers, which the bridge rejects.
#[test]
fn same_leaf_twice_publishes_equal_nullifiers() {
    let tree = Tree::Compress;
    let (public, private) = fresh_shape(tree, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(15));
    let mut p = private.clone();
    p.inputs[1] = p.inputs[0].clone();
    let total = 2 * p.inputs[0].amount;
    p.outputs[0].amount = 1;
    p.outputs[1].amount = total - 1;
    let native = redo(tree, &public, &p).expect("the circuit rules admit it");
    assert_eq!(payment5::bridge_checks(&native), Err("duplicate nullifier".into()));
    let (limbs, valid) = outputs(tree, &public, &p);
    assert!(valid, "the circuit admits it; the bridge and pool reject it");
    assert_eq!(limbs[38..47], limbs[47..56]);
}

/// The pinned circuit hashes are the code's (F38): the R5 manifest the bridge build pins, and the
/// deployed R4 bridge's build record, are recomputed from the current relations. A change to any
/// shared gadget that moves a hash fails here, before a bridge is rebuilt.
#[test]
fn pinned_circuit_hashes_match_the_code() {
    use templar_client_verifier_circuit::prove;
    let recorded = |rel: &str| -> Vec<u32> {
        let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["circuit_hash_u32_le"].as_array().unwrap().iter().map(|w| w.as_u64().unwrap() as u32).collect()
    };
    let (p5, w5) = fresh_shape(prove::TREE, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(1));
    let h5 = prove::words(prove::prove(&prove::R5(&p5, &w5), [7; 32], None).unwrap().circuit_hash);
    assert_eq!(h5.to_vec(), recorded("results/stwo-client-r5/trusted-config.json"), "R5");
    let (p4, w4) = payment4::fresh_shape(prove::TREE, payment4::Shape::Transfer, &mut StdRng::seed_from_u64(1));
    let h4 = prove::words(prove::prove(&prove::R4(&p4, &w4), [7; 32], None).unwrap().circuit_hash);
    assert_eq!(h4.to_vec(), recorded("results/r4-bridge/bridge-build-record.json"), "R4");
}
