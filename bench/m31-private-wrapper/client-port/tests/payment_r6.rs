//! R0 V6 (`docs/pool-v3-spec.md` §4): circuit outputs equal the native reference for every shape
//! and both tree formats; the topology is shape-independent; V5-ordinary and V6 agree under the
//! limb map φ; identity handles over the in-circuit `ak₀`; the expiry encoding; V4's mutations
//! still fail; bridge-only rules through the bridge decoder; the pinned circuit hash (F38).
use circuits::context::Context;
use circuits::ivalue::NoValue;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{self, Digest, Identity, Input, P, Tree, commitment, felt_limbs, h};
use templar_client_verifier_circuit::payment6::{
    self, N_OUTPUTS, Output, Private, Public, Shape, ak_of, build, decode_statement, fresh_shape, identity_handle, phi,
    receiver_of, sparse_paths, statement_limbs,
};
use templar_client_verifier_circuit::{payment4, payment5};

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

fn outputs5(tree: Tree, public: &payment5::Public, private: &payment5::Private) -> (Vec<u32>, bool) {
    let mut c = Context::<QM31>::new(payment5::N_OUTPUTS);
    let out = payment5::build(&mut c, tree, public, private);
    let limbs = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    (limbs, c.is_circuit_valid())
}

fn redo(tree: Tree, public: &Public, p: &Private) -> Result<Public, String> {
    payment6::statement(
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

/// Re-plants the real inputs under their ordinary receivers, so only the rule under test can fail.
fn replant(tree: Tree, public: &Public, mut p: Private, seed: u64) -> Private {
    let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&p.token)].concat();
    let real = if p.dummy { 1 } else { 2 };
    let leaves: Vec<(u32, Digest)> =
        p.inputs[..real].iter().map(|i| (i.position, commitment(&context, i.amount, &receiver_of(&i.sk).0, &i.rho))).collect();
    let (_, siblings) = sparse_paths(tree, &leaves, &mut StdRng::seed_from_u64(seed));
    for (i, s) in p.inputs.iter_mut().zip(siblings) {
        i.siblings = s;
    }
    p
}

fn root_of(limbs: &[u32]) -> Digest {
    limbs[29..38].try_into().unwrap()
}

#[test]
fn circuit_statement_matches_native_and_topology_is_fixed() {
    for tree in TREES {
        let mut topologies = vec![];
        for shape in SHAPES {
            for seed in 0..2 {
                let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(seed));
                let (limbs, valid) = outputs(tree, &public, &private);
                assert!(valid, "{tree:?} {shape:?}");
                assert_eq!(limbs, statement_limbs(tree, &public), "{tree:?} {shape:?}");
                // The bridge decoder reads back exactly the native statement.
                assert_eq!(decode_statement(tree, &limbs), Ok(public.clone()), "{tree:?} {shape:?}");
                let hidden = felt_limbs(&public.token_out).iter().all(|l| *l == 0);
                assert_eq!(hidden, !exits(shape));
                assert_eq!(limbs.len(), 132);
                assert_eq!(limbs[129..132], [0, 0, 0], "padding");
                assert_eq!(limbs[127] as u64 | (limbs[128] as u64) << 28, public.valid_until);
            }
            let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(7));
            let mut topo = Context::<NoValue>::new(N_OUTPUTS);
            build(&mut topo, tree, &public, &private);
            topologies.push(topo.circuit);
        }
        assert!(topologies.iter().all(|t| *t == topologies[0]), "shape changes the topology");
        let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(7));
        let mut v6 = Context::<QM31>::new(N_OUTPUTS);
        build(&mut v6, tree, &public, &private);
        let (p5, w5) = payment5::fresh_shape(tree, Shape::Transfer, payment5::Mode::Ordinary, &mut StdRng::seed_from_u64(7));
        let mut v5 = Context::<QM31>::new(payment5::N_OUTPUTS);
        payment5::build(&mut v5, tree, &p5, &w5);
        eprintln!(
            "{tree:?}: V6 qm31_ops {} eq {}; V5 qm31_ops {} eq {}",
            v6.circuit.n_qm31_ops_rows(),
            v6.circuit.eq.len(),
            v5.circuit.n_qm31_ops_rows(),
            v5.circuit.eq.len()
        );
    }
}

/// The V6 tags differ from V5's, V4's and V3's, and between tree formats; they are the spec's
/// values (`R0V6` = 0x52305636, `R0C6` = 0x52304336).
#[test]
fn tags_differ_from_earlier_versions() {
    assert_eq!(payment6::STATEMENT_TAG, [0x544d_505a, 0x5230_5636]);
    assert_eq!(payment6::STATEMENT_TAG_COMPRESS, [0x544d_505a, 0x5230_4336]);
    for tree in TREES {
        assert_ne!(payment6::statement_tag(tree), payment5::statement_tag(tree));
        assert_ne!(payment6::statement_tag(tree), payment4::statement_tag(tree));
        assert_ne!(payment6::statement_tag(tree), payment::statement_tag(tree));
    }
    assert_ne!(payment6::statement_tag(Tree::Sponge), payment6::statement_tag(Tree::Compress));
}

/// The hash kind WAUTH = 16 stays reserved permanently (spec §3): bound receivers already in pool
/// V3's tree contain it, and no hash kind of the crate may reuse it.
#[test]
fn wauth_kind_stays_reserved() {
    use templar_client_verifier_circuit::payment::{AUTH, IDENTITY, INNER, NF, NK, NODE, NODE1, NOTE, OWNER};
    use templar_client_verifier_circuit::policy;
    let kinds = [
        AUTH, NK, OWNER, INNER, NOTE, NODE, NF, NODE1, IDENTITY,
        policy::PNK, policy::PRECV, policy::POLICY, policy::OUTCOME, policy::OREST, policy::POLICY_ID,
    ];
    assert_eq!(payment5::WAUTH, 16);
    assert!(!kinds.contains(&16), "hash kind 16 (WAUTH) is reused");
    for (i, a) in kinds.iter().enumerate() {
        assert!(!kinds[i + 1..].contains(a), "kind {a} used twice");
    }
}

/// Cross-version equality (spec §3, MR-V6-6): every V6 witness is a V5-ordinary witness with the
/// same values, both circuits accept, and the published limbs agree under φ. Over every shape
/// (identity-active and single-input-with-dummy included) and both trees.
#[test]
fn v5_ordinary_equals_v6_under_phi() {
    for tree in TREES {
        for shape in SHAPES {
            for seed in [3, 4] {
                let (p6, w6) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(seed));
                let w5 = payment6::to_v5(&w6);
                let p5 = payment5::statement(
                    tree, &p6.chain, &p6.pool, p6.deliveries.clone(), (p6.withdrawal_recipient.clone(), p6.withdrawal_amount),
                    &p6.intent, p6.valid_until, &w5,
                )
                .expect("the same values are a V5-ordinary witness");
                assert_eq!(p5.account, "0x0");
                assert_eq!(
                    (&p5.chain, &p5.pool, &p5.token_out, p5.root, p5.nullifiers, p5.commitments, p5.identity, p5.valid_until),
                    (&p6.chain, &p6.pool, &p6.token_out, p6.root, p6.nullifiers, p6.commitments, p6.identity, p6.valid_until),
                    "{tree:?} {shape:?}"
                );
                let (l5, ok5) = outputs5(tree, &p5, &w5);
                let (l6, ok6) = outputs(tree, &p6, &w6);
                assert!(ok5 && ok6, "{tree:?} {shape:?}: both circuits accept");
                assert_eq!(phi(&l5, payment6::statement_tag(tree)), l6, "{tree:?} {shape:?}: limbs under φ");
                // The account limbs V6 drops are zero in V5-ordinary.
                assert!(l5[127..136].iter().all(|l| *l == 0));
            }
        }
        // A V5-ordinary spend that is valid under V5 is valid under V6 with the same values.
        let (p5, w5) = payment5::fresh_shape(tree, Shape::Transfer, payment5::Mode::Ordinary, &mut StdRng::seed_from_u64(5));
        let w6 = Private { token: w5.token.clone(), inputs: w5.inputs.clone(), dummy: w5.dummy, outputs: w5.outputs.clone(), identity: w5.identity.clone() };
        let p6 = payment6::statement(
            tree, &p5.chain, &p5.pool, p5.deliveries.clone(), (p5.withdrawal_recipient.clone(), p5.withdrawal_amount), &p5.intent,
            p5.valid_until, &w6,
        )
        .expect("a V5-ordinary witness is a V6 witness");
        let (l5, _) = outputs5(tree, &p5, &w5);
        let (l6, ok6) = outputs(tree, &p6, &w6);
        assert!(ok6);
        assert_eq!(phi(&l5, payment6::statement_tag(tree)), l6);
    }
}

/// A single-input spend with its stored companion: the same dummy input gives the same nullifier
/// under V5-ordinary and V6 (the SDK's companion check reads it).
#[test]
fn companion_nullifier_is_version_independent() {
    let tree = Tree::Compress;
    let (p6, w6) = fresh_shape(tree, Shape::Single, &mut StdRng::seed_from_u64(47));
    let w5 = payment6::to_v5(&w6);
    let p5 = payment5::statement(
        tree, &p6.chain, &p6.pool, p6.deliveries.clone(), (p6.withdrawal_recipient.clone(), p6.withdrawal_amount), &p6.intent,
        p6.valid_until, &w5,
    )
    .unwrap();
    assert_eq!(p5.nullifiers[1], p6.nullifiers[1]);
    let context = [felt_limbs(&p6.chain), felt_limbs(&p6.pool), felt_limbs(&w6.token)].concat();
    let d = &w6.inputs[1];
    let (receiver, nk) = receiver_of(&d.sk);
    assert_eq!(p6.nullifiers[1], payment::nullifier(&nk, &commitment(&context, 0, &receiver, &d.rho), d.position));
    // V5's native key derivation for a zero account is V6's.
    assert_eq!(payment5::receiver_of(&[0; 9], &d.sk), receiver_of(&d.sk));
}

/// Identity handles (spec §4.3, rule 2): the handle is `H(IDENTITY, H(AUTH, sk₀) ‖ scope)`, not
/// V4's over `sk₀` nor a bound key; another key's handle differs; each attempt is itself a valid
/// spend (the ordinary part of V5's `identity_handles_follow_the_selected_key`).
#[test]
fn identity_handle_is_over_the_in_circuit_ak() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Shadow, &mut StdRng::seed_from_u64(50));
        let (sk0, scope) = (private.inputs[0].sk, private.identity.scope);
        assert_eq!(public.identity, identity_handle(&ak_of(&sk0), &scope));
        assert_eq!(public.identity, h(payment::IDENTITY, 0, &[h(payment::AUTH, 0, &sk0).as_slice(), &scope].concat()));
        assert_ne!(public.identity, payment::identity_handle(&sk0, &scope), "not V4's handle over sk₀");
        let bound = payment5::ak_of(&felt_limbs("0x54f2b25"), &sk0);
        assert_ne!(public.identity, identity_handle(&bound, &scope), "not a bound key's handle");
        // The attacker's own notes under another key: a valid spend with another handle.
        let mut other = private.clone();
        other.inputs[0].sk = std::array::from_fn(|k| (sk0[k] + 1) % P);
        let other = replant(tree, &public, other, 52);
        let q = redo(tree, &public, &other).expect("a valid spend of the attacker's own notes");
        let (limbs, valid) = outputs(tree, &q, &other);
        assert!(valid && limbs == statement_limbs(tree, &q), "{tree:?}");
        assert_ne!(q.identity, public.identity, "{tree:?}: another key reproduces the handle");
    }
}

/// The plant test (spec §4.4; a regression, re-check F8): a note deposited to
/// `H(OWNER, ak_v ‖ H(NK, sk_att))`, where `ak_v` is a victim's authorization key the attacker
/// knows (a full-viewing-key holder), spent with the honest V6 circuit and `sk_att`. The circuit
/// either fails or publishes neither that note's root nor the victim's handle.
#[test]
fn plant_test_victim_ak_is_not_usable() {
    for tree in TREES {
        for shape in [Shape::Shadow, Shape::Single] {
            let rng = &mut StdRng::seed_from_u64(80);
            let (public, private) = fresh_shape(tree, shape, rng);
            let sk_v: Digest = std::array::from_fn(|_| rng.gen_range(0..P));
            let ak_v = ak_of(&sk_v);
            // Plant input 0 (and 1, if real) under receivers with the victim's ak and the attacker's nk.
            let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&private.token)].concat();
            let real = if private.dummy { 1 } else { 2 };
            let leaves: Vec<(u32, Digest)> = private.inputs[..real]
                .iter()
                .map(|i| {
                    let nk = h(payment::NK, 0, &i.sk);
                    let receiver = h(payment::OWNER, 0, &[ak_v, nk].concat());
                    (i.position, commitment(&context, i.amount, &receiver, &i.rho))
                })
                .collect();
            let (planted_root, siblings) = sparse_paths(tree, &leaves, &mut StdRng::seed_from_u64(81));
            let mut p = private.clone();
            for (i, s) in p.inputs.iter_mut().zip(siblings) {
                i.siblings = s;
            }
            let victim_handle = identity_handle(&ak_v, &private.identity.scope);
            let (limbs, valid) = outputs(tree, &public, &p);
            let reaches = limbs[29..38] == planted_root;
            let handle = limbs[118..127] == victim_handle;
            assert!(!valid || (!reaches && !handle), "{tree:?} {shape:?}: the victim's ak was usable");
        }
    }
}

/// A spend of one note (input 0) with a dummy input 1: one real output of the whole amount and a
/// dummy output.
fn spend_of_note(tree: Tree, pool: &str, token: &str, sk: Digest, rho: Digest, amount: u128, seed: u64) -> (Public, Private) {
    let chain = "0x534e5f5345504f4c4941";
    let rng = &mut StdRng::seed_from_u64(seed);
    let digest = |rng: &mut StdRng| -> Digest { std::array::from_fn(|_| rng.gen_range(0..P)) };
    let context = [felt_limbs(chain), felt_limbs(pool), felt_limbs(token)].concat();
    let position = rng.next_u32();
    let leaf = commitment(&context, amount, &receiver_of(&sk).0, &rho);
    let (_, siblings) = sparse_paths(tree, &[(position, leaf)], rng);
    let dummy = Input { sk: digest(rng), rho: digest(rng), amount: 0, position: position ^ 1, siblings: (0..32).map(|_| digest(rng)).collect() };
    let private = Private {
        token: token.into(),
        inputs: [Input { sk, rho, amount, position, siblings: siblings[0].clone() }, dummy],
        dummy: true,
        outputs: [
            Output { receiver: digest(rng), rho: digest(rng), amount },
            Output { receiver: digest(rng), rho: digest(rng), amount: 0 },
        ],
        identity: Identity::default(),
    };
    let deliveries = ["0x11".to_string(), "0x13".to_string()];
    let public = payment6::statement(tree, chain, pool, deliveries, ("0x0".into(), 0), "0x0", 77, &private).expect("valid");
    (public, private)
}

/// A note one spend creates, another spend consumes.
#[test]
fn a_created_note_is_spendable() {
    let tree = Tree::Compress;
    let rng = &mut StdRng::seed_from_u64(48);
    let (public, mut private) = fresh_shape(tree, Shape::Transfer, rng);
    let sk2: Digest = std::array::from_fn(|_| rng.gen_range(0..P));
    private.outputs[0].receiver = receiver_of(&sk2).0;
    let public = redo(tree, &public, &private).expect("valid");
    let (limbs, valid) = outputs(tree, &public, &private);
    assert!(valid && limbs == statement_limbs(tree, &public));
    let o = &private.outputs[0];
    let (p2, w2) = spend_of_note(tree, &public.pool, &private.token, sk2, o.rho, o.amount, 49);
    let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&private.token)].concat();
    assert_eq!(commitment(&context, o.amount, &o.receiver, &o.rho), public.commitments[0]);
    let (limbs, valid) = outputs(tree, &p2, &w2);
    assert!(valid && limbs == statement_limbs(tree, &p2));
}

/// A V5 bound note (receiver over `WAUTH`) cannot be spent under V6 (spec §11.5, stranding).
#[test]
fn a_bound_note_is_not_spendable_under_v6() {
    for tree in TREES {
        let (p5, w5) = payment5::fresh_shape(tree, Shape::Single, payment5::Mode::Bound, &mut StdRng::seed_from_u64(56));
        let w6 = Private { token: w5.token.clone(), inputs: w5.inputs.clone(), dummy: w5.dummy, outputs: w5.outputs.clone(), identity: w5.identity.clone() };
        let p6 = payment6::statement(
            tree, &p5.chain, &p5.pool, p5.deliveries.clone(), (p5.withdrawal_recipient.clone(), p5.withdrawal_amount), &p5.intent,
            p5.valid_until, &w6,
        )
        .expect("the circuit rules admit the witness");
        let (limbs, valid) = outputs(tree, &p6, &w6);
        assert!(!valid || root_of(&limbs) != p5.root, "{tree:?}: a bound note proved under its real root");
    }
}

/// The encoding extremes: `valid_until = 1` and `2^56 − 1` (positive cases, spec §4.4).
#[test]
fn expiry_extremes() {
    for tree in TREES {
        for valid_until in [1, (1 << 56) - 1] {
            let (mut public, private) = fresh_shape(tree, Shape::Partial, &mut StdRng::seed_from_u64(53));
            public.valid_until = valid_until;
            let (limbs, valid) = outputs(tree, &public, &private);
            assert!(valid);
            assert_eq!(decode_statement(tree, &limbs), Ok(public.clone()));
        }
    }
}

/// Mutations an attacker wants proved: each must make the circuit invalid (V4's list, HA-IM1).
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

/// Mutations that change what is proved: the circuit either fails or publishes a different
/// statement, which the pool then rejects.
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
            let mut p = private.clone();
            p.inputs[0].sk[0] = (p.inputs[0].sk[0] + 1) % P;
            check("other spending key for input 0", p);
        }
    }
}

/// amount₀ = 0 on a consistent tree fails only the real-input nonzero check.
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

/// A zero spending key or zero randomness on either input, planted on a consistent tree, fails
/// only the input's nonzero check (hidden-asset-spec §4.3; the mutation table's "input sk / rho
/// nonzero deleted" rows).
#[test]
fn zero_input_key_or_randomness_fails_on_a_consistent_tree() {
    for tree in TREES {
        for input in 0..2 {
            for field in ["sk", "rho"] {
                let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(24));
                let mut control = private.clone();
                if field == "sk" {
                    control.inputs[input].sk = [1, 0, 0, 0, 0, 0, 0, 0, 0];
                } else {
                    control.inputs[input].rho = [1, 0, 0, 0, 0, 0, 0, 0, 0];
                }
                let control = replant(tree, &public, control, 25);
                assert!(outputs(tree, &public, &control).1, "{tree:?}: control {field}{input} = 1");
                let mut zero = private.clone();
                if field == "sk" {
                    zero.inputs[input].sk = [0; 9];
                } else {
                    zero.inputs[input].rho = [0; 9];
                }
                let zero = replant(tree, &public, zero, 25);
                assert!(!outputs(tree, &public, &zero).1, "{tree:?}: {field}{input} = 0 accepted");
            }
        }
    }
}

/// Input 1 committed under a different asset than input 0 cannot be spent with it.
#[test]
fn inputs_under_two_assets_are_rejected() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(13));
        let other = "0x5151";
        let ctx = |t: &str| [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(t)].concat();
        let leaf = |i: usize, t: &str| {
            let n = &private.inputs[i];
            (n.position, commitment(&ctx(t), n.amount, &receiver_of(&n.sk).0, &n.rho))
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

fn prime() -> &'static str {
    "800000000000011000000000000000000000000000000000000000000000001"
}

/// Statements the circuit proves but the bridge must reject (HA-IM3, F11): each is proved, then
/// decoded through the bridge mirror, which names the rule. Then decoder-only rules on raw limbs
/// (spec §4.4, new boundary tests): each padding limb nonzero, `valid_until = 0`, each
/// `valid_until` limb at 2^28, the tag, and every range rule.
#[test]
fn bridge_only_rules() {
    let tree = Tree::Compress;
    let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(21));
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
    pb.intent = format!("0x{}", prime());
    assert_eq!(decoded(&pb, &private), Err("non-canonical felt".into()));
    let mut pb = public.clone();
    pb.valid_until = 0;
    assert_eq!(decoded(&pb, &private), Err("valid_until".into()));
    // Decoder-only rules on raw limbs.
    let (limbs, _) = outputs(tree, &public, &private);
    let raw = |at: usize, v: u32| {
        let mut x = limbs.clone();
        x[at] = v;
        decode_statement(tree, &x)
    };
    for at in 129..132 {
        assert_eq!(raw(at, 1), Err("statement padding".into()), "padding limb {at}");
    }
    assert_eq!(raw(127, 1 << 28), Err("limb range".into()));
    assert_eq!(raw(128, 1 << 28), Err("limb range".into()));
    let mut zero = limbs.clone();
    zero[127] = 0;
    zero[128] = 0;
    assert_eq!(decode_statement(tree, &zero), Err("valid_until".into()));
    assert_eq!(raw(0, 0), Err("statement tag".into()));
    assert_eq!(raw(1, payment5::STATEMENT_TAG_COMPRESS[1]), Err("statement tag".into()), "V5's tag");
    assert_eq!(decode_statement(Tree::Sponge, &limbs), Err("statement tag".into()), "the sponge tag");
    assert_eq!(decode_statement(tree, &limbs[..128]), Err("output count".into()));
    for k in 101..109 {
        assert_eq!(raw(k, 1 << 16), Err("amount limb range".into()), "amount limb {k}");
    }
    let prime = felt_limbs(&format!("0x{}", prime()));
    for (name, at) in [("chain", 2), ("pool", 11), ("token_out", 20), ("delivery0", 65), ("delivery1", 83), ("recipient", 92), ("intent", 109)] {
        for l in 0..9 {
            assert_eq!(raw(at + l, 1 << 28), Err("limb range".into()), "{name} limb {l}");
        }
        let mut x = limbs.clone();
        x[at..at + 9].copy_from_slice(&prime);
        assert_eq!(decode_statement(tree, &x), Err("non-canonical felt".into()), "{name} = p");
    }
    for at in [29, 38, 56, 74, 118, 127] {
        assert_eq!(raw(at, P), Err("M31 range".into()), "word {at} at p");
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

/// The same leaf in both input slots yields equal nullifiers, which the bridge rejects.
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
    assert_eq!(payment6::bridge_checks(&native), Err("duplicate nullifier".into()));
    let (limbs, valid) = outputs(tree, &public, &p);
    assert!(valid, "the circuit admits it; the bridge and pool reject it");
    assert_eq!(limbs[38..47], limbs[47..56]);
}

/// The pinned circuit hash is the code's (F38): the R6 manifest the bridge build pins is recomputed
/// from the current relation. A change to any shared gadget that moves the hash fails here, before
/// a bridge is rebuilt. (Not counted as a mutation kill, spec §4.4.)
#[test]
fn pinned_circuit_hash_matches_the_code() {
    use templar_client_verifier_circuit::prove;
    let path = format!("{}/results/stwo-client-r6/trusted-config.json", env!("CARGO_MANIFEST_DIR"));
    let Ok(text) = std::fs::read_to_string(&path) else {
        panic!("{path} missing: run examples/prove_payment_r6 first");
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let recorded: Vec<u32> = v["circuit_hash_u32_le"].as_array().unwrap().iter().map(|w| w.as_u64().unwrap() as u32).collect();
    let (p6, w6) = fresh_shape(prove::TREE, Shape::Transfer, &mut StdRng::seed_from_u64(1));
    let h6 = prove::words(prove::prove(&prove::R6(&p6, &w6), [7; 32], None).unwrap().circuit_hash);
    assert_eq!(h6.to_vec(), recorded, "R6");
}
