//! Malicious hints against the R0 V5 circuit (`docs/account-bound-note-spec.md` §4.4): each case
//! overrides a hint the honest builder derives (feature `tamper`) and checks that the
//! constraints, not the hint code, reject it; and the load-bearing wiring (AB-M6) is checked on
//! the variables themselves.
use circuits::context::Context;
use rand::{SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{
    AUTH, CARRIES, Digest, NK, OWNER, P, Tree, amount_limbs, commitment, felt_limbs, h,
};
use templar_client_verifier_circuit::payment5::{
    Mode, N_OUTPUTS, Private, Public, Shape, TAMPER, Tamper, WAUTH, ak_of, build, decode_statement, fresh_shape,
    receiver_of, sparse_paths, statement, statement_limbs,
};

const TREES: [Tree; 2] = [Tree::Sponge, Tree::Compress];

fn run(tree: Tree, public: &Public, private: &Private, t: Tamper) -> (Vec<u32>, bool) {
    run_with(tree, public, private, t, None)
}

/// [`run`] with the conservation carries overridden (`payment::CARRIES`, one per limb boundary).
fn run_with(tree: Tree, public: &Public, private: &Private, t: Tamper, carries: Option<Vec<i64>>) -> (Vec<u32>, bool) {
    TAMPER.with(|x| *x.borrow_mut() = t);
    CARRIES.with(|x| *x.borrow_mut() = carries);
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, tree, public, private);
    TAMPER.with(|x| *x.borrow_mut() = Tamper::default());
    CARRIES.with(|x| *x.borrow_mut() = None);
    let limbs = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    (limbs, c.is_circuit_valid())
}

fn signed(a: u128) -> [i64; 8] {
    amount_limbs(a).map(|l| l as i64)
}

/// The carries conservation needs when the circuit's limb values are `ins` and `outs`, as signed
/// integers (a tampered limb may be negative or reach 2^16): `c_{k+1} = (Σ insₖ − Σ outsₖ + cₖ) / 2^16`.
/// Asserts the limbs balance exactly, so every limb equation holds.
fn integer_carries(ins: &[[i64; 8]], outs: &[[i64; 8]]) -> Vec<i64> {
    let mut carry = 0i64;
    let mut carries = vec![];
    for k in 0..8 {
        let d = ins.iter().map(|x| x[k]).sum::<i64>() - outs.iter().map(|x| x[k]).sum::<i64>() + carry;
        assert_eq!(d.rem_euclid(1 << 16), 0, "limb {k} does not balance");
        carry = d / (1 << 16);
        if k < 7 {
            carries.push(carry);
        }
    }
    assert_eq!(carry, 0, "the top limb does not balance");
    carries
}

/// Carries that satisfy every limb equation over M31 (not over the integers):
/// `c_{k+1} = (dₖ + cₖ) · 2^{−16} mod p`. The last equation holds iff the surplus is ≡ 0 mod p.
fn field_carries(ins: &[u128], outs: &[u128]) -> Vec<i64> {
    let p = P as u64;
    let pow = |mut b: u64, mut e: u64| {
        let mut r = 1;
        while e > 0 {
            if e & 1 == 1 {
                r = r * b % p;
            }
            b = b * b % p;
            e >>= 1;
        }
        r
    };
    let inv = pow(1 << 16, p - 2);
    let (li, lo): (Vec<_>, Vec<_>) = (ins.iter().map(|a| amount_limbs(*a)).collect(), outs.iter().map(|a| amount_limbs(*a)).collect());
    let mut carry = 0u64;
    let mut carries = vec![];
    for k in 0..7 {
        let d = (li.iter().map(|x| x[k] as u64).sum::<u64>() + 8 * p - lo.iter().map(|x| x[k] as u64).sum::<u64>()) % p;
        carry = (d + carry) % p * inv % p;
        carries.push(carry as i64);
    }
    carries
}

/// The honest bit hints of limb value `l`.
fn limb_bits(l: u32) -> [u32; 16] {
    std::array::from_fn(|k| (l >> k) & 1)
}

fn rejected(name: &str, tree: Tree, shape: Shape, mode: Mode, t: Tamper) {
    let (public, private) = fresh_shape(tree, shape, mode, &mut StdRng::seed_from_u64(31));
    let (_, honest) = run(tree, &public, &private, Tamper::default());
    assert!(honest, "{tree:?} {name}: the untampered witness must be valid");
    let (_, valid) = run(tree, &public, &private, t);
    assert!(!valid, "{tree:?} {mode:?} {name} accepted");
}

/// Plants the real inputs under receivers built from `ak = ak_fn(sk)`, so a witness whose keys
/// the circuit selects that way is consistent with the tree.
fn plant(tree: Tree, public: &Public, mut p: Private, ak_fn: impl Fn(&Digest) -> Digest) -> (Private, Digest) {
    let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&p.token)].concat();
    let real = if p.dummy { 1 } else { 2 };
    let leaves: Vec<(u32, Digest)> = p.inputs[..real]
        .iter()
        .map(|i| {
            let nk = h(NK, 0, &i.sk);
            let receiver = h(OWNER, 0, &[ak_fn(&i.sk), nk].concat());
            (i.position, commitment(&context, i.amount, &receiver, &i.rho))
        })
        .collect();
    let (root, siblings) = sparse_paths(tree, &leaves, &mut StdRng::seed_from_u64(60));
    for (i, s) in p.inputs.iter_mut().zip(siblings) {
        i.siblings = s;
    }
    (p, root)
}

#[test]
fn m_non_boolean() {
    for tree in TREES {
        for mode in [Mode::Ordinary, Mode::Bound] {
            rejected("m = 2", tree, Shape::Transfer, mode, Tamper { m: Some(2), ..Default::default() });
        }
    }
}

/// m = 1 with account = 0, isolated: the notes are planted under `H(WAUTH, 0 ‖ sk)` receivers, so
/// the select and the tree agree and only `nonzero_vector_if(account, m)` can reject it.
#[test]
fn m_one_with_zero_account_isolated() {
    for tree in TREES {
        for shape in [Shape::Transfer, Shape::Single] {
            let (public, private) = fresh_shape(tree, shape, Mode::Ordinary, &mut StdRng::seed_from_u64(61));
            let (p, root) = plant(tree, &public, private, |sk| h(WAUTH, 0, &[[0u32; 9].as_slice(), sk].concat()));
            let (limbs, valid) = run(tree, &public, &p, Tamper { m: Some(1), ..Default::default() });
            assert_eq!(limbs[29..38], root, "{tree:?} {shape:?}: the witness reaches the tree");
            assert!(!valid, "{tree:?} {shape:?}: m = 1 with account = 0 accepted");
        }
    }
}

/// m = 0 with account ≠ 0, isolated: ordinary notes, a published account, and m = 0 so the
/// select picks `H(AUTH, sk)`: only `accountₗ · (1 − m) = 0` can reject it.
#[test]
fn m_zero_with_account_isolated() {
    for tree in TREES {
        for shape in [Shape::Transfer, Shape::Single] {
            let (public, private) = fresh_shape(tree, shape, Mode::Bound, &mut StdRng::seed_from_u64(62));
            let (p, root) = plant(tree, &public, private, |sk| h(AUTH, 0, sk));
            let (limbs, valid) = run(tree, &public, &p, Tamper { m: Some(0), ..Default::default() });
            assert_eq!(limbs[29..38], root, "{tree:?} {shape:?}: the witness reaches the tree");
            assert!(!valid, "{tree:?} {shape:?}: m = 0 with account ≠ 0 accepted");
        }
    }
}

/// A bound spend with m forced to 0 (non-isolated) and an ordinary spend with m forced to 1.
#[test]
fn m_flipped() {
    for tree in TREES {
        rejected("m = 0 on a bound spend", tree, Shape::Single, Mode::Bound, Tamper { m: Some(0), ..Default::default() });
        rejected("m = 1 on an ordinary spend", tree, Shape::Single, Mode::Ordinary, Tamper { m: Some(1), ..Default::default() });
    }
}

/// The load-bearing wiring (AB-M6), checked on the variables: the published account limbs are the
/// words both WAUTH hashes read (S3); one `m` serves the mode rules and both selects; the identity
/// hash reads input 0's selected key, the same variables OWNER₀ reads (AB-M1). A mutant that
/// guesses a copy passes every value test, so only this catches it.
#[test]
fn wiring_uses_the_same_variables() {
    for tree in TREES {
        for mode in [Mode::Ordinary, Mode::Bound] {
            let (public, private) = fresh_shape(tree, Shape::Shadow, mode, &mut StdRng::seed_from_u64(63));
            let mut c = Context::<QM31>::new(N_OUTPUTS);
            build(&mut c, tree, &public, &private);
            let var = |name: &str| *c.debug_info.get(name).unwrap_or_else(|| panic!("{name} not recorded"));
            for k in 0..9 {
                let published = var(&format!("account.published.{k}"));
                assert_eq!(var(&format!("account.wauth0.{k}")), published, "WAUTH₀ word {k}");
                assert_eq!(var(&format!("account.wauth1.{k}")), published, "WAUTH₁ word {k}");
                assert_eq!(var(&format!("ak0.identity.{k}")), var(&format!("ak0.owner.{k}")), "identity key word {k}");
            }
            let m = var("mode.rules.0");
            assert_eq!(var("mode.select0.0"), m);
            assert_eq!(var("mode.select1.0"), m);
            // The mode rules read the published account (AB-IM3): m = 1 ⇔ published account ≠ 0.
            for k in 0..9 {
                assert_eq!(var(&format!("mode.account.{k}")), var(&format!("account.published.{k}")), "mode rules word {k}");
            }
        }
    }
}

/// Raw `account` limbs the honest encoder cannot produce (a limb at 2^28) are proved like any
/// other words; the bridge decoder rejects them.
#[test]
fn non_canonical_account_limbs_are_left_to_the_bridge() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(64));
        let mut raw = felt_limbs(&private.account);
        raw[0] = 1 << 28;
        let (p, root) = plant(tree, &public, private, |sk| wauth_ak(&raw, sk));
        let (limbs, valid) = run(tree, &public, &p, Tamper { account: Some(raw), ..Default::default() });
        assert!(valid, "{tree:?}: the circuit does not range-check the account");
        assert_eq!(limbs[29..38], root);
        assert_eq!(limbs[127..136], raw);
        assert_eq!(decode_statement(tree, &limbs), Err("limb range".into()));
    }
}

fn wauth_ak(account: &Digest, sk: &Digest) -> Digest {
    h(WAUTH, 0, &[account.as_slice(), sk].concat())
}

/// Raw `valid_until` limbs (a limb at 2^28) are proved verbatim; the bridge decoder rejects them.
#[test]
fn non_canonical_valid_until_limbs_are_left_to_the_bridge() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Partial, Mode::Bound, &mut StdRng::seed_from_u64(65));
        for raw in [[1 << 28, 0], [0, 1 << 28]] {
            let (limbs, valid) = run(tree, &public, &private, Tamper { valid_until: Some(raw), ..Default::default() });
            assert!(valid, "{tree:?}");
            assert_eq!(limbs[136..138], raw);
            assert_eq!(decode_statement(tree, &limbs), Err("limb range".into()));
        }
    }
}

#[test]
fn e1_non_boolean() {
    for tree in TREES {
        for mode in [Mode::Ordinary, Mode::Bound] {
            rejected("e1 = 2 on a dummy", tree, Shape::Single, mode, Tamper { e1: Some(2), ..Default::default() });
            rejected("e1 = 2 on a real input", tree, Shape::Transfer, mode, Tamper { e1: Some(2), ..Default::default() });
        }
    }
}

#[test]
fn e1_one_on_dummy_path_and_zero_on_real_input() {
    for tree in TREES {
        rejected("e1 = 1 on a dummy's random path", tree, Shape::Single, Mode::Bound, Tamper { e1: Some(1), ..Default::default() });
        rejected("e1 = 0 with amount₁ ≠ 0", tree, Shape::Transfer, Mode::Bound, Tamper { e1: Some(0), ..Default::default() });
    }
}

#[test]
fn x_zero_with_exit_and_non_boolean() {
    for tree in TREES {
        for (shape, name) in [(Shape::Partial, "a withdrawal"), (Shape::Full, "everything withdrawn"), (Shape::Invoke, "an intent")] {
            rejected(&format!("x = 0 with {name}"), tree, shape, Mode::Bound, Tamper { x: Some(0), ..Default::default() });
        }
        rejected("x = 2 with no exit", tree, Shape::Transfer, Mode::Bound, Tamper { x: Some(2), ..Default::default() });
    }
}

/// A voluntary reveal (x = 1 with neither withdrawal nor intent) satisfies the circuit; the
/// bridge decoder rejects it by the exit rule.
#[test]
fn voluntary_reveal_is_left_to_the_bridge() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, Mode::Bound, &mut StdRng::seed_from_u64(32));
        let (limbs, valid) = run(tree, &public, &private, Tamper { x: Some(1), ..Default::default() });
        assert!(valid, "{tree:?}");
        assert_ne!(limbs, statement_limbs(tree, &public));
        assert_eq!(limbs[20..29], felt_limbs(&private.token));
        assert_eq!(decode_statement(tree, &limbs), Err("exit rule".into()));
    }
}

/// Sanity for the planting helper: honest bound receivers equal `plant` with the WAUTH key.
#[test]
fn plant_matches_the_honest_receivers() {
    let (_, private) = fresh_shape(Tree::Compress, Shape::Single, Mode::Bound, &mut StdRng::seed_from_u64(66));
    let a = felt_limbs(&private.account);
    let sk = private.inputs[0].sk;
    assert_eq!(receiver_of(&a, &sk).0, h(OWNER, 0, &[wauth_ak(&a, &sk), h(NK, 0, &sk)].concat()));
}

// ---------------------------------------------------------------- F09: inflation-critical gadgets

/// Re-plants the real inputs under the witness's own bound receivers; returns the root.
fn replant(tree: Tree, public: &Public, p: Private) -> (Private, Digest) {
    let a = felt_limbs(&p.account);
    plant(tree, public, p, |sk| ak_of(&a, sk))
}

/// The carry range (AB-IM1): `in = 5`, `out = 5 + p`. Carries solving every limb equation over
/// M31 exist because the surplus is p; only `n(n−1)(n+1)(n+2) = 0` rejects them.
#[test]
fn carry_range_stops_a_mod_p_mint() {
    for tree in TREES {
        let (public, mut p) = fresh_shape(tree, Shape::Single, Mode::Bound, &mut StdRng::seed_from_u64(70));
        p.inputs[0].amount = 5;
        p.outputs[0].amount = 5 + P as u128;
        p.outputs[1].amount = 0;
        let (p, root) = replant(tree, &public, p);
        let carries = field_carries(&[5, 0], &[5 + P as u128, 0, 0]);
        let small = [0, 1, (P - 1) as i64, (P - 2) as i64];
        assert!(carries.iter().any(|c| !small.contains(c)), "some carry leaves {{−2..1}}");
        let (limbs, valid) = run_with(tree, &public, &p, Tamper::default(), Some(carries));
        assert_eq!(limbs[29..38], root, "{tree:?}: the witness reaches the tree");
        assert!(!valid, "{tree:?}: out = in + p accepted");
    }
}

/// Amount-bit booleanity (AB-IM1): output 1's limb 0 is −1 (bit₀ = p − 1) and output 0 gains one
/// unit. Every limb equation holds with in-range carries; only `b·(b − 1) = 0` rejects it.
#[test]
fn amount_bit_booleanity_stops_a_negative_limb() {
    for tree in TREES {
        let (public, mut p) = fresh_shape(tree, Shape::OneOut, Mode::Bound, &mut StdRng::seed_from_u64(71));
        let total = p.outputs[0].amount;
        p.outputs[0].amount = total + 1;
        let mut bits = [[0u32; 16]; 8];
        bits[0][0] = P - 1;
        let mut out1 = [0i64; 8];
        out1[0] = -1;
        let carries = integer_carries(&[signed(p.inputs[0].amount), signed(p.inputs[1].amount)], &[signed(total + 1), out1, [0; 8]]);
        let t = Tamper { amount_bits: Some((3, bits)), ..Default::default() };
        let (limbs, valid) = run_with(tree, &public, &p, t, Some(carries));
        assert_eq!(limbs[29..38], public.root, "{tree:?}: the witness reaches the tree");
        assert!(!valid, "{tree:?}: a negative output limb accepted");
    }
}

/// Input-1 limbs (p − 5, 5) on a dummy (AB-IM1): their sum is 0 mod p, so `sum₁·(1 − e₁) = 0`
/// holds with e₁ = 0, while the limbs carry 5·2^16 − 5 into conservation. Only booleanity rejects it.
#[test]
fn amount_bit_booleanity_stops_a_dummy_that_carries_value() {
    for tree in TREES {
        let (public, mut p) = fresh_shape(tree, Shape::Single, Mode::Bound, &mut StdRng::seed_from_u64(72));
        let minted = 5 * (1u128 << 16) - 5;
        p.outputs[0].amount += minted;
        let mut bits = [[0u32; 16]; 8];
        bits[0][0] = P - 5;
        bits[1] = limb_bits(5);
        let mut in1 = [0i64; 8];
        in1[0] = -5;
        in1[1] = 5;
        let carries = integer_carries(&[signed(p.inputs[0].amount), in1], &[signed(p.outputs[0].amount), signed(p.outputs[1].amount), [0; 8]]);
        let t = Tamper { amount_bits: Some((1, bits)), ..Default::default() };
        let (limbs, valid) = run_with(tree, &public, &p, t, Some(carries));
        assert_eq!(limbs[29..38], public.root, "{tree:?}: the witness reaches the tree");
        assert!(!valid, "{tree:?}: a dummy carrying 5·2^16 − 5 accepted");
    }
}

/// An output limb at 2^16 (bit₁₅ = 2), balanced by the other output: only booleanity rejects it.
#[test]
fn amount_bit_booleanity_stops_a_limb_at_2_16() {
    for tree in TREES {
        let (public, mut p) = fresh_shape(tree, Shape::OneOut, Mode::Bound, &mut StdRng::seed_from_u64(73));
        let total = p.outputs[0].amount;
        p.outputs[0].amount = total - (1 << 16);
        let mut bits = [[0u32; 16]; 8];
        bits[0][15] = 2;
        let mut out1 = [0i64; 8];
        out1[0] = 1 << 16;
        let carries = integer_carries(&[signed(p.inputs[0].amount), signed(p.inputs[1].amount)], &[signed(total - (1 << 16)), out1, [0; 8]]);
        let t = Tamper { amount_bits: Some((3, bits)), ..Default::default() };
        let (limbs, valid) = run_with(tree, &public, &p, t, Some(carries));
        assert_eq!(limbs[29..38], public.root, "{tree:?}: the witness reaches the tree");
        assert!(!valid, "{tree:?}: an output limb at 2^16 accepted");
    }
}

/// Position-bit booleanity (AB-IM1): with the level-0 sibling equal to the note itself, any bit
/// value leaves the path unchanged, and bit₀ = 2 gives the same note a second nullifier. Only
/// booleanity rejects it.
#[test]
fn position_bit_booleanity_stops_a_second_nullifier() {
    for tree in TREES {
        let (public, mut p) = fresh_shape(tree, Shape::Single, Mode::Bound, &mut StdRng::seed_from_u64(74));
        let a = felt_limbs(&p.account);
        let position = p.inputs[0].position & !1;
        let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&p.token)].concat();
        let i = &p.inputs[0];
        let cm = commitment(&context, i.amount, &receiver_of(&a, &i.sk).0, &i.rho);
        let (root, siblings) = sparse_paths(tree, &[(position, cm), (position | 1, cm)], &mut StdRng::seed_from_u64(75));
        p.inputs[0].position = position;
        p.inputs[0].siblings = siblings[0].clone();
        assert_eq!(siblings[0][0], cm, "the level-0 sibling is the note");
        let (honest, valid) = run(tree, &public, &p, Tamper::default());
        assert!(valid && honest[29..38] == root, "{tree:?}: control");
        let mut bits: [u32; 32] = std::array::from_fn(|k| (position >> k) & 1);
        bits[0] = 2;
        let (limbs, valid) = run(tree, &public, &p, Tamper { position_bits: Some((0, bits)), ..Default::default() });
        assert_eq!(limbs[29..38], root, "{tree:?}: the witness reaches the tree");
        assert_ne!(limbs[38..47], honest[38..47], "{tree:?}: a second nullifier for the same note");
        assert!(!valid, "{tree:?}: a non-boolean position bit accepted");
    }
}

/// A zero-budget invoke with x forced to 0 (AB-IM1): nothing is withdrawn, so only
/// `(1 − x)·intent = 0` rejects it.
#[test]
fn exit_bit_is_forced_by_an_intent_alone() {
    for tree in TREES {
        let (public, mut p) = fresh_shape(tree, Shape::Invoke, Mode::Bound, &mut StdRng::seed_from_u64(76));
        p.outputs[1].amount += public.withdrawal_amount;
        let public = statement(tree, &public.chain, &public.pool, public.deliveries.clone(), ("0x0".into(), 0), &public.intent, public.valid_until, &p)
            .expect("a zero-budget invoke");
        let (_, valid) = run(tree, &public, &p, Tamper::default());
        assert!(valid, "{tree:?}: control");
        let (_, valid) = run(tree, &public, &p, Tamper { x: Some(0), ..Default::default() });
        assert!(!valid, "{tree:?}: x = 0 with an intent and no withdrawal accepted");
    }
}

/// An identity flag of 2 (AB-IM1) publishes twice the handle; only booleanity rejects it.
#[test]
fn identity_flag_is_boolean() {
    for tree in TREES {
        rejected("identity flag 2", tree, Shape::Shadow, Mode::Bound, Tamper { identity_flag: Some(2), ..Default::default() });
        rejected("identity flag 2 without identity", tree, Shape::Invoke, Mode::Bound, Tamper { identity_flag: Some(2), ..Default::default() });
    }
}
