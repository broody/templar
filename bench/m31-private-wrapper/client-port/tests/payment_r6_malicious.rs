//! Malicious hints against the R0 V6 circuit (`docs/pool-v3-spec.md` §4.4): each case overrides a
//! hint the honest builder derives (feature `tamper`) and checks that the constraints, not the hint
//! code, reject it; and the wiring test (MR-V6-1) checks every fan-out and hash-output-to-consumer
//! edge on the variables themselves.
use circuits::context::Context;
use rand::{SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{
    CARRIES, Digest, NK, NODE1, OWNER, P, TAG, Tree, amount_limbs, commitment, felt_limbs, h,
};
use templar_client_verifier_circuit::payment6::{
    N_OUTPUTS, Private, Public, Shape, TAMPER, Tamper, ak_of, build, decode_statement, fresh_shape, receiver_of, sparse_paths,
    statement, statement_limbs, statement_tag,
};
use stwo::core::fields::m31::M31;

const TREES: [Tree; 2] = [Tree::Sponge, Tree::Compress];
const SHAPES: [Shape; 8] = [
    Shape::Transfer, Shape::Single, Shape::OneOut, Shape::Partial, Shape::Full, Shape::Invoke, Shape::Shadow, Shape::Nft,
];

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
/// integers: `c_{k+1} = (Σ insₖ − Σ outsₖ + cₖ) / 2^16`. Asserts the limbs balance exactly.
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

fn limb_bits(l: u32) -> [u32; 16] {
    std::array::from_fn(|k| (l >> k) & 1)
}

fn rejected(name: &str, tree: Tree, shape: Shape, t: Tamper) {
    let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(31));
    let (_, honest) = run(tree, &public, &private, Tamper::default());
    assert!(honest, "{tree:?} {name}: the untampered witness must be valid");
    let (_, valid) = run(tree, &public, &private, t);
    assert!(!valid, "{tree:?} {name} accepted");
}

/// Plants the real inputs under receivers built from `ak = ak_fn(sk)`.
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

// ---------------------------------------------------------------- the wiring test (MR-V6-1)

/// A circuit variable's id.
type Var = usize;

/// The recorded wires of one build.
struct Wires {
    info: std::collections::HashMap<String, Var>,
    /// The circuit's constants, by value.
    constants: std::collections::HashMap<QM31, Var>,
}

impl Wires {
    fn of(tree: Tree, public: &Public, private: &Private) -> Wires {
        let mut c = Context::<QM31>::new(N_OUTPUTS);
        build(&mut c, tree, public, private);
        assert!(c.is_circuit_valid());
        Wires {
            info: c.debug_info.iter().map(|(k, v)| (k.clone(), v.idx)).collect(),
            constants: c.constants().iter().map(|(k, v)| (*k, v.idx)).collect(),
        }
    }

    /// The `n` variables recorded under `name.0 … name.(n−1)`.
    fn get(&self, name: &str, n: usize) -> Vec<Var> {
        (0..n).map(|k| *self.info.get(&format!("{name}.{k}")).unwrap_or_else(|| panic!("{name}.{k} not recorded"))).collect()
    }

    /// The circuit's constant variable for `v`.
    fn constant(&self, v: u32) -> Var {
        *self.constants.get(&QM31::from(M31::from(v))).unwrap_or_else(|| panic!("no constant {v}"))
    }

    fn slice(&self, name: &str, from: usize, to: usize) -> Vec<Var> {
        self.get(name, to)[from..].to_vec()
    }
}

/// Asserts variable-id equality on one edge.
fn same(edge: &str, a: &[Var], b: &[Var]) {
    assert_eq!(a.len(), b.len(), "{edge}: lengths");
    assert_eq!(a, b, "{edge}: not the same variables");
}

/// The normative wiring test (spec §4.4): variable-id equality on every fan-out edge and every
/// hash-output-to-consumer edge, single-use ones included. A guessed copy of any recorded wire, on
/// the path to any of its consumers, fails here, whatever values it carries.
///
/// Payload layouts: `keys` = [AUTH(sk₀), NK(sk₀), AUTH(sk₁), NK(sk₁)]; `inner_out` = [INNER(recv_outⱼ
/// ‖ rho_outⱼ)]; `owners` = [OWNER(ak₀ ‖ nk₀), OWNER(ak₁ ‖ nk₁), IDENTITY(ak₀ ‖ scope)];
/// `inner_in` = [INNER(ownerᵢ ‖ rhoᵢ)]; `notes` = [NOTE(pub_ctx₁₈ ‖ token₉ ‖ amount₈ ‖ inner₉)] for
/// the two inputs then the two outputs; `nf` = [NF(nkᵢ ‖ cmᵢ ‖ lo ‖ hi)].
#[test]
fn wiring_uses_the_same_variables() {
    for tree in TREES {
        for shape in SHAPES {
            let (public, private) = fresh_shape(tree, shape, &mut StdRng::seed_from_u64(63));
            let w = Wires::of(tree, &public, &private);
            let auth = |i: usize| w.get(&format!("keys.{}.out", 2 * i), 9);
            let nk = |i: usize| w.get(&format!("keys.{}.out", 2 * i + 1), 9);
            // Identity: identity.ak == owner₀.ak == auth₀.out.
            same("identity.ak = owner0.ak", &w.slice("owners.2.in", 0, 9), &w.slice("owners.0.in", 0, 9));
            same("owner0.ak = auth0.out", &w.slice("owners.0.in", 0, 9), &auth(0));
            same("identity.ak = auth0.out", &w.slice("owners.2.in", 0, 9), &auth(0));
            same("identity handle = IDENTITY out", &w.get("identity.handle", 9), &w.get("owners.2.out", 9));
            for i in 0..2 {
                let sk = w.get(&format!("guess.sk{i}"), 9);
                // authᵢ.in == nkᵢ.in == the skᵢ guess.
                same(&format!("auth{i}.in = sk{i}"), &w.get(&format!("keys.{}.in", 2 * i), 9), &sk);
                same(&format!("nk{i}.in = sk{i}"), &w.get(&format!("keys.{}.in", 2 * i + 1), 9), &sk);
                // ownerᵢ.ak == authᵢ.out; ownerᵢ.nk == nfᵢ.nk == nkᵢ.out.
                same(&format!("owner{i}.ak = auth{i}.out"), &w.slice(&format!("owners.{i}.in"), 0, 9), &auth(i));
                same(&format!("owner{i}.nk = nk{i}.out"), &w.slice(&format!("owners.{i}.in"), 9, 18), &nk(i));
                same(&format!("nf{i}.nk = nk{i}.out"), &w.slice(&format!("nf.{i}.in"), 0, 9), &nk(i));
                // innerᵢ.recv == ownerᵢ.out; innerᵢ.rho == the rhoᵢ guess; noteᵢ.inner == innerᵢ.out.
                same(&format!("inner{i}.recv = owner{i}.out"), &w.slice(&format!("inner_in.{i}.in"), 0, 9), &w.get(&format!("owners.{i}.out"), 9));
                same(&format!("inner{i}.rho = rho{i}"), &w.slice(&format!("inner_in.{i}.in"), 9, 18), &w.get(&format!("guess.rho{i}"), 9));
                same(&format!("note{i}.inner = inner{i}.out"), &w.slice(&format!("notes.{i}.in"), 35, 44), &w.get(&format!("inner_in.{i}.out"), 9));
                // nfᵢ.cm == pathᵢ.leaf == noteᵢ.out.
                same(&format!("nf{i}.cm = note{i}.out"), &w.slice(&format!("nf.{i}.in"), 9, 18), &w.get(&format!("notes.{i}.out"), 9));
                same(&format!("path{i}.leaf = note{i}.out"), &w.get(&format!("path{i}.leaf"), 9), &w.get(&format!("notes.{i}.out"), 9));
                // NFᵢ's lo and hi are the pack outputs over the same bit variables as the path.
                let lohi = [w.get(&format!("pack{i}.lo.out"), 1), w.get(&format!("pack{i}.hi.out"), 1)].concat();
                same(&format!("nf{i}.lohi = pack{i}.out"), &w.slice(&format!("nf.{i}.in"), 18, 20), &lohi);
                let position = w.get(&format!("guess.position{i}"), 32);
                let packed = [w.get(&format!("pack{i}.lo.bits"), 16), w.get(&format!("pack{i}.hi.bits"), 16)].concat();
                same(&format!("pack{i}.bits = position{i}"), &packed, &position);
                let path_bits: Vec<Var> = (0..32).map(|l| w.get(&format!("path{i}.bit{l}"), 1)[0]).collect();
                same(&format!("path{i}.bits = position{i}"), &path_bits, &position);
                // Every membership hop: level 0 reads the note, each level reads the previous
                // level's output, and the root is the last output (NODE outputs, spec §4.4).
                same(&format!("path{i}.level0.in = note{i}.out"), &w.get(&format!("path{i}.level0.in"), 9), &w.get(&format!("notes.{i}.out"), 9));
                for l in 1..32 {
                    same(&format!("path{i}.level{l}.in = level{}.out", l - 1), &w.get(&format!("path{i}.level{l}.in"), 9), &w.get(&format!("path{i}.level{}.out", l - 1), 9));
                }
                same(&format!("path{i}.root = level31.out"), &w.get(&format!("path{i}.root"), 9), &w.get(&format!("path{i}.level31.out"), 9));
                // Each level's hash reads the request that level made (NF-M1), and is handed exactly
                // it, with the compress tree's domain constants [TAG, 1, NODE1, level] (ADV-RC-1, -3).
                for l in 0..32 {
                    let payload = w.get(&format!("path{i}.level{l}.payload"), 18);
                    same(&format!("path{i}.level{l}.payload = req"), &payload, &w.get(&format!("path{i}.level{l}.req"), 18));
                    let n = if tree == Tree::Compress { 22 } else { 18 };
                    let state = w.get(&format!("path{i}.level{l}.state"), n);
                    same(&format!("path{i}.level{l}.state = payload"), &state[..18], &payload);
                    if tree == Tree::Compress {
                        let domain: Vec<Var> = [TAG, 1, NODE1, l as u32].iter().map(|v| w.constant(*v)).collect();
                        same(&format!("path{i}.level{l}.state domain = constants"), &state[18..], &domain);
                    }
                }
            }
            // The NOTE amounts are the conservation amounts.
            same("note0.amount = conservation.in0", &w.slice("notes.0.in", 27, 35), &w.get("conservation.in0", 8));
            same("note1.amount = conservation.in1", &w.slice("notes.1.in", 27, 35), &w.get("conservation.in1", 8));
            same("note2.amount = conservation.out0", &w.slice("notes.2.in", 27, 35), &w.get("conservation.out0", 8));
            same("note3.amount = conservation.out1", &w.slice("notes.3.in", 27, 35), &w.get("conservation.out1", 8));
            same("conservation.in0 = amount.in0", &w.get("conservation.in0", 8), &w.get("amount.in0", 8));
            same("conservation.in1 = amount.in1", &w.get("conservation.in1", 8), &w.get("amount.in1", 8));
            same("conservation.out0 = amount.out0", &w.get("conservation.out0", 8), &w.get("amount.out0", 8));
            same("conservation.out1 = amount.out1", &w.get("conservation.out1", 8), &w.get("amount.out1", 8));
            for j in 0..2 {
                // The output notes: noteⱼ.inner == INNER(recv_outⱼ ‖ rho_outⱼ).out, over the guesses.
                same(&format!("note{}.inner = inner_out{j}.out", 2 + j), &w.slice(&format!("notes.{}.in", 2 + j), 35, 44), &w.get(&format!("inner_out.{j}.out"), 9));
                same(&format!("inner_out{j}.recv = recv_out{j}"), &w.slice(&format!("inner_out.{j}.in"), 0, 9), &w.get(&format!("guess.recv_out{j}"), 9));
                same(&format!("inner_out{j}.rho = rho_out{j}"), &w.slice(&format!("inner_out.{j}.in"), 9, 18), &w.get(&format!("guess.rho_out{j}"), 9));
            }
            // withdrawn: the same variable in conservation, the x gate and the published limbs.
            let withdrawn = w.get("amount.withdrawn", 8);
            same("conservation.withdrawn = withdrawn", &w.get("conservation.withdrawn", 8), &withdrawn);
            same("xgate.withdrawn = withdrawn", &w.get("xgate.withdrawn", 8), &withdrawn);
            same("published.withdrawn = withdrawn", &w.slice("published", 101, 109), &withdrawn);
            same("xgate.intent = published.intent", &w.get("xgate.intent", 9), &w.slice("published", 109, 118));
            // token: the same variable in all four NOTE contexts and in token_out.
            let token = w.get("guess.token", 9);
            for n in 0..4 {
                same(&format!("note{n}.token = token"), &w.slice(&format!("notes.{n}.in"), 18, 27), &token);
            }
            same("token_out.token = token", &w.get("token_out.token", 9), &token);
            // pub_ctx: the same variable in NOTE and in the published limbs.
            let pub_ctx = w.get("guess.pub_ctx", 18);
            for n in 0..4 {
                same(&format!("note{n}.pub_ctx = pub_ctx"), &w.slice(&format!("notes.{n}.in"), 0, 18), &pub_ctx);
            }
            same("published.pub_ctx = pub_ctx", &w.slice("published", 2, 20), &pub_ctx);
            // The published root is cur₀; the published nf and cm are the gate outputs.
            same("published.root = path0.root", &w.slice("published", 29, 38), &w.get("path0.root", 9));
            same("published.nf0 = nf0.out", &w.slice("published", 38, 47), &w.get("nf.0.out", 9));
            same("published.nf1 = nf1.out", &w.slice("published", 47, 56), &w.get("nf.1.out", 9));
            same("published.cm0 = note2.out", &w.slice("published", 56, 65), &w.get("notes.2.out", 9));
            same("published.cm1 = note3.out", &w.slice("published", 74, 83), &w.get("notes.3.out", 9));
            // The enabled-input gap compares the published root with input 1's own root.
            same("gap root = path0.root", &w.get("use.gap.root", 9), &w.get("path0.root", 9));
            same("gap other = path1.root", &w.get("use.gap.other", 9), &w.get("path1.root", 9));
            // A disabled input 1's sum is the one its amount limbs make, recorded where
            // `amount_from_bits` returns both (NF-M1).
            same("idle sum1 = amount.in1.sum", &w.get("use.idle.sum1", 1), &w.get("amount.in1.sum", 1));
            // The outputs are handed exactly the published limbs, then zero padding (ADV-RC-1).
            let chunks: Vec<Var> = (0..N_OUTPUTS).flat_map(|k| w.get(&format!("publish.chunk{k}"), 4)).collect();
            let published = w.get("published", 129);
            same("output chunks = published", &chunks[..129], &published);
            assert!(chunks[129..].iter().all(|v| *v == 0), "the padding is the zero variable");
            // The published tag limbs are the circuit's constants, never guesses (NF-M2).
            for (k, v) in statement_tag(tree).iter().enumerate() {
                assert_eq!(w.slice("published", k, k + 1)[0], w.constant(*v), "published tag limb {k} is not the constant");
            }
            // The published token_out and identity are the gate outputs.
            same("published.token_out = reveal out", &w.slice("published", 20, 29), &w.get("token_out.out", 9));
            same("published.identity = mask out", &w.slice("published", 118, 127), &w.get("identity.masked", 9));
            // One variable per bit guess at each of its uses.
            same("e1 idle = e1", &w.get("use.e1.idle", 1), &w.get("guess.e1", 1));
            same("e1 gap = e1", &w.get("use.e1.gap", 1), &w.get("guess.e1", 1));
            same("x hidden = x", &w.get("use.x.hidden", 1), &w.get("guess.x", 1));
            same("x token_out = x", &w.get("use.x.token_out", 1), &w.get("guess.x", 1));
            same("identity flag use = guess", &w.get("use.identity_flag", 1), &w.get("guess.identity_flag", 1));
            // Every hash digest variable is distinct from every guess (a digest is never a free word).
            let guesses: std::collections::HashSet<Var> =
                w.info.iter().filter(|(k, _)| k.starts_with("guess.")).map(|(_, v)| *v).collect();
            for (name, v) in &w.info {
                if name.contains(".out.") && !name.starts_with("pack") {
                    assert!(!guesses.contains(v), "{name} is a guessed variable");
                }
            }
        }
    }
}

// ---------------------------------------------------------------- bit and range hints

/// Raw `valid_until` limbs (a limb at 2^28) are proved verbatim; the bridge decoder rejects them.
#[test]
fn non_canonical_valid_until_limbs_are_left_to_the_bridge() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Partial, &mut StdRng::seed_from_u64(65));
        for raw in [[1 << 28, 0], [0, 1 << 28]] {
            let (limbs, valid) = run(tree, &public, &private, Tamper { valid_until: Some(raw), ..Default::default() });
            assert!(valid, "{tree:?}");
            assert_eq!(limbs[127..129], raw);
            assert_eq!(decode_statement(tree, &limbs), Err("limb range".into()));
        }
        let (limbs, valid) = run(tree, &public, &private, Tamper { valid_until: Some([0, 0]), ..Default::default() });
        assert!(valid, "{tree:?}: the circuit does not check valid_until ≠ 0");
        assert_eq!(decode_statement(tree, &limbs), Err("valid_until".into()));
    }
}

#[test]
fn e1_non_boolean() {
    for tree in TREES {
        rejected("e1 = 2 on a dummy", tree, Shape::Single, Tamper { e1: Some(2), ..Default::default() });
        rejected("e1 = 2 on a real input", tree, Shape::Transfer, Tamper { e1: Some(2), ..Default::default() });
    }
}

#[test]
fn e1_one_on_dummy_path_and_zero_on_real_input() {
    for tree in TREES {
        rejected("e1 = 1 on a dummy's random path", tree, Shape::Single, Tamper { e1: Some(1), ..Default::default() });
        rejected("e1 = 0 with amount₁ ≠ 0", tree, Shape::Transfer, Tamper { e1: Some(0), ..Default::default() });
    }
}

#[test]
fn x_zero_with_exit_and_non_boolean() {
    for tree in TREES {
        for (shape, name) in [(Shape::Partial, "a withdrawal"), (Shape::Full, "everything withdrawn"), (Shape::Invoke, "an intent")] {
            rejected(&format!("x = 0 with {name}"), tree, shape, Tamper { x: Some(0), ..Default::default() });
        }
        rejected("x = 2 with no exit", tree, Shape::Transfer, Tamper { x: Some(2), ..Default::default() });
    }
}

/// A voluntary reveal (x = 1 with neither withdrawal nor intent) satisfies the circuit; the
/// bridge decoder rejects it by the exit rule.
#[test]
fn voluntary_reveal_is_left_to_the_bridge() {
    for tree in TREES {
        let (public, private) = fresh_shape(tree, Shape::Transfer, &mut StdRng::seed_from_u64(32));
        let (limbs, valid) = run(tree, &public, &private, Tamper { x: Some(1), ..Default::default() });
        assert!(valid, "{tree:?}");
        assert_ne!(limbs, statement_limbs(tree, &public));
        assert_eq!(limbs[20..29], felt_limbs(&private.token));
        assert_eq!(decode_statement(tree, &limbs), Err("exit rule".into()));
    }
}

/// Sanity for the planting helper: honest receivers equal `plant` with the AUTH key.
#[test]
fn plant_matches_the_honest_receivers() {
    let (_, private) = fresh_shape(Tree::Compress, Shape::Single, &mut StdRng::seed_from_u64(66));
    let sk = private.inputs[0].sk;
    assert_eq!(receiver_of(&sk).0, h(OWNER, 0, &[ak_of(&sk), h(NK, 0, &sk)].concat()));
}

// ---------------------------------------------------------------- F09: inflation-critical gadgets

fn replant(tree: Tree, public: &Public, p: Private) -> (Private, Digest) {
    plant(tree, public, p, ak_of)
}

/// The carry range (AB-IM1): `in = 5`, `out = 5 + p`. Carries solving every limb equation over
/// M31 exist because the surplus is p; only `n(n−1)(n+1)(n+2) = 0` rejects them.
#[test]
fn carry_range_stops_a_mod_p_mint() {
    for tree in TREES {
        let (public, mut p) = fresh_shape(tree, Shape::Single, &mut StdRng::seed_from_u64(70));
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
        let (public, mut p) = fresh_shape(tree, Shape::OneOut, &mut StdRng::seed_from_u64(71));
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
        let (public, mut p) = fresh_shape(tree, Shape::Single, &mut StdRng::seed_from_u64(72));
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
        let (public, mut p) = fresh_shape(tree, Shape::OneOut, &mut StdRng::seed_from_u64(73));
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
        let (public, mut p) = fresh_shape(tree, Shape::Single, &mut StdRng::seed_from_u64(74));
        let position = p.inputs[0].position & !1;
        let context = [felt_limbs(&public.chain), felt_limbs(&public.pool), felt_limbs(&p.token)].concat();
        let i = &p.inputs[0];
        let cm = commitment(&context, i.amount, &receiver_of(&i.sk).0, &i.rho);
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
        let (public, mut p) = fresh_shape(tree, Shape::Invoke, &mut StdRng::seed_from_u64(76));
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
        rejected("identity flag 2", tree, Shape::Shadow, Tamper { identity_flag: Some(2), ..Default::default() });
        rejected("identity flag 2 without identity", tree, Shape::Invoke, Tamper { identity_flag: Some(2), ..Default::default() });
    }
}
