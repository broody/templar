//! Experimental R0 payment relation, V4 (`docs/hidden-asset-spec.md` §4): R0 V3 with a private
//! asset, a zero-value dummy second input and always-present outputs.
//!
//! Changes from V3 (`payment.rs`), all normative in the spec:
//!
//! - The asset (`token₉`) is a private witness shared by all four NOTE hashes and constrained
//!   nonzero. The statement publishes `token_out = x · token`, where the exit bit `x` is forced
//!   to 1 by any withdrawal or intent; the bridge rejects `x = 1` without either (voluntary
//!   reveal), so an in-pool transfer publishes `token_out = 0`.
//! - Input 0 is always real: nonzero amount, membership under the published root `cur₀`.
//!   Input 1 has an enable bit `e₁`: `sum₁ · (1 − e₁) = 0` on the same range-checked amount limbs
//!   that enter its commitment and conservation, and `e₁ · (cur₁ − cur₀) = 0` per word. A disabled
//!   input carries amount 0 on an arbitrary path; its nullifier is published like a real one.
//! - Both outputs always exist; an amount may be zero (a dummy output). There is no `active` flag,
//!   and commitments and delivery digests are published unmasked.
//!
//! Hashing, the note format, nullifiers, the identity handle and the conservation gadget are V3's.
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::IValue;
use circuits::ops::{eq, from_partial_evals};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use stwo::core::fields::m31::M31;

use crate::membership::{Lanes, compress_lanes};
use crate::merkle::guess_bits;
use crate::payment::{
    AUTH, DEPTH, Digest, IDENTITY, INNER, Identity, Input, NF, NK, NODE, NODE1, NOTE, OWNER, P, TAG,
    Tree, amount, amount_limbs, amount_unchecked, climb, commitment, conservation, felt_limbs, guess_words,
    hash_batch, identity_handle, node, nonzero_vector, nullifier, receiver_of,
};
use crate::ro::guess_m31;

pub use crate::payment::N_OUTPUTS;

/// Statement tag: `TMPZ`, `R0V4`.
pub const STATEMENT_TAG: [u32; 2] = [0x544d_505a, 0x5230_5634];
/// Statement tag for [`Tree::Compress`]: `TMPZ`, `R0C4`.
pub const STATEMENT_TAG_COMPRESS: [u32; 2] = [0x544d_505a, 0x5230_4334];

pub fn statement_tag(tree: Tree) -> [u32; 2] {
    match tree {
        Tree::Sponge => STATEMENT_TAG,
        Tree::Compress => STATEMENT_TAG_COMPRESS,
    }
}

/// An output slot. Always published; `amount` may be zero (a dummy output).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    pub receiver: Digest,
    pub rho: Digest,
    pub amount: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Private {
    /// The spend's asset identifier (`0x` hex felt), shared by every note of the spend.
    pub token: String,
    pub inputs: [Input; 2],
    /// Input 1 is a disabled dummy (`e₁ = 0`): its amount must be zero and its path is unchecked.
    pub dummy: bool,
    pub outputs: [Output; 2],
    #[serde(default)]
    pub identity: Identity,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Public {
    pub chain: String,
    pub pool: String,
    /// The asset on exit (a withdrawal or an intent); `0x0` for an in-pool transfer.
    pub token_out: String,
    pub root: Digest,
    pub nullifiers: [Digest; 2],
    pub commitments: [Digest; 2],
    /// Both nonzero.
    pub deliveries: [String; 2],
    /// `0x0` and 0 when there is no withdrawal; otherwise both nonzero.
    pub withdrawal_recipient: String,
    pub withdrawal_amount: u128,
    /// The open-note execution intent, `0x0` when the spend invokes nothing.
    pub intent: String,
    /// The identity handle, zero when unused.
    pub identity: Digest,
}

fn is_zero_felt(hex: &str) -> bool {
    felt_limbs(hex).iter().all(|l| *l == 0)
}

/// The 127 public limbs (padded with zeros to 128) in output order.
pub fn statement_limbs(tree: Tree, p: &Public) -> Vec<u32> {
    let mut x = statement_tag(tree).to_vec();
    x.extend(felt_limbs(&p.chain));
    x.extend(felt_limbs(&p.pool));
    x.extend(felt_limbs(&p.token_out));
    x.extend(p.root);
    x.extend(p.nullifiers.concat());
    for j in 0..2 {
        x.extend(p.commitments[j]);
        x.extend(felt_limbs(&p.deliveries[j]));
    }
    x.extend(felt_limbs(&p.withdrawal_recipient));
    x.extend(amount_limbs(p.withdrawal_amount));
    x.extend(felt_limbs(&p.intent));
    x.extend(p.identity);
    x.resize(4 * N_OUTPUTS, 0);
    x
}

// ---------------------------------------------------------------- native reference

/// The public statement the circuit proves for a witness, or an error naming the first witness
/// rule the circuit rejects. The circuit also admits statements the bridge rejects (duplicate
/// nullifiers, zero delivery digests, a recipient without an amount, an identity without an
/// intent, a voluntary asset reveal, out-of-range addresses): a spend is valid only if
/// [`bridge_checks`] also accepts its statement.
pub fn statement(
    tree: Tree,
    chain: &str,
    pool: &str,
    deliveries: [String; 2],
    withdrawal: (String, u128),
    intent: &str,
    w: &Private,
) -> Result<Public, String> {
    let nonzero = |d: &Digest| d.iter().any(|v| *v != 0);
    let canonical = |d: &Digest| d.iter().all(|v| *v < P);
    if is_zero_felt(&w.token) {
        return Err("zero asset".into());
    }
    let context = [felt_limbs(chain), felt_limbs(pool), felt_limbs(&w.token)].concat();
    let mut roots = vec![];
    let mut nullifiers = vec![];
    for (k, i) in w.inputs.iter().enumerate() {
        if !nonzero(&i.sk) || !nonzero(&i.rho) || !canonical(&i.sk) || !canonical(&i.rho) || i.siblings.len() != DEPTH {
            return Err("input encoding".into());
        }
        if k == 0 && i.amount == 0 {
            return Err("zero input".into());
        }
        let (receiver, nk) = receiver_of(&i.sk);
        let cm = commitment(&context, i.amount, &receiver, &i.rho);
        roots.push(climb(tree, &cm, i.position, &i.siblings));
        nullifiers.push(nullifier(&nk, &cm, i.position));
    }
    if w.dummy {
        if w.inputs[1].amount != 0 {
            return Err("dummy input carries value".into());
        }
    } else if roots[0] != roots[1] {
        return Err("inputs under different roots".into());
    }
    let mut commitments = vec![];
    for o in &w.outputs {
        if !nonzero(&o.receiver) || !nonzero(&o.rho) || !canonical(&o.receiver) || !canonical(&o.rho) {
            return Err("output encoding".into());
        }
        commitments.push(commitment(&context, o.amount, &o.receiver, &o.rho));
    }
    let w_amount = &withdrawal.1;
    let has_intent = !is_zero_felt(intent);
    if !canonical(&w.identity.scope) {
        return Err("identity encoding".into());
    }
    let identity = if w.identity.active { identity_handle(&w.inputs[0].sk, &w.identity.scope) } else { [0; 9] };
    let wide = |xs: &[u128]| xs.iter().fold((0u128, 0u128), |(hi, lo), x| {
        let (l, carry) = lo.overflowing_add(*x);
        (hi + carry as u128, l)
    });
    if wide(&[w.inputs[0].amount, w.inputs[1].amount]) != wide(&[w.outputs[0].amount, w.outputs[1].amount, *w_amount]) {
        return Err("conservation".into());
    }
    let exit = *w_amount != 0 || has_intent;
    Ok(Public {
        chain: chain.into(),
        pool: pool.into(),
        token_out: if exit { w.token.clone() } else { "0x0".into() },
        root: roots[0],
        nullifiers: [nullifiers[0], nullifiers[1]],
        commitments: [commitments[0], commitments[1]],
        deliveries,
        withdrawal_recipient: withdrawal.0,
        withdrawal_amount: withdrawal.1,
        intent: intent.into(),
        identity,
    })
}

/// A `0x` hex felt below 2^251.
fn below_2_251(hex: &str) -> bool {
    let digits = hex.trim_start_matches("0x").trim_start_matches('0');
    digits.len() < 63 || (digits.len() == 63 && digits.chars().next().unwrap().to_digit(16).unwrap() < 8)
}

/// The R0 V4 bridge's own checks on a decoded statement (spec §4.5), which the circuit does not
/// enforce: nonzero context, addresses and the asset below 2^251, nonzero distinct nullifiers,
/// nonzero commitments and delivery digests, recipient ⇔ amount, the exit rule (no voluntary
/// reveal) and identity ⇒ intent. Mirrors `cairo-r4/bridge/src/lib.cairo`.
pub fn bridge_checks(p: &Public) -> Result<(), String> {
    let nonzero = |d: &Digest| d.iter().any(|v| *v != 0);
    if is_zero_felt(&p.chain) || is_zero_felt(&p.pool) {
        return Err("zero context".into());
    }
    if !below_2_251(&p.pool) || !below_2_251(&p.token_out) || !below_2_251(&p.withdrawal_recipient) {
        return Err("address range".into());
    }
    if !nonzero(&p.nullifiers[0]) || !nonzero(&p.nullifiers[1]) {
        return Err("zero digest".into());
    }
    if p.nullifiers[0] == p.nullifiers[1] {
        return Err("duplicate nullifier".into());
    }
    if !nonzero(&p.commitments[0]) || !nonzero(&p.commitments[1]) {
        return Err("zero commitment".into());
    }
    if p.deliveries.iter().any(|d| is_zero_felt(d)) {
        return Err("delivery".into());
    }
    if !is_zero_felt(&p.withdrawal_recipient) != (p.withdrawal_amount != 0) {
        return Err("withdrawal".into());
    }
    let exits = p.withdrawal_amount != 0 || !is_zero_felt(&p.intent);
    if !is_zero_felt(&p.token_out) != exits {
        return Err("exit rule".into());
    }
    if nonzero(&p.identity) && is_zero_felt(&p.intent) {
        return Err("identity intent".into());
    }
    Ok(())
}

/// What a fresh test spend looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Two real inputs, two real outputs, nothing leaves the pool.
    Transfer,
    /// One real input and a dummy; two real outputs.
    Single,
    /// Two real inputs; one real output and a dummy output.
    OneOut,
    /// Change, a dummy output and a withdrawal.
    Partial,
    /// Two dummy outputs; everything is withdrawn.
    Full,
    /// Change, a dummy output and an adapter budget under an intent.
    Invoke,
    /// [`Shape::Invoke`] with a shadow-account identity handle.
    Shadow,
    /// A single ERC721-style note of amount 1, moved in the pool: one real input, a dummy, one
    /// output of 1 and a dummy output.
    Nft,
}

/// Siblings for `leaves` placed at their positions in one sparse depth-32 tree whose other
/// subtrees are random, and the resulting root.
pub fn sparse_paths(tree: Tree, leaves: &[(u32, Digest)], rng: &mut impl RngCore) -> (Digest, Vec<Vec<Digest>>) {
    let digest = |rng: &mut dyn RngCore| -> Digest { std::array::from_fn(|_| rng.gen_range(0..P)) };
    let mut known: Vec<(u64, Digest)> = leaves.iter().map(|(p, d)| (*p as u64, *d)).collect();
    let mut index: Vec<u64> = leaves.iter().map(|(p, _)| *p as u64).collect();
    let mut siblings = vec![vec![]; leaves.len()];
    for level in 0..DEPTH {
        let mut fillers: Vec<(u64, Digest)> = vec![];
        for i in 0..leaves.len() {
            let sib = index[i] ^ 1;
            let s = match known.iter().chain(&fillers).find(|(k, _)| *k == sib) {
                Some((_, d)) => *d,
                None => {
                    let d = digest(rng);
                    fillers.push((sib, d));
                    d
                }
            };
            siblings[i].push(s);
        }
        known.extend(fillers);
        let mut parents: Vec<(u64, Digest)> = vec![];
        for idx in &index {
            let parent = idx >> 1;
            if parents.iter().any(|(k, _)| *k == parent) {
                continue;
            }
            let get = |k: u64| known.iter().find(|(j, _)| *j == k).unwrap().1;
            let (l, r) = (get(parent << 1), get((parent << 1) | 1));
            parents.push((parent, node(tree, level as u32, &l, &r)));
        }
        known = parents;
        index.iter_mut().for_each(|i| *i >>= 1);
    }
    (known[0].1, siblings)
}

/// A fresh random V4 spend of `shape` under a random asset.
pub fn fresh_shape(tree: Tree, shape: Shape, rng: &mut impl RngCore) -> (Public, Private) {
    let chain = "0x534e5f5345504f4c4941";
    let pool = format!("0x{:x}", rng.gen_range(1u64..u64::MAX));
    // A hashed identifier just below 2^251 half the time, a small address otherwise.
    let token = if rng.gen_bool(0.5) {
        format!("0x7{:062x}", rng.gen_range(1u64..u64::MAX))
    } else {
        format!("0x{:x}", rng.gen_range(1u64..u64::MAX))
    };
    let context = [felt_limbs(chain), felt_limbs(&pool), felt_limbs(&token)].concat();
    let digest = |rng: &mut dyn RngCore| -> Digest { std::array::from_fn(|_| rng.gen_range(0..P)) };
    let single = matches!(shape, Shape::Single | Shape::Nft);
    let sks = [digest(rng), digest(rng)];
    let rhos = [digest(rng), digest(rng)];
    let amounts = match shape {
        Shape::Nft => [1, 0],
        Shape::Single => [rng.gen_range(2..u128::MAX / 4), 0],
        _ => [rng.gen_range(2..u128::MAX / 4), rng.gen_range(1..u128::MAX / 4)],
    };
    let mut positions = [rng.next_u32(), rng.next_u32()];
    while positions[1] == positions[0] {
        positions[1] = rng.next_u32();
    }
    let leaves: Vec<Digest> = (0..2)
        .map(|i| commitment(&context, amounts[i], &receiver_of(&sks[i]).0, &rhos[i]))
        .collect();
    let real = if single { 1 } else { 2 };
    let placed: Vec<(u32, Digest)> = (0..real).map(|i| (positions[i], leaves[i])).collect();
    let (_, mut siblings) = sparse_paths(tree, &placed, rng);
    if single {
        // The dummy's path is random: membership is not checked for it.
        siblings.push((0..DEPTH).map(|_| digest(rng)).collect());
    }
    let total = amounts[0] + amounts[1];
    let (out, withdrawn) = match shape {
        Shape::Transfer | Shape::Single => {
            let out0 = rng.gen_range(1..total);
            ([out0, total - out0], 0)
        }
        Shape::OneOut => ([total, 0], 0),
        Shape::Partial | Shape::Invoke | Shape::Shadow => {
            let out0 = rng.gen_range(1..total);
            ([out0, 0], total - out0)
        }
        Shape::Full => ([0, 0], total),
        Shape::Nft => ([1, 0], 0),
    };
    let private = Private {
        token,
        inputs: std::array::from_fn(|i| Input {
            sk: sks[i],
            rho: rhos[i],
            amount: amounts[i],
            position: positions[i],
            siblings: siblings[i].clone(),
        }),
        dummy: single,
        outputs: std::array::from_fn(|j| Output { receiver: digest(rng), rho: digest(rng), amount: out[j] }),
        identity: Identity { active: shape == Shape::Shadow, scope: if shape == Shape::Shadow { digest(rng) } else { [0; 9] } },
    };
    let deliveries: [String; 2] = std::array::from_fn(|_| format!("0x{:x}", rng.next_u64() | 1));
    let withdrawal = if withdrawn != 0 {
        (format!("0x{:x}", rng.gen_range(1u64..u64::MAX)), withdrawn)
    } else {
        ("0x0".to_string(), 0)
    };
    let intent = match shape {
        Shape::Invoke | Shape::Shadow => format!("0x{:x}", rng.gen_range(1u64..u64::MAX)),
        _ => "0x0".to_string(),
    };
    let public = statement(tree, chain, &pool, deliveries, withdrawal, &intent, &private).expect("fresh witness is valid");
    bridge_checks(&public).expect("fresh statement passes the bridge");
    (public, private)
}

// ---------------------------------------------------------------- circuit

/// Test-only overrides of the enable and exit bits' hint values (feature `tamper`), so tests can
/// show that the constraints, not the hint code, reject non-boolean or inconsistent bits.
#[derive(Clone, Debug, Default)]
pub struct Tamper {
    pub e1: Option<u32>,
    pub x: Option<u32>,
}

thread_local! {
    pub static TAMPER: std::cell::RefCell<Tamper> = std::cell::RefCell::new(Tamper::default());
}

fn tamper() -> Tamper {
    if cfg!(feature = "tamper") { TAMPER.with(|t| t.borrow().clone()) } else { Tamper::default() }
}

/// A guessed bit: `b·(b − 1) = 0` (as [`guess_bits`] with one bit, but from a raw hint value).
fn bit<V: IValue>(c: &mut Context<V>, value: u32) -> Var {
    let b = guess_m31(c, value);
    let zero = c.zero();
    let boolean = eval!(c, (b) * ((b) - (1)));
    eq(c, boolean, zero);
    b
}

fn assert_zero<V: IValue>(c: &mut Context<V>, v: Var) {
    let zero = c.zero();
    eq(c, v, zero);
}

/// Builds R0 V4 and returns the 32 output variables (the public statement).
pub fn build<V: Lanes>(c: &mut Context<V>, tree: Tree, public: &Public, w: &Private) -> Vec<Var> {
    let t = tamper();
    let tag: Vec<Var> = statement_tag(tree).iter().map(|v| c.constant(M31::from(*v).into())).collect();
    let pub_ctx = guess_words(c, &[felt_limbs(&public.chain), felt_limbs(&public.pool)].concat());
    // The single private asset witness, nonzero; shared by all four commitments.
    let token_values = felt_limbs(&w.token);
    let token = guess_words(c, &token_values);
    nonzero_vector(c, &token, &token_values);
    let context = [pub_ctx.clone(), token.clone()].concat();
    // Inputs: keys, randomness and positions as V3.
    let mut sk = vec![];
    let mut rho = vec![];
    let mut bits = vec![];
    for i in &w.inputs {
        let s = guess_words(c, &i.sk);
        nonzero_vector(c, &s, &i.sk);
        let r = guess_words(c, &i.rho);
        nonzero_vector(c, &r, &i.rho);
        sk.push(s);
        rho.push(r);
        bits.push(guess_bits(c, i.position as usize, DEPTH as u32));
    }
    // Input 0 is real: range-checked, nonzero amount. Input 1: range-checked limbs and their sum;
    // a disabled input (e₁ = 0) has sum 0, hence amount 0. The same limbs enter cm₁ and
    // conservation below.
    let amt0 = amount(c, w.inputs[0].amount);
    let (amt1, sum1) = amount_unchecked(c, w.inputs[1].amount);
    let e1 = bit(c, t.e1.unwrap_or(!w.dummy as u32));
    let idle = eval!(c, (sum1) * ((1) - (e1)));
    assert_zero(c, idle);
    // Outputs: always present, nonzero receiver and rho, range-checked amount that may be zero.
    let mut recv_out = vec![];
    let mut rho_out = vec![];
    let mut amt_out = vec![];
    for o in &w.outputs {
        let r = guess_words(c, &o.receiver);
        nonzero_vector(c, &r, &o.receiver);
        let q = guess_words(c, &o.rho);
        nonzero_vector(c, &q, &o.rho);
        let (amt, sum) = amount_unchecked(c, o.amount);
        c.mark_as_maybe_unused(&sum);
        recv_out.push(r);
        rho_out.push(q);
        amt_out.push(amt);
    }
    let keys = hash_batch(c, vec![(AUTH, 0, sk[0].clone()), (NK, 0, sk[0].clone()), (AUTH, 0, sk[1].clone()), (NK, 0, sk[1].clone())]);
    let (nk0, nk1) = (keys[1].clone(), keys[3].clone());
    let b = hash_batch(c, vec![
        (OWNER, 0, [keys[0].clone(), keys[1].clone()].concat()),
        (OWNER, 0, [keys[2].clone(), keys[3].clone()].concat()),
        (INNER, 0, [recv_out[0].clone(), rho_out[0].clone()].concat()),
        (INNER, 0, [recv_out[1].clone(), rho_out[1].clone()].concat()),
    ]);
    let inner_in = hash_batch(c, vec![
        (INNER, 0, [b[0].clone(), rho[0].clone()].concat()),
        (INNER, 0, [b[1].clone(), rho[1].clone()].concat()),
    ]);
    let note = |ctxv: &[Var], amt: &[Var], inner: &[Var]| (NOTE, 0, [ctxv.to_vec(), amt.to_vec(), inner.to_vec()].concat());
    let cms = hash_batch(c, vec![
        note(&context, &amt0, &inner_in[0]),
        note(&context, &amt1, &inner_in[1]),
        note(&context, &amt_out[0], &b[2]),
        note(&context, &amt_out[1], &b[3]),
    ]);
    // Both membership paths, level by level, as V3.
    let mut cur = [cms[0].clone(), cms[1].clone()];
    for level in 0..DEPTH {
        let mut reqs = vec![];
        for p in 0..2 {
            let sib = guess_words(c, &w.inputs[p].siblings[level]);
            let bit = bits[p][level];
            let mut left = vec![];
            let mut right = vec![];
            for (x, y) in cur[p].iter().zip(&sib) {
                let (x, y) = (*x, *y);
                let d = eval!(c, (bit) * ((y) - (x)));
                left.push(eval!(c, (x) + (d)));
                right.push(eval!(c, (y) - (d)));
            }
            reqs.push((level as u32, [left, right].concat()));
        }
        let next = match tree {
            Tree::Sponge => hash_batch(c, reqs.into_iter().map(|(l, x)| (NODE, l, x)).collect()),
            Tree::Compress => {
                let states = reqs
                    .into_iter()
                    .map(|(l, x)| {
                        let mut st = x;
                        st.extend([TAG, 1, NODE1, l].iter().map(|v| c.constant(M31::from(*v).into())));
                        st
                    })
                    .collect::<Vec<_>>();
                compress_lanes(c, &states)
            }
        };
        cur = [next[0].clone(), next[1].clone()];
    }
    // cur₀ is the published root; an enabled input 1 must reach it.
    for (a, b) in cur[0].clone().into_iter().zip(cur[1].clone()) {
        let gap = eval!(c, (e1) * ((b) - (a)));
        assert_zero(c, gap);
    }
    let pack = |c: &mut Context<V>, bits: &[Var]| {
        let mut v = c.zero();
        for (k, b) in bits.iter().enumerate() {
            let w = c.constant(M31::from(1u32 << k).into());
            v = eval!(c, (v) + ((*b) * (w)));
        }
        v
    };
    let mut nf_reqs = vec![];
    for (p, nk) in [nk0, nk1].into_iter().enumerate() {
        let lo = pack(c, &bits[p][..16]);
        let hi = pack(c, &bits[p][16..]);
        nf_reqs.push((NF, 0, [nk, cms[p].clone(), vec![lo, hi]].concat()));
    }
    let nfs = hash_batch(c, nf_reqs).concat();
    // Outputs, unmasked; delivery digests carried (the bridge requires them nonzero).
    let mut outs: Vec<Var> = vec![];
    for j in 0..2 {
        outs.extend(cms[2 + j].clone());
        outs.extend(guess_words(c, &felt_limbs(&public.deliveries[j])));
    }
    let recipient = guess_words(c, &felt_limbs(&public.withdrawal_recipient));
    let (withdrawn, withdrawn_sum) = amount_unchecked(c, public.withdrawal_amount);
    c.mark_as_maybe_unused(&withdrawn_sum);
    conservation(
        c,
        &[&amt0, &amt1],
        &[&amt_out[0], &amt_out[1], &withdrawn],
        &[w.inputs[0].amount, w.inputs[1].amount],
        &[w.outputs[0].amount, w.outputs[1].amount, public.withdrawal_amount],
    );
    let intent = guess_words(c, &felt_limbs(&public.intent));
    // Exit reveal: any withdrawal or intent forces x = 1, and token_out = x · token.
    let exit = public.withdrawal_amount != 0 || !is_zero_felt(&public.intent);
    let x = bit(c, t.x.unwrap_or(exit as u32));
    for l in withdrawn.iter().chain(&intent) {
        let l = *l;
        let hidden = eval!(c, (l) * ((1) - (x)));
        assert_zero(c, hidden);
    }
    let token_out: Vec<Var> = token.iter().map(|l| eval!(c, (*l) * (x))).collect();
    let id_active = guess_bits(c, w.identity.active as usize, 1)[0];
    let scope = guess_words(c, &w.identity.scope);
    let handle = hash_batch(c, vec![(IDENTITY, 0, [sk[0].clone(), scope].concat())]).concat();
    let identity: Vec<Var> = handle.into_iter().map(|word| eval!(c, (word) * (id_active))).collect();
    let zero = c.zero();
    let mut limbs: Vec<Var> =
        [tag, pub_ctx, token_out, cur[0].clone(), nfs, outs, recipient, withdrawn, intent, identity].concat();
    limbs.resize(4 * N_OUTPUTS, zero);
    limbs.chunks_exact(4).map(|q| from_partial_evals(c, q.try_into().unwrap())).collect()
}
