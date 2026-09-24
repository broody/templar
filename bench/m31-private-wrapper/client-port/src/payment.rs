//! Experimental R0 payment relation (V3): two ordinary inputs, up to two ordinary outputs, one
//! public token, one optional public withdrawal, an optional open-note execution intent and an
//! optional shadow-account identity handle; depth-32 membership (`bench/m31-statement/privacy-contract.md` §2–3), over
//! Poseidon2-M31 with 9-word digests. It mirrors the accepted ordinary statement
//! (`controlled-push-e2e/cairo/src/statement.cairo`) with controller/policy fields zero. It is
//! a **resource-measurement format**: domains, encodings and identifiers are not a reviewed
//! production suite.
//!
//! Every hash is `H(kind, level, payload) = sponge([TAG, 1, kind, level] ++ payload)[..9]`:
//!
//! - `ak = H(AUTH, sk)`, `nk = H(NK, sk)`, `receiver = H(OWNER, ak ‖ nk)`
//! - `inner = H(INNER, receiver ‖ rho)`
//! - `cm = H(NOTE, chain₉ ‖ pool₉ ‖ token₉ ‖ amount₈ ‖ inner)`
//! - `node = H(NODE, level, left ‖ right)` ([`Tree::Sponge`], two permutations per node), or
//!   `node = P(left ++ right ++ [TAG, 1, NODE1, level, 0, 0])[..9]` ([`Tree::Compress`]:
//!   one truncated permutation per node, as Plonky3's Merkle compression; an **experimental
//!   format variant** pending its own review)
//! - `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`
//! - `handle = H(IDENTITY, sk₀ ‖ scope)` (V3): a pseudonymous per-application identity handle
//!   derived from the first input's spending key and a private scope; published only when the
//!   private identity flag is set, otherwise zero
//!
//! Felts (chain, pool, token, delivery digests) are nine 28-bit little-endian limbs; amounts are
//! eight 16-bit little-endian limbs, each range-checked by bits. Private checks: nonzero `sk`,
//! `rho`, `receiver` and amounts, both paths reaching one root, and
//! `in₀ + in₁ = out₀ + out₁` as integers. Distinct nullifiers are checked publicly (as the pool
//! does when it marks them spent).
//!
//! The public statement is 127 limbs (padded to 128), emitted as 32 QM31 outputs (four limbs
//! each): tag (2), chain, pool, token, root, nf₀, nf₁, cm_out₀, delivery₀, cm_out₁, delivery₁,
//! withdrawal recipient (9 each), withdrawal amount (8), intent (9), identity handle (9).
//!
//! V3 adds `intent` and the identity handle. The circuit carries `intent` verbatim: it is a
//! Poseidon felt the pool recomputes over the open-note execution (adapter, calldata, budget
//! and its recipient, expiry, destinations), so binding it here makes the spend authorize
//! exactly that execution. The budget is the withdrawal and may be zero.
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::IValue;
use circuits::ops::{eq, from_partial_evals};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use stwo::core::fields::m31::M31;

use crate::hash::WIDTH;
use crate::membership::{Lanes, compress_lanes, permute, sponge_lanes};
use crate::merkle::guess_bits;
use crate::ro::guess_m31;

pub const P: u32 = (1 << 31) - 1;
/// Frame tag `TMR0`.
pub const TAG: u32 = 0x544d_5230;
/// Statement tag: `TMPZ`, `R0V3` (V3: V2's optional outputs and withdrawal slot, plus the
/// execution intent and identity handle).
pub const STATEMENT_TAG: [u32; 2] = [0x544d_505a, 0x5230_5633];
/// Statement tag for [`Tree::Compress`]: `TMPZ`, `R0C3`, so the two tree formats never share a
/// statement encoding (binding review L1).
pub const STATEMENT_TAG_COMPRESS: [u32; 2] = [0x544d_505a, 0x5230_4333];

/// The statement tag of a tree format.
pub fn statement_tag(tree: Tree) -> [u32; 2] {
    match tree {
        Tree::Sponge => STATEMENT_TAG,
        Tree::Compress => STATEMENT_TAG_COMPRESS,
    }
}
pub const DEPTH: usize = 32;
pub const N_OUTPUTS: usize = 32;
const LIMB_BITS: usize = 28;
const AMOUNT_LIMBS: usize = 8;

pub const AUTH: u32 = 1;
pub const NK: u32 = 2;
pub const OWNER: u32 = 3;
pub const INNER: u32 = 4;
pub const NOTE: u32 = 5;
pub const NODE: u32 = 6;
/// Node kind for [`Tree::Compress`], distinct from every sponge-mode kind.
pub const NODE1: u32 = 8;
/// Identity-handle kind (V3).
pub const IDENTITY: u32 = 9;

/// How tree nodes are hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tree {
    /// `H(NODE, level, left ‖ right)`: the framed rate-15 sponge, two permutations.
    Sponge,
    /// One width-24 permutation over `[left, right, TAG, 1, NODE1, level, 0, 0]`, truncated to
    /// nine words. The six fixed words sit in the sponge's capacity positions (18..24), so a
    /// node input can equal a later sponge block only if six capacity words match (math review
    /// M1); first sponge blocks have zero capacity and `TAG ≠ 0`.
    Compress,
}
pub const NF: u32 = 7;

pub type Digest = [u32; 9];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Input {
    pub sk: Digest,
    pub rho: Digest,
    pub amount: u128,
    pub position: u32,
    pub siblings: Vec<Digest>,
}

/// An output slot. An inactive slot creates no note: its public commitment and delivery digest
/// are zero and its amount must be zero.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    pub active: bool,
    pub receiver: Digest,
    pub rho: Digest,
    pub amount: u128,
}

/// The optional shadow-account identity: when `active`, the statement publishes
/// `H(IDENTITY, sk₀ ‖ scope)`; `scope` is private (a wallet derives it per application).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Identity {
    pub active: bool,
    pub scope: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Private {
    pub inputs: [Input; 2],
    pub outputs: [Output; 2],
    #[serde(default)]
    pub identity: Identity,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Public {
    pub chain: String,
    pub pool: String,
    pub token: String,
    pub root: Digest,
    pub nullifiers: [Digest; 2],
    /// Zero for an inactive output slot.
    pub commitments: [Digest; 2],
    /// `0x0` for an inactive output slot.
    pub deliveries: [String; 2],
    /// The public withdrawal: `0x0` and 0 when there is none; otherwise both nonzero.
    pub withdrawal_recipient: String,
    pub withdrawal_amount: u128,
    /// The open-note execution intent (a felt), `0x0` when the spend invokes nothing. With an
    /// intent, the withdrawal (possibly zero) is the execution's input budget.
    pub intent: String,
    /// The identity handle, zero when unused.
    pub identity: Digest,
}

// ---------------------------------------------------------------- encodings

/// A felt given as `0x` hex, as nine 28-bit little-endian limbs.
pub fn felt_limbs(hex: &str) -> [u32; 9] {
    let digits = hex.strip_prefix("0x").expect("0x hex");
    let nibbles: Vec<u32> = digits.chars().rev().map(|c| c.to_digit(16).expect("hex digit")).collect();
    assert!(nibbles.len() <= 63, "felt exceeds 252 bits");
    let bit = |k: usize| nibbles.get(k / 4).map_or(0, |n| (n >> (k % 4)) & 1);
    std::array::from_fn(|l| (0..LIMB_BITS).map(|b| bit(l * LIMB_BITS + b) << b).sum())
}

pub fn amount_limbs(a: u128) -> [u32; AMOUNT_LIMBS] {
    std::array::from_fn(|k| ((a >> (16 * k)) & 0xffff) as u32)
}

fn context_limbs(p: &Public) -> Vec<u32> {
    [felt_limbs(&p.chain), felt_limbs(&p.pool), felt_limbs(&p.token)].concat()
}

/// The 127 public limbs (padded with zeros to 128) in output order.
pub fn statement_limbs(tree: Tree, p: &Public) -> Vec<u32> {
    let mut x = statement_tag(tree).to_vec();
    x.extend(context_limbs(p));
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

fn frame(kind: u32, level: u32, payload: &[u32]) -> Vec<u32> {
    let mut x = vec![TAG, 1, kind, level];
    x.extend_from_slice(payload);
    x
}

/// The circuit's sponge (`membership::sponge`), natively.
fn native_sponge(message: &[u32]) -> [M31; WIDTH] {
    let m: Vec<M31> = message.iter().map(|v| M31::from(*v)).collect();
    let mut state = [M31::from(0); WIDTH];
    let mut offset = 0;
    loop {
        let n = (m.len() - offset).min(15);
        state[..n].copy_from_slice(&m[offset..offset + n]);
        offset += n;
        let done = offset == m.len();
        if n < 15 {
            state[n] = M31::from(1);
            for s in &mut state[n + 1..15] {
                *s = M31::from(0);
            }
        } else if done {
            state[15] += M31::from(1);
        }
        state = permute(state);
        if done {
            return state;
        }
    }
}

pub fn h(kind: u32, level: u32, payload: &[u32]) -> Digest {
    let s = native_sponge(&frame(kind, level, payload));
    std::array::from_fn(|i| s[i].0)
}

fn cat(parts: &[&[u32]]) -> Vec<u32> {
    parts.concat()
}

pub fn receiver_of(sk: &Digest) -> (Digest, Digest) {
    let ak = h(AUTH, 0, sk);
    let nk = h(NK, 0, sk);
    (h(OWNER, 0, &cat(&[&ak, &nk])), nk)
}

pub fn commitment(context: &[u32], amount: u128, receiver: &Digest, rho: &Digest) -> Digest {
    let inner = h(INNER, 0, &cat(&[receiver, rho]));
    h(NOTE, 0, &cat(&[context, &amount_limbs(amount), &inner]))
}

/// A tree node at `level` from its two children.
pub fn node(tree: Tree, level: u32, l: &Digest, r: &Digest) -> Digest {
    match tree {
        Tree::Sponge => h(NODE, level, &cat(&[l, r])),
        Tree::Compress => {
            let mut state = [M31::from(0); WIDTH];
            for (i, v) in l.iter().chain(r).chain(&[TAG, 1, NODE1, level]).enumerate() {
                state[i] = M31::from(*v);
            }
            let out = permute(state);
            std::array::from_fn(|i| out[i].0)
        }
    }
}

pub fn climb(tree: Tree, leaf: &Digest, position: u32, siblings: &[Digest]) -> Digest {
    let mut cur = *leaf;
    for (level, sib) in siblings.iter().enumerate() {
        let (l, r) = if (position >> level) & 1 == 0 { (cur, *sib) } else { (*sib, cur) };
        cur = node(tree, level as u32, &l, &r);
    }
    cur
}

pub fn nullifier(nk: &Digest, cm: &Digest, position: u32) -> Digest {
    h(NF, 0, &cat(&[nk, cm, &[position & 0xffff, position >> 16]]))
}

/// The identity handle for a spending key and a private scope.
pub fn identity_handle(sk: &Digest, scope: &Digest) -> Digest {
    h(IDENTITY, 0, &cat(&[sk, scope]))
}

/// The public statement a valid witness proves, or an error naming the first broken rule.
pub fn statement(
    tree: Tree,
    chain: &str,
    pool: &str,
    token: &str,
    deliveries: [String; 2],
    withdrawal: (String, u128),
    intent: &str,
    w: &Private,
) -> Result<Public, String> {
    let context = [felt_limbs(chain), felt_limbs(pool), felt_limbs(token)].concat();
    let nonzero = |d: &Digest| d.iter().any(|v| *v != 0);
    let mut roots = vec![];
    let mut nullifiers = vec![];
    for i in &w.inputs {
        if !nonzero(&i.sk) || !nonzero(&i.rho) || i.amount == 0 {
            return Err("zero input".into());
        }
        if i.siblings.len() != DEPTH || i.sk.iter().chain(&i.rho).any(|v| *v >= P) {
            return Err("input encoding".into());
        }
        let (receiver, nk) = receiver_of(&i.sk);
        let cm = commitment(&context, i.amount, &receiver, &i.rho);
        roots.push(climb(tree, &cm, i.position, &i.siblings));
        nullifiers.push(nullifier(&nk, &cm, i.position));
    }
    if roots[0] != roots[1] {
        return Err("inputs under different roots".into());
    }
    if nullifiers[0] == nullifiers[1] {
        return Err("duplicate input".into());
    }
    let mut commitments = vec![];
    for (o, d) in w.outputs.iter().zip(&deliveries) {
        if o.active {
            if !nonzero(&o.receiver) || !nonzero(&o.rho) || o.amount == 0 {
                return Err("zero output".into());
            }
            commitments.push(commitment(&context, o.amount, &o.receiver, &o.rho));
        } else {
            if o.amount != 0 || felt_limbs(d).iter().any(|l| *l != 0) {
                return Err("inactive output carries value".into());
            }
            commitments.push([0; 9]);
        }
    }
    let (recipient, w_amount) = &withdrawal;
    let has_recipient = felt_limbs(recipient).iter().any(|l| *l != 0);
    if has_recipient != (*w_amount != 0) {
        return Err("withdrawal recipient and amount".into());
    }
    if !w.outputs.iter().any(|o| o.active) && *w_amount == 0 {
        return Err("no output".into());
    }
    // An intent may carry a zero budget (a collect-only invoke); the pool checks the budget
    // recipient against the intent.
    let has_intent = felt_limbs(intent).iter().any(|l| *l != 0);
    if w.identity.active && !has_intent {
        return Err("identity without an intent".into());
    }
    if w.identity.scope.iter().any(|v| *v >= P) {
        return Err("identity encoding".into());
    }
    let identity = if w.identity.active { identity_handle(&w.inputs[0].sk, &w.identity.scope) } else { [0; 9] };
    // u128 amounts; the sums are compared as integers (up to 130 bits).
    let wide = |xs: &[u128]| xs.iter().fold((0u128, 0u128), |(hi, lo), x| {
        let (l, carry) = lo.overflowing_add(*x);
        (hi + carry as u128, l)
    });
    if wide(&[w.inputs[0].amount, w.inputs[1].amount]) != wide(&[w.outputs[0].amount, w.outputs[1].amount, *w_amount]) {
        return Err("conservation".into());
    }
    Ok(Public {
        chain: chain.into(),
        pool: pool.into(),
        token: token.into(),
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

/// Which output slots are active and whether there is a withdrawal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Two new notes, nothing leaves the pool.
    Transfer,
    /// One new note (change) and a withdrawal.
    Partial,
    /// No new note; everything is withdrawn.
    Full,
    /// Change and an adapter budget under an open-note execution intent (V3).
    Invoke,
    /// [`Shape::Invoke`] with a shadow-account identity handle (V3).
    Shadow,
}

/// A fresh random R0 transfer (see [`fresh_shape`]).
pub fn fresh(tree: Tree, rng: &mut impl RngCore) -> (Public, Private) {
    fresh_shape(tree, Shape::Transfer, rng)
}

/// A fresh random R0 payment: two notes at independent positions of one sparse depth-32 tree
/// (the paths share nodes only where they meet), spent into the outputs and withdrawal of
/// `shape`.
pub fn fresh_shape(tree: Tree, shape: Shape, rng: &mut impl RngCore) -> (Public, Private) {
    let chain = "0x534e5f5345504f4c4941";
    let pool = format!("0x{:x}", rng.gen_range(1u64..u64::MAX));
    let token = format!("0x{:x}", rng.gen_range(1u64..u64::MAX));
    let context = [felt_limbs(chain), felt_limbs(&pool), felt_limbs(&token)].concat();
    let digest = |rng: &mut dyn RngCore| -> Digest { std::array::from_fn(|_| rng.gen_range(0..P)) };
    let sks = [digest(rng), digest(rng)];
    let rhos = [digest(rng), digest(rng)];
    let amounts = [rng.gen_range(1..u128::MAX / 4), rng.gen_range(1..u128::MAX / 4)];
    let mut positions = [rng.next_u32(), rng.next_u32()];
    while positions[1] == positions[0] {
        positions[1] = rng.next_u32();
    }
    let leaves: Vec<Digest> = (0..2)
        .map(|i| commitment(&context, amounts[i], &receiver_of(&sks[i]).0, &rhos[i]))
        .collect();
    // Sparse tree: known nodes per level; missing siblings are random subtrees.
    let mut known: Vec<(u64, Digest)> = (0..2).map(|i| (positions[i] as u64, leaves[i])).collect();
    let mut siblings = vec![vec![], vec![]];
    let mut index: Vec<u64> = positions.iter().map(|p| *p as u64).collect();
    for level in 0..DEPTH {
        let mut fillers: Vec<(u64, Digest)> = vec![];
        for i in 0..2 {
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
        for i in 0..2 {
            let parent = index[i] >> 1;
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
    let total = amounts[0] + amounts[1];
    let (out, withdrawn) = match shape {
        Shape::Transfer => {
            let out0 = rng.gen_range(1..total);
            ([out0, total - out0], 0)
        }
        Shape::Partial => {
            let out0 = rng.gen_range(1..total);
            ([out0, 0], total - out0)
        }
        Shape::Full => ([0, 0], total),
        Shape::Invoke | Shape::Shadow => {
            let out0 = rng.gen_range(1..total);
            ([out0, 0], total - out0)
        }
    };
    let private = Private {
        inputs: std::array::from_fn(|i| Input {
            sk: sks[i],
            rho: rhos[i],
            amount: amounts[i],
            position: positions[i],
            siblings: siblings[i].clone(),
        }),
        outputs: std::array::from_fn(|j| Output {
            active: out[j] != 0,
            receiver: digest(rng),
            rho: digest(rng),
            amount: out[j],
        }),
        identity: Identity { active: shape == Shape::Shadow, scope: if shape == Shape::Shadow { digest(rng) } else { [0; 9] } },
    };
    let deliveries: [String; 2] = std::array::from_fn(|j| {
        if out[j] != 0 { format!("0x{:x}", rng.next_u64() | 1) } else { "0x0".to_string() }
    });
    let withdrawal = if withdrawn != 0 {
        (format!("0x{:x}", rng.gen_range(1u64..u64::MAX)), withdrawn)
    } else {
        ("0x0".to_string(), 0)
    };
    let intent = match shape {
        Shape::Invoke | Shape::Shadow => format!("0x{:x}", rng.gen_range(1u64..u64::MAX)),
        _ => "0x0".to_string(),
    };
    let public = statement(tree, chain, &pool, &token, deliveries, withdrawal, &intent, &private).expect("fresh witness is valid");
    (public, private)
}

// ---------------------------------------------------------------- circuit

pub(crate) fn guess_words<V: IValue>(c: &mut Context<V>, words: &[u32]) -> Vec<Var> {
    words.iter().map(|w| guess_m31(c, *w)).collect()
}

/// Asserts `v ≠ 0` with a witness inverse.
pub(crate) fn nonzero<V: IValue>(c: &mut Context<V>, v: Var, value: u32) {
    let inv = if value == 0 { 0 } else { M31::from(value).inverse().0 };
    let inv = guess_m31(c, inv);
    let one = c.one();
    let prod = eval!(c, (v) * (inv));
    eq(c, prod, one);
}

/// `v · inv = active`, with `active` boolean: `v ≠ 0` when active, no constraint on `v` otherwise.
pub(crate) fn nonzero_if<V: IValue>(c: &mut Context<V>, v: Var, value: u32, active: (Var, bool)) {
    let inv = if active.1 && value != 0 { M31::from(value).inverse().0 } else { 0 };
    let inv = guess_m31(c, inv);
    let prod = eval!(c, (v) * (inv));
    eq(c, prod, active.0);
}

/// [`nonzero_vector`] when `active` (an output slot's flag); no constraint otherwise.
pub(crate) fn nonzero_vector_if<V: IValue>(c: &mut Context<V>, words: &[Var], values: &[u32], active: (Var, bool)) {
    let k = values.iter().position(|v| *v != 0).unwrap_or(0);
    let bits: Vec<Var> = (0..words.len()).map(|i| guess_bits(c, (i == k) as usize, 1)[0]).collect();
    let mut sum_bits = c.zero();
    let mut picked = c.zero();
    for (b, w) in bits.iter().zip(words) {
        sum_bits = eval!(c, (sum_bits) + (*b));
        picked = eval!(c, (picked) + ((*b) * (*w)));
    }
    let one = c.one();
    eq(c, sum_bits, one);
    nonzero_if(c, picked, values[k], active);
}

/// Asserts some word of `words` is nonzero: a one-hot selector picks it, then [`nonzero`].
pub(crate) fn nonzero_vector<V: IValue>(c: &mut Context<V>, words: &[Var], values: &[u32]) {
    let k = values.iter().position(|v| *v != 0).unwrap_or(0);
    let bits: Vec<Var> = (0..words.len()).map(|i| guess_bits(c, (i == k) as usize, 1)[0]).collect();
    let mut sum_bits = c.zero();
    let mut picked = c.zero();
    for (b, w) in bits.iter().zip(words) {
        sum_bits = eval!(c, (sum_bits) + (*b));
        picked = eval!(c, (picked) + ((*b) * (*w)));
    }
    let one = c.one();
    eq(c, sum_bits, one);
    nonzero(c, picked, values[k]);
}

/// A u128 amount as eight range-checked 16-bit limbs; asserts it is nonzero.
pub(crate) fn amount<V: IValue>(c: &mut Context<V>, a: u128) -> Vec<Var> {
    let (vars, sum) = amount_unchecked(c, a);
    // Eight limbs below 2^16 sum below 2^19, so the sum is zero only if every limb is.
    let s: u32 = amount_limbs(a).iter().sum();
    nonzero(c, sum, s);
    vars
}

/// A u128 amount as eight range-checked 16-bit limbs and their sum (zero iff the amount is).
pub(crate) fn amount_unchecked<V: IValue>(c: &mut Context<V>, a: u128) -> (Vec<Var>, Var) {
    let limbs = amount_limbs(a);
    let mut vars = vec![];
    let mut sum = c.zero();
    for l in limbs {
        let bits = guess_bits(c, l as usize, 16);
        let mut v = c.zero();
        for (k, b) in bits.iter().enumerate() {
            let w = c.constant(M31::from(1u32 << k).into());
            v = eval!(c, (v) + ((*b) * (w)));
        }
        sum = eval!(c, (sum) + (v));
        vars.push(v);
    }
    (vars, sum)
}

thread_local! {
    /// Test-only carry overrides for [`conservation`] (feature `tamper`); never read otherwise.
    pub static CARRIES: std::cell::RefCell<Option<Vec<i64>>> = const { std::cell::RefCell::new(None) };
}

/// `Σ ins = Σ outs` over the integers (two inputs; outputs and withdrawal), limb by limb. Each
/// limb difference lies in (-3·2^16, 2·2^16), so the signed carries lie in {-2, -1, 0, 1}.
pub(crate) fn conservation<V: IValue>(c: &mut Context<V>, ins: &[&[Var]], outs: &[&[Var]], in_values: &[u128], out_values: &[u128]) {
    let shift = c.constant(M31::from(1u32 << 16).into());
    let li: Vec<[u32; AMOUNT_LIMBS]> = in_values.iter().map(|a| amount_limbs(*a)).collect();
    let lo: Vec<[u32; AMOUNT_LIMBS]> = out_values.iter().map(|a| amount_limbs(*a)).collect();
    let mut carry = c.zero();
    let mut carry_value: i64 = 0;
    for k in 0..AMOUNT_LIMBS {
        let mut d = c.zero();
        let mut dv = carry_value;
        for (x, l) in ins.iter().zip(&li) {
            let x = x[k];
            d = eval!(c, (d) + (x));
            dv += l[k] as i64;
        }
        for (x, l) in outs.iter().zip(&lo) {
            let x = x[k];
            d = eval!(c, (d) - (x));
            dv -= l[k] as i64;
        }
        // An invalid witness gets some carry anyway, and the constraint below fails.
        let honest = dv.div_euclid(1 << 16).clamp(-2, 1);
        let next_value = if cfg!(feature = "tamper") {
            CARRIES.with(|cc| cc.borrow().as_ref().map(|v| v[k.min(v.len() - 1)])).unwrap_or(honest)
        } else {
            honest
        };
        let next = if k + 1 == AMOUNT_LIMBS {
            c.zero()
        } else {
            let enc = if next_value < 0 { P - (-next_value) as u32 } else { next_value as u32 };
            let n = guess_m31(c, enc);
            // n ∈ {-2, -1, 0, 1}: n·(n - 1)·(n + 1)·(n + 2) = 0.
            let t = eval!(c, (((n) * ((n) - (1))) * ((n) + (1))) * ((n) + (2)));
            let zero = c.zero();
            eq(c, t, zero);
            n
        };
        let lhs = eval!(c, (d) + (carry));
        let rhs = eval!(c, (next) * (shift));
        eq(c, lhs, rhs);
        carry = next;
        carry_value = next_value;
    }
}

/// Hashes independent requests of equal framed length, four per lane-packed sponge
/// (`membership::sponge_lanes`); returns each request's digest in order.
pub(crate) fn hash_batch<V: Lanes>(c: &mut Context<V>, requests: Vec<(u32, u32, Vec<Var>)>) -> Vec<Vec<Var>> {
    let messages: Vec<Vec<Var>> = requests
        .into_iter()
        .map(|(kind, level, payload)| {
            let mut x: Vec<Var> = [TAG, 1, kind, level].iter().map(|v| c.constant(M31::from(*v).into())).collect();
            x.extend(payload);
            x
        })
        .collect();
    messages.chunks(4).flat_map(|group| sponge_lanes(c, group)).collect()
}

/// Builds R0 and returns the 32 output variables (the public statement). Hashes run four to a
/// row where they are independent, two along the membership paths.
pub fn build<V: Lanes>(c: &mut Context<V>, tree: Tree, public: &Public, w: &Private) -> Vec<Var> {
    let tag: Vec<Var> = statement_tag(tree).iter().map(|t| c.constant(M31::from(*t).into())).collect();
    let context = guess_words(c, &context_limbs(public));
    // Private inputs, with their nonzero and range checks.
    let mut sk = vec![];
    let mut rho = vec![];
    let mut amt_in = vec![];
    let mut bits = vec![];
    for i in &w.inputs {
        let s = guess_words(c, &i.sk);
        nonzero_vector(c, &s, &i.sk);
        let r = guess_words(c, &i.rho);
        nonzero_vector(c, &r, &i.rho);
        sk.push(s);
        rho.push(r);
        amt_in.push(amount(c, i.amount));
        bits.push(guess_bits(c, i.position as usize, DEPTH as u32));
    }
    let mut recv_out = vec![];
    let mut rho_out = vec![];
    let mut amt_out = vec![];
    let mut active = vec![];
    for o in &w.outputs {
        // The slot flag: active outputs need nonzero receiver, rho and amount; inactive ones
        // need zero amount (below) and publish zeros.
        let a = guess_bits(c, o.active as usize, 1)[0];
        let r = guess_words(c, &o.receiver);
        nonzero_vector_if(c, &r, &o.receiver, (a, o.active));
        let q = guess_words(c, &o.rho);
        nonzero_vector_if(c, &q, &o.rho, (a, o.active));
        let (amt, sum) = amount_unchecked(c, o.amount);
        nonzero_if(c, sum, amount_limbs(o.amount).iter().sum(), (a, o.active));
        let idle = eval!(c, (sum) * ((1) - (a)));
        let zero = c.zero();
        eq(c, idle, zero);
        recv_out.push(r);
        rho_out.push(q);
        amt_out.push(amt);
        active.push(a);
    }
    // ak, nk for both inputs.
    let keys = hash_batch(c, vec![(AUTH, 0, sk[0].clone()), (NK, 0, sk[0].clone()), (AUTH, 0, sk[1].clone()), (NK, 0, sk[1].clone())]);
    let (nk0, nk1) = (keys[1].clone(), keys[3].clone());
    // Input receivers and output inner hashes.
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
    // All four note commitments.
    let note = |ctxv: &[Var], amt: &[Var], inner: &[Var]| (NOTE, 0, [ctxv.to_vec(), amt.to_vec(), inner.to_vec()].concat());
    let cms = hash_batch(c, vec![
        note(&context, &amt_in[0], &inner_in[0]),
        note(&context, &amt_in[1], &inner_in[1]),
        note(&context, &amt_out[0], &b[2]),
        note(&context, &amt_out[1], &b[3]),
    ]);
    // Both membership paths, level by level.
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
    for (a, b) in cur[0].clone().into_iter().zip(cur[1].clone()) {
        eq(c, a, b);
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
    let mut outs: Vec<Var> = vec![];
    for j in 0..2 {
        // An inactive slot publishes a zero commitment and a zero delivery digest.
        let a = active[j];
        for word in cms[2 + j].clone() {
            outs.push(eval!(c, (word) * (a)));
        }
        for limb in guess_words(c, &felt_limbs(&public.deliveries[j])) {
            let idle = eval!(c, (limb) * ((1) - (a)));
            let zero = c.zero();
            eq(c, idle, zero);
            outs.push(limb);
        }
    }
    // The withdrawal: recipient limbs (range-checked by the bridge) and a range-checked amount.
    let recipient = guess_words(c, &felt_limbs(&public.withdrawal_recipient));
    let (withdrawn, withdrawn_sum) = amount_unchecked(c, public.withdrawal_amount);
    // A zero withdrawal is allowed (the bridge ties it to a zero recipient): its sum is unused.
    c.mark_as_maybe_unused(&withdrawn_sum);
    conservation(
        c,
        &[&amt_in[0], &amt_in[1]],
        &[&amt_out[0], &amt_out[1], &withdrawn],
        &[w.inputs[0].amount, w.inputs[1].amount],
        &[w.outputs[0].amount, w.outputs[1].amount, public.withdrawal_amount],
    );
    // V3: the intent is carried verbatim (range-checked by the bridge); the identity handle is
    // H(IDENTITY, sk₀ ‖ scope), published only under the private identity flag.
    let intent = guess_words(c, &felt_limbs(&public.intent));
    let id_active = guess_bits(c, w.identity.active as usize, 1)[0];
    let scope = guess_words(c, &w.identity.scope);
    let handle = hash_batch(c, vec![(IDENTITY, 0, [sk[0].clone(), scope].concat())]).concat();
    let identity: Vec<Var> = handle.into_iter().map(|word| eval!(c, (word) * (id_active))).collect();
    let zero = c.zero();
    let mut limbs: Vec<Var> = [tag, context, cur[0].clone(), nfs, outs, recipient, withdrawn, intent, identity].concat();
    limbs.resize(4 * N_OUTPUTS, zero);
    limbs.chunks_exact(4).map(|q| from_partial_evals(c, q.try_into().unwrap())).collect()
}

// ---------------------------------------------------------------- wallet support

/// The root of the depth-32 tree holding `leaves` at indices 0..n (empty subtrees elsewhere) and,
/// for each of `positions`, its 32 siblings from the leaf up. Matches the pool's appends.
pub fn tree_paths(tree: Tree, leaves: &[Digest], positions: &[u32]) -> (Digest, Vec<Vec<Digest>>) {
    let mut zeros = vec![[0u32; 9]];
    for level in 0..DEPTH {
        let z = *zeros.last().unwrap();
        zeros.push(node(tree, level as u32, &z, &z));
    }
    let mut level_nodes = leaves.to_vec();
    let mut index: Vec<u64> = positions.iter().map(|p| *p as u64).collect();
    let mut paths = vec![vec![]; positions.len()];
    for level in 0..DEPTH {
        for (i, idx) in index.iter().enumerate() {
            let sib = (*idx ^ 1) as usize;
            paths[i].push(level_nodes.get(sib).copied().unwrap_or(zeros[level]));
        }
        let mut next = vec![];
        for pair in level_nodes.chunks(2) {
            let r = if pair.len() == 2 { pair[1] } else { zeros[level] };
            next.push(node(tree, level as u32, &pair[0], &r));
        }
        if next.is_empty() {
            next.push(zeros[level + 1]);
        }
        level_nodes = next;
        index.iter_mut().for_each(|i| *i >>= 1);
    }
    (level_nodes[0], paths)
}
