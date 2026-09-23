//! Experimental R0 payment relation: two ordinary inputs, two ordinary outputs, one public
//! token, depth-32 membership (`bench/m31-statement/privacy-contract.md` §2–3), over
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
//!   `node = P([TAG, 1, NODE1, level] ++ left ++ right ++ [0, 0])[..9]` ([`Tree::Compress`]:
//!   one truncated permutation per node, as Plonky3's Merkle compression; an **experimental
//!   format variant** pending its own review)
//! - `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`
//!
//! Felts (chain, pool, token, delivery digests) are nine 28-bit little-endian limbs; amounts are
//! eight 16-bit little-endian limbs, each range-checked by bits. Private checks: nonzero `sk`,
//! `rho`, `receiver` and amounts, both paths reaching one root, and
//! `in₀ + in₁ = out₀ + out₁` as integers. Distinct nullifiers are checked publicly (as the pool
//! does when it marks them spent).
//!
//! The public statement is 92 limbs, emitted as 23 QM31 outputs (four limbs each):
//! tag (2), chain, pool, token, root, nf₀, nf₁, cm_out₀, delivery₀, cm_out₁, delivery₁ (9 each).
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
/// Statement tag: `TMPZ`, `R0V1`.
pub const STATEMENT_TAG: [u32; 2] = [0x544d_505a, 0x5230_5631];
pub const DEPTH: usize = 32;
pub const N_OUTPUTS: usize = 23;
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

/// How tree nodes are hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tree {
    /// `H(NODE, level, left ‖ right)`: the framed rate-15 sponge, two permutations.
    Sponge,
    /// One width-24 permutation over `[TAG, 1, NODE1, level, left, right, 0, 0]`, truncated to
    /// nine words.
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    pub receiver: Digest,
    pub rho: Digest,
    pub amount: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Private {
    pub inputs: [Input; 2],
    pub outputs: [Output; 2],
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Public {
    pub chain: String,
    pub pool: String,
    pub token: String,
    pub root: Digest,
    pub nullifiers: [Digest; 2],
    pub commitments: [Digest; 2],
    pub deliveries: [String; 2],
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

/// The 92 public limbs in output order.
pub fn statement_limbs(p: &Public) -> Vec<u32> {
    let mut x = STATEMENT_TAG.to_vec();
    x.extend(context_limbs(p));
    x.extend(p.root);
    x.extend(p.nullifiers.concat());
    for j in 0..2 {
        x.extend(p.commitments[j]);
        x.extend(felt_limbs(&p.deliveries[j]));
    }
    assert_eq!(x.len(), 4 * N_OUTPUTS);
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
            for (i, v) in [TAG, 1, NODE1, level].iter().chain(l).chain(r).enumerate() {
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

/// The public statement a valid witness proves, or an error naming the first broken rule.
pub fn statement(tree: Tree, chain: &str, pool: &str, token: &str, deliveries: [String; 2], w: &Private) -> Result<Public, String> {
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
    for o in &w.outputs {
        if !nonzero(&o.receiver) || !nonzero(&o.rho) || o.amount == 0 {
            return Err("zero output".into());
        }
        commitments.push(commitment(&context, o.amount, &o.receiver, &o.rho));
    }
    // u128 amounts; the sums are compared as integers (up to 129 bits).
    let sum = |a: u128, b: u128| (a as u128).overflowing_add(b);
    if sum(w.inputs[0].amount, w.inputs[1].amount) != sum(w.outputs[0].amount, w.outputs[1].amount) {
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
    })
}

/// A fresh random R0 payment: two notes at independent positions of one sparse depth-32 tree
/// (the paths share nodes only where they meet), and two outputs splitting the total.
pub fn fresh(tree: Tree, rng: &mut impl RngCore) -> (Public, Private) {
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
    let out0 = rng.gen_range(1..total);
    let private = Private {
        inputs: std::array::from_fn(|i| Input {
            sk: sks[i],
            rho: rhos[i],
            amount: amounts[i],
            position: positions[i],
            siblings: siblings[i].clone(),
        }),
        outputs: [
            Output { receiver: digest(rng), rho: digest(rng), amount: out0 },
            Output { receiver: digest(rng), rho: digest(rng), amount: total - out0 },
        ],
    };
    let deliveries = [format!("0x{:x}", rng.next_u64() | 1), format!("0x{:x}", rng.next_u64() | 1)];
    let public = statement(tree, chain, &pool, &token, deliveries, &private).expect("fresh witness is valid");
    (public, private)
}

// ---------------------------------------------------------------- circuit

fn guess_words<V: IValue>(c: &mut Context<V>, words: &[u32]) -> Vec<Var> {
    words.iter().map(|w| guess_m31(c, *w)).collect()
}

/// Asserts `v ≠ 0` with a witness inverse.
fn nonzero<V: IValue>(c: &mut Context<V>, v: Var, value: u32) {
    let inv = if value == 0 { 0 } else { M31::from(value).inverse().0 };
    let inv = guess_m31(c, inv);
    let one = c.one();
    let prod = eval!(c, (v) * (inv));
    eq(c, prod, one);
}

/// Asserts some word of `words` is nonzero: a one-hot selector picks it, then [`nonzero`].
fn nonzero_vector<V: IValue>(c: &mut Context<V>, words: &[Var], values: &[u32]) {
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
fn amount<V: IValue>(c: &mut Context<V>, a: u128) -> Vec<Var> {
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
    // Eight limbs below 2^16 sum below 2^19, so the sum is zero only if every limb is.
    let s: u32 = limbs.iter().sum();
    nonzero(c, sum, s);
    vars
}

/// `a₀ + a₁ = b₀ + b₁` over the integers, limb by limb with signed carries in {-1, 0, 1}.
fn conservation<V: IValue>(c: &mut Context<V>, ins: [&[Var]; 2], outs: [&[Var]; 2], values: ([u128; 2], [u128; 2])) {
    let shift = c.constant(M31::from(1u32 << 16).into());
    let (ai, ao) = values;
    let (li, lo) = (ai.map(amount_limbs), ao.map(amount_limbs));
    let mut carry = c.zero();
    let mut carry_value: i64 = 0;
    for k in 0..AMOUNT_LIMBS {
        let d = eval!(c, (((ins[0][k]) + (ins[1][k])) - (outs[0][k])) - (outs[1][k]));
        let dv = li[0][k] as i64 + li[1][k] as i64 - lo[0][k] as i64 - lo[1][k] as i64 + carry_value;
        // An invalid witness gets some carry anyway, and the constraint below fails.
        let next_value = dv.div_euclid(1 << 16).clamp(-1, 1);
        let next = if k + 1 == AMOUNT_LIMBS {
            c.zero()
        } else {
            let enc = if next_value < 0 { P - (-next_value) as u32 } else { next_value as u32 };
            let n = guess_m31(c, enc);
            // n ∈ {-1, 0, 1}: n·(n - 1)·(n + 1) = 0.
            let t = eval!(c, ((n) * ((n) - (1))) * ((n) + (1)));
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
fn hash_batch<V: Lanes>(c: &mut Context<V>, requests: Vec<(u32, u32, Vec<Var>)>) -> Vec<Vec<Var>> {
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

/// Builds R0 and returns the 23 output variables (the public statement). Hashes run four to a
/// row where they are independent, two along the membership paths.
pub fn build<V: Lanes>(c: &mut Context<V>, tree: Tree, public: &Public, w: &Private) -> Vec<Var> {
    let tag: Vec<Var> = STATEMENT_TAG.iter().map(|t| c.constant(M31::from(*t).into())).collect();
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
    for o in &w.outputs {
        let r = guess_words(c, &o.receiver);
        nonzero_vector(c, &r, &o.receiver);
        let q = guess_words(c, &o.rho);
        nonzero_vector(c, &q, &o.rho);
        recv_out.push(r);
        rho_out.push(q);
        amt_out.push(amount(c, o.amount));
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
                        let mut st: Vec<Var> = [TAG, 1, NODE1, l].iter().map(|v| c.constant(M31::from(*v).into())).collect();
                        st.extend(x);
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
        outs.extend(cms[2 + j].clone());
        outs.extend(guess_words(c, &felt_limbs(&public.deliveries[j])));
    }
    conservation(
        c,
        [&amt_in[0], &amt_in[1]],
        [&amt_out[0], &amt_out[1]],
        ([w.inputs[0].amount, w.inputs[1].amount], [w.outputs[0].amount, w.outputs[1].amount]),
    );
    let limbs: Vec<Var> = [tag, context, cur[0].clone(), nfs, outs].concat();
    assert_eq!(limbs.len(), 4 * N_OUTPUTS);
    limbs.chunks_exact(4).map(|q| from_partial_evals(c, q.try_into().unwrap())).collect()
}
