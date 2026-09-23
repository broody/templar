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
//! - `node = H(NODE, level, left ‖ right)`
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
use crate::membership::{permute, sponge};
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

pub fn climb(leaf: &Digest, position: u32, siblings: &[Digest]) -> Digest {
    let mut cur = *leaf;
    for (level, sib) in siblings.iter().enumerate() {
        let (l, r) = if (position >> level) & 1 == 0 { (cur, *sib) } else { (*sib, cur) };
        cur = h(NODE, level as u32, &cat(&[&l, &r]));
    }
    cur
}

pub fn nullifier(nk: &Digest, cm: &Digest, position: u32) -> Digest {
    h(NF, 0, &cat(&[nk, cm, &[position & 0xffff, position >> 16]]))
}

/// The public statement a valid witness proves, or an error naming the first broken rule.
pub fn statement(chain: &str, pool: &str, token: &str, deliveries: [String; 2], w: &Private) -> Result<Public, String> {
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
        roots.push(climb(&cm, i.position, &i.siblings));
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
pub fn fresh(rng: &mut impl RngCore) -> (Public, Private) {
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
            parents.push((parent, h(NODE, level as u32, &cat(&[&l, &r]))));
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
    let public = statement(chain, &pool, &token, deliveries, &private).expect("fresh witness is valid");
    (public, private)
}

// ---------------------------------------------------------------- circuit

fn guess_words<V: IValue>(c: &mut Context<V>, words: &[u32]) -> Vec<Var> {
    words.iter().map(|w| guess_m31(c, *w)).collect()
}

fn hash<V: IValue>(c: &mut Context<V>, kind: u32, level: u32, payload: &[Var]) -> Vec<Var> {
    let mut x: Vec<Var> = [TAG, 1, kind, level].iter().map(|v| c.constant(M31::from(*v).into())).collect();
    x.extend_from_slice(payload);
    sponge(c, &x)[..9].to_vec()
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

/// Builds R0 and returns the 23 output variables (the public statement).
pub fn build<V: IValue>(c: &mut Context<V>, public: &Public, w: &Private) -> Vec<Var> {
    let tag: Vec<Var> = STATEMENT_TAG.iter().map(|t| c.constant(M31::from(*t).into())).collect();
    let context = guess_words(c, &context_limbs(public));
    let mut roots: Vec<Vec<Var>> = vec![];
    let mut nfs: Vec<Var> = vec![];
    let mut amounts_in = vec![];
    for i in &w.inputs {
        let sk = guess_words(c, &i.sk);
        nonzero_vector(c, &sk, &i.sk);
        let rho = guess_words(c, &i.rho);
        nonzero_vector(c, &rho, &i.rho);
        let amt = amount(c, i.amount);
        let ak = hash(c, AUTH, 0, &sk);
        let nk = hash(c, NK, 0, &sk);
        let receiver = hash(c, OWNER, 0, &[ak, nk.clone()].concat());
        let inner = hash(c, INNER, 0, &[receiver, rho].concat());
        let cm = hash(c, NOTE, 0, &[context.clone(), amt.clone(), inner].concat());
        let bits = guess_bits(c, i.position as usize, DEPTH as u32);
        let mut cur = cm.clone();
        for (level, s) in i.siblings.iter().enumerate() {
            let sib = guess_words(c, s);
            let bit = bits[level];
            let mut left = vec![];
            let mut right = vec![];
            for (x, y) in cur.iter().zip(&sib) {
                let (x, y) = (*x, *y);
                let d = eval!(c, (bit) * ((y) - (x)));
                left.push(eval!(c, (x) + (d)));
                right.push(eval!(c, (y) - (d)));
            }
            cur = hash(c, NODE, level as u32, &[left, right].concat());
        }
        roots.push(cur);
        let pack = |c: &mut Context<V>, bits: &[Var]| {
            let mut v = c.zero();
            for (k, b) in bits.iter().enumerate() {
                let w = c.constant(M31::from(1u32 << k).into());
                v = eval!(c, (v) + ((*b) * (w)));
            }
            v
        };
        let lo = pack(c, &bits[..16]);
        let hi = pack(c, &bits[16..]);
        nfs.extend(hash(c, NF, 0, &[nk, cm, vec![lo, hi]].concat()));
        amounts_in.push(amt);
    }
    for (a, b) in roots[0].clone().into_iter().zip(roots[1].clone()) {
        eq(c, a, b);
    }
    let mut outs: Vec<Var> = vec![];
    let mut amounts_out = vec![];
    for (j, o) in w.outputs.iter().enumerate() {
        let receiver = guess_words(c, &o.receiver);
        nonzero_vector(c, &receiver, &o.receiver);
        let rho = guess_words(c, &o.rho);
        nonzero_vector(c, &rho, &o.rho);
        let amt = amount(c, o.amount);
        let inner = hash(c, INNER, 0, &[receiver, rho].concat());
        outs.extend(hash(c, NOTE, 0, &[context.clone(), amt.clone(), inner].concat()));
        outs.extend(guess_words(c, &felt_limbs(&public.deliveries[j])));
        amounts_out.push(amt);
    }
    conservation(
        c,
        [&amounts_in[0], &amounts_in[1]],
        [&amounts_out[0], &amounts_out[1]],
        ([w.inputs[0].amount, w.inputs[1].amount], [w.outputs[0].amount, w.outputs[1].amount]),
    );
    let limbs: Vec<Var> = [tag, context, roots[0].clone(), nfs, outs].concat();
    assert_eq!(limbs.len(), 4 * N_OUTPUTS);
    limbs.chunks_exact(4).map(|q| from_partial_evals(c, q.try_into().unwrap())).collect()
}
