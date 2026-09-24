//! Experimental P1 policy-settlement relation (`docs/policy-note-spec.md` §3–5, ADR-0025): one
//! policy note, spent with its capability into one committed outcome of its policy. It reuses
//! R0's hash, tree, range-check and conservation gadgets (`payment.rs`); R0 itself is unchanged.
//!
//! Hashes are R0's `H(kind, 0, payload)`; new kinds `PNK 10, PRECV 11, POLICY 12, OUTCOME 13,
//! OREST 14, POLICY_ID 15`:
//!
//! - `pnk = H(PNK, cap)`, `recv_p = H(PRECV, pnk ‖ policy)`, then R0's `inner`, `cm` and `nf`
//!   with `recv_p` as the receiver and `pnk` as the nullifier key
//! - `o = H(OUTCOME, type ‖ not_before₄ ‖ out₀ ‖ out₁ ‖ w_recipient₉ ‖ w_amount₈)`,
//!   `out_j = active ‖ receiver₉ ‖ rho₉ ‖ amount₈ ‖ delivery₉`
//! - `orest = H(OREST, o₁ ‖ o₂ ‖ o₃)`
//! - `policy = H(POLICY, 1 ‖ 1 ‖ controller₉ ‖ class₉ ‖ handle₉ ‖ deadline₄ ‖ salt₉ ‖ o₀ ‖ orest)`
//! - `policy_id = H(POLICY_ID, chain₉ ‖ pool₉ ‖ token₉ ‖ amount₈ ‖ policy)`
//!
//! Felts are nine 28-bit limbs, amounts eight and block numbers four 16-bit limbs. The public
//! statement is 163 limbs (padded to 164), emitted as 41 QM31 outputs: tag (2), chain, pool,
//! token, root, nullifier, commitment₀, commitment₁, delivery₀, delivery₁, withdrawal recipient
//! (9 each), withdrawal amount (8), controller, controller class, handle, policy_id (9 each),
//! deadline (4), not_before (4), outcome index, outcome type, x (8), data (9).
//!
//! A **resource-measurement and review format**: the encodings follow the reviewed design but
//! are not a frozen production suite.
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::IValue;
use circuits::ops::{eq, from_partial_evals};
use serde::{Deserialize, Serialize};
use stwo::core::fields::m31::M31;

use crate::membership::{Lanes, compress_lanes};
use crate::merkle::guess_bits;
use crate::payment::{
    self, DEPTH, Digest, INNER, NF, NODE, NODE1, NOTE, P, TAG, Tree, amount, amount_limbs, amount_unchecked, climb,
    conservation, felt_limbs, guess_words, h, hash_batch, nonzero_if, nonzero_vector, nonzero_vector_if,
};
use crate::ro::guess_m31;

pub const PNK: u32 = 10;
pub const PRECV: u32 = 11;
pub const POLICY: u32 = 12;
pub const OUTCOME: u32 = 13;
pub const OREST: u32 = 14;
pub const POLICY_ID: u32 = 15;
/// Policy format version and kind (outcome menu): circuit constants, never witnesses.
pub const VERSION: u32 = 1;
pub const KIND: u32 = 1;
pub const FIXED: u8 = 1;
pub const SPLIT: u8 = 2;
/// Statement tags: `TMPZ` with `P1V1` (sponge nodes) or `P1C1` (single-permutation nodes).
pub const STATEMENT_TAG: [u32; 2] = [0x544d_505a, 0x5031_5631];
pub const STATEMENT_TAG_COMPRESS: [u32; 2] = [0x544d_505a, 0x5031_4331];
pub const N_OUTPUTS: usize = 41;
pub const N_LIMBS: usize = 163;

pub fn statement_tag(tree: Tree) -> [u32; 2] {
    match tree {
        Tree::Sponge => STATEMENT_TAG,
        Tree::Compress => STATEMENT_TAG_COMPRESS,
    }
}

/// One output of an outcome. Inactive: every field zero. In a split outcome both are active and
/// `amount` is zero (the amounts come from the public `x`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutSpec {
    pub active: bool,
    pub receiver: Digest,
    pub rho: Digest,
    pub amount: u128,
    /// The output ciphertext's delivery digest (a felt, `0x` hex), fixed at creation.
    pub delivery: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    /// [`FIXED`] or [`SPLIT`].
    pub kind: u8,
    pub not_before: u64,
    pub outputs: [OutSpec; 2],
    pub withdrawal_recipient: String,
    pub withdrawal_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub controller: String,
    pub controller_class: String,
    pub handle: String,
    pub deadline: u64,
    pub salt: Digest,
}

/// A whole policy: the header and up to four outcomes (`None` is an unused, zero slot).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub header: Header,
    pub outcomes: [Option<Outcome>; 4],
}

/// The P1 witness: the note, the policy header, the selected outcome and the digests needed to
/// recompute the policy (the selected slot's entry in `slots` is ignored; `rest` is used only for
/// the refund, index 0).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Private {
    pub cap: Digest,
    pub rho: Digest,
    pub amount: u128,
    pub position: u32,
    pub siblings: Vec<Digest>,
    pub header: Header,
    pub index: u8,
    pub selected: Outcome,
    pub slots: [Digest; 4],
    pub rest: Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Public {
    pub chain: String,
    pub pool: String,
    pub token: String,
    pub root: Digest,
    pub nullifier: Digest,
    pub commitments: [Digest; 2],
    pub deliveries: [String; 2],
    pub withdrawal_recipient: String,
    pub withdrawal_amount: u128,
    pub controller: String,
    pub controller_class: String,
    pub handle: String,
    pub policy_id: Digest,
    pub deadline: u64,
    pub not_before: u64,
    pub index: u8,
    pub kind: u8,
    pub x: u128,
    pub data: String,
}

// ---------------------------------------------------------------- encodings and native reference

pub fn block_limbs(b: u64) -> [u32; 4] {
    std::array::from_fn(|k| ((b >> (16 * k)) & 0xffff) as u32)
}

fn out_payload(o: &OutSpec) -> Vec<u32> {
    [&[o.active as u32][..], &o.receiver, &o.rho, &amount_limbs(o.amount), &felt_limbs(&o.delivery)].concat()
}

/// The outcome hash's payload (94 words).
pub fn outcome_payload(o: &Outcome) -> Vec<u32> {
    [
        &[o.kind as u32][..],
        &block_limbs(o.not_before),
        &out_payload(&o.outputs[0]),
        &out_payload(&o.outputs[1]),
        &felt_limbs(&o.withdrawal_recipient),
        &amount_limbs(o.withdrawal_amount),
    ]
    .concat()
}

pub fn outcome_digest(o: &Outcome) -> Digest {
    h(OUTCOME, 0, &outcome_payload(o))
}

pub fn slot_digest(o: &Option<Outcome>) -> Digest {
    o.as_ref().map_or([0; 9], outcome_digest)
}

pub fn orest(o1: &Digest, o2: &Digest, o3: &Digest) -> Digest {
    h(OREST, 0, &[&o1[..], &o2[..], &o3[..]].concat())
}

pub fn policy_digest(header: &Header, o0: &Digest, rest: &Digest) -> Digest {
    let payload = [
        &[VERSION, KIND][..],
        &felt_limbs(&header.controller),
        &felt_limbs(&header.controller_class),
        &felt_limbs(&header.handle),
        &block_limbs(header.deadline),
        &header.salt,
        o0,
        rest,
    ]
    .concat();
    h(POLICY, 0, &payload)
}

impl Policy {
    pub fn slots(&self) -> [Digest; 4] {
        std::array::from_fn(|k| slot_digest(&self.outcomes[k]))
    }

    pub fn rest(&self) -> Digest {
        let s = self.slots();
        orest(&s[1], &s[2], &s[3])
    }

    pub fn digest(&self) -> Digest {
        policy_digest(&self.header, &self.slots()[0], &self.rest())
    }
}

fn context_limbs(chain: &str, pool: &str, token: &str) -> Vec<u32> {
    [felt_limbs(chain), felt_limbs(pool), felt_limbs(token)].concat()
}

pub fn policy_id(chain: &str, pool: &str, token: &str, amount: u128, policy: &Digest) -> Digest {
    h(POLICY_ID, 0, &[context_limbs(chain, pool, token), amount_limbs(amount).to_vec(), policy.to_vec()].concat())
}

pub fn pnk_of(cap: &Digest) -> Digest {
    h(PNK, 0, cap)
}

/// The note's receiver (`recv_p`): what an R0 output or a deposit's `inner` uses to create it.
pub fn receiver(cap: &Digest, policy: &Digest) -> Digest {
    h(PRECV, 0, &[pnk_of(cap), *policy].concat())
}

/// The witness for settling `policy`'s outcome `index`, for a note at `position` with `siblings`.
pub fn private_for(policy: &Policy, index: u8, cap: Digest, rho: Digest, amount: u128, position: u32, siblings: Vec<Digest>) -> Private {
    let outcome = policy.outcomes[index as usize].clone().expect("selected slot is used");
    Private {
        cap,
        rho,
        amount,
        position,
        siblings,
        header: policy.header.clone(),
        index,
        selected: outcome,
        slots: policy.slots(),
        rest: policy.rest(),
    }
}

/// The public statement a valid witness proves, or the first broken rule. `x` is the split
/// amount (zero for a fixed outcome) and `data` the controller call's data felt.
pub fn statement(tree: Tree, chain: &str, pool: &str, token: &str, x: u128, data: &str, w: &Private) -> Result<Public, String> {
    let nonzero = |d: &Digest| d.iter().any(|v| *v != 0);
    let canonical = |d: &Digest| d.iter().all(|v| *v < P);
    if !nonzero(&w.cap) || !nonzero(&w.rho) || w.amount == 0 {
        return Err("zero note".into());
    }
    if !canonical(&w.cap) || !canonical(&w.rho) || !canonical(&w.header.salt) || w.siblings.len() != DEPTH {
        return Err("note encoding".into());
    }
    if w.index > 3 {
        return Err("outcome index".into());
    }
    let o = &w.selected;
    let split = match o.kind {
        FIXED => false,
        SPLIT => true,
        _ => return Err("outcome type".into()),
    };
    for (j, out) in o.outputs.iter().enumerate() {
        let zero_delivery = felt_limbs(&out.delivery).iter().all(|l| *l == 0);
        if out.active {
            if !nonzero(&out.receiver) || !nonzero(&out.rho) || zero_delivery {
                return Err(format!("output {j} fields"));
            }
            if !canonical(&out.receiver) || !canonical(&out.rho) {
                return Err(format!("output {j} encoding"));
            }
            if split != (out.amount == 0) {
                return Err(format!("output {j} amount"));
            }
        } else if split || nonzero(&out.receiver) || nonzero(&out.rho) || out.amount != 0 || !zero_delivery {
            return Err(format!("inactive output {j} carries data"));
        }
    }
    let has_recipient = felt_limbs(&o.withdrawal_recipient).iter().any(|l| *l != 0);
    if split && (has_recipient || o.withdrawal_amount != 0) {
        return Err("split withdrawal".into());
    }
    if w.index == 0 && (split || o.not_before != 0 || !o.outputs[0].active || has_recipient || o.withdrawal_amount != 0) {
        return Err("refund outcome".into());
    }
    // Output amounts.
    let (a0, a1) = if split {
        if x == 0 || x > w.amount {
            return Err("split amount".into());
        }
        (x, w.amount - x)
    } else {
        if x != 0 {
            return Err("x on a fixed outcome".into());
        }
        (o.outputs[0].amount, o.outputs[1].amount)
    };
    let total = [a0, a1, o.withdrawal_amount].iter().try_fold(0u128, |s, v| s.checked_add(*v));
    if total != Some(w.amount) {
        return Err("conservation".into());
    }
    // The policy with the selected slot recomputed.
    let mut slots = w.slots;
    slots[w.index as usize] = outcome_digest(o);
    let rest = if w.index == 0 { w.rest } else { orest(&slots[1], &slots[2], &slots[3]) };
    let policy = policy_digest(&w.header, &slots[0], &rest);
    let context = context_limbs(chain, pool, token);
    let pnk = pnk_of(&w.cap);
    let recv = h(PRECV, 0, &[pnk, policy].concat());
    let cm = payment::commitment(&context, w.amount, &recv, &w.rho);
    let root = climb(tree, &cm, w.position, &w.siblings);
    let nullifier = payment::nullifier(&pnk, &cm, w.position);
    // Published outputs: the second is absent when inactive, or when a split leaves nothing.
    let publish = [o.outputs[0].active, if split { a1 != 0 } else { o.outputs[1].active }];
    let mut commitments = [[0u32; 9]; 2];
    let mut deliveries = ["0x0".to_string(), "0x0".to_string()];
    for j in 0..2 {
        if publish[j] {
            let out = &o.outputs[j];
            commitments[j] = payment::commitment(&context, [a0, a1][j], &out.receiver, &out.rho);
            deliveries[j] = out.delivery.clone();
        }
    }
    Ok(Public {
        chain: chain.into(),
        pool: pool.into(),
        token: token.into(),
        root,
        nullifier,
        commitments,
        deliveries,
        withdrawal_recipient: o.withdrawal_recipient.clone(),
        withdrawal_amount: o.withdrawal_amount,
        controller: w.header.controller.clone(),
        controller_class: w.header.controller_class.clone(),
        handle: w.header.handle.clone(),
        policy_id: policy_id(chain, pool, token, w.amount, &policy),
        deadline: w.header.deadline,
        not_before: o.not_before,
        index: w.index,
        kind: o.kind,
        x,
        data: data.into(),
    })
}

/// The 163 public limbs (padded with zeros to 164) in output order.
pub fn statement_limbs(tree: Tree, p: &Public) -> Vec<u32> {
    let mut x = statement_tag(tree).to_vec();
    x.extend(context_limbs(&p.chain, &p.pool, &p.token));
    x.extend(p.root);
    x.extend(p.nullifier);
    x.extend(p.commitments.concat());
    x.extend(felt_limbs(&p.deliveries[0]));
    x.extend(felt_limbs(&p.deliveries[1]));
    x.extend(felt_limbs(&p.withdrawal_recipient));
    x.extend(amount_limbs(p.withdrawal_amount));
    x.extend(felt_limbs(&p.controller));
    x.extend(felt_limbs(&p.controller_class));
    x.extend(felt_limbs(&p.handle));
    x.extend(p.policy_id);
    x.extend(block_limbs(p.deadline));
    x.extend(block_limbs(p.not_before));
    x.push(p.index as u32);
    x.push(p.kind as u32);
    x.extend(amount_limbs(p.x));
    x.extend(felt_limbs(&p.data));
    assert_eq!(x.len(), N_LIMBS);
    x.resize(4 * N_OUTPUTS, 0);
    x
}

// ---------------------------------------------------------------- circuit

/// `n` range-checked 16-bit limbs of `v` (little-endian) and their sum (zero iff `v` is).
fn limbs16<V: IValue>(c: &mut Context<V>, v: u64, n: usize) -> (Vec<Var>, Var) {
    let mut vars = vec![];
    let mut sum = c.zero();
    for k in 0..n {
        let bits = guess_bits(c, ((v >> (16 * k)) & 0xffff) as usize, 16);
        let mut x = c.zero();
        for (i, b) in bits.iter().enumerate() {
            let w = c.constant(M31::from(1u32 << i).into());
            x = eval!(c, (x) + ((*b) * (w)));
        }
        sum = eval!(c, (sum) + (x));
        vars.push(x);
    }
    (vars, sum)
}

fn assert_zero<V: IValue>(c: &mut Context<V>, v: Var) {
    let zero = c.zero();
    eq(c, v, zero);
}

/// Asserts `gate · v = 0` for each of `words`.
fn zero_when<V: IValue>(c: &mut Context<V>, words: &[Var], gate: Var) {
    for w in words {
        let w = *w;
        let t = eval!(c, (w) * (gate));
        assert_zero(c, t);
    }
}

fn constants<V: IValue>(c: &mut Context<V>, values: &[u32]) -> Vec<Var> {
    values.iter().map(|v| c.constant(M31::from(*v).into())).collect()
}

/// A boolean witness bit.
fn bit<V: IValue>(c: &mut Context<V>, b: bool) -> Var {
    guess_bits(c, b as usize, 1)[0]
}

/// `z ∈ {0, 1}` with `z = 1` exactly when `sum ≠ 0` (`sum·t = z`, `sum·(1 − z) = 0`); `sum` is a
/// sum of 16-bit limbs, far below the modulus.
fn is_nonzero<V: IValue>(c: &mut Context<V>, sum: Var, value: u32) -> Var {
    let z = bit(c, value != 0);
    let t = guess_m31(c, if value == 0 { 0 } else { M31::from(value).inverse().0 });
    let prod = eval!(c, (sum) * (t));
    eq(c, prod, z);
    let idle = eval!(c, (sum) * ((1) - (z)));
    assert_zero(c, idle);
    z
}

/// Builds P1 and returns the 41 output variables (the public statement).
pub fn build<V: Lanes>(c: &mut Context<V>, tree: Tree, public: &Public, w: &Private) -> Vec<Var> {
    let tag = constants(c, &statement_tag(tree));
    let context = guess_words(c, &context_limbs(&public.chain, &public.pool, &public.token));
    // The note.
    let cap = guess_words(c, &w.cap);
    nonzero_vector(c, &cap, &w.cap);
    let rho = guess_words(c, &w.rho);
    nonzero_vector(c, &rho, &w.rho);
    let amt = amount(c, w.amount);
    let bits = guess_bits(c, w.position as usize, DEPTH as u32);
    // The header: felts are published (the bridge decodes them canonically), the deadline is
    // range-checked here.
    let controller = guess_words(c, &felt_limbs(&w.header.controller));
    let class = guess_words(c, &felt_limbs(&w.header.controller_class));
    let handle = guess_words(c, &felt_limbs(&w.header.handle));
    let (deadline, deadline_sum) = limbs16(c, w.header.deadline, 4);
    c.mark_as_maybe_unused(&deadline_sum);
    let salt = guess_words(c, &w.header.salt);
    // The selected outcome. `s` is the split bit; the type is `1 + s`.
    let o = &w.selected;
    let split = o.kind == SPLIT;
    let s = bit(c, split);
    let kind = eval!(c, (1) + (s));
    let (not_before, nb_sum) = limbs16(c, o.not_before, 4);
    let mut act = vec![];
    let mut recv = vec![];
    let mut orho = vec![];
    let mut pamt = vec![];
    let mut dl = vec![];
    for out in &o.outputs {
        let a = bit(c, out.active);
        let r = guess_words(c, &out.receiver);
        let q = guess_words(c, &out.rho);
        let (m, m_sum) = amount_unchecked(c, out.amount);
        let dv = felt_limbs(&out.delivery);
        let d = guess_words(c, &dv);
        // Active: nonzero receiver, rho and delivery; a fixed amount is nonzero.
        nonzero_vector_if(c, &r, &out.receiver, (a, out.active));
        nonzero_vector_if(c, &q, &out.rho, (a, out.active));
        nonzero_vector_if(c, &d, &dv, (a, out.active));
        let fixed_active = eval!(c, (a) * ((1) - (s)));
        nonzero_if(c, m_sum, amount_limbs(out.amount).iter().sum(), (fixed_active, out.active && !split));
        // Inactive: every field zero.
        let idle = eval!(c, (1) - (a));
        zero_when(c, &[r.clone(), q.clone(), m.clone(), d.clone()].concat(), idle);
        // Split: both active, committed amounts zero.
        let inactive_split = eval!(c, (s) * ((1) - (a)));
        assert_zero(c, inactive_split);
        let split_amount = eval!(c, (m_sum) * (s));
        assert_zero(c, split_amount);
        act.push(a);
        recv.push(r);
        orho.push(q);
        pamt.push(m);
        dl.push(d);
    }
    let w_rec = guess_words(c, &felt_limbs(&o.withdrawal_recipient));
    let (w_amt, w_sum) = amount_unchecked(c, o.withdrawal_amount);
    // A split has no withdrawal.
    zero_when(c, &w_rec, s);
    let t = eval!(c, (w_sum) * (s));
    assert_zero(c, t);
    // x: zero for a fixed outcome, nonzero for a split. r = amount − x (split only), with its
    // nonzero bit gating the second output.
    let (x, x_sum) = amount_unchecked(c, public.x);
    let not_split = eval!(c, (1) - (s));
    let t = eval!(c, (x_sum) * (not_split));
    assert_zero(c, t);
    nonzero_if(c, x_sum, amount_limbs(public.x).iter().sum(), (s, split));
    let r_value = if split { w.amount.saturating_sub(public.x) } else { 0 };
    let (r, r_sum) = amount_unchecked(c, r_value);
    let t = eval!(c, (r_sum) * (not_split));
    assert_zero(c, t);
    let nz_r = is_nonzero(c, r_sum, amount_limbs(r_value).iter().sum());
    // Commitment amounts: the committed ones (fixed) or x and r (split); the other is zero.
    let mut cam = vec![];
    for (j, extra) in [&x, &r].into_iter().enumerate() {
        let v: Vec<Var> = pamt[j].iter().zip(extra.iter()).map(|(p, e)| {
            let (p, e) = (*p, *e);
            eval!(c, (p) + ((s) * (e)))
        }).collect();
        cam.push(v);
    }
    let cam_values = if split { [public.x, r_value] } else { [o.outputs[0].amount, o.outputs[1].amount] };
    conservation(c, &[&amt], &[&cam[0], &cam[1], &w_amt], &[w.amount], &[cam_values[0], cam_values[1], o.withdrawal_amount]);
    // The selector: one-hot bits, the public index is Σ k·b_k.
    let sel: Vec<Var> = (0..4).map(|k| bit(c, w.index as usize == k)).collect();
    let mut sum_sel = c.zero();
    let mut index = c.zero();
    for (k, b) in sel.iter().enumerate() {
        let b = *b;
        sum_sel = eval!(c, (sum_sel) + (b));
        let kc = c.constant(M31::from(k as u32).into());
        index = eval!(c, (index) + ((b) * (kc)));
    }
    let one = c.one();
    eq(c, sum_sel, one);
    // The refund (index 0): fixed, not_before 0, an active first output, no withdrawal.
    let b0 = sel[0];
    let t = eval!(c, (b0) * (s));
    assert_zero(c, t);
    let t = eval!(c, (b0) * (nb_sum));
    assert_zero(c, t);
    let a0 = act[0];
    let t = eval!(c, (b0) * ((1) - (a0)));
    assert_zero(c, t);
    zero_when(c, &w_rec, b0);
    let t = eval!(c, (b0) * (w_sum));
    assert_zero(c, t);
    // The outcome digest and the capability's nullifier key.
    let mut payload = vec![kind];
    payload.extend(not_before.iter().copied());
    for j in 0..2 {
        payload.push(act[j]);
        payload.extend(recv[j].iter().copied());
        payload.extend(orho[j].iter().copied());
        payload.extend(pamt[j].iter().copied());
        payload.extend(dl[j].iter().copied());
    }
    payload.extend(w_rec.iter().copied());
    payload.extend(w_amt.iter().copied());
    let own = hash_batch(c, vec![(OUTCOME, 0, payload)]).concat();
    let pnk = hash_batch(c, vec![(PNK, 0, cap)]).concat();
    // Slots: the selected one is the recomputed digest, the others witnesses.
    let mut slots = vec![];
    for (k, b) in sel.iter().enumerate() {
        let wk = guess_words(c, &w.slots[k]);
        let b = *b;
        let v: Vec<Var> = wk.iter().zip(&own).map(|(x, y)| {
            let (x, y) = (*x, *y);
            eval!(c, (x) + ((b) * ((y) - (x))))
        }).collect();
        slots.push(v);
    }
    let rest_c = hash_batch(c, vec![(OREST, 0, [slots[1].clone(), slots[2].clone(), slots[3].clone()].concat())]).concat();
    let rest_w = guess_words(c, &w.rest);
    let rest: Vec<Var> = rest_c.iter().zip(&rest_w).map(|(x, y)| {
        let (x, y) = (*x, *y);
        eval!(c, (x) + ((b0) * ((y) - (x))))
    }).collect();
    let mut policy_payload = constants(c, &[VERSION, KIND]);
    for part in [&controller, &class, &handle, &deadline, &salt, &slots[0], &rest] {
        policy_payload.extend(part.iter().copied());
    }
    let policy = hash_batch(c, vec![(POLICY, 0, policy_payload)]).concat();
    // Receiver and the outputs' inner hashes (equal lengths: one lane each).
    let b = hash_batch(c, vec![
        (PRECV, 0, [pnk.clone(), policy.clone()].concat()),
        (INNER, 0, [recv[0].clone(), orho[0].clone()].concat()),
        (INNER, 0, [recv[1].clone(), orho[1].clone()].concat()),
    ]);
    let inner = hash_batch(c, vec![(INNER, 0, [b[0].clone(), rho.clone()].concat())]).concat();
    // The note, both outputs and the policy id (all 44 words).
    let note = |amount: &[Var], inner: &[Var]| (NOTE, 0, [context.clone(), amount.to_vec(), inner.to_vec()].concat());
    let cms = hash_batch(c, vec![
        note(&amt, &inner),
        note(&cam[0], &b[1]),
        note(&cam[1], &b[2]),
        (POLICY_ID, 0, [context.clone(), amt.clone(), policy.clone()].concat()),
    ]);
    // Membership.
    let mut cur = cms[0].clone();
    for level in 0..DEPTH {
        let sib = guess_words(c, &w.siblings[level]);
        let bt = bits[level];
        let mut left = vec![];
        let mut right = vec![];
        for (x, y) in cur.iter().zip(&sib) {
            let (x, y) = (*x, *y);
            let d = eval!(c, (bt) * ((y) - (x)));
            left.push(eval!(c, (x) + (d)));
            right.push(eval!(c, (y) - (d)));
        }
        let children = [left, right].concat();
        cur = match tree {
            Tree::Sponge => hash_batch(c, vec![(NODE, level as u32, children)]).concat(),
            Tree::Compress => {
                let mut st = children;
                st.extend(constants(c, &[TAG, 1, NODE1, level as u32]));
                compress_lanes(c, &[st]).concat()
            }
        };
    }
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
    let nf = hash_batch(c, vec![(NF, 0, [pnk, cms[0].clone(), vec![lo, hi]].concat())]).concat();
    // Published outputs: the first when active (always, for a split), the second when active
    // (fixed) or when the split leaves a remainder.
    let a1 = act[1];
    let g = [act[0], eval!(c, ((a1) * ((1) - (s))) + ((s) * (nz_r)))];
    let mut pub_cm = vec![];
    let mut pub_dl = vec![];
    for j in 0..2 {
        let gj = g[j];
        for word in cms[1 + j].clone() {
            pub_cm.push(eval!(c, (word) * (gj)));
        }
        for limb in dl[j].clone() {
            pub_dl.push(eval!(c, (limb) * (gj)));
        }
    }
    let data = guess_words(c, &felt_limbs(&public.data));
    let zero = c.zero();
    let mut limbs: Vec<Var> = [
        tag, context, cur, nf, pub_cm, pub_dl, w_rec, w_amt, controller, class, handle, cms[3].clone(), deadline,
        not_before, vec![index, kind], x, data,
    ]
    .concat();
    assert_eq!(limbs.len(), N_LIMBS);
    limbs.resize(4 * N_OUTPUTS, zero);
    limbs.chunks_exact(4).map(|q| from_partial_evals(c, q.try_into().unwrap())).collect()
}


// ---------------------------------------------------------------- fixtures

/// Which outcome a fixture settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Index 0: the refund (one output, the whole amount).
    Refund,
    /// A fixed outcome with two outputs.
    Settle,
    /// A fixed outcome with one output and a withdrawal.
    Withdraw,
    /// A split leaving a remainder.
    Split,
    /// A split of the whole amount (the second output is not published).
    SplitAll,
}

pub const SHAPES: [Shape; 5] = [Shape::Refund, Shape::Settle, Shape::Withdraw, Shape::Split, Shape::SplitAll];

fn random_digest(rng: &mut impl rand::RngCore) -> Digest {
    use rand::Rng;
    std::array::from_fn(|_| rng.gen_range(1..P))
}

fn random_felt(rng: &mut impl rand::RngCore) -> String {
    use rand::Rng;
    format!("0x{:x}", rng.gen_range(1u64..u64::MAX))
}

fn active_out(rng: &mut impl rand::RngCore, amount: u128) -> OutSpec {
    OutSpec { active: true, receiver: random_digest(rng), rho: random_digest(rng), amount, delivery: random_felt(rng) }
}

pub fn inactive_out() -> OutSpec {
    OutSpec { active: false, receiver: [0; 9], rho: [0; 9], amount: 0, delivery: "0x0".into() }
}

/// A fresh random policy of `amount` with a refund, a two-output settlement, a withdrawal and a
/// split, and a note settling the outcome `shape` names, in a sparse depth-32 tree.
pub fn fresh(tree: Tree, shape: Shape, rng: &mut impl rand::RngCore) -> (Public, Private, Policy) {
    use rand::Rng;
    let chain = "0x534e5f5345504f4c4941";
    let pool = random_felt(rng);
    let token = random_felt(rng);
    let amount: u128 = rng.gen_range(1000..u128::MAX / 4);
    let quarter = amount / 4;
    let fixed = |not_before: u64, outputs: [OutSpec; 2], w: (String, u128)| Outcome {
        kind: FIXED, not_before, outputs, withdrawal_recipient: w.0, withdrawal_amount: w.1,
    };
    let none = ("0x0".to_string(), 0);
    let refund = fixed(0, [active_out(rng, amount), inactive_out()], none.clone());
    let settle = fixed(rng.gen_range(0..1_000_000), [active_out(rng, amount - quarter), active_out(rng, quarter)], none.clone());
    let withdraw = fixed(0, [active_out(rng, amount - quarter), inactive_out()], (random_felt(rng), quarter));
    let split = Outcome {
        kind: SPLIT,
        not_before: 5,
        outputs: [active_out(rng, 0), active_out(rng, 0)],
        withdrawal_recipient: "0x0".into(),
        withdrawal_amount: 0,
    };
    let header = Header {
        controller: random_felt(rng),
        controller_class: random_felt(rng),
        handle: random_felt(rng),
        deadline: rng.gen_range(1_000_000..u64::MAX / 2),
        salt: random_digest(rng),
    };
    let policy = Policy { header, outcomes: [Some(refund), Some(settle), Some(withdraw), Some(split)] };
    let cap = random_digest(rng);
    let rho = random_digest(rng);
    let recv = receiver(&cap, &policy.digest());
    let cm = payment::commitment(&context_limbs(chain, &pool, &token), amount, &recv, &rho);
    let position = rng.next_u32();
    let siblings: Vec<Digest> = (0..DEPTH).map(|_| random_digest(rng)).collect();
    let _ = cm;
    let (index, x) = match shape {
        Shape::Refund => (0, 0),
        Shape::Settle => (1, 0),
        Shape::Withdraw => (2, 0),
        Shape::Split => (3, rng.gen_range(1..amount)),
        Shape::SplitAll => (3, amount),
    };
    let private = private_for(&policy, index, cap, rho, amount, position, siblings);
    let data = random_felt(rng);
    let public = statement(tree, chain, &pool, &token, x, &data, &private).expect("fresh witness is valid");
    (public, private, policy)
}
