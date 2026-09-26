//! R0 payment relation, V6 (`docs/pool-v3-spec.md` §3–§4): R0 V5 with the mode fixed to ordinary.
//! No mode bit, no `WAUTH`, no published account (ADR-0027).
//!
//! Changes from V5 (`payment5.rs`), all normative in the spec:
//!
//! - **Keys.** For both inputs `ak = H(AUTH, sk)` and `nk = H(NK, sk)`, computed in the circuit from
//!   the same guessed `sk`; `receiver = H(OWNER, ak ‖ nk)`.
//! - **Identity** (load-bearing): `handle = H(IDENTITY, ak₀ ‖ scope)`, whose first nine payload
//!   words are the output variables of input 0's `H(AUTH, sk₀)`, the same variables `OWNER₀`
//!   reads. A guessed copy would let anyone who knows a victim's `ak` publish the victim's handle
//!   (spec §4.3), so the wiring test checks the variables themselves.
//! - **Statement:** V5's without the account: 129 limbs (V4's 127 and `valid_until`), padded with
//!   three zero limbs to 132 and emitted as 33 QM31 outputs. Tags `R0V6` and `R0C6`.
//!
//! The circuit is V5's with the account guess, the mode bit and its rules, the two `WAUTH` hashes
//! and the per-word selects deleted. Everything else (outputs, conservation, the private asset, the
//! dummy input, the exit bit, the membership paths and the batch order) is unchanged. The circuit
//! range-checks `valid_until` no more than V5 did; the bridge does ([`decode_statement`],
//! [`bridge_checks`]).
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::IValue;
use circuits::ops::{eq, from_partial_evals};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use stwo::core::fields::m31::M31;

use crate::membership::{Lanes, compress_lanes};
use crate::merkle::guess_bits_raw;
use crate::payment::{
    AUTH, DEPTH, Digest, IDENTITY, INNER, Identity, Input, NF, NK, NODE, NODE1, NOTE, OWNER, P, TAG, Tree,
    amount, amount_bits, amount_from_bits, amount_limbs, climb, commitment, conservation, felt_limbs, guess_words, h,
    hash_batch, nonzero_vector, nullifier,
};
pub use crate::payment4::{Output, Shape, sparse_paths};
use crate::ro::guess_m31;

/// 33 QM31 outputs: 129 statement limbs and three zero limbs.
pub const N_OUTPUTS: usize = 33;
/// Statement limbs before padding: V4's 127 and `valid_until` (2).
pub const N_LIMBS: usize = 129;
/// `valid_until` is below 2^56 (two 28-bit limbs).
pub const VALID_UNTIL_BOUND: u64 = 1 << 56;
/// Offset of `valid_until`'s two limbs (spec §3, the limb map φ).
pub const VALID_UNTIL_AT: usize = 127;

/// Statement tag: `TMPZ`, `R0V6`.
pub const STATEMENT_TAG: [u32; 2] = [0x544d_505a, 0x5230_5636];
/// Statement tag for [`Tree::Compress`]: `TMPZ`, `R0C6`.
pub const STATEMENT_TAG_COMPRESS: [u32; 2] = [0x544d_505a, 0x5230_4336];

pub fn statement_tag(tree: Tree) -> [u32; 2] {
    match tree {
        Tree::Sponge => STATEMENT_TAG,
        Tree::Compress => STATEMENT_TAG_COMPRESS,
    }
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
    /// The last block at which the pool accepts the spend; nonzero, below 2^56.
    pub valid_until: u64,
}

fn is_zero_felt(hex: &str) -> bool {
    felt_limbs(hex).iter().all(|l| *l == 0)
}

/// `valid_until` as two 28-bit little-endian limbs.
pub fn valid_until_limbs(v: u64) -> [u32; 2] {
    assert!(v < VALID_UNTIL_BOUND, "valid_until exceeds 56 bits");
    [(v & 0xfff_ffff) as u32, (v >> 28) as u32]
}

/// The 129 public limbs (padded with zeros to 132) in output order.
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
    x.extend(valid_until_limbs(p.valid_until));
    debug_assert_eq!(x.len(), N_LIMBS);
    x.resize(4 * N_OUTPUTS, 0);
    x
}

// ---------------------------------------------------------------- native reference

/// The authorization key `ak = H(AUTH, sk)`.
pub fn ak_of(sk: &Digest) -> Digest {
    h(AUTH, 0, sk)
}

/// `(receiver, nk)` of a spending key: `H(OWNER, H(AUTH, sk) ‖ H(NK, sk))` and `H(NK, sk)`.
pub fn receiver_of(sk: &Digest) -> (Digest, Digest) {
    let nk = h(NK, 0, sk);
    (h(OWNER, 0, &[ak_of(sk), nk].concat()), nk)
}

/// The identity handle `H(IDENTITY, ak₀ ‖ scope)` (ADR-0027, amending ADR-0023).
pub fn identity_handle(ak: &Digest, scope: &Digest) -> Digest {
    h(IDENTITY, 0, &[ak.as_slice(), scope].concat())
}

/// The public statement the circuit proves for a witness, or an error naming the first witness
/// rule the circuit rejects. The circuit also admits statements the bridge rejects (see
/// [`bridge_checks`]): a spend is valid only if the bridge also accepts its statement.
#[allow(clippy::too_many_arguments)]
pub fn statement(
    tree: Tree,
    chain: &str,
    pool: &str,
    deliveries: [String; 2],
    withdrawal: (String, u128),
    intent: &str,
    valid_until: u64,
    w: &Private,
) -> Result<Public, String> {
    let nonzero = |d: &Digest| d.iter().any(|v| *v != 0);
    let canonical = |d: &Digest| d.iter().all(|v| *v < P);
    if is_zero_felt(&w.token) {
        return Err("zero asset".into());
    }
    if valid_until >= VALID_UNTIL_BOUND {
        return Err("valid_until encoding".into());
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
    let identity = if w.identity.active { identity_handle(&ak_of(&w.inputs[0].sk), &w.identity.scope) } else { [0; 9] };
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
        valid_until,
    })
}

/// A `0x` hex felt below 2^251.
fn below_2_251(hex: &str) -> bool {
    let digits = hex.trim_start_matches("0x").trim_start_matches('0');
    digits.len() < 63 || (digits.len() == 63 && digits.chars().next().unwrap().to_digit(16).unwrap() < 8)
}

/// The Stark field prime `2^251 + 17·2^192 + 1` as 63 hex digits.
const FELT_PRIME_HEX: &str = "800000000000011000000000000000000000000000000000000000000000001";

/// A `0x` hex value below the Stark field prime (a canonical felt252, F15).
fn canonical_felt(hex: &str) -> bool {
    let digits = hex.trim_start_matches("0x").trim_start_matches('0').to_ascii_lowercase();
    digits.len() < 63 || (digits.len() == 63 && digits.as_str() < FELT_PRIME_HEX)
}

/// The R0 V6 bridge's own checks on a decoded statement (spec §5.1), which the circuit does not
/// enforce: V4's rules (nonzero context, addresses and the asset below 2^251, nonzero distinct
/// nullifiers, nonzero commitments and delivery digests, recipient ⇔ amount, the exit rule,
/// identity ⇒ intent), canonical felts (F15), and a nonzero `valid_until` below 2^56. Mirrors
/// `cairo-r6/bridge`.
pub fn bridge_checks(p: &Public) -> Result<(), String> {
    let nonzero = |d: &Digest| d.iter().any(|v| *v != 0);
    let felts = [&p.chain, &p.pool, &p.token_out, &p.deliveries[0], &p.deliveries[1], &p.withdrawal_recipient, &p.intent];
    if felts.iter().any(|f| !canonical_felt(f)) {
        return Err("non-canonical felt".into());
    }
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
    if p.valid_until == 0 {
        return Err("valid_until".into());
    }
    if p.valid_until >= VALID_UNTIL_BOUND {
        return Err("valid_until range".into());
    }
    Ok(())
}

/// Nine 28-bit little-endian limbs as `0x` hex, or the bridge's reason for rejecting them:
/// every limb below 2^28 and the value below the field prime (`felt_from_limbs`).
pub fn felt_from_limbs(limbs: &[u32]) -> Result<String, String> {
    crate::payment5::felt_from_limbs(limbs)
}

/// Decodes the 132 statement limbs exactly as the bridge does (spec §5.1) and applies
/// [`bridge_checks`]: the tag, distinct nullifiers, canonical felts, 16-bit amount limbs,
/// 28-bit `valid_until` limbs and zero padding (and every limb below the M31 prime).
pub fn decode_statement(tree: Tree, x: &[u32]) -> Result<Public, String> {
    if x.len() != 4 * N_OUTPUTS {
        return Err("output count".into());
    }
    // Every limb is an M31 coordinate of a QM31 output, so below p (the Cairo bridge reads them
    // from reduced QM31 values; this mirror takes raw limbs, so it checks).
    if x.iter().any(|l| *l >= P) {
        return Err("M31 range".into());
    }
    if x[..2] != statement_tag(tree) {
        return Err("statement tag".into());
    }
    let digest = |at: usize| -> Digest { x[at..at + 9].try_into().unwrap() };
    let (nf0, nf1) = (digest(38), digest(47));
    if nf0 == nf1 {
        return Err("duplicate nullifier".into());
    }
    if x[101..109].iter().any(|l| *l >= 1 << 16) {
        return Err("amount limb range".into());
    }
    if x[VALID_UNTIL_AT..VALID_UNTIL_AT + 2].iter().any(|l| *l >= 1 << 28) {
        return Err("limb range".into());
    }
    if x[N_LIMBS..4 * N_OUTPUTS].iter().any(|l| *l != 0) {
        return Err("statement padding".into());
    }
    let felt = |at: usize| felt_from_limbs(&x[at..at + 9]);
    let public = Public {
        chain: felt(2)?,
        pool: felt(11)?,
        token_out: felt(20)?,
        root: digest(29),
        nullifiers: [nf0, nf1],
        commitments: [digest(56), digest(74)],
        deliveries: [felt(65)?, felt(83)?],
        withdrawal_recipient: felt(92)?,
        withdrawal_amount: (0..8).map(|k| (x[101 + k] as u128) << (16 * k)).sum(),
        intent: felt(109)?,
        identity: digest(118),
        valid_until: x[VALID_UNTIL_AT] as u64 | (x[VALID_UNTIL_AT + 1] as u64) << 28,
    };
    bridge_checks(&public)?;
    Ok(public)
}

/// A fresh random V6 spend of `shape` under a random asset.
pub fn fresh_shape(tree: Tree, shape: Shape, rng: &mut impl RngCore) -> (Public, Private) {
    let chain = "0x534e5f5345504f4c4941";
    let pool = format!("0x{:x}", rng.gen_range(1u64..u64::MAX));
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
    let leaves: Vec<Digest> = (0..2).map(|i| commitment(&context, amounts[i], &receiver_of(&sks[i]).0, &rhos[i])).collect();
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
    let valid_until = rng.gen_range(1..VALID_UNTIL_BOUND);
    let public = statement(tree, chain, &pool, deliveries, withdrawal, &intent, valid_until, &private)
        .expect("fresh witness is valid");
    bridge_checks(&public).expect("fresh statement passes the bridge");
    (public, private)
}

/// The V5-ordinary witness with the same values (the account zero), for the cross-version tests
/// (spec §3, equivalence).
pub fn to_v5(w: &Private) -> crate::payment5::Private {
    crate::payment5::Private {
        token: w.token.clone(),
        account: "0x0".into(),
        inputs: w.inputs.clone(),
        dummy: w.dummy,
        outputs: w.outputs.clone(),
        identity: w.identity.clone(),
    }
}

/// The limb map φ (spec §3): V5's 140 limbs to V6's 132. Deletes the account limbs (127–135),
/// moves `valid_until` (136–137) to 127–128, and swaps the tag for `tag6`.
pub fn phi(v5_limbs: &[u32], tag6: [u32; 2]) -> Vec<u32> {
    assert_eq!(v5_limbs.len(), 4 * crate::payment5::N_OUTPUTS);
    let mut x = tag6.to_vec();
    x.extend(&v5_limbs[2..127]);
    x.extend(&v5_limbs[136..138]);
    x.resize(4 * N_OUTPUTS, 0);
    x
}

// ---------------------------------------------------------------- circuit

/// Test-only overrides of hint values (feature `tamper`), so tests can show that the constraints,
/// not the hint code, reject a malicious witness: the enable and exit bits, raw `valid_until`
/// words (non-canonical limbs the honest encoders cannot produce), and raw bit hints (F09) for one
/// amount, one input's position and the identity flag. Each honest hint and its override go through
/// the same call, so a test exercises the constraint the honest path uses.
#[derive(Clone, Debug, Default)]
pub struct Tamper {
    pub e1: Option<u32>,
    pub x: Option<u32>,
    pub valid_until: Option<[u32; 2]>,
    /// `(slot, bits)`: slot 1 is input 1, slots 2 and 3 the outputs, slot 4 the withdrawal.
    pub amount_bits: Option<(usize, [[u32; 16]; 8])>,
    /// `(input, bits)`: the input's 32 position bits.
    pub position_bits: Option<(usize, [u32; 32])>,
    pub identity_flag: Option<u32>,
}

impl Tamper {
    fn amount(&self, slot: usize, a: u128) -> [[u32; 16]; 8] {
        match self.amount_bits {
            Some((s, bits)) if s == slot => bits,
            _ => amount_bits(a),
        }
    }

    fn position(&self, input: usize, position: u32) -> [u32; 32] {
        match self.position_bits {
            Some((i, bits)) if i == input => bits,
            _ => std::array::from_fn(|k| (position >> k) & 1),
        }
    }
}

thread_local! {
    pub static TAMPER: std::cell::RefCell<Tamper> = std::cell::RefCell::new(Tamper::default());
}

fn tamper() -> Tamper {
    if cfg!(feature = "tamper") { TAMPER.with(|t| t.borrow().clone()) } else { Tamper::default() }
}

/// Records the variables of one wire under `name.k` (feature `tamper`), so the wiring test can
/// compare variable ids (spec §4.4, MR-V6-1): a mutant that guesses a copy passes every value
/// test. It changes nothing in the circuit.
fn record<V: IValue>(c: &mut Context<V>, name: &str, vars: &[Var]) {
    if cfg!(feature = "tamper") {
        for (k, v) in vars.iter().enumerate() {
            c.debug_info.insert(format!("{name}.{k}"), *v);
        }
    }
}

/// [`hash_batch`], recording each request's payload as `{name}.{i}.in` and its digest as
/// `{name}.{i}.out`, where `i` is the request index within the batch.
fn hashes<V: Lanes>(c: &mut Context<V>, name: &str, requests: Vec<(u32, u32, Vec<Var>)>) -> Vec<Vec<Var>> {
    let payloads: Vec<Vec<Var>> = requests.iter().map(|r| r.2.clone()).collect();
    let out = hash_batch(c, requests);
    for (i, (p, o)) in payloads.iter().zip(&out).enumerate() {
        record(c, &format!("{name}.{i}.in"), p);
        record(c, &format!("{name}.{i}.out"), o);
    }
    out
}

/// A guessed bit: `b·(b − 1) = 0`.
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

// Each consumer below records the variables it actually receives, inside the call, so no
// statement can stand between a recorded wire and its use (spec §4.4, the wiring test).

/// `Σ bᵢ·2^i` over `bits`, recording the bits it reads as `{name}.bits` and its output as `{name}.out`.
fn pack<V: IValue>(c: &mut Context<V>, name: &str, bits: &[Var]) -> Var {
    record(c, &format!("{name}.bits"), bits);
    let mut v = c.zero();
    for (k, b) in bits.iter().enumerate() {
        let w = c.constant(M31::from(1u32 << k).into());
        v = eval!(c, (v) + ((*b) * (w)));
    }
    record(c, &format!("{name}.out"), &[v]);
    v
}

/// `sum₁ · (1 − e₁) = 0`: a disabled input 1 carries nothing.
fn idle<V: IValue>(c: &mut Context<V>, sum1: Var, e1: Var) {
    record(c, "use.e1.idle", &[e1]);
    record(c, "use.idle.sum1", &[sum1]);
    let idle = eval!(c, (sum1) * ((1) - (e1)));
    assert_zero(c, idle);
}

/// `e₁ · (b − a) = 0` per word: an enabled input 1 reaches the published root `a`.
fn reaches<V: IValue>(c: &mut Context<V>, e1: Var, root: &[Var], other: &[Var]) {
    record(c, "use.e1.gap", &[e1]);
    record(c, "use.gap.root", root);
    record(c, "use.gap.other", other);
    for (a, b) in root.iter().zip(other) {
        let (a, b) = (*a, *b);
        let gap = eval!(c, (e1) * ((b) - (a)));
        assert_zero(c, gap);
    }
}

/// Conservation over the amounts it receives, recorded as `conservation.*`.
fn conserve<V: IValue>(c: &mut Context<V>, ins: [&[Var]; 2], outs: [&[Var]; 3], in_values: [u128; 2], out_values: [u128; 3]) {
    record(c, "conservation.in0", ins[0]);
    record(c, "conservation.in1", ins[1]);
    record(c, "conservation.out0", outs[0]);
    record(c, "conservation.out1", outs[1]);
    record(c, "conservation.withdrawn", outs[2]);
    conservation(c, &ins, &outs, &in_values, &out_values);
}

/// `(1 − x) · l = 0` for every limb of the withdrawal and the intent: any exit forces `x = 1`.
fn exits<V: IValue>(c: &mut Context<V>, x: Var, withdrawn: &[Var], intent: &[Var]) {
    record(c, "use.x.hidden", &[x]);
    record(c, "xgate.withdrawn", withdrawn);
    record(c, "xgate.intent", intent);
    for l in withdrawn.iter().chain(intent) {
        let l = *l;
        let hidden = eval!(c, (l) * ((1) - (x)));
        assert_zero(c, hidden);
    }
}

/// `token_out = x · token`, recording its output as `token_out.out`.
fn reveal<V: IValue>(c: &mut Context<V>, token: &[Var], x: Var) -> Vec<Var> {
    record(c, "token_out.token", token);
    record(c, "use.x.token_out", &[x]);
    let out: Vec<Var> = token.iter().map(|l| eval!(c, (*l) * (x))).collect();
    record(c, "token_out.out", &out);
    out
}

/// The published identity: the handle masked by the identity flag, recorded as `identity.masked`.
fn mask<V: IValue>(c: &mut Context<V>, handle: &[Var], flag: Var) -> Vec<Var> {
    record(c, "identity.handle", handle);
    record(c, "use.identity_flag", &[flag]);
    let out: Vec<Var> = handle.iter().map(|word| eval!(c, (*word) * (flag))).collect();
    record(c, "identity.masked", &out);
    out
}

/// A guessed nonzero word vector, recorded before its guard reads it (NF-M2).
fn guess_nonzero<V: IValue>(c: &mut Context<V>, name: &str, values: &[u32]) -> Vec<Var> {
    let v = guess_words(c, values);
    record(c, name, &v);
    nonzero_vector(c, &v, values);
    v
}

/// Guessed bits, recorded where they are made.
fn guess_bits_rec<V: IValue>(c: &mut Context<V>, name: &str, values: &[u32]) -> Vec<Var> {
    let b = guess_bits_raw(c, values);
    record(c, name, &b);
    b
}

/// A guessed bit, recorded where it is made.
fn bit_rec<V: IValue>(c: &mut Context<V>, name: &str, value: u32) -> Var {
    let b = bit(c, value);
    record(c, name, &[b]);
    b
}

/// Range-checked amount limbs and their sum, recorded where `amount_from_bits` returns them
/// (NF-M1): `{name}` and `{name}.sum`.
fn amount_rec<V: IValue>(c: &mut Context<V>, name: &str, bits: &[[u32; 16]; 8]) -> (Vec<Var>, Var) {
    let (limbs, sum) = amount_from_bits(c, bits);
    record(c, name, &limbs);
    record(c, &format!("{name}.sum"), &[sum]);
    (limbs, sum)
}

/// Input 0's range-checked, nonzero amount limbs, recorded where they are made (`amount.in0`).
fn amount_in0<V: IValue>(c: &mut Context<V>, value: u128) -> Vec<Var> {
    let limbs = amount(c, value);
    record(c, "amount.in0", &limbs);
    limbs
}

/// The published limbs, recorded where they become the circuit's outputs (NF-M1).
fn publish<V: IValue>(c: &mut Context<V>, mut limbs: Vec<Var>) -> Vec<Var> {
    record(c, "published", &limbs);
    let zero = c.zero();
    limbs.resize(4 * N_OUTPUTS, zero);
    // Each output's four limbs, recorded as they are handed to the gate (ADV-RC-1).
    limbs
        .chunks_exact(4)
        .enumerate()
        .map(|(k, q)| {
            record(c, &format!("publish.chunk{k}"), q);
            from_partial_evals(c, q.try_into().unwrap())
        })
        .collect()
}

/// One membership level's request for path `p`: the current node and its sibling, ordered by the
/// position bit. Records the node it reads (`path{p}.level{l}.in`) and the bit (`path{p}.bit{l}`).
fn level_request<V: IValue>(c: &mut Context<V>, p: usize, level: usize, cur: &[Var], sib: &[Var], bit: Var) -> Vec<Var> {
    record(c, &format!("path{p}.level{level}.in"), cur);
    record(c, &format!("path{p}.bit{level}"), &[bit]);
    let mut left = vec![];
    let mut right = vec![];
    for (x, y) in cur.iter().zip(sib) {
        let (x, y) = (*x, *y);
        let d = eval!(c, (bit) * ((y) - (x)));
        left.push(eval!(c, (x) + (d)));
        right.push(eval!(c, (y) - (d)));
    }
    let req = [left, right].concat();
    record(c, &format!("path{p}.level{level}.req"), &req);
    req
}

/// Hashes one membership level of both paths (`NODE` in the sponge tree, `NODE1` compressions in
/// the compress tree), recording each output as `path{p}.level{l}.out`.
fn level_hash<V: Lanes>(c: &mut Context<V>, tree: Tree, level: usize, reqs: Vec<Vec<Var>>) -> Vec<Vec<Var>> {
    // The payload each path's hash reads (NF-M1).
    for (p, req) in reqs.iter().enumerate() {
        record(c, &format!("path{p}.level{level}.payload"), req);
    }
    // The exact words each hash is handed, recorded next to the call (ADV-RC-1): the NODE payload,
    // and in the compress tree the payload with its domain constants (ADV-RC-3).
    let next = match tree {
        Tree::Sponge => {
            let requests: Vec<_> = reqs.into_iter().map(|x| (NODE, level as u32, x)).collect();
            for (p, (_, _, x)) in requests.iter().enumerate() {
                record(c, &format!("path{p}.level{level}.state"), x);
            }
            hash_batch(c, requests)
        }
        Tree::Compress => {
            let states = reqs
                .into_iter()
                .map(|x| {
                    let mut st = x;
                    st.extend([TAG, 1, NODE1, level as u32].iter().map(|v| c.constant(M31::from(*v).into())));
                    st
                })
                .collect::<Vec<_>>();
            for (p, st) in states.iter().enumerate() {
                record(c, &format!("path{p}.level{level}.state"), st);
            }
            compress_lanes(c, &states)
        }
    };
    for (p, out) in next.iter().enumerate() {
        record(c, &format!("path{p}.level{level}.out"), out);
    }
    next
}

/// Builds R0 V6 and returns the 33 output variables (the public statement).
pub fn build<V: Lanes>(c: &mut Context<V>, tree: Tree, public: &Public, w: &Private) -> Vec<Var> {
    let t = tamper();
    let tag: Vec<Var> = statement_tag(tree).iter().map(|v| c.constant(M31::from(*v).into())).collect();
    let pub_ctx = guess_words(c, &[felt_limbs(&public.chain), felt_limbs(&public.pool)].concat());
    record(c, "guess.pub_ctx", &pub_ctx);
    // The single private asset witness, nonzero; shared by all four commitments.
    let token_values = felt_limbs(&w.token);
    let token = guess_nonzero(c, "guess.token", &token_values);
    let context = [pub_ctx.clone(), token.clone()].concat();
    // Inputs: keys, randomness and positions as V4.
    let mut sk = vec![];
    let mut rho = vec![];
    let mut bits = vec![];
    for (k, i) in w.inputs.iter().enumerate() {
        let s = guess_nonzero(c, &format!("guess.sk{k}"), &i.sk);
        let r = guess_nonzero(c, &format!("guess.rho{k}"), &i.rho);
        let b = guess_bits_rec(c, &format!("guess.position{k}"), &t.position(k, i.position));
        sk.push(s);
        rho.push(r);
        bits.push(b);
    }
    // Input 0 is real: range-checked, nonzero amount. Input 1: range-checked limbs and their sum;
    // a disabled input (e₁ = 0) has sum 0, hence amount 0.
    let amt0 = amount_in0(c, w.inputs[0].amount);
    let (amt1, sum1) = amount_rec(c, "amount.in1", &t.amount(1, w.inputs[1].amount));
    let e1 = bit_rec(c, "guess.e1", t.e1.unwrap_or(!w.dummy as u32));
    idle(c, sum1, e1);
    // Outputs: always present, nonzero receiver and rho, range-checked amount that may be zero.
    let mut recv_out = vec![];
    let mut rho_out = vec![];
    let mut amt_out = vec![];
    for (j, o) in w.outputs.iter().enumerate() {
        let r = guess_nonzero(c, &format!("guess.recv_out{j}"), &o.receiver);
        let q = guess_nonzero(c, &format!("guess.rho_out{j}"), &o.rho);
        let (amt, sum) = amount_rec(c, &format!("amount.out{j}"), &t.amount(2 + j, o.amount));
        c.mark_as_maybe_unused(&sum);
        recv_out.push(r);
        rho_out.push(q);
        amt_out.push(amt);
    }
    // Keys: AUTH and NK over the same guessed sk, per input (spec §4.3, rule 1).
    let keys = hashes(c, "keys", vec![(AUTH, 0, sk[0].clone()), (NK, 0, sk[0].clone()), (AUTH, 0, sk[1].clone()), (NK, 0, sk[1].clone())]);
    let (ak0, nk0, ak1, nk1) = (keys[0].clone(), keys[1].clone(), keys[2].clone(), keys[3].clone());
    let b = hashes(c, "inner_out", vec![
        (INNER, 0, [recv_out[0].clone(), rho_out[0].clone()].concat()),
        (INNER, 0, [recv_out[1].clone(), rho_out[1].clone()].concat()),
    ]);
    // The identity handle over input 0's ak (spec §4.3, rule 2): the AUTH₀ output variables
    // themselves, the same ones OWNER₀ reads. Batched with the receivers.
    let id_active = guess_bits_rec(c, "guess.identity_flag", &[t.identity_flag.unwrap_or(w.identity.active as u32)])[0];
    let scope = guess_words(c, &w.identity.scope);
    let owners = hashes(c, "owners", vec![
        (OWNER, 0, [ak0.clone(), nk0.clone()].concat()),
        (OWNER, 0, [ak1, nk1.clone()].concat()),
        (IDENTITY, 0, [ak0, scope].concat()),
    ]);
    let inner_in = hashes(c, "inner_in", vec![
        (INNER, 0, [owners[0].clone(), rho[0].clone()].concat()),
        (INNER, 0, [owners[1].clone(), rho[1].clone()].concat()),
    ]);
    let note = |ctxv: &[Var], amt: &[Var], inner: &[Var]| (NOTE, 0, [ctxv.to_vec(), amt.to_vec(), inner.to_vec()].concat());
    let cms = hashes(c, "notes", vec![
        note(&context, &amt0, &inner_in[0]),
        note(&context, &amt1, &inner_in[1]),
        note(&context, &amt_out[0], &b[0]),
        note(&context, &amt_out[1], &b[1]),
    ]);
    // Both membership paths, level by level, as V4.
    let mut cur = [cms[0].clone(), cms[1].clone()];
    for (p, leaf) in cur.iter().enumerate() {
        record(c, &format!("path{p}.leaf"), leaf);
    }
    for level in 0..DEPTH {
        let mut reqs = vec![];
        for p in 0..2 {
            let sib = guess_words(c, &w.inputs[p].siblings[level]);
            reqs.push(level_request(c, p, level, &cur[p], &sib, bits[p][level]));
        }
        let next = level_hash(c, tree, level, reqs);
        cur = [next[0].clone(), next[1].clone()];
    }
    record(c, "path0.root", &cur[0]);
    record(c, "path1.root", &cur[1]);
    // cur₀ is the published root; an enabled input 1 must reach it.
    reaches(c, e1, &cur[0], &cur[1]);
    let mut nf_reqs = vec![];
    for (p, nk) in [nk0, nk1].into_iter().enumerate() {
        let lo = pack(c, &format!("pack{p}.lo"), &bits[p][..16]);
        let hi = pack(c, &format!("pack{p}.hi"), &bits[p][16..]);
        nf_reqs.push((NF, 0, [nk, cms[p].clone(), vec![lo, hi]].concat()));
    }
    let nfs = hashes(c, "nf", nf_reqs).concat();
    // Outputs, unmasked; delivery digests carried (the bridge requires them nonzero).
    let mut outs: Vec<Var> = vec![];
    for j in 0..2 {
        outs.extend(cms[2 + j].clone());
        outs.extend(guess_words(c, &felt_limbs(&public.deliveries[j])));
    }
    let recipient = guess_words(c, &felt_limbs(&public.withdrawal_recipient));
    let (withdrawn, withdrawn_sum) = amount_rec(c, "amount.withdrawn", &t.amount(4, public.withdrawal_amount));
    c.mark_as_maybe_unused(&withdrawn_sum);
    conserve(
        c,
        [&amt0, &amt1],
        [&amt_out[0], &amt_out[1], &withdrawn],
        [w.inputs[0].amount, w.inputs[1].amount],
        [w.outputs[0].amount, w.outputs[1].amount, public.withdrawal_amount],
    );
    let intent = guess_words(c, &felt_limbs(&public.intent));
    // Exit reveal: any withdrawal or intent forces x = 1, and token_out = x · token.
    let exit = public.withdrawal_amount != 0 || !is_zero_felt(&public.intent);
    let x = bit_rec(c, "guess.x", t.x.unwrap_or(exit as u32));
    exits(c, x, &withdrawn, &intent);
    let token_out = reveal(c, &token, x);
    let identity = mask(c, &owners[2], id_active);
    let valid_until = guess_words(c, &t.valid_until.unwrap_or_else(|| valid_until_limbs(public.valid_until)));
    publish(c, [tag, pub_ctx, token_out, cur[0].clone(), nfs, outs, recipient, withdrawn, intent, identity, valid_until].concat())
}
