//! Experimental R0 payment relation, V5 (`docs/account-bound-note-spec.md` §4): R0 V4 with
//! account-bound notes and a public expiry.
//!
//! Changes from V4 (`payment4.rs`), all normative in the spec:
//!
//! - **Account-bound receivers.** `ak_w = H(WAUTH, account ‖ sk)` (kind 16) replaces
//!   `ak = H(AUTH, sk)` in `receiver = H(OWNER, ak ‖ nk)`. One mode bit `m` per spend, shared by
//!   both inputs: `accountₗ · (1 − m) = 0` for every limb and `nonzero_vector_if(account, m)`, so
//!   `m = 1 ⇔ account ≠ 0`. Each input's `ak` is selected per word between `H(AUTH, sk)` and
//!   `H(WAUTH, account ‖ sk)`; both hashes are always computed. **The WAUTH input words are the
//!   published `account` variables** (S3).
//! - **Identity** (AB-M1): `handle = H(IDENTITY, ak₀ ‖ scope)` over input 0's selected key.
//! - **Public expiry:** `valid_until`, two 28-bit limbs, published verbatim. The circuit range-checks
//!   neither `account` nor `valid_until`; the bridge does ([`decode_statement`], [`bridge_checks`]).
//!
//! The statement is V4's 127 limbs, then `account` (9) and `valid_until` (2): 138 limbs padded
//! with two zero limbs to 140, emitted as 35 QM31 outputs. Outputs, conservation, the private
//! asset, the dummy input and the exit bit are V4's, unchanged.
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
    hash_batch, nonzero_vector, nonzero_vector_if, nullifier,
};
pub use crate::payment4::{Output, Shape, sparse_paths};
use crate::ro::guess_m31;

/// Hash kind of the account-bound authorization key (spec §3.1).
pub const WAUTH: u32 = 16;
/// 35 QM31 outputs: 138 statement limbs and two zero limbs.
pub const N_OUTPUTS: usize = 35;
/// Statement limbs before padding: V4's 127, `account` (9), `valid_until` (2).
pub const N_LIMBS: usize = 138;
/// `valid_until` is below 2^56 (two 28-bit limbs).
pub const VALID_UNTIL_BOUND: u64 = 1 << 56;

/// Statement tag: `TMPZ`, `R0V5`.
pub const STATEMENT_TAG: [u32; 2] = [0x544d_505a, 0x5230_5635];
/// Statement tag for [`Tree::Compress`]: `TMPZ`, `R0C5`.
pub const STATEMENT_TAG_COMPRESS: [u32; 2] = [0x544d_505a, 0x5230_4335];

pub fn statement_tag(tree: Tree) -> [u32; 2] {
    match tree {
        Tree::Sponge => STATEMENT_TAG,
        Tree::Compress => STATEMENT_TAG_COMPRESS,
    }
}

/// Whose authorization a spend needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `m = 0`: the Templar key alone; `account = 0`.
    Ordinary,
    /// `m = 1`: the Templar key and the account's signature (checked by the statement account).
    Bound,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Private {
    /// The spend's asset identifier (`0x` hex felt), shared by every note of the spend.
    pub token: String,
    /// The account both inputs are bound to (`0x` hex), or `0x0` for an ordinary spend.
    pub account: String,
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
    /// The bound account, `0x0` for an ordinary spend.
    pub account: String,
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

/// The 138 public limbs (padded with zeros to 140) in output order.
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
    x.extend(felt_limbs(&p.account));
    x.extend(valid_until_limbs(p.valid_until));
    debug_assert_eq!(x.len(), N_LIMBS);
    x.resize(4 * N_OUTPUTS, 0);
    x
}

// ---------------------------------------------------------------- native reference

/// Input `i`'s authorization key: `H(AUTH, sk)` for a zero account, else `H(WAUTH, account ‖ sk)`.
/// `account` is the nine words the circuit hashes (canonical limbs for an honest spend).
pub fn ak_of(account: &Digest, sk: &Digest) -> Digest {
    if account.iter().all(|w| *w == 0) { h(AUTH, 0, sk) } else { h(WAUTH, 0, &[account.as_slice(), sk].concat()) }
}

/// `(receiver, nk)` of a spending key, bound to `account` unless it is zero.
pub fn receiver_of(account: &Digest, sk: &Digest) -> (Digest, Digest) {
    let ak = ak_of(account, sk);
    let nk = h(NK, 0, sk);
    (h(OWNER, 0, &[ak, nk].concat()), nk)
}

/// The identity handle over a selected authorization key (AB-M1).
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
    let account = felt_limbs(&w.account);
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
        let (receiver, nk) = receiver_of(&account, &i.sk);
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
    let identity = if w.identity.active {
        identity_handle(&ak_of(&account, &w.inputs[0].sk), &w.identity.scope)
    } else {
        [0; 9]
    };
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
        account: w.account.clone(),
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

/// The R0 V5 bridge's own checks on a decoded statement (spec §5.1), which the circuit does not
/// enforce: V4's rules (nonzero context, addresses and the asset below 2^251, nonzero distinct
/// nullifiers, nonzero commitments and delivery digests, recipient ⇔ amount, the exit rule,
/// identity ⇒ intent), canonical felts (F15), the account below 2^251, and a nonzero
/// `valid_until` below 2^56. Mirrors `cairo-r5/bridge` (P3).
pub fn bridge_checks(p: &Public) -> Result<(), String> {
    let nonzero = |d: &Digest| d.iter().any(|v| *v != 0);
    let felts = [&p.chain, &p.pool, &p.token_out, &p.deliveries[0], &p.deliveries[1], &p.withdrawal_recipient, &p.intent, &p.account];
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
    if !below_2_251(&p.account) {
        return Err("account range".into());
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
    if limbs.len() != 9 {
        return Err("limb count".into());
    }
    if limbs.iter().any(|l| *l >= 1 << 28) {
        return Err("limb range".into());
    }
    let mut bits = vec![];
    for l in limbs {
        for k in 0..28 {
            bits.push((l >> k) & 1);
        }
    }
    let nibbles: Vec<u32> = bits.chunks(4).map(|c| c.iter().enumerate().map(|(k, b)| b << k).sum()).collect();
    let hex: String = nibbles.iter().rev().map(|n| std::char::from_digit(*n, 16).unwrap()).collect();
    let trimmed = hex.trim_start_matches('0');
    let out = format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed });
    if !canonical_felt(&out) {
        return Err("non-canonical felt".into());
    }
    Ok(out)
}

/// Decodes the 140 statement limbs exactly as the bridge does (spec §5.1) and applies
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
    if x[136..138].iter().any(|l| *l >= 1 << 28) {
        return Err("limb range".into());
    }
    if x[138..140].iter().any(|l| *l != 0) {
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
        account: felt(127)?,
        valid_until: x[136] as u64 | (x[137] as u64) << 28,
    };
    bridge_checks(&public)?;
    Ok(public)
}

/// A random bound account: just below 2^251 half the time, a small address otherwise.
pub fn random_account(rng: &mut impl RngCore) -> String {
    if rng.gen_bool(0.5) {
        format!("0x7{:062x}", rng.gen_range(1u64..u64::MAX))
    } else {
        format!("0x{:x}", rng.gen_range(1u64..u64::MAX))
    }
}

/// A fresh random V5 spend of `shape` in `mode` under a random asset.
pub fn fresh_shape(tree: Tree, shape: Shape, mode: Mode, rng: &mut impl RngCore) -> (Public, Private) {
    let chain = "0x534e5f5345504f4c4941";
    let pool = format!("0x{:x}", rng.gen_range(1u64..u64::MAX));
    let token = if rng.gen_bool(0.5) {
        format!("0x7{:062x}", rng.gen_range(1u64..u64::MAX))
    } else {
        format!("0x{:x}", rng.gen_range(1u64..u64::MAX))
    };
    let account = match mode {
        Mode::Ordinary => "0x0".to_string(),
        Mode::Bound => random_account(rng),
    };
    let account_words = felt_limbs(&account);
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
        .map(|i| commitment(&context, amounts[i], &receiver_of(&account_words, &sks[i]).0, &rhos[i]))
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
        account,
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

// ---------------------------------------------------------------- circuit

/// Test-only overrides of hint values (feature `tamper`), so tests can show that the constraints,
/// not the hint code, reject a malicious witness: the enable, exit and mode bits, raw `account`
/// and `valid_until` words (non-canonical limbs the honest encoders cannot produce), and raw bit
/// hints (F09) for one amount, one input's position and the identity flag. Each honest hint and
/// its override go through the same call, so a test exercises the constraint the honest path uses.
#[derive(Clone, Debug, Default)]
pub struct Tamper {
    pub e1: Option<u32>,
    pub x: Option<u32>,
    pub m: Option<u32>,
    pub account: Option<Digest>,
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

/// Records which variables a load-bearing wiring rule uses (feature `tamper`), so tests can check
/// the wiring itself (AB-M6): a mutant that guesses a copy passes every value test.
fn record<V: IValue>(c: &mut Context<V>, name: &str, vars: &[Var]) {
    if cfg!(feature = "tamper") {
        for (k, v) in vars.iter().enumerate() {
            c.debug_info.insert(format!("{name}.{k}"), *v);
        }
    }
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

/// The mode rules: `accountₗ · (1 − m) = 0` for every limb and `nonzero_vector_if(account, m)`.
/// With `m` boolean, `m = 1 ⇔ account ≠ 0`.
fn mode_rules<V: IValue>(c: &mut Context<V>, m: Var, m_value: u32, account: &[Var], account_values: &[u32]) {
    record(c, "mode.rules", &[m]);
    record(c, "mode.account", account);
    for l in account {
        let l = *l;
        let off = eval!(c, (l) * ((1) - (m)));
        assert_zero(c, off);
    }
    nonzero_vector_if(c, account, account_values, (m, m_value == 1));
}

/// `akₗ = aₗ + m · (wₗ − aₗ)` per word: `a` when `m = 0`, `w` when `m = 1`.
fn select<V: IValue>(c: &mut Context<V>, name: &str, m: Var, a: &[Var], w: &[Var]) -> Vec<Var> {
    record(c, name, &[m]);
    a.iter()
        .zip(w)
        .map(|(a, w)| {
            let (a, w) = (*a, *w);
            eval!(c, (a) + ((m) * ((w) - (a))))
        })
        .collect()
}

/// Builds R0 V5 and returns the 35 output variables (the public statement).
pub fn build<V: Lanes>(c: &mut Context<V>, tree: Tree, public: &Public, w: &Private) -> Vec<Var> {
    let t = tamper();
    let tag: Vec<Var> = statement_tag(tree).iter().map(|v| c.constant(M31::from(*v).into())).collect();
    let pub_ctx = guess_words(c, &[felt_limbs(&public.chain), felt_limbs(&public.pool)].concat());
    // The single private asset witness, nonzero; shared by all four commitments.
    let token_values = felt_limbs(&w.token);
    let token = guess_words(c, &token_values);
    nonzero_vector(c, &token, &token_values);
    let context = [pub_ctx.clone(), token.clone()].concat();
    // The account: nine words, created once, hashed by both WAUTH requests and published (S3).
    let account_values = t.account.unwrap_or_else(|| felt_limbs(&w.account));
    let account = guess_words(c, &account_values);
    // Mode: m·(m − 1) = 0 and the mode rules, so m = 1 ⇔ account ≠ 0. One m serves both inputs.
    // (The two rules already force m ∈ {0, 1}; the booleanity check is kept as the spec states it.)
    let m_value = t.m.unwrap_or(account_values.iter().any(|v| *v != 0) as u32);
    let m = bit(c, m_value);
    mode_rules(c, m, m_value, &account, &account_values);
    // Inputs: keys, randomness and positions as V4.
    let mut sk = vec![];
    let mut rho = vec![];
    let mut bits = vec![];
    for (k, i) in w.inputs.iter().enumerate() {
        let s = guess_words(c, &i.sk);
        nonzero_vector(c, &s, &i.sk);
        let r = guess_words(c, &i.rho);
        nonzero_vector(c, &r, &i.rho);
        sk.push(s);
        rho.push(r);
        bits.push(guess_bits_raw(c, &t.position(k, i.position)));
    }
    // Input 0 is real: range-checked, nonzero amount. Input 1: range-checked limbs and their sum;
    // a disabled input (e₁ = 0) has sum 0, hence amount 0.
    let amt0 = amount(c, w.inputs[0].amount);
    let (amt1, sum1) = amount_from_bits(c, &t.amount(1, w.inputs[1].amount));
    let e1 = bit(c, t.e1.unwrap_or(!w.dummy as u32));
    let idle = eval!(c, (sum1) * ((1) - (e1)));
    assert_zero(c, idle);
    // Outputs: always present, nonzero receiver and rho, range-checked amount that may be zero.
    let mut recv_out = vec![];
    let mut rho_out = vec![];
    let mut amt_out = vec![];
    for (j, o) in w.outputs.iter().enumerate() {
        let r = guess_words(c, &o.receiver);
        nonzero_vector(c, &r, &o.receiver);
        let q = guess_words(c, &o.rho);
        nonzero_vector(c, &q, &o.rho);
        let (amt, sum) = amount_from_bits(c, &t.amount(2 + j, o.amount));
        c.mark_as_maybe_unused(&sum);
        recv_out.push(r);
        rho_out.push(q);
        amt_out.push(amt);
    }
    let keys = hash_batch(c, vec![(AUTH, 0, sk[0].clone()), (NK, 0, sk[0].clone()), (AUTH, 0, sk[1].clone()), (NK, 0, sk[1].clone())]);
    let (nk0, nk1) = (keys[1].clone(), keys[3].clone());
    // Both WAUTH hashes, always computed, beside the output INNER hashes (all 22-word frames).
    let wauth0 = [account.clone(), sk[0].clone()].concat();
    let wauth1 = [account.clone(), sk[1].clone()].concat();
    record(c, "account.wauth0", &wauth0[..9]);
    record(c, "account.wauth1", &wauth1[..9]);
    let b = hash_batch(c, vec![
        (WAUTH, 0, wauth0),
        (WAUTH, 0, wauth1),
        (INNER, 0, [recv_out[0].clone(), rho_out[0].clone()].concat()),
        (INNER, 0, [recv_out[1].clone(), rho_out[1].clone()].concat()),
    ]);
    // Each input's key, selected per word by the shared m.
    let ak0 = select(c, "mode.select0", m, &keys[0], &b[0]);
    let ak1 = select(c, "mode.select1", m, &keys[2], &b[1]);
    // The identity handle over input 0's selected key (AB-M1), batched with the receivers.
    let id_active = guess_bits_raw(c, &[t.identity_flag.unwrap_or(w.identity.active as u32)])[0];
    let scope = guess_words(c, &w.identity.scope);
    let owner0 = [ak0.clone(), nk0.clone()].concat();
    let id_payload = [ak0, scope].concat();
    record(c, "ak0.owner", &owner0[..9]);
    record(c, "ak0.identity", &id_payload[..9]);
    let owners = hash_batch(c, vec![
        (OWNER, 0, owner0),
        (OWNER, 0, [ak1, nk1.clone()].concat()),
        (IDENTITY, 0, id_payload),
    ]);
    let inner_in = hash_batch(c, vec![
        (INNER, 0, [owners[0].clone(), rho[0].clone()].concat()),
        (INNER, 0, [owners[1].clone(), rho[1].clone()].concat()),
    ]);
    let note = |ctxv: &[Var], amt: &[Var], inner: &[Var]| (NOTE, 0, [ctxv.to_vec(), amt.to_vec(), inner.to_vec()].concat());
    let cms = hash_batch(c, vec![
        note(&context, &amt0, &inner_in[0]),
        note(&context, &amt1, &inner_in[1]),
        note(&context, &amt_out[0], &b[2]),
        note(&context, &amt_out[1], &b[3]),
    ]);
    // Both membership paths, level by level, as V4.
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
    let (withdrawn, withdrawn_sum) = amount_from_bits(c, &t.amount(4, public.withdrawal_amount));
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
    let identity: Vec<Var> = owners[2].iter().map(|word| eval!(c, (*word) * (id_active))).collect();
    let valid_until = guess_words(c, &t.valid_until.unwrap_or_else(|| valid_until_limbs(public.valid_until)));
    let zero = c.zero();
    let mut limbs: Vec<Var> =
        [tag, pub_ctx, token_out, cur[0].clone(), nfs, outs, recipient, withdrawn, intent, identity, account, valid_until]
            .concat();
    record(c, "account.published", &limbs[127..136]);
    limbs.resize(4 * N_OUTPUTS, zero);
    limbs.chunks_exact(4).map(|q| from_partial_evals(c, q.try_into().unwrap())).collect()
}
