//! Spends (spec §7.2, §7.3): note selection, outputs, dummies and the sticky companion dummy
//! input, the statement and the bridge's checks, the binding and the pool calldata, and the client
//! proof. Every choice uses the core's CSPRNG.
//!
//! Two relations: R0 V4 for pool V2, and R0 V5 for pool V3 (`docs/account-bound-note-spec.md`),
//! which adds a public `valid_until` and, for a bound wallet, the account both inputs are bound to.
//! The keys come from a [`KeySource`]: the Templar wallet's seed (never bound) or a bound wallet's.
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use templar_client_verifier_circuit::payment::{DEPTH, Identity, Input};
use templar_client_verifier_circuit::payment4::{self, Output};
use templar_client_verifier_circuit::payment5;
use templar_client_verifier_circuit::prove::{self, R4, R5, TREE};

use crate::address::Address;
use crate::felt::{self, Felt32};
use crate::keys::{Account, BoundWallet, Seed};
use crate::note;
use crate::sealbox;
use crate::tree::Tree;
use crate::{Digest, Error, Result, digest_ok, random_digest};

/// Bounded FRI columns while proving (the bench's setting; about 0.3–0.6 GiB).
pub const MAX_FRI_COLUMNS: usize = 16;

pub use crate::pool::{PoolRef, Version};

/// A source of spending keys.
pub trait KeySource {
    /// The keys of account `i` in `pool`.
    fn account(&self, pool: &PoolRef, i: u32) -> Result<Account>;
    /// The account every input is bound to: zero for the Templar wallet, `A` for a bound wallet.
    fn bound_account(&self) -> Felt32;
}

impl KeySource for Seed {
    fn account(&self, pool: &PoolRef, i: u32) -> Result<Account> {
        Seed::account(self, pool.chain(), pool.pool(), i)
    }
    fn bound_account(&self) -> Felt32 {
        [0; 32]
    }
}

impl KeySource for BoundWallet {
    fn account(&self, pool: &PoolRef, i: u32) -> Result<Account> {
        self.keys(pool, i)
    }
    fn bound_account(&self) -> Felt32 {
        *self.account_address()
    }
}

/// Inputs to a V5 spend's `valid_until`, all read at one block together with the tree the root
/// and paths come from (spec §8.2, AB-PV6): a re-plan takes all of them fresh, never an old root
/// with a new expiry.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Expiry {
    /// The latest block, the one the tree was read at.
    pub latest_block: u64,
    /// The pool's `E`.
    pub window: u64,
    /// The pool's `Q`.
    pub quantum: u64,
}

/// A V5 plan can still land when proved at `now.latest_block` (AB-SM4): on the pool's grid,
/// ahead of the latest block, and not beyond what the pool accepts (`E + Q`). A plan that fails
/// is re-planned with a fresh root and expiry (AB-PV6).
pub fn check_fresh(plan: &Plan, now: &Expiry) -> Result<()> {
    if plan.version != Version::V5 {
        return Ok(());
    }
    let v = plan.valid_until;
    if now.quantum == 0 || now.quantum > u32::MAX as u64 || now.window > u32::MAX as u64 {
        return Err(Error::input("expiry: the pool's E and Q"));
    }
    if !v.is_multiple_of(now.quantum) || v <= now.latest_block || v > now.latest_block.saturating_add(now.window + now.quantum) {
        return Err(Error::new("stale_plan", "the plan's valid_until no longer fits the pool's rules; plan again"));
    }
    Ok(())
}

/// The SDK's `valid_until = ceil((latest + E) / Q) · Q` (spec §8.2): on the pool's grid, at least
/// `E` blocks ahead and at most `E + Q`.
pub fn valid_until(e: &Expiry) -> Result<u64> {
    if e.quantum == 0 || e.quantum > u32::MAX as u64 || e.window > u32::MAX as u64 {
        return Err(Error::input("expiry: the pool's E and Q"));
    }
    let v = e.latest_block.checked_add(e.window + e.quantum - 1).ok_or_else(|| Error::input("expiry: latest block"))? / e.quantum * e.quantum;
    if v == 0 || v >= payment5::VALID_UNTIL_BOUND {
        return Err(Error::input("expiry: valid_until out of range"));
    }
    Ok(v)
}

/// A spendable note, as the wallet holds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteRef {
    pub index: u64,
    pub account: u32,
    pub asset: String,
    pub amount: String,
    pub rho: Digest,
    pub commitment: Digest,
}

/// A note's sticky dummy input (spec §3.3, SDK-M17).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Companion {
    pub sk: Digest,
    pub rho: Digest,
    pub position: u32,
    pub siblings: Vec<Digest>,
}

impl Companion {
    fn fresh(rng: &mut (impl RngCore + CryptoRng)) -> Companion {
        Companion {
            sk: random_digest(rng),
            rho: random_digest(rng),
            position: rng.next_u32(),
            siblings: (0..DEPTH).map(|_| random_digest(rng)).collect(),
        }
    }

    /// The nullifier the companion publishes for `asset` (the wallet checks it is unspent). A
    /// bound spend's companion is bound to the same account (spec §6.2, AB-M14); `account` is zero
    /// otherwise.
    pub fn nullifier(&self, chain: &Felt32, pool: &Felt32, asset: &Felt32, account: &Felt32) -> Result<Digest> {
        let (receiver, nk) = payment5::receiver_of(&felt::limbs(account)?, &self.sk);
        let cm = note::commitment(chain, pool, asset, 0, &receiver, &self.rho)?;
        Ok(note::nullifier(&nk, &cm, self.position))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    Transfer { asset: String, amount: String, to: String },
    Withdraw { asset: String, amount: String, recipient: String },
    Consolidate { asset: String },
}

/// One output slot with its sealed note.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlannedOutput {
    pub receiver: Digest,
    pub rho: Digest,
    pub amount: String,
    pub ciphertext: Vec<String>,
    pub delivery: String,
}

/// A checked plan: everything the proof needs except keys, which are re-derived from the seed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    /// The relation. The V5 fields are omitted for V4, so a V4 plan serializes as before V5.
    #[serde(default, skip_serializing_if = "is_v4")]
    pub version: Version,
    /// V5: the last block the spend may land in; 0 for V4.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub valid_until: u64,
    /// V5: the account the inputs are bound to, `0x0` for an ordinary spend.
    #[serde(default = "zero_hex", skip_serializing_if = "is_zero_hex")]
    pub bound_account: String,
    pub chain: String,
    pub pool: String,
    pub asset: String,
    pub account: u32,
    pub root: Digest,
    /// Leaf count of the tree the root is taken from (for the eviction rule, spec §9.1).
    pub leaf_count: u64,
    pub inputs: Vec<NoteRef>,
    pub paths: Vec<Vec<Digest>>,
    /// The dummy input of a single-input spend.
    pub companion: Option<Companion>,
    /// Whether `companion` was created by this plan (the wallet stores it with the note once the
    /// statement leaves the wallet).
    pub companion_is_new: bool,
    pub outputs: [PlannedOutput; 2],
    pub withdrawal_recipient: String,
    pub withdrawal_amount: String,
}

fn zero_hex() -> String {
    "0x0".into()
}
fn is_zero_hex(s: &str) -> bool {
    s == "0x0"
}
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_v4(v: &Version) -> bool {
    *v == Version::V4
}

/// A canonical decimal u128: digits only, no sign, no leading zeros (SDK-IM7).
pub fn u128_of(s: &str) -> Result<u128> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return Err(Error::input("amount: not a canonical decimal u128"));
    }
    s.parse::<u128>().map_err(|_| Error::input("amount: not a decimal u128"))
}

fn words_hex(w: &[Felt32; 10]) -> Vec<String> {
    w.iter().map(felt::to_hex).collect()
}

fn seal_output(pk: &[u8; 32], asset: &Felt32, receiver: Digest, amount: u128, rng: &mut (impl RngCore + CryptoRng)) -> Result<PlannedOutput> {
    let rho = random_digest(rng);
    let sealed = sealbox::seal(pk, &note::m301(asset, &receiver, &rho, amount), rng)?;
    let words = sealbox::to_words(&sealed)?;
    Ok(PlannedOutput { receiver, rho, amount: amount.to_string(), ciphertext: words_hex(&words), delivery: felt::to_hex(&sealbox::delivery(&words)) })
}

/// A zero-value note to a fresh random receiver, with a real sealed box of a random plaintext to a
/// fresh key pair (hidden-asset spec §6).
fn dummy_output(rng: &mut (impl RngCore + CryptoRng)) -> Result<PlannedOutput> {
    let pk = sealbox::public_key(&sealbox::clamp({
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        k
    }));
    let mut plaintext = [0u8; sealbox::PLAINTEXT];
    rng.fill_bytes(&mut plaintext);
    let sealed = sealbox::seal(&pk, &plaintext, rng)?;
    let words = sealbox::to_words(&sealed)?;
    Ok(PlannedOutput {
        receiver: random_digest(rng),
        rho: random_digest(rng),
        amount: "0".into(),
        ciphertext: words_hex(&words),
        delivery: felt::to_hex(&sealbox::delivery(&words)),
    })
}

/// Chooses inputs: the smallest single note covering `amount`, else the covering pair with the
/// smallest total, all from one account (spec §7.2).
fn select(notes: &[NoteRef], amount: u128) -> Result<Vec<NoteRef>> {
    let amt = |n: &NoteRef| u128_of(&n.amount);
    let mut best_single: Option<(u128, &NoteRef)> = None;
    for n in notes {
        let a = amt(n)?;
        if a >= amount && best_single.is_none_or(|(b, _)| a < b) {
            best_single = Some((a, n));
        }
    }
    if let Some((_, n)) = best_single {
        return Ok(vec![n.clone()]);
    }
    let mut best_pair: Option<(u128, usize, usize)> = None;
    for i in 0..notes.len() {
        for j in i + 1..notes.len() {
            if notes[i].account != notes[j].account {
                continue;
            }
            let Some(total) = amt(&notes[i])?.checked_add(amt(&notes[j])?) else { continue };
            if total >= amount && best_pair.is_none_or(|(b, ..)| total < b) {
                best_pair = Some((total, i, j));
            }
        }
    }
    match best_pair {
        Some((_, i, j)) => Ok(vec![notes[i].clone(), notes[j].clone()]),
        None => Err(Error::new("insufficient_notes", "no one or two notes of one account cover the amount; consolidate first")),
    }
}

pub struct PlanInput<'a> {
    pub keys: &'a dyn KeySource,
    pub version: Version,
    /// Required for V5; the tree must be the one read at `expiry.latest_block`.
    pub expiry: Option<Expiry>,
    pub chain: Felt32,
    pub pool: Felt32,
    pub request: Request,
    /// Spendable notes (complete sync, deep enough, unspent, not in a live record).
    pub notes: &'a [NoteRef],
    /// Existing companions by note index.
    pub companions: &'a [(u64, Companion)],
    /// A live record's inputs, which a re-plan must reuse exactly (spec §9.1).
    pub required_inputs: Option<&'a [u64]>,
    /// Every nullifier the pool has marked spent (from the synced `NullifierSpent` events): no
    /// input and no companion may be spent (SDK-IM4).
    pub spent: &'a [Digest],
    pub tree: &'a Tree,
}

pub fn plan(p: PlanInput, rng: &mut (impl RngCore + CryptoRng)) -> Result<Plan> {
    let (asset_hex, want, recipient) = match &p.request {
        Request::Transfer { asset, amount, .. } => (asset, u128_of(amount)?, None),
        Request::Withdraw { asset, amount, recipient } => (asset, u128_of(amount)?, Some(felt::parse(recipient)?)),
        Request::Consolidate { asset } => (asset, 0, None),
    };
    let asset = felt::parse(asset_hex)?;
    felt::check_address(&asset, "asset")?;
    let candidates: Vec<NoteRef> = p.notes.iter().filter(|n| felt::parse(&n.asset).ok() == Some(asset)).cloned().collect();
    let inputs = match (&p.request, p.required_inputs) {
        (_, Some(required)) => {
            let chosen: Vec<NoteRef> = required.iter().filter_map(|i| candidates.iter().find(|n| n.index == *i).cloned()).collect();
            if chosen.len() != required.len() || chosen.is_empty() || chosen.len() > 2 {
                return Err(Error::new("record_inputs", "a live record's inputs must be reused exactly"));
            }
            chosen
        }
        (Request::Consolidate { .. }, None) => {
            // The two smallest notes of whichever account gives the smallest pair (SDK-IM6).
            let mut best: Option<(u128, NoteRef, NoteRef)> = None;
            for i in 0..candidates.len() {
                for j in i + 1..candidates.len() {
                    let (a, b) = (&candidates[i], &candidates[j]);
                    if a.account != b.account {
                        continue;
                    }
                    let Some(total) = u128_of(&a.amount)?.checked_add(u128_of(&b.amount)?) else { continue };
                    if best.as_ref().is_none_or(|(t, ..)| total < *t) {
                        best = Some((total, a.clone(), b.clone()));
                    }
                }
            }
            let (_, a, b) = best.ok_or_else(|| Error::new("insufficient_notes", "consolidation needs two notes of one account"))?;
            vec![a, b]
        }
        (_, None) => select(&candidates, want)?,
    };
    // Every transfer and withdrawal moves a nonzero amount, re-plans included (SDK-IM7).
    if !matches!(p.request, Request::Consolidate { .. }) && want == 0 {
        return Err(Error::input("amount: zero"));
    }
    let account_index = inputs[0].account;
    if inputs.iter().any(|n| n.account != account_index) {
        return Err(Error::new("one_account", "a spend's inputs come from one account"));
    }
    let bound = p.keys.bound_account();
    let pool_ref = PoolRef::new(p.chain, p.pool, p.version)?;
    let valid_until = match (p.version, &p.expiry) {
        (Version::V4, _) if !felt::is_zero(&bound) => return Err(Error::new("wrong_relation", "a bound wallet spends only with R0 V5")),
        (Version::V4, _) => 0,
        (Version::V5, Some(e)) => valid_until(e)?,
        (Version::V5, None) => return Err(Error::input("a V5 spend needs the pool's expiry rules and the latest block")),
    };
    let account = p.keys.account(&pool_ref, account_index)?;
    let mut total: u128 = 0;
    for n in &inputs {
        let amount = u128_of(&n.amount)?;
        let cm = note::commitment(&p.chain, &p.pool, &asset, amount, &account.receiver, &n.rho)?;
        if cm != n.commitment || p.tree.leaf(n.index) != Some(cm) {
            return Err(Error::new("not_ours", format!("note {} is not this account's leaf", n.index)));
        }
        total = total.checked_add(amount).ok_or_else(|| Error::input("amount overflow"))?;
    }
    for n in &inputs {
        let position = u32::try_from(n.index).map_err(|_| Error::input("position"))?;
        if p.spent.contains(&note::nullifier(&account.nk, &n.commitment, position)) {
            return Err(Error::new("spent", format!("note {} is already spent", n.index)));
        }
    }
    let paths = inputs.iter().map(|n| p.tree.path(n.index)).collect::<Result<Vec<_>>>()?;
    let change = total.checked_sub(want).ok_or_else(|| Error::new("insufficient_notes", "the inputs do not cover the amount"))?;
    let (mut outputs, withdrawal) = match &p.request {
        Request::Transfer { to, .. } => {
            let to = Address::decode(to)?;
            if to.chain != p.chain || to.pool != p.pool {
                return Err(Error::new("wrong_pool", "the address is for another chain or pool"));
            }
            let pay = seal_output(&to.pk, &asset, to.receiver, want, rng)?;
            let second = if change > 0 { seal_output(&account.pk, &asset, account.receiver, change, rng)? } else { dummy_output(rng)? };
            ([pay, second], (felt::from_u128(0), 0u128))
        }
        Request::Withdraw { .. } => {
            let recipient = recipient.expect("set above");
            felt::check_address(&recipient, "recipient")?;
            let first = if change > 0 { seal_output(&account.pk, &asset, account.receiver, change, rng)? } else { dummy_output(rng)? };
            ([first, dummy_output(rng)?], (recipient, want))
        }
        Request::Consolidate { .. } => {
            ([seal_output(&account.pk, &asset, account.receiver, total, rng)?, dummy_output(rng)?], (felt::from_u128(0), 0u128))
        }
    };
    if rng.gen_bool(0.5) {
        outputs.swap(0, 1);
    }
    let mut inputs = inputs;
    let mut paths = paths;
    if inputs.len() == 2 && rng.gen_bool(0.5) {
        inputs.swap(0, 1);
        paths.swap(0, 1);
    }
    let (companion, companion_is_new) = if inputs.len() == 1 {
        match p.companions.iter().find(|(i, _)| *i == inputs[0].index) {
            Some((_, c)) => {
                if p.spent.contains(&c.nullifier(&p.chain, &p.pool, &asset, &bound)?) {
                    return Err(Error::new("companion_spent", "the note's companion dummy was already spent"));
                }
                (Some(c.clone()), false)
            }
            None => (Some(Companion::fresh(rng)), true),
        }
    } else {
        (None, false)
    };
    let plan = Plan {
        version: p.version,
        valid_until,
        bound_account: felt::to_hex(&bound),
        chain: felt::to_hex(&p.chain),
        pool: felt::to_hex(&p.pool),
        asset: felt::to_hex(&asset),
        account: account_index,
        root: p.tree.root(),
        leaf_count: p.tree.len(),
        inputs,
        paths,
        companion,
        companion_is_new,
        outputs,
        withdrawal_recipient: felt::to_hex(&withdrawal.0),
        withdrawal_amount: withdrawal.1.to_string(),
    };
    // The whole statement is checked now, before any proving.
    witness(p.keys, &plan)?;
    Ok(plan)
}

/// The openings a free full withdrawal reveals to the prover server (spec §7.2, AB-M13): each
/// output's `inner`, when the plan is a V5 plain withdrawal whose outputs are both zero-value notes.
/// The server recomputes each commitment with the published asset and amount 0. `None` for any
/// other plan, which pays a ticket instead.
pub fn free_withdrawal_openings(plan: &Plan) -> Result<Option<[Digest; 2]>> {
    if plan.version != Version::V5 || u128_of(&plan.withdrawal_amount)? == 0 || plan.outputs.iter().any(|o| o.amount != "0") {
        return Ok(None);
    }
    Ok(Some([note::inner(&plan.outputs[0].receiver, &plan.outputs[0].rho), note::inner(&plan.outputs[1].receiver, &plan.outputs[1].rho)]))
}

/// A spend's public statement: R0 V4's, or R0 V5's (V4's plus `account` and `valid_until`).
/// Serialized as the relation's own JSON (the server's `statement`), with u128 amounts as exact
/// integers. It is never parsed back in the core.
#[derive(Clone, Debug)]
pub enum Statement {
    V4(payment4::Public),
    V5(payment5::Public),
}

impl Serialize for Statement {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Statement::V4(p) => p.serialize(s),
            Statement::V5(p) => p.serialize(s),
        }
    }
}

impl Statement {
    pub fn version(&self) -> Version {
        match self {
            Statement::V4(_) => Version::V4,
            Statement::V5(_) => Version::V5,
        }
    }
    pub fn root(&self) -> Digest {
        match self {
            Statement::V4(p) => p.root,
            Statement::V5(p) => p.root,
        }
    }
    pub fn nullifiers(&self) -> [Digest; 2] {
        match self {
            Statement::V4(p) => p.nullifiers,
            Statement::V5(p) => p.nullifiers,
        }
    }
    pub fn commitments(&self) -> [Digest; 2] {
        match self {
            Statement::V4(p) => p.commitments,
            Statement::V5(p) => p.commitments,
        }
    }
    pub fn token_out(&self) -> &str {
        match self {
            Statement::V4(p) => &p.token_out,
            Statement::V5(p) => &p.token_out,
        }
    }
    /// `TMR0_BIND_V4` or `TMR0_BIND_V5`: the bridge's and the pool's binding.
    pub fn binding(&self) -> Result<Felt32> {
        match self {
            Statement::V4(p) => binding(p),
            Statement::V5(p) => binding5(p),
        }
    }
    /// `apply_spend(spend, proof)` calldata for the statement's pool.
    pub fn calldata(&self, ciphertexts: &[Vec<String>; 2]) -> Result<Vec<String>> {
        match self {
            Statement::V4(p) => calldata(p, ciphertexts),
            Statement::V5(p) => calldata5(p, ciphertexts),
        }
    }
}

/// The relation's private witness, for proving only.
#[derive(Debug)]
pub enum Witness {
    V4(payment4::Private),
    V5(payment5::Private),
}

/// Rebuilds the relation's witness and statement from a plan, with every check the bridge runs.
pub fn witness(keys: &dyn KeySource, plan: &Plan) -> Result<(Statement, Witness)> {
    let chain = felt::parse(&plan.chain)?;
    let pool = felt::parse(&plan.pool)?;
    let asset = felt::parse(&plan.asset)?;
    felt::check_address(&pool, "pool")?;
    felt::check_address(&asset, "asset")?;
    if chain != felt::from_short_string("SN_SEPOLIA")? && chain != felt::from_short_string("SN_MAIN")? {
        return Err(Error::input("chain"));
    }
    // The relation's own encoders panic on non-canonical text (64 hex digits), so every felt it
    // parses is rebuilt from its parsed value (SDK-IM1).
    let (chain_s, pool_s, asset_s) = (felt::to_hex(&chain), felt::to_hex(&pool), felt::to_hex(&asset));
    let bound = keys.bound_account();
    if felt::parse(&plan.bound_account)? != bound {
        return Err(Error::input("the plan is for another wallet's account binding"));
    }
    match plan.version {
        Version::V4 if !felt::is_zero(&bound) || plan.valid_until != 0 => return Err(Error::input("a V4 plan is ordinary and has no expiry")),
        Version::V5 if plan.valid_until == 0 || plan.valid_until >= payment5::VALID_UNTIL_BOUND => {
            return Err(Error::input("valid_until out of range"));
        }
        _ => {}
    }
    let account = keys.account(&PoolRef::new(chain, pool, plan.version)?, plan.account)?;
    if plan.inputs.is_empty() || plan.inputs.len() > 2 || plan.paths.len() != plan.inputs.len() {
        return Err(Error::input("one or two inputs"));
    }
    let mut inputs = vec![];
    for (n, path) in plan.inputs.iter().zip(&plan.paths) {
        let position = u32::try_from(n.index).map_err(|_| Error::input("position"))?;
        if path.len() != DEPTH || !digest_ok(&n.rho) {
            return Err(Error::input("input encoding"));
        }
        inputs.push(Input { sk: account.sk, rho: n.rho, amount: u128_of(&n.amount)?, position, siblings: path.clone() });
    }
    let dummy = inputs.len() == 1;
    if dummy {
        let c = plan.companion.as_ref().ok_or_else(|| Error::input("a single-input spend needs its companion"))?;
        if c.siblings.len() != DEPTH || !digest_ok(&c.sk) || !digest_ok(&c.rho) {
            return Err(Error::input("companion encoding"));
        }
        inputs.push(Input { sk: c.sk, rho: c.rho, amount: 0, position: c.position, siblings: c.siblings.clone() });
    } else if plan.companion.is_some() {
        return Err(Error::input("a two-input spend has no companion"));
    }
    let mut outputs = vec![];
    let mut deliveries = vec![];
    for o in &plan.outputs {
        let words: Vec<Felt32> = o.ciphertext.iter().map(|w| felt::parse(w)).collect::<Result<_>>()?;
        let words: [Felt32; 10] = words.try_into().map_err(|_| Error::input("ciphertext: not ten words"))?;
        sealbox::from_words(&words)?;
        let delivery = sealbox::delivery(&words);
        if Ok(delivery) != felt::parse(&o.delivery) {
            return Err(Error::input("delivery digest"));
        }
        if !digest_ok(&o.receiver) || !digest_ok(&o.rho) {
            return Err(Error::input("output encoding"));
        }
        outputs.push(Output { receiver: o.receiver, rho: o.rho, amount: u128_of(&o.amount)? });
        deliveries.push(felt::to_hex(&delivery));
        // An output to this account must decrypt to exactly what it commits to, so a corrupted
        // plan cannot strand the change (SDK-IM8). A payee's output cannot be checked here.
        if o.receiver == account.receiver {
            let sealed = sealbox::from_words(&words)?;
            let pt = sealbox::open(&account.ivk, &sealed).and_then(|x| note::parse(&x));
            let amount = u128_of(&o.amount)?;
            if pt.is_none_or(|pt| pt.side.is_some() || pt.asset != asset || pt.receiver != o.receiver || pt.rho != o.rho || pt.amount != amount) {
                return Err(Error::input("an output to this account does not decrypt to its note"));
            }
        }
    }
    let recipient = felt::parse(&plan.withdrawal_recipient)?;
    let w_amount = u128_of(&plan.withdrawal_amount)?;
    if !felt::below_2_251(&recipient) {
        return Err(Error::input("recipient"));
    }
    let recipient_s = felt::to_hex(&recipient);
    let deliveries = [deliveries[0].clone(), deliveries[1].clone()];
    let (inputs, outputs) = ([inputs[0].clone(), inputs[1].clone()], [outputs[0].clone(), outputs[1].clone()]);
    let (statement, witness) = match plan.version {
        Version::V4 => {
            let private = payment4::Private { token: asset_s.clone(), inputs, dummy, outputs, identity: Identity::default() };
            let public = payment4::statement(TREE, &chain_s, &pool_s, deliveries, (recipient_s, w_amount), "0x0", &private)
                .map_err(|e| Error::new("invalid_spend", e))?;
            payment4::bridge_checks(&public).map_err(|e| Error::new("bridge_would_reject", e))?;
            (Statement::V4(public), Witness::V4(private))
        }
        Version::V5 => {
            let private = payment5::Private {
                token: asset_s.clone(), account: felt::to_hex(&bound), inputs, dummy, outputs, identity: Identity::default(),
            };
            let public = payment5::statement(TREE, &chain_s, &pool_s, deliveries, (recipient_s, w_amount), "0x0", plan.valid_until, &private)
                .map_err(|e| Error::new("invalid_spend", e))?;
            payment5::bridge_checks(&public).map_err(|e| Error::new("bridge_would_reject", e))?;
            (Statement::V5(public), Witness::V5(private))
        }
    };
    if statement.root() != plan.root {
        return Err(Error::new("invalid_spend", "an input is not under the plan's root"));
    }
    Ok((statement, witness))
}

fn words_felts(d: &Digest) -> Vec<Felt32> {
    d.iter().map(|w| felt::from_u128(*w as u128)).collect()
}

/// `Poseidon('TMR0_BIND_V4', …)` over a V4 statement (the bridge's and the pool's binding).
pub fn binding(p: &payment4::Public) -> Result<Felt32> {
    let f = |s: &str| felt::parse(s);
    let mut b = vec![felt::from_short_string("TMR0_BIND_V4")?, f(&p.chain)?, f(&p.pool)?, f(&p.token_out)?];
    b.extend(words_felts(&p.root));
    b.extend(words_felts(&p.nullifiers[0]));
    b.extend(words_felts(&p.nullifiers[1]));
    b.extend(words_felts(&p.commitments[0]));
    b.push(f(&p.deliveries[0])?);
    b.extend(words_felts(&p.commitments[1]));
    b.push(f(&p.deliveries[1])?);
    b.push(f(&p.withdrawal_recipient)?);
    b.push(felt::from_u128(p.withdrawal_amount));
    b.push(f(&p.intent)?);
    b.extend(words_felts(&p.identity));
    Ok(felt::poseidon(&b))
}

/// `Poseidon('TMR0_BIND_V5', …)`: V4's fields, then `valid_until`; never the account (spec §5.2).
pub fn binding5(p: &payment5::Public) -> Result<Felt32> {
    let f = |s: &str| felt::parse(s);
    let mut b = vec![felt::from_short_string("TMR0_BIND_V5")?, f(&p.chain)?, f(&p.pool)?, f(&p.token_out)?];
    b.extend(words_felts(&p.root));
    b.extend(words_felts(&p.nullifiers[0]));
    b.extend(words_felts(&p.nullifiers[1]));
    b.extend(words_felts(&p.commitments[0]));
    b.push(f(&p.deliveries[0])?);
    b.extend(words_felts(&p.commitments[1]));
    b.push(f(&p.deliveries[1])?);
    b.push(f(&p.withdrawal_recipient)?);
    b.push(felt::from_u128(p.withdrawal_amount));
    b.push(f(&p.intent)?);
    b.extend(words_felts(&p.identity));
    b.push(felt::from_u128(p.valid_until as u128));
    Ok(felt::poseidon(&b))
}

/// Pool V3's `apply_spend(spend, proof)` calldata: `spend5::Spend` (V4's fields, then
/// `valid_until`, then the binding) and an empty `proof` span.
pub fn calldata5(p: &payment5::Public, ciphertexts: &[Vec<String>; 2]) -> Result<Vec<String>> {
    let v4 = payment4::Public {
        chain: p.chain.clone(), pool: p.pool.clone(), token_out: p.token_out.clone(), root: p.root,
        nullifiers: p.nullifiers, commitments: p.commitments, deliveries: p.deliveries.clone(),
        withdrawal_recipient: p.withdrawal_recipient.clone(), withdrawal_amount: p.withdrawal_amount, intent: p.intent.clone(),
        identity: p.identity,
    };
    let mut out = calldata(&v4, ciphertexts)?;
    // V4's layout ends `…, identity₉, binding, 0x0` (the empty proof span).
    let tail = out.split_off(out.len() - 2);
    debug_assert_eq!(tail[1], "0x0");
    out.push(format!("0x{:x}", p.valid_until));
    out.push(felt::to_hex(&binding5(p)?));
    out.push("0x0".into());
    Ok(out)
}

/// `apply_spend(spend, proof)` calldata: the pool's `spend4::Spend` then an empty `proof` span.
pub fn calldata(p: &payment4::Public, ciphertexts: &[Vec<String>; 2]) -> Result<Vec<String>> {
    let f = |s: &str| felt::parse(s).map(|x| felt::to_hex(&x));
    let span = |d: &[u32]| -> Vec<String> {
        std::iter::once(format!("0x{:x}", d.len())).chain(d.iter().map(|w| format!("0x{w:x}"))).collect()
    };
    let mut out = vec![f(&p.chain)?, f(&p.pool)?, f(&p.token_out)?];
    out.extend(span(&p.root));
    out.extend(span(&[p.nullifiers[0], p.nullifiers[1]].concat()));
    out.push("0x2".into());
    for (cm, ct) in p.commitments.iter().zip(ciphertexts) {
        out.extend(span(cm));
        out.push(format!("0x{:x}", ct.len()));
        for w in ct {
            out.push(f(w)?);
        }
    }
    out.push(f(&p.withdrawal_recipient)?);
    out.push(format!("0x{:x}", p.withdrawal_amount));
    out.push(f(&p.intent)?);
    out.extend(span(&p.identity));
    out.push(felt::to_hex(&binding(p)?));
    out.push("0x0".into());
    Ok(out)
}

/// A proved spend, ready for the prover server and the pool.
#[derive(Clone, Debug, Serialize)]
pub struct Proved {
    pub version: Version,
    /// The client proof as the bridge's Cairo arguments (the server's `proof`).
    pub proof: Vec<String>,
    /// The public statement (the server's `statement`).
    pub statement: Statement,
    pub binding: String,
    pub calldata: Vec<String>,
    /// The client circuit hash, eight u32 little-endian words.
    pub circuit_hash: [u32; 8],
    /// The input nullifiers, companion included.
    pub nullifiers: [Digest; 2],
}

/// Proves a plan: rebuilds and checks the witness, proves with a fresh blinding seed, checks the
/// hiding budget and verifies the proof natively (spec §7.3). A V5 plan needs `now`, the pool's
/// rules and the latest block, and is refused when it can no longer land (AB-SM4).
pub fn prove_plan(keys: &dyn KeySource, plan: &Plan, now: Option<&Expiry>, rng: &mut (impl RngCore + CryptoRng)) -> Result<Proved> {
    match (plan.version, now) {
        (Version::V5, Some(now)) => check_fresh(plan, now)?,
        (Version::V5, None) => return Err(Error::input("proving a V5 plan needs the pool's expiry rules and the latest block")),
        (Version::V4, _) => {}
    }
    let (statement, witness) = witness(keys, plan)?;
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    let proved = match (&statement, &witness) {
        (Statement::V4(public), Witness::V4(private)) => prove::prove(&R4(public, private), blinding, Some(MAX_FRI_COLUMNS)),
        (Statement::V5(public), Witness::V5(private)) => prove::prove(&R5(public, private), blinding, Some(MAX_FRI_COLUMNS)),
        _ => unreachable!("witness returns matching versions"),
    }
    .map_err(|e| Error::new("proving", e))?;
    let circuit_hash = prove::words(proved.circuit_hash);
    let proof = prove::cairo_arguments(proved);
    let ciphertexts = [plan.outputs[0].ciphertext.clone(), plan.outputs[1].ciphertext.clone()];
    Ok(Proved {
        version: statement.version(),
        proof,
        binding: felt::to_hex(&statement.binding()?),
        calldata: statement.calldata(&ciphertexts)?,
        circuit_hash,
        nullifiers: statement.nullifiers(),
        statement,
    })
}
