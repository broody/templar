//! R0 V4 spends (spec §7.2, §7.3): note selection, outputs, dummies and the sticky companion
//! dummy input, the statement and the bridge's checks, the binding and the pool calldata, and the
//! client proof. Every choice uses the core's CSPRNG.
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use templar_client_verifier_circuit::payment::{DEPTH, Identity, Input};
use templar_client_verifier_circuit::payment4::{self, Output, Private, Public};
use templar_client_verifier_circuit::prove::{self, R4, TREE};

use crate::address::Address;
use crate::felt::{self, Felt32};
use crate::keys::Seed;
use crate::note;
use crate::sealbox;
use crate::tree::Tree;
use crate::{Digest, Error, Result, digest_ok, random_digest};

/// Bounded FRI columns while proving (the bench's setting; about 0.3–0.6 GiB).
pub const MAX_FRI_COLUMNS: usize = 16;

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

    /// The nullifier the companion publishes for `asset` (the wallet checks it is unspent).
    pub fn nullifier(&self, chain: &Felt32, pool: &Felt32, asset: &Felt32) -> Result<Digest> {
        let (receiver, nk) = templar_client_verifier_circuit::payment::receiver_of(&self.sk);
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

fn u128_of(s: &str) -> Result<u128> {
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
    pub seed: &'a Seed,
    pub chain: Felt32,
    pub pool: Felt32,
    pub request: Request,
    /// Spendable notes (complete sync, deep enough, unspent, not in a live record).
    pub notes: &'a [NoteRef],
    /// Existing companions by note index.
    pub companions: &'a [(u64, Companion)],
    /// A live record's inputs, which a re-plan must reuse exactly (spec §9.1).
    pub required_inputs: Option<&'a [u64]>,
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
            let mut by_amount = candidates.clone();
            by_amount.sort_by_key(|n| u128_of(&n.amount).unwrap_or(u128::MAX));
            let first = by_amount.first().ok_or_else(|| Error::new("insufficient_notes", "nothing to consolidate"))?.clone();
            let second = by_amount.iter().skip(1).find(|n| n.account == first.account).cloned()
                .ok_or_else(|| Error::new("insufficient_notes", "consolidation needs two notes of one account"))?;
            vec![first, second]
        }
        (_, None) => {
            if want == 0 {
                return Err(Error::input("amount: zero"));
            }
            select(&candidates, want)?
        }
    };
    let account_index = inputs[0].account;
    if inputs.iter().any(|n| n.account != account_index) {
        return Err(Error::new("one_account", "a spend's inputs come from one account"));
    }
    let account = p.seed.account(&p.chain, &p.pool, account_index)?;
    let mut total: u128 = 0;
    for n in &inputs {
        let amount = u128_of(&n.amount)?;
        let cm = note::commitment(&p.chain, &p.pool, &asset, amount, &account.receiver, &n.rho)?;
        if cm != n.commitment || p.tree.leaf(n.index) != Some(cm) {
            return Err(Error::new("not_ours", format!("note {} is not this account's leaf", n.index)));
        }
        total = total.checked_add(amount).ok_or_else(|| Error::input("amount overflow"))?;
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
            Some((_, c)) => (Some(c.clone()), false),
            None => (Some(Companion::fresh(rng)), true),
        }
    } else {
        (None, false)
    };
    let plan = Plan {
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
    witness(p.seed, &plan)?;
    Ok(plan)
}

/// Rebuilds the relation's witness and statement from a plan, with every check the bridge runs.
pub fn witness(seed: &Seed, plan: &Plan) -> Result<(Public, Private)> {
    let chain = felt::parse(&plan.chain)?;
    let pool = felt::parse(&plan.pool)?;
    let asset = felt::parse(&plan.asset)?;
    felt::check_address(&pool, "pool")?;
    felt::check_address(&asset, "asset")?;
    if chain != felt::from_short_string("SN_SEPOLIA")? && chain != felt::from_short_string("SN_MAIN")? {
        return Err(Error::input("chain"));
    }
    let account = seed.account(&chain, &pool, plan.account)?;
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
        if felt::to_hex(&sealbox::delivery(&words)) != o.delivery {
            return Err(Error::input("delivery digest"));
        }
        if !digest_ok(&o.receiver) || !digest_ok(&o.rho) {
            return Err(Error::input("output encoding"));
        }
        outputs.push(Output { receiver: o.receiver, rho: o.rho, amount: u128_of(&o.amount)? });
        deliveries.push(o.delivery.clone());
    }
    let recipient = felt::parse(&plan.withdrawal_recipient)?;
    let w_amount = u128_of(&plan.withdrawal_amount)?;
    if !felt::below_2_251(&recipient) {
        return Err(Error::input("recipient"));
    }
    let private = Private {
        token: plan.asset.clone(),
        inputs: [inputs[0].clone(), inputs[1].clone()],
        dummy,
        outputs: [outputs[0].clone(), outputs[1].clone()],
        identity: Identity::default(),
    };
    let public = payment4::statement(
        TREE,
        &plan.chain,
        &plan.pool,
        [deliveries[0].clone(), deliveries[1].clone()],
        (plan.withdrawal_recipient.clone(), w_amount),
        "0x0",
        &private,
    )
    .map_err(|e| Error::new("invalid_spend", e))?;
    payment4::bridge_checks(&public).map_err(|e| Error::new("bridge_would_reject", e))?;
    if public.root != plan.root {
        return Err(Error::new("invalid_spend", "an input is not under the plan's root"));
    }
    Ok((public, private))
}

fn words_felts(d: &Digest) -> Vec<Felt32> {
    d.iter().map(|w| felt::from_u128(*w as u128)).collect()
}

/// `Poseidon('TMR0_BIND_V4', …)` over a V4 statement (the bridge's and the pool's binding).
pub fn binding(p: &Public) -> Result<Felt32> {
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

/// `apply_spend(spend, proof)` calldata: the pool's `spend4::Spend` then an empty `proof` span.
pub fn calldata(p: &Public, ciphertexts: &[Vec<String>; 2]) -> Result<Vec<String>> {
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proved {
    /// The client proof as the bridge's Cairo arguments (the server's `proof`).
    pub proof: Vec<String>,
    /// The public statement (the server's `statement`).
    pub statement: Public,
    pub binding: String,
    pub calldata: Vec<String>,
    /// The client circuit hash, eight u32 little-endian words.
    pub circuit_hash: [u32; 8],
    /// The input nullifiers, companion included.
    pub nullifiers: [Digest; 2],
}

/// Proves a plan: rebuilds and checks the witness, proves with a fresh blinding seed, checks the
/// hiding budget and verifies the proof natively (spec §7.3).
pub fn prove_plan(seed: &Seed, plan: &Plan, rng: &mut (impl RngCore + CryptoRng)) -> Result<Proved> {
    let (public, private) = witness(seed, plan)?;
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    let proved = prove::prove(&R4(&public, &private), blinding, Some(MAX_FRI_COLUMNS)).map_err(|e| Error::new("proving", e))?;
    let circuit_hash = prove::words(proved.circuit_hash);
    let proof = prove::cairo_arguments(proved);
    let ciphertexts = [plan.outputs[0].ciphertext.clone(), plan.outputs[1].ciphertext.clone()];
    Ok(Proved {
        proof,
        binding: felt::to_hex(&binding(&public)?),
        calldata: calldata(&public, &ciphertexts)?,
        circuit_hash,
        nullifiers: public.nullifiers,
        statement: public,
    })
}
