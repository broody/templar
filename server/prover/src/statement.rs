//! A submission: the relation, the client proof (the wallet's `cairo-arguments.json`: a
//! length-prefixed felt span) and the public statement (its `public.json`). Parsing is fallible
//! and bounded; the statement's fields become the bridge's `main` arguments, exactly as the bench
//! validators pass them (`validate_bridge_r4.py`, `validate_bridge_p1.py`).
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use starknet_types_core::felt::Felt;

use crate::rpc::felt;

const P: u64 = (1 << 31) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    R4,
    P1,
}

impl Relation {
    pub fn parse(s: &str) -> Result<Relation> {
        match s {
            "r4" => Ok(Relation::R4),
            "p1" => Ok(Relation::P1),
            _ => bail!("relation must be r4 or p1"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Relation::R4 => "r4",
            Relation::P1 => "p1",
        }
    }
}

#[derive(Deserialize)]
pub struct SubmissionJson {
    pub relation: String,
    pub proof: Vec<String>,
    pub statement: Value,
}

#[derive(Debug, Clone)]
pub struct Submission {
    pub relation: Relation,
    /// The proof span as the bridge takes it: `[len, felts...]`.
    pub proof: Vec<Felt>,
    pub chain: Felt,
    pub pool: Felt,
    /// Nine words each: the root and every nullifier (R4: two; P1: one).
    pub root: Vec<Felt>,
    pub nullifiers: Vec<Vec<Felt>>,
    /// The bridge's statement arguments (the proof span follows them).
    pub statement_args: Vec<Felt>,
}

fn f(v: &Value, key: &str) -> Result<Felt> {
    let s = v.get(key).and_then(Value::as_str).with_context(|| format!("statement.{key}: expected a hex felt"))?;
    felt(s)
}

/// A decimal or JSON integer below `2^bits` (`bits` ≤ 128).
fn int(v: &Value, key: &str, bits: u32) -> Result<Felt> {
    let x = v.get(key).with_context(|| format!("statement.{key}"))?;
    let n: u128 = match x {
        Value::Number(n) => n.as_u64().with_context(|| format!("statement.{key}: integer"))? as u128,
        Value::String(s) => s.parse().with_context(|| format!("statement.{key}: integer"))?,
        _ => bail!("statement.{key}: integer"),
    };
    if bits < 128 && n >> bits != 0 {
        bail!("statement.{key}: out of range");
    }
    Ok(Felt::from(n))
}

/// Nine canonical M31 words.
fn words(v: &Value, what: &str) -> Result<Vec<Felt>> {
    let a = v.as_array().with_context(|| format!("{what}: expected nine words"))?;
    if a.len() != 9 {
        bail!("{what}: expected nine words");
    }
    a.iter()
        .map(|w| {
            let n = w.as_u64().with_context(|| format!("{what}: word"))?;
            if n >= P {
                bail!("{what}: word not canonical");
            }
            Ok(Felt::from(n))
        })
        .collect()
}

fn digest(v: &Value, key: &str) -> Result<Vec<Felt>> {
    words(v.get(key).with_context(|| format!("statement.{key}"))?, key)
}

fn pair<'a>(v: &'a Value, key: &str) -> Result<[&'a Value; 2]> {
    let a = v.get(key).and_then(Value::as_array).with_context(|| format!("statement.{key}: expected two entries"))?;
    if a.len() != 2 {
        bail!("statement.{key}: expected two entries");
    }
    Ok([&a[0], &a[1]])
}

fn span(xs: &[Felt]) -> Vec<Felt> {
    let mut v = vec![Felt::from(xs.len() as u64)];
    v.extend_from_slice(xs);
    v
}

impl Submission {
    pub fn parse(body: SubmissionJson, max_proof_felts: usize) -> Result<Submission> {
        let relation = Relation::parse(&body.relation)?;
        if body.proof.is_empty() || body.proof.len() > max_proof_felts {
            bail!("proof: length out of range");
        }
        let proof: Vec<Felt> = body.proof.iter().map(|s| felt(s)).collect::<Result<_>>().context("proof")?;
        if proof[0] != Felt::from((proof.len() - 1) as u64) {
            bail!("proof: the length prefix does not match");
        }
        let s = &body.statement;
        let chain = f(s, "chain")?;
        let pool = f(s, "pool")?;
        let root = digest(s, "root")?;
        let mut args = vec![chain, pool];
        let nullifiers = match relation {
            Relation::R4 => {
                let [n0, n1] = pair(s, "nullifiers")?;
                let nfs = vec![words(n0, "nullifier")?, words(n1, "nullifier")?];
                let [c0, c1] = pair(s, "commitments")?;
                let [d0, d1] = pair(s, "deliveries")?;
                let d = |v: &Value| felt(v.as_str().context("delivery: hex felt")?);
                args.push(f(s, "token_out")?);
                args.extend(span(&root));
                args.extend(span(&[nfs[0].clone(), nfs[1].clone()].concat()));
                args.extend(span(&[words(c0, "commitment")?, words(c1, "commitment")?].concat()));
                args.extend(span(&[d(d0)?, d(d1)?]));
                args.push(f(s, "withdrawal_recipient")?);
                args.push(int(s, "withdrawal_amount", 128)?);
                args.push(f(s, "intent")?);
                args.extend(span(&digest(s, "identity")?));
                nfs
            }
            Relation::P1 => {
                let nf = digest(s, "nullifier")?;
                let [c0, c1] = pair(s, "commitments")?;
                let [d0, d1] = pair(s, "deliveries")?;
                let d = |v: &Value| felt(v.as_str().context("delivery: hex felt")?);
                args.push(f(s, "token")?);
                args.extend(span(&root));
                args.extend(span(&nf));
                args.extend(span(&words(c0, "commitment")?));
                args.extend(span(&words(c1, "commitment")?));
                args.push(d(d0)?);
                args.push(d(d1)?);
                args.push(f(s, "withdrawal_recipient")?);
                args.push(int(s, "withdrawal_amount", 128)?);
                args.push(f(s, "controller")?);
                args.push(f(s, "controller_class")?);
                args.push(f(s, "handle")?);
                args.extend(span(&digest(s, "policy_id")?));
                args.push(int(s, "deadline", 64)?);
                args.push(int(s, "not_before", 64)?);
                args.push(int(s, "index", 8)?);
                args.push(int(s, "kind", 8)?);
                args.push(int(s, "x", 128)?);
                args.push(f(s, "data")?);
                vec![nf]
            }
        };
        Ok(Submission { relation, proof, chain, pool, root, nullifiers, statement_args: args })
    }

    /// The deduplication key: input 0's nullifier (R4) or the policy note's (P1).
    pub fn dedup_key(&self) -> String {
        self.nullifiers[0].iter().map(|w| format!("{:x}", w)).collect::<Vec<_>>().join(".")
    }

    /// The bridge's full argument list.
    pub fn bridge_args(&self) -> Vec<Felt> {
        [self.statement_args.clone(), self.proof.clone()].concat()
    }
}
