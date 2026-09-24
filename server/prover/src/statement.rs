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
    // JSON numbers are kept exact (serde_json `arbitrary_precision`): u128 amounts above 2^64 are
    // honest (PI-3).
    let n: u128 = match x {
        Value::Number(n) => n.to_string().parse().with_context(|| format!("statement.{key}: integer"))?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn r4(amount: Value, proof: Vec<&str>) -> SubmissionJson {
        let d = json!([1, 2, 3, 4, 5, 6, 7, 8, 9]);
        SubmissionJson {
            relation: "r4".into(),
            proof: proof.into_iter().map(String::from).collect(),
            statement: json!({"chain": "0x534e5f5345504f4c4941", "pool": "0x1", "token_out": "0x0", "root": d,
                "nullifiers": [d, d], "commitments": [d, d], "deliveries": ["0x1", "0x2"],
                "withdrawal_recipient": "0x0", "withdrawal_amount": amount, "intent": "0x0", "identity": d}),
        }
    }

    #[test]
    fn parses_and_encodes() {
        let s = Submission::parse(r4(json!(0), vec!["0x2", "0x5", "0x6"]), 10).unwrap();
        assert_eq!(s.proof.len(), 3);
        // chain, pool, token_out, root span(10), nullifiers span(19), commitments span(19),
        // deliveries span(3), recipient, amount, intent, identity span(10), then the proof.
        assert_eq!(s.statement_args.len(), 3 + 10 + 19 + 19 + 3 + 3 + 10);
        assert_eq!(s.bridge_args().len(), s.statement_args.len() + 3);
    }

    #[test]
    fn u128_amounts_above_2_64() {
        let big: Value = serde_json::from_str("1180591620717411303424").unwrap(); // 2^70
        assert!(Submission::parse(r4(big, vec!["0x0"]), 10).is_ok());
        let too_big: Value = serde_json::from_str("340282366920938463463374607431768211456").unwrap(); // 2^128
        assert!(Submission::parse(r4(too_big, vec!["0x0"]), 10).is_err());
        assert!(Submission::parse(r4(json!("1180591620717411303424"), vec!["0x0"]), 10).is_ok());
    }

    #[test]
    fn refuses_malformed() {
        assert!(Submission::parse(r4(json!(0), vec!["0x2", "0x5"]), 10).is_err(), "length prefix");
        assert!(Submission::parse(r4(json!(0), vec![]), 10).is_err(), "empty");
        assert!(Submission::parse(r4(json!(0), vec!["0x0"; 11]), 10).is_err(), "too long");
        assert!(Submission::parse(r4(json!(0), vec!["0xzz"]), 10).is_err(), "bad hex");
        let p = "0x800000000000011000000000000000000000000000000000000000000000001";
        assert!(Submission::parse(r4(json!(0), vec![p]), 10).is_err(), "non-canonical felt");
        let mut j = r4(json!(0), vec!["0x0"]);
        j.statement["root"] = json!([2147483647, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(Submission::parse(j, 10).is_err(), "non-canonical M31 word");
        let mut j = r4(json!(0), vec!["0x0"]);
        j.relation = "r0".into();
        assert!(Submission::parse(j, 10).is_err(), "relation");
    }
}
