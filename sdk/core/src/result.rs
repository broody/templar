//! Checks on a prover server's result against the SDK's pinned constants, never the server's own
//! description (spec §8, SDK-M9, SDK-P7), and the submission window computed locally.
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::felt::{self, Felt32};
use crate::{Error, Result};

/// The largest proof the gateway accepts, in bytes.
pub const MAX_PROOF_BYTES: usize = 480_000;
/// Blocks after the base block before the sequencer accepts the proof.
pub const SUBMIT_DELAY: u64 = 11;

/// The pinned constants of one route (spec §10.2; `docs/pool-v3-spec.md` §6.1): a pre-cutover
/// adapter's single route, or one route of a routing adapter's pinned state. The proof version,
/// variant and output version default to today's PROOF2 values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pins {
    pub chain: String,
    pub pool: String,
    pub statement: String,
    pub statement_class: String,
    pub account_tag: String,
    pub os_program: String,
    pub config_hash: String,
    pub max_proof_age: u64,
    #[serde(default = "proof2")]
    pub proof_version: String,
    #[serde(default = "virtual_snos")]
    pub proof_variant: String,
    #[serde(default = "virtual_snos0")]
    pub output_version: String,
}

fn proof2() -> String {
    "PROOF2".into()
}
fn virtual_snos() -> String {
    "VIRTUAL_SNOS".into()
}
fn virtual_snos0() -> String {
    "VIRTUAL_SNOS0".into()
}

/// The server's result, as `GET /v1/jobs/{id}` returns it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerResult {
    pub proof: String,
    pub proof_facts: Vec<String>,
    pub base_block: u64,
    pub binding: String,
    /// The route key (pool-v3-spec §9.5, PR2-3): the statement account whose message the proof
    /// carries. A pre-cutover server omits it.
    #[serde(default)]
    pub statement: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub submit_after: u64,
    pub valid_until: u64,
}

/// `Poseidon(statement, 0, 5, statement_class, account_tag, chain, pool, binding)`: the adapter's
/// expected message hash.
pub fn message_hash(pins: &Pins, binding: &Felt32) -> Result<Felt32> {
    Ok(felt::poseidon(&[
        felt::parse(&pins.statement)?,
        [0; 32],
        felt::from_u128(5),
        felt::parse(&pins.statement_class)?,
        felt::from_short_string(&pins.account_tag)?,
        felt::parse(&pins.chain)?,
        felt::parse(&pins.pool)?,
        *binding,
    ]))
}

/// Checks a result and computes its window. For R0 V5, `statement_valid_until` caps it: the result
/// may land until `min(valid_until, base + max_proof_age)`, the server's `send_deadline`.
pub fn check(pins: &Pins, binding: &str, r: &ServerResult, latest_block: u64, statement_valid_until: Option<u64>) -> Result<Window> {
    let bad = |m: &str| Error::new("bad_result", m.to_string());
    let binding = felt::parse(binding)?;
    if felt::parse(&r.binding).map_err(|_| bad("binding"))? != binding {
        return Err(bad("the result is for another binding"));
    }
    // A result that names its route must name the route these pins are for.
    if let Some(s) = &r.statement {
        if felt::parse(s).map_err(|_| bad("statement"))? != felt::parse(&pins.statement)? {
            return Err(bad("the result names another route"));
        }
    }
    let facts: Vec<Felt32> = r.proof_facts.iter().map(|f| felt::parse(f)).collect::<Result<_>>().map_err(|_| bad("facts"))?;
    if facts.len() != 9 {
        return Err(bad("facts: not nine entries"));
    }
    let expect = [
        (0, felt::from_short_string(&pins.proof_version)?, "proof version"),
        (1, felt::from_short_string(&pins.proof_variant)?, "variant"),
        (2, felt::parse(&pins.os_program)?, "OS program"),
        (3, felt::from_short_string(&pins.output_version)?, "output version"),
        (4, felt::from_u128(r.base_block as u128), "base block"),
        (6, felt::parse(&pins.config_hash)?, "config hash"),
        (7, felt::from_u128(1), "message count"),
        (8, message_hash(pins, &binding)?, "message hash"),
    ];
    for (i, want, what) in expect {
        if facts[i] != want {
            return Err(bad(&format!("facts: {what}")));
        }
    }
    if felt::is_zero(&facts[5]) {
        return Err(bad("facts: base block hash"));
    }
    if r.base_block > latest_block {
        return Err(bad("base block in the future"));
    }
    let proof = base64::engine::general_purpose::STANDARD.decode(&r.proof).map_err(|_| bad("proof: not base64"))?;
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err(bad("proof size"));
    }
    let submit_after = r.base_block.checked_add(SUBMIT_DELAY).ok_or_else(|| bad("base block"))?;
    let proof_age = r.base_block.checked_add(pins.max_proof_age).ok_or_else(|| bad("base block"))?;
    let valid_until = statement_valid_until.map_or(proof_age, |v| v.min(proof_age));
    if valid_until < submit_after {
        return Err(bad("the result can never land: its deadline is before submit_after"));
    }
    Ok(Window { submit_after, valid_until })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> Pins {
        serde_json::from_value(serde_json::json!({
            "chain": "0x534e5f5345504f4c4941", "pool": "0x7e57b301", "statement": "0x5a7e", "statement_class": "0xc1a5",
            "account_tag": "TMPZR0_PAYMENT_V6", "os_program": "0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1",
            "config_hash": "0xc0f", "max_proof_age": 512,
        }))
        .unwrap()
    }

    fn result(p: &Pins, binding: &str, base: u64) -> ServerResult {
        let mh = message_hash(p, &felt::parse(binding).unwrap()).unwrap();
        let s = |x: &str| felt::to_hex(&felt::from_short_string(x).unwrap());
        ServerResult {
            proof: "AAAA".into(),
            proof_facts: vec![s("PROOF2"), s("VIRTUAL_SNOS"), p.os_program.clone(), s("VIRTUAL_SNOS0"), format!("0x{base:x}"), "0xb10c".into(),
                              p.config_hash.clone(), "0x1".into(), felt::to_hex(&mh)],
            base_block: base,
            binding: binding.into(),
            statement: Some(p.statement.clone()),
        }
    }

    /// Route pins (pool-v3-spec §9.5, §10.2): the proof version, variant and output version default
    /// to PROOF2's, the route's own age bounds the window, and a result that names another route is
    /// refused.
    #[test]
    fn route_pins_and_route_key() {
        let p = pins();
        assert_eq!((p.proof_version.as_str(), p.proof_variant.as_str(), p.output_version.as_str()), ("PROOF2", "VIRTUAL_SNOS", "VIRTUAL_SNOS0"));
        let r = result(&p, "0xb1d", 1000);
        assert_eq!(check(&p, "0xb1d", &r, 1005, Some(9000)).unwrap(), Window { submit_after: 1011, valid_until: 1512 });
        let mut other = r.clone();
        other.statement = Some("0x5a7f".into());
        assert_eq!(check(&p, "0xb1d", &other, 1005, None).unwrap_err().code, "bad_result");
        let mut none = r.clone();
        none.statement = None;
        check(&p, "0xb1d", &none, 1005, None).unwrap();
        // A route pinning another output version refuses PROOF2's facts.
        let mut q = p.clone();
        q.output_version = "VIRTUAL_SNOS1".into();
        assert!(check(&q, "0xb1d", &r, 1005, None).unwrap_err().message.contains("output version"));
        // Another route's statement: another message hash.
        let mut q = p.clone();
        q.statement = "0x5a7f".into();
        let mut r2 = r.clone();
        r2.statement = None;
        assert!(check(&q, "0xb1d", &r2, 1005, None).unwrap_err().message.contains("message hash"));
    }
}
