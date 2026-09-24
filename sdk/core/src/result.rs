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

/// The pinned constants of one pool's R4 relation (spec §10.2).
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
}

/// The server's result, as `GET /v1/jobs/{id}` returns it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerResult {
    pub proof: String,
    pub proof_facts: Vec<String>,
    pub base_block: u64,
    pub binding: String,
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

pub fn check(pins: &Pins, binding: &str, r: &ServerResult, latest_block: u64) -> Result<Window> {
    let bad = |m: &str| Error::new("bad_result", m.to_string());
    let binding = felt::parse(binding)?;
    if felt::parse(&r.binding).map_err(|_| bad("binding"))? != binding {
        return Err(bad("the result is for another binding"));
    }
    let facts: Vec<Felt32> = r.proof_facts.iter().map(|f| felt::parse(f)).collect::<Result<_>>().map_err(|_| bad("facts"))?;
    if facts.len() != 9 {
        return Err(bad("facts: not nine entries"));
    }
    let expect = [
        (0, felt::from_short_string("PROOF2")?, "proof version"),
        (1, felt::from_short_string("VIRTUAL_SNOS")?, "variant"),
        (2, felt::parse(&pins.os_program)?, "OS program"),
        (3, felt::from_short_string("VIRTUAL_SNOS0")?, "output version"),
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
    let valid_until = r.base_block.checked_add(pins.max_proof_age).ok_or_else(|| bad("base block"))?;
    Ok(Window { submit_after, valid_until })
}
