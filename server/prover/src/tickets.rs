//! Paying for the service (`docs/account-bound-note-spec.md` §7.2, §9): tickets, their states and
//! the free full withdrawal.
//!
//! - **A ticket** is an RFC 9474 blind RSA signature (RSABSSA-SHA384-PSS-Randomized) by an issuer
//!   key on `"TEMPLAR_TICKET_V1" ‖ nonce`, with a random 32-byte nonce: publicly verifiable, and
//!   unlinkable to its issuance. The wire form is `{key_id, nonce, randomizer, signature}` (hex).
//! - **One spent set per issuer key**, keyed by nonce, persisted as an append-only log (`spent_dir`,
//!   on its own volume) and always loaded, even past the key's expiry, so neither a restart nor a
//!   clock set back makes a ticket spendable twice (AB-P30, AB-SM6). P4 has one redeemer: a second
//!   server or relayer needs a shared spent set, or issuer keys partitioned between redeemers (P7).
//! - **Fail-closed**: a spend that cannot be synced to the log fails the job, and the ledger refuses
//!   new reservations until the log is writable again (AB-SM5, AB-SP9).
//! - **States** (spec §9): reserved at admission; released by a server-side or timing refusal or a
//!   signature failure; consumed by a bridge rejection or a calldata mismatch; spent at job start;
//!   refunded, blind, on the job's own blinded requests, when the server fails the job itself.
//! - **The free full withdrawal**: `intent = 0`, a priced asset at or above its minimum, and both
//!   outputs opened to zero-value notes of the published asset.
//!
//! P4 runs a test issuer: the refund key is the issuer's secret key, held by this server. P7
//! specifies the issuer, key periods and the claim flow (`docs/relayer-spec.md`).
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{ensure, Context, Result};
use blind_rsa_signatures::{
    BlindSignature, DefaultRng, MessageRandomizer, PublicKeySha384PSSRandomized as PublicKey,
    SecretKeySha384PSSRandomized as SecretKey, Signature,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use starknet_types_core::felt::Felt;

use crate::m31;
use crate::statement::{Relation, Submission};
use crate::v5::to_u64;

pub const TICKET_TAG: &[u8] = b"TEMPLAR_TICKET_V1";

/// `[payment]`: absent means the service is free (a self-hosted server).
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentConfig {
    /// Refuse jobs without payment.
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub issuer_keys: Vec<IssuerKeyConfig>,
    /// The test issuer's secret key (P4), which signs refunds; its key id must be one of
    /// `issuer_keys`.
    pub refund_key: Option<RefundKeyConfig>,
    #[serde(default)]
    pub costs: Costs,
    /// Assets whose full withdrawal at or above `minimum` costs no ticket.
    #[serde(default)]
    pub priced_assets: Vec<PricedAsset>,
    #[serde(default)]
    pub free: FreeLimits,
    /// The spent logs' directory; default `data_dir/spent`. Keep it off the job directories'
    /// volume, so a full volume cannot stop a spend from being recorded (AB-SP9).
    pub spent_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssuerKeyConfig {
    pub id: String,
    /// PEM (`PUBLIC KEY`).
    pub public_key: PathBuf,
    /// Unix seconds after which the key's tickets are refused and its spent set dropped.
    pub not_after: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefundKeyConfig {
    pub id: String,
    /// PEM (`PRIVATE KEY`).
    pub secret_key: PathBuf,
}

/// Tickets per job (spec §7.2, initial policy).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct Costs {
    pub transfer: u32,
    pub withdrawal: u32,
    pub invoke: u32,
    pub policy: u32,
}

impl Default for Costs {
    fn default() -> Self {
        Costs { transfer: 1, withdrawal: 1, invoke: 2, policy: 1 }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PricedAsset {
    pub asset: String,
    /// Decimal u128.
    pub minimum: String,
}

/// The free queue's bounds (spec §7.2: free jobs never take a paid job's slot).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct FreeLimits {
    #[serde(default = "d_free_queue")]
    pub queue_capacity: usize,
    #[serde(default = "d_free_per_hour")]
    pub per_hour: u32,
    /// Free jobs per address bucket per hour (relays share the global bound only).
    #[serde(default = "d_free_per_address")]
    pub per_address_per_hour: u32,
    /// The share of the prover's time free jobs may take in any hour, in percent (AB-SP3): past it,
    /// free jobs wait even when no paid job does.
    #[serde(default = "d_free_share")]
    pub max_share_percent: u32,
}

impl Default for FreeLimits {
    fn default() -> Self {
        FreeLimits {
            queue_capacity: d_free_queue(), per_hour: d_free_per_hour(),
            per_address_per_hour: d_free_per_address(), max_share_percent: d_free_share(),
        }
    }
}

fn d_free_queue() -> usize { 4 }
fn d_free_per_hour() -> u32 { 30 }
fn d_free_per_address() -> u32 { 4 }
fn d_free_share() -> u32 { 25 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TicketJson {
    pub key_id: String,
    pub nonce: String,
    pub randomizer: String,
    pub signature: String,
}

/// A job's payment: `{tickets, refund_requests}` (one blinded refund request per ticket), or
/// `{free_full_withdrawal: {openings}}` (both outputs' `inner`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PaymentJson {
    Tickets { tickets: Vec<TicketJson>, refund_requests: Vec<String> },
    FreeFullWithdrawal { free_full_withdrawal: FreeJson },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeJson {
    pub openings: [Vec<u32>; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ticket {
    pub key_id: String,
    pub nonce: [u8; 32],
    randomizer: [u8; 32],
    signature: Vec<u8>,
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s.strip_prefix("0x").unwrap_or(s)).with_context(|| format!("{what}: hex"))?;
    v.try_into().map_err(|_| anyhow::anyhow!("{what}: 32 bytes"))
}

impl Ticket {
    pub fn parse(t: &TicketJson) -> Result<Ticket> {
        ensure!(valid_key_id(&t.key_id), "ticket: key id");
        let signature = hex::decode(t.signature.strip_prefix("0x").unwrap_or(&t.signature)).context("ticket: signature hex")?;
        ensure!(signature.len() <= 512, "ticket: signature too long");
        Ok(Ticket { key_id: t.key_id.clone(), nonce: hex32(&t.nonce, "ticket nonce")?, randomizer: hex32(&t.randomizer, "ticket randomizer")?, signature })
    }

    pub fn message(nonce: &[u8; 32]) -> Vec<u8> {
        [TICKET_TAG, nonce.as_slice()].concat()
    }
}

/// A spent-log line's nonce: 64 hex characters, or longer when a torn line from before the fresh-line
/// rule ran into the next one (the whole nonce is then the last 64). Anything else is torn.
fn spent_line(line: &str) -> Option<[u8; 32]> {
    let line = line.trim();
    if line.len() < 64 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex32(&line[line.len() - 64..], "spent log").ok()
}

/// Key ids name files: letters, digits, `-` and `_`, at most 64.
fn valid_key_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

struct IssuerKey {
    public: PublicKey,
    not_after: u64,
}

#[derive(Default)]
struct Ledger {
    /// key id → spent nonces.
    spent: HashMap<String, HashSet<[u8; 32]>>,
    /// (key id, nonce) → the reservation holding it.
    reserved: HashMap<(String, [u8; 32]), u64>,
    next: u64,
    /// A spend could not be synced: no new reservations until the log is writable (AB-SM5).
    broken: bool,
    /// Consumed tickets whose spend could not be synced: spent once the log is writable again
    /// (recheck N6).
    pending: Vec<Reservation>,
}

/// Tickets held for one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    id: u64,
    tickets: Vec<(String, [u8; 32])>,
    /// Blinded refund requests, one per ticket.
    pub refund_requests: Vec<Vec<u8>>,
}

impl Reservation {
    pub fn len(&self) -> usize {
        self.tickets.len()
    }
}

/// The ticket ledger: issuer keys, spent sets and reservations.
pub struct Tickets {
    pub config: PaymentConfig,
    keys: HashMap<String, IssuerKey>,
    refund: Option<(String, SecretKey)>,
    priced: HashMap<Felt, u128>,
    dir: PathBuf,
    ledger: Mutex<Ledger>,
}

impl Tickets {
    /// Loads the keys and every key's spent set (`spent_dir/<key id>.log`), expired keys'
    /// included: the logs are kept, so a clock set back cannot revive a key with an empty set.
    pub fn load(config: PaymentConfig, data_dir: &Path, _now: u64) -> Result<Tickets> {
        let dir = config.spent_dir.clone().unwrap_or_else(|| data_dir.join("spent"));
        std::fs::create_dir_all(&dir)?;
        let mut keys = HashMap::new();
        let mut spkis = HashSet::new();
        let mut ledger = Ledger::default();
        for k in &config.issuer_keys {
            ensure!(valid_key_id(&k.id), "payment: issuer key id {:?}", k.id);
            let pem = std::fs::read_to_string(&k.public_key).with_context(|| format!("reading {}", k.public_key.display()))?;
            let public = PublicKey::from_pem(&pem).map_err(|e| anyhow::anyhow!("issuer key {}: {e:?}", k.id))?;
            // One key under two ids would spend each ticket once per id (AB-SM7).
            let spki = public.to_spki().map_err(|e| anyhow::anyhow!("issuer key {}: {e:?}", k.id))?;
            ensure!(spkis.insert(spki), "payment: the issuer key {} is another id's key", k.id);
            ensure!(keys.insert(k.id.clone(), IssuerKey { public, not_after: k.not_after }).is_none(), "payment: duplicate key id {}", k.id);
            let log = dir.join(format!("{}.log", k.id));
            let mut set = HashSet::new();
            if log.exists() {
                for line in std::fs::read_to_string(&log)?.lines().filter(|l| !l.is_empty()) {
                    match spent_line(line) {
                        Some(n) => {
                            set.insert(n);
                        }
                        // A line torn by a failed write: that spend returned an error, so no job
                        // ran on it (recheck N2).
                        None => tracing::warn!(key = %k.id, "skipping a torn spent-log line"),
                    }
                }
            }
            ledger.spent.insert(k.id.clone(), set);
        }
        let refund = match &config.refund_key {
            Some(r) => {
                ensure!(keys.contains_key(&r.id), "payment: the refund key {} is not an issuer key", r.id);
                let pem = std::fs::read_to_string(&r.secret_key).with_context(|| format!("reading {}", r.secret_key.display()))?;
                let sk = SecretKey::from_pem(&pem).map_err(|e| anyhow::anyhow!("refund key: {e:?}"))?;
                let public = sk.public_key().map_err(|e| anyhow::anyhow!("refund key: {e:?}"))?;
                ensure!(public.to_der().ok() == keys[&r.id].public.to_der().ok(), "payment: the refund key is not the issuer key {}", r.id);
                Some((r.id.clone(), sk))
            }
            None => None,
        };
        let mut priced = HashMap::new();
        for a in &config.priced_assets {
            let asset = crate::rpc::felt(&a.asset)?;
            let minimum = a.minimum.parse::<u128>().context("payment: priced asset minimum")?;
            ensure!(asset != Felt::ZERO && minimum != 0, "payment: a priced asset and its minimum are nonzero");
            ensure!(priced.insert(asset, minimum).is_none(), "payment: priced asset {} twice", a.asset);
        }
        Ok(Tickets { config, keys, refund, priced, dir, ledger: Mutex::new(ledger) })
    }

    /// The ticket is signed by an issuer key that has not expired.
    pub fn verify(&self, t: &Ticket, now: u64) -> Result<()> {
        let k = self.keys.get(&t.key_id).context("ticket: unknown issuer key")?;
        ensure!(now < k.not_after, "ticket: the issuer key has expired");
        k.public
            .verify(&Signature(t.signature.clone()), Some(MessageRandomizer(t.randomizer)), Ticket::message(&t.nonce))
            .map_err(|_| anyhow::anyhow!("ticket: invalid signature"))
    }

    /// Reserves every ticket of a job, or none: each valid, distinct, unspent and unreserved.
    pub fn reserve(&self, tickets: &[Ticket], refund_requests: Vec<Vec<u8>>, now: u64) -> Result<Reservation> {
        ensure!(refund_requests.len() == tickets.len(), "payment: one blinded refund request per ticket");
        for t in tickets {
            self.verify(t, now)?;
        }
        for (r, t) in refund_requests.iter().zip(tickets) {
            let size = self.keys[&t.key_id].public.components().n().len();
            ensure!(r.len() == size, "payment: a refund request is not the key's modulus size");
        }
        let mut l = self.ledger.lock().unwrap();
        if l.broken {
            self.probe().context("payment: the spent log is not writable; retry later")?;
            // Consumed tickets whose spend failed are spent first (recheck N6).
            for r in std::mem::take(&mut l.pending) {
                if let Err(e) = self.spend_locked(&mut l, &r) {
                    l.pending.push(r);
                    return Err(e.context("payment: the spent log is not writable; retry later"));
                }
            }
            l.broken = false;
        }
        let mut seen = HashSet::new();
        for t in tickets {
            let key = (t.key_id.clone(), t.nonce);
            ensure!(seen.insert(key.clone()), "payment: the same ticket twice");
            ensure!(!l.spent.get(&t.key_id).is_some_and(|s| s.contains(&t.nonce)), "payment: a ticket is already spent");
            ensure!(!l.reserved.contains_key(&key), "payment: a ticket is held by another job");
        }
        l.next += 1;
        let id = l.next;
        let held: Vec<(String, [u8; 32])> = seen.into_iter().collect();
        for k in &held {
            l.reserved.insert(k.clone(), id);
        }
        Ok(Reservation { id, tickets: held, refund_requests })
    }

    /// Returns the tickets to their holder (a refusal that is not the client's fault).
    pub fn release(&self, r: &Reservation) {
        let mut l = self.ledger.lock().unwrap();
        for k in &r.tickets {
            if l.reserved.get(k) == Some(&r.id) {
                l.reserved.remove(k);
            }
        }
    }

    /// Spends the tickets durably: appended to their keys' logs and synced before the job goes on.
    /// On an error the tickets stay reserved (the caller releases them or keeps them held), and the
    /// ledger takes no new reservation until the log is writable (AB-SM5, AB-SP9). A nonce that
    /// reached the log before the error counts as spent after a restart: the error fails closed.
    pub fn spend(&self, r: &Reservation) -> Result<()> {
        let mut l = self.ledger.lock().unwrap();
        self.spend_locked(&mut l, r)
    }

    /// Consumes a job's tickets (a bridge rejection or a calldata mismatch). If the spend cannot be
    /// synced, they stay held and are spent as soon as the log is writable (recheck N6).
    pub fn consume(&self, r: &Reservation) {
        let mut l = self.ledger.lock().unwrap();
        if let Err(e) = self.spend_locked(&mut l, r) {
            tracing::error!("spending consumed tickets: {e:#}");
            l.pending.push(r.clone());
        }
    }

    fn spend_locked(&self, l: &mut Ledger, r: &Reservation) -> Result<()> {
        let mut by_key: HashMap<&str, Vec<[u8; 32]>> = HashMap::new();
        for (k, n) in &r.tickets {
            by_key.entry(k.as_str()).or_default().push(*n);
        }
        for (k, nonces) in by_key {
            let written = self.append(k, &nonces);
            if let Err(e) = written {
                l.broken = true;
                return Err(e.context("spending tickets: the spent log"));
            }
            let set = l.spent.entry(k.to_string()).or_default();
            set.extend(nonces);
        }
        for k in &r.tickets {
            l.reserved.remove(k);
        }
        Ok(())
    }

    fn append(&self, key: &str, nonces: &[[u8; 32]]) -> Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).read(true).append(true).open(self.dir.join(format!("{key}.log")))?;
        let mut text = String::new();
        // After a torn write, start on a fresh line, so the torn part stays a line of its own.
        if f.metadata()?.len() > 0 {
            let mut last = [0u8];
            f.seek(SeekFrom::End(-1))?;
            f.read_exact(&mut last)?;
            if last[0] != b'\n' {
                text.push('\n');
            }
        }
        text.extend(nonces.iter().map(|n| format!("{}\n", hex::encode(n))));
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        Ok(())
    }

    /// Whether the spent logs can be written and synced again.
    fn probe(&self) -> Result<()> {
        let p = self.dir.join(".probe");
        let mut f = std::fs::File::create(&p)?;
        f.write_all(b"probe")?;
        f.sync_all()?;
        std::fs::remove_file(&p)?;
        Ok(())
    }

    /// Replacement tickets for a job the server failed: the refund key blind-signs the job's own
    /// requests, so a refund cannot be linked to the client's later spends (AB-P30).
    pub fn refund(&self, r: &Reservation) -> Result<Value> {
        let (id, sk) = self.refund.as_ref().context("no refund key: refunds are owed but cannot be signed")?;
        let sigs = r
            .refund_requests
            .iter()
            .map(|m| sk.blind_sign(m).map(|s: BlindSignature| hex::encode(&s.0)).map_err(|e| anyhow::anyhow!("refund: {e:?}")))
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({"key_id": id, "blind_signatures": sigs}))
    }

    /// The tickets a job costs (spec §7.2).
    pub fn cost(&self, sub: &Submission) -> u32 {
        let c = self.config.costs;
        match (&sub.relation, &sub.v5) {
            (Relation::P1, _) => c.policy,
            (_, Some(j)) if j.statement.intent != Felt::ZERO => c.invoke,
            (_, Some(j)) if j.statement.withdrawal_amount != Felt::ZERO => c.withdrawal,
            (_, Some(_)) => c.transfer,
            // R0 V4 carries no parsed statement fields here; its withdrawal shape costs the same.
            (_, None) => c.withdrawal.max(c.transfer),
        }
    }

    /// The free full withdrawal (spec §7.2, AB-M13): a plain spend (`intent = 0`) of a priced asset
    /// at or above its minimum, whose two outputs open to zero-value notes of that asset. The asset
    /// is the statement's decoded `token_out`, never the client's.
    pub fn free_full_withdrawal(&self, sub: &Submission, openings: &[Vec<u32>; 2]) -> Result<()> {
        let j = sub.v5.as_ref().context("free withdrawal: R0 V5 only")?;
        let s = &j.statement;
        ensure!(s.intent == Felt::ZERO, "free withdrawal: a plain withdrawal only (intent = 0)");
        let minimum = self.priced.get(&s.token_out).context("free withdrawal: not a priced asset")?;
        let b = s.withdrawal_amount.to_bytes_be();
        ensure!(b[..16].iter().all(|x| *x == 0), "free withdrawal: amount");
        let amount = u128::from_be_bytes(b[16..].try_into().unwrap());
        ensure!(amount >= *minimum, "free withdrawal: below the asset's minimum");
        for (k, inner) in openings.iter().enumerate() {
            ensure!(inner.len() == 9 && inner.iter().all(|w| (*w as u64) < m31::P), "free withdrawal: opening {k}: nine canonical words");
            let inner: m31::Digest = inner.as_slice().try_into().unwrap();
            let cm = m31::commitment(&s.chain, &s.pool, &s.token_out, 0, &inner);
            let want: Vec<u64> = s.commitments[k].iter().map(|w| to_u64(w).unwrap_or(u64::MAX)).collect();
            ensure!(cm.iter().map(|w| *w as u64).collect::<Vec<_>>() == want, "free withdrawal: output {k} is not a zero-value note of the asset");
        }
        Ok(())
    }

    /// What `/v1/info` publishes: the issuer keys, the costs, the priced assets and the free bounds.
    pub fn info(&self) -> Value {
        let keys: Vec<Value> = self
            .config
            .issuer_keys
            .iter()
            .map(|k| json!({"id": k.id, "not_after": k.not_after,
                            "public_key_spki": self.keys[&k.id].public.to_spki().map(hex::encode).unwrap_or_default()}))
            .collect();
        json!({"required": self.config.required, "scheme": "RSABSSA-SHA384-PSS-Randomized (RFC 9474)",
               "message": "TEMPLAR_TICKET_V1 || nonce32", "issuer_keys": keys, "costs": self.config.costs,
               "priced_assets": self.config.priced_assets, "free": self.config.free})
    }
}

/// Test issuer (P4): a key pair, and tickets minted by blinding, signing and finalizing locally.
pub mod issuer {
    use super::*;
    use blind_rsa_signatures::KeyPairSha384PSSRandomized as KeyPair;

    pub fn keygen(dir: &Path, id: &str) -> Result<()> {
        ensure!(valid_key_id(id), "key id");
        let kp = KeyPair::generate(&mut DefaultRng, 2048).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(format!("{id}.pub.pem")), kp.pk.to_pem().map_err(|e| anyhow::anyhow!("{e:?}"))?)?;
        let sk_path = dir.join(format!("{id}.key.pem"));
        std::fs::write(&sk_path, kp.sk.to_pem().map_err(|e| anyhow::anyhow!("{e:?}"))?)?;
        #[cfg(unix)]
        std::fs::set_permissions(&sk_path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        Ok(())
    }

    /// `n` tickets under `(id, sk)`, as a client obtains them: blind, blind-sign, finalize.
    pub fn mint(id: &str, sk: &SecretKey, n: usize) -> Result<Vec<TicketJson>> {
        let pk = sk.public_key().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        (0..n)
            .map(|_| {
                let nonce: [u8; 32] = rand::random();
                let msg = Ticket::message(&nonce);
                let b = pk.blind(&mut DefaultRng, &msg).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let bs = sk.blind_sign(&b.blind_message).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let sig = pk.finalize(&bs, &b, &msg).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let r = b.msg_randomizer.context("a randomized scheme")?;
                Ok(TicketJson { key_id: id.into(), nonce: hex::encode(nonce), randomizer: hex::encode(r.0), signature: hex::encode(&sig.0) })
            })
            .collect()
    }

    /// A blinded refund request for a fresh nonce, and what the client keeps to finalize it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn refund_request(pk: &PublicKey) -> Result<(Vec<u8>, [u8; 32], blind_rsa_signatures::BlindingResult)> {
        let nonce: [u8; 32] = rand::random();
        let b = pk.blind(&mut DefaultRng, Ticket::message(&nonce)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok((b.blind_message.0.clone(), nonce, b))
    }

    pub fn load_secret(path: &Path) -> Result<SecretKey> {
        SecretKey::from_pem(&std::fs::read_to_string(path)?).map_err(|e| anyhow::anyhow!("{e:?}"))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn load_public(path: &Path) -> Result<PublicKey> {
        PublicKey::from_pem(&std::fs::read_to_string(path)?).map_err(|e| anyhow::anyhow!("{e:?}"))
    }
}

pub fn parse_payment(v: &Value) -> Result<PaymentJson> {
    let keys: Vec<&str> = v.as_object().context("payment: an object")?.keys().map(String::as_str).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    ensure!(sorted == ["refund_requests", "tickets"] || sorted == ["free_full_withdrawal"], "payment: {{tickets, refund_requests}} or {{free_full_withdrawal}}");
    serde_json::from_value(v.clone()).context("payment: malformed")
}

pub fn decode_requests(rs: &[String]) -> Result<Vec<Vec<u8>>> {
    rs.iter().map(|r| hex::decode(r.strip_prefix("0x").unwrap_or(r)).context("refund request: hex")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// One test key pair for the module (RSA generation is slow).
    fn key() -> &'static (PathBuf, SecretKey) {
        static K: OnceLock<(PathBuf, SecretKey)> = OnceLock::new();
        K.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("templar-tickets-{}", std::process::id()));
            issuer::keygen(&dir, "test").unwrap();
            let sk = issuer::load_secret(&dir.join("test.key.pem")).unwrap();
            (dir, sk)
        })
    }

    fn ledger(data: &Path) -> Tickets {
        ledger_with(data, |_| {}).unwrap()
    }

    fn ledger_with(data: &Path, f: impl FnOnce(&mut PaymentConfig)) -> Result<Tickets> {
        let (dir, _) = key();
        let cfg = PaymentConfig {
            required: true,
            issuer_keys: vec![IssuerKeyConfig { id: "test".into(), public_key: dir.join("test.pub.pem"), not_after: 2_000_000_000 }],
            refund_key: Some(RefundKeyConfig { id: "test".into(), secret_key: dir.join("test.key.pem") }),
            costs: Costs::default(),
            priced_assets: vec![PricedAsset { asset: "0x7e57b3a1".into(), minimum: "100".into() }],
            free: FreeLimits::default(),
            spent_dir: None,
        };
        let mut cfg = cfg;
        f(&mut cfg);
        Tickets::load(cfg, data, 1_000)
    }

    fn fresh_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("templar-ledger-{tag}-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn requests(t: &Tickets, n: usize) -> Vec<Vec<u8>> {
        let pk = &t.keys["test"].public;
        (0..n).map(|_| issuer::refund_request(pk).unwrap().0).collect()
    }

    #[test]
    fn tickets_verify_reserve_spend_and_persist() {
        let (_, sk) = key();
        let data = fresh_dir("a");
        let t = ledger(&data);
        let minted: Vec<Ticket> = issuer::mint("test", sk, 3).unwrap().iter().map(|j| Ticket::parse(j).unwrap()).collect();
        for m in &minted {
            t.verify(m, 1_000).unwrap();
        }
        // A tampered nonce or signature, an unknown key, an expired key.
        let mut bad = minted[0].clone();
        bad.nonce[0] ^= 1;
        assert!(t.verify(&bad, 1_000).is_err());
        let mut bad = minted[0].clone();
        bad.signature[10] ^= 1;
        assert!(t.verify(&bad, 1_000).is_err());
        let mut bad = minted[0].clone();
        bad.key_id = "other".into();
        assert!(t.verify(&bad, 1_000).is_err());
        assert!(t.verify(&minted[0], 2_000_000_000).is_err(), "expired key");
        // Reserve: all or none; a held ticket cannot be reserved again, nor twice in one job.
        let r = t.reserve(&minted[..2], requests(&t, 2), 1_000).unwrap();
        assert!(t.reserve(&minted[1..], requests(&t, 2), 1_000).is_err(), "held by another job");
        assert!(t.reserve(&[minted[2].clone(), minted[2].clone()], requests(&t, 2), 1_000).is_err(), "the same ticket twice");
        assert!(t.reserve(&minted[2..], requests(&t, 0), 1_000).is_err(), "one refund request per ticket");
        // Released tickets can be reserved again; spent ones never, even after a restart.
        t.release(&r);
        let r = t.reserve(&minted[..2], requests(&t, 2), 1_000).unwrap();
        t.spend(&r).unwrap();
        assert!(t.reserve(&minted[..1], requests(&t, 1), 1_000).is_err(), "spent");
        let reloaded = ledger(&data);
        assert!(reloaded.reserve(&minted[1..2], requests(&reloaded, 1), 1_000).is_err(), "spent survives a restart");
        assert!(reloaded.reserve(&minted[2..], requests(&reloaded, 1), 1_000).is_ok());
    }

    /// The spent logs are always loaded, even an expired key's, so a clock set back cannot revive
    /// a spent ticket (AB-SM6); one key under two ids and a zero priced asset are refused (AB-SM7,
    /// AB-SM8).
    #[test]
    fn spent_logs_outlive_their_keys_and_config_is_strict() {
        let (dir, sk) = key();
        let data = fresh_dir("d");
        let minted: Vec<Ticket> = issuer::mint("test", sk, 1).unwrap().iter().map(|j| Ticket::parse(j).unwrap()).collect();
        let t = ledger(&data);
        t.spend(&t.reserve(&minted, requests(&t, 1), 1_000).unwrap()).unwrap();
        // Loaded while the key has expired, then the clock goes back before `not_after`.
        let expired = ledger_with(&data, |c| c.issuer_keys[0].not_after = 500).unwrap();
        assert!(expired.ledger.lock().unwrap().spent["test"].contains(&minted[0].nonce));
        let rolled_back = ledger(&data);
        assert!(rolled_back.reserve(&minted, requests(&rolled_back, 1), 1_000).is_err());
        let twice = |c: &mut PaymentConfig| c.issuer_keys.push(IssuerKeyConfig { id: "alias".into(), public_key: dir.join("test.pub.pem"), not_after: 2_000_000_000 });
        assert!(ledger_with(&data, twice).is_err(), "one key under two ids");
        assert!(ledger_with(&data, |c| c.priced_assets[0].asset = "0x0".into()).is_err());
        assert!(ledger_with(&data, |c| c.priced_assets[0].minimum = "0".into()).is_err());
        assert!(ledger_with(&data, |c| c.priced_assets.push(c.priced_assets[0].clone())).is_err(), "an asset twice");
    }

    /// A spend that cannot be synced fails, leaves the tickets reserved, and the ledger takes no
    /// reservation until its log is writable again (AB-SM5, AB-SP9).
    #[test]
    #[cfg(unix)]
    fn ledger_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let (_, sk) = key();
        let data = fresh_dir("e");
        let spent = data.join("spent-volume");
        let t = ledger_with(&data, |c| c.spent_dir = Some(spent.clone())).unwrap();
        let minted: Vec<Ticket> = issuer::mint("test", sk, 2).unwrap().iter().map(|j| Ticket::parse(j).unwrap()).collect();
        let r = t.reserve(&minted[..1], requests(&t, 1), 1_000).unwrap();
        std::fs::set_permissions(&spent, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::File::create(spent.join("x")).is_ok() {
            return; // running as root: permissions do not bind
        }
        assert!(t.spend(&r).is_err());
        assert!(t.reserve(&minted[..1], requests(&t, 1), 1_000).is_err(), "still held");
        assert!(t.reserve(&minted[1..], requests(&t, 1), 1_000).is_err(), "no reservation while the log is not writable");
        std::fs::set_permissions(&spent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let r2 = t.reserve(&minted[1..], requests(&t, 1), 1_000).unwrap();
        t.spend(&r2).unwrap();
        t.spend(&r).unwrap();
        assert!(std::fs::read_to_string(spent.join("test.log")).unwrap().lines().count() == 2);
        // A consume that fails is spent by the next reservation once the log is writable (N6).
        let minted: Vec<Ticket> = issuer::mint("test", sk, 2).unwrap().iter().map(|j| Ticket::parse(j).unwrap()).collect();
        let c = t.reserve(&minted[..1], requests(&t, 1), 1_000).unwrap();
        std::fs::set_permissions(&spent, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::set_permissions(spent.join("test.log"), std::fs::Permissions::from_mode(0o400)).unwrap();
        t.consume(&c);
        assert!(t.reserve(&minted[1..], requests(&t, 1), 1_000).is_err());
        std::fs::set_permissions(&spent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(spent.join("test.log"), std::fs::Permissions::from_mode(0o600)).unwrap();
        t.reserve(&minted[1..], requests(&t, 1), 1_000).unwrap();
        let text = std::fs::read_to_string(spent.join("test.log")).unwrap();
        assert!(text.contains(&hex::encode(minted[0].nonce)), "the consumed ticket reached the log");
    }

    /// A torn spent-log line never stops a restart, and the next append starts a fresh line; a
    /// torn line that ran into a whole one keeps the whole one (recheck N2).
    #[test]
    fn torn_spent_lines() {
        let (_, sk) = key();
        let data = fresh_dir("f");
        let minted: Vec<Ticket> = issuer::mint("test", sk, 3).unwrap().iter().map(|j| Ticket::parse(j).unwrap()).collect();
        let hex = |t: &Ticket| hex::encode(t.nonce);
        // An old-style log: a torn half line followed on the same line by a whole nonce.
        std::fs::create_dir_all(data.join("spent")).unwrap();
        std::fs::write(data.join("spent/test.log"), format!("{}\n{}{}", hex(&minted[0]), &hex(&minted[1])[..20], hex(&minted[2]))).unwrap();
        let t = ledger(&data);
        assert!(t.reserve(&minted[..1], requests(&t, 1), 1_000).is_err());
        assert!(t.reserve(&minted[2..], requests(&t, 1), 1_000).is_err(), "the whole nonce after the torn part");
        // A torn tail: the load skips it, and the next spend begins a new line.
        std::fs::write(data.join("spent/test.log"), format!("{}\n{}", hex(&minted[0]), &hex(&minted[1])[..20])).unwrap();
        let t = ledger(&data);
        let r = t.reserve(&minted[1..2], requests(&t, 1), 1_000).unwrap();
        t.spend(&r).unwrap();
        let text = std::fs::read_to_string(data.join("spent/test.log")).unwrap();
        assert_eq!(text.lines().last().unwrap(), hex(&minted[1]));
        let t = ledger(&data);
        assert!(t.reserve(&minted[1..2], requests(&t, 1), 1_000).is_err(), "spent after a restart");
    }

    /// The free full withdrawal: a plain withdrawal of a priced asset at or above its minimum whose
    /// two outputs open to zero-value notes of that asset.
    #[test]
    fn free_full_withdrawal_rules() {
        use crate::statement::V5Job;
        use crate::v5::{PoolCall, StatementV5};
        let data = fresh_dir("c");
        let t = ledger(&data);
        let (chain, pool, asset) = (crate::rpc::short_string("SN_SEPOLIA").unwrap(), Felt::from(0x7e57b301u64), Felt::from(0x7e57b3a1u64));
        let inner: [m31::Digest; 2] = [std::array::from_fn(|k| 11 + k as u32), std::array::from_fn(|k| 21 + k as u32)];
        let cm = |i: &m31::Digest, amount: u128| m31::commitment(&chain, &pool, &asset, amount, i).iter().map(|w| Felt::from(*w as u64)).collect::<Vec<_>>();
        let st = StatementV5 {
            chain, pool, token_out: asset, root: vec![Felt::ONE; 9], nullifiers: [vec![Felt::ONE; 9], vec![Felt::TWO; 9]],
            commitments: [cm(&inner[0], 0), cm(&inner[1], 0)], deliveries: [Felt::ONE, Felt::TWO],
            withdrawal_recipient: Felt::from(0xb0bu64), withdrawal_amount: Felt::from(100u64), intent: Felt::ZERO,
            identity: vec![Felt::ZERO; 9], account: Felt::ZERO, valid_until: 6500,
        };
        let sub = |st: StatementV5| Submission {
            relation: Relation::R5, proof: vec![], chain, pool, root: vec![], nullifiers: vec![], statement_args: vec![],
            v5: Some(V5Job {
                pool_call: PoolCall { entry_point: "apply_spend".into(), calldata: vec![], spend: st.clone(), binding: Felt::ZERO, intent: None },
                statement: st,
            }),
        };
        let openings = [inner[0].to_vec(), inner[1].to_vec()];
        t.free_full_withdrawal(&sub(st.clone()), &openings).unwrap();
        // Below the minimum; an unpriced asset; an intent; a wrong opening; an output holding value.
        let below = StatementV5 { withdrawal_amount: Felt::from(99u64), ..st.clone() };
        assert!(t.free_full_withdrawal(&sub(below), &openings).is_err());
        let unpriced = StatementV5 { token_out: asset + Felt::ONE, ..st.clone() };
        assert!(t.free_full_withdrawal(&sub(unpriced), &openings).is_err());
        let invoke = StatementV5 { intent: Felt::ONE, ..st.clone() };
        assert!(t.free_full_withdrawal(&sub(invoke), &openings).is_err());
        assert!(t.free_full_withdrawal(&sub(st.clone()), &[inner[1].to_vec(), inner[0].to_vec()]).is_err(), "swapped openings");
        let change = StatementV5 { commitments: [cm(&inner[0], 5), cm(&inner[1], 0)], ..st.clone() };
        assert!(t.free_full_withdrawal(&sub(change), &openings).is_err(), "an output with value");
        assert!(t.free_full_withdrawal(&sub(st), &[inner[0][..8].to_vec(), inner[1].to_vec()]).is_err(), "eight words");
    }

    /// A refund is a blind signature on the client's own request: it finalizes into a valid,
    /// fresh ticket the server has never seen.
    #[test]
    fn refunds_finalize_into_fresh_tickets() {
        let (dir, sk) = key();
        let data = fresh_dir("b");
        let t = ledger(&data);
        let pk = issuer::load_public(&dir.join("test.pub.pem")).unwrap();
        let minted: Vec<Ticket> = issuer::mint("test", sk, 1).unwrap().iter().map(|j| Ticket::parse(j).unwrap()).collect();
        let (request, nonce, blinding) = issuer::refund_request(&pk).unwrap();
        let r = t.reserve(&minted, vec![request], 1_000).unwrap();
        t.spend(&r).unwrap();
        let refund = t.refund(&r).unwrap();
        let bs = hex::decode(refund["blind_signatures"][0].as_str().unwrap()).unwrap();
        let sig = pk.finalize(&BlindSignature(bs), &blinding, Ticket::message(&nonce)).unwrap();
        let fresh = Ticket { key_id: "test".into(), nonce, randomizer: blinding.msg_randomizer.unwrap().0, signature: sig.0 };
        t.verify(&fresh, 1_000).unwrap();
        assert!(t.reserve(&[fresh], requests(&t, 1), 1_000).is_ok(), "the refund ticket is spendable");
    }
}
