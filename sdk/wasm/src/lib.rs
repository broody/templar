//! `templar-wasm`: the WebAssembly façade over `templar-core` (spec §10.1). JSON strings and byte
//! arrays in and out; every error is thrown as a JSON `{code, message}` string, never a trap.
//! Secrets derived from the seed stay inside; only the explicit viewing-key export returns one.
use std::collections::HashMap;

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use templar_core::address::{Address, ViewingKey};
use templar_core::felt::{self, Felt32};
use templar_core::keys::{self, Seed};
use templar_core::pool::{PoolRef, Version};
use templar_core::result::{self, Pins, ServerResult};
use templar_core::scan::{self, Context, Published, Registered, ScanKey, Settlement};
use templar_core::spend::{self, Companion, Expiry, NoteRef, Plan, PlanInput, Request};
use templar_core::{Digest, Error, note, sealbox, store};
use wasm_bindgen::prelude::*;

type Out<T> = Result<T, JsValue>;

fn err(e: Error) -> JsValue {
    JsValue::from_str(&serde_json::to_string(&e).unwrap_or_default())
}

fn bad(m: &str) -> JsValue {
    err(Error::input(m))
}

fn parse<T: for<'a> Deserialize<'a>>(s: &str, what: &str) -> Out<T> {
    serde_json::from_str(s).map_err(|e| bad(&format!("{what}: {e}")))
}

fn to_json(v: &impl Serialize) -> Out<String> {
    serde_json::to_string(v).map_err(|e| err(Error::new("internal", e.to_string())))
}

fn f(s: &str) -> Out<Felt32> {
    felt::parse(s).map_err(err)
}

fn seed_of(b: &[u8]) -> Out<Seed> {
    Seed::from_bytes(b).map_err(err)
}

fn version_of(v: &str) -> Out<Version> {
    match v {
        "v4" => Ok(Version::V4),
        "v5" => Ok(Version::V5),
        "v6" => Ok(Version::V6),
        _ => Err(bad("pool version: v4, v5 or v6")),
    }
}

fn pool_ref(chain: &str, pool: &str, version: &str) -> Out<PoolRef> {
    PoolRef::new(f(chain)?, f(pool)?, version_of(version)?).map_err(err)
}

fn u128_of(s: &str) -> Out<u128> {
    spend::u128_of(s).map_err(err)
}

// ---------------------------------------------------------------- seed and keys

#[wasm_bindgen]
pub fn seed_generate() -> Vec<u8> {
    Seed::generate(&mut OsRng).bytes().to_vec()
}

#[wasm_bindgen]
pub fn seed_from_mnemonic(words: &str) -> Out<Vec<u8>> {
    Ok(Seed::from_mnemonic(words).map_err(err)?.bytes().to_vec())
}

#[wasm_bindgen]
pub fn mnemonic_from_seed(seed: &[u8]) -> Out<String> {
    Ok(seed_of(seed)?.mnemonic())
}

/// `{address, receiver, fingerprint}` of account `i`; refuses indexes past the gap limit.
#[wasm_bindgen]
pub fn account(keys: &[u8], chain: &str, pool: &str, version: &str, i: u32, highest_used: u32) -> Out<String> {
    keys::check_index(i, highest_used).map_err(err)?;
    let pr = pool_ref(chain, pool, version)?;
    let a = seed_of(keys)?.account(pr.chain(), pr.pool(), i).map_err(err)?;
    let addr = Address::of(pr.chain(), pr.pool(), &a);
    to_json(&json!({"address": addr.encode().map_err(err)?, "receiver": a.receiver, "fingerprint": addr.fingerprint()}))
}

#[wasm_bindgen]
pub fn address_decode(address: &str) -> Out<String> {
    let a = Address::decode(address).map_err(err)?;
    to_json(&json!({
        "chain": felt::to_hex(&a.chain), "pool": felt::to_hex(&a.pool), "receiver": a.receiver,
        "pk": hex_bytes(&a.pk), "fingerprint": a.fingerprint(),
    }))
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[wasm_bindgen]
pub fn viewing_key_export(keys: &[u8], chain: &str, pool: &str, version: &str, i: u32, full: bool) -> Out<String> {
    let pr = pool_ref(chain, pool, version)?;
    let a = seed_of(keys)?.account(pr.chain(), pr.pool(), i).map_err(err)?;
    ViewingKey::of(pr.chain(), pr.pool(), &a, full).encode().map_err(err)
}

/// Checks a viewing key against the expected address: `{full, chain, pool, receiver}`.
#[wasm_bindgen]
pub fn viewing_key_import(key: &str, expected_address: &str) -> Out<String> {
    let expected = Address::decode(expected_address).map_err(err)?;
    let k = ViewingKey::import(key, &expected).map_err(err)?;
    to_json(&json!({"full": k.nk.is_some(), "chain": felt::to_hex(&k.chain), "pool": felt::to_hex(&k.pool), "receiver": k.receiver}))
}

// ---------------------------------------------------------------- notes and deposits

#[wasm_bindgen]
pub fn asset_id(standard: u16, contract: &str, id_low: &str, id_high: &str) -> Out<String> {
    Ok(felt::to_hex(&note::asset_id(standard, &f(contract)?, (u128_of(id_low)?, u128_of(id_high)?)).map_err(err)?))
}

/// A deposit's note for `address`: `{inner, ciphertext, delivery, commitment}` (the pool's
/// `inner₉`, `ct₁₀`, the digest it will record and the leaf it will publish).
#[wasm_bindgen]
pub fn note_for(address: &str, asset: &str, amount: &str, chain: &str, pool: &str) -> Out<String> {
    let to = Address::decode(address).map_err(err)?;
    // A note for another pool's receiver is never found by its owner: the funds would be stranded
    // (SDK-IM2).
    if to.chain != f(chain)? || to.pool != f(pool)? {
        return Err(err(Error::new("wrong_pool", "the address is for another chain or pool")));
    }
    let asset = f(asset)?;
    felt::check_address(&asset, "asset").map_err(err)?;
    let amount = spend::u128_of(amount).map_err(err)?;
    if amount == 0 {
        return Err(bad("amount: zero"));
    }
    let rho = templar_core::random_digest(&mut OsRng);
    let sealed = sealbox::seal(&to.pk, &note::m301(&asset, &to.receiver, &rho, amount), &mut OsRng).map_err(err)?;
    let words = sealbox::to_words(&sealed).map_err(err)?;
    let cm = note::commitment(&to.chain, &to.pool, &asset, amount, &to.receiver, &rho).map_err(err)?;
    to_json(&json!({
        "inner": note::inner(&to.receiver, &rho),
        "ciphertext": words.iter().map(felt::to_hex).collect::<Vec<_>>(),
        "delivery": felt::to_hex(&sealbox::delivery(&words)),
        "commitment": cm,
    }))
}

/// The commitment the pool computes for a deposit from its `inner` (checks and test doubles).
#[wasm_bindgen]
pub fn pool_commitment(chain: &str, pool: &str, asset: &str, amount: &str, inner: &str) -> Out<String> {
    let inner: Digest = parse(inner, "inner")?;
    to_json(&note::commitment_of_inner(&f(chain)?, &f(pool)?, &f(asset)?, u128_of(amount)?, &inner).map_err(err)?)
}

/// `Poseidon('CTRL_DELIVERY_V1', 304, words)` of ten ciphertext words (what the pool records).
#[wasm_bindgen]
pub fn delivery_digest(words: &str) -> Out<String> {
    let words: Vec<String> = parse(words, "words")?;
    let words: Vec<Felt32> = words.iter().map(|w| f(w)).collect::<Out<_>>()?;
    let words: [Felt32; 10] = words.try_into().map_err(|_| bad("not ten words"))?;
    sealbox::from_words(&words).map_err(err)?;
    Ok(felt::to_hex(&sealbox::delivery(&words)))
}

// ---------------------------------------------------------------- the tree

#[wasm_bindgen]
pub struct Tree(templar_core::tree::Tree);

#[wasm_bindgen]
impl Tree {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Tree {
        Tree(templar_core::tree::Tree::new())
    }

    /// Appends leaves given as a JSON array of nine-word digests.
    pub fn append(&mut self, leaves: &str) -> Out<()> {
        let leaves: Vec<Digest> = parse(leaves, "leaves")?;
        if leaves.iter().any(|d| d.iter().any(|w| *w >= templar_core::P)) {
            return Err(bad("leaf word not below p"));
        }
        self.0.append(&leaves).map_err(err)
    }

    pub fn truncate(&mut self, n: u64) {
        self.0.truncate(n)
    }

    pub fn root(&self) -> Out<String> {
        to_json(&self.0.root())
    }

    pub fn len(&self) -> u64 {
        self.0.len()
    }
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------- scanning

#[derive(Deserialize)]
struct ScanNote {
    index: u64,
    commitment: Digest,
    digest: String,
    words: Vec<String>,
}

#[derive(Deserialize)]
struct ScanRegistered {
    asset: String,
    standard: u16,
    contract: String,
    id_low: String,
    id_high: String,
}

#[derive(Deserialize)]
struct ScanSettlement {
    first_index: u64,
    x: String,
}

#[derive(Deserialize)]
struct ScanRequest {
    chain: String,
    pool: String,
    /// Account indexes to scan with the seed (when scanning with the seed).
    #[serde(default)]
    accounts: Vec<u32>,
    /// Or a viewing key and the address it was checked against.
    viewing_key: Option<String>,
    expected_address: Option<String>,
    notes: Vec<ScanNote>,
    #[serde(default)]
    registry: Vec<ScanRegistered>,
    registry_complete: bool,
    #[serde(default)]
    settlements: Vec<ScanSettlement>,
    /// The pool's relation (`v4` default, `v5`).
    #[serde(default)]
    version: Version,
}

/// Trial decryption of published notes (spec §6): `{owned, bad_digests}`. Pass the key material
/// with `accounts`, or empty key material with `viewing_key` and `expected_address`.
#[wasm_bindgen]
pub fn scan(keys: &[u8], request: &str) -> Out<String> {
    let r: ScanRequest = parse(request, "scan request")?;
    let (chain, pool) = (f(&r.chain)?, f(&r.pool)?);
    let keys: Vec<ScanKey> = match (&r.viewing_key, &r.expected_address) {
        (Some(vk), Some(addr)) => {
            let k = ViewingKey::import(vk, &Address::decode(addr).map_err(err)?).map_err(err)?;
            vec![ScanKey { index: 0, receiver: k.receiver, ivk: k.ivk, nk: k.nk.map(|(_, nk)| nk) }]
        }
        (None, None) => {
            let k = seed_of(keys)?;
            let pr = PoolRef::new(chain, pool, r.version).map_err(err)?;
            r.accounts
                .iter()
                .map(|i| {
                    let a = k.account(pr.chain(), pr.pool(), *i)?;
                    Ok(ScanKey { index: *i, receiver: a.receiver, ivk: a.ivk, nk: Some(a.nk) })
                })
                .collect::<Result<_, Error>>()
                .map_err(err)?
        }
        _ => return Err(bad("a viewing key needs its expected address")),
    };
    let mut registry = HashMap::new();
    for g in &r.registry {
        registry.insert(f(&g.asset)?, Registered { standard: g.standard, contract: f(&g.contract)?, id: (u128_of(&g.id_low)?, u128_of(&g.id_high)?) });
    }
    let settlements: Vec<Settlement> =
        r.settlements.iter().map(|s| Ok(Settlement { first_index: s.first_index, x: u128_of(&s.x)? })).collect::<Out<_>>()?;
    // Malformed words are "not ours" (and a digest mismatch), never an error.
    let notes: Vec<Published> = r
        .notes
        .iter()
        .map(|n| Published {
            index: n.index,
            commitment: n.commitment,
            digest: felt::parse(&n.digest).unwrap_or([0xff; 32]),
            words: n.words.iter().map(|w| felt::parse(w).unwrap_or([0xff; 32])).collect(),
        })
        .collect();
    let ctx = Context { chain, pool, registry: &registry, registry_complete: r.registry_complete, settlements: &settlements };
    let out = scan::scan(&ctx, &keys, &notes).map_err(err)?;
    let owned: Vec<Value> = out
        .owned
        .iter()
        .map(|o| {
            json!({
                "index": o.index, "account": o.account, "commitment": o.commitment, "asset": felt::to_hex(&o.asset),
                "kind": o.kind, "amount": o.amount.to_string(), "rho": o.rho, "nullifier": o.nullifier,
            })
        })
        .collect();
    to_json(&json!({"owned": owned, "bad_digests": out.bad_digests}))
}

// ---------------------------------------------------------------- spends

#[derive(Deserialize)]
struct PlanRequest {
    chain: String,
    pool: String,
    request: Request,
    notes: Vec<NoteRef>,
    #[serde(default)]
    companions: Vec<(u64, Companion)>,
    required_inputs: Option<Vec<u64>>,
    /// Every nullifier the pool has marked spent.
    #[serde(default)]
    spent: Vec<Digest>,
    /// `v4` (pool V2, the default) or `v5` (pool V3).
    #[serde(default)]
    version: spend::Version,
    /// V5: the latest block (the one the tree was read at) and the pool's `E` and `Q`.
    #[serde(default)]
    expiry: Option<spend::Expiry>,
}

fn plan_with(keys: &[u8], request: &str, tree: &Tree, rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Out<String> {
    let r: PlanRequest = parse(request, "plan request")?;
    let k = seed_of(keys)?;
    let plan = spend::plan(
        PlanInput {
            keys: &k,
            version: r.version,
            expiry: r.expiry,
            chain: f(&r.chain)?,
            pool: f(&r.pool)?,
            request: r.request,
            notes: &r.notes,
            companions: &r.companions,
            required_inputs: r.required_inputs.as_deref(),
            spent: &r.spent,
            tree: &tree.0,
        },
        rng,
    )
    .map_err(err)?;
    to_json(&plan)
}

/// A checked spend plan (spec §7.2): selection, ordering, sealed outputs and the companion.
#[wasm_bindgen]
pub fn plan_spend(keys: &[u8], request: &str, tree: &Tree) -> Out<String> {
    plan_with(keys, request, tree, &mut OsRng)
}

/// The proved spend, plus its statement as its own JSON string. Serialized directly, never through
/// `serde_json::Value`, which cannot hold a u128 above `u64::MAX` (SDK-IP3).
#[derive(Serialize)]
struct ProvedOut<'a> {
    #[serde(flatten)]
    proved: &'a spend::Proved,
    statement_json: String,
}

fn proved_json(p: &spend::Proved) -> Out<String> {
    to_json(&ProvedOut { proved: p, statement_json: to_json(&p.statement)? })
}

/// Proves a plan (run in a worker): `{version, proof, statement, statement_json, binding,
/// calldata, circuit_hash, nullifiers}`. A V5 plan needs `now` (`{latest_block, window,
/// quantum}`, JSON), and is refused when it can no longer land (AB-SM4); V4 takes `"null"`.
#[wasm_bindgen]
pub fn prove_spend(keys: &[u8], plan: &str, now: &str) -> Out<String> {
    let plan: Plan = parse(plan, "plan")?;
    let now: Option<Expiry> = parse(now, "now")?;
    proved_json(&spend::prove_plan(&seed_of(keys)?, &plan, now.as_ref(), &mut OsRng).map_err(err)?)
}

/// The companion's nullifier, which the wallet checks is unspent before proving (SDK-M17).
#[wasm_bindgen]
pub fn companion_nullifier(companion: &str, chain: &str, pool: &str, asset: &str) -> Out<String> {
    let c: Companion = parse(companion, "companion")?;
    to_json(&c.nullifier(&f(chain)?, &f(pool)?, &f(asset)?).map_err(err)?)
}

/// Checks a server result against the pins; returns the locally computed `{submit_after,
/// valid_until}`. For R0 V5 pass the statement's `valid_until`: the window ends at the server's
/// `send_deadline`.
#[wasm_bindgen]
pub fn check_result(pins: &str, binding: &str, server_result: &str, latest_block: u64, statement_valid_until: Option<u64>) -> Out<String> {
    let pins: Pins = parse(pins, "pins")?;
    let r: ServerResult = parse(server_result, "result")?;
    to_json(&result::check(&pins, binding, &r, latest_block, statement_valid_until).map_err(err)?)
}

// ---------------------------------------------------------------- R0 V5: payment

/// A free full withdrawal's openings (spec §7.2): both outputs' `inner`, or `null` when the plan
/// is not a V5 full withdrawal.
#[wasm_bindgen]
pub fn free_withdrawal_openings(plan: &str) -> Out<String> {
    let plan: Plan = parse(plan, "plan")?;
    to_json(&spend::free_withdrawal_openings(&plan).map_err(err)?)
}

// ---------------------------------------------------------------- the store

#[wasm_bindgen]
pub fn store_seal(keys: &[u8], chain: &str, pool: &str, record_type: &str, record_key: &str, plaintext: &[u8]) -> Out<Vec<u8>> {
    store::seal(&seed_of(keys)?, &f(chain)?, &f(pool)?, record_type, record_key, plaintext, &mut OsRng).map_err(err)
}

#[wasm_bindgen]
pub fn store_open(keys: &[u8], chain: &str, pool: &str, record_type: &str, record_key: &str, sealed: &[u8]) -> Out<Vec<u8>> {
    store::open(&seed_of(keys)?, &f(chain)?, &f(pool)?, record_type, record_key, sealed).map_err(err)
}

#[wasm_bindgen]
pub fn store_record_id(keys: &[u8], chain: &str, pool: &str, record_type: &str, record_key: &str) -> Out<String> {
    Ok(store::record_id(&seed_of(keys)?, &f(chain)?, &f(pool)?, record_type, record_key))
}

// ---------------------------------------------------------------- OHTTP

#[wasm_bindgen]
pub struct OhttpRequest {
    envelope: Vec<u8>,
    context: Option<ohttp_ctx::Context>,
}

mod ohttp_ctx {
    pub type Context = templar_core::ohttp::Pending;
}

#[wasm_bindgen]
impl OhttpRequest {
    /// Encapsulates `method path` with a JSON body under the pinned key configuration list.
    #[wasm_bindgen(constructor)]
    pub fn new(config: &[u8], method: &str, path: &str, body: &[u8]) -> Out<OhttpRequest> {
        let p = templar_core::ohttp::encapsulate(config, method, path, body).map_err(err)?;
        Ok(OhttpRequest { envelope: p.envelope.clone(), context: Some(p) })
    }

    pub fn envelope(&self) -> Vec<u8> {
        self.envelope.clone()
    }

    /// Opens the response (once): `{status, body}` with the body as a byte array.
    pub fn open(&mut self, response: &[u8]) -> Out<String> {
        let p = self.context.take().ok_or_else(|| bad("response already opened"))?;
        let (status, body) = templar_core::ohttp::decapsulate(p.context, response).map_err(err)?;
        to_json(&json!({"status": status, "body": body}))
    }
}

// ---------------------------------------------------------------- tests only

/// Seeded planning and proving for reproducibility tests; absent from release artifacts (SDK-M13).
#[cfg(feature = "test-rng")]
#[wasm_bindgen]
pub fn test_prove_spend_seeded(keys: &[u8], plan: &str, now: &str, rng_seed: u64) -> Out<String> {
    use rand_core::SeedableRng;
    let plan: Plan = parse(plan, "plan")?;
    let now: Option<Expiry> = parse(now, "now")?;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(rng_seed);
    proved_json(&spend::prove_plan(&seed_of(keys)?, &plan, now.as_ref(), &mut rng).map_err(err)?)
}

/// The nine proof facts an honest server returns for `binding` (mock servers in tests only).
#[cfg(feature = "test-rng")]
#[wasm_bindgen]
pub fn test_expected_facts(pins: &str, binding: &str, base_block: u64, base_hash: &str) -> Out<String> {
    let p: Pins = parse(pins, "pins")?;
    let mh = result::message_hash(&p, &f(binding)?).map_err(err)?;
    let s = |x: &str| felt::from_short_string(x).map(|v| felt::to_hex(&v)).map_err(err);
    to_json(&vec![s(&p.proof_version)?, s(&p.proof_variant)?, p.os_program.clone(), s(&p.output_version)?, format!("0x{base_block:x}"),
                  base_hash.to_string(), p.config_hash.clone(), "0x1".into(), felt::to_hex(&mh)])
}

#[cfg(feature = "test-rng")]
#[wasm_bindgen]
pub fn test_plan_spend_seeded(keys: &[u8], request: &str, tree: &Tree, rng_seed: u64) -> Out<String> {
    use rand_core::SeedableRng;
    plan_with(keys, request, tree, &mut rand_chacha::ChaCha20Rng::seed_from_u64(rng_seed))
}

#[cfg(test)]
mod tests {
    /// A u128 withdrawal above `u64::MAX` survives serialization exactly (SDK-IP3).
    #[test]
    fn large_withdrawal_serializes() {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/sepolia-s1.json")).unwrap()).unwrap();
        let mut public: templar_core::payment4::Public = serde_json::from_value(v["public"].clone()).unwrap();
        public.withdrawal_amount = 1u128 << 100;
        let statement = templar_core::spend::Proved {
            version: templar_core::spend::Version::V4, proof: vec!["0x1".into()], nullifiers: public.nullifiers,
            statement: templar_core::spend::Statement::V4(public), binding: "0x1".into(), calldata: vec![], circuit_hash: [0; 8],
        };
        let out = super::proved_json(&statement).unwrap();
        assert!(out.contains(&(1u128 << 100).to_string()));
        let inner: String = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&out).map(|m| m["statement_json"].as_str().unwrap().to_string()).unwrap_or_default();
        assert!(inner.contains("\"withdrawal_amount\":1267650600228229401496703205376"));
    }
}
