//! A minimal Starknet JSON-RPC client (v0.10) and felt helpers.
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use starknet_types_core::felt::Felt;

/// Parses a `0x` hex felt, requiring it to be canonical (below the field prime).
pub fn felt(hex: &str) -> Result<Felt> {
    let digits = hex.strip_prefix("0x").context("felt: expected 0x hex")?;
    if digits.is_empty() || digits.len() > 64 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("felt: malformed hex");
    }
    let padded = format!("{digits:0>64}");
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16)?;
    }
    let f = Felt::from_bytes_be(&bytes);
    if f.to_bytes_be() != bytes {
        bail!("felt: not canonical (at or above the field prime)");
    }
    Ok(f)
}

pub fn hex(f: &Felt) -> String {
    format!("{:#x}", f)
}

/// `sn_keccak`: Keccak-256 truncated to 250 bits (selectors and simple storage addresses).
pub fn sn_keccak(name: &str) -> Felt {
    let mut h: [u8; 32] = Keccak256::digest(name.as_bytes()).into();
    h[0] &= 0x03;
    Felt::from_bytes_be(&h)
}

/// A Cairo short string as a felt.
pub fn short_string(s: &str) -> Result<Felt> {
    if s.len() > 31 || !s.is_ascii() {
        bail!("short string too long or not ASCII: {s}");
    }
    let mut bytes = [0u8; 32];
    bytes[32 - s.len()..].copy_from_slice(s.as_bytes());
    Ok(Felt::from_bytes_be(&bytes))
}

#[derive(Clone)]
pub struct Rpc {
    url: String,
    http: reqwest::Client,
}

impl Rpc {
    pub fn new(url: &str) -> Rpc {
        Rpc { url: url.to_string(), http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap() }
    }

    pub async fn call_raw(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let v: Value = self.http.post(&self.url).json(&body).send().await?.json().await?;
        if let Some(e) = v.get("error") {
            bail!("rpc {method}: {e}");
        }
        v.get("result").cloned().context("rpc: no result")
    }

    pub async fn chain_id(&self) -> Result<Felt> {
        felt(self.call_raw("starknet_chainId", json!([])).await?.as_str().context("chainId")?)
    }

    pub async fn block_number(&self) -> Result<u64> {
        self.call_raw("starknet_blockNumber", json!([])).await?.as_u64().context("blockNumber")
    }

    pub async fn block_hash(&self, number: u64) -> Result<Felt> {
        let b = self.call_raw("starknet_getBlockWithTxHashes", json!([{"block_number": number}])).await?;
        felt(b["block_hash"].as_str().context("block_hash")?)
    }

    pub async fn nonce(&self, block: u64, address: &str) -> Result<String> {
        Ok(self.call_raw("starknet_getNonce", json!([{"block_number": block}, address])).await?.as_str().context("nonce")?.to_string())
    }

    pub async fn class_hash_at(&self, address: &str) -> Result<Felt> {
        self.class_hash_at_block(None, address).await
    }

    /// The class hash at `block` (the latest when `None`).
    pub async fn class_hash_at_block(&self, block: Option<u64>, address: &str) -> Result<Felt> {
        let at = block.map_or(json!("latest"), |n| json!({"block_number": n}));
        felt(self.call_raw("starknet_getClassHashAt", json!([at, address])).await?.as_str().context("class hash")?)
    }

    pub async fn storage_at(&self, address: &str, key: &Felt) -> Result<Felt> {
        felt(self.call_raw("starknet_getStorageAt", json!([address, hex(key), "latest"])).await?.as_str().context("storage")?)
    }

    /// A view call at the latest block.
    pub async fn call(&self, address: &str, function: &str, calldata: &[Felt]) -> Result<Vec<Felt>> {
        self.call_at(None, address, function, calldata).await
    }

    /// A view call at `block` (the latest when `None`).
    pub async fn call_at(&self, block: Option<u64>, address: &str, function: &str, calldata: &[Felt]) -> Result<Vec<Felt>> {
        let req = json!({"contract_address": address, "entry_point_selector": hex(&sn_keccak(function)),
                         "calldata": calldata.iter().map(hex).collect::<Vec<_>>()});
        let at = match block {
            Some(n) => json!({"block_number": n}),
            None => json!("latest"),
        };
        let r = self.call_raw("starknet_call", json!([req, at])).await?;
        r.as_array().context("call result")?.iter().map(|v| felt(v.as_str().context("felt")?)).collect()
    }

    /// The latest block's timestamp.
    pub async fn latest_timestamp(&self) -> Result<u64> {
        let b = self.call_raw("starknet_getBlockWithTxHashes", json!(["latest"])).await?;
        b["timestamp"].as_u64().context("timestamp")
    }
}
