//! The deployment's configuration (spec §8): one TOML file, checked against the chain at startup.
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: Server,
    pub limits: Limits,
    pub network: Network,
    #[serde(rename = "relation")]
    pub relations: Vec<RelationConfig>,
    pub binaries: Binaries,
    pub sandbox: Sandbox,
    #[serde(default)]
    pub prover: Prover,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub listen: String,
    /// Job directories (inputs, logs, results), deleted at the end of retention.
    pub data_dir: PathBuf,
    #[serde(default = "d_retention")]
    pub retention_secs: u64,
    #[serde(default = "d_body")]
    pub max_body_bytes: usize,
    #[serde(default = "d_proof_felts")]
    pub max_proof_felts: usize,
    #[serde(default = "d_one")]
    pub max_concurrent_jobs: usize,
    #[serde(default = "d_queue")]
    pub queue_capacity: usize,
    /// Take the client address from `X-Forwarded-For` (only behind a trusted proxy).
    #[serde(default)]
    pub trust_forwarded_for: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Limits {
    /// Submissions per address bucket (IPv4 address or IPv6 /64) per hour.
    #[serde(default = "d_per_hour")]
    pub submissions_per_hour: u32,
    #[serde(default = "d_two")]
    pub queued_per_address: usize,
    /// Seconds a refused duplicate nullifier waits before it may be tried again, doubling per refusal.
    #[serde(default = "d_backoff")]
    pub duplicate_backoff_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Network {
    pub name: String,
    /// `SN_SEPOLIA` or `SN_MAIN`.
    pub chain_id: String,
    pub rpc_url: String,
    pub pool: String,
    /// The virtual OS program hash the adapters pin.
    pub os_program: String,
    pub max_proof_age: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelationConfig {
    /// `r4` or `p1`.
    pub name: String,
    pub statement_account: String,
    pub statement_class: String,
    pub account_tag: String,
    pub adapter: String,
    /// The bridge build the statement account was compiled from (with `build-record.json`).
    pub bridge_dir: PathBuf,
    pub bridge_record_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Binaries {
    pub os_runner: PathBuf,
    pub prove: PathBuf,
    pub scarb: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sandbox {
    /// A writable, delegated cgroup v2 directory; the server refuses to start without one.
    pub cgroup_root: PathBuf,
    #[serde(default = "d_job_memory")]
    pub job_memory: String,
    #[serde(default = "d_check_memory")]
    pub check_memory: String,
    #[serde(default = "d_check_secs")]
    pub check_seconds: u64,
    #[serde(default = "d_os_secs")]
    pub os_seconds: u64,
    #[serde(default = "d_prove_secs")]
    pub prove_seconds: u64,
    /// Prefix that runs a command with no network (`check` and `prove`).
    #[serde(default = "d_no_network")]
    pub no_network: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Prover {
    #[serde(default = "d_columns")]
    pub cairo_fri_columns: usize,
    #[serde(default = "d_columns")]
    pub circuit_fri_columns: usize,
    #[serde(default)]
    pub stream_commitments: bool,
    #[serde(default = "d_cpus")]
    pub threads: u32,
}

impl Default for Prover {
    fn default() -> Self {
        Prover { cairo_fri_columns: 16, circuit_fri_columns: 16, stream_commitments: false, threads: 4 }
    }
}

fn d_retention() -> u64 { 3600 }
fn d_body() -> usize { 2_000_000 }
fn d_proof_felts() -> usize { 60_000 }
fn d_one() -> usize { 1 }
fn d_queue() -> usize { 16 }
fn d_per_hour() -> u32 { 20 }
fn d_two() -> usize { 2 }
fn d_backoff() -> u64 { 60 }
fn d_job_memory() -> String { "32G".into() }
fn d_check_memory() -> String { "4G".into() }
fn d_cpus() -> u32 { 4 }
fn d_check_secs() -> u64 { 120 }
fn d_os_secs() -> u64 { 600 }
fn d_prove_secs() -> u64 { 1800 }
fn d_columns() -> usize { 16 }
fn d_no_network() -> Vec<String> {
    ["unshare", "--user", "--net"].map(String::from).to_vec()
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: Config = toml::from_str(&text).context("parsing the configuration")?;
        let mut names: Vec<&str> = c.relations.iter().map(|r| r.name.as_str()).collect();
        names.sort();
        names.dedup();
        if names.len() != c.relations.len() || names.iter().any(|n| !matches!(*n, "r4" | "p1")) {
            bail!("relations must be distinct, each r4 or p1");
        }
        if c.server.max_concurrent_jobs == 0 {
            bail!("max_concurrent_jobs must be at least 1");
        }
        Ok(c)
    }

    pub fn relation(&self, name: &str) -> Option<&RelationConfig> {
        self.relations.iter().find(|r| r.name == name)
    }
}
