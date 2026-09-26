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
    /// Oblivious HTTP (spec §2); absent means plain HTTP only.
    pub ohttp: Option<Ohttp>,
    /// Paying for the service (tickets and free full withdrawals); absent means free.
    pub payment: Option<crate::tickets::PaymentConfig>,
    #[serde(default)]
    pub caps: Caps,
}

/// Bounds on the virtual-OS run, checked before proving (spec §9, AB-SP4): a job over them is the
/// client's fault. With the bound account classes they keep an accepted job in the measured leaf
/// bucket and within `job_memory`. The defaults are P0b's measurements (3.41M steps for the R0
/// transaction with an inline signature check, at most 172k for a real account's call) with about
/// 10% headroom; P5 sets them from the bound transactions measured in the virtual OS.
#[derive(Debug, Clone, Deserialize)]
pub struct Caps {
    #[serde(default = "d_os_steps")]
    pub os_steps: u64,
    /// Builtin instances by name (`range_check`, `poseidon`, …), as the PIE's execution resources
    /// name them; a builtin not named is not capped.
    #[serde(default)]
    pub builtins: std::collections::BTreeMap<String, u64>,
}

impl Default for Caps {
    fn default() -> Self {
        Caps { os_steps: d_os_steps(), builtins: Default::default() }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Ohttp {
    /// A file holding the hex X25519 private key (64 hex characters). Rotate by replacing it and
    /// restarting; clients re-fetch `/ohttp-keys` (cached for an hour).
    pub key_file: PathBuf,
    /// Submissions per relay address per hour (all of a relay's clients share it).
    #[serde(default = "d_relay_per_hour")]
    pub submissions_per_hour_per_relay: u32,
    /// Relay addresses or CIDR blocks that get relay limits (PI-12). An OHTTP envelope from any
    /// other address is limited like a direct client.
    #[serde(default)]
    pub relays: Vec<String>,
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
    /// Pre-checks (bridge executions) at once; submissions beyond it are refused, not queued.
    #[serde(default = "d_two")]
    pub max_concurrent_checks: usize,
    #[serde(default = "d_queue")]
    pub queue_capacity: usize,
    /// Take the client address from `X-Forwarded-For` (only behind a trusted proxy).
    #[serde(default)]
    pub trust_forwarded_for: bool,
    /// R0 V5 admission (spec §9 step 5): the blocks one queued job takes, and the relay margin. A
    /// statement is refused unless `valid_until ≥ latest + (jobs ahead + 1) · blocks_per_job + 11 +
    /// relay_margin_blocks`.
    #[serde(default = "d_blocks_per_job")]
    pub blocks_per_job: u64,
    #[serde(default = "d_relay_margin")]
    pub relay_margin_blocks: u64,
    /// The L2 gas bound of the virtual transaction (spec §9: set from the measured cost of
    /// `__execute__`; P3 measured about 364–372M in snforge, P5 in the virtual OS).
    #[serde(default = "d_os_l2_gas")]
    pub os_l2_gas: u64,
    /// Seconds a bound job's result is kept when the client does not acknowledge it (spec §9).
    #[serde(default = "d_bound_retention")]
    pub bound_retention_secs: u64,
    /// Bound jobs' directories (the account, salt and signature sit in their inputs, PIE and
    /// logs): a tmpfs, apart from `data_dir` (spec §9, bound-mode data, AB-SP10). Required with
    /// `operator_node`.
    pub bound_data_dir: Option<PathBuf>,
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
    /// 2 (R0 V4 and P1, pool V2) or 3 (R0 V5 and P1, pool V3). Default 2.
    #[serde(default = "d_pool_version")]
    pub pool_version: u8,
    /// The virtual OS program hash the adapters pin.
    pub os_program: String,
    pub max_proof_age: u64,
    /// The node is the operator's own (spec §9, AB-P10): required to serve bound spends, whose
    /// account, nullifiers and root checks it sees together.
    #[serde(default)]
    pub operator_node: bool,
    /// Pool V3: refuse jobs from this many seconds before a pending verifier (or target shadow
    /// class) change can apply until it applies, is cancelled or lapses (AB-PV7, AB-SP1).
    /// Default `max_proof_age × 6` seconds, a result's life at the slowest block time assumed
    /// (recheck N7).
    pub pending_margin_secs: Option<u64>,
    /// Bound spends: the account classes served (the classes whose virtual-OS resources were
    /// measured, spec §9 bounds before proving, AB-SP4). Required with `operator_node`.
    #[serde(default)]
    pub bound_account_classes: Vec<String>,
    /// Pool V3's `E`, `Q`, `W`, `T`, read at startup.
    #[serde(skip)]
    pub parameters: Option<PoolParameters>,
}

/// Pool V3's constructor constants (`get_parameters`).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PoolParameters {
    pub expiry_window: u64,
    pub quantum: u64,
    pub root_window: u64,
    pub timelock: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelationConfig {
    /// `r4` (pool V2), `r5` (pool V3) or `p1`.
    pub name: String,
    pub statement_account: String,
    pub statement_class: String,
    pub account_tag: String,
    pub adapter: String,
    /// The bridge build the statement account was compiled from (with `build-record.json`).
    pub bridge_dir: PathBuf,
    pub bridge_record_sha256: String,
    /// sha256 of the compiled bridge (`target/dev/templar_membership_bridge.executable.json`),
    /// the program the pre-check executes (PI-6).
    pub bridge_executable_sha256: String,
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
    /// Proving threads per job (and the job's CPU limit). 16 halves the proof time against 4;
    /// beyond 16 there is almost no gain (bench/m31-private-wrapper/proof2-large, core scaling).
    #[serde(default = "d_threads")]
    pub threads: u32,
}

impl Default for Prover {
    fn default() -> Self {
        Prover { cairo_fri_columns: 16, circuit_fri_columns: 16, stream_commitments: false, threads: 16 }
    }
}

fn d_retention() -> u64 { 3600 }
fn d_body() -> usize { 2_000_000 }
fn d_proof_felts() -> usize { 60_000 }
fn d_one() -> usize { 1 }
fn d_queue() -> usize { 16 }
fn d_per_hour() -> u32 { 20 }
fn d_two() -> usize { 2 }
fn d_relay_per_hour() -> u32 { 400 }
fn d_backoff() -> u64 { 60 }
fn d_job_memory() -> String { "32G".into() }
fn d_check_memory() -> String { "2G".into() }
fn d_check_secs() -> u64 { 120 }
fn d_os_secs() -> u64 { 600 }
fn d_prove_secs() -> u64 { 1800 }
fn d_columns() -> usize { 16 }
fn d_threads() -> u32 { 16 }
fn d_blocks_per_job() -> u64 { 60 }
fn d_relay_margin() -> u64 { 30 }
fn d_os_l2_gas() -> u64 { 450_000_000 }
fn d_bound_retention() -> u64 { 600 }
fn d_pool_version() -> u8 { 2 }
fn d_os_steps() -> u64 { 4_000_000 }
fn d_no_network() -> Vec<String> {
    ["unshare", "--user", "--net"].map(String::from).to_vec()
}

impl Network {
    /// Seconds before a pending change's `eta` from which jobs are refused (AB-PV7, AB-SP1).
    pub fn pending_margin(&self) -> u64 {
        self.pending_margin_secs.unwrap_or(self.max_proof_age * 6)
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: Config = toml::from_str(&text).context("parsing the configuration")?;
        let mut names: Vec<&str> = c.relations.iter().map(|r| r.name.as_str()).collect();
        names.sort();
        names.dedup();
        if names.len() != c.relations.len() || names.iter().any(|n| !matches!(*n, "r4" | "r5" | "p1")) {
            bail!("relations must be distinct, each r4, r5 or p1");
        }
        match c.network.pool_version {
            2 if names.contains(&"r5") => bail!("r5 spends settle on pool V3 (pool_version = 3)"),
            3 if names.contains(&"r4") => bail!("r4 spends settle on pool V2 (pool_version = 2)"),
            2 | 3 => {}
            v => bail!("pool_version {v}: expected 2 or 3"),
        }
        if c.server.max_concurrent_jobs == 0 {
            bail!("max_concurrent_jobs must be at least 1");
        }
        if c.network.operator_node && names.contains(&"r5") {
            if c.server.bound_data_dir.is_none() {
                bail!("operator_node (bound spends) needs server.bound_data_dir, a tmpfs");
            }
            if c.network.bound_account_classes.is_empty() {
                bail!("operator_node (bound spends) needs network.bound_account_classes");
            }
            for h in &c.network.bound_account_classes {
                crate::rpc::felt(h).with_context(|| format!("bound_account_classes: {h}"))?;
            }
        }
        Ok(c)
    }

    pub fn relation(&self, name: &str) -> Option<&RelationConfig> {
        self.relations.iter().find(|r| r.name == name)
    }
}
