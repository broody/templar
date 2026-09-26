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
    /// The relayer's handoff (account-bound spec §7.3, P4b): finished R0 V5 results wait here for
    /// the relayer, which answers each with a transaction hash or a refusal. Absent: this server
    /// does not relay (self-hosted), and clients submit themselves.
    pub relay: Option<Relay>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Relay {
    /// The handoff API's own listener, never the public one: its results are not public before
    /// settlement, and a forged report would steer clients' fallbacks. Loopback, or a private
    /// network or TLS proxy (the token travels in the clear on the listener itself).
    pub listen: String,
    /// The bearer token both sides read (always required, AB-RL10).
    pub token_file: PathBuf,
}

/// Bounds on the virtual-OS run, checked before proving (spec §9, AB-SP4): a job over them is the
/// client's fault. They keep an accepted job in the measured leaf bucket and within `job_memory`.
/// P5 measured R0 V5 in the virtual OS at most 3.61M steps, bound spends with real Ready and
/// Braavos accounts included (bench/account-bound-p5); the builtin caps it measured are in the
/// example configuration. Only ordinary spends are served now (ADR-0027).
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
    /// Blocks left for the relay after proving: at least the relayer's own margin (60 by default,
    /// above the wallet's fallback margin of 40), so admitted jobs are ones it will take.
    #[serde(default = "d_relay_margin")]
    pub relay_margin_blocks: u64,
    /// The L2 gas bound of the virtual transaction (spec §9: set from the measured cost of
    /// `__execute__`; P3 measured about 364–372M in snforge, P5 in the virtual OS).
    #[serde(default = "d_os_l2_gas")]
    pub os_l2_gas: u64,
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
    /// 2 (R0 V4 and P1, pool V2) or 3 (R0 V5, R0 V6 and P1, pool V3). Default 2.
    #[serde(default = "d_pool_version")]
    pub pool_version: u8,
    /// The virtual OS program hash the pre-cutover adapters pin (a routed relation pins its own,
    /// per route).
    pub os_program: String,
    /// The pre-cutover adapters' proof age (a routed relation's route has its own).
    pub max_proof_age: u64,
    /// Pool V3: refuse jobs from this many seconds before a pending verifier (or target shadow
    /// class) change can apply until it applies, is cancelled or lapses (AB-PV7, AB-SP1).
    /// Default: the largest proof age served (`max_proof_age` and every routed relation's own
    /// route) × 6 seconds, a result's life at the slowest block time assumed (recheck N7,
    /// pool-v3-spec §9.5).
    pub pending_margin_secs: Option<u64>,
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

/// A route of a routing adapter (`docs/pool-v3-spec.md` §6.1): its eight fields, in the adapter's
/// Serde order. The proof version, variant and output version are short strings.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RoutePin {
    pub statement: String,
    pub statement_class: String,
    pub account_tag: String,
    pub os_program: String,
    #[serde(default = "d_proof_version")]
    pub proof_version: String,
    #[serde(default = "d_proof_variant")]
    pub proof_variant: String,
    #[serde(default = "d_output_version")]
    pub output_version: String,
    pub max_proof_age: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelationConfig {
    /// `r4` (pool V2), `r5` or `r6` (pool V3) or `p1`.
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
    /// A routing adapter's pinned class (pool-v3-spec §6, §9.2). Absent: a pre-cutover adapter,
    /// whose configuration is read from its storage.
    #[serde(default)]
    pub adapter_class: Option<String>,
    /// A routed relation: every route this release knows (the own route, keyed by
    /// `statement_account`, among them).
    #[serde(default)]
    pub routes: Vec<RoutePin>,
    /// The pinned states of the adapter's route set, each a set of statement addresses from
    /// `routes` (a release pins every state a planned change passes through, §10.2). Default: the
    /// own route alone.
    #[serde(default)]
    pub route_states: Vec<Vec<String>>,
    /// P1 during the cutover (§9.5): the pre-cutover adapter, served while it is still the pool's
    /// verifier; `adapter` is then the P1 routing adapter.
    #[serde(default)]
    pub legacy_adapter: Option<String>,
}

impl RelationConfig {
    pub fn is_routed(&self) -> bool {
        self.adapter_class.is_some()
    }

    /// The own route: the one keyed by this relation's statement account (§9.5).
    pub fn own_route(&self) -> Option<&RoutePin> {
        let own = crate::rpc::felt(&self.statement_account).ok()?;
        self.routes.iter().find(|r| crate::rpc::felt(&r.statement).ok() == Some(own))
    }

    /// The proof age that bounds this relation's results: its own route's, else the network's.
    pub fn max_proof_age(&self, network: &Network) -> u64 {
        self.own_route().map_or(network.max_proof_age, |r| r.max_proof_age)
    }

    /// The OS program this relation's proofs carry: its own route's, else the network's.
    pub fn os_program<'a>(&'a self, network: &'a Network) -> &'a str {
        self.own_route().map_or(network.os_program.as_str(), |r| r.os_program.as_str())
    }

    /// The pinned route-set states, as sets of statement felts (sorted for set comparison).
    pub fn pinned_states(&self) -> Result<Vec<Vec<starknet_types_core::felt::Felt>>> {
        let states: Vec<Vec<String>> =
            if self.route_states.is_empty() { vec![vec![self.statement_account.clone()]] } else { self.route_states.clone() };
        states
            .iter()
            .map(|st| {
                let mut v = st.iter().map(|a| crate::rpc::felt(a)).collect::<Result<Vec<_>>>()?;
                v.sort();
                Ok(v)
            })
            .collect()
    }
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
    /// The PROOF2 leaf bucket every routed relation's job must land in (pool-v3-spec §9.3): the
    /// Cairo trace log size whose leaf verifier the proof's header names, so every spend has the
    /// same public header. 25, the smallest the registry lists.
    #[serde(default = "d_bucket")]
    pub bucket_log_size: u32,
    /// A directory holding a reference `os.pie.zip` (a routed spend's virtual-OS run, the largest
    /// shape). Required to serve a routed relation: at startup the server runs the bucket check on
    /// it and refuses to start if it misses the bucket. A route switch is a new release, so it is
    /// checked again at that restart.
    #[serde(default)]
    pub bucket_reference: Option<PathBuf>,
}

impl Default for Prover {
    fn default() -> Self {
        Prover { cairo_fri_columns: 16, circuit_fri_columns: 16, stream_commitments: false, threads: 16, bucket_log_size: 25, bucket_reference: None }
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
fn d_bucket() -> u32 { 25 }
fn d_blocks_per_job() -> u64 { 60 }
fn d_relay_margin() -> u64 { 60 }
fn d_os_l2_gas() -> u64 { 450_000_000 }
fn d_pool_version() -> u8 { 2 }
fn d_os_steps() -> u64 { 4_000_000 }
fn d_proof_version() -> String { "PROOF2".into() }
fn d_proof_variant() -> String { "VIRTUAL_SNOS".into() }
fn d_output_version() -> String { "VIRTUAL_SNOS0".into() }
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
        if names.len() != c.relations.len() || names.iter().any(|n| !matches!(*n, "r4" | "r5" | "r6" | "p1")) {
            bail!("relations must be distinct, each r4, r5, r6 or p1");
        }
        match c.network.pool_version {
            2 if names.contains(&"r5") || names.contains(&"r6") => bail!("r5 and r6 spends settle on pool V3 (pool_version = 3)"),
            3 if names.contains(&"r4") => bail!("r4 spends settle on pool V2 (pool_version = 2)"),
            2 | 3 => {}
            v => bail!("pool_version {v}: expected 2 or 3"),
        }
        if c.server.max_concurrent_jobs == 0 {
            bail!("max_concurrent_jobs must be at least 1");
        }
        // The PROOF2 registry lists leaf buckets 25 to 29 (pool-v3-spec §9.3); servers pinning
        // different buckets would split the header anonymity set, so 25 is the norm.
        if !(25..=29).contains(&c.prover.bucket_log_size) {
            bail!("prover.bucket_log_size must be a registry leaf bucket, 25 to 29");
        }
        for rel in &c.relations {
            check_relation(&c.network, rel).with_context(|| format!("relation {}", rel.name))?;
        }
        if let Some(r) = &c.relay {
            let addr: std::net::SocketAddr = r.listen.parse().context("relay.listen")?;
            if !names.contains(&"r5") && !names.contains(&"r6") {
                bail!("relay: only R0 V5 and V6 jobs carry a pool call to relay (serve r5 or r6)");
            }
            if !addr.ip().is_loopback() {
                tracing::warn!("relay.listen is not loopback: keep it on a private network or behind TLS");
            }
            if addr.to_string() == c.server.listen {
                bail!("relay.listen must not be the public listener");
            }
        }
        Ok(c)
    }

    pub fn relation(&self, name: &str) -> Option<&RelationConfig> {
        self.relations.iter().find(|r| r.name == name)
    }

    /// Seconds before a pending change's `eta` from which jobs are refused: configured, or the
    /// largest proof age served × 6 (pool-v3-spec §9.5).
    pub fn pending_margin(&self) -> u64 {
        let largest = self.relations.iter().map(|r| r.max_proof_age(&self.network)).max().unwrap_or(0).max(self.network.max_proof_age);
        self.network.pending_margin_secs.unwrap_or(largest * 6)
    }
}

/// A relation's own rules: r6 is routed; a routed relation pins its adapter's class, its own
/// route (whose class and tag are the relation's), and route-set states over known routes, each
/// containing the own route; only p1 names a legacy adapter, and only when routed.
pub(crate) fn check_relation(network: &Network, rel: &RelationConfig) -> Result<()> {
    use crate::rpc::{felt, short_string};
    if rel.name == "r6" && !rel.is_routed() {
        bail!("r6 is served through a routing adapter: set adapter_class and routes");
    }
    if rel.legacy_adapter.is_some() && (rel.name != "p1" || !rel.is_routed()) {
        bail!("legacy_adapter is for a routed p1 during the cutover");
    }
    if !rel.is_routed() {
        if !rel.routes.is_empty() || !rel.route_states.is_empty() {
            bail!("routes need a routing adapter (adapter_class)");
        }
        return Ok(());
    }
    if network.pool_version != 3 {
        bail!("routing adapters serve pool V3");
    }
    felt(rel.adapter_class.as_deref().unwrap_or(""))?;
    let own = rel.own_route().context("routes must include the own route, keyed by statement_account")?;
    if felt(&own.statement_class)? != felt(&rel.statement_class)? || own.account_tag != rel.account_tag {
        bail!("the own route's class and tag must be the relation's");
    }
    // While P1 is served through its legacy adapter, jobs are proved with the own route's values
    // (facts, OS program, deadline), so they must be the legacy adapter's (PR-RC-2).
    if rel.legacy_adapter.is_some()
        && (felt(&own.os_program)? != felt(&network.os_program)?
            || own.max_proof_age != network.max_proof_age
            || (own.proof_version.as_str(), own.proof_variant.as_str(), own.output_version.as_str()) != ("PROOF2", "VIRTUAL_SNOS", "VIRTUAL_SNOS0"))
    {
        bail!("with legacy_adapter, the own route's os_program, max_proof_age and versions must be the legacy adapter's ([network]'s and PROOF2's)");
    }
    let known: Vec<_> = rel.routes.iter().map(|r| felt(&r.statement)).collect::<Result<_>>()?;
    let mut sorted = known.clone();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != known.len() {
        bail!("routes: a statement appears twice");
    }
    for r in &rel.routes {
        for x in [&r.statement, &r.statement_class, &r.os_program] {
            if felt(x)? == starknet_types_core::felt::Felt::ZERO {
                bail!("routes: every field is nonzero");
            }
        }
        for x in [&r.account_tag, &r.proof_version, &r.proof_variant, &r.output_version] {
            short_string(x)?;
        }
        if r.max_proof_age == 0 {
            bail!("routes: max_proof_age is nonzero");
        }
    }
    let own_felt = felt(&own.statement)?;
    for state in rel.pinned_states()? {
        if state.is_empty() || state.len() > 4 {
            bail!("route_states: each state holds 1 to 4 routes");
        }
        if !state.iter().all(|s| known.contains(s)) {
            bail!("route_states: a state names an unknown route");
        }
        if !state.contains(&own_felt) {
            bail!("route_states: every state holds the own route");
        }
    }
    Ok(())
}
