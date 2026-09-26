//! The pre-check that executes the compiled bridge (spec §4.5) and the job (spec §5).
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use starknet_types_core::hash::{Poseidon, StarkHash};
use starknet_types_core::felt::Felt;

use crate::config::{Config, RelationConfig};
use crate::rpc::{felt, hex, short_string, Rpc};
use crate::sandbox::{self, Limits};
use crate::statement::{Relation, Submission, V5Job};

/// A job failure that is the client's doing (spec §9, ticket states): a bridge rejection, a
/// calldata mismatch, a virtual-OS revert or failed execution, a message mismatch or a cap
/// violation. Tickets stay spent (or are consumed). Every other error (a sandbox that fails to
/// start, the node, a disk, a time-out) is the server's: before job start the tickets are released,
/// after it refunded (AB-SP5).
/// `proven`: the bridge had accepted the proof, so the submitter holds a valid proof for the note
/// (a calldata or output mismatch, and every job failure).
#[derive(Debug)]
pub struct ClientFault {
    pub message: String,
    pub proven: bool,
}

impl std::fmt::Display for ClientFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ClientFault {}

fn client(msg: impl Into<String>) -> anyhow::Error {
    ClientFault { message: msg.into(), proven: false }.into()
}

fn proven_client(msg: impl Into<String>) -> anyhow::Error {
    ClientFault { message: msg.into(), proven: true }.into()
}

pub fn is_client_fault(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<ClientFault>())
}

/// A client fault after the bridge accepted the proof: only then may it back off the note, since
/// anyone can name another's nullifier in a junk proof (spec §9, recheck N10).
pub fn is_proven_fault(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<ClientFault>().is_some_and(|f| f.proven))
}

/// Whether a failed virtual-OS run's log shows the transaction reverted or failed execution (the
/// client's doing) rather than a node, sandbox or time-out failure (the server's). A state read
/// the node failed surfaces inside an execution failure, so those markers win.
pub fn os_client_fault(log: &str) -> bool {
    let server = ["StateReadError", "RPC", "rpc error", "transport", "connection", "Upstream JSON-RPC", "error sending request"];
    log.contains("Reverted transactions are not supported")
        || log.contains("Transaction execution failed") && !server.iter().any(|m| log.contains(m))
}

/// What the bridge returns: `[chain, pool, token, binding]`.
#[derive(Debug, Clone)]
pub struct BridgeOutput {
    pub token: Felt,
    pub binding: Felt,
    pub steps: Option<u64>,
    pub seconds: f64,
}

fn parse_output_felt(s: &str) -> Result<Felt> {
    match s.strip_prefix('-') {
        Some(rest) => Ok(Felt::ZERO - Felt::from_dec_str(rest).context("program output")?),
        None => Felt::from_dec_str(s).context("program output"),
    }
}

/// Executes the relation's bridge on the submission (its standalone `main` decodes and checks
/// the statement, verifies the proof and compares with the submitted statement).
pub async fn check(cfg: &Config, rel: &RelationConfig, sub: &Submission, dir: &Path, id: &str) -> Result<BridgeOutput> {
    let args: Vec<String> = sub.bridge_args().iter().map(hex).collect();
    let args_path = dir.join("bridge-args.json");
    std::fs::write(&args_path, serde_json::to_vec(&args)?)?;
    let cache = dir.join("scarb-cache");
    std::fs::create_dir_all(&cache)?;
    let argv: Vec<String> = [
        "--json", "--offline", "--manifest-path", &rel.bridge_dir.join("Scarb.toml").display().to_string(), "execute", "--no-build",
        "-p", "templar_membership_bridge", "--arguments-file", &args_path.display().to_string(), "--print-program-output",
        "--print-resource-usage", "--output", "none",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let limits = Limits { memory: cfg.sandbox.check_memory.clone(), cpus: 1, seconds: cfg.sandbox.check_seconds, network: false };
    let envs = [("SCARB_CACHE", cache.display().to_string()), ("HOME", dir.display().to_string())];
    let out = sandbox::run(&cfg.sandbox, &format!("check-{id}"), &cfg.binaries.scarb, &argv, &envs, limits).await?;
    std::fs::write(dir.join("check.log"), [out.stdout.as_slice(), out.stderr.as_slice()].concat())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.timed_out {
        bail!("bridge: timed out; retry later");
    }
    if !out.success {
        // Only a Cairo panic (`Panicked with …`) is the bridge rejecting the proof (the client's). A
        // failure without one (killed for memory, a sandbox or disk error, scarb itself crashing)
        // is the server's (recheck N3, N11).
        let panic = stdout
            .lines()
            .chain(String::from_utf8_lossy(&out.stderr).lines())
            .find(|l| l.contains("Panicked with"))
            .map(|l| l.chars().take(300).collect::<String>());
        match panic {
            Some(reason) => return Err(client(format!("bridge: {reason}"))),
            None => bail!("bridge: failed without a verdict; retry later"),
        }
    }
    let program: Vec<Value> = stdout.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|v| v.get("program_output").is_some()).collect();
    let text = program.last().and_then(|v| v["program_output"].as_str()).context("bridge: no program output")?;
    let words: Vec<Felt> = text.split_whitespace().map(parse_output_felt).collect::<Result<_>>()?;
    if words.len() < 4 {
        bail!("bridge: short output");
    }
    let o = &words[words.len() - 4..];
    if o[0] != sub.chain || o[1] != sub.pool {
        return Err(proven_client("bridge: output context differs from the statement"));
    }
    let steps = stdout
        .lines()
        .filter(|l| l.to_lowercase().contains("steps"))
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find_map(|v| v["resources"]["n_steps"].as_u64());
    // R0 V5: the pool call must settle exactly this statement (spec §9 step 7, AB-P28).
    if let Some(j) = &sub.v5 {
        j.pool_call.matches(&j.statement, o[3]).map_err(|e| proven_client(format!("{e:#}")))?;
    }
    Ok(BridgeOutput { token: o[2], binding: o[3], steps, seconds: out.seconds })
}

/// Root known to the pool and no nullifier spent (spec §4.4, §5.1).
pub async fn chain_state(rpc: &Rpc, cfg: &Config, sub: &Submission) -> Result<()> {
    let span = |xs: &[Felt]| [vec![Felt::from(xs.len() as u64)], xs.to_vec()].concat();
    let known = rpc.call(&cfg.network.pool, "root_is_known", &span(&sub.root)).await?;
    if known.first() != Some(&Felt::ONE) {
        bail!("root: unknown to the pool");
    }
    for nf in &sub.nullifiers {
        let spent = rpc.call(&cfg.network.pool, "get_nullifier_spent", &span(nf)).await?;
        if spent.first() != Some(&Felt::ZERO) {
            bail!("nullifier: already spent");
        }
    }
    Ok(())
}

/// The relation's verifier key on pool V3 (`'R0'` or `'P1'`).
fn verifier_kind(rel: &RelationConfig) -> Result<Felt> {
    short_string(if rel.name == "p1" { "P1" } else { "R0" })
}

/// The pool's current verifier for the relation must still be the configured adapter (PS-12),
/// and on pool V3 no verifier change may be due ([`change_due`]).
pub async fn verifier_unchanged(rpc: &Rpc, cfg: &Config, rel: &RelationConfig) -> Result<()> {
    verifier_current(rpc, cfg, rel).await?;
    if cfg.network.pool_version == 3 {
        change_due(rpc, cfg, verifier_kind(rel)?, &format!("the pool's {} verifier", rel.name)).await?;
    }
    Ok(())
}

/// The pool's current verifier for the relation is the configured adapter.
pub async fn verifier_current(rpc: &Rpc, cfg: &Config, rel: &RelationConfig) -> Result<()> {
    let adapter = felt(&rel.adapter)?;
    if cfg.network.pool_version == 3 {
        let v = rpc.call(&cfg.network.pool, "get_verifier", &[verifier_kind(rel)?]).await?;
        if v.first() != Some(&adapter) {
            bail!("the pool's {} verifier is no longer the configured adapter", rel.name);
        }
        return Ok(());
    }
    let getter = if rel.name == "r4" { "get_verifier" } else { "get_policy_verifier" };
    let v = rpc.call(&cfg.network.pool, getter, &[]).await?;
    if v.first() != Some(&adapter) {
        bail!("the pool's {getter} is no longer the configured adapter");
    }
    Ok(())
}

/// Whether a timelocked change under `key` is due (spec §8.4, AB-PV7, AB-SP1): a proposal applies
/// only within `[eta, eta + T]` and then lapses, so a job is refused from `pending_margin_secs`
/// before `eta` until `eta + T`, or until the change is applied or cancelled. A lapsed proposal is
/// no proposal. During that window the pool still settles with the old value, but the owner may
/// switch at any moment, and a proof made now could never land.
pub async fn change_due(rpc: &Rpc, cfg: &Config, key: Felt, what: &str) -> Result<()> {
    let t = cfg.network.parameters.context("pool V3 parameters not read")?.timelock;
    let p = rpc.call(&cfg.network.pool, "get_proposal", &[key]).await?;
    let eta = p.get(1).and_then(crate::v5::to_u64).context("get_proposal")?;
    let now = rpc.latest_timestamp().await?;
    if proposal_live(eta, now, cfg.network.pending_margin(), t) {
        bail!("a change of {what} can apply between {} and {}; retry after it is applied, cancelled or lapsed",
              eta, eta.saturating_add(t));
    }
    Ok(())
}

pub fn proposal_live(eta: u64, now: u64, margin: u64, timelock: u64) -> bool {
    eta != 0 && eta <= now.saturating_add(margin) && now <= eta.saturating_add(timelock)
}

/// A pending verifier change at startup: logged, not fatal (AB-SP1); jobs are refused while it
/// is due.
pub async fn warn_pending(rpc: &Rpc, cfg: &Config, rel: &RelationConfig) {
    if cfg.network.pool_version != 3 {
        return;
    }
    if let Ok(kind) = verifier_kind(rel) {
        if let Err(e) = change_due(rpc, cfg, kind, &format!("the pool's {} verifier", rel.name)).await {
            tracing::warn!("{e:#}");
        }
    }
}

/// Pool V3's settlement rules the server can check before proving (AB-SP7), at the latest block
/// (admission) or the base block (job start). A job the pool would always refuse is the client's.
/// - `valid_until`: nonzero, on the Q grid, and some block up to the deadline satisfies
///   `valid_until ≤ block + E + Q`, with the relay margin to spare;
/// - an invoke: its intent unexpired through the job, an adapter that is neither zero nor the
///   pool, and `COMPUTE ⇔ identity ≠ 0`.
pub fn pool_rules(cfg: &Config, sub: &Submission, latest: u64) -> Result<()> {
    let Some(j) = &sub.v5 else { return Ok(()) };
    let p = cfg.network.parameters.context("pool V3 parameters not read")?;
    let vu = j.statement.valid_until;
    let deadline = send_deadline(cfg, sub, latest);
    if vu == 0 || p.quantum == 0 || vu % p.quantum != 0 {
        return Err(client(format!("valid_until {vu}: not a multiple of the pool's quantum {}", p.quantum)));
    }
    if vu.saturating_sub(p.expiry_window + p.quantum) + cfg.server.relay_margin_blocks > deadline {
        return Err(client(format!("valid_until {vu}: no block up to {deadline} can settle it")));
    }
    if let Some(i) = &j.pool_call.intent {
        // The intent must still be live in the first block that can settle `valid_until`, after
        // the proof, with the relay margin (recheck N4).
        let first = (vu.saturating_sub(p.expiry_window + p.quantum)).max(latest + cfg.server.blocks_per_job + 11);
        let need = first + cfg.server.relay_margin_blocks;
        if i.expiry < need {
            return Err(client(format!("intent expiry {}: this server needs until at least block {need}", i.expiry)));
        }
        if i.adapter == Felt::ZERO || i.adapter == sub.pool {
            return Err(client("intent: the adapter is zero or the pool"));
        }
        let identity = j.statement.identity.iter().any(|w| *w != Felt::ZERO);
        if (i.kind == crate::v5::COMPUTE) != identity {
            return Err(client("intent: COMPUTE needs an identity, INVOKE none"));
        }
    }
    Ok(())
}

/// Pool V3's invoke rules that read its state (AB-SP7): the spend's asset a known ERC20, no
/// destination a registered asset or a contract of another standard, the adapter's class a shadow
/// class exactly for `COMPUTE`, and no change of that class's status due.
pub async fn invoke_state(rpc: &Rpc, cfg: &Config, sub: &Submission) -> Result<()> {
    let Some((j, i)) = sub.v5.as_ref().and_then(|j| j.pool_call.intent.as_ref().map(|i| (j, i))) else { return Ok(()) };
    let pool = &cfg.network.pool;
    let standard = rpc.call(pool, "get_contract_standard", &[j.statement.token_out]).await?;
    if standard.first() != Some(&Felt::from(20u64)) {
        return Err(client("intent: executions move ERC20 only, and the spend's asset is not a known ERC20"));
    }
    for d in &i.destinations {
        let a = rpc.call(pool, "get_asset", &[d.token]).await?;
        if a.first() != Some(&Felt::ZERO) {
            return Err(client("intent: a destination token is a registered asset"));
        }
        // `record_standard(token, ERC20)` refuses a contract recorded under another standard.
        let s = rpc.call(pool, "get_contract_standard", &[d.token]).await?;
        if !matches!(s.first().and_then(crate::v5::to_u64), Some(0) | Some(20)) {
            return Err(client("intent: a destination token is an NFT contract"));
        }
    }
    let class = rpc.class_hash_at(&hex(&i.adapter)).await.map_err(|_| client("intent: the adapter is not deployed"))?;
    let shadow = rpc.call(pool, "is_shadow_class", &[class]).await?;
    if (shadow.first() == Some(&Felt::ONE)) != (i.kind == crate::v5::COMPUTE) {
        return Err(client("intent: COMPUTE targets a shadow class, INVOKE never does"));
    }
    change_due(rpc, cfg, class, "the adapter class's shadow status").await
}

/// Bound spends: the account's class must be one this server serves (AB-SP4), at `block`.
pub async fn bound_class(rpc: &Rpc, cfg: &Config, job: &V5Job, block: Option<u64>) -> Result<()> {
    let class = rpc.class_hash_at_block(block, &hex(&job.statement.account)).await?;
    let served = cfg.network.bound_account_classes.iter().filter_map(|h| felt(h).ok()).any(|h| h == class);
    if !served {
        return Err(client("the bound account's class is not one this server serves"));
    }
    Ok(())
}

/// The virtual-OS resources within the caps (spec §9 bounds before proving, AB-SP4).
pub fn within_caps(cfg: &Config, resources: &Value) -> Result<()> {
    let steps = resources["n_steps"].as_u64().context("os: n_steps")?;
    if steps > cfg.caps.os_steps {
        return Err(client(format!("os: {steps} steps, over this server's cap of {}", cfg.caps.os_steps)));
    }
    let counts = &resources["builtin_instance_counter"];
    for (name, cap) in &cfg.caps.builtins {
        let n = counts.get(name).or_else(|| counts.get(format!("{name}_builtin"))).and_then(Value::as_u64).unwrap_or(0);
        if n > *cap {
            return Err(client(format!("os: {n} {name} instances, over this server's cap of {cap}")));
        }
    }
    Ok(())
}

/// Pool V3's root rule at `deadline` (spec §8.3, §9 step 6, AB-PV6): a replaced root must stay
/// accepted until the spend's last block, `superseded_at − 1 + W ≥ deadline`.
pub async fn root_fresh(rpc: &Rpc, cfg: &Config, sub: &Submission, deadline: u64) -> Result<()> {
    let p = cfg.network.parameters.context("pool V3 parameters not read")?;
    let span = [vec![Felt::from(sub.root.len() as u64)], sub.root.clone()].concat();
    let s = rpc.call(&cfg.network.pool, "get_root_superseded_at", &span).await?;
    let s = s.first().and_then(crate::v5::to_u64).context("get_root_superseded_at")?;
    if s != 0 && s - 1 + p.root_window < deadline {
        bail!("root: replaced, and no longer accepted by block {deadline}; prove again against a newer root");
    }
    Ok(())
}

/// Spec §9 step 5: a statement must leave room for the queue, the proof, `submit_after` and the
/// relay: `valid_until ≥ latest + (jobs ahead + 1) · blocks_per_job + 11 + relay_margin_blocks`.
pub fn expiry_admits(cfg: &Config, valid_until: u64, latest: u64, jobs_ahead: usize) -> Result<()> {
    let need = latest + (jobs_ahead as u64 + 1) * cfg.server.blocks_per_job + 11 + cfg.server.relay_margin_blocks;
    if valid_until < need {
        bail!("valid_until {valid_until} is too close: this server needs until at least block {need}");
    }
    Ok(())
}

/// The last block a result may land in: `min(valid_until, base + max_proof_age)` (spec §9), and
/// for an invoke no later than its intent's expiry (recheck N4).
pub fn send_deadline(cfg: &Config, sub: &Submission, base: u64) -> u64 {
    let proof_age = base + cfg.network.max_proof_age;
    sub.v5.as_ref().map_or(proof_age, |j| {
        let intent = j.pool_call.intent.as_ref().map_or(u64::MAX, |i| i.expiry);
        j.statement.valid_until.min(proof_age).min(intent)
    })
}

/// The bound account's `is_valid_signature` over the spend message, through `starknet_call` at
/// `block` (spec §9 step 8, job start). Advisory: the virtual-OS run is authoritative (AB-IP2).
/// The error never names the account (spec §9, bound-mode data).
pub async fn signature_valid(rpc: &Rpc, job: &V5Job, block: Option<u64>) -> Result<()> {
    let hash = job.statement.message_hash(job.salt);
    let calldata = [vec![hash, Felt::from(job.signature.len() as u64)], job.signature.clone()].concat();
    let account = hex(&job.statement.account);
    match rpc.call_at(block, &account, "is_valid_signature", &calldata).await {
        Ok(r) if r == [short_string("VALID")?] => Ok(()),
        _ => bail!("signature: the bound account does not accept it; authorize the spend again"),
    }
}

pub struct JobResult {
    pub value: Value,
}

/// Runs one admitted job to a result (spec §5). `stage` is updated as it goes; entering `os`
/// spends the job's tickets, and an error there (the spend could not be synced) fails the job
/// before the virtual OS runs (AB-SM5).
pub async fn run(cfg: &Config, rpc: &Rpc, rel: &RelationConfig, sub: &Submission, bridge: &BridgeOutput, dir: &Path, id: &str,
                 stage: &(dyn Fn(&str) -> Result<()> + Send + Sync)) -> Result<JobResult> {
    stage("recheck")?;
    chain_state(rpc, cfg, sub).await?;
    verifier_unchanged(rpc, cfg, rel).await?;
    // Base block: the latest block at job start (PS-3).
    let base = rpc.block_number().await?;
    let base_hash = rpc.block_hash(base).await?;
    let deadline = send_deadline(cfg, sub, base);
    if let Some(j) = &sub.v5 {
        // Job start (spec §9): the admission rules again at the base block, proving time included
        // (AB-SP6); a job that expired in the queue is the server's delay, so its tickets are
        // released. Then the root at the deadline, the pool's rules, and for a bound spend the
        // account's class and signature at the base block.
        expiry_admits(cfg, j.statement.valid_until, base, 0).context("expired in the queue")?;
        root_fresh(rpc, cfg, sub, deadline).await?;
        pool_rules(cfg, sub, base)?;
        invoke_state(rpc, cfg, sub).await?;
        if j.statement.bound() {
            bound_class(rpc, cfg, j, Some(base)).await?;
            signature_valid(rpc, j, Some(base)).await?;
        }
    }
    let nonce = rpc.nonce(base, &rel.statement_account).await?;
    let l2_gas = if sub.v5.is_some() { cfg.server.os_l2_gas } else { 1_000_000_000 };
    let tx = json!({
        "type": "INVOKE", "version": "0x3", "sender_address": rel.statement_account,
        "calldata": sub.execute_calldata().iter().map(hex).collect::<Vec<_>>(), "signature": [], "nonce": nonce,
        "resource_bounds": {
            "l1_gas": {"max_amount": "0x0", "max_price_per_unit": "0x0"},
            "l2_gas": {"max_amount": format!("{l2_gas:#x}"), "max_price_per_unit": "0x0"},
            "l1_data_gas": {"max_amount": "0x0", "max_price_per_unit": "0x0"},
        },
        "tip": "0x0", "paymaster_data": [], "account_deployment_data": [],
        "nonce_data_availability_mode": "L1", "fee_data_availability_mode": "L1",
    });
    std::fs::write(dir.join("os-job.json"), serde_json::to_vec_pretty(&json!({
        "rpc_url": cfg.network.rpc_url, "chain_id": cfg.network.chain_id, "block_number": base, "transaction": tx,
    }))?)?;
    stage("os")?;
    let limits = Limits { memory: cfg.sandbox.job_memory.clone(), cpus: cfg.prover.threads, seconds: cfg.sandbox.os_seconds, network: true };
    let os = sandbox::run(&cfg.sandbox, &format!("os-{id}"), &cfg.binaries.os_runner, &["run".into(), dir.display().to_string()],
                          &[("RAYON_NUM_THREADS", cfg.prover.threads.to_string()), ("TOKIO_WORKER_THREADS", cfg.prover.threads.to_string())],
                          limits).await?;
    std::fs::write(dir.join("os.log"), [os.stdout.as_slice(), os.stderr.as_slice()].concat())?;
    if !os.success {
        let log = String::from_utf8_lossy(&os.stderr);
        if !os.timed_out && os_client_fault(&log) {
            return Err(client("virtual OS: the transaction reverted or failed"));
        }
        bail!("virtual OS run failed{}", if os.timed_out { " (timed out)" } else { "" });
    }
    let result: Value = serde_json::from_slice(&std::fs::read(dir.join("os-result.json"))?)?;
    let messages = result["l2_to_l1_messages"].as_array().context("os: messages")?;
    let num = |v: &Value| -> Result<Felt> {
        match v {
            Value::String(s) => felt(s),
            Value::Number(n) => Ok(Felt::from(n.as_u64().context("number")?)),
            _ => bail!("os: message field"),
        }
    };
    if messages.len() != 1 || num(&messages[0]["from_address"])? != felt(&rel.statement_account)? {
        return Err(client("os: expected one message from the statement account"));
    }
    let payload: Vec<Felt> = messages[0]["payload"].as_array().context("payload")?.iter().map(num).collect::<Result<_>>()?;
    let expected = vec![felt(&rel.statement_class)?, short_string(&rel.account_tag)?, sub.chain, sub.pool, bridge.binding];
    if payload != expected {
        return Err(client("os: the statement account's message differs from the expected one"));
    }
    within_caps(cfg, &result["resources"])?;
    let os_steps = result["resources"]["n_steps"].as_u64();
    stage("prove")?;
    std::fs::write(dir.join("prove-job.json"), serde_json::to_vec(&json!({
        "cairo_fri_columns": cfg.prover.cairo_fri_columns, "circuit_fri_columns": cfg.prover.circuit_fri_columns,
        "stream_commitments": cfg.prover.stream_commitments,
    }))?)?;
    let limits = Limits { memory: cfg.sandbox.job_memory.clone(), cpus: cfg.prover.threads, seconds: cfg.sandbox.prove_seconds, network: false };
    let pr = sandbox::run(&cfg.sandbox, &format!("prove-{id}"), &cfg.binaries.prove, &["prove".into(), dir.display().to_string()],
                          &[("RAYON_NUM_THREADS", cfg.prover.threads.to_string())], limits).await?;
    std::fs::write(dir.join("prove.log"), [pr.stdout.as_slice(), pr.stderr.as_slice()].concat())?;
    if !pr.success {
        bail!("proving failed{}", if pr.timed_out { " (timed out)" } else { "" });
    }
    stage("facts")?;
    let preimage: Vec<String> = serde_json::from_slice(&std::fs::read(dir.join("output-preimage.json"))?)?;
    let mut facts = vec![short_string("PROOF2")?, short_string("VIRTUAL_SNOS")?];
    for p in &preimage {
        facts.push(felt(p)?);
    }
    // Every field the adapter checks (PS-9).
    let message_hash = Poseidon::hash_array(&[vec![felt(&rel.statement_account)?, Felt::ZERO, Felt::from(5u64)], payload.clone()].concat());
    if facts.len() != 9
        || facts[2] != felt(&cfg.network.os_program)?
        || facts[3] != short_string("VIRTUAL_SNOS0")?
        || facts[4] != Felt::from(base)
        || facts[5] != base_hash
        || facts[7] != Felt::ONE
        || facts[8] != message_hash
    {
        bail!("facts: the proof's facts differ from what the adapter requires");
    }
    let proof = std::fs::read(dir.join("proof.bin"))?;
    use base64::Engine;
    let mut value = json!({
        "relation": sub.relation.name(),
        "proof": base64::engine::general_purpose::STANDARD.encode(&proof),
        "proof_facts": facts.iter().map(hex).collect::<Vec<_>>(),
        "base_block": base, "submit_after": base + 11,
        "binding": hex(&bridge.binding), "message_hash": hex(&message_hash),
        "asset": if matches!(sub.relation, Relation::R4 | Relation::R5) { Some(hex(&bridge.token)) } else { None },
        "timings": {"check_seconds": bridge.seconds, "os_seconds": os.seconds, "prove_seconds": pr.seconds,
                    "os_steps": os_steps, "prove_peak_memory_bytes": pr.peak_memory_bytes},
        "proof_bytes": proof.len(),
    });
    match &sub.v5 {
        // A name distinct from the statement's `valid_until` (spec §9), and the pool call the
        // relayer settles (AB-P28).
        Some(j) => {
            value["send_deadline"] = json!(deadline);
            value["pool_call"] = json!({"entry_point": j.pool_call.entry_point,
                                        "calldata": j.pool_call.calldata.iter().map(hex).collect::<Vec<_>>()});
        }
        None => value["valid_until"] = json!(deadline),
    }
    Ok(JobResult { value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PoolParameters;
    use crate::rpc::sn_keccak;
    use crate::v5::StatementV5;
    use axum::Json;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A JSON-RPC stub: `starknet_call` answers by selector, the latest block has `timestamp`.
    async fn stub(calls: HashMap<Felt, Vec<Felt>>, timestamp: u64) -> Rpc {
        stub_args(calls, HashMap::new(), timestamp).await
    }

    /// As `stub`, with answers by (selector, first argument) taking precedence.
    async fn stub_args(calls: HashMap<Felt, Vec<Felt>>, by_arg: HashMap<(Felt, Felt), Vec<Felt>>, timestamp: u64) -> Rpc {
        let (calls, by_arg) = (Arc::new(calls), Arc::new(by_arg));
        let app = axum::Router::new().route("/", axum::routing::post(move |Json(req): Json<Value>| {
            let (calls, by_arg) = (calls.clone(), by_arg.clone());
            async move {
                let result = match req["method"].as_str() {
                    Some("starknet_call") => {
                        let sel = felt(req["params"][0]["entry_point_selector"].as_str().unwrap()).unwrap();
                        let arg = req["params"][0]["calldata"].get(0).and_then(Value::as_str).map(|a| felt(a).unwrap());
                        match arg.and_then(|a| by_arg.get(&(sel, a))).or_else(|| calls.get(&sel)) {
                            Some(r) => json!(r.iter().map(hex).collect::<Vec<_>>()),
                            None => return Json(json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 40, "message": "Contract error"}})),
                        }
                    }
                    Some("starknet_getBlockWithTxHashes") => json!({"timestamp": timestamp, "block_hash": "0x1"}),
                    Some("starknet_getClassHashAt") => json!("0xc1a55"),
                    _ => json!(null),
                };
                Json(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Rpc::new(&url)
    }

    fn v3_config() -> Config {
        let mut c = Config::load(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/prover.example.toml"))).unwrap();
        c.network.pool_version = 3;
        c.network.parameters = Some(PoolParameters { expiry_window: 1500, quantum: 100, root_window: 4096, timelock: 86400 });
        c.network.pending_margin_secs = Some(3600);
        c
    }

    fn sub_with_root() -> Submission {
        Submission {
            relation: Relation::R5, proof: vec![Felt::ZERO], chain: Felt::ONE, pool: Felt::ONE, root: vec![Felt::ONE; 9],
            nullifiers: vec![], statement_args: vec![], v5: None,
        }
    }

    #[tokio::test]
    async fn v3_verifier_and_pending_changes() {
        let cfg = v3_config();
        let rel = cfg.relations[0].clone();
        let adapter = felt(&rel.adapter).unwrap();
        let (gv, gp) = (sn_keccak("get_verifier"), sn_keccak("get_proposal"));
        let ok = stub(HashMap::from([(gv, vec![adapter]), (gp, vec![Felt::ZERO, Felt::ZERO])]), 1000).await;
        verifier_unchanged(&ok, &cfg, &rel).await.unwrap();
        let other = stub(HashMap::from([(gv, vec![adapter + Felt::ONE]), (gp, vec![Felt::ZERO, Felt::ZERO])]), 1000).await;
        assert!(verifier_unchanged(&other, &cfg, &rel).await.is_err(), "another verifier");
        // A pending change: refused within the margin (3600 s), served before it.
        let due = stub(HashMap::from([(gv, vec![adapter]), (gp, vec![Felt::ONE, Felt::from(1000u64 + 3600)])]), 1000).await;
        assert!(verifier_unchanged(&due, &cfg, &rel).await.is_err(), "a change due within the margin");
        let later = stub(HashMap::from([(gv, vec![adapter]), (gp, vec![Felt::ONE, Felt::from(1000u64 + 3601)])]), 1000).await;
        verifier_unchanged(&later, &cfg, &rel).await.unwrap();
        // Refused through `eta + T`; a lapsed proposal (the review's probe) is none (AB-SP1).
        let at = |now: u64| stub(HashMap::from([(gv, vec![adapter]), (gp, vec![Felt::ONE, Felt::from(1_000_000u64)])]), now);
        assert!(verifier_unchanged(&at(1_000_000 + 86_400).await, &cfg, &rel).await.is_err(), "the last second of the window");
        verifier_unchanged(&at(1_000_000 + 86_401).await, &cfg, &rel).await.unwrap();
        verifier_unchanged(&at(10_000_000).await, &cfg, &rel).await.unwrap();
        // Startup only needs the current verifier.
        verifier_current(&at(1_000_000).await, &cfg, &rel).await.unwrap();
    }

    #[test]
    fn proposal_windows() {
        // Margin 3600, T 86400, eta 10_000.
        assert!(!proposal_live(0, 5_000, 3600, 86_400), "no proposal");
        assert!(!proposal_live(10_000, 6_399, 3600, 86_400));
        assert!(proposal_live(10_000, 6_400, 3600, 86_400));
        assert!(proposal_live(10_000, 96_400, 3600, 86_400));
        assert!(!proposal_live(10_000, 96_401, 3600, 86_400), "lapsed");
        assert!(proposal_live(u64::MAX - 5, u64::MAX - 5, 3600, 86_400), "no overflow");
    }

    #[test]
    fn faults_by_cause() {
        // Revert and failed execution are the client's; a node failure inside execution, a time-out
        // or anything else the server's (AB-SP5).
        assert!(os_client_fault("Error: virtual OS: Reverted transactions are not supported; hash: 0x1, revert reason: x"));
        assert!(os_client_fault("Error: virtual OS: Transaction execution failed: Execution failed. Failure reason: 0x61"));
        assert!(!os_client_fault("Error: virtual OS: Transaction execution failed: StateReadError(\"error sending request\")"));
        assert!(!os_client_fault("Error: virtual OS: RPC provider error: connection refused"));
        assert!(!os_client_fault(""));
        let e = client("bridge: panicked").context("admission");
        assert!(is_client_fault(&e) && !is_proven_fault(&e));
        assert!(is_proven_fault(&proven_client("pool call: mismatch").context("admission")));
        assert!(!is_client_fault(&anyhow::anyhow!("sandbox: spawn failed")));
    }

    #[test]
    fn caps_before_proving() {
        let mut cfg = v3_config();
        cfg.caps.os_steps = 1000;
        cfg.caps.builtins.insert("poseidon".into(), 10);
        within_caps(&cfg, &json!({"n_steps": 1000, "builtin_instance_counter": {"poseidon_builtin": 10, "range_check_builtin": 99}})).unwrap();
        let over = within_caps(&cfg, &json!({"n_steps": 1001, "builtin_instance_counter": {}})).unwrap_err();
        assert!(is_client_fault(&over));
        assert!(is_client_fault(&within_caps(&cfg, &json!({"n_steps": 5, "builtin_instance_counter": {"poseidon": 11}})).unwrap_err()));
        assert!(within_caps(&cfg, &json!({})).is_err(), "no step count");
    }

    fn statement(valid_until: u64) -> StatementV5 {
        StatementV5 {
            chain: short_string("SN_SEPOLIA").unwrap(), pool: Felt::from(0x7e57b301u64), token_out: Felt::from(0x7e57b3a1u64),
            root: vec![Felt::ONE; 9], nullifiers: [vec![Felt::ONE; 9], vec![Felt::TWO; 9]],
            commitments: [vec![Felt::ONE; 9], vec![Felt::TWO; 9]], deliveries: [Felt::ONE, Felt::TWO],
            withdrawal_recipient: Felt::ZERO, withdrawal_amount: Felt::ZERO, intent: Felt::ZERO, identity: vec![Felt::ZERO; 9],
            account: Felt::ZERO, valid_until,
        }
    }

    fn v5_sub(st: StatementV5, intent: Option<crate::v5::Intent>) -> Submission {
        let pool_call = crate::v5::PoolCall { entry_point: "apply_spend".into(), calldata: vec![], spend: st.clone(), binding: st.binding(), intent };
        Submission {
            relation: Relation::R5, proof: vec![], chain: st.chain, pool: st.pool, root: st.root.clone(), nullifiers: vec![],
            statement_args: vec![], v5: Some(V5Job { pool_call, statement: st, salt: Felt::ZERO, signature: vec![] }),
        }
    }

    fn intent(kind: u64, adapter: u64, expiry: u64) -> crate::v5::Intent {
        crate::v5::Intent { kind, adapter: Felt::from(adapter), nonce: Felt::ZERO, expiry, calldata: vec![], destinations: vec![
            crate::v5::Destination { note_id: Felt::ONE, token: Felt::from(0x70u64), minimum: Felt::ONE, inner: vec![Felt::ONE; 9], ciphertext: vec![Felt::ONE; 10] },
        ] }
    }

    #[test]
    fn pool_rules_mirror_the_pool() {
        let cfg = v3_config();
        // E 1500, Q 100, max_proof_age from the example; latest 5000.
        let age = cfg.network.max_proof_age;
        pool_rules(&cfg, &v5_sub(statement(6500), None), 5000).unwrap();
        for bad in [0, 6550] {
            assert!(is_client_fault(&pool_rules(&cfg, &v5_sub(statement(bad), None), 5000).unwrap_err()), "{bad}");
        }
        // The last settling block is the deadline, 5000 + age: valid_until − E − Q + margin ≤ it.
        let last = (5000 + age + 1600 - 30) / 100 * 100;
        pool_rules(&cfg, &v5_sub(statement(last), None), 5000).unwrap();
        assert!(pool_rules(&cfg, &v5_sub(statement(last + 100), None), 5000).is_err());
        // Invokes: expiry through the job, an adapter neither zero nor the pool, COMPUTE ⇔ identity.
        let need = 5000 + 60 + 11 + 30;
        pool_rules(&cfg, &v5_sub(statement(6500), Some(intent(0, 0xada, need))), 5000).unwrap();
        assert!(pool_rules(&cfg, &v5_sub(statement(6500), Some(intent(0, 0xada, need - 1))), 5000).is_err());
        assert!(pool_rules(&cfg, &v5_sub(statement(6500), Some(intent(0, 0, need))), 5000).is_err());
        assert!(pool_rules(&cfg, &v5_sub(statement(6500), Some(intent(0, 0x7e57b301, need))), 5000).is_err());
        assert!(pool_rules(&cfg, &v5_sub(statement(6500), Some(intent(1, 0xada, need))), 5000).is_err(), "COMPUTE without identity");
        let mut with_id = statement(6500);
        with_id.identity[3] = Felt::ONE;
        pool_rules(&cfg, &v5_sub(with_id.clone(), Some(intent(1, 0xada, need))), 5000).unwrap();
        assert!(pool_rules(&cfg, &v5_sub(with_id, Some(intent(0, 0xada, need))), 5000).is_err(), "INVOKE with identity");
        // The review's probe (recheck N4): valid_until 6800 settles from block 5200 only, so an
        // intent expiring at 5101 could never land; it must last to 5200 plus the relay margin.
        assert!(pool_rules(&cfg, &v5_sub(statement(6800), Some(intent(0, 0xada, 5101))), 5000).is_err());
        assert!(pool_rules(&cfg, &v5_sub(statement(6800), Some(intent(0, 0xada, 5229))), 5000).is_err());
        pool_rules(&cfg, &v5_sub(statement(6800), Some(intent(0, 0xada, 5230))), 5000).unwrap();
        // The deadline never passes the intent's expiry.
        assert_eq!(send_deadline(&cfg, &v5_sub(statement(6800), Some(intent(0, 0xada, 5230))), 5000), 5230);
        assert_eq!(send_deadline(&cfg, &v5_sub(statement(6800), None), 5000), 6800.min(5000 + age));
    }

    #[tokio::test]
    async fn invoke_state_mirrors_the_pool() {
        let cfg = v3_config();
        let sub = |kind| v5_sub(statement(6500), Some(intent(kind, 0xada, 9000)));
        let (std_, asset, shadow, prop) = (sn_keccak("get_contract_standard"), sn_keccak("get_asset"), sn_keccak("is_shadow_class"), sn_keccak("get_proposal"));
        let chain = |standard: u64, registered: u64, is_shadow: bool, eta: u64| {
            stub(HashMap::from([
                (std_, vec![Felt::from(standard)]), (asset, vec![Felt::from(registered), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
                (shadow, vec![if is_shadow { Felt::ONE } else { Felt::ZERO }]), (prop, vec![Felt::ONE, Felt::from(eta)]),
            ]), 1000)
        };
        invoke_state(&chain(20, 0, false, 0).await, &cfg, &sub(0)).await.unwrap();
        invoke_state(&chain(20, 0, true, 0).await, &cfg, &sub(1)).await.unwrap();
        assert!(invoke_state(&chain(721, 0, false, 0).await, &cfg, &sub(0)).await.is_err(), "not an ERC20");
        assert!(invoke_state(&chain(20, 20, false, 0).await, &cfg, &sub(0)).await.is_err(), "a registered destination");
        assert!(invoke_state(&chain(20, 0, true, 0).await, &cfg, &sub(0)).await.is_err(), "INVOKE on a shadow class");
        assert!(invoke_state(&chain(20, 0, false, 0).await, &cfg, &sub(1)).await.is_err(), "COMPUTE on another class");
        assert!(invoke_state(&chain(20, 0, true, 2000).await, &cfg, &sub(1)).await.is_err(), "the class's status is changing");
        // A destination recorded as an NFT contract would fail `record_standard` (recheck N4).
        let nft = stub_args(
            HashMap::from([(asset, vec![Felt::ZERO; 4]), (shadow, vec![Felt::ZERO]), (prop, vec![Felt::ZERO, Felt::ZERO])]),
            HashMap::from([((std_, Felt::from(0x7e57b3a1u64)), vec![Felt::from(20u64)]), ((std_, Felt::from(0x70u64)), vec![Felt::from(721u64)])]),
            1000,
        ).await;
        assert!(invoke_state(&nft, &cfg, &sub(0)).await.is_err(), "an NFT destination");
        // A plain spend reads nothing.
        invoke_state(&stub(HashMap::new(), 0).await, &cfg, &v5_sub(statement(6500), None)).await.unwrap();
    }

    #[tokio::test]
    async fn bound_classes_served() {
        let mut cfg = v3_config();
        let mut st = statement(6500);
        st.account = Felt::from(0xacc0u64);
        let sub = v5_sub(st, None);
        let job = sub.v5.as_ref().unwrap();
        let rpc = stub(HashMap::new(), 0).await;
        cfg.network.bound_account_classes = vec!["0x1234".into()];
        assert!(is_client_fault(&bound_class(&rpc, &cfg, job, Some(7)).await.unwrap_err()));
        cfg.network.bound_account_classes.push("0xc1a55".into());
        bound_class(&rpc, &cfg, job, Some(7)).await.unwrap();
    }

    #[tokio::test]
    async fn v3_root_freshness_at_the_deadline() {
        let cfg = v3_config();
        let sel = sn_keccak("get_root_superseded_at");
        // The current root (never replaced) is always fine.
        let current = stub(HashMap::from([(sel, vec![Felt::ZERO])]), 0).await;
        root_fresh(&current, &cfg, &sub_with_root(), 10_000_000).await.unwrap();
        // Replaced at block 1000 (stored 1001): accepted through 1000 + W.
        let replaced = stub(HashMap::from([(sel, vec![Felt::from(1001u64)])]), 0).await;
        root_fresh(&replaced, &cfg, &sub_with_root(), 1000 + 4096).await.unwrap();
        assert!(root_fresh(&replaced, &cfg, &sub_with_root(), 1000 + 4097).await.is_err());
    }

    #[tokio::test]
    async fn bound_signature_check() {
        let st = StatementV5 {
            chain: short_string("SN_SEPOLIA").unwrap(), pool: Felt::from(0x7e57b301u64), token_out: Felt::ZERO,
            root: vec![Felt::ONE; 9], nullifiers: [vec![Felt::ONE; 9], vec![Felt::TWO; 9]],
            commitments: [vec![Felt::ONE; 9], vec![Felt::TWO; 9]], deliveries: [Felt::ONE, Felt::TWO],
            withdrawal_recipient: Felt::ZERO, withdrawal_amount: Felt::ZERO, intent: Felt::ZERO, identity: vec![Felt::ZERO; 9],
            account: Felt::from(0x7e57b3c0u64), valid_until: 6500,
        };
        let job = V5Job {
            pool_call: crate::v5::PoolCall {
                entry_point: "apply_spend".into(), calldata: vec![], spend: st.clone(), binding: st.binding(), intent: None,
            },
            statement: st, salt: Felt::from(5u64), signature: vec![Felt::ONE, Felt::TWO],
        };
        let sel = sn_keccak("is_valid_signature");
        let valid = stub(HashMap::from([(sel, vec![short_string("VALID").unwrap()])]), 0).await;
        signature_valid(&valid, &job, None).await.unwrap();
        signature_valid(&valid, &job, Some(123)).await.unwrap();
        for answer in [vec![Felt::ZERO], vec![short_string("VALID").unwrap(), Felt::ZERO], vec![]] {
            let rpc = stub(HashMap::from([(sel, answer)]), 0).await;
            let e = signature_valid(&rpc, &job, None).await.unwrap_err().to_string();
            assert!(e.contains("does not accept") && !e.contains("7e57b3c0"), "{e}");
        }
        // A reverting account.
        let reverts = stub(HashMap::new(), 0).await;
        assert!(signature_valid(&reverts, &job, None).await.is_err());
    }

    #[test]
    fn expiry_and_deadline_rules() {
        let cfg = v3_config();
        // valid_until ≥ latest + (ahead + 1)·60 + 11 + 30.
        assert!(expiry_admits(&cfg, 1000 + 60 + 41, 1000, 0).is_ok());
        assert!(expiry_admits(&cfg, 1000 + 60 + 40, 1000, 0).is_err());
        assert!(expiry_admits(&cfg, 1000 + 3 * 60 + 41, 1000, 2).is_ok());
        assert!(expiry_admits(&cfg, 1000 + 3 * 60 + 40, 1000, 2).is_err());
    }
}
