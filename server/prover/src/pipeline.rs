//! The pre-check that executes the compiled bridge (spec §4.5) and the job (spec §5).
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use starknet_types_core::hash::{Poseidon, StarkHash};
use starknet_types_core::felt::Felt;

use crate::config::{Config, RelationConfig};
use crate::rpc::{felt, hex, short_string, Rpc};
use crate::sandbox::{self, Limits};
use crate::statement::{Relation, Submission};

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
    if !out.success {
        let reason = stdout
            .lines()
            .chain(String::from_utf8_lossy(&out.stderr).lines())
            .find(|l| l.to_lowercase().contains("panicked"))
            .map(|l| l.chars().take(300).collect::<String>())
            .unwrap_or_else(|| if out.timed_out { "timed out".into() } else { "the bridge rejected the proof".into() });
        bail!("bridge: {reason}");
    }
    let program: Vec<Value> = stdout.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|v| v.get("program_output").is_some()).collect();
    let text = program.last().and_then(|v| v["program_output"].as_str()).context("bridge: no program output")?;
    let words: Vec<Felt> = text.split_whitespace().map(parse_output_felt).collect::<Result<_>>()?;
    if words.len() < 4 {
        bail!("bridge: short output");
    }
    let o = &words[words.len() - 4..];
    if o[0] != sub.chain || o[1] != sub.pool {
        bail!("bridge: output context differs from the statement");
    }
    let steps = stdout
        .lines()
        .filter(|l| l.to_lowercase().contains("steps"))
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find_map(|v| v["resources"]["n_steps"].as_u64());
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

/// The pool's current verifier for the relation must still be the configured adapter (PS-12).
pub async fn verifier_unchanged(rpc: &Rpc, cfg: &Config, rel: &RelationConfig) -> Result<()> {
    let getter = if rel.name == "r4" { "get_verifier" } else { "get_policy_verifier" };
    let v = rpc.call(&cfg.network.pool, getter, &[]).await?;
    if v.first() != Some(&felt(&rel.adapter)?) {
        bail!("the pool's {getter} is no longer the configured adapter");
    }
    Ok(())
}

pub struct JobResult {
    pub value: Value,
}

/// Runs one admitted job to a result (spec §5). `stage` is updated as it goes.
pub async fn run(cfg: &Config, rpc: &Rpc, rel: &RelationConfig, sub: &Submission, bridge: &BridgeOutput, dir: &Path, id: &str,
                 stage: &(dyn Fn(&str) + Send + Sync)) -> Result<JobResult> {
    stage("recheck");
    chain_state(rpc, cfg, sub).await?;
    verifier_unchanged(rpc, cfg, rel).await?;
    // Base block: the latest block at job start (PS-3).
    let base = rpc.block_number().await?;
    let base_hash = rpc.block_hash(base).await?;
    let nonce = rpc.nonce(base, &rel.statement_account).await?;
    let tx = json!({
        "type": "INVOKE", "version": "0x3", "sender_address": rel.statement_account,
        "calldata": sub.proof.iter().map(hex).collect::<Vec<_>>(), "signature": [], "nonce": nonce,
        "resource_bounds": {
            "l1_gas": {"max_amount": "0x0", "max_price_per_unit": "0x0"},
            "l2_gas": {"max_amount": "0x3b9aca00", "max_price_per_unit": "0x0"},
            "l1_data_gas": {"max_amount": "0x0", "max_price_per_unit": "0x0"},
        },
        "tip": "0x0", "paymaster_data": [], "account_deployment_data": [],
        "nonce_data_availability_mode": "L1", "fee_data_availability_mode": "L1",
    });
    std::fs::write(dir.join("os-job.json"), serde_json::to_vec_pretty(&json!({
        "rpc_url": cfg.network.rpc_url, "chain_id": cfg.network.chain_id, "block_number": base, "transaction": tx,
    }))?)?;
    stage("os");
    let limits = Limits { memory: cfg.sandbox.job_memory.clone(), cpus: cfg.prover.threads, seconds: cfg.sandbox.os_seconds, network: true };
    let os = sandbox::run(&cfg.sandbox, &format!("os-{id}"), &cfg.binaries.os_runner, &["run".into(), dir.display().to_string()],
                          &[("RAYON_NUM_THREADS", cfg.prover.threads.to_string()), ("TOKIO_WORKER_THREADS", cfg.prover.threads.to_string())],
                          limits).await?;
    std::fs::write(dir.join("os.log"), [os.stdout.as_slice(), os.stderr.as_slice()].concat())?;
    if !os.success {
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
        bail!("os: expected one message from the statement account");
    }
    let payload: Vec<Felt> = messages[0]["payload"].as_array().context("payload")?.iter().map(num).collect::<Result<_>>()?;
    let expected = vec![felt(&rel.statement_class)?, short_string(&rel.account_tag)?, sub.chain, sub.pool, bridge.binding];
    if payload != expected {
        bail!("os: the statement account's message differs from the expected one");
    }
    let os_steps = result["resources"]["n_steps"].as_u64();
    stage("prove");
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
    stage("facts");
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
    let value = json!({
        "relation": sub.relation.name(),
        "proof": base64::engine::general_purpose::STANDARD.encode(&proof),
        "proof_facts": facts.iter().map(hex).collect::<Vec<_>>(),
        "base_block": base, "submit_after": base + 11, "valid_until": base + cfg.network.max_proof_age,
        "binding": hex(&bridge.binding), "message_hash": hex(&message_hash),
        "asset": if sub.relation == Relation::R4 { Some(hex(&bridge.token)) } else { None },
        "timings": {"check_seconds": bridge.seconds, "os_seconds": os.seconds, "prove_seconds": pr.seconds,
                    "os_steps": os_steps, "prove_peak_memory_bytes": pr.peak_memory_bytes},
        "proof_bytes": proof.len(),
    });
    Ok(JobResult { value })
}
