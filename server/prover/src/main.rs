//! `templar-prover`: the Templar prover server (`docs/prover-server-spec.md`).
//!
//! - `templar-prover serve CONFIG`: startup checks against the chain, the sandbox self-test, then
//!   the HTTP API.
//! - `templar-prover check CONFIG SUBMISSION_JSON [--skip-chain-state]`: the pre-checks on one
//!   submission, outside the queue (reads chain state unless skipped, and runs the bridge).
//! - `templar-prover info CONFIG`: the startup checks and the published configuration.
mod api;
mod config;
mod ohttp;
mod pipeline;
mod rpc;
mod sandbox;
mod statement;

use std::net::SocketAddr;
use std::sync::Arc;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::rpc::{felt, hex, short_string, sn_keccak, Rpc};

/// Copies each relation's bridge build into `into/<relation>` and points the configuration at the
/// copy: `scarb execute` takes a lock file in the build directory, so it needs a writable copy the
/// server owns, and the startup checks then hash exactly what the pre-check will execute. Only the
/// workspace manifests, lock file, sources, build record and compiled executable are copied.
fn stage_bridges(cfg: &mut Config, into: &Path) -> Result<()> {
    fn copy(from: &Path, to: &Path) -> Result<()> {
        if from.is_dir() {
            std::fs::create_dir_all(to)?;
            for e in std::fs::read_dir(from)? {
                let e = e?;
                if e.file_name() == "target" {
                    continue;
                }
                copy(&e.path(), &to.join(e.file_name()))?;
            }
        } else {
            std::fs::copy(from, to).with_context(|| format!("copying {}", from.display()))?;
        }
        Ok(())
    }
    for rel in &mut cfg.relations {
        let dst = into.join(&rel.name);
        let _ = std::fs::remove_dir_all(&dst);
        std::fs::create_dir_all(&dst)?;
        for part in ["Scarb.toml", "Scarb.lock", "build-record.json", "bridge", "account", "vendor"] {
            if rel.bridge_dir.join(part).exists() {
                copy(&rel.bridge_dir.join(part), &dst.join(part))?;
            }
        }
        let exe = "target/dev/templar_membership_bridge.executable.json";
        std::fs::create_dir_all(dst.join("target/dev"))?;
        std::fs::copy(rel.bridge_dir.join(exe), dst.join(exe)).context("copying the compiled bridge")?;
        rel.bridge_dir = dst;
    }
    Ok(())
}

/// Checks the configuration against the chain and the local artifacts (spec §8, PS-5, PS-12) and
/// returns the published information.
async fn startup(cfg: &Config, rpc: &Rpc) -> Result<Value> {
    let chain = rpc.chain_id().await?;
    if chain != short_string(&cfg.network.chain_id)? {
        bail!("the RPC node is on another chain ({})", hex(&chain));
    }
    let mut relations = vec![];
    for rel in &cfg.relations {
        let class = rpc.class_hash_at(&rel.statement_account).await?;
        if class != felt(&rel.statement_class)? {
            bail!("{}: the statement account's class is {} not the configured one", rel.name, hex(&class));
        }
        // The adapter's configuration, read from its storage.
        let expect = [
            ("pool", felt(&cfg.network.pool)?),
            ("statement", felt(&rel.statement_account)?),
            ("statement_class", felt(&rel.statement_class)?),
            ("os_program", felt(&cfg.network.os_program)?),
            ("max_proof_age", cfg.network.max_proof_age.into()),
            ("account_tag", short_string(&rel.account_tag)?),
        ];
        for (name, want) in expect {
            let got = rpc.storage_at(&rel.adapter, &sn_keccak(name)).await?;
            if got != want {
                bail!("{}: the adapter's {name} is {} not {}", rel.name, hex(&got), hex(&want));
            }
        }
        pipeline::verifier_unchanged(rpc, cfg, rel).await?;
        let record = std::fs::read(rel.bridge_dir.join("build-record.json")).context("the bridge build record")?;
        let sha = format!("{:x}", Sha256::digest(&record));
        if sha != rel.bridge_record_sha256 {
            bail!("{}: the bridge build record's sha256 is {sha}", rel.name);
        }
        // The compiled bridge the pre-check executes (PI-6).
        let exe = std::fs::read(rel.bridge_dir.join("target/dev/templar_membership_bridge.executable.json"))
            .context("the compiled bridge")?;
        let exe_sha = format!("{:x}", Sha256::digest(&exe));
        if exe_sha != rel.bridge_executable_sha256 {
            bail!("{}: the compiled bridge's sha256 is {exe_sha}", rel.name);
        }
        let record: Value = serde_json::from_slice(&record)?;
        if record["message_tag"].as_str() != Some(rel.account_tag.as_str()) {
            bail!("{}: the bridge build is for another account tag", rel.name);
        }
        relations.push(json!({
            "name": rel.name, "statement_account": rel.statement_account, "statement_class": rel.statement_class,
            "account_tag": rel.account_tag, "adapter": rel.adapter, "circuit_hash_u32_le": record["circuit_hash_u32_le"],
            "bridge_record_sha256": rel.bridge_record_sha256, "bridge_executable_sha256": rel.bridge_executable_sha256,
        }));
    }
    let version = |bin: &Path| -> Result<Value> {
        let out = std::process::Command::new(bin).arg("version").output().with_context(|| format!("running {}", bin.display()))?;
        serde_json::from_slice(&out.stdout).with_context(|| format!("{} version", bin.display()))
    };
    let os_runner = version(&cfg.binaries.os_runner)?;
    if os_runner["virtual_os_program"].as_str().map(felt).transpose()? != Some(felt(&cfg.network.os_program)?) {
        bail!("templar-os-runner embeds another virtual OS program than the adapters pin");
    }
    Ok(json!({
        "server": {"binary": "templar-prover", "version": env!("CARGO_PKG_VERSION")},
        "network": {"name": cfg.network.name, "chain_id": cfg.network.chain_id, "pool": cfg.network.pool,
                    "os_program": cfg.network.os_program, "max_proof_age": cfg.network.max_proof_age},
        "relations": relations,
        "dependencies": {"os_runner": os_runner, "prove": version(&cfg.binaries.prove)?},
        "limits": {"max_body_bytes": cfg.server.max_body_bytes, "max_proof_felts": cfg.server.max_proof_felts,
                   "submissions_per_hour": cfg.limits.submissions_per_hour, "queued_per_address": cfg.limits.queued_per_address,
                   "max_concurrent_jobs": cfg.server.max_concurrent_jobs, "retention_secs": cfg.server.retention_secs},
        "submission_window": {"submit_after": "base_block + 11", "valid_until": "base_block + max_proof_age"},
    }))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().collect();
    let cfg_path = args.get(2).context("usage: templar-prover serve|check|info CONFIG ...")?;
    let mut cfg = Config::load(Path::new(cfg_path))?;
    let staging = cfg.server.data_dir.parent().map(Path::to_path_buf).unwrap_or_else(|| cfg.server.data_dir.clone())
        .join(if args[1] == "serve" { "bridges".to_string() } else { format!("bridges-{}", std::process::id()) });
    stage_bridges(&mut cfg, &staging).context("staging the bridge builds")?;
    let rpc = Rpc::new(&cfg.network.rpc_url);
    match args[1].as_str() {
        "info" => {
            let out = startup(&cfg, &rpc).await;
            let _ = std::fs::remove_dir_all(&staging);
            println!("{}", serde_json::to_string_pretty(&out?)?);
        }
        "check" => {
            let body: statement::SubmissionJson = serde_json::from_slice(&std::fs::read(args.get(3).context("SUBMISSION_JSON")?)?)?;
            let sub = statement::Submission::parse(body, cfg.server.max_proof_felts)?;
            let rel = cfg.relation(sub.relation.name()).context("relation not served")?;
            // Tests on proofs for other pools skip the chain-state check; the bridge still runs.
            if !args.iter().any(|a| a == "--skip-chain-state") {
                pipeline::chain_state(&rpc, &cfg, &sub).await?;
            }
            let tag = format!("cli-{:016x}", rand::random::<u64>());
            let dir = cfg.server.data_dir.join(&tag);
            std::fs::create_dir_all(&dir)?;
            let out = pipeline::check(&cfg, rel, &sub, &dir, &tag).await;
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::remove_dir_all(&staging);
            let out = out?;
            println!("{}", json!({"accepted": true, "binding": hex(&out.binding), "asset": hex(&out.token), "steps": out.steps, "seconds": out.seconds}));
        }
        "serve" => {
            sandbox::prepare_root(&mut cfg.sandbox).context("preparing the cgroup subtree")?;
            let purged = sandbox::purge(&cfg.sandbox)?;
            // Job directories from a previous run hold statements and cannot be resumed (PI-8).
            if cfg.server.data_dir.exists() {
                for e in std::fs::read_dir(&cfg.server.data_dir)? {
                    let _ = std::fs::remove_dir_all(e?.path());
                }
            }
            tracing::info!(purged, "cleared state from a previous run");
            sandbox::self_test(&cfg.sandbox).await.context("the sandbox self-test (spec §9): a delegated cgroup v2 subtree is required")?;
            let info = startup(&cfg, &rpc).await?;
            std::fs::create_dir_all(&cfg.server.data_dir)?;
            let listen: SocketAddr = cfg.server.listen.parse().context("listen")?;
            let ohttp = match &cfg.ohttp {
                Some(o) => {
                    let key = std::fs::read_to_string(&o.key_file).context("reading the OHTTP key file")?;
                    Some(Arc::new(ohttp::OhttpState { gateway: ohttp::gateway(&key)?, body_limit: cfg.server.max_body_bytes + 4096 }))
                }
                None => None,
            };
            let mut info = info;
            info["ohttp"] = match &ohttp {
                Some(o) => json!({"enabled": true, "keys_path": "/ohttp-keys", "key_config_hex": hex::encode(o.gateway.encoded_config())}),
                None => json!({"enabled": false}),
            };
            let cfg_root = cfg.sandbox.clone();
            let state = api::start(cfg, rpc, info);
            let app = api::router(state, ohttp).into_make_service_with_connect_info::<SocketAddr>();
            let listener = tokio::net::TcpListener::bind(listen).await?;
            tracing::info!(%listen, "serving");
            let root = cfg_root;
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
                    tokio::select! {
                        _ = term.recv() => {}
                        _ = tokio::signal::ctrl_c() => {}
                    }
                    tracing::info!("shutting down: killing running steps");
                    let _ = sandbox::purge(&root);
                })
                .await?;
        }
        other => bail!("unknown mode {other}"),
    }
    Ok(())
}
