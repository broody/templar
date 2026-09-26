//! `templar-prover`: the Templar prover server (`docs/prover-server-spec.md`).
//!
//! - `templar-prover serve CONFIG`: startup checks against the chain, the sandbox self-test, then
//!   the HTTP API.
//! - `templar-prover check CONFIG SUBMISSION_JSON [--skip-chain-state]`: the pre-checks on one
//!   submission, outside the queue (reads chain state unless skipped, and runs the bridge).
//! - `templar-prover info CONFIG`: the startup checks and the published configuration.
//! - `templar-prover issuer keygen DIR KEY_ID | issuer mint SECRET_KEY_PEM KEY_ID N`: the test
//!   issuer (P4): an RSA key pair, and tickets minted by blinding, signing and finalizing locally.
mod api;
mod config;
mod ohttp;
mod pipeline;
mod rpc;
mod sandbox;
mod statement;
mod v5;
mod m31;
mod tickets;

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

/// Pool V3's constants (`get_parameters`: E, Q, W, T), which the R0 V5 checks use.
async fn load_parameters(cfg: &mut Config, rpc: &Rpc) -> Result<()> {
    if cfg.network.pool_version == 3 {
        let p = rpc.call(&cfg.network.pool, "get_parameters", &[]).await.context("pool V3 get_parameters")?;
        let v = |i: usize| p.get(i).and_then(crate::v5::to_u64).context("get_parameters: four u64s");
        cfg.network.parameters = Some(config::PoolParameters { expiry_window: v(0)?, quantum: v(1)?, root_window: v(2)?, timelock: v(3)? });
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
        // A pending change is logged, not fatal: jobs are refused only while it is due (AB-SP1).
        pipeline::verifier_current(rpc, cfg, rel).await?;
        pipeline::warn_pending(rpc, cfg, rel).await;
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
    // R0 V5 (spec §9, Info): the spend message's hashes, the relation and the pool's expiry rules.
    let v5 = cfg.relation("r5").map(|_| json!({
        "relation": "R0 V5", "binding": "TMR0_BIND_V5", "account_tag": "TMPZR0_PAYMENT_V5",
        "spend_message": {"domain": {"name": "Templar", "version": "V5", "revision": "1"},
                          "domain_type_hash": crate::v5::DOMAIN_TYPE_HASH, "spend_type_hash": crate::v5::SPEND_TYPE_HASH},
        "pool_parameters": cfg.network.parameters,
        "bound_mode": cfg.network.operator_node,
        "bound_account_classes": cfg.network.bound_account_classes,
        "caps": {"os_steps": cfg.caps.os_steps, "builtins": cfg.caps.builtins},
        "admission": {"blocks_per_job": cfg.server.blocks_per_job, "relay_margin_blocks": cfg.server.relay_margin_blocks},
        "result": {"send_deadline": "min(statement.valid_until, base_block + max_proof_age)"},
    }));
    Ok(json!({
        "server": {"binary": "templar-prover", "version": env!("CARGO_PKG_VERSION")},
        "network": {"name": cfg.network.name, "chain_id": cfg.network.chain_id, "pool": cfg.network.pool,
                    "pool_version": cfg.network.pool_version,
                    "os_program": cfg.network.os_program, "max_proof_age": cfg.network.max_proof_age},
        "r5": v5,
        "relations": relations,
        "dependencies": {"os_runner": os_runner, "prove": version(&cfg.binaries.prove)?},
        "limits": {"max_body_bytes": cfg.server.max_body_bytes, "max_proof_felts": cfg.server.max_proof_felts,
                   "submissions_per_hour": cfg.limits.submissions_per_hour, "queued_per_address": cfg.limits.queued_per_address,
                   "max_concurrent_jobs": cfg.server.max_concurrent_jobs, "retention_secs": cfg.server.retention_secs},
        "submission_window": {"submit_after": "base_block + 11", "valid_until": "base_block + max_proof_age"},
    }))
}

/// Whether `path` lies on a tmpfs (or ramfs), from the longest mount point containing it.
fn on_tmpfs(path: &Path) -> Result<bool> {
    let path = std::fs::canonicalize(path)?;
    let mounts = std::fs::read_to_string("/proc/self/mounts").context("reading /proc/self/mounts")?;
    let fs = mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_, point, fstype) = (f.next()?, f.next()?, f.next()?);
            // Mount points escape spaces as \040.
            Some((std::path::PathBuf::from(point.replace("\\040", " ")), fstype.to_string()))
        })
        .filter(|(point, _)| path.starts_with(point))
        .max_by_key(|(point, _)| point.as_os_str().len())
        .map(|(_, fstype)| fstype);
    Ok(matches!(fs.as_deref(), Some("tmpfs") | Some("ramfs")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn tmpfs_detection() {
        // /dev/shm is a tmpfs on Linux; the crate directory is not.
        if std::path::Path::new("/dev/shm").exists() {
            assert!(super::on_tmpfs(std::path::Path::new("/dev/shm")).unwrap());
        }
        assert!(!super::on_tmpfs(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().collect();
    // The test issuer (P4; docs/account-bound-note-spec.md §7.2): no configuration, no chain.
    if args.get(1).map(String::as_str) == Some("issuer") {
        return match (args.get(2).map(String::as_str), &args[3..]) {
            (Some("keygen"), [dir, id]) => tickets::issuer::keygen(Path::new(dir), id),
            (Some("mint"), [secret_key, id, n]) => {
                let sk = tickets::issuer::load_secret(Path::new(secret_key))?;
                println!("{}", serde_json::to_string(&tickets::issuer::mint(id, &sk, n.parse()?)?)?);
                Ok(())
            }
            _ => bail!("usage: templar-prover issuer keygen DIR KEY_ID | issuer mint SECRET_KEY_PEM KEY_ID N"),
        };
    }
    let cfg_path = args.get(2).context("usage: templar-prover serve|check|info CONFIG ... | issuer ...")?;
    let mut cfg = Config::load(Path::new(cfg_path))?;
    // Staged inside data_dir, which only the server writes (PI-14).
    let staging = cfg.server.data_dir.join(if args[1] == "serve" { "bridges".to_string() } else { format!("bridges-cli-{:016x}", rand::random::<u64>()) });
    stage_bridges(&mut cfg, &staging).context("staging the bridge builds")?;
    let rpc = Rpc::new(&cfg.network.rpc_url);
    // Pool V3's constants, unless a check runs without the chain.
    if !(args[1] == "check" && args.iter().any(|a| a == "--skip-chain-state")) {
        load_parameters(&mut cfg, &rpc).await?;
    }
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
            // Job directories from a previous run hold statements and cannot be resumed (PI-8). Only
            // entries the server creates are removed: job ids (32 hex) and CLI scratch (PI-14).
            for root in std::iter::once(&cfg.server.data_dir).chain(cfg.server.bound_data_dir.as_ref()) {
                if !root.exists() {
                    continue;
                }
                for e in std::fs::read_dir(root)? {
                    let e = e?;
                    let name = e.file_name().to_string_lossy().to_string();
                    let job = name.len() == 32 && name.chars().all(|c| c.is_ascii_hexdigit());
                    if e.path().is_dir() && (job || name.starts_with("cli-") || name.starts_with("bridges-cli-")) {
                        let _ = std::fs::remove_dir_all(e.path());
                    }
                }
            }
            if let Some(b) = &cfg.server.bound_data_dir {
                std::fs::create_dir_all(b)?;
                // Bound inputs hold the account, salt and signature: memory only (spec §9, AB-SP10).
                if !on_tmpfs(b)? {
                    bail!("server.bound_data_dir {} is not on a tmpfs", b.display());
                }
            }
            // A result lives up to max_proof_age blocks (about 6 s each at most); a verifier change
            // that can apply sooner than that after a job starts could strand it (recheck N7).
            if cfg.network.pool_version == 3 && cfg.network.pending_margin() < cfg.network.max_proof_age * 6 {
                tracing::warn!(margin = cfg.network.pending_margin(), "pending_margin_secs is below max_proof_age × 6 s: a verifier change could apply before a result lands");
            }
            tracing::info!(purged, "cleared state from a previous run");
            sandbox::self_test(&cfg.sandbox).await.context("the sandbox self-test (spec §9): a delegated cgroup v2 subtree is required")?;
            let mut info = startup(&cfg, &rpc).await?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let tickets = match cfg.payment.clone() {
                Some(p) => Some(Arc::new(tickets::Tickets::load(p, &cfg.server.data_dir, now).context("the payment configuration")?)),
                None => None,
            };
            info["payment"] = tickets.as_ref().map_or(json!({"required": false}), |t| t.info());
            std::fs::create_dir_all(&cfg.server.data_dir)?;
            let listen: SocketAddr = cfg.server.listen.parse().context("listen")?;
            let ohttp = match &cfg.ohttp {
                Some(o) => {
                    let key = std::fs::read_to_string(&o.key_file).context("reading the OHTTP key file")?;
                    Some(Arc::new(ohttp::OhttpState { gateway: ohttp::gateway(&key)?, body_limit: cfg.server.max_body_bytes + 4096 }))
                }
                None => None,
            };
            info["ohttp"] = match &ohttp {
                Some(o) => json!({"enabled": true, "keys_path": "/ohttp-keys", "key_config_hex": hex::encode(o.gateway.encoded_config())}),
                None => json!({"enabled": false}),
            };
            let cfg_root = cfg.sandbox.clone();
            let state = api::start(cfg, rpc, info, tickets);
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
