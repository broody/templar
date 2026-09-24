//! `templar-os-runner run JOB_DIR`: execute one transaction in the pinned virtual Starknet OS
//! against a Starknet RPC node and write the Cairo PIE for the prover (prover-server spec §5.4).
//!
//! `JOB_DIR/os-job.json`: `{rpc_url, chain_id, block_number, transaction}`, where `transaction`
//! is an RPC `INVOKE_V3` (the statement account's call carrying the client proof). Writes
//! `JOB_DIR/os.pie.zip` and `JOB_DIR/os-result.json` (`{os_seconds, resources,
//! l2_to_l1_messages}`). The runner and its OS program are upstream's at the pinned revision; this
//! binary only builds the request and records the output. It never proves.
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use blockifier::state::contract_class_manager::ContractClassManager;
use blockifier_reexecution::state_reader::rpc_objects::BlockId;
use blockifier_reexecution::utils::get_chain_info;
use serde_json::{json, Value};
use starknet_api::core::ChainId;
use starknet_api::rpc_transaction::{RpcInvokeTransaction, RpcTransaction};
use starknet_api::transaction::InvokeTransaction;
use starknet_transaction_prover::running::runner::{RpcRunnerFactory, RunnerConfig, VirtualSnosRunner};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") if args.len() == 3 => run(Path::new(&args[2])).await,
        Some("version") => {
            // The hash of the virtual OS program this binary embeds, computed from the program
            // itself (not the recorded constant), so the server's startup check covers the build.
            let virtual_os = apollo_starknet_os_program::program_hash::compute_virtual_os_program_hash()
                .map_err(|e| anyhow::anyhow!("hashing the embedded virtual OS: {e:?}"))?;
            println!("{}", json!({"binary": "templar-os-runner", "version": env!("CARGO_PKG_VERSION"),
                                 "sequencer": "broody/sequencer@625929ac645c399f2481fb2b65ffdd14702aa525",
                                 "virtual_os_program": format!("{:#x}", virtual_os)}));
            Ok(())
        }
        _ => bail!("usage: templar-os-runner run JOB_DIR | version"),
    }
}

async fn run(dir: &Path) -> Result<()> {
    let job: Value = serde_json::from_slice(&std::fs::read(dir.join("os-job.json")).context("reading os-job.json")?)
        .context("parsing os-job.json")?;
    let url: url::Url = job["rpc_url"].as_str().context("rpc_url")?.parse().context("rpc_url")?;
    let chain_id = ChainId::from(job["chain_id"].as_str().context("chain_id")?.to_string());
    let block = BlockId::Number(starknet_api::block::BlockNumber(job["block_number"].as_u64().context("block_number")?));
    let RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) =
        serde_json::from_value(job["transaction"].clone()).context("transaction")?
    else {
        bail!("only INVOKE_V3 transactions");
    };
    let config: RunnerConfig = serde_json::from_value(json!({"virtual_block_executor_config": {"prefetch_state": false}}))?;
    let factory = RpcRunnerFactory::new(url, get_chain_info(&chain_id, None), ContractClassManager::start(Default::default()), config);
    let start = Instant::now();
    let output = factory
        .run_virtual_os(block, vec![InvokeTransaction::V3(tx.into())])
        .await
        .map_err(|e| anyhow::anyhow!("virtual OS: {e}"))?;
    output.cairo_pie.write_zip_file(&dir.join("os.pie.zip"), true).context("writing the PIE")?;
    let result = json!({
        "os_seconds": start.elapsed().as_secs_f64(),
        "resources": output.cairo_pie.execution_resources,
        "l2_to_l1_messages": output.l2_to_l1_messages,
    });
    std::fs::write(dir.join("os-result.json"), serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}
