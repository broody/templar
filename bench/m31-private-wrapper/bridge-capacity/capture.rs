//! Execute the pinned virtual OS and save its public PIE without starting proof generation.
//! The runner modules are compiled verbatim from the pinned source; no execution bypass.
mod running {
    #[path = "/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af/crates/starknet_transaction_prover/src/running/classes_provider.rs"] pub mod classes_provider;
    #[path = "/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af/crates/starknet_transaction_prover/src/running/committer_utils.rs"] pub mod committer_utils;
    #[path = "/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af/crates/starknet_transaction_prover/src/running/runner.rs"] pub mod runner;
    #[path = "/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af/crates/starknet_transaction_prover/src/running/storage_proofs.rs"] pub mod storage_proofs;
    #[path = "/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af/crates/starknet_transaction_prover/src/running/virtual_block_executor.rs"] pub mod virtual_block_executor;
}
#[path = "/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af/crates/starknet_transaction_prover/src/errors.rs"]
mod errors;
use std::{fs, path::Path};
use running::runner::{RpcRunnerFactory, VirtualSnosRunner, RunnerConfig};
use blockifier::state::contract_class_manager::ContractClassManager;
use blockifier_reexecution::{utils::get_chain_info,state_reader::rpc_objects::BlockId};
use starknet_api::{core::ChainId, rpc_transaction::{RpcTransaction,RpcInvokeTransaction},transaction::InvokeTransaction};
use serde_json::json;
#[tokio::main]
async fn main() {
    let a:Vec<_>=std::env::args().collect();
    assert_eq!(a.len(),4,"capture LOOPBACK_RPC REQUEST_JSON OUT_DIR");
    let url:url::Url=a[1].parse().unwrap();
    assert_eq!(url.host_str(),Some("127.0.0.1"));
    let data:serde_json::Value=serde_json::from_slice(&fs::read(&a[2]).unwrap()).unwrap();
    let block:BlockId=serde_json::from_value(data["block_id"].clone()).unwrap();
    let RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx))=serde_json::from_value(data["transaction"].clone()).unwrap() else {panic!("INVOKE_V3 only")};
    let config:RunnerConfig=serde_json::from_value(json!({"virtual_block_executor_config":{"prefetch_state":false}})).unwrap();
    let factory=RpcRunnerFactory::new(url,get_chain_info(&ChainId::Sepolia,None),ContractClassManager::start(Default::default()),config);
    let start=std::time::Instant::now();
    let result=factory.run_virtual_os(block,vec![InvokeTransaction::V3(tx.into())]).await.unwrap();
    let out=Path::new(&a[3]);fs::create_dir_all(out).unwrap();
    result.cairo_pie.write_zip_file(&out.join("os.pie.zip"),true).unwrap();
    fs::write(out.join("capture.json"),serde_json::to_vec_pretty(&json!({"scope":"public execution capture only; no proof","os_seconds":start.elapsed().as_secs_f64(),"resources":result.cairo_pie.execution_resources,"l2_to_l1_messages":result.l2_to_l1_messages})).unwrap()).unwrap();
}
