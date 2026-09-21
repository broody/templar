//! Synthetic RPC fixture glue. All hashes, compilation, addressing and tree nodes
//! use the pinned sequencer libraries; no prover or verifier is modified.
use std::{fs, path::Path};
use serde_json::{json, Value};
use blockifier_reexecution::compile::sierra_to_versioned_contract_class_v1;
use starknet_api::{
    block::{BlockHash, BlockNumber, BlockTimestamp, GasPrice, GasPricePerToken, StarknetVersion},
    block_hash::block_hash_calculator::{calculate_block_commitments, calculate_block_hash, PartialBlockHashComponents},
    contract_class::{ContractClass, compiled_class_hash::{HashableCompiledClass, HashVersion}},
    core::{calculate_contract_address, ChainId, ContractAddress, Nonce, OsChainInfo, SequencerContractAddress},
    data_availability::L1DataAvailabilityMode,
    hash::{HashOutput, StateRoots},
    state::{SierraContractClass, ThinStateDiff},
    transaction::fields::{Calldata, ContractAddressSalt},
};
use starknet_committer::{
    hash_function::hash::TreeHashFunctionImpl,
    patricia_merkle_tree::{leaf::leaf_impl::ContractState, types::CompiledClassHash},
};
use starknet_patricia::patricia_merkle_tree::{
    node_data::{inner_node::{EdgeData, EdgePathLength, NodeData, PathToBottom}, leaf::Leaf},
    updated_skeleton_tree::hash_function::TreeHashFunction,
};
use starknet_types_core::felt::Felt;

fn hex(x: Felt) -> String { format!("{x:#x}") }
fn edge<L: Leaf>(key: Felt, leaf: L) -> (HashOutput, Value)
where TreeHashFunctionImpl: TreeHashFunction<L> {
    let child = TreeHashFunctionImpl::compute_leaf_hash(&leaf);
    let node = NodeData::<L, HashOutput>::Edge(EdgeData {
        bottom_data: child,
        path_to_bottom: PathToBottom::new(key.into(), EdgePathLength::MAX).unwrap(),
    });
    let root = TreeHashFunctionImpl::compute_node_hash(&node);
    (root, json!({"node_hash": hex(root.0), "node": {
        "child": hex(child.0), "path": hex(key), "length": 251
    }}))
}

async fn construct(rpc_class: Value) -> Value {
    let sierra: SierraContractClass = serde_json::from_value(rpc_class.clone()).unwrap();
    let class_hash = sierra.calculate_class_hash();
    let (compiled, _) = sierra_to_versioned_contract_class_v1(sierra).unwrap();
    let ContractClass::V1((casm, _)) = compiled else { panic!("Cairo1 class required") };
    let compiled_hash = casm.hash(&HashVersion::V2);
    let salt = ContractAddressSalt(Felt::from_bytes_be_slice(b"M31_APPEND_FIXTURE_V1"));
    let address = calculate_contract_address(salt, class_hash, &Calldata::default(), ContractAddress::default()).unwrap();
    let address_felt = *address.0.key();
    assert_ne!(address_felt, Felt::ZERO);
    let (contracts, contract_edge) = edge(address_felt, ContractState {
        class_hash, nonce: Nonce(Felt::ZERO), storage_root_hash: HashOutput(Felt::ZERO),
    });
    let (classes, class_edge) = edge(class_hash.0, CompiledClassHash(compiled_hash.0));
    let root = StateRoots { contracts_trie_root_hash: contracts, classes_trie_root_hash: classes }.global_root();
    let version = StarknetVersion::V0_14_3;
    let (commitments, measurements) = calculate_block_commitments(&[], ThinStateDiff::default(), L1DataAvailabilityMode::Calldata, &version).await;
    assert_eq!((measurements.n_txs, measurements.n_events, measurements.state_diff_length), (0, 0, 0));
    let gas = GasPricePerToken { price_in_fri: GasPrice(1), price_in_wei: GasPrice(1) };
    let partial = PartialBlockHashComponents {
        header_commitments: commitments.clone(), block_number: BlockNumber(100),
        l1_gas_price: gas, l1_data_gas_price: gas, l2_gas_price: gas,
        sequencer: SequencerContractAddress(ContractAddress::from(0x321_u128)),
        timestamp: BlockTimestamp(1_789_977_600), starknet_version: version,
    };
    let parent = BlockHash(Felt::from_bytes_be_slice(b"SYNTHETIC_PARENT"));
    let block_hash = calculate_block_hash(&partial, root, parent).unwrap();
    let chain = Felt::from_bytes_be_slice(b"SN_SEPOLIA");
    let chain_info = blockifier_reexecution::utils::get_chain_info(&ChainId::Sepolia, None);
    let os_config = OsChainInfo { chain_id: ChainId::Sepolia,
        strk_fee_token_address: chain_info.fee_token_addresses.strk_fee_token_address
    }.compute_virtual_os_config_hash(StarknetVersion::LATEST).unwrap();
    json!({
        "scope": "synthetic local trust anchor; no network state or finality claim",
        "chain_id": hex(chain),
        "authority": {"statement": hex(address_felt), "statement_class": hex(class_hash.0),
            "compiled_class_v2": hex(compiled_hash.0), "salt": hex(salt.0),
            "deployer": "0x0", "constructor_calldata": [], "pool": "0x456",
            "os_config_hash": hex(os_config)},
        "block": {
            "status": "ACCEPTED_ON_L2", "block_hash": hex(block_hash.0), "parent_hash": hex(parent.0),
            "block_number": 100, "sequencer_address": "0x321", "new_root": hex(root.0),
            "timestamp": 1_789_977_600, "starknet_version": "0.14.3", "l1_da_mode": "CALLDATA",
            "l1_gas_price": {"price_in_fri":"0x1", "price_in_wei":"0x1"},
            "l2_gas_price": {"price_in_fri":"0x1", "price_in_wei":"0x1"},
            "l1_data_gas_price": {"price_in_fri":"0x1", "price_in_wei":"0x1"},
            "state_diff_commitment": hex(commitments.state_diff_commitment.0.0),
            "transaction_commitment": hex(commitments.transaction_commitment.0),
            "event_commitment": hex(commitments.event_commitment.0),
            "receipt_commitment": hex(commitments.receipt_commitment.0),
            "transaction_count": 0, "event_count": 0, "state_diff_length": 0, "transactions": []
        },
        "classes": {(hex(class_hash.0)): {"rpc_class": rpc_class, "casm": casm}},
        "contracts": {(hex(address_felt)): {
            "leaf": {"class_hash": hex(class_hash.0), "nonce":"0x0", "storage_root":"0x0"},
            "storage": {}, "storage_proof": []
        }},
        "storage_proof": {
            "classes_proof": [class_edge], "contracts_proof": {"nodes": [contract_edge]},
            "global_roots": {"block_hash": hex(block_hash.0),
                "contracts_tree_root": hex(contracts.0), "classes_tree_root": hex(classes.0)}
        }
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4, "state-fixture make SIERRA OUT | check FIXTURE REPORT");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    assert!(!Path::new(&args[3]).exists(), "fresh output required");
    if args[1] == "make" {
        let class: starknet_core::types::contract::SierraClass = serde_json::from_slice(&fs::read(&args[2]).unwrap()).unwrap();
        let rpc_class = serde_json::to_value(class.flatten().unwrap()).unwrap();
        let fixture = runtime.block_on(construct(rpc_class));
        fs::write(&args[3], serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    } else {
        assert_eq!(args[1], "check");
        let fixture: Value = serde_json::from_slice(&fs::read(&args[2]).unwrap()).unwrap();
        let classes = fixture["classes"].as_object().unwrap();
        assert_eq!(classes.len(), 1);
        // A fresh compilation and reconstruction from only the public Sierra input:
        // all externally serialized roots, metadata, authority and CASM must match.
        let expected = runtime.block_on(construct(classes.values().next().unwrap()["rpc_class"].clone()));
        assert!(fixture == expected, "fixture differs from canonical reconstruction");
        // Exercise the same parsers used by the pinned RPC reader/proof provider.
        let _: blockifier_reexecution::state_reader::rpc_objects::BlockHeader = serde_json::from_value(fixture["block"].clone()).unwrap();
        let mut proof = fixture["storage_proof"].clone();
        proof["contracts_proof"]["contract_leaves_data"] = json!([fixture["contracts"].as_object().unwrap().values().next().unwrap()["leaf"]]);
        proof["contracts_storage_proofs"] = json!([[]]);
        let _: starknet_rust_core::types::StorageProof = serde_json::from_value(proof).unwrap();
        fs::write(&args[3], serde_json::to_vec_pretty(&json!({
            "canonical_reconstruction": true, "pinned_rpc_parsers": true,
            "scope": "separate reconstruction using the same pinned libraries; original OS verification still required",
            "authority": fixture["authority"], "base_block_hash": fixture["block"]["block_hash"],
            "base_root": fixture["block"]["new_root"]
        })).unwrap()).unwrap();
    }
}
