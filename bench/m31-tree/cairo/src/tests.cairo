use m31_tree_bench::contracts::{IFeltBenchDispatcher, IFeltBenchDispatcherTrait, IM31BenchDispatcher, IM31BenchDispatcherTrait};
use m31_tree_bench::felt_tree::{ITreeDispatcher, ITreeDispatcherTrait};
use m31_tree_bench::m31_tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};
use m31_tree_bench::m31_hash::{Digest, P, pack, unpack};
use m31_tree_bench::golden::{expected_root, expected_empty_root};
use m31_tree_bench::snapshots::{felt_nodes,felt_nodes_for,felt_zeros,felt_history,felt_history_for,felt_expected,m31_nodes,m31_nodes_for,m31_zeros,m31_history,m31_history_for,m31_expected};
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait};
use starknet::ContractAddress;
fn deploy(name: ByteArray) -> ContractAddress {
    let class = declare(name).unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    address
}
fn leaves(start: u32, count: u32) -> Array<felt252> {
    let mut values = array![];
    for i in start..start+count { values.append(i.into()); };
    values
}
fn felt_case(warm: bool, n: u32) {
    let address = deploy("FeltTreeBench");
    let writer = IFeltBenchDispatcher { contract_address: address };
    let tree = ITreeDispatcher { contract_address: address };
    if warm { writer.seed_snapshot(felt_nodes().span(),felt_zeros().span(),felt_history().span()); }
    let start = if warm { 9 } else { 1 };
    let root = writer.append_batch(leaves(start, n).span());
    assert_eq!(tree.get_root(), root);
    assert_eq!(root, felt_expected(start+n-1));
    assert_eq!(tree.get_leaf_count(), (start+n-1).into());
    assert!(tree.root_is_known(root));
}
fn m31_case(warm: bool, n: u32) {
    let address = deploy("M31TreeBench");
    let writer = IM31BenchDispatcher { contract_address: address };
    let tree = IM31TreeDispatcher { contract_address: address };
    if warm { writer.seed_snapshot(m31_nodes().span(),m31_zeros().span(),m31_history().span()); }
    let start = if warm { 9 } else { 1 };
    let root = writer.append_batch(leaves(start, n).span());
    assert_eq!(root, expected_root(start+n-1));
    assert_eq!(tree.get_root(), root);
    assert_eq!(tree.get_leaf_count(), (start+n-1).into());
    assert!(tree.root_is_known(root));
    assert!(tree.root_is_known(expected_empty_root()));
}
#[test]
fn cost_felt_cold_1() { felt_case(false, 1); }
#[test]
fn cost_felt_cold_2() { felt_case(false, 2); }
#[test]
fn cost_felt_cold_4() { felt_case(false, 4); }
#[test]
fn cost_felt_cold_8() { felt_case(false, 8); }
#[test]
fn cost_felt_warm_1() { felt_case(true, 1); }
#[test]
fn cost_felt_warm_2() { felt_case(true, 2); }
#[test]
fn cost_felt_warm_4() { felt_case(true, 4); }
#[test]
fn cost_felt_warm_8() { felt_case(true, 8); }
#[test]
fn cost_m31_cold_1() { m31_case(false, 1); }
#[test]
fn cost_m31_cold_2() { m31_case(false, 2); }
#[test]
fn cost_m31_cold_4() { m31_case(false, 4); }
#[test]
fn cost_m31_cold_8() { m31_case(false, 8); }
#[test]
fn cost_m31_warm_1() { m31_case(true, 1); }
#[test]
fn cost_m31_warm_2() { m31_case(true, 2); }
#[test]
fn cost_m31_warm_4() { m31_case(true, 4); }
#[test]
fn cost_m31_warm_8() { m31_case(true, 8); }
#[test]
fn packing_max_roundtrip() {
    let words = array![P-1,P-1,P-1,P-1,P-1,P-1,P-1,P-1,P-1];
    assert_eq!(unpack(pack(words.span())), words);
}
#[test]
#[should_panic(expected: 'NONCANONICAL_M31')]
fn packing_reject_low_p() { unpack(Digest { low: P.into(), high: 0 }); }
#[test]
#[should_panic(expected: 'NONCANONICAL_M31')]
fn packing_reject_high_p() { unpack(Digest { low: 0, high: P.into() }); }
#[test]
#[should_panic(expected: 'DIGEST_TOP_BITS')]
fn packing_reject_top_bits() { unpack(Digest { low: 0x100000000000000000000000000000000000000000000000000000000000000, high: 0 }); }
#[test]
#[should_panic(expected: 'ZERO_LEAF')]
fn m31_reject_zero() {
    IM31BenchDispatcher { contract_address: deploy("M31TreeBench") }.append_batch(array![0].span());
}
#[test]
#[should_panic(expected: 'TREE_FULL')]
fn m31_reject_full() {
    let writer = IM31BenchDispatcher { contract_address: deploy("M31TreeBench") };
    writer.seed_prefix(array![1].span());
    writer.seed_counters(0x100000000, 2);
    writer.append_batch(array![2].span());
}
#[test]
fn m31_history_eviction() {
    let address = deploy("M31TreeBench");
    let writer = IM31BenchDispatcher { contract_address: address };
    let tree = IM31TreeDispatcher { contract_address: address };
    writer.seed_prefix(array![1].span());
    assert!(tree.root_is_known(expected_empty_root()));
    writer.seed_counters(1, 256);
    let root = writer.append_batch(array![2].span());
    assert_eq!(root, expected_root(2));
    assert!(!tree.root_is_known(expected_empty_root()));
    assert!(tree.root_is_known(expected_root(1)));
    assert!(tree.root_is_known(root));
}

// Check every written storage entry, every ring slot, and explicit unwritten
// probes. Compare both implementations of setup to independently generated data.
fn snapshot_felt_case(count: u32) {
    let genuine=IFeltBenchDispatcher { contract_address: deploy("FeltTreeBench") };
    let seeded=IFeltBenchDispatcher { contract_address: deploy("FeltTreeBench") };
    genuine.seed_prefix(leaves(1,count).span());
    seeded.seed_snapshot(felt_nodes_for(count).span(),felt_zeros().span(),felt_history_for(count).span());
    let mut keys=array![];
    let mut expected=array![];
    for entry in felt_nodes_for(count).span() {
        let (key,value)=*entry;
        keys.append(key);
        expected.append(value);
    };
    // Unwritten node slots: the next leaf, an out-of-tree level, and a far index.
    keys.append(m31_tree_bench::felt_tree::node_key(0,count.into()));
    keys.append(m31_tree_bench::felt_tree::node_key(33,0));
    keys.append(m31_tree_bench::felt_tree::node_key(15,0x80000000));
    for _ in 0_u32..3 { expected.append(0); };
    for value in felt_zeros().span() { expected.append(*value); };
    // zero_hashes[33] was never written.
    expected.append(0);
    expected.append(1);
    expected.append(count.into());
    expected.append(felt_expected(count));
    expected.append((count+1).into());
    let roots=felt_history_for(count);
    for slot in 0_u32..256 {
        let value=if slot<=count { *roots.at(slot) } else { 0 };
        expected.append(value);
    };
    let mut history_keys=array![];
    for root in roots.span() { history_keys.append(*root); expected.append(1); };
    // Neither an unset digest nor the next prefix's root is known yet.
    history_keys.append(0); expected.append(0);
    history_keys.append(felt_expected(count+1)); expected.append(0);
    let actual=genuine.read_raw_state(keys.span(),history_keys.span());
    let installed=seeded.read_raw_state(keys.span(),history_keys.span());
    assert_eq!(@actual,@expected);
    assert_eq!(@installed,@expected);
    assert_eq!(actual,installed);
}
#[test]
fn snapshot_felt_prefix1() { snapshot_felt_case(1); }
#[test]
fn snapshot_felt_prefix2() { snapshot_felt_case(2); }

#[test]
fn snapshot_felt_prefix8() { snapshot_felt_case(8); }

// Check every written storage entry, every ring slot, and explicit unwritten
// probes. Compare both implementations of setup to independently generated data.
fn snapshot_m31_case(count: u32) {
    let genuine=IM31BenchDispatcher { contract_address: deploy("M31TreeBench") };
    let seeded=IM31BenchDispatcher { contract_address: deploy("M31TreeBench") };
    genuine.seed_prefix(leaves(1,count).span());
    seeded.seed_snapshot(m31_nodes_for(count).span(),m31_zeros().span(),m31_history_for(count).span());
    let mut keys=array![];
    let mut expected=array![];
    for entry in m31_nodes_for(count).span() {
        let (key,value)=*entry;
        keys.append(key);
        let value=value; expected.append(value.low); expected.append(value.high);
    };
    // Unwritten node slots: the next leaf, an out-of-tree level, and a far index.
    keys.append(m31_tree_bench::felt_tree::node_key(0,count.into()));
    keys.append(m31_tree_bench::felt_tree::node_key(33,0));
    keys.append(m31_tree_bench::felt_tree::node_key(15,0x80000000));
    for _ in 0_u32..3 { let value=Digest { low: 0, high: 0 }; expected.append(value.low); expected.append(value.high); };
    for value in m31_zeros().span() { let value=*value; expected.append(value.low); expected.append(value.high); };
    // zero_hashes[33] was never written.
    let value=Digest { low: 0, high: 0 }; expected.append(value.low); expected.append(value.high);
    expected.append(1);
    expected.append(count.into());
    let value=m31_expected(count); expected.append(value.low); expected.append(value.high);
    expected.append((count+1).into());
    let roots=m31_history_for(count);
    for slot in 0_u32..256 {
        let value=if slot<=count { *roots.at(slot) } else { Digest { low: 0, high: 0 } };
        let value=value; expected.append(value.low); expected.append(value.high);
    };
    let mut history_keys=array![];
    for root in roots.span() { history_keys.append(*root); expected.append(1); };
    // Neither an unset digest nor the next prefix's root is known yet.
    history_keys.append(Digest { low: 0, high: 0 }); expected.append(0);
    history_keys.append(m31_expected(count+1)); expected.append(0);
    let actual=genuine.read_raw_state(keys.span(),history_keys.span());
    let installed=seeded.read_raw_state(keys.span(),history_keys.span());
    assert_eq!(@actual,@expected);
    assert_eq!(@installed,@expected);
    assert_eq!(actual,installed);
}
#[test]
fn snapshot_m31_prefix1() { snapshot_m31_case(1); }
#[test]
fn snapshot_m31_prefix2() { snapshot_m31_case(2); }
