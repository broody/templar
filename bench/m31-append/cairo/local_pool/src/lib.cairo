//! Public synthetic tree-maintenance fixture. Its constructor queues authorized leaves;
//! it has no deposits, private notes, payment authorization, or token accounting.
//! The runtime must verify PROOF1 before exposing proof_facts. Setting cheat facts alone
//! is NOT end-to-end proof verification. This contract never evaluates an M31 hash.
#[derive(Copy,Drop,Serde,PartialEq,Debug,starknet::Store)]
pub struct Root { pub low: felt252,pub high: felt252 }
#[derive(Copy,Drop,Serde)]
pub struct Transition {
    pub old_root: Root,
    pub old_count: u64,
    pub new_root: Root,
    pub new_count: u64,
    pub commitments: Span<felt252>,
}
#[starknet::interface]
pub trait IAppendPool<TState> {
    fn apply_append(ref self: TState,transition: Transition);
    fn state(self: @TState) -> (Root,u64);
    fn queued(self: @TState,index: u64) -> felt252;
}
pub const DOMAIN: felt252='M31_APPEND_V1';
// Pinned reviewed Plonky3 oracle depth32 empty root; establishes empty genesis.
pub const EMPTY_ROOT: Root=Root { low: 194250202315021002790422369058999935285926933295307486729424430452319255097,high: 2139620970 };
pub fn canonical_root(root: Root) {
    let mut low: u256=root.low.into();
    for _ in 0_u32..8 { assert(low%0x80000000<0x7fffffff,'NONCANONICAL_ROOT'); low/=0x80000000; };
    assert(low==0,'ROOT_TOP_BITS');
    let high: u32=root.high.try_into().expect('ROOT_HIGH');
    assert(high<0x7fffffff,'NONCANONICAL_ROOT');
}
pub fn public_values(transition: Transition,chain_id: felt252,pool: felt252) -> Span<felt252> {
    let n: felt252=transition.commitments.len().into();
    let mut words=array![DOMAIN,chain_id,pool,transition.old_root.low,transition.old_root.high,transition.old_count.into(),n];
    for commitment in transition.commitments { words.append(*commitment); };
    words.append(transition.new_root.low); words.append(transition.new_root.high); words.append(transition.new_count.into());
    array![DOMAIN,chain_id,pool,transition.old_root.low,transition.old_root.high,transition.old_count.into(),core::poseidon::poseidon_hash_span(words.span()),n].span()
}
#[starknet::contract]
pub mod PublicAppendPool {
    use super::{Root,Transition,canonical_root,public_values,EMPTY_ROOT};
    use starknet::{ContractAddress,get_contract_address,SyscallResultTrait};
    use starknet::syscalls::get_execution_info_v3_syscall;
    use starknet::storage::{Map,StorageMapReadAccess,StorageMapWriteAccess,StoragePointerReadAccess,StoragePointerWriteAccess};
    use core::poseidon::poseidon_hash_span;
    #[storage]
    struct Storage {
        root: Root,
        count: u64,
        expected_commitments: Map<u64,felt252>,
        queued_end: u64,
        statement: ContractAddress,
        statement_class: felt252,
        max_proof_age: u64,
    }
    #[constructor]
    fn constructor(ref self: ContractState,root: Root,count: u64,authorized_commitments: Span<felt252>,statement: ContractAddress,statement_class: felt252,max_proof_age: u64) {
        canonical_root(root);
        assert(count==0 && root==EMPTY_ROOT,'EMPTY_GENESIS');
        let queued_end=count+authorized_commitments.len().into();
        assert(queued_end<=0x100000000,'QUEUE_CAPACITY');
        assert(statement.into()!=0 && statement_class!=0 && max_proof_age!=0,'BAD_AUTHORITY');
        let mut index=count;
        for commitment in authorized_commitments {
            assert(*commitment!=0,'ZERO_COMMITMENT');
            self.expected_commitments.write(index,*commitment); index+=1;
        };
        self.root.write(root); self.count.write(count); self.queued_end.write(queued_end);
        self.statement.write(statement); self.statement_class.write(statement_class); self.max_proof_age.write(max_proof_age);
    }
    #[abi(embed_v0)]
    impl AppendPoolImpl of super::IAppendPool<ContractState> {
        fn state(self: @ContractState) -> (Root,u64) { (self.root.read(),self.count.read()) }
        fn queued(self: @ContractState,index: u64) -> felt252 { self.expected_commitments.read(index) }
        fn apply_append(ref self: ContractState,transition: Transition) {
            let n=transition.commitments.len();
            assert(n==1 || n==2,'BATCH_SIZE');
            canonical_root(transition.old_root); canonical_root(transition.new_root);
            assert(transition.old_root==self.root.read(),'STALE_ROOT');
            assert(transition.old_count==self.count.read(),'STALE_COUNT');
            assert(transition.new_count==transition.old_count+n.into(),'NEW_COUNT');
            assert(transition.new_count<=0x100000000,'TREE_CAPACITY');
            assert(transition.new_count<=self.queued_end.read(),'UNAUTHORIZED_RANGE');
            let mut index=transition.old_count;
            for commitment in transition.commitments {
                assert(*commitment!=0 && self.expected_commitments.read(index)==*commitment,'ORDERED_COMMITMENT');
                index+=1;
            };
            let info=get_execution_info_v3_syscall().unwrap_syscall();
            let public=public_values(transition,info.tx_info.chain_id,get_contract_address().into());
            let facts=info.tx_info.proof_facts;
            assert(facts.len()==9,'PROOF_FACTS_LENGTH');
            assert(*facts.at(0)=='PROOF1','PROOF_VERSION');
            assert(*facts.at(1)=='VIRTUAL_SNOS','PROOF_VARIANT');
            assert(*facts.at(2)==0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1,'OS_PROGRAM');
            assert(*facts.at(3)=='VIRTUAL_SNOS0','OUTPUT_VERSION');
            let base: u64=(*facts.at(4)).try_into().expect('BASE_BLOCK');
            let current=info.block_info.block_number;
            assert(base<current && current-base<=self.max_proof_age.read(),'PROOF_AGE');
            assert(*facts.at(7)==1,'MESSAGE_COUNT');
            let mut message=array![self.statement.read().into(),0,9,self.statement_class.read()];
            for value in public { message.append(*value); };
            assert(*facts.at(8)==poseidon_hash_span(message.span()),'PROOF_BINDING');
            // All authority, current-state, queue and cryptographic-fact checks precede writes.
            index=transition.old_count;
            for _ in transition.commitments { self.expected_commitments.write(index,0); index+=1; };
            self.root.write(transition.new_root); self.count.write(transition.new_count);
        }
    }
}

#[cfg(test)]
mod verified_facts_tests;
