//! Feasibility harness only: single-token ordinary notes, no fees/controllers/governance.
//! Not a production replacement for packages/pool. All mutation stays inside deposit/spend.
use starknet::ContractAddress;
#[starknet::interface]
pub trait IERC20<T> {
    fn transfer_from(ref self: T, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer(ref self: T, recipient: ContractAddress, amount: u256) -> bool;
    fn approve(ref self: T, spender: ContractAddress, amount: u256) -> bool;
    fn balance_of(self: @T, account: ContractAddress) -> u256;
}
#[starknet::interface]
pub trait IBenchPool<T> {
    fn deposit(ref self: T, amount: u128, inner: u256);
    fn spend(ref self: T, root: u256, nullifiers: Span<u256>, outputs: Span<u256>, amount: u128, recipient: ContractAddress, proof: Span<felt252>);
    fn get_root(self: @T) -> u256;
    fn get_spent(self: @T, nf: u256) -> bool;
}
#[starknet::contract]
pub mod BenchPool {
    use super::{IERC20Dispatcher,IERC20DispatcherTrait};
    use desktop::hashing::{hash,pair,FR};
    use desktop::honk_verifier::{IUltraKeccakZKHonkVerifierDispatcher,IUltraKeccakZKHonkVerifierDispatcherTrait};
    use starknet::{ContractAddress,get_caller_address,get_contract_address,get_tx_info};
    use starknet::storage::{Map,StorageMapReadAccess,StorageMapWriteAccess,StoragePointerReadAccess,StoragePointerWriteAccess};
    pub const VERSION: u256 = 0x54454d504c41525f4445534b544f5031;
    #[storage]
    struct Storage {
        token: ContractAddress, verifier: ContractAddress, locked: bool,
        count: u64, root: u256, nodes: Map<(u32,u64),u256>, zeros: Map<u32,u256>,
        roots: Map<u256,bool>, spent: Map<u256,bool>,
    }
    #[constructor]
    fn constructor(ref self: ContractState, token: ContractAddress, verifier: ContractAddress) {
        self.token.write(token);self.verifier.write(verifier);
        let mut z: u256=0;self.zeros.write(0,z);
        for level in 0_u32..32_u32 {z=pair(z,z);self.zeros.write(level+1,z);};
        self.root.write(z);self.roots.write(z,true);
    }
    #[abi(embed_v0)]
    impl API of super::IBenchPool<ContractState> {
        fn deposit(ref self: ContractState, amount: u128, inner: u256) {
            self.start();assert(amount>0 && inner>0 && inner<FR,'BAD_DEPOSIT');
            let token: felt252=self.token.read().into();
            let leaf=hash(array![0x434f4d4d49544d454e545f5441473a5633,token.into(),amount.into(),0,0,inner].span());
            assert(IERC20Dispatcher{contract_address:self.token.read()}.transfer_from(get_caller_address(),get_contract_address(),amount.into()),'TRANSFER_FAILED');
            self.insert(leaf);self.locked.write(false);
        }
        fn spend(ref self: ContractState, root: u256, nullifiers: Span<u256>, outputs: Span<u256>, amount: u128, recipient: ContractAddress, proof: Span<felt252>) {
            self.start();assert(self.roots.read(root),'UNKNOWN_ROOT');
            assert(nullifiers.len()>0 && nullifiers.len()<=2 && outputs.len()<=2,'BAD_COUNTS');
            let pool:felt252=get_contract_address().into();let chain=get_tx_info().unbox().chain_id;
            let token:felt252=self.token.read().into();let to:felt252=recipient.into();
            if amount==0 {assert(to==0,'BAD_RECIPIENT');} else {assert(to!=0,'BAD_RECIPIENT');}
            let mut data=array![0x54585f42494e445f5441473a5632,VERSION,chain.into(),pool.into(),root,nullifiers.len().into()];
            for i in 0_usize..2_usize {data.append(if i<nullifiers.len(){*nullifiers.at(i)}else{0});};
            data.append(outputs.len().into());
            for i in 0_usize..2_usize {data.append(if i<outputs.len(){*outputs.at(i)}else{0});};
            data.append(token.into());data.append(amount.into());data.append(to.into());
            let binding=hash(data.span());
            let expected=array![VERSION,chain.into(),pool.into(),root,0,0,0,binding];
            let actual=IUltraKeccakZKHonkVerifierDispatcher{contract_address:self.verifier.read()}.verify_ultra_keccak_zk_honk_proof(proof).unwrap();
            assert_eq!(actual.len(),expected.len());
            for i in 0_usize..8_usize {assert_eq!(*actual.at(i),*expected.at(i));};
            for nf in nullifiers {assert(*nf!=0 && *nf<FR,'BAD_NF');assert(!self.spent.read(*nf),'DOUBLE_SPEND');self.spent.write(*nf,true);};
            for cm in outputs {self.insert(*cm);};
            if amount>0 {assert(IERC20Dispatcher{contract_address:self.token.read()}.transfer(recipient,amount.into()),'TRANSFER_FAILED');}
            self.locked.write(false);
        }
        fn get_root(self: @ContractState)->u256 {self.root.read()}
        fn get_spent(self: @ContractState,nf:u256)->bool {self.spent.read(nf)}
    }
    #[generate_trait]
    impl Internal of InternalTrait {
        fn start(ref self: ContractState){assert(!self.locked.read(),'REENTRANCY');self.locked.write(true);}
        fn insert(ref self: ContractState,leaf:u256){
            assert(leaf>0 && leaf<FR,'BAD_LEAF');let index=self.count.read();assert(index<0x100000000,'TREE_FULL');
            let mut idx=index;let mut node=leaf;self.nodes.write((0,idx),node);
            for level in 0_u32..32_u32 {
                let sibling_index=if idx%2==0{idx+1}else{idx-1};
                let stored=self.nodes.read((level,sibling_index));
                let sibling=if stored==0{self.zeros.read(level)}else{stored};
                node=if idx%2==0{pair(node,sibling)}else{pair(sibling,node)};
                idx/=2;self.nodes.write((level+1,idx),node);
            };
            self.root.write(node);self.roots.write(node,true);self.count.write(index+1);
        }
    }
}
