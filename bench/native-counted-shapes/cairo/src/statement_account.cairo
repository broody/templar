//! Virtual execution entry point. The private witness stays at the local prover.
#[starknet::contract(account)]
pub mod StatementAccount {
    use starknet::{ContractAddress, get_contract_address, get_caller_address};
    use starknet::syscalls::{get_execution_info_v3_syscall, get_class_hash_at_syscall, send_message_to_l1_syscall};
    use starknet::SyscallResultTrait;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage { pool: ContractAddress }

    #[constructor]
    fn constructor(ref self: ContractState, pool: ContractAddress) {
        assert(pool.into() != 0, 'ZERO_POOL');
        self.pool.write(pool);
    }

    #[external(v0)]
    fn __validate__(self: @ContractState, witness: Span<felt252>) -> felt252 {
        let info = get_execution_info_v3_syscall().unwrap_syscall();
        assert(info.tx_info.tip == 0, 'PROVE_ONLY');
        for bound in info.tx_info.resource_bounds {
            assert(*bound.max_price_per_unit == 0, 'PROVE_ONLY');
        };
        'VALID'
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, witness: Span<felt252>) {
        assert(get_caller_address().into() == 0, 'OS_ONLY');
        let p = crate::statement::verify_spend(witness);
        let info = get_execution_info_v3_syscall().unwrap_syscall();
        assert(*p.at(0) == crate::spend::PROTOCOL_VERSION, 'WRONG_VERSION');
        assert(*p.at(1) == info.tx_info.chain_id, 'WRONG_CHAIN');
        assert(*p.at(2) == self.pool.read().into(), 'WRONG_POOL');
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let mut payload = array![class_hash.into()];
        for x in p.span() { payload.append(*x); };
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
