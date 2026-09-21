//! Stateless generic public append verifier account for virtual execution only.
//! The receiving pool independently authorizes this account/class/program and its queue.
#[starknet::contract(account)]
pub mod M31AppendStatementAccount {
    use starknet::{ContractAddress,get_caller_address,get_contract_address,SyscallResultTrait};
    use starknet::syscalls::{get_class_hash_at_syscall,get_execution_info_v3_syscall,send_message_to_l1_syscall};
    #[storage]
    struct Storage {}
    #[external(v0)]
    fn __validate__(self: @ContractState,proof_data: Span<felt252>) -> felt252 {
        let info=get_execution_info_v3_syscall().unwrap_syscall();
        assert!(info.tx_info.tip==0,"PROVE_ONLY");
        for bound in info.tx_info.resource_bounds { assert!(*bound.max_price_per_unit==0,"PROVE_ONLY"); };
        'VALID'
    }
    #[external(v0)]
    fn __execute__(ref self: ContractState,proof_data: Span<felt252>) {
        assert!(get_caller_address().into()==0,"OS_ONLY");
        let output=templar_m31_append_bridge::verify_serialized(proof_data);
        assert!(output.public_values.len()==8,"PUBLIC_LENGTH");
        assert!(*output.public_values.at(0)=='M31_APPEND_V1',"APPEND_VERSION");
        let info=get_execution_info_v3_syscall().unwrap_syscall();
        assert!(*output.public_values.at(1)==info.tx_info.chain_id,"ACTUAL_CHAIN");
        let pool: ContractAddress=(*output.public_values.at(2)).try_into().expect('POOL_ADDRESS');
        assert!(pool.into()!=0,"ZERO_POOL");
        let class_hash=get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let mut message=array![class_hash.into()];
        for value in output.public_values { message.append(*value); };
        send_message_to_l1_syscall(0,message.span()).unwrap_syscall();
    }
}
