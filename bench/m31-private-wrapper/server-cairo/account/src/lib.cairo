//! Virtual execution only. This probe verifies a public hash circuit proof and exposes its
//! public commitment to the outer statement. It does not implement a payment statement.
#[starknet::contract(account)]
pub mod ServerHashCircuitAccount {
    use starknet::{get_caller_address, get_contract_address};
    use starknet::syscalls::{
        get_class_hash_at_syscall, get_execution_info_v3_syscall, send_message_to_l1_syscall,
    };
    use starknet::SyscallResultTrait;

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn __validate__(self: @ContractState, proof_data: Span<felt252>) -> felt252 {
        let info = get_execution_info_v3_syscall().unwrap_syscall();
        assert!(info.tx_info.tip == 0, "PROVE_ONLY");
        for bound in info.tx_info.resource_bounds {
            assert!(*bound.max_price_per_unit == 0, "PROVE_ONLY");
        };
        'VALID'
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, proof_data: Span<felt252>) {
        assert!(get_caller_address().into() == 0, "OS_ONLY");
        let output = templar_server_hash_bridge::verify_serialized(proof_data);
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let [h0, h1, h2, h3, h4, h5, h6, h7] = output.output_hash.hash.unbox();
        // Four u64 limbs preserve all 256 digest bits. This is a diagnostic schema,
        // deliberately separate from the pool's version/chain/transition encoding.
        let info = get_execution_info_v3_syscall().unwrap_syscall();
        let payload = array![
            class_hash.into(), 'SERVER_HASH_CIRCUIT_V1', info.tx_info.chain_id, 0,
            h0.into() + h1.into() * 0x100000000,
            h2.into() + h3.into() * 0x100000000,
            h4.into() + h5.into() * 0x100000000,
            h6.into() + h7.into() * 0x100000000, 0,
        ];
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
