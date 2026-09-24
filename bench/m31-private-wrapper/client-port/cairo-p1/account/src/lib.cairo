//! Virtual execution only. Verifies a P1 policy-settlement client proof (arithmetic-only
//! stwo-circuits) and emits `[class_hash, 'TMPZP1_POLICY_V1', chain, pool, binding]` to the outer
//! PROOF2 facts. The account checks the proof's chain id against the transaction's. The consuming
//! pool recomputes `binding` from its policy-spend data and applies the settlement
//! (`docs/policy-note-spec.md` §6). This account does not implement the pool.
#[starknet::contract(account)]
pub mod PolicyVerifierAccount {
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
        }
        'VALID'
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, proof_data: Span<felt252>) {
        assert!(get_caller_address().into() == 0, "OS_ONLY");
        let chain = get_execution_info_v3_syscall().unwrap_syscall().tx_info.chain_id;
        let statement = templar_membership_bridge::verify_policy(proof_data);
        assert!(statement.chain == chain, "chain");
        let binding = templar_membership_bridge::binding(@statement);
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let payload = array![
            class_hash.into(), 'TMPZP1_POLICY_V1', statement.chain, statement.pool, binding,
        ];
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
