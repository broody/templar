//! Virtual execution only. Verifies an arithmetic-profile client membership proof and emits its
//! statement to the outer PROOF2 facts: `[class_hash, tag, chain, pool, root[0..9]]`. The account
//! checks the proof's chain id against the transaction's; the consuming pool checks `pool` is its
//! own address and `root` one of its roots. It does not implement a payment or pool state
//! transition.
#[starknet::contract(account)]
pub mod MembershipVerifierAccount {
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
        let statement = templar_membership_bridge::verify_membership(proof_data);
        assert!(statement.chain == chain, "chain");
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let mut payload = array![
            class_hash.into(), 'TMPZSA01_MEMBERSHIP_V1', statement.chain, statement.pool,
        ];
        for r in statement.root {
            payload.append(r.into());
        }
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
