//! Virtual execution only. Verifies an R0 V6 payment client proof (arithmetic-only
//! stwo-circuits) and emits `[class_hash, 'TMPZR0_PAYMENT_V6', chain, pool, binding]` to the outer
//! large-proof facts (`docs/pool-v3-spec.md` §5.3).
//!
//! The client proof alone authorizes the spend: there is no salt, no signature, no constructor
//! argument, no storage read and no external call, so the class hash fixes the relation (route
//! admission, spec §6.5). The account checks the proof's chain id against the transaction's
//! (defense in depth beside the adapter's check). The consuming pool recomputes `binding` from its
//! spend data (the asset on exit, root, nullifiers, output commitments, delivery digests,
//! `valid_until`), checks the root, the expiry and the nullifiers, and applies the spend. The
//! caller-0 guard stays in `__execute__`, since a direct call to `__execute__` skips
//! `__validate__`. This account exposes no `is_valid_signature`.
#[starknet::contract(account)]
pub mod PaymentVerifierAccount {
    use starknet::syscalls::{get_class_hash_at_syscall, get_execution_info_v3_syscall, send_message_to_l1_syscall};
    use starknet::{SyscallResultTrait, get_caller_address, get_contract_address};
    use templar_membership_bridge::{binding, verify_payment};

    #[storage]
    struct Storage {}

    /// Zero tip and zero prices (`PROVE_ONLY`, as V5): the account can only be proved, never pay
    /// for a real transaction.
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
        let statement = verify_payment(proof_data);
        assert!(statement.chain == chain, "chain");
        let binding = binding(@statement);
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let payload = array![class_hash.into(), 'TMPZR0_PAYMENT_V6', statement.chain, statement.pool, binding];
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
