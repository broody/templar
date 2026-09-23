//! Virtual execution only. Verifies a circuit-A proof that a TMPZK002 private-membership
//! proof is valid for a statement `x`, and emits `Blake2s(x)` with the membership root to
//! the outer PROOF2 facts. The consuming pool must rebuild `x` from its own chain, its own
//! address and the root (`templar_membership_bridge::statement_bytes`) and compare digests.
//! Keeping that check in the pool keeps this class under the declared-class size limit.
//! It does not implement a payment or pool state transition.
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
        let (digest, root) = templar_membership_bridge::verify_membership(proof_data);
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        // Blake2s(x) as two 128-bit halves, little-endian word order within each half.
        let d = digest.span();
        let mut lo: felt252 = 0;
        let mut hi: felt252 = 0;
        let mut k = 4;
        while k > 0 {
            k -= 1;
            lo = lo * 0x100000000 + (*d.at(k)).into();
            hi = hi * 0x100000000 + (*d.at(k + 4)).into();
        }
        let mut payload = array![class_hash.into(), 'TMPZK002_MEMBERSHIP_V1', chain, lo, hi];
        for r in root.span() {
            payload.append((*r).into());
        }
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
