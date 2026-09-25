//! P0b feasibility spike (throwaway, not production).
//!
//! `SigProbe` is a prove-only account in the shape of the R4 statement account
//! (`bench/m31-private-wrapper/client-port/cairo-r4/account`): `__validate__` accepts only
//! zero-fee transactions, and `__execute__` runs only as the top-level account call (caller 0).
//! `__execute__(target, hash, signature)` calls `target.is_valid_signature(hash, signature)`,
//! requires the return to be exactly `['VALID']` (a failed call or any other return rejects), and
//! then emits one L2->L1 message `[class_hash, 'SPIKE_SIG_V1', target, hash]`.
#[starknet::contract(account)]
pub mod SigProbe {
    use starknet::syscalls::{
        call_contract_syscall, get_class_hash_at_syscall, get_execution_info_v3_syscall,
        send_message_to_l1_syscall,
    };
    use starknet::{ContractAddress, SyscallResultTrait, get_caller_address, get_contract_address};

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn __validate__(
        self: @ContractState, target: ContractAddress, hash: felt252, signature: Span<felt252>,
    ) -> felt252 {
        let info = get_execution_info_v3_syscall().unwrap_syscall();
        assert!(info.tx_info.tip == 0, "PROVE_ONLY");
        for bound in info.tx_info.resource_bounds {
            assert!(*bound.max_price_per_unit == 0, "PROVE_ONLY");
        }
        'VALID'
    }

    #[external(v0)]
    fn __execute__(
        ref self: ContractState, target: ContractAddress, hash: felt252, signature: Span<felt252>,
    ) {
        assert!(get_caller_address().into() == 0, "OS_ONLY");
        let mut calldata = array![hash];
        signature.serialize(ref calldata);
        let ret = match call_contract_syscall(
            target, selector!("is_valid_signature"), calldata.span(),
        ) {
            Result::Ok(ret) => ret,
            Result::Err(_) => panic!("SIG_CALL_FAILED"),
        };
        assert!(ret.len() == 1 && *ret.at(0) == 'VALID', "SIG_NOT_VALID");
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let payload = array![class_hash.into(), 'SPIKE_SIG_V1', target.into(), hash];
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
