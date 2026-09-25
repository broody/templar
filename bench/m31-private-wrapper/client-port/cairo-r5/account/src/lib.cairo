//! Virtual execution only. Verifies an R0 V5 payment client proof (arithmetic-only
//! stwo-circuits), authorizes it, and emits `[class_hash, tag, chain, pool, binding]` to the outer
//! large-proof facts (`docs/account-bound-note-spec.md` §5.4).
//!
//! - Ordinary mode (`account = 0`): the Templar key alone, proved by the client proof; `salt` must
//!   be 0 and `signature` empty.
//! - Bound mode: the named account must also authorize the spend. The account computes the
//!   SNIP-12 spend message from the statement and the client's salt and calls the bound account's
//!   `is_valid_signature`; only the exact return `['VALID']` passes. A failed call reverts.
//!
//! The account checks the proof's chain id against the transaction's. The consuming pool
//! recomputes `binding` from its spend data (the asset on exit, root, nullifiers, output
//! commitments, delivery digests, `valid_until`), checks the root and expiry and the nullifiers
//! unspent, and applies the spend. The adapter's `MESSAGE_COUNT = 1` rejects a callee that emits a
//! message, and the caller-0 guard blocks re-entry. This account exposes no `is_valid_signature`.
#[starknet::contract(account)]
pub mod PaymentVerifierAccount {
    use starknet::syscalls::{
        call_contract_syscall, get_class_hash_at_syscall, get_execution_info_v3_syscall,
        send_message_to_l1_syscall,
    };
    use starknet::{ContractAddress, SyscallResultTrait, get_caller_address, get_contract_address};
    use templar_membership_bridge::snip12::spend_message_hash;
    use templar_membership_bridge::{binding, verify_payment};

    #[storage]
    struct Storage {}

    /// R4's rule with V5's calldata (AB-M11): zero tip and zero prices, so the account can only be
    /// proved, never pay for a real transaction.
    #[external(v0)]
    fn __validate__(
        self: @ContractState, proof_data: Span<felt252>, salt: felt252, signature: Span<felt252>,
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
        ref self: ContractState, proof_data: Span<felt252>, salt: felt252, signature: Span<felt252>,
    ) {
        assert!(get_caller_address().into() == 0, "OS_ONLY");
        let chain = get_execution_info_v3_syscall().unwrap_syscall().tx_info.chain_id;
        let statement = verify_payment(proof_data);
        assert!(statement.chain == chain, "chain");
        let binding = binding(@statement);
        if statement.account == 0 {
            // Ordinary: nothing but the proof authorizes the spend.
            assert!(salt == 0 && signature.is_empty(), "ORDINARY_AUTH");
        } else {
            assert!(salt != 0, "SALT");
            let account: ContractAddress = statement.account.try_into().unwrap();
            assert!(account != get_contract_address(), "SELF_ACCOUNT");
            // Calling an undeployed address aborts the whole execution rather than returning an
            // error; check first, so the rejection is explicit.
            let class: felt252 = get_class_hash_at_syscall(account).unwrap_syscall().into();
            assert!(class != 0, "ACCOUNT_NOT_DEPLOYED");
            let hash = spend_message_hash(
                statement.chain,
                statement.account,
                statement.pool,
                binding,
                salt,
                statement.token_out,
                statement.withdrawal_recipient,
                statement.withdrawal_amount,
                statement.intent,
            );
            let mut calldata = array![hash];
            signature.serialize(ref calldata);
            let ret = match call_contract_syscall(account, selector!("is_valid_signature"), calldata.span()) {
                Result::Ok(ret) => ret,
                Result::Err(_) => panic!("SIG_CALL_FAILED"),
            };
            assert!(ret.len() == 1 && *ret.at(0) == 'VALID', "SIG_NOT_VALID");
        }
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let payload = array![class_hash.into(), 'TMPZR0_PAYMENT_V5', statement.chain, statement.pool, binding];
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
