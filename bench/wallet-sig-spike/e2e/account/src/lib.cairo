//! P0b spike (THROWAWAY, measurement only). The R4 statement account
//! (`client-port/cairo-r4/account`) plus an owner authorization: after the client proof and the
//! chain check, it computes the SNIP-12 rev-1 `TemplarSpend` message hash
//! (`bench/wallet-sig-spike/snip12`) for a fixed synthetic owner account and checks a Stark
//! ECDSA signature over it with `core::ecdsa::check_ecdsa_signature`. That call INLINES what an
//! Argent-style `is_valid_signature` does for a single Stark owner; the synthetic fixture state
//! has no owner account to call, so the external call and its dispatch are not measured.
//!
//! Calldata: `[proof_data span..., owner_pubkey, salt, valid_until, r, s]`. The emitted message
//! is unchanged from R4: `[class_hash, 'TMPZR0_PAYMENT_V4', chain, pool, binding]`.
//! `valid_until` is signed but not compared with the block (not decided for the spike).
#[starknet::contract(account)]
pub mod WalletSigSpikeAccount {
    use core::ecdsa::check_ecdsa_signature;
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use starknet::syscalls::{
        get_class_hash_at_syscall, get_execution_info_v3_syscall, send_message_to_l1_syscall,
    };
    use starknet::SyscallResultTrait;

    /// Fixed synthetic owner account: the SNIP-12 `account` slot (the S1 KAT account).
    const OWNER_ACCOUNT: felt252 = 0x0734b2c2;

    #[storage]
    struct Storage {}

    /// The bridge already bounds pool, token_out and recipient below 2^251.
    fn address(x: felt252) -> ContractAddress {
        x.try_into().expect('address')
    }

    #[external(v0)]
    fn __validate__(
        self: @ContractState,
        proof_data: Span<felt252>,
        owner_pubkey: felt252,
        salt: felt252,
        valid_until: u128,
        signature_r: felt252,
        signature_s: felt252,
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
        ref self: ContractState,
        proof_data: Span<felt252>,
        owner_pubkey: felt252,
        salt: felt252,
        valid_until: u128,
        signature_r: felt252,
        signature_s: felt252,
    ) {
        assert!(get_caller_address().into() == 0, "OS_ONLY");
        let chain = get_execution_info_v3_syscall().unwrap_syscall().tx_info.chain_id;
        let statement = templar_membership_bridge::verify_payment(proof_data);
        assert!(statement.chain == chain, "chain");
        let binding = templar_membership_bridge::binding(@statement);
        let hash = templar_wallet_sig_snip12::spend_message_hash(
            statement.chain,
            address(OWNER_ACCOUNT),
            address(statement.pool),
            binding,
            salt,
            address(statement.token_out),
            address(statement.withdrawal_recipient),
            statement.withdrawal_amount,
            statement.intent,
            valid_until,
        );
        assert!(check_ecdsa_signature(hash, owner_pubkey, signature_r, signature_s), "owner signature");
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let payload = array![
            class_hash.into(), 'TMPZR0_PAYMENT_V4', statement.chain, statement.pool, binding,
        ];
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
