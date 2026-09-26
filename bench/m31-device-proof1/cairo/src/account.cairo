//! Virtual execution only. The cost-model statement account (`statement.cairo`), in the shape of
//! the R5 statement account (`client-port/cairo-r5/account/src/lib.cairo`): prove-only
//! `__validate__`, OS-only `__execute__`, the transaction's chain id, and one message
//! `[class_hash, tag, chain, pool, binding]` with the R0 V5 `spend5` binding.
//!
//! The binding takes the computed root, nullifiers, output commitments and identity handle where
//! the run computed them, and the public calldata values otherwise (small `k`). The account makes
//! no soundness claim: nothing here authorizes a spend.
#[starknet::contract(account)]
pub mod CostStatementAccount {
    use starknet::syscalls::{get_class_hash_at_syscall, get_execution_info_v3_syscall, send_message_to_l1_syscall};
    use starknet::{SyscallResultTrait, get_caller_address, get_contract_address};
    use crate::spend::Output;
    use crate::spend5::{Spend, compute_binding};
    use crate::statement::{check_witness, conservation, run};

    pub const TAG: felt252 = 'TMPZDP1_COST_V1';

    #[storage]
    struct Storage {}

    /// Zero tip and zero prices, so the account can only be proved, never pay for a transaction.
    #[external(v0)]
    fn __validate__(self: @ContractState, spend: Spend, witness: Span<felt252>, jobs: u32, nodes: u32) -> felt252 {
        let info = get_execution_info_v3_syscall().unwrap_syscall();
        assert!(info.tx_info.tip == 0, "PROVE_ONLY");
        for bound in info.tx_info.resource_bounds {
            assert!(*bound.max_price_per_unit == 0, "PROVE_ONLY");
        }
        'VALID'
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, spend: Spend, witness: Span<felt252>, jobs: u32, nodes: u32) {
        assert!(get_caller_address().into() == 0, "OS_ONLY");
        let chain = get_execution_info_v3_syscall().unwrap_syscall().tx_info.chain_id;
        assert!(spend.chain == chain, "chain");
        check_witness(witness);
        conservation(witness, spend.withdrawal.amount);
        let c = run(witness, spend.chain, spend.pool.into(), spend.asset, jobs, nodes);
        let root = match c.root {
            Option::Some(r) => r.span(),
            Option::None => spend.root,
        };
        let nullifiers = match c.nullifiers {
            Option::Some((a, b)) => {
                let mut n = array![];
                n.append_span(a.span());
                n.append_span(b.span());
                n.span()
            },
            Option::None => spend.nullifiers,
        };
        let outputs = match c.outputs {
            Option::Some((a, b)) => array![
                Output { commitment: a.span(), ciphertext: *spend.outputs.at(0).ciphertext },
                Output { commitment: b.span(), ciphertext: *spend.outputs.at(1).ciphertext },
            ]
                .span(),
            Option::None => spend.outputs,
        };
        let identity = match c.identity {
            Option::Some(d) => d.span(),
            Option::None => spend.identity,
        };
        let bound = Spend {
            chain: spend.chain, pool: spend.pool, asset: spend.asset, root, nullifiers, outputs,
            withdrawal: spend.withdrawal, intent: spend.intent, identity, valid_until: spend.valid_until,
            binding: 0,
        };
        let binding = compute_binding(@bound);
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let payload = array![class_hash.into(), TAG, spend.chain, spend.pool.into(), binding];
        send_message_to_l1_syscall(0, payload.span()).unwrap_syscall();
    }
}
