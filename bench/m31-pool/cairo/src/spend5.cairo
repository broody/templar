//! R0 V5 spend data and its binding (`docs/account-bound-note-spec.md` §5.2, §8.1). The binding
//! is the one the R0 V5 bridge emits (`client-port/cairo-r5/bridge/src/lib.cairo`, `binding`):
//! `Poseidon('TMR0_BIND_V5', chain, pool, asset, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
//! recipient, amount, intent, identity₉, valid_until)`: V4's fields, then the public expiry. The
//! bound account never reaches the chain, so it is not a field here.
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;
use crate::spend::{Output, Withdrawal, delivery_digest, is_active};

#[derive(Drop, Serde)]
pub struct Spend {
    pub chain: felt252,
    pub pool: ContractAddress,
    /// The asset on exit (a withdrawal or an intent), zero for an in-pool transfer.
    pub asset: felt252,
    /// Nine words: a root the pool accepts (§8.3).
    pub root: Span<felt252>,
    /// Two nullifiers, nine words each (a dummy input's included).
    pub nullifiers: Span<felt252>,
    /// Exactly two, both with a nonzero commitment and a ciphertext.
    pub outputs: Span<Output>,
    pub withdrawal: Withdrawal,
    /// Zero for an ordinary spend; the execution intent otherwise.
    pub intent: felt252,
    /// Nine words: the shadow-account identity handle, zero when unused.
    pub identity: Span<felt252>,
    /// The last block at which the spend may land (§8.2).
    pub valid_until: u64,
    pub binding: felt252,
}

pub fn compute_binding(s: @Spend) -> felt252 {
    assert(s.root.len() == 9, 'ROOT_LENGTH');
    assert(s.nullifiers.len() == 18, 'INPUT_COUNT');
    assert(s.outputs.len() == 2, 'OUTPUT_COUNT');
    assert(s.identity.len() == 9, 'IDENTITY_LENGTH');
    let mut data = array!['TMR0_BIND_V5', *s.chain, (*s.pool).into(), *s.asset];
    data.append_span(*s.root);
    data.append_span(*s.nullifiers);
    for output in *s.outputs {
        assert(output.commitment.len() == 9, 'COMMITMENT_LENGTH');
        assert(is_active(*output.commitment), 'ZERO_COMMITMENT');
        data.append_span(*output.commitment);
        data.append(delivery_digest(*output.ciphertext));
    }
    let w = *s.withdrawal;
    data.append(w.recipient.into());
    data.append(w.amount.into());
    data.append(*s.intent);
    data.append_span(*s.identity);
    data.append((*s.valid_until).into());
    poseidon_hash_span(data.span())
}
