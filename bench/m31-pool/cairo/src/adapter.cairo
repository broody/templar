//! PROOF2 fact adapter for the M31 pool's `IVerifier` seam, modeled on the PROOF1 adapter used in
//! the earlier Sepolia runs (`controlled-push-e2e/cairo/src/proof_adapter.cairo`). Starknet
//! verifies the attached proof before execution; this contract binds the verified virtual
//! execution's single message to this pool and spend:
//!
//! - facts = `['PROOF2', 'VIRTUAL_SNOS', os_program, 'VIRTUAL_SNOS0', base_block, base_hash, _,
//!   n_messages, message_hash]` (the sequencer's `ProofFactsVariant::Snos` layout);
//! - `message_hash = Poseidon(statement, 0, 5, statement_class, 'TMPZR0_PAYMENT_V3', chain, pool,
//!   binding)`: the R0 statement account's L2→L1 message (`client-port/cairo-r0/account`).
//!
//! The sequencer checks the base block's hash; this adapter bounds its age.
#[starknet::contract]
pub mod Proof2Adapter {
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::syscalls::get_execution_info_v3_syscall;
    use starknet::{ContractAddress, SyscallResultTrait, get_caller_address};
    use crate::spend::IVerifier;

    #[storage]
    struct Storage {
        pool: ContractAddress,
        statement: ContractAddress,
        statement_class: felt252,
        os_program: felt252,
        max_proof_age: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, pool: ContractAddress, statement: ContractAddress, statement_class: felt252,
        os_program: felt252, max_proof_age: u64,
    ) {
        assert(pool.into() != 0 && statement.into() != 0, 'ZERO_ADDRESS');
        assert(statement_class != 0 && os_program != 0 && max_proof_age != 0, 'BAD_CONFIG');
        self.pool.write(pool);
        self.statement.write(statement);
        self.statement_class.write(statement_class);
        self.os_program.write(os_program);
        self.max_proof_age.write(max_proof_age);
    }

    #[abi(embed_v0)]
    impl VerifierImpl of IVerifier<ContractState> {
        fn verify(self: @ContractState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool {
            assert(proof.is_empty(), 'PROOF_IN_TX_ONLY');
            assert(get_caller_address() == self.pool.read(), 'ONLY_POOL');
            // The pool passes [chain, pool, binding].
            assert(public_inputs.len() == 3, 'PUBLIC_LENGTH');
            let info = get_execution_info_v3_syscall().unwrap_syscall();
            let chain = *public_inputs.at(0);
            assert(chain == info.tx_info.chain_id, 'WRONG_CHAIN');
            assert(*public_inputs.at(1) == self.pool.read().into(), 'WRONG_POOL');
            let facts = info.tx_info.proof_facts;
            assert(facts.len() == 9, 'PROOF_FACTS_LENGTH');
            assert(*facts.at(0) == 'PROOF2', 'PROOF_VERSION');
            assert(*facts.at(1) == 'VIRTUAL_SNOS', 'PROOF_VARIANT');
            assert(*facts.at(2) == self.os_program.read(), 'OS_PROGRAM');
            assert(*facts.at(3) == 'VIRTUAL_SNOS0', 'OUTPUT_VERSION');
            let base: u64 = (*facts.at(4)).try_into().expect('BASE_BLOCK');
            let current = info.block_info.block_number;
            assert(base < current, 'PROOF_AGE');
            assert(current - base <= self.max_proof_age.read(), 'PROOF_AGE');
            assert(*facts.at(7) == 1, 'MESSAGE_COUNT');
            let message = array![
                self.statement.read().into(), 0, 5, self.statement_class.read(), 'TMPZR0_PAYMENT_V3', chain,
                *public_inputs.at(1), *public_inputs.at(2),
            ];
            assert(*facts.at(8) == poseidon_hash_span(message.span()), 'PROOF_BINDING');
            true
        }
    }
}
