//! Experimental native PROOF1 adapter for the unchanged pool IVerifier seam.
//! Cryptographic proof verification is performed by Starknet before execution.
//! This contract binds the verified virtual message to this pool and statement.
#[starknet::contract]
pub mod NativeProofVerifier {
    use core::poseidon::poseidon_hash_span;
    use starknet::{ContractAddress, get_caller_address};
    use starknet::syscalls::get_execution_info_v3_syscall;
    use starknet::SyscallResultTrait;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use pool::spend::{IVerifier, PROTOCOL_VERSION};

    #[storage]
    struct Storage {
        pool: ContractAddress,
        statement: ContractAddress,
        statement_class: felt252,
        max_proof_age: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, pool: ContractAddress, statement: ContractAddress,
        statement_class: felt252, max_proof_age: u64,
    ) {
        assert(pool.into() != 0 && statement.into() != 0, 'ZERO_ADDRESS');
        assert(statement_class != 0 && max_proof_age != 0, 'BAD_CONFIG');
        self.pool.write(pool);
        self.statement.write(statement);
        self.statement_class.write(statement_class);
        self.max_proof_age.write(max_proof_age);
    }

    #[abi(embed_v0)]
    impl VerifierImpl of IVerifier<ContractState> {
        fn verify(self: @ContractState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool {
            assert(proof.is_empty(), 'PROOF_IN_TX_ONLY');
            assert(get_caller_address() == self.pool.read(), 'ONLY_POOL');
            assert(public_inputs.len() == 8, 'PUBLIC_LENGTH');
            let info = get_execution_info_v3_syscall().unwrap_syscall();
            assert(*public_inputs.at(0) == PROTOCOL_VERSION, 'WRONG_VERSION');
            assert(*public_inputs.at(1) == info.tx_info.chain_id, 'WRONG_CHAIN');
            assert(*public_inputs.at(2) == self.pool.read().into(), 'WRONG_POOL');
            let facts = info.tx_info.proof_facts;
            assert(facts.len() == 9, 'PROOF_FACTS_LENGTH');
            assert(*facts.at(0) == 'PROOF1', 'PROOF_VERSION');
            assert(*facts.at(1) == 'VIRTUAL_SNOS', 'PROOF_VARIANT');
            assert(*facts.at(2) ==
                0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1,
                'OS_PROGRAM');
            assert(*facts.at(3) == 'VIRTUAL_SNOS0', 'OUTPUT_VERSION');
            let base: u64 = (*facts.at(4)).try_into().expect('BASE_BLOCK');
            let current = info.block_info.block_number;
            assert(base < current, 'PROOF_AGE');
            assert(current - base <= self.max_proof_age.read(), 'PROOF_AGE');
            assert(*facts.at(7) == 1, 'MESSAGE_COUNT');
            let mut message = array![self.statement.read().into(), 0, 9, self.statement_class.read()];
            for x in public_inputs { message.append(*x); };
            assert(*facts.at(8) == poseidon_hash_span(message.span()), 'PROOF_BINDING');
            true
        }
    }
}
