//! M1 verifier seams: configurable-verdict mocks for the inner-proof and
//! controller-signature checks. Replaced in M2/M3 (see `spend.cairo`).

#[starknet::contract]
pub mod MockVerifier {
    use pool::spend::IVerifier;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        verdict: bool,
    }

    #[constructor]
    fn constructor(ref self: ContractState, verdict: bool) {
        self.verdict.write(verdict);
    }

    #[abi(embed_v0)]
    impl VerifierImpl of IVerifier<ContractState> {
        fn verify(self: @ContractState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool {
            self.verdict.read()
        }
    }
}

