//! Immutable single-key authorization fixture using real Stark-curve ECDSA.
//! Policy is evaluated off-chain before signing the canonical scoped transition.
#[starknet::contract]
pub mod SignatureController {
    use core::ecdsa::check_ecdsa_signature;
    use core::ec::{EcPointTrait, stark_curve::ORDER};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use pool::spend::IController;
    #[storage]
    struct Storage { public_key: felt252 }
    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        assert(EcPointTrait::new_nz_from_x(public_key).is_some(), 'BAD_PUBLIC_KEY');
        self.public_key.write(public_key);
    }
    #[abi(embed_v0)]
    impl ControllerImpl of IController<ContractState> {
        fn verify_transition(self: @ContractState, transition: felt252, sig_r: felt252, sig_s: felt252) -> bool {
            let r: u256 = sig_r.into(); let s: u256 = sig_s.into(); let order: u256 = ORDER.into();
            if transition == 0 || r == 0 || s == 0 || r >= order || s >= order { return false; };
            // Canonical 251-bit message conversion; full transition stays bound by the proof.
            let digest: u256 = transition.into();
            let message: felt252 = (digest & 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff).try_into().unwrap();
            check_ecdsa_signature(message,self.public_key.read(),sig_r,sig_s)
        }
    }
}
