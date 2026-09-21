//! Deliberately permissive fixture, mirroring upstream's caller/approval convention.
#[starknet::contract]
pub mod TestAdapter {
    use starknet::{ContractAddress, get_caller_address, SyscallResultTrait};
    use starknet::syscalls::call_contract_syscall;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
    use pool::return_note::OpenNoteDeposit;
    #[storage]
    struct Storage { mode: u32 }
    #[external(v0)]
    fn configure(ref self: ContractState, mode: u32) { self.mode.write(mode); }
    #[external(v0)]
    fn privacy_invoke(ref self: ContractState, note_id: felt252, token: ContractAddress) -> Span<OpenNoteDeposit> {
        let mode = self.mode.read();
        let caller = get_caller_address();
        if mode == 1 {
            call_contract_syscall(caller,selector!("deposit"),array![token.into(),1,0,0,1,10,1,2,3,4,5,6,7,8,9,10].span()).unwrap_syscall();
        };
        if mode == 2 { return array![].span(); };
        if mode != 3 { IERC20Dispatcher { contract_address: token }.approve(caller,110); };
        let id = if mode == 4 { note_id + 1 } else { note_id };
        let out_token = if mode == 5 { caller } else { token };
        let amount = if mode == 6 { 69 } else { 77 };
        let mut result = array![OpenNoteDeposit { note_id: id, token: out_token, amount }];
        if mode == 7 || mode == 8 {
            result.append(OpenNoteDeposit { note_id: if mode == 8 { id } else { id+1 }, token, amount: 33 });
        };
        result.span()
    }
}

#[starknet::contract]
pub mod MalformedAdapter {
    use starknet::ContractAddress;
    #[storage]
    struct Storage {}
    #[external(v0)]
    fn privacy_invoke(ref self: ContractState, note_id: felt252, token: ContractAddress) -> Span<felt252> {
        // Four words, but element count says 3 rather than one deposit.
        array![note_id,token.into(),77].span()
    }
}
