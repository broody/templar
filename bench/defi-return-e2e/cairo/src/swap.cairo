//! Isolated exact-input, single-hop swap pathfinding. No arbitrary pool approvals.
use starknet::ContractAddress;
use core::poseidon::poseidon_hash_span;
use pool::spend::{Spend, PROTOCOL_VERSION, delivery_digest};

#[derive(Drop, Serde)]
pub struct SwapIntent {
    pub adapter: ContractAddress,
    pub out_token: ContractAddress,
    pub amount: u128,
    pub minimum: u128,
    pub expiry: u64,
    pub inner: felt252,
    pub policy: felt252,
    pub ciphertext: Span<felt252>,
    pub route: Span<felt252>,
}
pub fn hash_intent(spend: @Spend, intent: @SwapIntent) -> felt252 {
    assert(intent.route.len() <= 16, 'ROUTE_LIMIT');
    let mut data = array!['DFI_SWAP_V1', PROTOCOL_VERSION, *spend.chain, (*spend.pool).into(),
        (*spend.token).into(), (*spend.controller).into(), (*intent.adapter).into(),
        (*intent.out_token).into(), (*intent.amount).into(), (*intent.minimum).into(),
        (*intent.expiry).into(), *intent.inner, *intent.policy, delivery_digest(*intent.ciphertext),
        intent.route.len().into()];
    for word in *intent.route { data.append(*word); };
    poseidon_hash_span(data.span())
}
pub fn return_digest(ciphertext: Span<felt252>, amount: u128) -> felt252 {
    assert(amount != 0, 'RETURN_ZERO');
    poseidon_hash_span(array!['DFI_RETURN_V1', amount.into(), delivery_digest(ciphertext)].span())
}
#[starknet::interface]
pub trait IBalance<TState> {
    fn balance_of(self: @TState, account: ContractAddress) -> u256;
}
#[starknet::interface]
pub trait ISwapAdapter<TState> {
    fn swap(ref self: TState, token: ContractAddress, out_token: ContractAddress,
        amount: u128, minimum: u128, route: Span<felt252>) -> u128;
}

/// Real Ekubo router adapter. The immutable pool is the only permitted caller.
/// Route is (fee, tick_spacing, extension, skip_ahead); router is immutable.
#[starknet::contract]
pub mod EkuboAdapter {
    use starknet::{ContractAddress, get_caller_address, get_contract_address, SyscallResultTrait};
    use starknet::syscalls::call_contract_syscall;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
    use super::{ISwapAdapter, IBalanceDispatcher, IBalanceDispatcherTrait};
    #[storage]
    struct Storage { pool: ContractAddress, router: ContractAddress }
    #[constructor]
    fn constructor(ref self: ContractState, pool: ContractAddress, router: ContractAddress) {
        assert(pool.into() != 0 && router.into() != 0, 'ZERO_CONFIG');
        self.pool.write(pool); self.router.write(router);
    }
    #[abi(embed_v0)]
    impl Adapter of ISwapAdapter<ContractState> {
        fn swap(ref self: ContractState, token: ContractAddress, out_token: ContractAddress,
            amount: u128, minimum: u128, route: Span<felt252>) -> u128 {
            assert(get_caller_address() == self.pool.read(), 'ONLY_POOL');
            assert(route.len() == 4 && *route.at(2) == 0, 'ROUTE_SHAPE');
            assert(token != out_token && amount != 0, 'SWAP_ARGS');
            let router = self.router.read(); let me = get_contract_address();
            let output = IBalanceDispatcher { contract_address: out_token };
            let before = output.balance_of(me);
            assert(IERC20Dispatcher { contract_address: token }.transfer(router,amount.into()), 'INPUT_TRANSFER');
            let token0 = if token < out_token { token } else { out_token };
            let token1 = if token < out_token { out_token } else { token };
            // ABI: RouteNode { PoolKey, sqrt_ratio_limit:u256, skip_ahead:u128 },
            // TokenAmount { token, amount:i129 { mag:u128, sign:bool } }.
            call_contract_syscall(router,selector!("swap"),array![token0.into(),token1.into(),
                *route.at(0),*route.at(1),*route.at(2),0,0,*route.at(3),token.into(),amount.into(),0].span()).unwrap_syscall();
            let remaining = call_contract_syscall(router,selector!("clear"),array![token.into()].span()).unwrap_syscall();
            assert(remaining.len() == 2 && *remaining.at(0) == 0 && *remaining.at(1) == 0, 'PARTIAL_FILL');
            call_contract_syscall(router,selector!("clear_minimum"),array![out_token.into(),minimum.into(),0].span()).unwrap_syscall();
            let received: u128 = (output.balance_of(me) - before).try_into().expect('RETURN_OVERFLOW');
            assert(received >= minimum && received != 0, 'SWAP_MINIMUM');
            assert(IERC20Dispatcher { contract_address: out_token }.approve(self.pool.read(),received.into()), 'OUTPUT_APPROVAL');
            received
        }
    }
}

/// Test fixture: mutable fill amount represents a market moving after proving.
#[starknet::contract]
pub mod MockSwapAdapter {
    use starknet::{ContractAddress, get_caller_address, get_contract_address, SyscallResultTrait};
    use starknet::syscalls::call_contract_syscall;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
    use super::ISwapAdapter;
    #[storage]
    struct Storage { pool: ContractAddress, owner: ContractAddress, fill: u128, mode: u32 }
    #[constructor]
    fn constructor(ref self: ContractState, pool: ContractAddress, owner: ContractAddress, fill: u128) {
        self.pool.write(pool); self.owner.write(owner); self.fill.write(fill);
    }
    #[external(v0)]
    fn configure(ref self: ContractState, fill: u128, mode: u32) {
        assert(get_caller_address() == self.owner.read(), 'ONLY_OWNER');
        self.fill.write(fill); self.mode.write(mode);
    }
    #[abi(embed_v0)]
    impl Adapter of ISwapAdapter<ContractState> {
        fn swap(ref self: ContractState, token: ContractAddress, out_token: ContractAddress,
            amount: u128, minimum: u128, route: Span<felt252>) -> u128 {
            assert(get_caller_address() == self.pool.read(), 'ONLY_POOL');
            assert(route.len() == 1 && *route.at(0) == 42, 'MOCK_ROUTE');
            let fill = self.fill.read();
            assert(fill >= minimum, 'MOCK_SLIPPAGE');
            assert(IERC20Dispatcher { contract_address: token }.transfer(self.owner.read(),amount.into()), 'MOCK_INPUT');
            if self.mode.read() == 1 {
                // Reenter deposit with an otherwise well-formed receipt.
                call_contract_syscall(self.pool.read(),selector!("deposit"),array![
                    out_token.into(),1,0,0,1,10,1,2,3,4,5,6,7,8,9,10].span()).unwrap_syscall();
            };
            if self.mode.read() == 2 { return 1000000; }; // No allowance/funding.
            assert(IERC20Dispatcher { contract_address: out_token }.approve(self.pool.read(),fill.into()), 'MOCK_APPROVE');
            fill
        }
    }
}
