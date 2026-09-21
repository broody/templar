//! State/atomicity tests use an explicit mock proof verdict. Native tests are separate.
use starknet::{ContractAddress, contract_address_const, get_tx_info, SyscallResultTrait};
use starknet::syscalls::call_contract_syscall;
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, test_address,
    start_cheat_block_number};
use core::poseidon::poseidon_hash_span;
use pool::pool::{IPoolDispatcher, IPoolDispatcherTrait, IPoolSafeDispatcher, IPoolSafeDispatcherTrait};
use pool::spend::{Spend, Withdrawal, PROTOCOL_VERSION, compute_binding, IERC20Dispatcher, IERC20DispatcherTrait};
use pool::swap::{SwapIntent, hash_intent, return_digest, IBalanceDispatcher, IBalanceDispatcherTrait,
    ISwapAdapterSafeDispatcher, ISwapAdapterSafeDispatcherTrait};
use pool::tree::{ITreeDispatcher, ITreeDispatcherTrait};

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
fn payload() -> Span<felt252> { array![1,2,3,4,5,6,7,8,9,10].span() }
fn balance(token: ContractAddress, who: ContractAddress) -> u256 {
    IBalanceDispatcher { contract_address: token }.balance_of(who)
}
fn setup() -> (IPoolDispatcher, Spend, SwapIntent) {
    let verifier = deploy("MockVerifier",array![1]);
    let pool = deploy("Pool",array![test_address().into(),verifier.into()]);
    let a = deploy("E2EToken",array![test_address().into(),10000,0]);
    let b = deploy("E2EToken",array![test_address().into(),10000,0]);
    let adapter = deploy("MockSwapAdapter",array![pool.into(),test_address().into(),77]);
    let p = IPoolDispatcher { contract_address: pool };
    start_cheat_block_number(pool,1);
    IERC20Dispatcher { contract_address: a }.approve(pool,1000);
    p.deposit(a,1000,contract_address_const::<0>(),0,0xbeef,payload());
    IERC20Dispatcher { contract_address: b }.transfer(adapter,500);
    let mut spend = Spend {
        version: PROTOCOL_VERSION, chain: get_tx_info().unbox().chain_id, pool,
        root: ITreeDispatcher { contract_address: pool }.get_root(), token: a,
        binding: 0, controller: contract_address_const::<0>(), deadline: 0, nonce: 0,
        transition: 0, sig_r: 0, sig_s: 0, intent: 0, nullifiers: array![123].span(),
        outputs: array![].span(), withdrawals: array![Withdrawal { recipient: adapter, amount: 100 }].span(),
    };
    let intent = SwapIntent { adapter, out_token: b, amount: 100, minimum: 70,
        expiry: 1000, inner: 0xface, policy: 0, ciphertext: payload(), route: array![42].span() };
    spend.intent = hash_intent(@spend,@intent); spend.binding = compute_binding(@spend);
    (p,spend,intent)
}
#[feature("safe_dispatcher")]
fn rejected(p: IPoolDispatcher, spend: Spend, intent: SwapIntent, reason: felt252) {
    let tree = ITreeDispatcher { contract_address: p.contract_address };
    let root = tree.get_root(); let count = tree.get_leaf_count();
    let a = spend.token; let b = intent.out_token; let adapter = intent.adapter;
    let balances = (balance(a,p.contract_address),balance(b,p.contract_address),balance(a,adapter),balance(b,adapter));
    let result = IPoolSafeDispatcher { contract_address: p.contract_address }.execute_swap(spend,intent,array![].span());
    let error = result.expect_err('EXPECTED_REJECTION');
    let mut found = false; for word in error.span() { if *word == reason { found=true; }; };
    assert(found,'WRONG_REJECTION_REASON');
    assert_eq!(tree.get_root(),root); assert_eq!(tree.get_leaf_count(),count);
    assert(!p.get_nullifier_spent(123),'NULLIFIER_CHANGED');
    assert_eq!((balance(a,p.contract_address),balance(b,p.contract_address),balance(a,adapter),balance(b,adapter)),balances);
}
#[test]
fn actual_proceeds_fund_final_note() {
    let (p,s,i) = setup(); let out = i.out_token; let inner = i.inner;
    p.execute_swap(s,i,array![].span());
    let tree = ITreeDispatcher { contract_address: p.contract_address };
    assert_eq!(tree.get_leaf_count(),2); assert(p.get_nullifier_spent(123),'NOT_SPENT');
    assert_eq!(balance(out,p.contract_address),77);
    let cm = poseidon_hash_span(array!['DFI_NOTE_V1',get_tx_info().unbox().chain_id,p.contract_address.into(),out.into(),77,0,0,inner].span());
    assert_eq!(tree.get_node(0,1),cm);
    assert_eq!(p.get_delivery_digest(1),return_digest(payload(),77));
}
#[test]
#[feature("safe_dispatcher")]
fn standalone_withdrawal_rejected() {
    let (p,s,_) = setup(); let a = s.token;
    let result = IPoolSafeDispatcher { contract_address: p.contract_address }.apply_spend(s,array![].span());
    assert(result.is_err(),'WITHDRAWAL_ACCEPTED');
    assert(!p.get_nullifier_spent(123),'NULLIFIER_CHANGED');
    assert_eq!(balance(a,p.contract_address),1000);
}
#[test]
fn slippage_reverts_input_transfer_and_nullifier() {
    let (p,mut s,mut i) = setup(); i.minimum = 80;
    s.intent = hash_intent(@s,@i); s.binding = compute_binding(@s);
    rejected(p,s,i,'MOCK_SLIPPAGE');
}
#[test]
fn redirected_return_rejected() { let (p,s,mut i)=setup(); i.inner=0xbad; rejected(p,s,i,'SWAP_INTENT'); }
#[test]
fn changed_output_token_rejected() { let (p,s,mut i)=setup(); i.out_token=s.token; rejected(p,s,i,'SWAP_INTENT'); }
#[test]
fn changed_route_rejected() { let (p,s,mut i)=setup(); i.route=array![43].span(); rejected(p,s,i,'SWAP_INTENT'); }
#[test]
fn changed_minimum_rejected() { let (p,s,mut i)=setup(); i.minimum=1; rejected(p,s,i,'SWAP_INTENT'); }
#[test]
fn changed_ciphertext_rejected() { let (p,s,mut i)=setup(); i.ciphertext=array![2,2,3,4,5,6,7,8,9,10].span(); rejected(p,s,i,'SWAP_INTENT'); }
#[test]
fn expired_swap_rejected() {
    let (p,s,i)=setup(); start_cheat_block_number(p.contract_address,1001); rejected(p,s,i,'SWAP_EXPIRED');
}
#[test]
fn invalid_withdrawal_budget_rejected() {
    let (p,mut s,i)=setup(); s.withdrawals=array![Withdrawal { recipient: i.adapter,amount: 101 }].span();
    s.binding=compute_binding(@s); rejected(p,s,i,'SWAP_BUDGET');
}
#[test]
fn reentrant_callback_rolls_back() {
    let (p,s,i)=setup();
    call_contract_syscall(i.adapter,selector!("configure"),array![77,1].span()).unwrap_syscall();
    rejected(p,s,i,'REENTRANCY');
}
#[test]
fn unfunded_return_rolls_back() {
    let (p,s,i)=setup();
    call_contract_syscall(i.adapter,selector!("configure"),array![77,2].span()).unwrap_syscall();
    rejected(p,s,i,'INSUFFICIENT_ALLOWANCE');
}
#[test]
#[feature("safe_dispatcher")]
fn adapter_cannot_be_called_directly() {
    let (_,s,i)=setup();
    let result=ISwapAdapterSafeDispatcher { contract_address: i.adapter }.swap(s.token,i.out_token,100,70,i.route);
    assert(result.is_err(),'UNAUTHORIZED_ADAPTER');
}
#[test]
fn false_native_verdict_cannot_fund_return() {
    let (p,s,i)=setup(); let verifier=deploy("MockVerifier",array![0]); p.set_verifier(verifier);
    rejected(p,s,i,'PROOF_REJECTED');
}
