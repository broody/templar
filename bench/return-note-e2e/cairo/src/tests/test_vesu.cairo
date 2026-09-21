use starknet::{get_tx_info, SyscallResultTrait};
use pool::pool::IPoolDispatcherTrait;
use pool::spend::{Withdrawal, IERC20Dispatcher, IERC20DispatcherTrait};
use pool::return_note::ReturnNote;
use pool::tree::{ITreeDispatcher, ITreeDispatcherTrait};
use super::test_return_note::{deploy,payload,balance,authorize,setup};
// Imported, unmodified upstream adapter against its mock vault. Not live Vesu qualification.
pub fn exercise_vault() {
    let (p,mut s,mut i)=setup(); let underlying=s.token;
    let mut ctor: Array<felt252>=array![]; let name: ByteArray="Vault"; let symbol: ByteArray="VLT";
    name.serialize(ref ctor); symbol.serialize(ref ctor);
    underlying.serialize(ref ctor); 2_u256.serialize(ref ctor);
    let vault=deploy("MockVesuVault",ctor); i.adapter=deploy("VesuLendingAnonymizer",array![]);
    IERC20Dispatcher { contract_address:underlying }.transfer(vault,100);
    s.withdrawals=array![Withdrawal { recipient:i.adapter,amount:100 }].span();
    i.calldata=array![0,underlying.into(),vault.into(),100,0,17].span();
    i.notes=array![ReturnNote { note_id:17,token:vault,minimum:100,inner:0xface,ciphertext:payload() }].span();
    authorize(ref s,@i); p.execute_returns(s,i,array![].span()); assert_eq!(balance(vault,p.contract_address),100);
    let (_,mut s,mut i)=setup(); // Only reuse value fixtures; execute against the first pool.
    s.pool=p.contract_address; s.root=ITreeDispatcher { contract_address:p.contract_address }.get_root();
    s.token=vault; s.nullifiers=array![124].span();
    i.adapter=deploy("VesuLendingAnonymizer",array![]);
    s.withdrawals=array![Withdrawal { recipient:i.adapter,amount:100 }].span();
    i.calldata=array![1,vault.into(),underlying.into(),100,0,18].span();
    i.notes=array![ReturnNote { note_id:18,token:underlying,minimum:200,inner:0xbeef,ciphertext:payload() }].span();
    authorize(ref s,@i); p.execute_returns(s,i,array![].span());
    assert_eq!(balance(vault,p.contract_address),0); assert_eq!(balance(underlying,p.contract_address),1100);
}
