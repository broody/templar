"""Off-chain policy fixture: scoped legs only; real Stark signing, no wallet witnesses."""
from protocol import transition_hash, signature_message
from starknet_py.hash.utils import message_signature, private_to_stark_key, verify_message_signature
FIELDS={'chain','pool','root','token','controller','deadline','nonce','inputs','outputs','withdrawals'}
def approve(request,policy,private_key,*,current_block):
    if set(request)!=FIELDS: raise ValueError('unexpected transition fields')
    for name in ['chain','pool','token','controller']:
        if request[name]!=policy[name]: raise ValueError('policy context')
    if not current_block<request['deadline']<=current_block+2000: raise ValueError('policy expiry')
    if not request['nonce']: raise ValueError('policy nonce')
    ins,outs,wds=request['inputs'],request['outputs'],request['withdrawals']
    if not (1<=len(ins)<=4 and len(outs)<=4 and len(wds)<=2 and len(outs)+len(wds)>0): raise ValueError('policy shape')
    if any(leg[2]!=policy['policy_id'] for leg in ins+outs): raise ValueError('policy commitment')
    if any(amt<=0 or amt>=2**128 for _,amt,*_ in ins+outs): raise ValueError('policy amount')
    if any(to!=policy['withdrawal_recipient'] or not 0<amt<=policy['max_withdrawal'] for to,amt in wds): raise ValueError('policy withdrawal')
    if sum(x[1] for x in ins)!=sum(x[1] for x in outs)+sum(x[1] for x in wds): raise ValueError('policy conservation')
    digest=transition_hash(**request)
    signature=message_signature(signature_message(digest),private_key)
    assert verify_message_signature(signature_message(digest),signature,private_to_stark_key(private_key))
    return list(signature)
