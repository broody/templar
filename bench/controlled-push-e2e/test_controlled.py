import copy,hashlib,unittest
from dataclasses import replace
from protocol import *
from authorization import approve,private_to_stark_key,verify_message_signature
from encoding import encode_spend
CTRL,POLICY,DEST=0x987,0x456,0xb0b

def fixture(controlled=True,maximum=False):
    alice=Wallet.restore(hashlib.sha256(b'PUBLIC controlled fixture Alice').digest())
    bob=Wallet.restore(hashlib.sha256(b'PUBLIC controlled fixture Bob').digest())
    ctrl=CTRL if controlled else 0;policy=POLICY if controlled else 0
    ledger=Ledger();inputs=[]
    for i in range(4 if maximum else 1):
        n,e=send(alice.address,TOKEN,100,rho=10+i,controller=ctrl,policy=policy)
        idx=ledger.fund(n,e);inputs.append((n,alice.spend_key,idx))
    outputs=[send(bob.address,TOKEN,80 if maximum else 60,rho=20+i,controller=ctrl,policy=policy) for i in range(4 if maximum else 1)]
    wds=[(DEST,40),(DEST,40)] if maximum else [(DEST,40)]
    c=make_case(inputs,outputs,wds,ledger.tree,deadline=1000 if ctrl else 0,nonce=7 if ctrl else 0)
    validate_case(c)
    return alice,bob,ledger,inputs,outputs,c

def policy(c):
    r=c['transition_request']
    return {**{k:r[k] for k in ['chain','pool','token','controller']},'policy_id':POLICY,'withdrawal_recipient':DEST,'max_withdrawal':100}

class Controlled(unittest.TestCase):
    def setUp(self): self.a,self.b,self.l,self.ins,self.outs,self.c=fixture()
    def test_valid_controlled_statement_and_real_signature(self):
        sig=approve(self.c['transition_request'],policy(self.c),1234,current_block=1)
        self.assertTrue(verify_message_signature(signature_message(self.c['public'][6]),sig,private_to_stark_key(1234)))
    def test_ordinary_still_valid(self): validate_case(fixture(False)[-1])
    def test_maximum_shape(self): validate_case(fixture(maximum=True)[-1])
    def test_payer_cannot_spend_recipient_output(self):
        with self.assertRaisesRegex(ValueError,'not the owner'): self.outs[0][0].nullifier(self.a.spend_key,1)
    def test_controller_key_does_not_replace_owner(self):
        c=copy.deepcopy(self.c);c['witness'][13]=1234
        with self.assertRaisesRegex(ValueError,'membership'): validate_case(c)
    def test_viewer_key_does_not_replace_owner(self):
        c=copy.deepcopy(self.c);c['witness'][13]=self.a.full_view.nullifier_secret
        with self.assertRaisesRegex(ValueError,'membership'): validate_case(c)
    def test_controller_stripping_rejected(self):
        c=copy.deepcopy(self.c);c['witness'][6]=0;c['witness'][7:10]=[0,0,0]
        with self.assertRaisesRegex(ValueError,'controller mismatch'): validate_case(c)
    def test_output_controller_cannot_change(self):
        n,e=self.outs[0];n=replace(n,controller=CTRL+1)
        c=make_case(self.ins,[(n,e)],[(DEST,40)],self.l.tree,deadline=1000,nonce=7)
        with self.assertRaisesRegex(ValueError,'controller mismatch'): validate_case(c)
    def test_input_policy_cannot_change(self):
        c=copy.deepcopy(self.c);c['witness'][17]+=1
        with self.assertRaisesRegex(ValueError,'membership'): validate_case(c)
    def test_policy_rejects_output_policy_change(self):
        n,e=self.outs[0];n=replace(n,policy=POLICY+1)
        c=make_case(self.ins,[(n,e)],[(DEST,40)],self.l.tree,deadline=1000,nonce=7);validate_case(c)
        with self.assertRaisesRegex(ValueError,'policy commitment'): approve(c['transition_request'],policy(c),1234,current_block=1)
    def test_new_destination_new_proof_still_needs_new_approval(self):
        sig=approve(self.c['transition_request'],policy(self.c),1234,current_block=1)
        c=make_case(self.ins,self.outs,[(DEST+1,40)],self.l.tree,deadline=1000,nonce=7);validate_case(c)
        self.assertFalse(verify_message_signature(signature_message(c['public'][6]),sig,private_to_stark_key(1234)))
        with self.assertRaisesRegex(ValueError,'policy withdrawal'): approve(c['transition_request'],policy(c),1234,current_block=1)
    def test_each_authorized_field_changes_digest(self):
        original=self.c['transition_request'];digest=transition_hash(**original)
        for field in ['chain','pool','root','token','controller','deadline','nonce']:
            r=copy.deepcopy(original);r[field]+=1;self.assertNotEqual(digest,transition_hash(**r))
        for field,width in [('inputs',3),('outputs',4),('withdrawals',2)]:
            for pos in range(width):
                r=copy.deepcopy(original);r[field]=[list(x) for x in r[field]];r[field][0][pos]+=1
                self.assertNotEqual(digest,transition_hash(**r))
    def test_changed_transition_with_rebound_public_operation_fails_statement(self):
        c=copy.deepcopy(self.c);c['witness'][9]+=1
        c['witness'][5]=binding(CHAIN,POOL,c['public'][3],TOKEN,c['nullifiers'],c['outputs'],c['withdrawals'],CTRL,1000,7,c['witness'][9])
        with self.assertRaisesRegex(ValueError,'transition'): validate_case(c)
    def test_expired_policy_refuses_signing(self):
        with self.assertRaisesRegex(ValueError,'policy expiry'): approve(self.c['transition_request'],policy(self.c),1234,current_block=1001)
    def test_private_witness_not_in_controller_request(self):
        r=self.c['transition_request'];self.assertNotIn(self.a.spend_key,[v for v in r.values() if isinstance(v,int)])
        self.assertNotIn('witness',r);self.assertNotIn('receiver',r)
    def test_controlled_payload_and_view_recovery(self):
        n,e=self.outs[0];seen=self.b.view.receive(e)
        self.assertEqual((seen.controller,seen.policy,seen.amount),(CTRL,POLICY,60))
        self.l.apply(self.c,[e]);self.assertEqual(self.b.full_view.nullifier(n,1),n.nullifier(self.b.spend_key,1))
    def test_canonical_spend_abi_has_controller_and_signature(self):
        self.c['signature']=[1,2];data=encode_spend(self.c,[self.outs[0][1]])
        self.assertEqual(data[6:12],[CTRL,1000,7,self.c['public'][6],1,2])
if __name__=='__main__': unittest.main(verbosity=2)
