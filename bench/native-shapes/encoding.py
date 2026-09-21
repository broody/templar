"""Canonical public ciphertext and ordinary-pool ABI encoding."""
from protocol import Event, felt

def chunks(data):
    if not isinstance(data,bytes) or len(data)!=304: raise ValueError('ciphertext length')
    return [int.from_bytes(data[i:i+31],'big') for i in range(0,304,31)]

def unchunks(words):
    if len(words)!=10: raise ValueError('ciphertext word count')
    result=[]
    for i,word in enumerate(words):
        size=25 if i==9 else 31
        if type(word) is not int or not 0<=word<2**(8*size): raise ValueError('noncanonical ciphertext word')
        result.append(word.to_bytes(size,'big'))
    return b''.join(result)

def parse_publication(data):
    if len(data)!=14 or data[3]!=10: raise ValueError('publication encoding')
    index,cm,digest=data[:3]
    if type(index) is not int or not 0<=index<2**32: raise ValueError('leaf index')
    return Event(felt(cm,True),unchunks(data[4:]),felt(digest,True),index)

def encode_spend(case,events):
    p=case['public']
    data=[p[0],p[1],p[2],p[3],case['witness'][4],p[7],p[4],p[5],case['nonce'],p[6],*case['signature'],len(case['nullifiers']),*case['nullifiers'],len(events)]
    for event in events: data.extend([event.commitment,10,*chunks(event.ciphertext)])
    data.append(len(case['withdrawals']))
    for recipient,amount in case['withdrawals']: data.extend([recipient,amount])
    return data+[0]  # Proof bytes belong to the transaction, never contract calldata.

def encode_deposit(note,event):
    assert note.commitment==event.commitment
    return [note.token,note.amount,note.controller,note.policy,note.inner,10,*chunks(event.ciphertext)]
