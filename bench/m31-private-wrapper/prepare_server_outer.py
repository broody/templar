"""Independently calculate exact batch bindings and outer expected facts from public jobs.

No expected binding is taken from a proof-supplied claim.
"""
from pathlib import Path
import hashlib,json,struct
HERE=Path(__file__).resolve().parent
OUT=HERE/'results/server-circuit'
def words(b): return list(struct.unpack('<'+'I'*(len(b)//4),b))
def pack(ws): return b''.join(struct.pack('<I',w) for w in ws)
def main():
    jobs=json.loads((OUT/'jobs.json').read_text()); inputs=[]; outputs=[]
    for j in jobs:
        msg=bytes(j['message']); digest=hashlib.blake2s(msg).digest()
        assert digest==bytes(j['digest'])
        inputs += [len(msg),*words(msg+bytes((-len(msg))%4))]; outputs+=words(digest)
    binding=words(hashlib.blake2s(pack(inputs)).digest())+words(hashlib.blake2s(pack(outputs)).digest())
    qm31_words=[coord for word in binding for coord in [word&65535,word>>16,0,0]]
    config=json.loads((OUT/'proof/trusted-config.json').read_text())
    final=hashlib.blake2s(pack(config['preprocessed_root_u32_le']+qm31_words)).digest()
    values=[int.from_bytes(b'SERVER_HASH_CIRCUIT_V1','big'),int.from_bytes(b'SN_SEPOLIA','big'),0,*struct.unpack('<4Q',final),0]
    args=json.loads((OUT/'proof/cairo-arguments.json').read_text())
    (OUT/'outer-input.json').write_text(json.dumps({'scope':'server hash circuit only; not membership','public_values':list(map(hex,values)),'calldata':args,'expected_bridge_output':words(final)},indent=2)+'\n')
if __name__=='__main__':main()
