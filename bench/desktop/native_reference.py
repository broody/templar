"""BN254 Poseidon2 reference matching the pinned bb permutation (not Starknet Poseidon).
Parameters are extracted from the vendored upstream header; no new constants are chosen.
"""
from pathlib import Path
import re
P=21888242871839275222246405745257275088548364400416034343698204186575808495617
HEADER=(Path(__file__).parent/'vendor/poseidon2_params.hpp').read_text()
def constants(section,end):
    return [int(x,16) for x in re.findall(r'0x[0-9a-f]+',HEADER.split(section,1)[1].split(end,1)[0])]
DIAG=constants('internal_matrix_diagonal = {','};')
RC=constants('round_constants{','};')
assert len(DIAG)==4 and len(RC)==256
M=[[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]
def external(s):return [sum(a*b for a,b in zip(row,s))%P for row in M]
def perm(s):
    s=external(s)
    for r in range(64):
        if r<4 or r>=60:
            s=external([pow((x+RC[4*r+i])%P,5,P) for i,x in enumerate(s)])
        else:
            s[0]=pow((s[0]+RC[4*r])%P,5,P)
            total=sum(s)%P
            s=[(total+x*d)%P for x,d in zip(s,DIAG)]
    return s

def h(values):
    assert all(0<=x<P for x in values)
    s=[0,0,0,len(values)<<64]
    for off in range(0,max(1,len(values)),3):
        for j,x in enumerate(values[off:off+3]):s[j]=(s[j]+x)%P
        s=perm(s)
    return s[0]

def pair(a,b):return h([a,b])
if __name__=='__main__':print(hex(pair(1,2)))
