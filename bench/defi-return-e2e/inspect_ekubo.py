"""Read-only qualification of documented Ekubo Sepolia deployments and ABIs."""
from common import *

SOURCE='https://docs.ekubo.org/reference/contracts/starknet-sepolia/'
ADDRESSES={
 'core':'0x0444a09d96389aa7148f1aada508e30b71299ffe650d9c97fdaae38cb9a23384',
 'router':'0x0045f933adf0607292468ad1c1dedaa74d5ad166392590e72676a34d01d7b763',
 'positions':'0x06a2aee84bb0ed5dded4384ddd0e40e9c1372b818668375ab8e3ec08807417e5',
}
assert int(rpc('starknet_chainId',{}),16)==int.from_bytes(b'SN_SEPOLIA','big')
block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'});bid={'block_hash':block['block_hash']}
def read(pair):
 name,address=pair
 value=rpc('starknet_getClassAt',{'block_id':bid,'contract_address':address})
 abi=json.loads(value['abi']) if isinstance(value['abi'],str) else value['abi']
 save(RUN/(name+'-abi.json'),abi)
 klass=rpc('starknet_getClassHashAt',{'block_id':bid,'contract_address':address})
 return name,{'address':address,'class_hash':klass,'block_number':block['block_number'],'block_hash':block['block_hash'],'source':SOURCE}
with ThreadPoolExecutor(3) as executor:result=dict(executor.map(read,ADDRESSES.items()))
save(RUN/'ekubo.json',result)
print(json.dumps(result,indent=2))
