"""Fresh-process wallet recovery; requires only backup and public deployment metadata."""
import argparse
from dataclasses import asdict
from common import *
from protocol import Wallet,FullView,Address,CHAIN
from sync import canonical_checkpoint

p=argparse.ArgumentParser()
group=p.add_mutually_exclusive_group(required=True)
group.add_argument('--seed-file',type=Path);group.add_argument('--view-file',type=Path)
p.add_argument('--address-file',required=True,type=Path);p.add_argument('--label',required=True)
p.add_argument('--minimum-block',type=int,default=0)
args=p.parse_args()
deploy=json.loads((RUN/'deployment.json').read_text())
a=json.loads(args.address_file.read_text());expected=Address(a['chain'],a['pool'],a['receiver'],bytes.fromhex(a['encryption_key']))
if args.seed_file:
    wallet=Wallet.restore(bytes.fromhex(args.seed_file.read_text().strip()),CHAIN,int(deploy['pool'],16))
    assert wallet.address==expected
    view=wallet.full_view
else:
    view=FullView.load(json.loads(args.view_file.read_text()),expected_address=expected)
report,archive,checkpoint,metadata=canonical_checkpoint(deploy,view,minimum_block=args.minimum_block)
dest=RUN/'wallets'/args.label
save(dest/'private-recovered.json',{'notes':{str(i):asdict(n) for i,n in report.notes.items()},
     'spent_indices':report.spent_indices,'commitments':[r.commitment for r in checkpoint.receipts]})
save(dest/'summary.json',report.summary())
save(dest/'sync.json',metadata)
print(json.dumps({'label':args.label,'summary':report.summary(),'sync_seconds':metadata['seconds']}),flush=True)
