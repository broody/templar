"""Sequential release qualification matrix used in this experiment.

Run once only: each case refuses to overwrite an existing measurement folder.
Expected OOM results are retained and do not prevent the remaining cases.
"""
from pathlib import Path
import subprocess
H=Path(__file__).resolve().parent
cases=[
 ('ordinary-keep-trees','ordinary',15391165,12,1,['--keep-cairo-trees']),
 ('ordinary-repeat-10','ordinary',15391165,10,3,[]),
 ('controlled-repeat-10','controlled',15391278,10,3,[]),
 ('8-8-4-repeat-10','8-8-4',15391320,10,3,[]),
 ('return-repeat-10','return',15391363,10,3,[]),
 ('invalid-intent','invalid-intent',15391363,10,1,[]),
 ('8-8-4-repeat-11','8-8-4',15391320,11,3,['--trace-spans']),
 ('8-8-4-repeat-11-release','8-8-4',15391320,11,3,[]),
 ('ordinary-recompute-release','ordinary',15391165,12,1,[]),
]
for name,fixture,block,cap,requests,extra in cases:
 command=['python3',str(H/'run.py'),'--variant','staged-release','--fixture',fixture,
          '--cap',str(cap),'--requests',str(requests),'--block',str(block),'--name',name]+extra
 with (H/'results'/f'{name}-driver.log').open('x') as output:
  result=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT)
 print(name, 'driver exit',result.returncode,flush=True)
