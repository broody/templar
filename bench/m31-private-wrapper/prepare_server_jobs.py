"""Extract the measured representative batch from the frozen public Blake client proof."""
from pathlib import Path
import hashlib,json
from workload import inspect
HERE=Path(__file__).resolve().parent
BASE=HERE.parent/'m31-private-blake/results/native'
OUT=HERE/'results/server-circuit'
def main():
    _,unique,work=inspect(BASE/'public.json',BASE/'proof-1.bin')
    jobs=[]
    for kind,count in [('claims',1),('base',1),('small',16),('node',64)]:
        for job in [j for j in unique if j['kind']==kind][:count]:
            jobs.append({'message':list(job['message']),'digest':list(hashlib.blake2s(job['message']).digest())})
    OUT.mkdir(parents=True,exist_ok=True)
    encoded=json.dumps(jobs,separators=(',',':'))+'\n'
    path=OUT/'jobs.json'
    if path.exists(): assert path.read_text()==encoded,'preserved batch differs'
    else:path.write_text(encoded)
    report={'source_proof_sha256':hashlib.sha256((BASE/'proof-1.bin').read_bytes()).hexdigest(),'jobs_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'jobs':len(jobs),'bytes':sum(len(j['message']) for j in jobs),'compressions':sum(max(1,(len(j['message'])+63)//64) for j in jobs),'full_cached_workload':work}
    text=json.dumps(report,indent=2)+'\n'
    path=OUT/'input-manifest.json'
    if path.exists():assert path.read_text()==text,'preserved inventory differs'
    else:path.write_text(text)
if __name__=='__main__':main()
