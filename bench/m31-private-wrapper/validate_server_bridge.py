"""Exact output binding and adversarial serialization checks for the server circuit bridge."""
from pathlib import Path
import hashlib,json,subprocess,sys,re
HERE=Path(__file__).resolve().parent
OUT=HERE/'results/server-circuit'
WORK=HERE.parent.parent/'target/m31-private-wrapper/server-cairo'
SCARB=Path('/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    data=json.loads((OUT/'proof/cairo-arguments.json').read_text())
    data=list(map(lambda x:int(x,16),data))
    # Span length; output array length; 16 QM31 outputs; nonce; 11 QM31 sums; PCS config.
    assert data[0]==len(data)-1 and data[1]==16
    config_at=2+16*4+1+11*4
    assert data[config_at:config_at+7]==[26,2,0,35,4,0,22]
    root_at=config_at+7+1
    assert data[root_at-1]==4
    cases=[('valid',data,True)]
    for name,index in [('output',2),('interaction-nonce',66),('config',config_at),('trusted-root',root_at),('trace-root',root_at+8)]:
        bad=data.copy();bad[index]^=1;cases.append((name,bad,False))
    cases += [('trailing',[data[0]+1,*data[1:],0],False),('truncated',[data[0]-1,*data[1:-1]],False)]
    expected=json.loads((OUT/'outer-input.json').read_text())['expected_bridge_output']
    report={'scope':'public hash circuit bridge, no membership or PROOF1 claim','expected':expected,'executable_sha256':sha(WORK/'target/dev/templar_server_hash_bridge.executable.json'),'cases':[]}
    for name,args,accept in cases:
        argfile=OUT/('cairo-'+name+'.json');argfile.write_text(json.dumps(list(map(hex,args))))
        command=[sys.executable,str(HERE/'measure_server.py'),'--name','cairo-'+name,'--cap-gib','8','--threads','4','--scope',report['scope'],'--',str(SCARB),'--json','--manifest-path',str(WORK/'Scarb.toml'),'execute','--no-build','-p','templar_server_hash_bridge','--arguments-file',str(argfile),'--print-program-output','--print-resource-usage','--output','none']
        result=subprocess.run(command,capture_output=True,text=True,timeout=610)
        folder=OUT/('cairo-'+name);log=(folder/'stdout.log').read_text();resource=json.loads((folder/'summary.json').read_text())
        executions=[json.loads(line) for line in log.splitlines() if line.startswith('{') and '"program_output"' in line]
        values=list(map(int,executions[-1]['program_output'].split())) if executions else None
        panicked=('panicked' in log.lower() or 'panick' in log.lower())
        passed=(result.returncode==0 and values==expected) if accept else (result.returncode!=0 and panicked and resource['sampled_oom_kill']==0)
        row={'name':name,'passed':passed,'expected_accept':accept,'exit_code':result.returncode,'program_rejection':panicked,'output_matches':values==expected,'resources':executions[-1]['resources'] if executions else None,'peak_rss_gib':resource['time_peak_rss_gib'],'elapsed_seconds':resource['elapsed_seconds'],'arguments_sha256':sha(argfile)}
        report['cases'].append(row);(OUT/'cairo-validation.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(row),flush=True)
        assert passed,log[-4000:]
if __name__=='__main__':main()
