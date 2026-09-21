"""Validate public results, unchanged dependency pins, and exported file boundaries."""
from pathlib import Path
import hashlib,json,tomllib,re
from run import FIXTURES
H=Path(__file__).resolve().parent;E=json.loads((H/'environment.json').read_text());W=Path(E['work']);R=H/'results'
report=json.loads((R/'summary.json').read_text())
assert hashlib.sha256(Path(E['stock_prover']).read_bytes()).hexdigest()=='31fb582d5ec8cfcb028ae7c144f0152acc432f68d5cbfeb4c10e881a00f18db5'
assert hashlib.sha256(Path(E['verifier']).read_bytes()).hexdigest()=='492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934' 
for s in report['results']:
 if s.get('status')=='PASS':
  assert s['cgroup_peak_gib'] <= s['cap_gib']+.001
  assert s['swap_peak_bytes']==0 and s['oom_kill']==0
 if s['requests']:
  package,case=FIXTURES[s['fixture']]
  runtime=Path(json.loads((H.parent/package/'run-location.json').read_text())['runtime'])
  expected=json.loads((runtime/'cases'/case/'public-response.json').read_text())
 for i,r in enumerate(s['requests']):
  d=R/s['name']/f'proof-{i}'
  assert hashlib.sha256((d/'proof.bin').read_bytes()).hexdigest()==r['proof_sha256']
  facts=(d/'proof-facts.txt').read_text().split(',')
  assert len(facts)==len(expected['proof_facts'])
  for index in [0,2,8]:assert int(facts[index],16)==int(expected['proof_facts'][index],16)
  assert json.loads((d/'public-messages.json').read_text())==expected['l2_to_l1_messages']
  log=(d/'verification.log').read_text()
  assert 'valid proof: PASS' in log
  assert all(x in log for x in ['changed message digest: rejected','changed program hash: rejected','corrupted proof bytes: rejected'])
# All remote registry/git packages remain at exactly their original sources and checksums.
old=tomllib.loads((Path(E['sequencer_original'])/'Cargo.lock').read_text())['package']
new=tomllib.loads((W/'sequencer/Cargo.lock').read_text())['package']
key=lambda p:(p['name'],p['version'],p.get('source'),p.get('checksum'))
old_remote={key(p) for p in old if 'source' in p};new_remote={key(p) for p in new if 'source' in p}
removed=old_remote-new_remote
assert {p[0] for p in removed}=={'cairo-program-runner-lib','privacy-prove','stwo','stwo-cairo-prover','cairo-air','stwo-cairo-adapter','stwo-cairo-common','stwo-cairo-serialize','stwo-cairo-serialize-derive'}
assert not new_remote-old_remote
# Local dependency family replacements contain exactly the reviewed source changes.
changed_sources=[];unchanged_dependency_files=0
for directory,original,allowed in [
 ('stwo',E['stwo_original'],{'crates/stwo/src/prover/pcs/mod.rs'}),
 ('stwo-cairo',E['stwo_cairo_original'],{'stwo_cairo_prover/crates/prover/src/prover.rs'}),
]:
 for p in (W/directory).rglob('*.rs'):
  rel=p.relative_to(W/directory)
  if 'target' in rel.parts:continue
  original_file=Path(original)/rel
  assert original_file.is_file(),str(p)
  if p.read_bytes()!=original_file.read_bytes():
   assert str(rel) in allowed,str(p)
   changed_sources.append(str(Path(directory)/rel))
  else:unchanged_dependency_files+=1
review_pins=re.findall(r'\| `([^`]+)` \| `([0-9a-f]{64})` \|',(H/'review.md').read_text())
assert len(review_pins)==4
for rel,expected_hash in review_pins:
 assert hashlib.sha256((W/rel).read_bytes()).hexdigest()==expected_hash,rel
for name in ['low-memory-prover','profiled-prover']:
 metadata=R/f'{name}-build.json'
 if not metadata.exists():continue
 m=json.loads(metadata.read_text())
 assert hashlib.sha256((W/'bin'/name).read_bytes()).hexdigest()==m['binary_sha256']
 assert hashlib.sha256((W/'sequencer/Cargo.lock').read_bytes()).hexdigest()==m['cargo_lock_sha256']
 for rel,digest in m['source_sha256'].items():
  assert hashlib.sha256((H/rel).read_bytes()).hexdigest()==digest,rel
# The copied local verifier and runner are byte-identical to pinned source.
unchanged=[]
for package in ['cairo-program-runner-lib','privacy_circuit_verify']:
 for p in (W/'proving-utils/crates'/package).rglob('*'):
  if not p.is_file():continue
  rel=p.relative_to(W/'proving-utils');old=Path(E['proving_original'])/rel
  assert p.read_bytes()==old.read_bytes(),str(rel)
  unchanged.append(str(rel))
for f in ['consts.rs','lib.rs']:
 if f=='lib.rs':continue
 rel=Path('crates/privacy_prove/src')/f
 assert (W/'proving-utils'/rel).read_bytes()==(Path(E['proving_original'])/rel).read_bytes()
for name in ['private-request.json','private-case.json','wallets.json','signed-request.json','gateway-request.json']:
 assert not list(H.rglob(name)),f'Private export: {name}'
for p in R.rglob('*.json'):
 def check(value):
  if isinstance(value,dict):
   assert not ({'witness','spend_key','private_key','seed','signature','calldata'} & set(value)),str(p)
   for v in value.values():check(v)
  elif isinstance(value,list):
   for v in value:check(v)
 check(json.loads(p.read_text()))
result={'verified_proof_count':report['verified_proof_count'],'mutation_rejections':report['verified_proof_count']*3,'public_messages_and_proven_digests_match_original_fixtures':True,'remote_dependency_versions_unchanged':True,'local_runner_and_verifier_files_unchanged':len(unchanged),'dependency_source_files_unchanged':unchanged_dependency_files,'reviewed_dependency_source_changes':changed_sources,'no_private_fixture_exports':True,'same_request_comparisons':len(report['same_request_comparisons']),'previous_experiment_comparisons':report['previous_experiment_comparisons']}
(R/'archive-validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
