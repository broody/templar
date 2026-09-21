"""Compare the ordinary 4/4/2 shape against 2/2/1, using the same paid invoice."""
from pathlib import Path
import tomllib
from fixtures import toml
ROOT=Path(__file__).resolve().parent
src=ROOT/'statement-native';d=ROOT/'statement-native-wide';(d/'src').mkdir(parents=True,exist_ok=True)
(d/'Nargo.toml').write_text((src/'Nargo.toml').read_text())
s=(src/'src/main.nr').read_text().replace('ordinary 2/2/1','ordinary 4/4/2')
s=s.replace('inputs: [Input; 2]','inputs: [Input; 4]').replace('outputs: [Invoice; 2]','outputs: [Invoice; 4]')
s=s.replace('withdrawal: u128, recipient: Field','withdrawals: [u128; 2], recipients: [Field; 2]')
s=s.replace('n_in <= 2','n_in <= 4').replace('n_out <= 2','n_out <= 4')
s=s.replace('if withdrawal == 0 { assert(recipient == 0); } else { assert(recipient != 0); }', 'for k in 0..2 { if withdrawals[k] == 0 { assert(recipients[k] == 0); } else { assert(recipients[k] != 0); } }')
s=s.replace('let mut nullifiers = [0; 2]; let mut commitments = [0; 2];','let mut nullifiers = [0; 4]; let mut commitments = [0; 4];')
s=s.replace('let mut sum_out: Field = withdrawal as Field;','let mut sum_out: Field = withdrawals[0] as Field + withdrawals[1] as Field;')
s=s.replace('for i in 0..2 {','for i in 0..4 {')
s=s.replace('if n_in == 2 { assert(nullifiers[0] != nullifiers[1]); }','for i in 0..4 { for j in 0..4 { if i < j & j < n_in { assert(nullifiers[i] != nullifiers[j]); } } }')
s=s.replace('nullifiers[0],nullifiers[1],','nullifiers[0],nullifiers[1],nullifiers[2],nullifiers[3],')
s=s.replace('commitments[0],commitments[1],token,withdrawal as Field,recipient','commitments[0],commitments[1],commitments[2],commitments[3],token,withdrawals[0] as Field,recipients[0],withdrawals[1] as Field,recipients[1]')
(d/'src/main.nr').write_text(s)
p=tomllib.loads((src/'fixtures/alice-pay.toml').read_text())
p['withdrawals']=[p.pop('withdrawal'),'0'];p['recipients']=[p.pop('recipient'),'0']
p['inputs'] += [dict(salt='0',owner='0',amount='0',index=0,path=['0']*32) for _ in range(2)]
p['outputs'] += [dict(inner='0',amount='0') for _ in range(2)]
(d/'Prover.toml').write_text(toml(p))
