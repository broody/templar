// Experimental ordinary 4/4/2 statement; not a production format.
fn hash<let N: u32>(values: [Field; N]) -> Field {
    let mut s = [0, 0, 0, N as Field * 18446744073709551616];
    for block in 0..((N + 2) / 3) {
        for j in 0..3 {
            let i = block * 3 + j;
            if i < N { s[j] = s[j] + values[i]; }
        }
        s = std::hash::poseidon2_permutation(s, 4);
    }
    s[0]
}
global VERSION: Field = 112014988236564148666166936915858640945;
global BIND: Field = 1710723966219209225703245517313586;
global NF: Field = 104122676411346503581809280092728874547;
global CM: Field = 22904328969783278087854131930810541561395;
global NI: Field = 26647471191471950591998022714362800264755;
global NS: Field = 6821752625017608834574514217474175520101939;

struct Input { salt: u128, owner: Field, amount: u128, index: u32, path: [Field; 32] }
struct Invoice { inner: Field, amount: u128 }
fn main(chain: Field, pool: Field, root: Field, token: Field,
        n_in: u32, inputs: [Input; 4], n_out: u32, outputs: [Invoice; 4],
        withdrawals: [u128; 2], recipients: [Field; 2]) -> pub [Field; 8] {
    assert(n_in > 0 & n_in <= 4); assert(n_out <= 4); assert(token != 0);
    for k in 0..2 { if withdrawals[k] == 0 { assert(recipients[k] == 0); } else { assert(recipients[k] != 0); } }
    let mut nullifiers = [0; 4]; let mut commitments = [0; 4];
    let mut sum_in: Field = 0; let mut sum_out: Field = withdrawals[0] as Field + withdrawals[1] as Field;
    for i in 0..4 {
        if i < n_in {
            let note = inputs[i]; assert(note.amount > 0);
            let secret = hash([NS, note.salt as Field, note.owner]);
            let inner = hash([NI, secret]);
            let mut node = hash([CM, token, note.amount as Field, 0, 0, inner]);
            for level in 0..32 {
                let right = ((note.index >> level) & 1) == 1;
                let left = if right { note.path[level] } else { node };
                let r = if right { node } else { note.path[level] };
                node = hash([left,r]);
            }
            assert(node == root);
            nullifiers[i] = hash([NF,secret]); assert(nullifiers[i] != 0);
            sum_in = sum_in + note.amount as Field;
        }
        if i < n_out {
            let invoice = outputs[i]; assert(invoice.inner != 0); assert(invoice.amount > 0);
            commitments[i] = hash([CM,token,invoice.amount as Field,0,0,invoice.inner]);
            assert(commitments[i] != 0);
            sum_out = sum_out + invoice.amount as Field;
        }
    }
    for i in 0..4 { for j in 0..4 { if i < j & j < n_in { assert(nullifiers[i] != nullifiers[j]); } } }
    assert(sum_in == sum_out);
    let binding = hash([BIND, VERSION,chain,pool,root,n_in as Field,nullifiers[0],nullifiers[1],nullifiers[2],nullifiers[3],
                        n_out as Field,commitments[0],commitments[1],commitments[2],commitments[3],token,withdrawals[0] as Field,recipients[0],withdrawals[1] as Field,recipients[1]]);
    [VERSION,chain,pool,root,0,0,0,binding]
}
