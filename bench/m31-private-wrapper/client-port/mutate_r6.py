"""The R0 V6 mutation table (`docs/pool-v3-spec.md` §4.4, re-check F7).

Re-runs the P2 table (`docs/reviews/account-bound-p2-math-review.md`, the F09 and AB-IM1 rows)
against `payment6.rs`, without the mode and account rows, plus V6's rows: a guessed `ak` copy, a
guessed `nk` copy into OWNER and into NF, AUTH and NK over guessed `sk` copies, the mirror's
`R0C6` tag check deleted, and one guessed-copy row per fan-out wire of the wiring test. Each mutant
is applied to a sibling copy of the crate (`../.mut-r6`, same relative paths, its own target
directory); both V6 suites run with the `tamper` feature and `--no-fail-fast`; the F38 pinned-hash
test is skipped (it does not count as a kill). Each row records the tests that killed it, or
`equivalent` with the argument, or that it built nothing. Every guessed-copy row (`copy:` and
`guessed`) must be killed by `wiring_uses_the_same_variables` itself; the run fails otherwise.

    python3 mutate_r6.py [OUT_JSON]   # default results/stwo-client-r6/mutants.json
"""
import json, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COPY = HERE.parent / '.mut-r6'
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'results/stwo-client-r6/mutants.json'
P6 = 'src/payment6.rs'

# A guessed copy: new variables with the same values, as a cheating prover would guess them.
COPY_HELPER = '''
#[allow(dead_code)]
fn copy_vars<V: IValue>(c: &mut Context<V>, vars: &[Var]) -> Vec<Var> {
    vars.iter().map(|v| { let x = c.get(*v).m31_to_u32().unpack_u32(); guess_m31(c, x) }).collect()
}
'''

OWNERS = '    let owners = hashes(c, "owners", vec![\n'
NOTES = '    let cms = hashes(c, "notes", vec![\n'
INNER_IN = '    let inner_in = hashes(c, "inner_in", vec![\n'
INNER_OUT = '    let b = hashes(c, "inner_out", vec![\n'
KEYS = '    let keys = hashes(c, "keys", vec![(AUTH, 0, sk[0].clone()), (NK, 0, sk[0].clone()), (AUTH, 0, sk[1].clone()), (NK, 0, sk[1].clone())]);'
SPLIT = '    let (ak0, nk0, ak1, nk1) = (keys[0].clone(), keys[1].clone(), keys[2].clone(), keys[3].clone());'
LEVEL_REQ = '            reqs.push(level_request(c, p, level, &cur[p], &sib, bits[p][level]));'
LEVEL_HASH = '        let next = level_hash(c, tree, level, reqs);'
PUBLISHED = '    publish(c, [tag, pub_ctx, token_out, cur[0].clone(), nfs, outs, recipient, withdrawn, intent, identity, valid_until].concat())'
TAG = '    let tag: Vec<Var> = statement_tag(tree).iter().map(|v| c.constant(M31::from(*v).into())).collect();'
CONSERVATION = '    conserve(\n        c,\n        [&amt0, &amt1],\n        [&amt_out[0], &amt_out[1], &withdrawn],'


# Survivors argued equivalent (the accepted set of statements is unchanged), recorded as such.
EQUIVALENT = {
    'e1 booleanity deleted': 'With e1 outside {0, 1}: sum1*(1 - e1) = 0 forces sum1 = 0, so amount1 = 0 (its limbs are '
                             'range-checked), and e1*(b - a) = 0 with e1 != 0 forces input 1 onto the published root. That '
                             'is an enabled zero-value input, which e1 = 1 already admits; e1 is not published. The accepted '
                             'set is unchanged (V5 has the same gadget and no booleanity test either).',
}


def unguarded(var, name, values, indent=4):
    pad = ' ' * indent
    return f'{pad}let {var} = guess_words(c, {values});\n{pad}record(c, {name}, &{var});'


def before(anchor, line):
    return (anchor, line + '\n' + anchor)


MUTANTS = [
    # ---- The P2 table's relation rows, without mode and account.
    ('identity over sk0 (V4 handle)', P6, [('(IDENTITY, 0, [ak0, scope].concat()),', '(IDENTITY, 0, [sk[0].clone(), scope].concat()),')]),
    ('idle sum1*(1-e1) deleted', P6, [('    let idle = eval!(c, (sum1) * ((1) - (e1)));\n    assert_zero(c, idle);', '    let idle = eval!(c, (sum1) * ((1) - (e1)));\n    c.mark_as_maybe_unused(&idle);')]),
    ('(1-x)*withdrawn deleted', P6, [('    for l in withdrawn.iter().chain(intent) {', '    for l in intent.iter() {')]),
    ('(1-x)*intent deleted', P6, [('    for l in withdrawn.iter().chain(intent) {', '    for l in withdrawn.iter() {')]),
    ('identity-flag booleanity deleted', P6, [('    let id_active = guess_bits_rec(c, "guess.identity_flag", &[t.identity_flag.unwrap_or(w.identity.active as u32)])[0];',
                                                '    let id_active = guess_m31(c, t.identity_flag.unwrap_or(w.identity.active as u32));\n    record(c, "guess.identity_flag", &[id_active]);')]),
    ('e1 booleanity deleted', P6, [('    let e1 = bit_rec(c, "guess.e1", t.e1.unwrap_or(!w.dummy as u32));',
                                    '    let e1 = guess_m31(c, t.e1.unwrap_or(!w.dummy as u32));\n    record(c, "guess.e1", &[e1]);')]),
    ('x booleanity deleted', P6, [('    let x = bit_rec(c, "guess.x", t.x.unwrap_or(exit as u32));',
                                   '    let x = guess_m31(c, t.x.unwrap_or(exit as u32));\n    record(c, "guess.x", &[x]);')]),
    ('enabled input 1 root gap deleted', P6, [('        let gap = eval!(c, (e1) * ((b) - (a)));\n        assert_zero(c, gap);', '        let gap = eval!(c, (e1) * ((b) - (a)));\n        c.mark_as_maybe_unused(&gap);')]),
    ('input 0 amount nonzero deleted', P6, [('    let limbs = amount(c, value);', '    let limbs = amount_from_bits(c, &amount_bits(value)).0;')]),
    # A guard-less guess with the same record, one guard at a time.
    ('token nonzero deleted', P6, [('    let token = guess_nonzero(c, "guess.token", &token_values);', unguarded('token', '"guess.token"', '&token_values'))]),
    ('output receiver nonzero deleted', P6, [('        let r = guess_nonzero(c, &format!("guess.recv_out{j}"), &o.receiver);', unguarded('r', '&format!("guess.recv_out{j}")', '&o.receiver', 8))]),
    ('output rho nonzero deleted', P6, [('        let q = guess_nonzero(c, &format!("guess.rho_out{j}"), &o.rho);', unguarded('q', '&format!("guess.rho_out{j}")', '&o.rho', 8))]),
    ('input sk nonzero deleted', P6, [('        let s = guess_nonzero(c, &format!("guess.sk{k}"), &i.sk);', unguarded('s', '&format!("guess.sk{k}")', '&i.sk', 8))]),
    ('input rho nonzero deleted', P6, [('        let r = guess_nonzero(c, &format!("guess.rho{k}"), &i.rho);', unguarded('r', '&format!("guess.rho{k}")', '&i.rho', 8))]),
    ('shared carry range deleted (payment.rs)', 'src/payment.rs', [('            let t = eval!(c, (((n) * ((n) - (1))) * ((n) + (1))) * ((n) + (2)));\n            let zero = c.zero();\n            eq(c, t, zero);',
                                                                   '            let t = eval!(c, (((n) * ((n) - (1))) * ((n) + (1))) * ((n) + (2)));\n            c.mark_as_maybe_unused(&t);')]),
    ('shared guess_bits booleanity deleted (merkle.rs)', 'src/merkle.rs', [('            let boolean = eval!(ctx, (b) * ((b) - (1)));\n            eq(ctx, boolean, zero);',
                                                                            '            let boolean = eval!(ctx, (b) * ((b) - (1)));\n            let _ = zero;\n            ctx.mark_as_maybe_unused(&boolean);')]),
    # ---- The bridge mirror.
    ('mirror: amount-limb range deleted', P6, [('    if x[101..109].iter().any(|l| *l >= 1 << 16) {', '    if false {')]),
    ('mirror: valid_until limb range deleted', P6, [('    if x[VALID_UNTIL_AT..VALID_UNTIL_AT + 2].iter().any(|l| *l >= 1 << 28) {', '    if false {')]),
    ('mirror: padding deleted', P6, [('    if x[N_LIMBS..4 * N_OUTPUTS].iter().any(|l| *l != 0) {', '    if false {')]),
    ('mirror: valid_until != 0 deleted', P6, [('    if p.valid_until == 0 {', '    if false {')]),
    ('mirror: R0C6 tag check deleted', P6, [('    if x[..2] != statement_tag(tree) {', '    if false {')]),
    ('mirror: valid_until at V5 offset (136)', P6, [('pub const VALID_UNTIL_AT: usize = 127;', 'pub const VALID_UNTIL_AT: usize = 125;')]),
    # ---- V6 rows: key derivation.
    ('guessed ak copy (all consumers)', P6, [(SPLIT, '    let (ak0, nk0, ak1, nk1) = (copy_vars(c, &keys[0]), keys[1].clone(), keys[2].clone(), keys[3].clone());')]),
    ('guessed ak1 copy', P6, [(SPLIT, '    let (ak0, nk0, ak1, nk1) = (keys[0].clone(), keys[1].clone(), copy_vars(c, &keys[2]), keys[3].clone());')]),
    ('guessed ak copy into IDENTITY only (MR-V6-1)', P6, [before(OWNERS, '    let ak0_id = copy_vars(c, &ak0);'), ('(IDENTITY, 0, [ak0, scope].concat()),', '(IDENTITY, 0, [ak0_id, scope].concat()),')]),
    ('guessed ak copy into OWNER0 only', P6, [before(OWNERS, '    let ak0_ow = copy_vars(c, &ak0);'), ('(OWNER, 0, [ak0.clone(), nk0.clone()].concat()),', '(OWNER, 0, [ak0_ow, nk0.clone()].concat()),')]),
    ('guessed nk copy into OWNER0', P6, [before(OWNERS, '    let nk0_ow = copy_vars(c, &nk0);'), ('(OWNER, 0, [ak0.clone(), nk0.clone()].concat()),', '(OWNER, 0, [ak0.clone(), nk0_ow].concat()),')]),
    ('guessed nk copy into OWNER1', P6, [before(OWNERS, '    let nk1_ow = copy_vars(c, &nk1);'), ('(OWNER, 0, [ak1, nk1.clone()].concat()),', '(OWNER, 0, [ak1, nk1_ow].concat()),')]),
    ('guessed nk copy into NF0', P6, [('    for (p, nk) in [nk0, nk1].into_iter().enumerate() {', '    let nk0 = copy_vars(c, &nk0);\n    for (p, nk) in [nk0, nk1].into_iter().enumerate() {')]),
    ('guessed nk copy into NF1', P6, [('    for (p, nk) in [nk0, nk1].into_iter().enumerate() {', '    let nk1 = copy_vars(c, &nk1);\n    for (p, nk) in [nk0, nk1].into_iter().enumerate() {')]),
    ('guessed sk0 copy into AUTH0', P6, [(KEYS, '    let sk0c = copy_vars(c, &sk[0]);\n' + KEYS.replace('(AUTH, 0, sk[0].clone())', '(AUTH, 0, sk0c)'))]),
    ('guessed sk0 copy into NK0', P6, [(KEYS, '    let sk0c = copy_vars(c, &sk[0]);\n' + KEYS.replace('(NK, 0, sk[0].clone())', '(NK, 0, sk0c)'))]),
    ('guessed sk1 copy into AUTH1', P6, [(KEYS, '    let sk1c = copy_vars(c, &sk[1]);\n' + KEYS.replace('(AUTH, 0, sk[1].clone())', '(AUTH, 0, sk1c)'))]),
    # ---- V6 rows: one guessed copy per fan-out wire of the wiring test.
    ('copy: owner0 out into INNER0', P6, [before(INNER_IN, '    let o0 = copy_vars(c, &owners[0]);'), ('(INNER, 0, [owners[0].clone(), rho[0].clone()].concat()),', '(INNER, 0, [o0, rho[0].clone()].concat()),')]),
    ('copy: rho0 into INNER0', P6, [before(INNER_IN, '    let r0 = copy_vars(c, &rho[0]);'), ('(INNER, 0, [owners[0].clone(), rho[0].clone()].concat()),', '(INNER, 0, [owners[0].clone(), r0].concat()),')]),
    ('copy: recv_out0 into INNER_out0', P6, [before(INNER_OUT, '    let ro0 = copy_vars(c, &recv_out[0]);'), ('(INNER, 0, [recv_out[0].clone(), rho_out[0].clone()].concat()),', '(INNER, 0, [ro0, rho_out[0].clone()].concat()),')]),
    ('copy: inner0 out into NOTE0', P6, [before(NOTES, '    let i0 = copy_vars(c, &inner_in[0]);'), ('        note(&context, &amt0, &inner_in[0]),', '        note(&context, &amt0, &i0),')]),
    ('copy: inner_out0 into NOTE2', P6, [before(NOTES, '    let io0 = copy_vars(c, &b[0]);'), ('        note(&context, &amt_out[0], &b[0]),', '        note(&context, &amt_out[0], &io0),')]),
    ('copy: amount in0 into NOTE0', P6, [before(NOTES, '    let a0 = copy_vars(c, &amt0);'), ('        note(&context, &amt0, &inner_in[0]),', '        note(&context, &a0, &inner_in[0]),')]),
    ('copy: amount out0 into NOTE2', P6, [before(NOTES, '    let ao0 = copy_vars(c, &amt_out[0]);'), ('        note(&context, &amt_out[0], &b[0]),', '        note(&context, &ao0, &b[0]),')]),
    ('copy: token into NOTE1 context', P6, [before(NOTES, '    let ctx1 = [pub_ctx.clone(), copy_vars(c, &token)].concat();'), ('        note(&context, &amt1, &inner_in[1]),', '        note(&ctx1, &amt1, &inner_in[1]),')]),
    ('copy: pub_ctx into NOTE3 context', P6, [before(NOTES, '    let ctx3 = [copy_vars(c, &pub_ctx), token.clone()].concat();'), ('        note(&context, &amt_out[1], &b[1]),', '        note(&ctx3, &amt_out[1], &b[1]),')]),
    ('copy: note0 out into the path leaf', P6, [('    let mut cur = [cms[0].clone(), cms[1].clone()];', '    let mut cur = [copy_vars(c, &cms[0]), cms[1].clone()];')]),
    ('copy: note1 out into the path leaf', P6, [('    let mut cur = [cms[0].clone(), cms[1].clone()];', '    let mut cur = [cms[0].clone(), copy_vars(c, &cms[1])];')]),
    ('copy: note out into NF cm', P6, [('        nf_reqs.push((NF, 0, [nk, cms[p].clone(), vec![lo, hi]].concat()));', '        let cmc = copy_vars(c, &cms[p]);\n        nf_reqs.push((NF, 0, [nk, cmc, vec![lo, hi]].concat()));')]),
    ('copy: pack lo into NF', P6, [('        let lo = pack(c, &format!("pack{p}.lo"), &bits[p][..16]);', '        let lo = pack(c, &format!("pack{p}.lo"), &bits[p][..16]);\n        let lo = copy_vars(c, &[lo])[0];')]),
    ('copy: position bits into pack', P6, [('        let lo = pack(c, &format!("pack{p}.lo"), &bits[p][..16]);', '        let bc = copy_vars(c, &bits[p]);\n        let lo = pack(c, &format!("pack{p}.lo"), &bc[..16]);')]),
    ('copy: position bit into the path', P6, [(LEVEL_REQ, '            let bc = copy_vars(c, &[bits[p][level]])[0];\n' + LEVEL_REQ.replace('bits[p][level]));', 'bc));'))]),
    ('copy: withdrawn into conservation', P6, [(CONSERVATION, '    let wc = copy_vars(c, &withdrawn);\n' + CONSERVATION.replace('&withdrawn],', '&wc],'))]),
    ('copy: amounts into conservation', P6, [(CONSERVATION, '    let a1c = copy_vars(c, &amt1);\n' + CONSERVATION.replace('[&amt0, &amt1],', '[&amt0, &a1c],'))]),
    ('copy: withdrawn into the x gate', P6, [('    exits(c, x, &withdrawn, &intent);', '    let wc = copy_vars(c, &withdrawn);\n    exits(c, x, &wc, &intent);')]),
    ('copy: withdrawn into the published limbs', P6, [(PUBLISHED, '    let wc = copy_vars(c, &withdrawn);\n' + PUBLISHED.replace('recipient, withdrawn, intent', 'recipient, wc, intent'))]),
    ('copy: token into token_out', P6, [('    let token_out = reveal(c, &token, x);', '    let tc = copy_vars(c, &token);\n    let token_out = reveal(c, &tc, x);')]),
    ('copy: pub_ctx into the published limbs', P6, [(PUBLISHED, '    let pcc = copy_vars(c, &pub_ctx);\n' + PUBLISHED.replace('[tag, pub_ctx, token_out,', '[tag, pcc, token_out,'))]),
    ('copy: root into the published limbs', P6, [(PUBLISHED, '    let rc = copy_vars(c, &cur[0]);\n' + PUBLISHED.replace('cur[0].clone(), nfs,', 'rc, nfs,'))]),
    ('copy: nf into the published limbs', P6, [(PUBLISHED, '    let nfc = copy_vars(c, &nfs);\n' + PUBLISHED.replace('cur[0].clone(), nfs,', 'cur[0].clone(), nfc,'))]),
    ('copy: cm into the published limbs', P6, [('        outs.extend(cms[2 + j].clone());', '        outs.extend(copy_vars(c, &cms[2 + j]));')]),
    ('copy: identity handle into the published limbs', P6, [('    let identity = mask(c, &owners[2], id_active);', '    let hc = copy_vars(c, &owners[2]);\n    let identity = mask(c, &hc, id_active);')]),
    ('copy: e1 into the root gap', P6, [('    reaches(c, e1, &cur[0], &cur[1]);', '    let e1c = copy_vars(c, &[e1])[0];\n    reaches(c, e1c, &cur[0], &cur[1]);')]),
    ('copy: root into the root gap', P6, [('    reaches(c, e1, &cur[0], &cur[1]);', '    let r0 = copy_vars(c, &cur[0]);\n    reaches(c, e1, &r0, &cur[1]);')]),
    ('copy: e1 into idle', P6, [('    idle(c, sum1, e1);', '    let e1c = copy_vars(c, &[e1])[0];\n    idle(c, sum1, e1c);')]),
    ('copy: x into token_out', P6, [('    let token_out = reveal(c, &token, x);', '    let xc = copy_vars(c, &[x])[0];\n    let token_out = reveal(c, &token, xc);')]),
    ('copy: x into the hidden gate', P6, [('    exits(c, x, &withdrawn, &intent);', '    let xc = copy_vars(c, &[x])[0];\n    exits(c, xc, &withdrawn, &intent);')]),
    # ---- Rows added by the phase C review (MR-V6C-1, MR-V6C-2, ADV-V6-1).
    ('copy: root1 into the root gap', P6, [('    reaches(c, e1, &cur[0], &cur[1]);', '    let r1 = copy_vars(c, &cur[1]);\n    reaches(c, e1, &cur[0], &r1);')]),
    ('copy: sum1 into idle', P6, [('    idle(c, sum1, e1);', '    let s1 = copy_vars(c, &[sum1])[0];\n    idle(c, s1, e1);')]),
    ('copy: token_out into the published limbs', P6, [(PUBLISHED, '    let toc = copy_vars(c, &token_out);\n' + PUBLISHED.replace('pub_ctx, token_out, cur[0]', 'pub_ctx, toc, cur[0]'))]),
    ('copy: identity into the published limbs (MR-V6-1 outcome)', P6, [(PUBLISHED, '    let idc = copy_vars(c, &identity);\n' + PUBLISHED.replace('intent, identity, valid_until', 'intent, idc, valid_until'))]),
    ('copy: path0 node after level 10', P6, [(LEVEL_HASH, LEVEL_HASH + '\n        let next = if level == 10 { vec![copy_vars(c, &next[0]), next[1].clone()] } else { next };')]),
    ('copy: path1 node after level 10', P6, [(LEVEL_HASH, LEVEL_HASH + '\n        let next = if level == 10 { vec![next[0].clone(), copy_vars(c, &next[1])] } else { next };')]),
    ('copy: path0 last node into the root', P6, [(LEVEL_HASH, LEVEL_HASH + '\n        let next = if level == DEPTH - 1 { vec![copy_vars(c, &next[0]), next[1].clone()] } else { next };')]),
    ('copy: path1 node into the next level request', P6, [(LEVEL_REQ, '            let cp = if p == 1 && level == 5 { copy_vars(c, &cur[p]) } else { cur[p].clone() };\n' + LEVEL_REQ.replace('&cur[p], &sib', '&cp, &sib'))]),
    ('copy: intent into the x gate', P6, [('    exits(c, x, &withdrawn, &intent);', '    let ic = copy_vars(c, &intent);\n    exits(c, x, &withdrawn, &ic);')]),
    ('copy: owner1 out into INNER1', P6, [before(INNER_IN, '    let o1 = copy_vars(c, &owners[1]);'), ('(INNER, 0, [owners[1].clone(), rho[1].clone()].concat()),', '(INNER, 0, [o1, rho[1].clone()].concat()),')]),
    ('copy: rho1 into INNER1', P6, [before(INNER_IN, '    let r1 = copy_vars(c, &rho[1]);'), ('(INNER, 0, [owners[1].clone(), rho[1].clone()].concat()),', '(INNER, 0, [owners[1].clone(), r1].concat()),')]),
    ('copy: recv_out1 into INNER_out1', P6, [before(INNER_OUT, '    let ro1 = copy_vars(c, &recv_out[1]);'), ('(INNER, 0, [recv_out[1].clone(), rho_out[1].clone()].concat()),', '(INNER, 0, [ro1, rho_out[1].clone()].concat()),')]),
    ('copy: rho_out0 into INNER_out0', P6, [before(INNER_OUT, '    let q0 = copy_vars(c, &rho_out[0]);'), ('(INNER, 0, [recv_out[0].clone(), rho_out[0].clone()].concat()),', '(INNER, 0, [recv_out[0].clone(), q0].concat()),')]),
    ('copy: inner1 out into NOTE1', P6, [before(NOTES, '    let i1 = copy_vars(c, &inner_in[1]);'), ('        note(&context, &amt1, &inner_in[1]),', '        note(&context, &amt1, &i1),')]),
    ('copy: inner_out1 into NOTE3', P6, [before(NOTES, '    let io1 = copy_vars(c, &b[1]);'), ('        note(&context, &amt_out[1], &b[1]),', '        note(&context, &amt_out[1], &io1),')]),
    ('copy: amount in1 into NOTE1', P6, [before(NOTES, '    let a1 = copy_vars(c, &amt1);'), ('        note(&context, &amt1, &inner_in[1]),', '        note(&context, &a1, &inner_in[1]),')]),
    ('copy: amount out1 into NOTE3', P6, [before(NOTES, '    let ao1 = copy_vars(c, &amt_out[1]);'), ('        note(&context, &amt_out[1], &b[1]),', '        note(&context, &ao1, &b[1]),')]),
    # ---- Rows added by the phase C re-check (NF-M1, NF-M2, MR-V6C-2).
    ('copy: level request into the level hash (NF-M1)', P6, [(LEVEL_HASH, '        let reqs: Vec<Vec<Var>> = if level == 7 { reqs.iter().map(|r| copy_vars(c, r)).collect() } else { reqs };\n' + LEVEL_HASH)]),
    ('copy: published limbs into the outputs (NF-M1)', P6, [(PUBLISHED, PUBLISHED.replace('    publish(c, [', '    let lc = copy_vars(c, &[').replace('.concat())', '.concat());\n    publish(c, lc)'))]),
    ('tag limbs guessed, not constants (NF-M2)', P6, [(TAG, TAG.replace('c.constant(M31::from(*v).into())', 'guess_m31(c, *v)'))]),
    ('guessed sk1 copy into NK1', P6, [(KEYS, '    let sk1c = copy_vars(c, &sk[1]);\n' + KEYS.replace('(NK, 0, sk[1].clone())', '(NK, 0, sk1c)'))]),
    ('copy: pack hi into NF', P6, [('        let hi = pack(c, &format!("pack{p}.hi"), &bits[p][16..]);', '        let hi = pack(c, &format!("pack{p}.hi"), &bits[p][16..]);\n        let hi = copy_vars(c, &[hi])[0];')]),
    # ---- Rows added by the attacker's re-check (ADV-RC-1, ADV-RC-3): copies inside the recording
    # helpers after their records, and the compress tree's domain constants guessed.
    ('copy: limbs inside publish after the record (A3b)', P6, [('    record(c, "published", &limbs);\n', '    record(c, "published", &limbs);\n    let mut limbs = copy_vars(c, &limbs);\n')]),
    ('copy: requests inside level_hash after the payload record (A10b)', P6, [('    // The exact words each hash is handed', '    let reqs: Vec<Vec<Var>> = reqs.iter().map(|r| copy_vars(c, r)).collect();\n    // The exact words each hash is handed')]),
    ('NODE1 domain constants guessed (A8)', P6, [('st.extend([TAG, 1, NODE1, level as u32].iter().map(|v| c.constant(M31::from(*v).into())));', 'st.extend([TAG, 1, NODE1, level as u32].iter().map(|v| guess_m31(c, *v)));')]),
    ('copy: identity flag', P6, [('    let identity = mask(c, &owners[2], id_active);', '    let fc = copy_vars(c, &[id_active])[0];\n    let identity = mask(c, &owners[2], fc);')]),
]


def sync():
    """A fresh sibling copy of the crate's sources, keeping its target directory."""
    COPY.mkdir(exist_ok=True)
    for name in ('src', 'tests', 'oracle', 'examples'):
        shutil.rmtree(COPY / name, ignore_errors=True)
        shutil.copytree(HERE / name, COPY / name, ignore=shutil.ignore_patterns('target'))
    for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'):
        if (HERE / name).exists():
            shutil.copy(HERE / name, COPY / name)
    shutil.rmtree(COPY / 'results', ignore_errors=True)
    shutil.copytree(HERE / 'results/stwo-client-r6', COPY / 'results/stwo-client-r6')


def run_tests():
    r = subprocess.run(['cargo', '+nightly-2026-01-15', 'test', '--release', '--features', 'tamper', '--test', 'payment_r6',
                        '--test', 'payment_r6_malicious', '--no-fail-fast', '--', '--skip', 'pinned_circuit_hash'],
                       cwd=COPY, capture_output=True, text=True)
    out = r.stdout + r.stderr
    built = 'running ' in out
    failed = sorted({l.split()[1] for l in out.splitlines() if l.startswith('test ') and l.rstrip().endswith('FAILED')})
    return built, failed, out


def main():
    sync()
    built, failed, out = run_tests()
    assert built and not failed, f'the unmutated suites must pass:\n{out[-3000:]}'
    original = {p: (COPY / p).read_text() for p in {m[1] for m in MUTANTS} | {P6}}
    rows = []
    for name, path, edits in MUTANTS:
        for p, t in original.items():
            (COPY / p).write_text(t)
        text = original[path]
        for old, new in edits:
            assert text.count(old) == 1, (name, old[:60], text.count(old))
            changed = text.replace(old, new)
            assert changed != text, (name, 'an edit that changes nothing')
            text = changed
        if path == P6:
            text += COPY_HELPER
        (COPY / path).write_text(text)
        built, failed, out = run_tests()
        row = {'mutant': name, 'file': path, 'built': built, 'killed_by': failed}
        if not failed and name in EQUIVALENT:
            row['equivalent'] = EQUIVALENT[name]
        if not built:
            row['error'] = [l for l in out.splitlines() if l.startswith('error')][:3]
        rows.append(row)
        print(json.dumps(row), flush=True)
    for p, t in original.items():
        (COPY / p).write_text(t)
    survivors = [r['mutant'] for r in rows if r['built'] and not r['killed_by'] and 'equivalent' not in r]
    # A guessed copy the wiring test does not see is a hole in §4.4's defence, even if another
    # test happens to fail (MR-V6C-2).
    wiring_misses = [r['mutant'] for r in rows if r['mutant'].startswith(('copy:', 'guessed'))
                     and 'wiring_uses_the_same_variables' not in r['killed_by']]
    equivalent = [r['mutant'] for r in rows if 'equivalent' in r]
    unbuilt = [r['mutant'] for r in rows if not r['built']]
    OUT.write_text(json.dumps({'scope': 'R0 V6 mutation table (pool-v3-spec §4.4, re-check F7); the F38 pinned-hash test is skipped',
                               'mutants': rows, 'survivors': survivors, 'equivalent': equivalent, 'unbuilt': unbuilt,
                               'wiring_misses': wiring_misses}, indent=1) + '\n')
    print(json.dumps({'mutants': len(rows), 'survivors': survivors, 'equivalent': equivalent, 'unbuilt': unbuilt,
                      'wiring_misses': wiring_misses}))
    assert not survivors and not unbuilt and not wiring_misses, 'the table has holes'


if __name__ == '__main__':
    main()
