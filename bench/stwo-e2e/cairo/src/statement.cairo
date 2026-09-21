// Isolated evaluation of the existing felt252 Templar statement.
// Private witness enters through executable arguments; only the eight public
// scalars are returned. An accepting application must pin this program hash.
use core::poseidon::poseidon_hash_span;
fn take(ref w: Span<felt252>) -> felt252 { *w.pop_front().expect('SHORT_WITNESS') }
fn amount(ref w: Span<felt252>) -> felt252 {
    let x: u128 = take(ref w).try_into().expect('AMOUNT_RANGE');
    x.into()
}
fn h(a: Array<felt252>) -> felt252 { poseidon_hash_span(a.span()) }
fn commit(token: felt252, amt: felt252, ctrl: felt252, policy: felt252, inner: felt252) -> felt252 {
    h(array!['COMMITMENT_TAG:V3', token, amt, ctrl, policy, inner])
}
pub fn verify_spend(mut w: Span<felt252>) -> Array<felt252> {
    // Compatibility padding: the pinned privacy recursion circuit expects the
    // Pedersen components to be enabled. This checks a public constant only;
    // Templar's statement, commitments and tree still use Poseidon exclusively.
    assert(core::pedersen::pedersen(0, 0) ==
        0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804, 'PEDERSEN_PADDING');
    let version = take(ref w); let chain = take(ref w); let pool = take(ref w);
    let root = take(ref w); let ctrl = take(ref w);
    let deadline: u64 = take(ref w).try_into().expect('DEADLINE_RANGE');
    let tc = take(ref w); let binding = take(ref w);
    let actions = take(ref w); let token = take(ref w); let nonce = take(ref w);
    let ni: u32 = take(ref w).try_into().expect('INPUT_COUNT');
    let no: u32 = take(ref w).try_into().expect('OUTPUT_COUNT');
    let nw: u32 = take(ref w).try_into().expect('WITHDRAW_COUNT');
    assert(ni <= 4 && no <= 4 && nw <= 2, 'TOO_MANY_SLOTS');
    let mut nfs = array![]; let mut ins = array![];
    let mut cms = array![]; let mut outs = array![]; let mut wds = array![];
    let mut si = 0; let mut so = 0; let mut sw = 0;
    let mut i: u32 = 0;
    while i < 4 {
        if i < ni {
            let salt = amount(ref w); let owner = take(ref w); let amt = amount(ref w);
            let note_ctrl = take(ref w); let policy = take(ref w); let nf = take(ref w);
            let mut idx: u32 = take(ref w).try_into().expect('INDEX_RANGE');
            let secret = h(array!['NOTE_SECRET_TAG:V3', salt, owner]);
            let inner = h(array!['NOTE_INNER_TAG:V3', secret]);
            let mut cur = commit(token, amt, note_ctrl, policy, inner);
            let mut level: u32 = 0;
            while level < 32 {
                let sibling = take(ref w);
                cur = if idx % 2 == 0 { h(array![cur, sibling]) } else { h(array![sibling, cur]) };
                idx = idx / 2; level += 1;
            };
            assert(cur == root, 'BAD_MEMBERSHIP');
            assert(h(array!['NULLIFIER_TAG:V3', secret]) == nf, 'BAD_NULLIFIER');
            assert(note_ctrl == ctrl, 'INPUT_CONTROLLER');
            nfs.append(nf); ins.append(amt); si += amt;
        } else { nfs.append(0); ins.append(0); };
        i += 1;
    };
    i = 0;
    while i < 4 {
        if i < no {
            let inner = take(ref w); let amt = amount(ref w);
            let note_ctrl = take(ref w); let policy = take(ref w); let cm = take(ref w);
            assert(commit(token, amt, note_ctrl, policy, inner) == cm, 'BAD_OUTPUT');
            assert(note_ctrl == ctrl, 'OUTPUT_CONTROLLER');
            cms.append(cm); outs.append(amt); so += amt;
        } else { cms.append(0); outs.append(0); };
        i += 1;
    };
    i = 0;
    while i < 2 {
        if i < nw { let amt = amount(ref w); wds.append(amt); sw += amt; }
        else { wds.append(0); };
        i += 1;
    };
    assert(w.is_empty(), 'EXTRA_WITNESS');
    // At most four u128 inputs and six u128 output/withdrawal terms: no felt wrap.
    assert(si == so + sw, 'NOT_CONSERVED');
    let mut b = array!['TX_BIND_TAG:V2', version, chain, pool, root, ni.into()];
    i = 0; while i < 4 { b.append(*nfs.at(i.into())); i += 1; };
    b.append(no.into());
    i = 0; while i < 4 { b.append(*cms.at(i.into())); i += 1; };
    b.append(nw.into());
    i = 0; while i < 2 {
        b.append(if i < nw { token } else { 0 }); b.append(*wds.at(i.into())); b.append(0); i += 1;
    };
    b.append(ctrl); b.append(deadline.into()); b.append(tc); b.append(actions);
    assert(h(b) == binding, 'BAD_BINDING');
    if ctrl != 0 {
        let mut t = array!['TRANSITION_COMMIT_TAG:V2', version, chain, pool, ni.into()];
        i = 0; while i < 4 { t.append(*nfs.at(i.into())); t.append(*ins.at(i.into())); i += 1; };
        t.append(no.into());
        i = 0; while i < 4 { t.append(*cms.at(i.into())); t.append(*outs.at(i.into())); i += 1; };
        t.append(nw.into());
        i = 0; while i < 2 {
            t.append(if i < nw { token } else { 0 }); t.append(*wds.at(i.into())); t.append(0); i += 1;
        };
        t.append(ctrl); t.append(deadline.into()); t.append(nonce);
        assert(h(t) == tc, 'BAD_TRANSITION');
    };
    array![version, chain, pool, root, ctrl, deadline.into(), tc, binding]
}
