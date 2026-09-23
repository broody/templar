//! Controlled push ownership and transition checks; signatures are verified by the public pool.
use core::poseidon::poseidon_hash_span;
use pool::spend::{PROTOCOL_VERSION, compute_transition};
fn take(ref w: Span<felt252>) -> felt252 { *w.pop_front().expect('SHORT_WITNESS') }
fn h(v: Array<felt252>) -> felt252 { poseidon_hash_span(v.span()) }
fn amount(ref w: Span<felt252>) -> felt252 {
    let value: u128 = take(ref w).try_into().expect('AMOUNT_RANGE');
    assert(value != 0, 'ZERO_AMOUNT'); value.into()
}
fn addr(v: felt252) { let x: u256 = v.into(); assert(x < 0x800000000000000000000000000000000000000000000000000000000000000, 'ADDRESS_RANGE'); }
fn commitment(chain: felt252, pool: felt252, token: felt252, amt: felt252,
    receiver: felt252, rho: felt252, ctrl: felt252, policy: felt252) -> felt252 {
    assert(receiver != 0 && rho != 0, 'ZERO_NOTE');
    assert(ctrl != 0 || policy == 0, 'ORDINARY_POLICY');
    h(array!['CTRL_NOTE_V1',chain,pool,token,amt,ctrl,policy,h(array!['CTRL_INNER_V1',receiver,rho])])
}
#[inline(never)]
pub fn verify_spend(mut w: Span<felt252>) -> Array<felt252> {
    assert(core::pedersen::pedersen(0,0) ==
        0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804, 'PEDERSEN_PADDING');
    let version=take(ref w); assert(version == PROTOCOL_VERSION, 'VERSION');
    let chain=take(ref w); let pool=take(ref w); let root=take(ref w); let token=take(ref w);
    let expected=take(ref w); let ctrl=take(ref w); let deadline: u64=take(ref w).try_into().expect('DEADLINE_RANGE');
    let nonce=take(ref w); let transition=take(ref w);
    assert(chain != 0 && pool != 0 && token != 0, 'ZERO_CONTEXT'); addr(pool); addr(token); addr(ctrl);
    if ctrl == 0 { assert(deadline == 0 && nonce == 0 && transition == 0, 'ORDINARY_AUTH'); }
    else { assert(deadline != 0 && nonce != 0 && transition != 0, 'CONTROL_AUTH'); };
    let ni: u32=take(ref w).try_into().expect('INPUT_COUNT');
    let no: u32=take(ref w).try_into().expect('OUTPUT_COUNT');
    let nw: u32=take(ref w).try_into().expect('WITHDRAW_COUNT');
    assert(ni > 0 && ni <= 4 && no <= 4 && nw <= 2 && no+nw > 0, 'SHAPE');
    let mut nfs=array![]; let mut outputs=array![]; let mut wds=array![];
    let mut in_legs=array![]; let mut out_legs=array![];
    let mut sum_in: felt252=0; let mut sum_out: felt252=0;
    for i in 0..4_u32 {
        if i < ni {
            let sk=take(ref w); let rho=take(ref w); let amt=amount(ref w);
            let note_ctrl=take(ref w); let policy=take(ref w); let nf=take(ref w);
            let mut index: u32=take(ref w).try_into().expect('INDEX_RANGE'); let leaf_index=index;
            assert(note_ctrl == ctrl, 'CONTROLLER'); assert(sk != 0 && nf != 0, 'ZERO_SECRET');
            let ak=h(array!['CTRL_AUTH_V1',sk]); let nk=h(array!['CTRL_NK_V1',sk]);
            assert(ak != 0 && nk != 0, 'ZERO_VIEW_KEY');
            let receiver=h(array!['CTRL_OWNER_V1',ak,nk]);
            let cm=commitment(chain,pool,token,amt,receiver,rho,note_ctrl,policy);
            let mut cur=cm;
            for _ in 0..32_u32 { let sibling=take(ref w); cur=if index%2 == 0 { h(array![cur,sibling]) } else { h(array![sibling,cur]) }; index/=2; };
            assert(cur == root, 'MEMBERSHIP');
            assert(nf == h(array!['CTRL_NF_V1',nk,cm,leaf_index.into()]), 'NULLIFIER');
            for j in 0..i { assert(nf != *nfs.at(j.into()), 'DUPLICATE_INPUT'); };
            nfs.append(nf); in_legs.append(nf); in_legs.append(amt); in_legs.append(policy); sum_in+=amt;
        } else { nfs.append(0); in_legs.append(0); in_legs.append(0); in_legs.append(0); };
    };
    for i in 0..4_u32 {
        if i < no {
            let receiver=take(ref w); let rho=take(ref w); let amt=amount(ref w);
            let note_ctrl=take(ref w); let policy=take(ref w); let cm=take(ref w); let delivery=take(ref w);
            assert(note_ctrl == ctrl, 'CONTROLLER'); assert(cm != 0 && delivery != 0, 'ZERO_OUTPUT');
            assert(cm == commitment(chain,pool,token,amt,receiver,rho,note_ctrl,policy), 'OUTPUT');
            outputs.append(cm); outputs.append(delivery);
            out_legs.append(cm); out_legs.append(amt); out_legs.append(policy); out_legs.append(delivery); sum_out+=amt;
        } else { outputs.append(0); outputs.append(0); out_legs.append(0); out_legs.append(0); out_legs.append(0); out_legs.append(0); };
    };
    for i in 0..2_u32 {
        if i < nw { let recipient=take(ref w); let amt=amount(ref w); addr(recipient); assert(recipient != 0, 'RECIPIENT');
            wds.append(recipient); wds.append(amt); sum_out+=amt;
        } else { wds.append(0); wds.append(0); };
    };
    assert(w.is_empty(), 'EXTRA_WITNESS'); assert(sum_in == sum_out, 'CONSERVATION');
    if ctrl != 0 {
        assert(transition == compute_transition(chain,pool,root,token,ctrl,deadline.into(),nonce,
            ni.into(),no.into(),nw.into(),in_legs.span(),out_legs.span(),wds.span()), 'TRANSITION');
    };
    let mut b=array!['CTRL_BIND_V1',version,chain,pool,root,token,ctrl,deadline.into(),nonce,transition,ni.into()];
    for x in nfs.span() { b.append(*x); }; b.append(no.into());
    for x in outputs.span() { b.append(*x); }; b.append(nw.into());
    for x in wds.span() { b.append(*x); };
    assert(h(b) == expected, 'BINDING');
    array![version,chain,pool,root,ctrl,deadline.into(),transition,expected]
}
