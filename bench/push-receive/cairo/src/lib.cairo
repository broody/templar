//! Experimental ordinary push-note statement. Incompatible with deployed V3.
use core::poseidon::poseidon_hash_span;

fn take(ref w: Span<felt252>) -> felt252 { *w.pop_front().expect('SHORT_WITNESS') }
fn h(v: Array<felt252>) -> felt252 { poseidon_hash_span(v.span()) }
fn amount(ref w: Span<felt252>) -> felt252 {
    let value: u128 = take(ref w).try_into().expect('AMOUNT_RANGE');
    assert(value != 0, 'ZERO_AMOUNT');
    value.into()
}
fn commitment(chain: felt252, pool: felt252, token: felt252, amount: felt252,
              receiver: felt252, rho: felt252) -> felt252 {
    assert(receiver != 0 && rho != 0, 'ZERO_NOTE');
    let inner = h(array!['PUSH_INNER_V1', receiver, rho]);
    h(array!['PUSH_NOTE_V1', chain, pool, token, amount, 0, 0, inner])
}

#[executable]
fn main(mut w: Span<felt252>) -> Array<felt252> {
    // Same public compatibility padding as the existing standalone Stwo harness.
    assert(core::pedersen::pedersen(0, 0) ==
        0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804, 'PEDERSEN_PADDING');
    let version = take(ref w);
    assert(version == 'TEMPLAR_PUSH_POC1', 'VERSION');
    let chain = take(ref w); let pool = take(ref w); let root = take(ref w);
    let token = take(ref w); let expected = take(ref w);
    assert(chain != 0 && pool != 0 && token != 0, 'ZERO_CONTEXT');
    let ni: u32 = take(ref w).try_into().expect('INPUT_COUNT');
    let no: u32 = take(ref w).try_into().expect('OUTPUT_COUNT');
    let nw: u32 = take(ref w).try_into().expect('WITHDRAW_COUNT');
    assert(ni > 0 && ni <= 4 && no <= 4 && nw <= 2 && no + nw > 0, 'SHAPE');
    let mut nfs = array![];
    let mut outputs = array![];
    let mut withdrawals = array![];
    let mut sum_in: felt252 = 0;
    let mut sum_out: felt252 = 0;
    for i in 0..4_u32 {
        if i < ni {
            let sk = take(ref w); let rho = take(ref w); let amt = amount(ref w);
            let nf = take(ref w);
            let mut index: u32 = take(ref w).try_into().expect('INDEX_RANGE');
            let leaf_index = index;
            assert(sk != 0 && nf != 0, 'ZERO_SECRET');
            let receiver = h(array!['PUSH_OWNER_V1', sk]);
            let cm = commitment(chain, pool, token, amt, receiver, rho);
            let mut cur = cm;
            for _ in 0..32_u32 {
                let sibling = take(ref w);
                cur = if index % 2 == 0 { h(array![cur, sibling]) } else { h(array![sibling, cur]) };
                index /= 2;
            };
            assert(cur == root, 'MEMBERSHIP');
            assert(nf == h(array!['PUSH_NF_V1', sk, cm, leaf_index.into()]), 'NULLIFIER');
            for j in 0..i { assert(nf != *nfs.at(j.into()), 'DUPLICATE_INPUT'); };
            nfs.append(nf);
            sum_in += amt;
        } else { nfs.append(0); };
    };
    for i in 0..4_u32 {
        if i < no {
            let receiver = take(ref w); let rho = take(ref w); let amt = amount(ref w);
            let cm = take(ref w); let delivery = take(ref w);
            assert(cm != 0 && delivery != 0, 'ZERO_OUTPUT');
            assert(cm == commitment(chain, pool, token, amt, receiver, rho), 'OUTPUT');
            outputs.append(cm); outputs.append(delivery);
            sum_out += amt;
        } else { outputs.append(0); outputs.append(0); };
    };
    for i in 0..2_u32 {
        if i < nw {
            let recipient = take(ref w); let amt = amount(ref w);
            let address: u256 = recipient.into();
            assert(recipient != 0 && address < 0x800000000000000000000000000000000000000000000000000000000000000, 'RECIPIENT');
            withdrawals.append(recipient); withdrawals.append(amt);
            sum_out += amt;
        } else { withdrawals.append(0); withdrawals.append(0); };
    };
    assert(w.is_empty(), 'EXTRA_WITNESS');
    // At most four u128 inputs, six u128 output terms: sums cannot wrap felt252.
    assert(sum_in == sum_out, 'CONSERVATION');
    let mut b = array!['PUSH_BIND_V1', version, chain, pool, root, token, ni.into()];
    for nf in nfs.span() { b.append(*nf); };
    b.append(no.into());
    for output in outputs.span() { b.append(*output); };
    b.append(nw.into());
    for withdrawal in withdrawals.span() { b.append(*withdrawal); };
    assert(h(b) == expected, 'BINDING');
    array![version, chain, pool, root, 0, 0, 0, expected]
}
