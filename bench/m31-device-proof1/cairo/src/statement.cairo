//! Cost-model R0 statement for the device-proving spike (`../PLAN.md`, phase 1). Cost-faithful,
//! not production: it makes no soundness claim and proves no membership.
//!
//! It decodes a fixed 1,000-felt witness with canonical checks, then runs a prefix of the R0 V5
//! ordinary spend's hash schedule (`client-port/src/payment5.rs` lines 624-715) with the real
//! frame shapes, then `nodes` compress-format tree nodes alternating over two paths:
//!
//! | job | hash | frame words | permutations | cumulative |
//! |---|---|---:|---:|---:|
//! | 1-4 | AUTH(sk0), NK(sk0), AUTH(sk1), NK(sk1) | 13 | 1 each | 4 |
//! | 5-6 | WAUTH(account, sk_i) | 22 | 2 each | 8 |
//! | 7-8 | INNER(receiver_j, rho_j), outputs | 22 | 2 each | 12 |
//! | 9-10 | OWNER(ak_i, nk_i) | 22 | 2 each | 16 |
//! | 11 | IDENTITY(ak0, scope) | 22 | 2 | 18 |
//! | 12-13 | INNER(owner_i, rho_i), inputs | 22 | 2 each | 22 |
//! | 14-17 | NOTE(context27, amount8, inner) | 48 | 4 each | 38 |
//! | 18-19 | NF(nk_i, cm_i, lo, hi) | 24 | 2 each | 42 |
//!
//! The 42 schedule permutations go through the framed sponge (`hash.cairo`, `sponge`); tree nodes
//! are one permutation each (`hash.cairo`, `node` with `COMPRESS`). `k` permutations map to
//! `(jobs, nodes)` in the driver: the longest schedule prefix with at most `min(k, 42)`
//! permutations, then `k - prefix` nodes. At `k = 106` this is the R0 V5 ordinary spend: all 19
//! jobs and 64 nodes (depth 32 on two paths). A value not computed at small `k` is replaced by a
//! witness stand-in.
use crate::hash::{COMPRESS, Digest, INNER, NOTE, amount_limbs, felt_limbs, h, node};

pub const AUTH: felt252 = 1;
pub const NK: felt252 = 2;
pub const OWNER: felt252 = 3;
pub const NF: felt252 = 7;
pub const IDENTITY: felt252 = 9;
pub const WAUTH: felt252 = 16;

pub const W_LEN: u32 = 1000;
pub const MAX_JOBS: u32 = 19;
/// Two paths of at most 43 levels (the sweep's largest `k = 128` needs 86 nodes).
pub const MAX_NODES: u32 = 86;

// Witness layout: nine-word digests unless noted.
const SK0: u32 = 0;
const SK1: u32 = 9;
const ACCOUNT: u32 = 18;
const RECV0: u32 = 27;
const RHO_OUT0: u32 = 36;
const RECV1: u32 = 45;
const RHO_OUT1: u32 = 54;
const SCOPE: u32 = 63;
const RHO_IN0: u32 = 72;
const RHO_IN1: u32 = 81;
/// One bit each: the key mode (1: AUTH key, 0: WAUTH), and input 1 enabled.
const MODE: u32 = 90;
const E1: u32 = 91;
/// Four amounts: in0, in1, out0, out1.
const AMOUNTS: u32 = 92;
/// 43 position bits per path.
const POS0: u32 = 104;
const POS1: u32 = 147;
/// 90 sibling digests.
const SIB: u32 = 190;

const P: u32 = 0x7fffffff;

fn dg(w: Span<felt252>, off: u32) -> Digest {
    (*w.slice(off, 9).try_into().unwrap()).unbox()
}

fn cat(a: Digest, b: Digest) -> Span<felt252> {
    let mut m: Array<felt252> = array![];
    m.append_span(a.span());
    m.append_span(b.span());
    m.span()
}

fn bit(x: felt252) {
    assert(x * (x - 1) == 0, 'WITNESS_BIT');
}

fn amount(w: Span<felt252>, i: u32) -> u128 {
    (*w.at(AMOUNTS + i)).try_into().unwrap()
}

/// Sixteen position bits packed little-endian, as the NF frame's `lo`/`hi` words.
fn pack16(w: Span<felt252>, off: u32) -> felt252 {
    let mut v: felt252 = 0;
    let mut p: felt252 = 1;
    for i in 0..16_u32 {
        v += *w.at(off + i) * p;
        p *= 2;
    }
    v
}

/// The canonical witness decoding: exactly `W_LEN` words, each an M31 word below P; bits are 0/1.
pub fn check_witness(w: Span<felt252>) {
    assert(w.len() == W_LEN, 'WITNESS_LENGTH');
    for x in w {
        let v: u32 = (*x).try_into().expect('WITNESS_WORD');
        assert(v < P, 'WITNESS_WORD');
    }
    bit(*w.at(MODE));
    bit(*w.at(E1));
    for i in 0..43_u32 {
        bit(*w.at(POS0 + i));
        bit(*w.at(POS1 + i));
    }
}

#[derive(Drop)]
pub struct Computed {
    pub root: Option<Digest>,
    pub nullifiers: Option<(Digest, Digest)>,
    pub outputs: Option<(Digest, Digest)>,
    pub identity: Option<Digest>,
}

fn note(context: Span<felt252>, amount: u128, inner: Digest) -> Digest {
    let mut payload: Array<felt252> = array![];
    payload.append_span(context);
    amount_limbs(amount, ref payload);
    payload.append_span(inner.span());
    h(NOTE, 0, payload.span())
}

/// Runs the first `jobs` schedule hashes and `nodes` tree nodes over a checked witness.
pub fn run(w: Span<felt252>, chain: felt252, pool: felt252, asset: felt252, jobs: u32, nodes: u32) -> Computed {
    assert(jobs <= MAX_JOBS, 'JOBS');
    assert(nodes <= MAX_NODES, 'NODES');
    let sk0 = dg(w, SK0);
    let sk1 = dg(w, SK1);
    let account = dg(w, ACCOUNT);
    let (recv0, rho_out0, recv1, rho_out1) = (dg(w, RECV0), dg(w, RHO_OUT0), dg(w, RECV1), dg(w, RHO_OUT1));
    let scope = dg(w, SCOPE);
    let (rho_in0, rho_in1) = (dg(w, RHO_IN0), dg(w, RHO_IN1));

    let mut auth0 = sk0;
    let mut nk0 = sk1;
    let mut auth1 = sk1;
    let mut nk1 = sk0;
    if jobs >= 1 {
        auth0 = h(AUTH, 0, sk0.span());
    }
    if jobs >= 2 {
        nk0 = h(NK, 0, sk0.span());
    }
    if jobs >= 3 {
        auth1 = h(AUTH, 0, sk1.span());
    }
    if jobs >= 4 {
        nk1 = h(NK, 0, sk1.span());
    }
    let mut wauth0 = account;
    let mut wauth1 = account;
    if jobs >= 5 {
        wauth0 = h(WAUTH, 0, cat(account, sk0));
    }
    if jobs >= 6 {
        wauth1 = h(WAUTH, 0, cat(account, sk1));
    }
    let mut inner_out0 = recv0;
    let mut inner_out1 = recv1;
    if jobs >= 7 {
        inner_out0 = h(INNER, 0, cat(recv0, rho_out0));
    }
    if jobs >= 8 {
        inner_out1 = h(INNER, 0, cat(recv1, rho_out1));
    }
    // The key mode selects each input's key word by word in the circuit; here per digest.
    let ordinary = *w.at(MODE) == 1;
    let ak0 = if ordinary { auth0 } else { wauth0 };
    let ak1 = if ordinary { auth1 } else { wauth1 };
    let mut owner0 = ak0;
    let mut owner1 = ak1;
    let mut identity = Option::None;
    if jobs >= 9 {
        owner0 = h(OWNER, 0, cat(ak0, nk0));
    }
    if jobs >= 10 {
        owner1 = h(OWNER, 0, cat(ak1, nk1));
    }
    if jobs >= 11 {
        identity = Option::Some(h(IDENTITY, 0, cat(ak0, scope)));
    }
    let mut inner_in0 = owner0;
    let mut inner_in1 = owner1;
    if jobs >= 12 {
        inner_in0 = h(INNER, 0, cat(owner0, rho_in0));
    }
    if jobs >= 13 {
        inner_in1 = h(INNER, 0, cat(owner1, rho_in1));
    }
    // Conservation over the four amounts and the public withdrawal is checked by the account.
    let mut cm0 = inner_in0;
    let mut cm1 = inner_in1;
    let mut cm_out0 = inner_out0;
    let mut cm_out1 = inner_out1;
    let mut outputs = Option::None;
    if jobs >= 14 {
        // The note context (chain, pool, asset as 27 limbs) once, shared by the four notes.
        let mut context: Array<felt252> = array![];
        felt_limbs(chain, ref context);
        felt_limbs(pool, ref context);
        felt_limbs(asset, ref context);
        let context = context.span();
        cm0 = note(context, amount(w, 0), inner_in0);
        if jobs >= 15 {
            cm1 = note(context, amount(w, 1), inner_in1);
        }
        if jobs >= 16 {
            cm_out0 = note(context, amount(w, 2), inner_out0);
        }
        if jobs >= 17 {
            cm_out1 = note(context, amount(w, 3), inner_out1);
            outputs = Option::Some((cm_out0, cm_out1));
        }
    }
    // Both membership paths, alternating, one compress permutation per node.
    let mut cur0 = cm0;
    let mut cur1 = cm1;
    let mut i: u32 = 0;
    while i < nodes {
        let path = i % 2;
        let level = i / 2;
        let sibling = dg(w, SIB + 9 * i);
        let position = if path == 0 { *w.at(POS0 + level) } else { *w.at(POS1 + level) };
        let cur = if path == 0 { cur0 } else { cur1 };
        let (l, r) = if position == 0 { (cur, sibling) } else { (sibling, cur) };
        let next = node(COMPRESS, level.into(), l, r);
        if path == 0 {
            cur0 = next;
        } else {
            cur1 = next;
        }
        i += 1;
    }
    // An enabled second input must reach the same root.
    if *w.at(E1) == 1 {
        assert(cur0 == cur1, 'ROOT_MISMATCH');
    }
    let root = if nodes > 0 { Option::Some(cur0) } else { Option::None };
    let mut nullifiers = Option::None;
    if jobs >= 18 {
        let mut m: Array<felt252> = array![];
        m.append_span(nk0.span());
        m.append_span(cm0.span());
        m.append(pack16(w, POS0));
        m.append(pack16(w, POS0 + 16));
        let nf0 = h(NF, 0, m.span());
        let mut nf1 = nk1;
        if jobs >= 19 {
            let mut m: Array<felt252> = array![];
            m.append_span(nk1.span());
            m.append_span(cm1.span());
            m.append(pack16(w, POS1));
            m.append(pack16(w, POS1 + 16));
            nf1 = h(NF, 0, m.span());
            nullifiers = Option::Some((nf0, nf1));
        }
    }
    Computed { root, nullifiers, outputs, identity }
}

/// In + in = out + out + withdrawn, over the witness amounts.
pub fn conservation(w: Span<felt252>, withdrawn: u128) {
    let inputs: u256 = amount(w, 0).into() + amount(w, 1).into();
    let outputs: u256 = amount(w, 2).into() + amount(w, 3).into() + withdrawn.into();
    assert(inputs == outputs, 'CONSERVATION');
}
