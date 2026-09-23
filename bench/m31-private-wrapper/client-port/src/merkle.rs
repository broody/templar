//! `crypto::open` inside the circuit: salted leaf, then one `ro("node")` per
//! level with the order chosen by the index bit. The result must equal the
//! committed root, compared as packed words.
use crate::aligned::{Part, offset1_free, offset1_words, ro_parts};
use crate::ro::{Byte, Digest, guess_m31, pack_bytes};
use circuits::blake::m31_to_u32;
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::IValue;
use circuits::ops::eq;

/// Guessed boolean index bits, least significant first.
pub fn guess_bits<Value: IValue>(ctx: &mut Context<Value>, index: usize, n_bits: u32) -> Vec<Var> {
    (0..n_bits)
        .map(|k| {
            let b = guess_m31(ctx, ((index >> k) & 1) as u32);
            let zero = ctx.zero();
            let boolean = eval!(ctx, (b) * ((b) - (1)));
            eq(ctx, boolean, zero);
            b
        })
        .collect()
}

/// Canonical packed words of M31 values: `m31_to_u32` rejects the representation p.
fn value_words<Value: IValue>(ctx: &mut Context<Value>, vars: &[Var]) -> Vec<Var> {
    vars.iter().map(|v| *m31_to_u32(ctx, *v).get()).collect()
}

fn leaf<Value: IValue>(ctx: &mut Context<Value>, id: u32, bits: &[Var], values: &[u32], salt: &[u8]) -> (Vec<Var>, Digest) {
    let vars: Vec<Var> = values.iter().map(|v| guess_m31(ctx, *v)).collect();
    let words = value_words(ctx, &vars);
    let payload = offset1_words(ctx, &words);
    let salt = offset1_free(ctx, salt);
    let h = ro_parts(ctx, b"leaf", vec![
        Part::Const(id.to_le_bytes().to_vec()),
        Part::Index(bits.to_vec()),
        Part::Offset1 { contributions: payload, len: 4 * values.len() },
        Part::Offset1 { contributions: salt, len: 96 },
    ]);
    (vars, h)
}

/// `ro("node", [id, depth, left, right])` from aligned contributions of the two children.
fn node<Value: IValue>(ctx: &mut Context<Value>, id: u32, depth: u32, left: Vec<Var>, right: Vec<Var>) -> Digest {
    ro_parts(ctx, b"node", vec![
        Part::Const(id.to_le_bytes().to_vec()),
        Part::Const(depth.to_le_bytes().to_vec()),
        Part::Offset1 { contributions: left, len: 32 },
        Part::Offset1 { contributions: right, len: 32 },
    ])
}

fn climb<Value: IValue>(ctx: &mut Context<Value>, id: u32, mut h: Digest, first_depth: usize, bits: &[Var], siblings: &[[u8; 32]], root: &[Byte]) {
    assert_eq!(bits.len(), siblings.len());
    for (k, (bit, sibling)) in bits.iter().zip(siblings).enumerate() {
        let cur = offset1_words(ctx, &h);
        let sib = offset1_free(ctx, sibling);
        // Word-wise (left, right) = bit ? (sib, cur) : (cur, sib).
        let mut left = vec![];
        let mut right = vec![];
        for (c, s) in cur.into_iter().zip(sib) {
            let bit = *bit;
            let d = eval!(ctx, (bit) * ((s) - (c)));
            left.push(eval!(ctx, (c) + (d)));
            right.push(eval!(ctx, (s) - (d)));
        }
        h = node(ctx, id, (first_depth + k) as u32, left, right);
    }
    let root_words = pack_bytes(ctx, root);
    for (a, b) in h.iter().zip(root_words) {
        eq(ctx, *a, b);
    }
}

/// Opens the sibling leaves `2m` and `2m + 1` together: both leaves, their
/// common parent, then one shared path. `bits` are the bits of the index `j`
/// (bit 0 ignored); `siblings` is the even leaf's path. A valid odd-leaf path
/// is `[leaf(2m)] ++ siblings[1..]`, so acceptance equals opening both.
pub fn open_pair<Value: IValue>(
    ctx: &mut Context<Value>,
    id: u32,
    bits: &[Var],
    even: (&[u32], &[u8]),
    odd: (&[u32], &[u8]),
    siblings: &[[u8; 32]],
    root: &[Byte],
) -> (Vec<Var>, Vec<Var>) {
    let mut even_bits = bits.to_vec();
    even_bits[0] = ctx.zero();
    let mut odd_bits = bits.to_vec();
    odd_bits[0] = ctx.one();
    let (ev, eh) = leaf(ctx, id, &even_bits, even.0, even.1);
    let (ov, oh) = leaf(ctx, id, &odd_bits, odd.0, odd.1);
    let (l, r) = (offset1_words(ctx, &eh), offset1_words(ctx, &oh));
    let parent = node(ctx, id, 0, l, r);
    climb(ctx, id, parent, 1, &bits[1..], &siblings[1..], root);
    (ev, ov)
}

pub struct Opened {
    pub values: Vec<Var>,
}

/// Authenticates `values` (guessed M31 witnesses) at the index given by `bits`
/// (`bits.len() == log2(n)`) in tree `id` against the 32 checked `root` bytes.
pub fn open<Value: IValue>(
    ctx: &mut Context<Value>,
    id: u32,
    bits: &[Var],
    values: &[u32],
    salt: &[u8],
    siblings: &[[u8; 32]],
    root: &[Byte],
) -> Opened {
    let (vars, h) = leaf(ctx, id, bits, values, salt);
    climb(ctx, id, h, 0, bits, siblings, root);
    Opened { values: vars }
}
