//! Word-level construction of `ro` messages whose variable payloads start at byte
//! offset 1 mod 4 (every leaf and node message).
//!
//! For a canonical word `w = (lo, hi)` with bytes `b0..b3`:
//! `S = m31_to_u32(256 lo) = (256 b0, b1)` and `T = m31_to_u32(256 hi) = (256 b2, b3)`
//! exactly, since `256 lo, 256 hi < 2^24 < p` and the gate range-checks its limbs.
//! A payload of words `w_k` at offset 1 then contributes to message word `k` the value
//! `T_{k-1}.hi + S_k + i T_k.lo` (and `T_{n-1}.hi` to word `n`). Every term is a
//! checked limb, so each message word is canonical. Nothing is guessed.
//!
//! Payload bytes with no other use (salts, siblings) are guessed directly as aligned
//! message words: full words are upstream U32 guesses (both 16-bit limbs range-checked),
//! partial words are tied to checked bytes.
use crate::ro::{blake2s_words, check_byte, guess_m31};
use crate::transcript::low_limb;
use circuits::blake::m31_to_u32;
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::{IValue, qm31_from_u32s};
use circuits::ops::{Guess, eq, pointwise_mul};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;

fn minus_i<V: IValue>(ctx: &mut Context<V>) -> Var {
    ctx.constant(qm31_from_u32s(0, M31::from(-1).0, 0, 0))
}

/// High limb of a canonical packed word as a scalar `(hi, 0, 0, 0)`.
fn hi_scalar<V: IValue>(ctx: &mut Context<V>, w: Var) -> Var {
    let e1 = ctx.constant(qm31_from_u32s(0, 1, 0, 0));
    let part = pointwise_mul(ctx, w, e1);
    let m = minus_i(ctx);
    eval!(ctx, (part) * (m))
}

/// Contributions of canonical words `ws` placed at offset 1: `ws.len() + 1` values.
pub fn offset1_words<V: IValue>(ctx: &mut Context<V>, ws: &[Var]) -> Vec<Var> {
    let c256 = ctx.constant(qm31_from_u32s(256, 0, 0, 0));
    let c256i = ctx.constant(qm31_from_u32s(0, 256, 0, 0));
    let i = ctx.constant(qm31_from_u32s(0, 1, 0, 0));
    let m = minus_i(ctx);
    let mut out = vec![];
    let mut carry: Option<Var> = None;
    for &w in ws {
        let lo256 = pointwise_mul(ctx, w, c256);
        let hi256i = pointwise_mul(ctx, w, c256i);
        let hi256 = eval!(ctx, (hi256i) * (m));
        let s = *m31_to_u32(ctx, lo256).get();
        let t = *m31_to_u32(ctx, hi256).get();
        let t_hi = hi_scalar(ctx, t);
        // i T = i T.lo - T.hi, so i T.lo = i T + T.hi.
        let it = eval!(ctx, (t) * (i));
        let it_lo = eval!(ctx, (it) + (t_hi));
        let body = eval!(ctx, (s) + (it_lo));
        out.push(match carry {
            Some(c) => eval!(ctx, (body) + (c)),
            None => body,
        });
        carry = Some(t_hi);
    }
    out.push(carry.expect("nonempty payload"));
    out
}

/// Guessed witness bytes placed at offset 1, as aligned contributions. `bytes.len()`
/// must be `4k` with `k >= 1`: 3 leading bytes, `k - 1` full words, 1 trailing byte.
pub fn offset1_free<V: IValue>(ctx: &mut Context<V>, bytes: &[u8]) -> Vec<Var> {
    let n = bytes.len();
    assert!(n >= 4 && n % 4 == 0);
    let mut out = vec![];
    // First word: (256 s0, s1 + 256 s2). Guessed canonical, low limb tied to a checked byte.
    // Upstream U32 guesses range-check both 16-bit limbs.
    let w0 = *V::pack_u32(u32::from_le_bytes([0, bytes[0], bytes[1], bytes[2]])).guess(ctx).get();
    let s0 = guess_m31(ctx, bytes[0] as u32);
    check_byte(ctx, s0);
    let lo = low_limb(ctx, w0);
    let c256 = ctx.constant(M31::from(256).into());
    let scaled = eval!(ctx, (s0) * (c256));
    eq(ctx, lo, scaled);
    out.push(w0);
    // Full words: bytes 4k+3 .. 4k+6.
    for k in 0..n / 4 - 1 {
        let b = &bytes[4 * k + 3..4 * k + 7];
        let w = *V::pack_u32(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).guess(ctx).get();
        out.push(w);
    }
    // Trailing byte in position 0 of the last word.
    let last = guess_m31(ctx, bytes[n - 1] as u32);
    check_byte(ctx, last);
    out.push(last);
    out
}

/// A message part with a fixed byte length.
pub enum Part {
    Const(Vec<u8>),
    /// Contributions for a payload of `len` bytes starting at offset 1 (`len / 4 + 1` values).
    Offset1 { contributions: Vec<Var>, len: usize },
    /// Scalar variable bytes: each var is a checked byte.
    Scalars(Vec<Var>),
    /// `index as u64` from boolean bits (LSB first), at any offset.
    Index(Vec<Var>),
}

/// `crypto::ro(tag, parts)` built word by word. Returns the digest words.
pub fn ro_parts<V: IValue>(ctx: &mut Context<V>, tag: &[u8], parts: Vec<Part>) -> [Var; 8] {
    let mut consts: Vec<u8> = crate::ro::DOMAIN.to_vec();
    let mut contrib: Vec<(usize, Var)> = vec![];
    let push_len = |consts: &mut Vec<u8>, n: usize| consts.extend((n as u64).to_le_bytes());
    push_len(&mut consts, tag.len());
    consts.extend(tag);
    push_len(&mut consts, parts.len());
    // Adds `var * 256^(pos % 4)` (limb-aware) to the word containing byte `pos`.
    let scalar_at = |ctx: &mut Context<V>, contrib: &mut Vec<(usize, Var)>, pos: usize, var: Var| {
        let r = pos % 4;
        let coef = match r {
            0 => qm31_from_u32s(1, 0, 0, 0),
            1 => qm31_from_u32s(256, 0, 0, 0),
            2 => qm31_from_u32s(0, 1, 0, 0),
            _ => qm31_from_u32s(0, 256, 0, 0),
        };
        let v = if r == 0 { var } else { let c = ctx.constant(coef); eval!(ctx, (var) * (c)) };
        contrib.push((pos / 4, v));
    };
    for part in parts {
        match part {
            Part::Const(b) => {
                push_len(&mut consts, b.len());
                consts.extend(b);
            }
            Part::Offset1 { contributions, len } => {
                push_len(&mut consts, len);
                let start = consts.len();
                assert_eq!(start % 4, 1, "payload must start at offset 1");
                assert_eq!(contributions.len(), len / 4 + 1);
                for (k, c) in contributions.into_iter().enumerate() {
                    contrib.push((start / 4 + k, c));
                }
                consts.extend(std::iter::repeat_n(0, len));
            }
            Part::Scalars(vars) => {
                push_len(&mut consts, vars.len());
                for v in vars {
                    let pos = consts.len();
                    scalar_at(ctx, &mut contrib, pos, v);
                    consts.push(0);
                }
            }
            Part::Index(bits) => {
                push_len(&mut consts, 8);
                let start = consts.len();
                for (k, b) in bits.into_iter().enumerate() {
                    let pos = start + k / 8;
                    let scaled = if k % 8 == 0 { b } else { let c = ctx.constant(M31::from(1u32 << (k % 8)).into()); eval!(ctx, (b) * (c)) };
                    scalar_at(ctx, &mut contrib, pos, scaled);
                }
                consts.extend([0u8; 8]);
            }
        }
    }
    let n_bytes = consts.len();
    let n_words = n_bytes.div_ceil(4);
    consts.resize(4 * n_words, 0);
    let mut words: Vec<Option<Var>> = (0..n_words)
        .map(|k| {
            let w = u32::from_le_bytes(consts[4 * k..4 * k + 4].try_into().unwrap());
            if w == 0 { None } else { Some(ctx.constant(*QM31::pack_u32(w).get())) }
        })
        .collect();
    for (k, c) in contrib {
        words[k] = Some(match words[k] {
            Some(w) => eval!(ctx, (w) + (c)),
            None => c,
        });
    }
    let zero_word = ctx.constant(*QM31::pack_u32(0).get());
    let words: Vec<Var> = words.into_iter().map(|w| w.unwrap_or(zero_word)).collect();
    blake2s_words(ctx, words, n_bytes)
}
