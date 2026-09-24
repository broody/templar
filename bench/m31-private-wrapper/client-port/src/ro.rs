//! Byte-exact `crypto::ro` of the TMPZK002 client inside the circuit.
//!
//! A message is a byte list. Each item is a public constant or a variable byte
//! `(b, 0, 0, 0)` with `b < 256` enforced by `check_byte`. Bytes are packed
//! little-endian into Blake2s words encoded as `(low_u16, high_u16, 0, 0)`.
//! Every variable word is a linear combination of range-checked bytes, so it is
//! canonical by construction. Message lengths are fixed topology parameters.
use circuits::blake::{blake2s_u32s, m31_to_u32, triple_xor};
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::{IValue, qm31_from_u32s};
use circuits::ops::eq;
use circuits::wrappers::{M31Wrapper, U32Wrapper};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;

pub const DOMAIN: &[u8] = b"Templar-private-membership-BLAKE2S-v1";

#[derive(Clone, Copy, Debug)]
pub enum Byte {
    Const(u8),
    Var(Var),
}

pub type Digest = [Var; 8];

fn byte_value<Value: IValue>(b: u32) -> Value {
    Value::from_qm31(M31::from(b).into())
}

/// For `x = (b, 0, 0, 0)`, constrains `b < 256`: TripleXor accepts only the
/// canonical word `(b, 256 b)`. `b < 2^16` bounds `256 b < 2^24 < p`, so
/// `256 b < 2^16` holds over the integers and `b < 256` follows.
pub fn check_byte<Value: IValue>(ctx: &mut Context<Value>, x: Var) {
    let c = ctx.constant(qm31_from_u32s(0, 256, 0, 0));
    let zero = ctx.zero();
    let word = eval!(ctx, (x) + ((x) * (c)));
    // TripleXor range-checks its operands; the output equals the word iff it is canonical.
    let (w, z) = (U32Wrapper::new_unsafe(word), U32Wrapper::new_unsafe(zero));
    let checked = triple_xor(ctx, w, z, z);
    eq(ctx, *checked.get(), word);
}

/// Canonical word `(lo, hi, 0, 0)` from four range-checked bytes.
fn word_from_bytes<Value: IValue>(ctx: &mut Context<Value>, b: [Var; 4]) -> Var {
    let c256 = ctx.constant(M31::from(256).into());
    let hi = ctx.constant(qm31_from_u32s(0, 1, 0, 0));
    let (b0, b1, b2, b3) = (b[0], b[1], b[2], b[3]);
    let lo = eval!(ctx, (b0) + ((b1) * (c256)));
    let high = eval!(ctx, (b2) + ((b3) * (c256)));
    eval!(ctx, (lo) + ((high) * (hi)))
}

/// A guessed base-field value `(g, 0, 0, 0)`.
pub fn guess_m31<Value: IValue>(ctx: &mut Context<Value>, value: u32) -> Var {
    // Upstream M31 guesses are projected to the base field at finalization.
    *circuits::ops::guess_m31(ctx, M31Wrapper::new_unsafe(byte_value::<Value>(value))).get()
}

/// Splits a canonical packed word into four checked little-endian bytes. The
/// caller guarantees `w` is canonical (both limbs `< 2^16`), so the byte
/// decomposition is unique.
pub fn word_bytes<Value: IValue>(ctx: &mut Context<Value>, w: U32Wrapper<Var>) -> [Var; 4] {
    let w = *w.get();
    let native = ctx.get(w).unpack_u32();
    let b: [Var; 4] = std::array::from_fn(|i| guess_m31(ctx, (native >> (8 * i)) & 0xff));
    for x in b {
        check_byte(ctx, x);
    }
    let packed = word_from_bytes(ctx, b);
    eq(ctx, packed, w);
    b
}

/// The four little-endian bytes of the canonical u32 encoding of an M31 value
/// `(v, 0, 0, 0)`. `m31_to_u32` rejects the non-canonical representation of 0.
pub fn m31_bytes<Value: IValue>(ctx: &mut Context<Value>, v: Var) -> [Byte; 4] {
    let w = m31_to_u32(ctx, v);
    word_bytes(ctx, w).map(Byte::Var)
}

pub fn digest_bytes<Value: IValue>(ctx: &mut Context<Value>, h: &Digest) -> Vec<Byte> {
    h.iter().flat_map(|w| word_bytes(ctx, U32Wrapper::new_unsafe(*w))).map(Byte::Var).collect()
}

pub fn const_bytes(bytes: &[u8]) -> Vec<Byte> {
    bytes.iter().map(|b| Byte::Const(*b)).collect()
}

/// Words are canonical by construction: each is a combination of checked bytes.
pub fn pack_bytes<Value: IValue>(ctx: &mut Context<Value>, bytes: &[Byte]) -> Vec<Var> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut items = [Byte::Const(0); 4];
            items[..chunk.len()].copy_from_slice(chunk);
            if let [Byte::Const(a), Byte::Const(b), Byte::Const(c), Byte::Const(d)] = items {
                return ctx.constant(*QM31::pack_u32(u32::from_le_bytes([a, b, c, d])).get());
            }
            let vars = items.map(|item| match item {
                Byte::Const(c) => ctx.constant(M31::from(c as u32).into()),
                Byte::Var(v) => v,
            });
            word_from_bytes(ctx, vars)
        })
        .collect()
}

/// Unkeyed Blake2s-256 of a byte message. Returns all eight output words.
pub fn blake2s<Value: IValue>(ctx: &mut Context<Value>, message: &[Byte]) -> Digest {
    let words = pack_bytes(ctx, message);
    blake2s_words(ctx, words, message.len())
}

/// Unkeyed Blake2s-256 of `n_bytes` given as canonical little-endian message words, via
/// upstream `blake2s_u32s`. Bytes past `n_bytes` in the last word must be zero.
pub fn blake2s_words<Value: IValue>(ctx: &mut Context<Value>, words: Vec<Var>, n_bytes: usize) -> Digest {
    assert_eq!(words.len(), n_bytes.div_ceil(4));
    // Every caller builds words from checked bytes, checked limbs or TripleXor-checked guesses.
    let words = words.into_iter().map(U32Wrapper::new_unsafe).collect();
    blake2s_u32s(ctx, words, n_bytes).0.map(|w| *w.get())
}

/// `crypto::ro(tag, parts)`: domain, u64 lengths and parts, all little-endian.
pub fn ro<Value: IValue>(ctx: &mut Context<Value>, tag: &[u8], parts: &[Vec<Byte>]) -> Digest {
    let mut m = const_bytes(DOMAIN);
    m.extend(const_bytes(&(tag.len() as u64).to_le_bytes()));
    m.extend(const_bytes(tag));
    m.extend(const_bytes(&(parts.len() as u64).to_le_bytes()));
    for p in parts {
        m.extend(const_bytes(&(p.len() as u64).to_le_bytes()));
        m.extend_from_slice(p);
    }
    blake2s(ctx, &m)
}

/// Guesses `bytes` as checked variable bytes.
pub fn guess_bytes<Value: IValue>(ctx: &mut Context<Value>, bytes: &[u8]) -> Vec<Byte> {
    bytes
        .iter()
        .map(|b| {
            let v = guess_m31(ctx, *b as u32);
            check_byte(ctx, v);
            Byte::Var(v)
        })
        .collect()
}

pub fn digest_value(ctx: &Context<QM31>, h: &Digest) -> [u8; 32] {
    let mut out = [0; 32];
    for (i, w) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&ctx.get(*w).unpack_u32().to_le_bytes());
    }
    out
}
