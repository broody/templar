//! `crypto::Transcript` and `crypto::Coins` inside the circuit.
use crate::ro::{Byte, Digest, const_bytes, digest_bytes, ro};
use circuits::blake::m31_to_u32;
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::{IValue, qm31_from_u32s};
use circuits::ops::{eq, from_partial_evals, pointwise_mul};
use stwo::core::fields::m31::M31;

pub struct Transcript {
    x: Vec<Byte>,
    sigma: Vec<Byte>,
    phase: u32,
}

impl Transcript {
    pub fn new<Value: IValue>(ctx: &mut Context<Value>, x: Vec<Byte>) -> Self {
        let h = ro(ctx, b"public", &[x.clone()]);
        let sigma = digest_bytes(ctx, &h);
        Self { x, sigma, phase: 0 }
    }
    /// `sigma = ro("state", [phase, root, sigma])`. `root` is 32 checked bytes.
    pub fn commit<Value: IValue>(&mut self, ctx: &mut Context<Value>, root: &[Byte]) {
        assert_eq!(root.len(), 32);
        let parts = [const_bytes(&self.phase.to_le_bytes()), root.to_vec(), self.sigma.clone()];
        let h = ro(ctx, b"state", &parts);
        self.sigma = digest_bytes(ctx, &h);
        self.phase += 1;
    }
    pub fn sigma(&self) -> &[Byte] {
        &self.sigma
    }
    pub fn coins(&self) -> Coins {
        Coins { x: self.x.clone(), sigma: self.sigma.clone(), phase: self.phase, block: 0, words: vec![], at: 8 }
    }
}

pub struct Coins {
    x: Vec<Byte>,
    sigma: Vec<Byte>,
    phase: u32,
    block: u32,
    words: Vec<Var>,
    at: usize,
}

impl Coins {
    /// Next little-endian u32 coin word, as a canonical packed Blake output word.
    pub fn word<Value: IValue>(&mut self, ctx: &mut Context<Value>) -> Var {
        if self.at == 8 {
            let parts = [
                self.x.clone(),
                self.sigma.clone(),
                const_bytes(&self.phase.to_le_bytes()),
                const_bytes(&self.block.to_le_bytes()),
            ];
            let h: Digest = ro(ctx, b"coins", &parts);
            // A block yields 8 words; a phase may consume fewer.
            for w in &h {
                ctx.mark_as_maybe_unused(w);
            }
            self.words = h.to_vec();
            self.block += 1;
            self.at = 0;
        }
        self.at += 1;
        self.words[self.at - 1]
    }

    /// `Coins::field` with the first candidate required valid. Returns the QM31
    /// value `m0 + m1 i + m2 u + m3 iu`, `m_j = word_j & 0x7fffffff`, each `< p`.
    pub fn field<Value: IValue>(&mut self, ctx: &mut Context<Value>) -> Var {
        let m: [Var; 4] = std::array::from_fn(|_| {
            let w = self.word(ctx);
            masked_m31(ctx, w)
        });
        from_partial_evals(ctx, m)
    }
}

/// Low 16-bit limb of a canonical packed word, as `(lo, 0, 0, 0)`.
pub fn low_limb<Value: IValue>(ctx: &mut Context<Value>, w: Var) -> Var {
    let e0 = ctx.constant(qm31_from_u32s(1, 0, 0, 0));
    pointwise_mul(ctx, w, e0)
}

/// High 16-bit limb of a canonical packed word, as `(hi, 0, 0, 0)`.
pub fn high_limb<Value: IValue>(ctx: &mut Context<Value>, w: Var) -> Var {
    let e1 = ctx.constant(qm31_from_u32s(0, 1, 0, 0));
    let minus_i = ctx.constant(qm31_from_u32s(0, M31::from(-1).0, 0, 0));
    let hi_i = pointwise_mul(ctx, w, e1);
    eval!(ctx, (hi_i) * (minus_i))
}

/// `(w & 0x7fffffff)` as a canonical M31 value, rejecting `0x7fffffff` (= p).
/// `hi = h15 + 2^15 t` with boolean `t`; `m31_to_u32(lo + 2^16 h15)` must equal
/// `(lo, h15)`, which bounds `h15 <= 2^15 - 1` and excludes the integer p.
pub fn masked_m31<Value: IValue>(ctx: &mut Context<Value>, w: Var) -> Var {
    let native = ctx.get(w).unpack_u32();
    let lo = low_limb(ctx, w);
    let hi = high_limb(ctx, w);
    let t = crate::ro::guess_m31(ctx, native >> 31);
    let zero = ctx.zero();
    let boolean = eval!(ctx, (t) * ((t) - (1)));
    eq(ctx, boolean, zero);
    let c15 = ctx.constant(M31::from(1 << 15).into());
    let c16 = ctx.constant(M31::from(1 << 16).into());
    let h15 = eval!(ctx, (hi) - ((t) * (c15)));
    let m = eval!(ctx, (lo) + ((h15) * (c16)));
    let e1 = ctx.constant(qm31_from_u32s(0, 1, 0, 0));
    let expected = eval!(ctx, (lo) + ((h15) * (e1)));
    let canonical = m31_to_u32(ctx, m);
    eq(ctx, *canonical.get(), expected);
    m
}
