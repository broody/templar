//! Query indices and circle-domain points from boolean index bits.
//!
//! A coset point `initial + k step` is built by one conditional group addition
//! per bit of `k` with constant increments. Coordinates are base-field values
//! `(v, 0, 0, 0)`. Native values from stwo are only used to check tests.
use crate::merkle::guess_bits;
use crate::transcript::low_limb;
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::IValue;
use circuits::ops::{eq, inv};
use stwo::core::circle::{CirclePoint, Coset};
use stwo::core::fields::m31::M31;
use stwo::core::poly::circle::CanonicCoset;

use crate::native::{LOG_D, LOG_H, previous_indices};

pub type Point = (Var, Var);

fn constant<Value: IValue>(ctx: &mut Context<Value>, v: M31) -> Var {
    ctx.constant(v.into())
}

/// `p + q` for constant `q`: `(x qx - y qy, x qy + y qx)`.
fn add_const<Value: IValue>(ctx: &mut Context<Value>, p: Point, q: CirclePoint<M31>) -> Point {
    let (qx, qy) = (constant(ctx, q.x), constant(ctx, q.y));
    let (x, y) = p;
    (eval!(ctx, ((x) * (qx)) - ((y) * (qy))), eval!(ctx, ((x) * (qy)) + ((y) * (qx))))
}

fn select<Value: IValue>(ctx: &mut Context<Value>, bit: Var, a: Var, b: Var) -> Var {
    eval!(ctx, (a) + ((bit) * ((b) - (a))))
}

/// `initial + sum_s bit_s * (2^s step)`, with `bits[s]` the coefficient of `2^s step`.
pub fn coset_point<Value: IValue>(ctx: &mut Context<Value>, coset: Coset, bits: &[Var]) -> Point {
    let init = coset.initial();
    let mut p = (constant(ctx, init.x), constant(ctx, init.y));
    for (s, bit) in bits.iter().enumerate() {
        let inc = (coset.step_size * (1usize << s)).to_point();
        let q = add_const(ctx, p, inc);
        p = (select(ctx, *bit, p.0, q.0), select(ctx, *bit, p.1, q.1));
    }
    p
}

/// `poly::point(LOG_D, i)`: domain point at `bit_reverse(i, 13)`. Bit 0 of `i`
/// selects the conjugate half; bits 1..12 give `k` in reversed order.
pub fn domain_point<Value: IValue>(ctx: &mut Context<Value>, i_bits: &[Var]) -> Point {
    assert_eq!(i_bits.len(), LOG_D as usize);
    let half = CanonicCoset::new(LOG_D).circle_domain().half_coset;
    let k_bits: Vec<Var> = (0..LOG_D as usize - 1).map(|s| i_bits[LOG_D as usize - 1 - s]).collect();
    let (x, y) = coset_point(ctx, half, &k_bits);
    let b0 = i_bits[0];
    let two_b0 = eval!(ctx, (b0) + (b0));
    let conj_y = eval!(ctx, (y) - ((two_b0) * (y)));
    (x, conj_y)
}

/// Thirteen query bits from a coin word: `word & (D - 1)`. The low limb is
/// decomposed into 16 booleans, so the three unused bits are bound too.
pub fn query_bits<Value: IValue>(ctx: &mut Context<Value>, word: Var) -> Vec<Var> {
    let native = ctx.get(word).unpack_u32() as usize & 0xffff;
    let lo = low_limb(ctx, word);
    let bits = guess_bits(ctx, native, 16);
    let mut acc = ctx.zero();
    for (k, &b) in bits.iter().enumerate() {
        let c = constant(ctx, M31::from(1u32 << k));
        acc = eval!(ctx, (acc) + ((b) * (c)));
    }
    eq(ctx, acc, lo);
    bits[..LOG_D as usize].to_vec()
}

/// Bits of `previous_indices(LOG_D)[i]`, checked by `point(prev) == point(i) - step_H`.
/// `native_i` only chooses the witness; the check binds the result to `p`.
pub fn previous_bits<Value: IValue>(ctx: &mut Context<Value>, native_i: usize, p: Point) -> (Vec<Var>, Point) {
    let prev = previous_indices(LOG_D)[native_i];
    let bits = guess_bits(ctx, prev, LOG_D);
    let q = domain_point(ctx, &bits);
    let minus_step = -CanonicCoset::new(LOG_H).step();
    let expected = add_const(ctx, p, minus_step);
    eq(ctx, q.0, expected.0);
    eq(ctx, q.1, expected.1);
    (bits, q)
}

/// Inverse of the fold twiddle for a query with index bits `q_bits` at `layer`:
/// layer 0 uses `point(LOG_D, j & !1).y`; layer `l >= 1` uses the x-coordinate of
/// `line_domain(l).at(bit_reverse(j & !1, 13 - l))` with `j = q >> l`.
pub fn fold_twiddle_inv<Value: IValue>(ctx: &mut Context<Value>, layer: usize, q_bits: &[Var]) -> Var {
    let n = LOG_D as usize - layer;
    // bit_reverse over n bits of (j & !1): k bit s = bit (n-1-s) of j = bit (n-1-s+layer) of q, s < n-1.
    let k_bits: Vec<Var> = (0..n - 1).map(|s| q_bits[n - 1 - s + layer]).collect();
    let t = if layer == 0 {
        let half = CanonicCoset::new(LOG_D).circle_domain().half_coset;
        let (x, y) = coset_point(ctx, half, &k_bits);
        ctx.mark_as_maybe_unused(&x);
        y
    } else {
        let coset = Coset::half_odds(LOG_D - 1).repeated_double((layer - 1) as u32);
        let (x, y) = coset_point(ctx, coset, &k_bits);
        ctx.mark_as_maybe_unused(&y);
        x
    };
    inv(ctx, t)
}
