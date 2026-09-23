//! OOD sampling and `poly::check_ood` inside the circuit.
use crate::air::{self, C, SELS, W};
use crate::sym::{Sym, compile};
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::{IValue, qm31_from_u32s};
use circuits::ops::{conj, div, eq, inv, pointwise_mul};
use stwo::core::circle::{CirclePoint, Coset};
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::M31;
use stwo::core::poly::circle::CanonicCoset;

use crate::native::{LOG_D, LOG_H};

/// A point with QM31 coordinates.
pub type EfPoint = (Var, Var);

/// `p + q` for a constant base-field point `q`.
pub fn add_const(ctx: &mut Context<impl IValue>, p: EfPoint, q: CirclePoint<M31>) -> EfPoint {
    let (qx, qy) = (ctx.constant(q.x.into()), ctx.constant(q.y.into()));
    let (x, y) = p;
    (eval!(ctx, ((x) * (qx)) - ((y) * (qy))), eval!(ctx, ((x) * (qy)) + ((y) * (qx))))
}

fn double_x(ctx: &mut Context<impl IValue>, x: Var) -> Var {
    let sx = eval!(ctx, (x) * (x));
    eval!(ctx, ((sx) + (sx)) - (1))
}

/// `coset_vanishing(coset, p)`.
pub fn coset_vanishing(ctx: &mut Context<impl IValue>, coset: Coset, p: EfPoint) -> Var {
    let shift = -coset.initial + coset.step_size.half().to_point();
    // Only the x-coordinate of `p + shift` is needed: `x qx - y qy`.
    let (qx, qy) = (ctx.constant(shift.x.into()), ctx.constant(shift.y.into()));
    let (px, py) = p;
    let mut x = eval!(ctx, ((px) * (qx)) - ((py) * (qy)));
    for _ in 1..coset.log_size {
        x = double_x(ctx, x);
    }
    x
}

pub fn zh(ctx: &mut Context<impl IValue>, log: u32, p: EfPoint) -> Var {
    coset_vanishing(ctx, CanonicCoset::new(log).coset, p)
}

/// `poly::shift(p) = p - step_H`.
pub fn shift(ctx: &mut Context<impl IValue>, p: EfPoint) -> EfPoint {
    add_const(ctx, p, -CanonicCoset::new(LOG_H).step())
}

fn nonzero(ctx: &mut Context<impl IValue>, v: Var) {
    inv(ctx, v);
}

/// `poly::rational(t)` followed by `poly::valid_ood`, both required to succeed
/// for the first sampled `t`. Nonzero conditions are proven by inverses.
pub fn ood_point(ctx: &mut Context<impl IValue>, t: Var) -> EfPoint {
    let t2 = eval!(ctx, (t) * (t));
    let den = eval!(ctx, (1) + (t2));
    nonzero(ctx, den);
    let xn = eval!(ctx, (1) - (t2));
    let yn = eval!(ctx, (t) + (t));
    let z = (div(ctx, xn, den), div(ctx, yn, den));
    for p in [z, shift(ctx, z)] {
        let (x, y) = p;
        let norm = eval!(ctx, ((x) * (x)) + ((y) * (y)));
        let one = ctx.one();
        eq(ctx, norm, one);
        let a = zh(ctx, LOG_H, p);
        nonzero(ctx, a);
        let b = zh(ctx, LOG_D, p);
        nonzero(ctx, b);
        let cy = conj(ctx, y);
        let d = eval!(ctx, (y) - (cy));
        nonzero(ctx, d);
    }
    z
}

/// Evaluates a circle polynomial with constant coefficients at `p`, exactly as
/// the CPU backend: mappings `[y, x, dbl(x), ...]` reversed, then `fold`.
pub fn eval_poly(ctx: &mut Context<impl IValue>, coeffs: &[M31], p: EfPoint) -> Var {
    let log = coeffs.len().ilog2() as usize;
    assert_eq!(coeffs.len(), 1 << log);
    let mut mappings = vec![p.1];
    let mut x = p.0;
    for k in 1..log {
        mappings.push(x);
        // The backend doubles once more after the last push; that value is unused.
        if k + 1 < log {
            x = double_x(ctx, x);
        }
    }
    mappings.reverse();
    fn fold(ctx: &mut Context<impl IValue>, values: &[M31], factors: &[Var]) -> Var {
        if values.len() == 1 {
            return ctx.constant(values[0].into());
        }
        let (l, r) = values.split_at(values.len() / 2);
        let lhs = fold(ctx, l, &factors[1..]);
        let rhs = fold(ctx, r, &factors[1..]);
        let f = factors[0];
        eval!(ctx, (lhs) + ((rhs) * (f)))
    }
    fold(ctx, coeffs, &mappings)
}

/// Index of the first of the nine root constraints in `air::constraints`.
pub const ROOT_CONSTRAINTS: usize = C - 24 - 9;

/// `air::constraints(row, prev, s, root)` with `root` given as variables. The
/// client code is traced with a zero root; `s[3] * root_j` is then subtracted
/// from exactly the nine root constraints (checked by a test).
pub fn constraints(ctx: &mut Context<impl IValue>, row: &[Var], prev: &[Var], s: &[Var], root: &[Var]) -> Vec<Var> {
    assert_eq!((row.len(), prev.len(), s.len(), root.len()), (W, W, SELS, 9));
    let inputs = Sym::begin(2 * W + SELS);
    let traced = air::constraints(&inputs[..W], &inputs[W..2 * W], &inputs[2 * W..], &[0; 9]);
    assert_eq!(traced.len(), C);
    let all: Vec<Var> = row.iter().chain(prev).chain(s).copied().collect();
    let mut out = compile(ctx, &all, &traced);
    for j in 0..9 {
        let (c, s3, r) = (out[ROOT_CONSTRAINTS + j], s[3], root[j]);
        out[ROOT_CONSTRAINTS + j] = eval!(ctx, (c) - ((s3) * (r)));
    }
    out
}

/// The four base-field coordinates of a QM31 variable, each as `(c, 0, 0, 0)`.
pub fn coords(ctx: &mut Context<impl IValue>, v: Var) -> [Var; 4] {
    std::array::from_fn(|j| {
        let basis: [u32; 4] = std::array::from_fn(|k| (k == j) as u32);
        let e = ctx.constant(qm31_from_u32s(basis[0], basis[1], basis[2], basis[3]));
        let part = pointwise_mul(ctx, v, e);
        if j == 0 {
            return part;
        }
        let unit = qm31_from_u32s(basis[0], basis[1], basis[2], basis[3]);
        let back = ctx.constant(unit.inverse());
        eval!(ctx, (part) * (back))
    })
}

/// `poly::check_ood`: for each j, `sum_k c_k * coord_j(alpha^k) == zh_H(z) * q_j`.
pub fn check_ood(
    ctx: &mut Context<impl IValue>,
    fz: &[Var],
    ftz: &[Var],
    q: &[Var],
    selector_coeffs: &[Vec<M31>],
    alpha: Var,
    z: EfPoint,
    root: &[Var],
) {
    let s: Vec<Var> = selector_coeffs.iter().map(|c| eval_poly(ctx, c, z)).collect();
    let cs = constraints(ctx, fz, ftz, &s, root);
    let mut power = ctx.one();
    let mut acc = [ctx.zero(); 4];
    for (k, c) in cs.into_iter().enumerate() {
        if k > 0 {
            power = eval!(ctx, (power) * (alpha));
        }
        let w = coords(ctx, power);
        for j in 0..4 {
            let (a, wj) = (acc[j], w[j]);
            acc[j] = eval!(ctx, (a) + ((c) * (wj)));
        }
    }
    let v = zh(ctx, LOG_H, z);
    for j in 0..4 {
        let qj = q[j];
        let rhs = eval!(ctx, (v) * (qj));
        eq(ctx, acc[j], rhs);
    }
}
