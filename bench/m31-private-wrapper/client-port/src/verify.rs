//! Complete `proof::verify` for TMPZK002 as one circuit. The topology depends
//! only on the protocol constants, never on the proof or the statement.
use crate::air::W;
use crate::domain::{domain_point, fold_twiddle_inv, previous_bits, query_bits};
use crate::merkle::{open, open_pair};
use crate::native::{FOLDS, LOG_D, Parsed, QUERIES, ROOTS, previous_indices, selector_coeffs};
use crate::ood::{EfPoint, check_ood, ood_point, shift};
use crate::ro::{Byte, guess_bytes, guess_m31};
use crate::transcript::Transcript;
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::{IValue, qm31_from_u32s};
use circuits::ops::{conj, eq, from_partial_evals, im, inv};
use stwo::core::fields::FieldExpOps;

/// Public-statement variables the circuit exposes to the bridge.
pub struct Statement {
    pub x: Vec<Byte>,
    pub root: Vec<Var>,
}

fn qm31s(ctx: &mut Context<impl IValue>, m31s: &[Var]) -> Vec<Var> {
    m31s.chunks_exact(4).map(|c| from_partial_evals(ctx, c.try_into().unwrap())).collect()
}

/// `QM31(v.0, 0)`: the first CM31 half of `v`.
fn first_half(ctx: &mut Context<impl IValue>, v: Var) -> Var {
    let c = ctx.constant(qm31_from_u32s(1, 1, 0, 0));
    circuits::ops::pointwise_mul(ctx, v, c)
}
/// `QM31(v.1, 0)`: the second CM31 half of `v`, moved to the first.
fn second_half(ctx: &mut Context<impl IValue>, v: Var) -> Var {
    let part = im(ctx, v);
    let u_inv = ctx.constant(qm31_from_u32s(0, 0, 1, 0).inverse());
    eval!(ctx, (part) * (u_inv))
}

/// Per-point data of `Pair`: `c = conj(z).y - z.y` and the denominator parts.
struct Line {
    c: Var,
    x0: Var,
    x1: Var,
    y0: Var,
    y1: Var,
    y: Var,
}
fn line(ctx: &mut Context<impl IValue>, z: EfPoint) -> Line {
    let cy = conj(ctx, z.1);
    let y = z.1;
    let c = eval!(ctx, (cy) - (y));
    Line { c, x0: first_half(ctx, z.0), x1: second_half(ctx, z.0), y0: first_half(ctx, z.1), y1: second_half(ctx, z.1), y }
}
impl Line {
    /// `Pair::denominator(p)` for a base-field point.
    fn den(&self, ctx: &mut Context<impl IValue>, p: (Var, Var)) -> Var {
        let (px, py) = p;
        let (x0, x1, y0, y1) = (self.x0, self.x1, self.y0, self.y1);
        eval!(ctx, (((x0) - (px)) * (y1)) - (((y0) - (py)) * (x1)))
    }
    /// `(a, b)` of `Pair::new(z, v)` with `alpha = 1`.
    fn ab(&self, ctx: &mut Context<impl IValue>, v: Var) -> (Var, Var) {
        let cv = conj(ctx, v);
        let a = eval!(ctx, (cv) - (v));
        let (c, y) = (self.c, self.y);
        let b = eval!(ctx, ((v) * (c)) - ((a) * (y)));
        (a, b)
    }
}

fn fold(ctx: &mut Context<impl IValue>, a: Var, b: Var, twiddle_inv: Var, challenge: Var) -> Var {
    eval!(ctx, ((a) + (b)) + ((challenge) * (((a) - (b)) * (twiddle_inv))))
}

fn select(ctx: &mut Context<impl IValue>, bit: Var, a: Var, b: Var) -> Var {
    eval!(ctx, (a) + ((bit) * ((b) - (a))))
}

pub fn build<V: IValue>(ctx: &mut Context<V>, p: &Parsed, root_values: &[u32; 9]) -> Statement {
    let x = guess_bytes(ctx, &p.x);
    let root: Vec<Var> = root_values.iter().map(|v| guess_m31(ctx, *v)).collect();
    let roots: Vec<Vec<Byte>> = p.roots.iter().map(|r| guess_bytes(ctx, r)).collect();
    assert_eq!(roots.len(), ROOTS);
    let mut t = Transcript::new(ctx, x.clone());
    t.commit(ctx, &roots[0]);
    let alpha = t.coins().field(ctx);
    t.commit(ctx, &roots[1]);
    let tz = t.coins().field(ctx);
    let z = ood_point(ctx, tz);

    let claims = open(ctx, 2, &[], &p.claims.values, &p.claims.salt, &p.claims.siblings, &roots[2]).values;
    let claims = qm31s(ctx, &claims);
    check_ood(ctx, &claims[..W], &claims[W..2 * W], &claims[2 * W..], &selector_coeffs(), alpha, z, &root);

    t.commit(ctx, &roots[2]);
    t.commit(ctx, &roots[3]);
    let lambda = t.coins().field(ctx);
    let mut challenges = vec![];
    for layer in 0..FOLDS {
        t.commit(ctx, &roots[4 + layer]);
        challenges.push(t.coins().field(ctx));
    }
    let last = open(ctx, (ROOTS - 1) as u32, &[], &p.last.values, &p.last.salt, &p.last.siblings, &roots[ROOTS - 1]).values;
    let last = qm31s(ctx, &last)[0];
    t.commit(ctx, &roots[ROOTS - 1]);

    // Query-independent DEEP data: lambda powers and the per-point sums of a, b.
    let lz = line(ctx, z);
    let tzp = shift(ctx, z);
    let lt = line(ctx, tzp);
    let n_weights = 3 * W + 8;
    let mut w = vec![lambda];
    for k in 1..n_weights {
        let prev = w[k - 1];
        w.push(eval!(ctx, (prev) * (lambda)));
    }
    let (mut az, mut bz, mut at, mut bt) = (ctx.zero(), ctx.zero(), ctx.zero(), ctx.zero());
    for col in 0..W {
        let (a, b) = lz.ab(ctx, claims[col]);
        let wz = w[3 * col + 1];
        az = eval!(ctx, (az) + ((wz) * (a)));
        bz = eval!(ctx, (bz) + ((wz) * (b)));
        let (a, b) = lt.ab(ctx, claims[W + col]);
        let wt = w[3 * col + 2];
        at = eval!(ctx, (at) + ((wt) * (a)));
        bt = eval!(ctx, (bt) + ((wt) * (b)));
    }
    for col in 0..4 {
        let (a, b) = lz.ab(ctx, claims[2 * W + col]);
        let wz = w[3 * W + 2 * col + 1];
        az = eval!(ctx, (az) + ((wz) * (a)));
        bz = eval!(ctx, (bz) + ((wz) * (b)));
    }

    let mut coins = t.coins();
    let prev_index = previous_indices(LOG_D);
    for k in 0..QUERIES {
        let word = coins.word(ctx);
        let bits = query_bits(ctx, word);
        let i = p.draws[k];
        let pt = domain_point(ctx, &bits);
        let (pbits, _) = previous_bits(ctx, i, pt);
        let o = &p.base[&i];
        let row = open(ctx, 0, &bits, &o.values, &o.salt, &o.siblings, &roots[0]).values;
        let o = &p.base[&prev_index[i]];
        open(ctx, 0, &pbits, &o.values, &o.salt, &o.siblings, &roots[0]);
        let o = &p.q[&i];
        let qv = open(ctx, 1, &bits, &o.values, &o.salt, &o.siblings, &roots[1]).values;
        let o = &p.r[&i];
        let rv = open(ctx, 3, &bits, &o.values, &o.salt, &o.siblings, &roots[3]).values;
        let r = qm31s(ctx, &rv)[0];

        // batch(): r + raw + (c_z kz - az y - bz)/den_z + (c_t kt - at y - bt)/den_t.
        let (mut raw, mut kz, mut kt) = (ctx.zero(), ctx.zero(), ctx.zero());
        for col in 0..W {
            let f = row[col];
            let (w0, w1, w2) = (w[3 * col], w[3 * col + 1], w[3 * col + 2]);
            raw = eval!(ctx, (raw) + ((w0) * (f)));
            kz = eval!(ctx, (kz) + ((w1) * (f)));
            kt = eval!(ctx, (kt) + ((w2) * (f)));
        }
        for col in 0..4 {
            let f = qv[col];
            let (w0, w1) = (w[3 * W + 2 * col], w[3 * W + 2 * col + 1]);
            raw = eval!(ctx, (raw) + ((w0) * (f)));
            kz = eval!(ctx, (kz) + ((w1) * (f)));
        }
        let py = pt.1;
        let dz = lz.den(ctx, pt);
        let dz_inv = inv(ctx, dz);
        let dt = lt.den(ctx, pt);
        let dt_inv = inv(ctx, dt);
        let (cz, ct) = (lz.c, lt.c);
        let term_z = eval!(ctx, ((((cz) * (kz)) - ((az) * (py))) - (bz)) * (dz_inv));
        let term_t = eval!(ctx, ((((ct) * (kt)) - ((at) * (py))) - (bt)) * (dt_inv));
        let mut expected = eval!(ctx, (((r) + (raw)) + (term_z)) + (term_t));

        for layer in 0..FOLDS {
            let j = i >> layer;
            let (even, odd) = (&p.fri[layer][&(j & !1)], &p.fri[layer][&((j & !1) + 1)]);
            let (ev, ov) = open_pair(
                ctx,
                (4 + layer) as u32,
                &bits[layer..],
                (&even.values, &even.salt),
                (&odd.values, &odd.salt),
                &even.siblings,
                &roots[4 + layer],
            );
            let (a, b) = (qm31s(ctx, &ev)[0], qm31s(ctx, &ov)[0]);
            let chosen = select(ctx, bits[layer], a, b);
            eq(ctx, chosen, expected);
            let tw = fold_twiddle_inv(ctx, layer, &bits);
            expected = fold(ctx, a, b, tw, challenges[layer]);
        }
        eq(ctx, expected, last);
    }
    Statement { x, root }
}

/// Number of public outputs: upstream circuits expose one Blake2s digest (`N_RESERVED` words).
pub const N_OUTPUTS: usize = 8;

/// The statement digest `Blake2s(x || root_0 .. root_8)`, root words as little-endian u32.
/// The root appears inside `x` as JSON text and is also used by the OOD constraints; hashing the
/// constraint root next to `x` binds the two. The pool rebuilds `x` from its own chain, its own
/// address and the root, appends the same 36 bytes and compares digests.
pub fn statement_outputs<V: IValue>(ctx: &mut Context<V>, s: &Statement) -> Vec<Var> {
    let mut message = s.x.clone();
    for r in &s.root {
        message.extend(crate::ro::m31_bytes(ctx, *r));
    }
    crate::ro::blake2s(ctx, &message).to_vec()
}
