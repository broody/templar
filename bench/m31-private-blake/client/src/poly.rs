use crate::air::{self, P};
use anyhow::{Result, ensure};
use num_traits::{One, Zero};
use rand::{Rng, RngCore};
use std::collections::HashMap;
use stwo::core::{
    circle::{CirclePoint, Coset},
    constraints::{complex_conjugate_line_coeffs, coset_vanishing},
    fields::{ComplexConjugate, cm31::CM31, m31::M31, qm31::QM31},
    pcs::quotients::PointSample,
    poly::{
        circle::{CanonicCoset, CircleDomain},
        line::LineDomain,
    },
    utils::bit_reverse_index,
};
use stwo::prover::{
    backend::cpu::{CpuBackend, CpuCirclePoly},
    fri::FriOps,
    line::LineEvaluation,
    poly::{
        BitReversedOrder,
        circle::{CircleEvaluation, SecureEvaluation},
    },
    secure_column::SecureColumnByCoords,
};
pub type Point = CirclePoint<QM31>;
pub const LOG_H: u32 = 7;
pub const LOG_CAP: u32 = 10;
pub const LOG_D: u32 = 13;
pub const D: usize = 1 << LOG_D;
pub const FOLDS: usize = LOG_CAP as usize;
pub const QUERIES: usize = 120;
pub fn domain(log: u32) -> CircleDomain {
    CanonicCoset::new(log).circle_domain()
}
pub fn point(log: u32, i: usize) -> CirclePoint<M31> {
    domain(log).at(bit_reverse_index(i, log))
}
pub fn shift(p: Point) -> Point {
    p - CanonicCoset::new(LOG_H).step().into_ef()
}
pub fn zh(log: u32, p: Point) -> QM31 {
    coset_vanishing(CanonicCoset::new(log).coset, p)
}
pub fn key(p: CirclePoint<M31>) -> (u32, u32) {
    (p.x.0, p.y.0)
}
pub fn previous_indices(log: u32) -> Vec<usize> {
    let map: HashMap<_, _> = (0..1usize << log)
        .map(|i| (key(point(log, i)), i))
        .collect();
    let step = CanonicCoset::new(LOG_H).step();
    (0..1usize << log)
        .map(|i| map[&key(point(log, i) - step)])
        .collect()
}
pub fn interpolate(log: u32, values: Vec<M31>) -> CpuCirclePoly {
    CircleEvaluation::<CpuBackend, M31, BitReversedOrder>::new(domain(log), values).interpolate()
}
pub fn eval(p: &CpuCirclePoly, log: u32) -> Vec<M31> {
    p.evaluate(domain(log)).values
}
pub fn from_cyclic(values: &[M31]) -> CpuCirclePoly {
    let h = CanonicCoset::new(LOG_H);
    let map: HashMap<_, _> = (0..air::N).map(|i| (key(h.at(i)), values[i])).collect();
    interpolate(
        LOG_H,
        (0..air::N).map(|i| map[&key(point(LOG_H, i))]).collect(),
    )
}
pub fn selector_polys() -> Vec<CpuCirclePoly> {
    (0..air::SELS)
        .map(|j| {
            from_cyclic(
                &(0..air::N)
                    .map(|i| air::selectors(i)[j])
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}
pub fn mask(rows: &[Vec<M31>], rng: &mut impl RngCore) -> Vec<CpuCirclePoly> {
    let zeros: Vec<M31> = (0..1 << LOG_CAP)
        .map(|i| zh(LOG_H, point(LOG_CAP, i).into_ef()).to_m31_array()[0])
        .collect();
    let top: Vec<M31> = (0..1 << LOG_CAP)
        .map(|i| zh(8, point(LOG_CAP, i).into_ef()).to_m31_array()[0])
        .collect();
    (0..air::W)
        .map(|j| {
            let f = from_cyclic(&rows.iter().map(|r| r[j]).collect::<Vec<_>>());
            let r = CpuCirclePoly::new((0..256).map(|_| M31::from(rng.gen_range(0..P))).collect());
            let coefficient = M31::from(rng.gen_range(0..P));
            let fv = eval(&f, LOG_CAP);
            let rv = eval(&r, LOG_CAP);
            interpolate(
                LOG_CAP,
                (0..1 << LOG_CAP)
                    .map(|i| fv[i] + zeros[i] * (rv[i] + coefficient * top[i]))
                    .collect(),
            )
        })
        .collect()
}
pub fn composition_weights(alpha: QM31) -> Vec<[M31; 4]> {
    let mut power = QM31::one();
    (0..air::C)
        .map(|_| {
            let c = power.to_m31_array();
            power *= alpha;
            c
        })
        .collect()
}
pub fn quotients(
    f: &[CpuCirclePoly],
    sels: &[CpuCirclePoly],
    alpha: QM31,
    root: &[u32; 9],
) -> Vec<CpuCirclePoly> {
    let values: Vec<_> = f.iter().map(|p| eval(p, LOG_CAP)).collect();
    let selectors: Vec<_> = sels.iter().map(|p| eval(p, LOG_CAP)).collect();
    let prev = previous_indices(LOG_CAP);
    let weights = composition_weights(alpha);
    let mut qs = vec![vec![M31::zero(); 1 << LOG_CAP]; 4];
    for i in 0..1 << LOG_CAP {
        let row: Vec<_> = values.iter().map(|v| v[i]).collect();
        let before: Vec<_> = values.iter().map(|v| v[prev[i]]).collect();
        let s: Vec<_> = selectors.iter().map(|v| v[i]).collect();
        let cs = air::constraints(&row, &before, &s, root);
        let inv = zh(LOG_H, point(LOG_CAP, i).into_ef()).to_m31_array()[0].inverse();
        for j in 0..4 {
            qs[j][i] = cs.iter().zip(&weights).map(|(c, w)| *c * w[j]).sum::<M31>() * inv;
        }
    }
    qs.into_iter().map(|v| interpolate(LOG_CAP, v)).collect()
}
pub fn check_ood(
    fz: &[QM31],
    ftz: &[QM31],
    q: &[QM31],
    sels: &[CpuCirclePoly],
    alpha: QM31,
    z: Point,
    root: &[u32; 9],
) -> Result<()> {
    let s: Vec<_> = sels.iter().map(|p| p.eval_at_point(z)).collect();
    let cs = air::constraints(fz, ftz, &s, root);
    let weights = composition_weights(alpha);
    for j in 0..4 {
        let value: QM31 = cs.iter().zip(&weights).map(|(c, w)| *c * w[j]).sum();
        ensure!(value == zh(LOG_H, z) * q[j], "OOD composition identity {j}");
    }
    Ok(())
}
pub fn valid_ood(z: Point) -> bool {
    [z, shift(z)].iter().all(|p| {
        p.x * p.x + p.y * p.y == QM31::one()
            && !zh(LOG_H, *p).is_zero()
            && !zh(LOG_D, *p).is_zero()
            && p.y != p.y.complex_conjugate()
    })
}
pub fn rational(t: QM31) -> Option<Point> {
    let den = QM31::one() + t * t;
    if den.is_zero() {
        return None;
    }
    Some(CirclePoint {
        x: (QM31::one() - t * t) / den,
        y: (t + t) / den,
    })
}
#[derive(Clone)]
pub struct Pair {
    pub a: QM31,
    pub b: QM31,
    pub c: QM31,
    pub z: Point,
}
impl Pair {
    pub fn new(z: Point, v: QM31) -> Self {
        let (a, b, c) =
            complex_conjugate_line_coeffs(&PointSample { point: z, value: v }, QM31::one());
        Self { a, b, c, z }
    }
    pub fn denominator(&self, p: Point) -> QM31 {
        let embed = |v| QM31(v, CM31::zero());
        (embed(self.z.x.0) - p.x) * embed(self.z.y.1)
            - (embed(self.z.y.0) - p.y) * embed(self.z.x.1)
    }
    pub fn at(&self, p: Point, value: QM31) -> QM31 {
        (self.c * value - self.a * p.y - self.b) / self.denominator(p)
    }
}
pub fn random_secure(rng: &mut impl RngCore) -> QM31 {
    QM31::from_m31_array(std::array::from_fn(|_| M31::from(rng.gen_range(0..P))))
}
pub fn random_r(rng: &mut impl RngCore) -> Vec<QM31> {
    let cs: Vec<_> = (0..1 << LOG_CAP)
        .map(|_| random_secure(rng).to_m31_array())
        .collect();
    let v: Vec<_> = (0..4)
        .map(|j| {
            eval(
                &CpuCirclePoly::new(cs.iter().map(|x| x[j]).collect()),
                LOG_D,
            )
        })
        .collect();
    (0..D)
        .map(|i| QM31::from_m31_array(std::array::from_fn(|j| v[j][i])))
        .collect()
}
pub fn line_domain(layer: usize) -> LineDomain {
    assert!(layer >= 1);
    LineDomain::new(Coset::half_odds(LOG_D - 1)).repeated_double((layer - 1) as u32)
}
pub fn fold_value(layer: usize, i: usize, a: QM31, b: QM31, challenge: QM31) -> QM31 {
    let x = if layer == 0 {
        point(LOG_D, i & !1).y
    } else {
        let d = line_domain(layer);
        d.at(bit_reverse_index(i & !1, d.log_size()))
    };
    a + b + challenge * ((a - b) * x.inverse())
}
pub fn fold(values: &[QM31], layer: usize, challenge: QM31) -> Vec<QM31> {
    // The real prover uses S-two's CPU implementations. The independent sparse
    // verifier uses fold_value; tests compare them on every position.
    let coords = SecureColumnByCoords::<CpuBackend> {
        columns: std::array::from_fn(|j| values.iter().map(|v| v.to_m31_array()[j]).collect()),
    };
    use stwo::prover::poly::circle::PolyOps;
    let tw = CpuBackend::precompute_twiddles(domain(LOG_D).half_coset);
    let next = if layer == 0 {
        CpuBackend::fold_circle_into_line(
            &SecureEvaluation::<CpuBackend, BitReversedOrder>::new(domain(LOG_D), coords),
            challenge,
            &tw,
        )
    } else {
        CpuBackend::fold_line(
            &LineEvaluation::new(line_domain(layer), coords),
            challenge,
            &tw,
            1,
        )
    };
    next.values.into_iter().collect()
}
