//! Synthetic exact-algebra checks for the reviewed M0 masking candidate.
//! NOT a STARK, soundness test, privacy-qualified artifact, or benchmark.
//! Fixed RNG seeds make fixtures reproducible; they are never prover randomness.
//! Successful output contains check counts only. Failed assertions may print
//! synthetic field values or vectors; all such diagnostics must remain local.
use num_traits::{One, Zero};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde_json::json;
use stwo::core::{
    circle::CirclePoint,
    constraints::{complex_conjugate_line_coeffs, coset_vanishing},
    fields::{ComplexConjugate, FieldExpOps, cm31::CM31, m31::M31, qm31::QM31},
    pcs::quotients::{
        ColumnSampleBatch, PointSample, accumulate_row_quotients, quotient_constants,
    },
    poly::circle::CanonicCoset,
};
use stwo::prover::{
    backend::cpu::{CpuBackend, CpuCirclePoly},
    poly::circle::CircleEvaluation,
};

const P: u32 = 2_147_483_647;
type Point = CirclePoint<QM31>;

fn trim(mut a: Vec<M31>) -> Vec<M31> {
    while a.last().is_some_and(|x| x.is_zero()) {
        a.pop();
    }
    a
}
fn add(a: &[M31], b: &[M31]) -> Vec<M31> {
    let mut c = vec![M31::zero(); a.len().max(b.len())];
    for (i, v) in a.iter().enumerate() {
        c[i] += *v;
    }
    for (i, v) in b.iter().enumerate() {
        c[i] += *v;
    }
    trim(c)
}
fn scale(a: &[M31], s: M31) -> Vec<M31> {
    trim(a.iter().map(|x| *x * s).collect())
}
fn sub(a: &[M31], b: &[M31]) -> Vec<M31> {
    add(a, &scale(b, -M31::one()))
}
fn mul(a: &[M31], b: &[M31]) -> Vec<M31> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut c = vec![M31::zero(); a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            c[i + j] += *x * *y;
        }
    }
    trim(c)
}
fn divrem(a: &[M31], b: &[M31]) -> (Vec<M31>, Vec<M31>) {
    assert!(!b.is_empty());
    let mut r = trim(a.to_vec());
    let mut q = vec![M31::zero(); r.len().saturating_sub(b.len()) + 1];
    let inv = b.last().unwrap().inverse();
    while !r.is_empty() && r.len() >= b.len() {
        let k = r.len() - b.len();
        let c = *r.last().unwrap() * inv;
        q[k] += c;
        for (i, x) in b.iter().enumerate() {
            r[k + i] -= c * *x;
        }
        r = trim(r);
    }
    (trim(q), r)
}
fn eval(a: &[M31], x: QM31) -> QM31 {
    a.iter()
        .rev()
        .fold(QM31::zero(), |v, c| v * x + QM31::from(*c))
}
#[derive(Clone)]
struct Poly {
    a: Vec<M31>,
    b: Vec<M31>,
} // a(x) + y*b(x), y²=1-x².
impl Poly {
    fn at(&self, p: Point) -> QM31 {
        eval(&self.a, p.x) + p.y * eval(&self.b, p.x)
    }
    fn plus(&self, other: &Self) -> Self {
        Self {
            a: add(&self.a, &other.a),
            b: add(&self.b, &other.b),
        }
    }
    fn minus(&self, other: &Self) -> Self {
        Self {
            a: sub(&self.a, &other.a),
            b: sub(&self.b, &other.b),
        }
    }
    fn scaled(&self, s: M31) -> Self {
        Self {
            a: scale(&self.a, s),
            b: scale(&self.b, s),
        }
    }
    fn times(&self, other: &Self) -> Self {
        Self {
            a: add(
                &mul(&self.a, &other.a),
                &mul(
                    &mul(&self.b, &other.b),
                    &[M31::one(), M31::zero(), -M31::one()],
                ),
            ),
            b: add(&mul(&self.a, &other.b), &mul(&self.b, &other.a)),
        }
    }
    fn divide(&self, z: &[M31]) -> (Self, Self) {
        let (a, ra) = divrem(&self.a, z);
        let (b, rb) = divrem(&self.b, z);
        (Self { a, b }, Self { a: ra, b: rb })
    }
    fn is_zero(&self) -> bool {
        self.a.is_empty() && self.b.is_empty()
    }
    fn degree(&self) -> usize {
        self.a.len().saturating_sub(1).max(self.b.len())
    }
}
fn field(rng: &mut StdRng) -> M31 {
    M31::from(rng.gen_range(0..P))
}
fn secure(rng: &mut StdRng) -> QM31 {
    QM31::from_m31_array(std::array::from_fn(|_| field(rng)))
}
fn random_poly(rng: &mut StdRng, na: usize, nb: usize) -> Poly {
    Poly {
        a: (0..na).map(|_| field(rng)).collect(),
        b: (0..nb).map(|_| field(rng)).collect(),
    }
}
fn zerofier() -> Poly {
    let mut a = vec![M31::zero(), M31::one()];
    for _ in 1..8 {
        a = sub(&scale(&mul(&a, &a), M31::from(2)), &[M31::one()]);
    }
    Poly { a, b: vec![] }
}
fn domain(log: u32) -> Vec<Point> {
    let d = CanonicCoset::new(log).circle_domain();
    (0..d.size()).map(|i| d.at(i).into_ef()).collect()
}
fn sample_ood(rng: &mut StdRng, h: &[Point], d: &[Point]) -> Point {
    loop {
        let t = secure(rng);
        let den = QM31::one() + t * t;
        if den.is_zero() {
            continue;
        }
        let z = Point {
            x: (QM31::one() - t * t) / den,
            y: (t + t) / den,
        };
        if z.y != z.y.complex_conjugate() && !h.contains(&z) && !d.contains(&z) {
            return z;
        }
    }
}
fn base(x: QM31) -> M31 {
    let c = x.to_m31_array();
    assert!(c[1..].iter().all(Zero::is_zero));
    c[0]
}
// Same basis as the specification, with its full 65-dimensional space.
fn mask_basis(j: usize) -> Poly {
    if j < 33 {
        let mut a = vec![M31::zero(); j + 1];
        a[j] = M31::one();
        Poly { a, b: vec![] }
    } else {
        let mut b = vec![M31::zero(); j - 33 + 1];
        b[j - 33] = M31::one();
        Poly { a: vec![], b }
    }
}
fn from_mask_coeffs(v: &[M31]) -> Poly {
    assert_eq!(v.len(), 65);
    Poly {
        a: trim(v[..33].to_vec()),
        b: trim(v[33..].to_vec()),
    }
}
fn observations(f: &Poly, z: Point, queries: &[Point]) -> Vec<M31> {
    let mut out = f.at(z).to_m31_array().to_vec();
    out.extend(queries.iter().map(|p| base(f.at(*p))));
    out
}
fn matrix(z: Point, queries: &[Point], zh: Option<&Poly>) -> Vec<Vec<M31>> {
    let mut rows = vec![vec![M31::zero(); 65]; 4 + queries.len()];
    for j in 0..65 {
        let f = mask_basis(j);
        let f = zh.map_or(f.clone(), |v| v.times(&f));
        for (i, v) in observations(&f, z, queries).into_iter().enumerate() {
            rows[i][j] = v;
        }
    }
    rows
}
// Exact elimination, no least-squares approximation. Free variables set to zero.
fn solve(mut a: Vec<Vec<M31>>, rhs: &[M31]) -> (usize, Vec<M31>) {
    assert_eq!(a.len(), rhs.len());
    let n = a[0].len();
    for (row, v) in a.iter_mut().zip(rhs) {
        row.push(*v);
    }
    let mut pivots = vec![];
    for col in 0..n {
        let row = pivots.len();
        let Some(k) = (row..a.len()).find(|i| !a[*i][col].is_zero()) else {
            continue;
        };
        a.swap(row, k);
        let inv = a[row][col].inverse();
        for j in col..=n {
            a[row][j] *= inv;
        }
        let pivot = a[row].clone();
        for i in 0..a.len() {
            if i != row {
                let c = a[i][col];
                for j in col..=n {
                    a[i][j] -= c * pivot[j];
                }
            }
        }
        pivots.push(col);
        if pivots.len() == a.len() {
            break;
        }
    }
    for row in &a[pivots.len()..] {
        assert!(row[..n].iter().any(|x| !x.is_zero()) || row[n].is_zero());
    }
    let mut out = vec![M31::zero(); n];
    for (i, j) in pivots.iter().enumerate() {
        out[*j] = a[i][n];
    }
    (pivots.len(), out)
}
#[derive(Clone)]
struct FftPoly([CpuCirclePoly; 4]);
impl FftPoly {
    fn interpolate(log: u32, f: impl Fn(Point) -> QM31) -> Self {
        let d = CanonicCoset::new(log).circle_domain();
        let vals = (0..d.size())
            .map(|i| f(d.at(i).into_ef()).to_m31_array())
            .collect::<Vec<_>>();
        Self(std::array::from_fn(|k| {
            CircleEvaluation::<CpuBackend, M31>::new(d, vals.iter().map(|v| v[k]).collect())
                .bit_reverse()
                .interpolate()
        }))
    }
    fn at(&self, p: Point) -> QM31 {
        QM31::from_partial_evals(std::array::from_fn(|i| self.0[i].eval_at_point(p)))
    }
    fn coeffs(&self) -> Vec<QM31> {
        (0..self.0[0].coeffs.len())
            .map(|j| QM31::from_m31_array(std::array::from_fn(|i| self.0[i].coeffs[j])))
            .collect()
    }
    fn from_coeffs(c: &[QM31]) -> Self {
        Self(std::array::from_fn(|i| {
            CpuCirclePoly::new(c.iter().map(|v| v.to_m31_array()[i]).collect())
        }))
    }
    fn random(rng: &mut StdRng) -> Self {
        Self::from_coeffs(&(0..512).map(|_| secure(rng)).collect::<Vec<_>>())
    }
    fn combine(&self, other: &Self, scale: QM31) -> Self {
        Self::from_coeffs(
            &self
                .coeffs()
                .iter()
                .zip(other.coeffs())
                .map(|(a, b)| *a + scale * b)
                .collect::<Vec<_>>(),
        )
    }
    fn values(&self, log: u32) -> Vec<QM31> {
        let d = CanonicCoset::new(log).circle_domain();
        let v = self
            .0
            .each_ref()
            .map(|p| p.evaluate(d).bit_reverse().values);
        (0..d.size())
            .map(|j| QM31::from_m31_array(std::array::from_fn(|i| v[i][j])))
            .collect()
    }
}
fn pair_terms(z: Point, v: QM31, p: Point) -> (QM31, QM31, QM31) {
    let (a, b, c) = complex_conjugate_line_coeffs(&PointSample { point: z, value: v }, QM31::one());
    let embed = |v| QM31(v, CM31::zero());
    let den = (embed(z.x.0) - p.x) * embed(z.y.1) - (embed(z.y.0) - p.y) * embed(z.x.1);
    (a * p.y + b, c, den)
}
fn k_value(z: Point, v: QM31, p: Point, fp: QM31) -> QM31 {
    let (line, c, den) = pair_terms(z, v, p);
    assert!(!den.is_zero());
    (c * fp - line) / den
}
fn batch(f: &[Poly; 3], z: Point, lambda: QM31, d: &[Point]) -> FftPoly {
    let claims = f.each_ref().map(|p| p.at(z));
    let raw = f.each_ref().map(|p| FftPoly::interpolate(9, |x| p.at(x)));
    let k: [FftPoly; 3] =
        std::array::from_fn(|i| FftPoly::interpolate(9, |p| k_value(z, claims[i], p, f[i].at(p))));
    // Check identities at 4096 distinct points, exceeding their algebraic zero bounds.
    for i in 0..3 {
        let kv = k[i].values(12);
        let fv = raw[i].values(12);
        for (j, p) in d.iter().enumerate() {
            assert_eq!(fv[j], f[i].at(*p));
            let (line, c, den) = pair_terms(z, claims[i], *p);
            assert_eq!(kv[j] * den, c * fv[j] - line);
        }
    }
    let all = [&raw[0], &raw[1], &raw[2], &k[0], &k[1], &k[2]];
    let mut g = FftPoly::from_coeffs(&vec![QM31::zero(); 512]);
    let mut power = lambda;
    for p in all {
        g = g.combine(p, power);
        power *= lambda;
    }
    g
}
struct AlgebraView {
    z: Point,
    lambda: QM31,
    queries: Vec<Point>,
    claims: [QM31; 3],
    raw: Vec<[QM31; 3]>,
    r: Vec<QM31>,
    h: FftPoly,
}
fn view(
    f: &[Poly; 3],
    r: &FftPoly,
    g: &FftPoly,
    z: Point,
    lambda: QM31,
    queries: &[Point],
) -> AlgebraView {
    AlgebraView {
        z,
        lambda,
        queries: queries.to_vec(),
        claims: f.each_ref().map(|p| p.at(z)),
        raw: queries
            .iter()
            .map(|p| f.each_ref().map(|f| f.at(*p)))
            .collect(),
        r: queries.iter().map(|p| r.at(*p)).collect(),
        h: r.combine(g, QM31::one()),
    }
}
// This checker receives only the declared algebraic view, never raw private tables.
// It does not verify commitments, FRI, degree soundness, or oracle timing.
fn check_view(c: &Poly, zh: &Poly, v: &AlgebraView) -> bool {
    if v.claims[0] * v.claims[1] - c.at(v.z) != zh.at(v.z) * v.claims[2] {
        return false;
    }
    for (i, p) in v.queries.iter().enumerate() {
        let mut rhs = v.r[i];
        let mut power = v.lambda;
        for x in v.raw[i] {
            rhs += power * x;
            power *= v.lambda;
        }
        for j in 0..3 {
            rhs += power * k_value(v.z, v.claims[j], *p, v.raw[i][j]);
            power *= v.lambda;
        }
        if v.h.at(*p) != rhs {
            return false;
        }
    }
    true
}
fn simulate(
    c: &Poly,
    zh: &Poly,
    z: Point,
    lambda: QM31,
    queries: &[Point],
    d: &[Point],
    rng: &mut StdRng,
) -> AlgebraView {
    // Only public input and verifier coins; there is no private witness argument.
    let a = random_poly(rng, 33, 32);
    let b = random_poly(rng, 33, 32);
    let q_at = |p| (a.at(p) * b.at(p) - c.at(p)) / zh.at(p);
    let mut qs = q_at(z).to_m31_array().to_vec();
    qs.extend(queries.iter().map(|p| base(q_at(*p))));
    let (rank, coeff) = solve(matrix(z, queries, None), &qs);
    assert_eq!(rank, qs.len());
    let f = [a, b, from_mask_coeffs(&coeff)];
    let r = FftPoly::random(rng);
    let g = batch(&f, z, lambda, d);
    view(&f, &r, &g, z, lambda, queries)
}
fn run_case(seed: u64) -> serde_json::Value {
    let mut rng = StdRng::seed_from_u64(seed);
    let h = domain(8);
    let d = domain(12);
    let zh = zerofier();
    assert_eq!(zh.degree(), 128);
    assert!(h.iter().all(|p| zh.at(*p).is_zero()));
    assert!(d.iter().all(|p| !zh.at(*p).is_zero()));
    for p in &d {
        assert_eq!(zh.at(*p), coset_vanishing(CanonicCoset::new(8).coset, *p));
    }
    let a = random_poly(&mut rng, 128, 128);
    let b = random_poly(&mut rng, 128, 128);
    let (_, c) = a.times(&b).divide(&zh.a);
    let ah = a.plus(&zh.times(&random_poly(&mut rng, 33, 32)));
    let bh = b.plus(&zh.times(&random_poly(&mut rng, 33, 32)));
    let (q, rem) = ah.times(&bh).minus(&c).divide(&zh.a);
    assert!(rem.is_zero());
    assert!(ah.degree() <= 160 && bh.degree() <= 160 && q.degree() <= 192);
    for p in &h {
        assert_eq!(a.at(*p), ah.at(*p));
        assert_eq!(b.at(*p), bh.at(*p));
    }
    let f = [ah, bh, q]; // Freeze base and quotient polynomials before OOD coins.
    let z = sample_ood(&mut rng, &h, &d);
    assert_eq!(
        z.y.pow(u128::from(P) * u128::from(P)),
        z.y.complex_conjugate()
    );
    let r = FftPoly::random(&mut rng); // Freeze R before lambda (honest construction).
    let lambda = secure(&mut rng);
    let mut indices = (0..23)
        .map(|_| rng.gen_range(0..d.len()))
        .collect::<Vec<_>>();
    if seed == 3 {
        indices[22] = indices[0];
    } // Explicit duplicate-opening accounting case.
    indices.sort_unstable();
    indices.dedup();
    let queries = indices.iter().map(|i| d[*i]).collect::<Vec<_>>();
    let g = batch(&f, z, lambda, &d);
    let real = view(&f, &r, &g, z, lambda, &queries);
    assert!(check_view(&c, &zh, &real));
    // Same public c, a distinct witness. Couple masks through exact affine translation.
    let factor = M31::from(7);
    let a2 = a.scaled(factor);
    let b2 = b.scaled(factor.inverse());
    let mut replacements = vec![];
    for (old, new, masked) in [(&a, &a2, &f[0]), (&b, &b2, &f[1])] {
        let rhs = observations(&old.minus(new), z, &queries);
        let (rank, delta) = solve(matrix(z, &queries, Some(&zh)), &rhs);
        assert_eq!(rank, rhs.len());
        let replacement = masked
            .plus(&new.minus(old))
            .plus(&zh.times(&from_mask_coeffs(&delta)));
        assert_eq!(
            observations(masked, z, &queries),
            observations(&replacement, z, &queries)
        );
        replacements.push(replacement);
    }
    let (q2, rem2) = replacements[0]
        .times(&replacements[1])
        .minus(&c)
        .divide(&zh.a);
    assert!(rem2.is_zero());
    let f2 = [replacements[0].clone(), replacements[1].clone(), q2];
    let g2 = batch(&f2, z, lambda, &d);
    let r2 = r.combine(&g, QM31::one()).combine(&g2, -QM31::one()); // Coupling only, not honest prover code.
    let coupled = view(&f2, &r2, &g2, z, lambda, &queries);
    assert_eq!(real.claims, coupled.claims);
    assert_eq!(real.raw, coupled.raw);
    assert_eq!(real.r, coupled.r);
    assert_eq!(real.h.coeffs(), coupled.h.coeffs());
    assert!(check_view(&c, &zh, &coupled));
    // Independent witness-free simulator for the same public input.
    let simulated = simulate(&c, &zh, z, lambda, &queries, &d, &mut rng);
    assert!(check_view(&c, &zh, &simulated));
    // Differential normalization against the existing PCS on the declared raw positions.
    let samples = f.each_ref().map(|p| {
        vec![(
            PointSample {
                point: z,
                value: p.at(z),
            },
            QM31::one(),
        )]
    });
    for j in 0..3 {
        let batches = ColumnSampleBatch::new_vec(&[&samples[j]]);
        let constants = quotient_constants(&batches);
        for p in &queries {
            let bp = CirclePoint {
                x: base(p.x),
                y: base(p.y),
            };
            let got = accumulate_row_quotients(&batches, &[base(f[j].at(*p))], &constants, bp);
            assert_eq!(
                got,
                k_value(
                    z,
                    real.claims[j],
                    *p,
                    real.raw[queries.iter().position(|x| x == p).unwrap()][j]
                )
            );
        }
    }
    // Negative controls are algebraic rejections, NOT invalid-STARK tests.
    let one = Poly {
        a: vec![M31::one()],
        b: vec![],
    };
    let bad_c = c.plus(&one);
    assert!(!check_view(&bad_c, &zh, &real));
    assert!(!f[0].times(&f[1]).minus(&bad_c).divide(&zh.a).1.is_zero());
    let undersized = FftPoly::interpolate(8, |p| f[0].at(p));
    assert!(
        undersized
            .values(12)
            .iter()
            .zip(&d)
            .any(|(v, p)| *v != f[0].at(*p))
    );
    let mut bad_view = view(&f, &r, &g, z, lambda, &queries);
    bad_view.claims[2] += QM31::one();
    assert!(!check_view(&c, &zh, &bad_view));
    let mut bad_r = view(&f, &r, &g, z, lambda, &queries);
    bad_r.r[0] += QM31::one();
    assert!(!check_view(&c, &zh, &bad_r));
    json!({"fixture_seed":seed,"distinct_raw_queries":queries.len(),"observation_coordinates":4+queries.len(),
        "trace_preservation_points":256,"fft_and_pair_identity_points":4096,
        "same_public_input_coupling":true,"complete_h_coefficients_identical":true,
        "witness_free_algebra_simulator":true,"pcs_normalization_matches":true,"negative_controls":5})
}
fn main() {
    let cases = (0..4).map(run_case).collect::<Vec<_>>();
    println!("{}",serde_json::to_string_pretty(&json!({
        "scope":"synthetic exact algebra only; no FRI execution, commitments, soundness or compiled privacy claim",
        "deterministic_fixtures_not_prover_randomness":true,"cases":cases
    })).unwrap());
}
