//! M4a: OOD sampling and the composition identity on a real proof, with the
//! client's own constraint code compiled through the symbolic field.
use circuits::context::{Context, Var};
use circuits::ivalue::IValue;
use circuits::ops::{from_partial_evals, guess};
use rand::{Rng, SeedableRng, rngs::StdRng};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::poly::circle::CanonicCoset;
use templar_client_verifier_circuit::air;
use templar_client_verifier_circuit::merkle::{guess_bits, open};
use templar_client_verifier_circuit::native::{self, selector_coeffs};
use templar_client_verifier_circuit::ood::{ROOT_CONSTRAINTS, check_ood, constraints, eval_poly, ood_point};
use templar_client_verifier_circuit::ro::{guess_bytes, guess_m31};
use templar_client_verifier_circuit::transcript::Transcript;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m31-private-blake/results/native");

fn rand_qm31(rng: &mut StdRng) -> QM31 {
    QM31::from_m31_array(std::array::from_fn(|_| M31::from(rng.gen_range(0..air::P))))
}

#[test]
fn root_enters_exactly_nine_constraints() {
    let mut rng = StdRng::seed_from_u64(7);
    let row: Vec<QM31> = (0..air::W).map(|_| rand_qm31(&mut rng)).collect();
    let prev: Vec<QM31> = (0..air::W).map(|_| rand_qm31(&mut rng)).collect();
    let s: Vec<QM31> = (0..air::SELS).map(|_| rand_qm31(&mut rng)).collect();
    let root: [u32; 9] = std::array::from_fn(|_| rng.gen_range(0..air::P));
    let a = air::constraints(&row, &prev, &s, &root);
    let b = air::constraints(&row, &prev, &s, &[0; 9]);
    for k in 0..air::C {
        let expected = if (ROOT_CONSTRAINTS..ROOT_CONSTRAINTS + 9).contains(&k) {
            b[k] - s[3] * QM31::from(M31::from(root[k - ROOT_CONSTRAINTS]))
        } else {
            b[k]
        };
        assert_eq!(a[k], expected, "constraint {k}");
    }
}

#[test]
fn compiled_constraints_match_native_on_random_points() {
    let mut rng = StdRng::seed_from_u64(8);
    for _ in 0..2 {
        let row: Vec<QM31> = (0..air::W).map(|_| rand_qm31(&mut rng)).collect();
        let prev: Vec<QM31> = (0..air::W).map(|_| rand_qm31(&mut rng)).collect();
        let s: Vec<QM31> = (0..air::SELS).map(|_| rand_qm31(&mut rng)).collect();
        let root: [u32; 9] = std::array::from_fn(|_| rng.gen_range(0..air::P));
        let native = air::constraints(&row, &prev, &s, &root);
        let mut ctx = Context::<QM31>::new(0);
        let g = |ctx: &mut Context<QM31>, v: &[QM31]| v.iter().map(|x| guess(ctx, *x)).collect::<Vec<Var>>();
        let (r, p, sv) = (g(&mut ctx, &row), g(&mut ctx, &prev), g(&mut ctx, &s));
        let rv: Vec<Var> = root.iter().map(|x| guess_m31(&mut ctx, *x)).collect();
        let out = constraints(&mut ctx, &r, &p, &sv, &rv);
        for k in 0..air::C {
            assert_eq!(ctx.get(out[k]), native[k], "constraint {k}");
        }
        assert!(ctx.is_circuit_valid());
    }
}

#[test]
fn selector_polynomials_reproduce_selectors_on_the_trace_domain() {
    let coeffs = selector_coeffs();
    let h = CanonicCoset::new(native::LOG_H);
    let mut ctx = Context::<QM31>::new(0);
    for i in [0usize, 1, 2, 63, 64, 65, 100, 127] {
        let p = h.at(i);
        let pt = (ctx.constant(p.x.into()), ctx.constant(p.y.into()));
        for j in 0..air::SELS {
            let v = eval_poly(&mut ctx, &coeffs[j], pt);
            assert_eq!(ctx.get(v), QM31::from(air::selectors(i)[j]), "row {i} selector {j}");
        }
    }
}

fn claims_check<V: IValue>(ctx: &mut Context<V>, p: &native::Parsed, public: &air::Public, claims: &[u32]) {
    let x = guess_bytes(ctx, &p.x);
    let mut t = Transcript::new(ctx, x);
    let roots: Vec<_> = p.roots.iter().map(|r| guess_bytes(ctx, r)).collect();
    t.commit(ctx, &roots[0]);
    let alpha = t.coins().field(ctx);
    t.commit(ctx, &roots[1]);
    let tz = t.coins().field(ctx);
    let z = ood_point(ctx, tz);
    let bits = guess_bits(ctx, 0, 0);
    let opened = open(ctx, 2, &bits, claims, &p.claims.salt, &p.claims.siblings, &roots[2]);
    let qm: Vec<Var> = opened.values.chunks_exact(4).map(|c| from_partial_evals(ctx, c.try_into().unwrap())).collect();
    let w = air::W;
    let root: Vec<Var> = public.root.iter().map(|v| guess_m31(ctx, *v)).collect();
    check_ood(ctx, &qm[..w], &qm[w..2 * w], &qm[2 * w..], &selector_coeffs(), alpha, z, &root);
}

#[test]
fn real_ood_identity_holds_and_tampering_fails() {
    let public: air::Public = serde_json::from_slice(&std::fs::read(format!("{DIR}/public.json")).unwrap()).unwrap();
    let bytes = std::fs::read(format!("{DIR}/proof-1.bin")).unwrap();
    templar_client_verifier_circuit::oracle_verify(&public, &bytes).unwrap();
    let p = native::parse(&public, &bytes).unwrap();
    let mut ctx = Context::<QM31>::new(0);
    claims_check(&mut ctx, &p, &public, &p.claims.values);
    assert!(ctx.is_circuit_valid());
    // A wrong public root must fail the composition identity.
    let mut wrong = public.clone();
    wrong.root[3] = (wrong.root[3] + 1) % air::P;
    let mut ctx = Context::<QM31>::new(0);
    claims_check(&mut ctx, &p, &wrong, &p.claims.values);
    assert!(!ctx.is_circuit_valid());
}
