//! M3: query derivation from the real transcript, domain points, previous-row
//! indices and FRI fold twiddles against stwo.
use circuits::context::{Context, Var};
use circuits::ivalue::{IValue, NoValue};
use stwo::core::circle::Coset;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::poly::line::LineDomain;
use stwo::core::utils::bit_reverse_index;
use templar_client_verifier_circuit::air;
use templar_client_verifier_circuit::domain::{domain_point, fold_twiddle_inv, previous_bits, query_bits};
use templar_client_verifier_circuit::merkle::guess_bits;
use templar_client_verifier_circuit::native::{self, D, FOLDS, LOG_D, point, previous_indices};
use templar_client_verifier_circuit::ro::{Byte, guess_bytes};
use templar_client_verifier_circuit::transcript::Transcript;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m31-private-blake/results/native");

fn m31(ctx: &Context<QM31>, v: Var) -> M31 {
    let [a, b, c, d] = ctx.get(v).to_m31_array();
    assert_eq!([b, c, d], [M31::from(0); 3]);
    a
}

fn transcript_queries<V: IValue>(ctx: &mut Context<V>, p: &native::Parsed) -> (Vec<Byte>, Vec<Vec<Var>>) {
    let x = guess_bytes(ctx, &p.x);
    let mut t = Transcript::new(ctx, x);
    for root in &p.roots {
        let root = guess_bytes(ctx, root);
        t.commit(ctx, &root);
    }
    let mut coins = t.coins();
    let draws = (0..native::QUERIES).map(|_| { let w = coins.word(ctx); query_bits(ctx, w) }).collect();
    (t.sigma().to_vec(), draws)
}

#[test]
fn queries_from_real_transcript_match_native_draws() {
    let public: air::Public =
        serde_json::from_slice(&std::fs::read(format!("{DIR}/public.json")).unwrap()).unwrap();
    for k in 1..=3 {
        let bytes = std::fs::read(format!("{DIR}/proof-{k}.bin")).unwrap();
        let p = native::parse(&public, &bytes).unwrap();
        let mut ctx = Context::<QM31>::new(0);
        let (sigma, draws) = transcript_queries(&mut ctx, &p);
        let sigma: Vec<u8> = sigma.iter().map(|b| match b { Byte::Var(v) => m31(&ctx, *v).0 as u8, Byte::Const(c) => *c }).collect();
        assert_eq!(sigma, p.sigma, "final transcript state {k}");
        for (bits, want) in draws.iter().zip(&p.draws) {
            let got: usize = bits.iter().enumerate().map(|(s, b)| (m31(&ctx, *b).0 as usize) << s).sum();
            assert_eq!(got, *want);
        }
        assert!(ctx.is_circuit_valid());
        let mut topo = Context::<NoValue>::new(0);
        transcript_queries(&mut topo, &p);
        assert_eq!(topo.circuit, ctx.circuit);
    }
}

#[test]
fn domain_points_previous_rows_and_twiddles_match_stwo() {
    let prev = previous_indices(LOG_D);
    let mut ctx = Context::<QM31>::new(0);
    for i in (0..D).step_by(37).chain([0, 1, 2, D - 2, D - 1]) {
        let bits = guess_bits(&mut ctx, i, LOG_D);
        let p = domain_point(&mut ctx, &bits);
        let want = point(LOG_D, i);
        assert_eq!((m31(&ctx, p.0), m31(&ctx, p.1)), (want.x, want.y), "point {i}");
        let (pbits, _) = previous_bits(&mut ctx, i, p);
        let got: usize = pbits.iter().enumerate().map(|(s, b)| (m31(&ctx, *b).0 as usize) << s).sum();
        assert_eq!(got, prev[i]);
        for layer in 0..FOLDS {
            let j = i >> layer;
            let x = if layer == 0 {
                point(LOG_D, j & !1).y
            } else {
                let d = LineDomain::new(Coset::half_odds(LOG_D - 1)).repeated_double((layer - 1) as u32);
                d.at(bit_reverse_index(j & !1, d.log_size()))
            };
            let t = fold_twiddle_inv(&mut ctx, layer, &bits);
            assert_eq!(m31(&ctx, t), x.inverse(), "twiddle {i} layer {layer}");
        }
    }
    assert!(ctx.is_circuit_valid());
}

#[test]
fn wrong_previous_index_is_rejected() {
    for (i, wrong) in [(5usize, 6usize), (100, 101), (D - 1, 0)] {
        let mut ctx = Context::<QM31>::new(0);
        let bits = guess_bits(&mut ctx, i, LOG_D);
        let p = domain_point(&mut ctx, &bits);
        // Honest witness for a different row: the point relation must fail.
        let other = guess_bits(&mut ctx, wrong, LOG_D);
        let _ = domain_point(&mut ctx, &other);
        let (_, _) = previous_bits(&mut ctx, wrong, p);
        assert!(!ctx.is_circuit_valid(), "{i}->{wrong}");
    }
}
