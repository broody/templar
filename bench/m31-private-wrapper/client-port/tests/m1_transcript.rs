//! M1: byte-framed `ro`, transcript and coins against the client's independent
//! Python vectors, plus rejection of altered witness values.
use circuits::context::Context;
use circuits::ivalue::{IValue, NoValue};
use serde_json::Value as Json;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::ro::{Byte, digest_value, guess_bytes, ro};
use templar_client_verifier_circuit::transcript::Transcript;

fn vectors() -> Json {
    serde_json::from_str(include_str!("../../../m31-private-blake/client/blake-vectors.json")).unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn ro_case<V: IValue>(ctx: &mut Context<V>, case: &Json) -> templar_client_verifier_circuit::ro::Digest {
    let parts: Vec<Vec<Byte>> = case["parts_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| guess_bytes(ctx, &hex(p.as_str().unwrap())))
        .collect();
    ro(ctx, case["tag"].as_str().unwrap().as_bytes(), &parts)
}

#[test]
fn ro_matches_all_six_independent_domains() {
    for case in vectors()["ro"].as_array().unwrap() {
        let mut ctx = Context::<QM31>::new(0);
        let h = ro_case(&mut ctx, case);
        assert_eq!(digest_value(&ctx, &h).to_vec(), hex(case["digest"].as_str().unwrap()));
        assert!(ctx.is_circuit_valid(), "{}", case["tag"]);
        // Topology does not depend on byte values.
        let mut topo = Context::<NoValue>::new(0);
        ro_case(&mut topo, case);
        assert_eq!(topo.circuit, ctx.circuit);
    }
}

fn transcript_run<V: IValue>(ctx: &mut Context<V>, v: &Json) -> Vec<(Vec<Byte>, Vec<circuits::context::Var>)> {
    let x = guess_bytes(ctx, &hex(v["x"].as_str().unwrap()));
    let mut t = Transcript::new(ctx, x);
    let mut out = vec![];
    for phase in 0..16usize {
        let mut coins = t.coins();
        let words = (0..v["phases"][phase]["words"].as_array().unwrap().len()).map(|_| coins.word(ctx)).collect();
        out.push((t.sigma().to_vec(), words));
        if phase < 15 {
            let root: Vec<u8> = (0..32).map(|i| (phase * 17 + i) as u8).collect();
            let root = guess_bytes(ctx, &root);
            t.commit(ctx, &root);
        }
    }
    out
}

#[test]
fn sixteen_phases_and_120_coin_words_match() {
    let v = vectors();
    let mut ctx = Context::<QM31>::new(0);
    let run = transcript_run(&mut ctx, &v);
    for (phase, (sigma, words)) in run.iter().enumerate() {
        let got: Vec<u8> = sigma
            .iter()
            .map(|b| match b {
                Byte::Var(x) => ctx.get(*x).0.0.0 as u8,
                Byte::Const(c) => *c,
            })
            .collect();
        assert_eq!(got, hex(v["phases"][phase]["sigma"].as_str().unwrap()), "sigma {phase}");
        let expected: Vec<u32> =
            v["phases"][phase]["words"].as_array().unwrap().iter().map(|w| w.as_u64().unwrap() as u32).collect();
        let got: Vec<u32> = words.iter().map(|w| ctx.get(*w).unpack_u32()).collect();
        assert_eq!(got, expected, "coins {phase}");
    }
    assert!(ctx.is_circuit_valid());
}

#[test]
fn field_sampling_masks_top_bit_and_matches_native() {
    let v = vectors();
    let mut ctx = Context::<QM31>::new(0);
    let x = guess_bytes(&mut ctx, &hex(v["x"].as_str().unwrap()));
    let t = Transcript::new(&mut ctx, x);
    let mut coins = t.coins();
    let words: Vec<u32> = v["phases"][0]["words"].as_array().unwrap().iter().map(|w| w.as_u64().unwrap() as u32).collect();
    for k in 0..30 {
        let f = coins.field(&mut ctx);
        let expected: [M31; 4] = std::array::from_fn(|j| M31::from(words[4 * k + j] & 0x7fff_ffff));
        assert_eq!(ctx.get(f), QM31::from_m31_array(expected), "draw {k}");
    }
    assert!(ctx.is_circuit_valid());
}

#[test]
fn altered_bytes_and_limbs_are_rejected() {
    let v = vectors();
    let case = &v["ro"].as_array().unwrap()[4];
    let mut ctx = Context::<QM31>::new(0);
    ro_case(&mut ctx, case);
    let honest = ctx.values().clone();
    assert!(ctx.circuit.check(&honest).is_ok());
    let guessed: Vec<usize> = ctx
        .guessed_vars
        .as_ref()
        .unwrap()
        .iter()
        .map(|g| match g {
            circuits::context::GuessVar::M31(v) | circuits::context::GuessVar::QM31(v) | circuits::context::GuessVar::U16(v) => v.idx,
        })
        .collect();
    // Change the base-field coordinate of guessed byte witnesses: each must
    // break a constraint. Other coordinates of a raw guess are discarded by
    // the projection and never reach a gate input.
    for idx in guessed.iter().step_by(97).take(20) {
        for delta in [QM31::from(M31::from(1)), QM31::from(M31::from(256)), QM31::from(M31::from(-1))] {
            let mut bad = honest.clone();
            bad[*idx] += delta;
            assert!(ctx.circuit.check(&bad).is_err(), "guess {idx} + {delta:?} accepted");
        }
    }
}

#[test]
fn check_byte_rejects_extension_and_out_of_range_values() {
    use circuits::ops::guess;
    use templar_client_verifier_circuit::ro::check_byte;
    let inv256 = M31::from(256).inverse();
    for (x, ok) in [
        (QM31::from(M31::from(0)), true),
        (QM31::from(M31::from(255)), true),
        (QM31::from(M31::from(256)), false),
        (QM31::from(M31::from(65535)), false),
        (QM31::from(inv256), false),
        (QM31::from(M31::from(-1)), false),
        (circuits::ivalue::qm31_from_u32s(5, 1, 0, 0), false),
        (circuits::ivalue::qm31_from_u32s(5, 0, 1, 0), false),
    ] {
        // Witness generation panics on a non-canonical TripleXor input; either
        // outcome is a rejection.
        let valid = std::panic::catch_unwind(|| {
            let mut ctx = Context::<QM31>::new(0);
            let v = guess(&mut ctx, x);
            check_byte(&mut ctx, v);
            ctx.is_circuit_valid()
        })
        .unwrap_or(false);
        assert_eq!(valid, ok, "{x:?}");
    }
}
