//! M2: in-circuit Merkle authentication of real openings from a retained proof.
use circuits::context::Context;
use circuits::ivalue::{IValue, NoValue};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::air;
use templar_client_verifier_circuit::merkle::{guess_bits, open};
use templar_client_verifier_circuit::native::{self, D, FOLDS, Opening, Parsed};
use templar_client_verifier_circuit::ro::guess_bytes;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m31-private-blake/results/native");

fn retained() -> (air::Public, Vec<u8>, Parsed) {
    let public: air::Public =
        serde_json::from_slice(&std::fs::read(format!("{DIR}/public.json")).unwrap()).unwrap();
    let bytes = std::fs::read(format!("{DIR}/proof-1.bin")).unwrap();
    templar_client_verifier_circuit::oracle_verify(&public, &bytes).unwrap();
    let parsed = native::parse(&public, &bytes).unwrap();
    (public, bytes, parsed)
}

fn one<V: IValue>(ctx: &mut Context<V>, p: &Parsed, id: u32, n: usize, o: &Opening) {
    let root = guess_bytes(ctx, &p.roots[id as usize]);
    let bits = guess_bits(ctx, o.index, n.ilog2());
    open(ctx, id, &bits, &o.values, &o.salt, &o.siblings, &root);
}

fn build<V: IValue>(ctx: &mut Context<V>, p: &Parsed) {
    one(ctx, p, 2, 1, &p.claims);
    one(ctx, p, (native::ROOTS - 1) as u32, 1, &p.last);
    for o in p.base.values().take(2) {
        one(ctx, p, 0, D, o);
    }
    one(ctx, p, 1, D, p.q.values().next().unwrap());
    one(ctx, p, 3, D, p.r.values().next().unwrap());
    for layer in 0..FOLDS {
        one(ctx, p, (4 + layer) as u32, D >> layer, p.fri[layer].values().next().unwrap());
    }
}

#[test]
fn parser_consumes_retained_proofs_exactly() {
    let (public, _, p) = retained();
    assert_eq!(p.draws.len(), 120);
    assert_eq!(p.claims.values.len(), native::CLAIMS);
    for k in [2, 3] {
        let bytes = std::fs::read(format!("{DIR}/proof-{k}.bin")).unwrap();
        native::parse(&public, &bytes).unwrap();
    }
}

#[test]
fn real_openings_authenticate_in_circuit() {
    let (_, _, p) = retained();
    let mut ctx = Context::<QM31>::new(0);
    build(&mut ctx, &p);
    assert!(ctx.is_circuit_valid());
    let mut topo = Context::<NoValue>::new(0);
    build(&mut topo, &p);
    assert_eq!(topo.circuit, ctx.circuit);
    eprintln!("blake_g gates: {}, triple_xor: {}", ctx.circuit.blake_g_gate.len(), ctx.circuit.triple_xor.len());
}

#[test]
fn tampered_openings_are_rejected() {
    let (_, _, p) = retained();
    let o = p.base.values().next().unwrap().clone();
    let tamper = |f: &dyn Fn(&mut Opening, &mut usize)| {
        let mut o = o.clone();
        let mut index = o.index;
        f(&mut o, &mut index);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut ctx = Context::<QM31>::new(0);
            let root = guess_bytes(&mut ctx, &p.roots[0]);
            let bits = guess_bits(&mut ctx, index, D.ilog2());
            open(&mut ctx, 0, &bits, &o.values, &o.salt, &o.siblings, &root);
            ctx.is_circuit_valid()
        }))
        .unwrap_or(false)
    };
    assert!(tamper(&|_, _| {}));
    assert!(!tamper(&|o, _| o.values[700] = (o.values[700] + 1) % air::P));
    assert!(!tamper(&|o, _| o.salt[95] ^= 1));
    assert!(!tamper(&|o, _| o.siblings[12][0] ^= 0x80));
    assert!(!tamper(&|o, _| o.siblings[0][31] ^= 1));
    // Aligned-word boundaries: leading, middle and trailing salt/sibling bytes.
    for k in [0usize, 1, 2, 3, 6, 50, 94] {
        assert!(!tamper(&move |o, _| o.salt[k] ^= 0x10), "salt byte {k}");
    }
    for (level, k) in [(0usize, 0usize), (0, 2), (3, 3), (5, 16), (12, 30)] {
        assert!(!tamper(&move |o, _| o.siblings[level][k] ^= 0x01), "sibling {level} byte {k}");
    }
    assert!(!tamper(&|o, _| o.values[0] = (o.values[0] + 256) % air::P));
    assert!(!tamper(&|o, _| o.values[1190] = (o.values[1190] + (1 << 24)) % air::P));
    assert!(!tamper(&|_, i| *i ^= 1));
    assert!(!tamper(&|_, i| *i ^= 1 << 12));
    let _ = M31::from(0);
}
