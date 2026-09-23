//! M4b: the complete verifier circuit on all retained proofs, value-independent
//! topology, and rejection of altered proof contents.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::air;
use templar_client_verifier_circuit::native::{self, Parsed};
use templar_client_verifier_circuit::verify::build;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m31-private-blake/results");

fn load(kind: &str, k: usize) -> (air::Public, Parsed) {
    let public: air::Public = serde_json::from_slice(&std::fs::read(format!("{DIR}/native/public.json")).unwrap()).unwrap();
    let bytes = std::fs::read(format!("{DIR}/{kind}/proof-{k}.bin")).unwrap();
    templar_client_verifier_circuit::oracle_verify(&public, &bytes).unwrap();
    (public.clone(), native::parse(&public, &bytes).unwrap())
}

fn valid(p: &Parsed, root: &[u32; 9]) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut ctx = Context::<QM31>::new(0);
        build(&mut ctx, p, root);
        ctx.is_circuit_valid()
    }))
    .unwrap_or(false)
}

#[test]
fn retained_native_and_browser_proofs_verify_with_one_topology() {
    let (public, p1) = load("native", 1);
    let mut topo = Context::<NoValue>::new(0);
    build(&mut topo, &p1, &public.root);
    let reference = &topo.circuit;
    eprintln!("blake_g {} triple_xor {} m31_to_u32 {}", reference.blake_g_gate.len(), reference.triple_xor.len(), reference.m31_to_u32.len());
    for (kind, k) in [("native", 1), ("native", 2), ("native", 3), ("browser", 1), ("browser", 2), ("browser", 3)] {
        let (public, p) = load(kind, k);
        let mut ctx = Context::<QM31>::new(0);
        build(&mut ctx, &p, &public.root);
        assert!(ctx.is_circuit_valid(), "{kind} proof {k}");
        assert!(&ctx.circuit == reference, "{kind} proof {k} topology");
    }
}

#[test]
fn altered_contents_are_rejected() {
    let (public, p) = load("native", 1);
    let mut wrong_root = public.root;
    wrong_root[0] = (wrong_root[0] + 1) % air::P;
    assert!(!valid(&p, &wrong_root), "public root");
    let first = *p.base.keys().next().unwrap();
    let cases: Vec<(&str, Box<dyn Fn(&mut Parsed)>)> = vec![
        ("claim value", Box::new(|p| p.claims.values[17] = (p.claims.values[17] + 1) % air::P)),
        ("last value", Box::new(|p| p.last.values[0] = (p.last.values[0] + 1) % air::P)),
        ("base value", Box::new(move |p| { let o = p.base.get_mut(&first).unwrap(); o.values[3] = (o.values[3] + 1) % air::P })),
        ("fri value", Box::new(|p| { let o = p.fri[4].values_mut().next().unwrap(); o.values[2] = (o.values[2] + 1) % air::P })),
        ("root byte", Box::new(|p| p.roots[7][5] ^= 1)),
        ("statement byte", Box::new(|p| { let n = p.x.len(); p.x[n - 3] ^= 1 })),
    ];
    for (name, f) in cases {
        let mut bad = native::parse(&public, &std::fs::read(format!("{DIR}/native/proof-1.bin")).unwrap()).unwrap();
        f(&mut bad);
        assert!(!valid(&bad, &public.root), "{name} accepted");
    }
}
