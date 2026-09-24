//! Builds circuit A and runs the upstream unused-variable lint without proving.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use templar_client_verifier_circuit::air::Public;
use templar_client_verifier_circuit::native;
use templar_client_verifier_circuit::verify::{N_OUTPUTS, build, statement_outputs};
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let public: Public = serde_json::from_slice(&std::fs::read(&a[1]).unwrap()).unwrap();
    let p = native::parse(&public, &std::fs::read(&a[2]).unwrap()).unwrap();
    let mut c = Context::<NoValue>::new(N_OUTPUTS);
    let s = build(&mut c, &p, &public.root);
    let out = statement_outputs(&mut c, &s);
    c.set_outputs(&out);
    let basis = c.constant(circuits::ivalue::qm31_from_u32s(1, 1, 1, 1));
    circuits::ops::eq(&mut c, basis, basis);
    let uses = c.circuit.compute_multiplicities().0;
    let unused: Vec<usize> = uses.iter().enumerate().filter(|(_, u)| **u == 0).map(|(i, _)| i).collect();
    println!("unused (before maybe-unused filtering): {}", unused.len());
    let circ = &c.circuit;
    let mut kind = std::collections::HashMap::new();
    for g in &circ.add { kind.insert(g.out, "add"); }
    for g in &circ.sub { kind.insert(g.out, "sub"); }
    for g in &circ.mul { kind.insert(g.out, "mul"); }
    for g in &circ.pointwise_mul { kind.insert(g.out, "pointwise_mul"); }
    for g in &circ.triple_xor { kind.insert(g.out, "triple_xor"); }
    for g in &circ.m31_to_u32 { kind.insert(g.out, "m31_to_u32"); }
    for g in &circ.blake_g_gate { for o in [g.out_a, g.out_b, g.out_c, g.out_d] { kind.insert(o, "blake_g"); } }
    let guessed: std::collections::HashSet<usize> = c
        .guessed_vars
        .as_ref()
        .unwrap()
        .iter()
        .map(|g| match g {
            circuits::context::GuessVar::M31(v) | circuits::context::GuessVar::QM31(v) | circuits::context::GuessVar::U16(v) => v.idx,
        })
        .collect();
    let mut counts = std::collections::BTreeMap::new();
    for i in &unused {
        let k = if guessed.contains(i) { "guess" } else { kind.get(i).copied().unwrap_or("constant/other") };
        *counts.entry(k).or_insert(0) += 1;
    }
    println!("unused by producer: {counts:?}");
    println!("first unused: {:?}", &unused[..unused.len().min(12)]);
    c.finalize(true);
    println!("lint clean");
}
