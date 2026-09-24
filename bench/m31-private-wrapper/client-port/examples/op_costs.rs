//! Per-gadget qm31_ops row counts, and totals for the full circuit.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use templar_client_verifier_circuit::air::Public;
use templar_client_verifier_circuit::merkle::{guess_bits, open};
use templar_client_verifier_circuit::native;
use templar_client_verifier_circuit::ro::{Byte, check_byte, digest_bytes, guess_bytes, guess_m31, m31_bytes, ro};
use templar_client_verifier_circuit::verify::build;

fn ops(c: &Context<NoValue>) -> usize {
    c.circuit.add.len() + c.circuit.sub.len() + c.circuit.mul.len() + c.circuit.pointwise_mul.len()
}
fn measure(name: &str, f: impl Fn(&mut Context<NoValue>)) {
    let mut c = Context::<NoValue>::new(0);
    let before = ops(&c);
    f(&mut c);
    println!("{name:40} qm31_ops {:>8}  triple_xor {:>6}  blake_g {:>6}  eq {:>6}", ops(&c) - before, c.circuit.triple_xor.len(), c.circuit.blake_g_gate.len(), c.circuit.eq.len());
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let public: Public = serde_json::from_slice(&std::fs::read(&a[1]).unwrap()).unwrap();
    let p = native::parse(&public, &std::fs::read(&a[2]).unwrap()).unwrap();
    measure("check_byte", |c| { let v = guess_m31(c, 1); check_byte(c, v); });
    measure("guess_bytes(1)", |c| { guess_bytes(c, &[1]); });
    measure("m31_bytes", |c| { let v = guess_m31(c, 1); m31_bytes(c, v); });
    measure("digest_bytes", |c| { let h = ro(c, b"x", &[]); digest_bytes(c, &h); });
    measure("ro(node) 161B", |c| { let a = guess_bytes(c, &[0; 32]); let b = guess_bytes(c, &[0; 32]); ro(c, b"node", &[vec![Byte::Const(0); 4], vec![Byte::Const(0); 4], a, b]); });
    let o = p.base.values().next().unwrap();
    measure("open base (W=1191, depth 13)", |c| { let r = guess_bytes(c, &p.roots[0]); let b = guess_bits(c, o.index, 13); open(c, 0, &b, &o.values, &o.salt, &o.siblings, &r); });
    let o = p.q.values().next().unwrap();
    measure("open q (4, depth 13)", |c| { let r = guess_bytes(c, &p.roots[1]); let b = guess_bits(c, o.index, 13); open(c, 1, &b, &o.values, &o.salt, &o.siblings, &r); });
    measure("FULL circuit", |c| { build(c, &p, &public.root); });
}
