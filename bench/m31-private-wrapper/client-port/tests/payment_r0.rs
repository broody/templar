//! R0 payment relation: circuit outputs equal the native reference; broken witnesses fail.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use rand::{SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{self, N_OUTPUTS, Private, Public, build, statement_limbs};

fn outputs(public: &Public, private: &Private) -> (Vec<u32>, bool) {
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, public, private);
    let limbs = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    (limbs, c.is_circuit_valid())
}

#[test]
fn circuit_statement_matches_native_and_topology_is_fixed() {
    let mut rng = StdRng::seed_from_u64(7);
    let (public, private) = payment::fresh(&mut rng);
    let (limbs, valid) = outputs(&public, &private);
    assert!(valid);
    assert_eq!(limbs, statement_limbs(&public));
    let mut real = Context::<QM31>::new(N_OUTPUTS);
    build(&mut real, &public, &private);
    let (public2, private2) = payment::fresh(&mut rng);
    let mut topo = Context::<NoValue>::new(N_OUTPUTS);
    build(&mut topo, &public2, &private2);
    assert!(topo.circuit == real.circuit, "topology depends only on the relation");
    eprintln!("qm31_ops {} eq {}", real.circuit.n_qm31_ops_rows(), real.circuit.eq.len());
}

/// Each tampered witness either fails the circuit or proves a different statement.
#[test]
fn broken_witnesses_are_rejected() {
    let (public, private) = payment::fresh(&mut StdRng::seed_from_u64(8));
    let want = statement_limbs(&public);
    let check = |name: &str, p: Private| {
        let (limbs, valid) = outputs(&public, &p);
        assert!(!valid || limbs != want, "{name} accepted with the same statement");
    };
    let mut p = private.clone();
    p.outputs[0].amount += 1;
    check("inflated output", p);
    let mut p = private.clone();
    p.inputs[0].siblings[5][0] ^= 1;
    check("wrong sibling", p);
    let mut p = private.clone();
    p.inputs[1].position ^= 1 << 20;
    check("wrong position", p);
    let mut p = private.clone();
    p.inputs[0].sk[3] ^= 1;
    check("wrong secret", p);
    let mut p = private.clone();
    p.outputs[1].rho[0] ^= 1;
    check("wrong output rho", p);
}

#[test]
fn native_rules() {
    let (public, private) = payment::fresh(&mut StdRng::seed_from_u64(9));
    let redo = |p: &Private| payment::statement(&public.chain, &public.pool, &public.token, public.deliveries.clone(), p);
    assert_eq!(redo(&private).unwrap(), public);
    let mut p = private.clone();
    p.outputs[0].amount += 1;
    assert!(redo(&p).is_err());
    let mut p = private.clone();
    p.inputs[1] = p.inputs[0].clone();
    assert!(redo(&p).is_err(), "duplicate input");
    let mut p = private.clone();
    p.outputs[1].receiver = [0; 9];
    assert!(redo(&p).is_err());
}

/// The full client pipeline's finalization (unused-variable lint included) accepts the circuit.
#[test]
fn circuit_finalizes_with_lint() {
    let (public, private) = payment::fresh(&mut StdRng::seed_from_u64(10));
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, &public, &private);
    c.set_outputs(&out);
    let f = c.finalize(true);
    f.validate_circuit();
}
