//! Spike: membership relation as a plain stwo-circuits circuit, checked against the client.
use circuits::context::Context;
use circuits::ivalue::NoValue;
use rand::{SeedableRng, rngs::StdRng};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::air;
use templar_client_verifier_circuit::hash as client_hash;
use templar_client_verifier_circuit::membership::{build, permute};

#[test]
fn permutation_matches_client_record() {
    let mut rng = StdRng::seed_from_u64(1);
    for _ in 0..4 {
        let input: [M31; 24] = std::array::from_fn(|_| M31::from(rand::Rng::gen_range(&mut rng, 0..air::P)));
        assert_eq!(permute(input), client_hash::record(input).1);
    }
}

#[test]
fn circuit_root_matches_client_witness_and_rejects_changes() {
    let (public, private) = air::fresh(&mut StdRng::seed_from_u64(411)).unwrap();
    let mut ctx = Context::<QM31>::new(0);
    let root = build(&mut ctx, &private.secret, &private.siblings, &private.bits);
    let got: Vec<u32> = root.iter().map(|v| ctx.get(*v).to_m31_array()[0].0).collect();
    assert_eq!(got, public.root.to_vec());
    assert!(ctx.is_circuit_valid());
    let mut topo = Context::<NoValue>::new(0);
    build(&mut topo, &private.secret, &private.siblings, &private.bits);
    assert!(topo.circuit == ctx.circuit);
    eprintln!("qm31_ops {} eq {}", ctx.circuit.n_qm31_ops_rows(), ctx.circuit.eq.len());
    // A different secret gives a different root.
    let mut other = private.secret;
    other[0] = (other[0] + 1) % air::P;
    let mut ctx = Context::<QM31>::new(0);
    let root2 = build(&mut ctx, &other, &private.siblings, &private.bits);
    let got2: Vec<u32> = root2.iter().map(|v| ctx.get(*v).to_m31_array()[0].0).collect();
    assert_ne!(got2, public.root.to_vec());
}
