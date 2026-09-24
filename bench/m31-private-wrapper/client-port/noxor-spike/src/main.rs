//! Measurement only: the membership relation proved with an Eq + QM31-ops-only prover
//! (fixed XOR/range tables removed), then natively verified as that two-component statement.
#[allow(dead_code)]
#[path = "../../../../m31-private-blake/client/src/constants.rs"]
mod constants;
#[allow(dead_code)]
#[path = "../../../../m31-private-blake/client/src/hash.rs"]
mod client_hash;
#[path = "../../src/sym.rs"]
mod sym;
#[path = "../../src/membership.rs"]
mod membership;
mod ro {
    use circuits::context::{Context, Var};
    use circuits::ivalue::{IValue, qm31_from_u32s};
    use circuits::ops::{guess, pointwise_mul};
    use stwo::core::fields::m31::M31;
    pub fn guess_m31<V: IValue>(ctx: &mut Context<V>, value: u32) -> Var {
        let g = guess(ctx, V::from_qm31(M31::from(value).into()));
        let e0 = ctx.constant(qm31_from_u32s(1, 0, 0, 0));
        pointwise_mul(ctx, g, e0)
    }
}
mod merkle {
    use circuits::context::{Context, Var};
    use circuits::eval;
    use circuits::ivalue::IValue;
    use circuits::ops::eq;
    pub fn guess_bits<V: IValue>(ctx: &mut Context<V>, index: usize, n: u32) -> Vec<Var> {
        (0..n)
            .map(|k| {
                let b = crate::ro::guess_m31(ctx, ((index >> k) & 1) as u32);
                let zero = ctx.zero();
                let boolean = eval!(ctx, (b) * ((b) - (1)));
                eq(ctx, boolean, zero);
                b
            })
            .collect()
    }
}
use circuit_common::finalize::finalize_context;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{IValue, NoValue, qm31_from_u32s};
use circuits::ops::add_into;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use templar_private_membership::air;

/// Upstream-style blinding restricted to the two remaining components: 45 random
/// qm31_ops rows (x + 0 = x) and 45 random eq rows (x == x).
fn blind<V: IValue>(c: &mut FinalizedContext<V>, rng: &mut impl rand::RngCore) {
    let ctx = &mut c.context;
    for _ in 0..45 {
        for _ in 0..3 {
            let zero = ctx.zero();
            let x = ctx.new_var(V::from_qm31(qm31_from_u32s(rng.next_u32() >> 1, rng.next_u32() >> 1, rng.next_u32() >> 1, rng.next_u32() >> 1)));
            add_into(ctx, x, zero, x);
        }
        let zero = ctx.zero();
        let x = ctx.new_var(V::from_qm31(qm31_from_u32s(rng.next_u32() >> 1, rng.next_u32() >> 1, rng.next_u32() >> 1, rng.next_u32() >> 1)));
        add_into(ctx, x, zero, x);
        circuits::ops::eq(ctx, x, x);
    }
}

fn circuit<V: IValue>(p: &air::Private, rng: &mut impl rand::RngCore) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(9);
    let root = membership::build(&mut c, &p.secret, &p.siblings, &p.bits);
    c.set_outputs(&root);
    let basis = c.constant(qm31_from_u32s(1, 1, 1, 1));
    circuits::ops::eq(&mut c, basis, basis);
    let mut c = c.finalize(true);
    blind(&mut c, rng);
    finalize_context(&mut c);
    c
}

fn main() {
    assert!(std::env::var("TEMPLAR_NOXOR").is_ok(), "set TEMPLAR_NOXOR");
    let bounded: Option<usize> = std::env::var("SPIKE_MAX_FRI_COLUMNS").ok().map(|v| v.parse().unwrap());
    let mut rng = rand::rngs::OsRng;
    let (public, private) = air::fresh(&mut rng).unwrap();
    let topo = circuit::<NoValue>(&private, &mut rand::rngs::OsRng);
    let ctx = circuit::<QM31>(&private, &mut rng);
    assert!(topo.circuit() == ctx.circuit());
    ctx.validate_circuit();
    let pp = PreprocessedCircuit::from_finalized_circuit(topo.circuit());
    drop(topo);
    let config = PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig { log_blowup_factor: 2, log_last_layer_degree_bound: 0, n_queries: 35, fold_step: 4 },
        lifting_log_size: None,
    };
    let start = std::time::Instant::now();
    circuit_prover::prover::prove_and_verify_noxor::<Blake2sMerkleChannel>(&pp, ctx.values(), config, bounded).unwrap();
    let outputs: Vec<u32> = (3..12).map(|a| ctx.values()[a].to_m31_array()[0].0).collect();
    assert_eq!(outputs, public.root.to_vec());
    println!(
        "{{\"trace_log_size\": {}, \"preprocessed_columns\": {}, \"prove_and_verify_seconds\": {:.2}, \"bounded\": {:?}}}",
        pp.trace_log_size, pp.preprocessed_trace.n_columns(), start.elapsed().as_secs_f64(), bounded
    );
}
