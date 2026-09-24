//! Client proving as a library (`docs/sdk-spec.md` §7.3): the bench wallet's `prove_relation`
//! with fixed parameters and no I/O, clock or unwinding, so it builds for wasm32. Every check
//! returns an error: the hiding budget and native verification of the proof are mandatory.
//!
//! The bench's research provers keep `examples/support` (with its `TEMPLAR_FRI` override); this
//! module is the production path, pinned to the frozen bridge configuration.
use circuit_cairo_serialize::prepare_circuit_proof_for_cairo_verifier;
use circuit_common::finalize::{Profile, add_zk_blinding_for, pad_context_for};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_hash::compute_circuit_hash;
use circuit_prover::prover::{BaseColumnPool, CircuitProof, SimdBackend, prove_circuit_assignment_bounded};
use circuit_prover::verify::verify_circuit_proof;
use circuit_verifier::statement::{all_circuit_components, circuit_component_log_sizes};
use circuits::context::{Context, FinalizedContext, Var};
use circuits::ivalue::{NoValue, qm31_from_u32s};
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};

use crate::membership::Lanes;
use crate::payment::Tree;
use crate::{payment, payment4, policy};

pub type MC = Blake2sMerkleChannel;

/// The bridge FRI configuration: upstream production (`circuit_fri_config.json`: PoW 26, blowup 1,
/// 70 queries, fold 4, last layer 0) with blowup 2 and 35 queries, the same 96-bit line. The
/// deployed statement accounts verify exactly this; a test checks the fork's file.
pub const BRIDGE_FRI: FriConfig =
    FriConfig { pow_bits: 26, log_blowup_factor: 2, log_last_layer_degree_bound: 0, n_queries: 35, fold_step: 4 };

/// Upstream's allowance for non-query openings: two OOD points × 4 coordinates + 2
/// (`cairo_verifier/src/verify.rs`, `NON_QUERY_INFO_LEAK`).
pub const NON_QUERY_INFO_LEAK: usize = 10;

/// Every proof uses the pool's tree format.
pub const TREE: Tree = Tree::Compress;

pub fn config(trace_log_size: u32) -> PcsConfig {
    PcsConfig::from_fri_and_trace_size(BRIDGE_FRI, trace_log_size)
}

/// FRI fold steps for a trace of `trace_log_size`: each layer folds `fold_step` at a time until
/// the last layer.
pub fn fri_fold_schedule(trace_log_size: u32) -> Vec<u32> {
    let mut remaining = trace_log_size - BRIDGE_FRI.log_last_layer_degree_bound;
    let mut steps = vec![];
    while remaining > 0 {
        let s = remaining.min(BRIDGE_FRI.fold_step);
        steps.push(s);
        remaining -= s;
    }
    steps
}

/// Blinding iterations sized for everything a proof opens (math review H1): every FRI layer's
/// full coset per query, plus the out-of-domain samples.
pub fn blinding_budget(trace_log_size: u32) -> usize {
    let per_query: usize = fri_fold_schedule(trace_log_size).iter().map(|s| 1usize << s).sum();
    BRIDGE_FRI.n_queries * per_query + NON_QUERY_INFO_LEAK
}

/// Field values a proof reveals through FRI beyond the trace openings.
pub fn revealed_fri_values(proof: &CircuitProof<Blake2sMerkleHasher>) -> usize {
    let fri = &proof.stark_proof.proof.fri_proof;
    std::iter::once(&fri.first_layer).chain(&fri.inner_layers).map(|l| l.fri_witness.len()).sum::<usize>()
        + fri.last_layer_poly.len()
}

pub fn words(h: Blake2sHash) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_le_bytes(h.0[4 * i..4 * i + 4].try_into().unwrap()))
}

pub fn circuit_hash_of(pp: &PreprocessedCircuit, cfg: &PcsConfig, root: Blake2sHash) -> Blake2sHash {
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    compute_circuit_hash::<Blake2sMerkleHasher>(&log_sizes, cfg.fri_config.log_blowup_factor, root)
}

/// Upstream's `stwo_verify` flow with trusted inputs: the preprocessed root and configuration come
/// from the topology, never from the proof.
pub fn native_verify(
    proof: &CircuitProof<Blake2sMerkleHasher>,
    pp: &PreprocessedCircuit,
    trusted_root: Blake2sHash,
    expected: &[QM31],
) -> Result<(), String> {
    if proof.stark_proof.proof.commitments[0] != trusted_root {
        return Err("preprocessed root".into());
    }
    if proof.pcs_config != config(pp.trace_log_size()) {
        return Err("pcs config".into());
    }
    if proof.claim.output_values != expected {
        return Err("statement digest".into());
    }
    verify_circuit_proof::<MC>(proof, pp)
}

/// A relation the client proves: its output count, public limbs and circuit.
pub trait Relation {
    fn n_outputs(&self) -> usize;
    fn limbs(&self) -> Vec<u32>;
    fn build<V: Lanes>(&self, c: &mut Context<V>) -> Vec<Var>;
}

/// R0 V4 (`payment4`).
pub struct R4<'a>(pub &'a payment4::Public, pub &'a payment4::Private);
/// R0 V3 (`payment`).
pub struct R0<'a>(pub &'a payment::Public, pub &'a payment::Private);
/// P1 (`policy`).
pub struct P1<'a>(pub &'a policy::Public, pub &'a policy::Private);

impl Relation for R4<'_> {
    fn n_outputs(&self) -> usize {
        payment4::N_OUTPUTS
    }
    fn limbs(&self) -> Vec<u32> {
        payment4::statement_limbs(TREE, self.0)
    }
    fn build<V: Lanes>(&self, c: &mut Context<V>) -> Vec<Var> {
        payment4::build(c, TREE, self.0, self.1)
    }
}

impl Relation for R0<'_> {
    fn n_outputs(&self) -> usize {
        payment::N_OUTPUTS
    }
    fn limbs(&self) -> Vec<u32> {
        payment::statement_limbs(TREE, self.0)
    }
    fn build<V: Lanes>(&self, c: &mut Context<V>) -> Vec<Var> {
        payment::build(c, TREE, self.0, self.1)
    }
}

impl Relation for P1<'_> {
    fn n_outputs(&self) -> usize {
        policy::N_OUTPUTS
    }
    fn limbs(&self) -> Vec<u32> {
        policy::statement_limbs(TREE, self.0)
    }
    fn build<V: Lanes>(&self, c: &mut Context<V>) -> Vec<Var> {
        policy::build(c, TREE, self.0, self.1)
    }
}

fn circuit<V: Lanes, R: Relation>(rel: &R, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(rel.n_outputs());
    let outputs = rel.build(&mut c);
    c.set_outputs(&outputs);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

/// A verified client proof, before serialization.
pub struct Proved {
    pub proof: CircuitProof<Blake2sMerkleHasher>,
    pub pp: PreprocessedCircuit,
    pub cfg: PcsConfig,
    pub pp_root: Blake2sHash,
    pub circuit_hash: Blake2sHash,
    /// The statement as QM31 outputs.
    pub wanted: Vec<QM31>,
    pub blinding: usize,
    pub revealed: usize,
}

/// Proves `rel` with the zero-knowledge blinding seed `seed` (from a CSPRNG), then checks the
/// hiding budget and verifies the proof natively.
pub fn prove<R: Relation>(rel: &R, seed: [u8; 32], max_fri_columns: Option<usize>) -> Result<Proved, String> {
    let mut blinding = 0;
    let (topology, pp) = loop {
        let topology = circuit::<NoValue, R>(rel, [0; 32], blinding);
        let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
        let need = blinding_budget(pp.trace_log_size());
        if blinding >= need {
            break (topology, pp);
        }
        blinding = need;
    };
    let context = circuit::<QM31, R>(rel, seed, blinding);
    if topology.circuit() != context.circuit() {
        return Err("the witness changed the circuit topology".into());
    }
    drop(topology);
    let cfg = config(pp.trace_log_size());
    let pp_root = pp.preprocessed_root(cfg.fri_config.log_blowup_factor);
    let circuit_hash = circuit_hash_of(&pp, &cfg, pp_root);
    let limbs = rel.limbs();
    let wanted: Vec<QM31> = limbs.chunks_exact(4).map(|q| qm31_from_u32s(q[0], q[1], q[2], q[3])).collect();
    let proof = prove_circuit_assignment_bounded::<MC>(context.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), cfg, max_fri_columns)
        .map_err(|e| format!("proving: {e:?}"))?;
    drop(context);
    let revealed = revealed_fri_values(&proof);
    if revealed + NON_QUERY_INFO_LEAK > blinding {
        return Err(format!("hiding budget: {revealed} revealed values need more than {blinding} blinding rows"));
    }
    native_verify(&proof, &pp, pp_root, &wanted).map_err(|e| format!("self-verification: {e}"))?;
    Ok(Proved { proof, pp, cfg, pp_root, circuit_hash, wanted, blinding, revealed })
}

/// The proof as the bridge's Cairo arguments: a length-prefixed felt span, as `0x` hex
/// (`cairo-arguments.json`, the prover server's `proof`).
pub fn cairo_arguments(p: Proved) -> Vec<String> {
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &p.pp.preprocessed_trace.log_sizes());
    let felts = prepare_circuit_proof_for_cairo_verifier(p.proof, &log_sizes);
    let mut out = vec![format!("0x{:x}", felts.len())];
    out.extend(felts.iter().map(|f| format!("{f:#x}")));
    out
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// The pinned constant is upstream production with only blowup and queries changed.
    #[test]
    fn bridge_fri_matches_the_fork() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/proving-arith/circuit_registry_definitions/production/circuit_fri_config.json");
        let production: FriConfig = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!((production.pow_bits, production.log_blowup_factor, production.n_queries), (26, 1, 70));
        assert_eq!(FriConfig { log_blowup_factor: 2, n_queries: 35, ..production }, BRIDGE_FRI);
        assert!(BRIDGE_FRI.pow_bits as usize + BRIDGE_FRI.log_blowup_factor as usize * BRIDGE_FRI.n_queries >= 96);
    }
}
