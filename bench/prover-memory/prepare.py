"""Apply reproducible overlays to isolated pinned sources, leaving originals intact."""
from pathlib import Path
import difflib, json, shutil
HERE=Path(__file__).resolve().parent
E=json.loads((HERE/'environment.json').read_text()); W=Path(E['work']); seq=W/'sequencer'; pu=W/'proving-utils'
source=Path(E['proving_original'])/'crates/privacy_prove/src/lib.rs'
s=source.read_text()
# Reuse the exact pinned proof construction; change only object lifetimes.
start=s.index('pub fn privacy_recursive_prove('); end=s.index('\nfn run_privacy_bootloader',start)
f=s[start:end].replace('pub fn privacy_recursive_prove(\n    pie: CairoPie,\n    precomputes: Arc<RecursiveProverPrecomputes>,\n)', 'pub fn privacy_recursive_prove_low_memory(pie: CairoPie, options: LowMemoryOptions)')
f=f.replace('"privacy_recursive_prove"','"privacy_recursive_prove_low_memory"',1)
prepare='''    let mut cairo_params = CAIRO_PROVER_PARAMS;
    cairo_params.store_polynomials_coefficients = options.cache_cairo_coefficients;
    // Only twiddles survive both proof stages. Each stage owns its tree and pool.
    let cairo_lifting = CAIRO_PCS_CONFIG.lifting_log_size
        .ok_or("Missing Cairo lifting size")?;
    let circuit_lifting = CIRCUIT_PCS_CONFIG.lifting_log_size
        .ok_or("Missing circuit lifting size")?;
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max(cairo_lifting, circuit_lifting)).circle_domain().half_coset);
    info!("Prepare only the Cairo stage");
    let cairo_proof = {
        let pool = BaseColumnPool::<SimdBackend>::new();
        let trace = Arc::new(CAIRO_PROVER_PARAMS.preprocessed_trace.to_preprocessed_trace());
        let polys = SimdBackend::interpolate_columns(gen_trace(trace.clone()), &twiddles);
        let tree = CommitmentTreeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(
            polys, CAIRO_PCS_CONFIG.fri_config.log_blowup_factor, &twiddles,
            cairo_params.store_polynomials_coefficients, Some(cairo_lifting), &pool);
        info!("Generate the cairo proof");
        prove_cairo_with_precompute(&pool, &twiddles, trace,
            MaybeOwned::Owned(tree), prover_input, cairo_params)?
    };
    info!("Cairo stage tree and buffer pool released");
    let cairo_verifier_config = get_cairo_verifier_config()?;
    let circuit_config = get_recursive_circuit_config();
    let proof_config = get_proof_config();
'''
a=f.index('    info!("Generate the cairo proof");'); b=f.index('    // TODO(Leo)',a)
f=f[:a]+prepare+f[b:]
for name in ['cairo_verifier_config','circuit_config','proof_config']: f=f.replace('precomputes.'+name,name)
a=f.index('    info!("Prove the cairo-circuit verifier");'); b=f.index('    info!("Prepare the circuit proof for the circuit verifier");',a)
f=f[:a]+'''    // Serialized Cairo proof is already in the context; keep no duplicate proof alive.
    drop(cairo_proof);
    info!("Prepare only the recursive circuit stage");
    let circuit_proof = {
        let pool = BaseColumnPool::<SimdBackend>::new();
        let preprocessed_circuit = get_cairo_preprocessed_circuit(&cairo_verifier_config);
        let polys = SimdBackend::interpolate_columns(
            preprocessed_circuit.preprocessed_trace.get_trace::<SimdBackend>(), &twiddles);
        let tree = CommitmentTreeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(
            polys, CIRCUIT_FRI_CONFIG.log_blowup_factor, &twiddles,
            CIRCUIT_STORE_POLYNOMIALS_COEFFICIENTS,
            circuit_config.config.lifting_log_size, &pool);
        info!("Prove the cairo-circuit verifier");
        prove_circuit_with_precompute(&pool, &twiddles, &preprocessed_circuit,
            MaybeOwned::Owned(tree), context_values, circuit_config.config)?
    };
    info!("Recursive stage tree and buffer pool released");

'''+f[b:]
assert 'precomputes.' not in f
# The function never reads environment variables or changes protocol parameters.
low='''//! One-shot proving with phase-local commitment trees and buffer pools.
//!
//! Shared service precomputes remain available through the existing API. This
//! entry point trades precompute reuse for a smaller live working set. It keeps
//! the pinned proof format, blinding and all security parameters unchanged.
use super::*;

/// Allocation/runtime choices only. All cryptographic parameters remain pinned.
#[derive(Clone, Copy)]
pub struct LowMemoryOptions {
    pub cache_cairo_coefficients: bool,
}
impl Default for LowMemoryOptions {
    fn default() -> Self { Self { cache_cairo_coefficients: true } }
}

'''+f
(HERE/'overlay/low_memory.rs').write_text(low)
(pu/'crates/privacy_prove/src/low_memory.rs').write_text(low)
lib='mod low_memory;\npub use low_memory::{privacy_recursive_prove_low_memory, LowMemoryOptions};\n\n'+s
(pu/'crates/privacy_prove/src/lib.rs').write_text(lib)
seq0=Path(E['sequencer_original'])
rel='crates/starknet_transaction_prover/src/proving/prover.rs'
s=(seq0/rel).read_text()
s=s.replace('use privacy_prove::{privacy_recursive_prove, RecursiveProverPrecomputes};', '''use privacy_prove::{privacy_recursive_prove, privacy_recursive_prove_low_memory, LowMemoryOptions};

/// Benchmark integration: choose once at startup, never mutate shared precomputes.
pub(crate) enum RecursiveProverPrecomputes {
    Cached(Arc<privacy_prove::RecursiveProverPrecomputes>),
    LowMemory(LowMemoryOptions),
}

pub(crate) fn prepare_recursive_prover_precomputes()
    -> Result<Arc<RecursiveProverPrecomputes>, Box<dyn std::error::Error>>
{
    match std::env::var("TEMPLAR_LOW_MEMORY").as_deref() {
        Ok("1") => {
            let cache_cairo_coefficients = match std::env::var("TEMPLAR_CAIRO_COEFFICIENTS").as_deref() {
                Ok("0") => false,
                Err(std::env::VarError::NotPresent) | Ok("1") => true,
                _ => return Err("TEMPLAR_CAIRO_COEFFICIENTS must be 0 or 1".into()),
            };
            Ok(Arc::new(RecursiveProverPrecomputes::LowMemory(LowMemoryOptions { cache_cairo_coefficients })))
        },
        Err(std::env::VarError::NotPresent) | Ok("0") => Ok(Arc::new(
            RecursiveProverPrecomputes::Cached(privacy_prove::prepare_recursive_prover_precomputes()?))),
        _ => Err("TEMPLAR_LOW_MEMORY must be 0 or 1".into()),
    }
}''')
s=s.replace('privacy_recursive_prove(cairo_pie, precomputes).map_err(|e| e.to_string())','''match precomputes.as_ref() {
            RecursiveProverPrecomputes::Cached(shared) => privacy_recursive_prove(cairo_pie, shared.clone()),
            RecursiveProverPrecomputes::LowMemory(options) => privacy_recursive_prove_low_memory(cairo_pie, *options),
        }.map_err(|e| e.to_string())''')
(seq/rel).write_text(s)
for name in ['virtual_snos_prover.rs','prover_test.rs']:
 rel='crates/starknet_transaction_prover/src/proving/'+name
 s=(seq0/rel).read_text().replace('use privacy_prove::{prepare_recursive_prover_precomputes, RecursiveProverPrecomputes};','use super::prover::{prepare_recursive_prover_precomputes, RecursiveProverPrecomputes};')
 (seq/rel).write_text(s)
# Patch only the prover package. The independent verification binary is untouched.
s=(seq0/'Cargo.toml').read_text()+'\n[patch."https://github.com/starkware-libs/proving-utils"]\nprivacy-prove = { path = "../proving-utils/crates/privacy_prove" }\n'
(seq/'Cargo.toml').write_text(s)
# Native diagnostic sampler: separate from the portable optimization module.
rel='crates/starknet_transaction_prover/src/main.rs';s=(seq0/rel).read_text()
s=s.replace('//! CLI for the Starknet transaction prover.', '//! CLI for the Starknet transaction prover.\n#[cfg(feature = "memory_profile")]\nmod memory_profile;\n#[cfg(feature = "memory_profile")]\n#[global_allocator]\nstatic ALLOCATOR: memory_profile::CountingAllocator = memory_profile::CountingAllocator;')
s=s.replace('    let args = CliArgs::parse();','    #[cfg(feature = "memory_profile")]\n    memory_profile::start()?;\n    let args = CliArgs::parse();')
s=s.replace('    match args.log_format {', '    let events = if std::env::var_os("TEMPLAR_TRACE_SPANS").is_some() { tracing_subscriber::fmt::format::FmtSpan::NEW | tracing_subscriber::fmt::format::FmtSpan::CLOSE } else { tracing_subscriber::fmt::format::FmtSpan::NONE };\n    match args.log_format {')
s=s.replace('fmt::layer().json()', 'fmt::layer().with_span_events(events).json()').replace('registry.with(fmt::layer())', 'registry.with(fmt::layer().with_span_events(events))')
(seq/rel).write_text(s)
shutil.copyfile(HERE/'overlay/memory_profile.rs',seq/'crates/starknet_transaction_prover/src/memory_profile.rs')
rel='crates/starknet_transaction_prover/Cargo.toml'
s=(seq0/rel).read_text().replace('[features]', '[features]\nmemory_profile = []')
(seq/rel).write_text(s)
for label,original,patched in [('proving-utils',Path(E['proving_original']),pu),('sequencer',seq0,seq)]:
 diff=[]
 for p in sorted(list(patched.rglob('*.rs'))+list(patched.rglob('Cargo.toml'))):
  rel=p.relative_to(patched); old=original/rel
  a=old.read_text() if old.exists() else '';b=p.read_text()
  if a!=b:diff.extend(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
 (HERE/(label+'.patch')).write_text(''.join(diff))
print('Prepared portable low-memory API and isolated service/measurement overlays.')
