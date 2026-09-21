//! Unchanged felt252 Poseidon dependency closure reused from the archived membership benchmark.
use crate::Evaluation;
use crate::felt_statement::PublicData;
use anyhow::{Result, ensure};
use cairo_air::{components as air, relations::CommonLookupElements};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Arc, atomic::AtomicU32};
use stwo::core::fields::qm31::QM31;
use stwo::prover::{ComponentProver, backend::simd::SimdBackend};
use stwo_cairo_adapter::memory::{Memory, MemoryConfig};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::{
    PreProcessedTrace, PreProcessedTraceVariant,
};
use stwo_cairo_prover::witness::components as witness;
use stwo_constraint_framework::TraceLocationAllocator;
macro_rules! components {
    ($($name:ident),+ $(,)?)=>{
        #[derive(Serialize,Deserialize,Clone)]
        pub struct Claims {$( $name:air::$name::Claim, )+}
        pub struct Generators {$( $name:witness::$name::InteractionClaimGenerator, )+}
        impl Claims {
            pub fn sizes(&self)->[Vec<u32>;2] {
                let mut sizes=[Vec::new(),Vec::new()];
                $(let local=self.$name.log_sizes();sizes[0].extend(&local[0]);sizes[1].extend(&local[1]);)+ sizes
            }
            pub fn components(&self,sums:&[QM31],lookup:&CommonLookupElements,pre:&PreProcessedTrace,allocator:&mut TraceLocationAllocator)->Result<Vec<Box<dyn ComponentProver<SimdBackend>>>> {

                let mut sums=sums.iter(); let mut out:Vec<Box<dyn ComponentProver<SimdBackend>>>=Vec::new();
                $(out.push(Box::new(air::$name::Component::new(allocator,air::$name::Eval{claim:self.$name,common_lookup_elements:lookup.clone()},*sums.next().ok_or_else(||anyhow::anyhow!("missing component sum"))?)));)+
                ensure!(sums.next().is_none(),"extra component sum");
                allocator.validate_preprocessed_columns(&pre.ids()); Ok(out)
            }
            pub fn metadata(&self)->Vec<serde_json::Value>{vec![$({let s=self.$name.log_sizes();json!({"name":stringify!($name),"log_rows":s[0][0],"rows":1u64<<s[0][0],"trace_columns":s[0].len(),"interaction_base_columns":s[1].len()})}),+]}
            pub fn validate(&self,data:&PublicData)->Result<()> {
                ensure!(self.poseidon_aggregator.log_size==data.aggregator_log_size(),"aggregator shape");
                ensure!(self.sizes().iter().flatten().all(|&l|(4..=20).contains(&l)),"component size bounds");
                let mut terms=0u64;
                $(for r in air::$name::RELATION_USES_PER_ROW {terms+=(1u64<<self.$name.log_sizes()[0][0])*r.uses as u64;})+
                ensure!(terms+((data.rows.len()*6+data.requests.len()+512) as u64) < (1u64<<31)-1,"relation count bound");
                Ok(())
            }
        }
        impl Generators {
            pub fn interactions(self,lookup:&CommonLookupElements)->(Vec<Evaluation>,Vec<QM31>){
                let mut evals=Vec::new();let mut sums=Vec::new();
                $(let (trace,claim)=self.$name.write_interaction_trace(lookup);evals.extend(trace);sums.push(claim.claimed_sum);)+
                (evals,sums)
            }
        }
    }
}
components!(
    poseidon_aggregator,
    poseidon_full_round_chain,
    poseidon_3_partial_rounds_chain,
    cube_252,
    range_check_252_width_27,
    poseidon_round_keys,
    range_check_3_3_3_3_3,
    range_check_4_4_4_4,
    range_check_4_4,
    range_check_9_9,
    range_check_20,
    range_check_18
);

/// Canonical column definitions are lightweight; unselected tables are never generated.
pub fn preprocessing(aggregator_log: u32) -> Arc<PreProcessedTrace> {
    let mut pre = PreProcessedTrace::canonical_without_pedersen();
    pre.columns.retain(|c| {
        let id = c.id().id;
        [
            format!("seq_{aggregator_log}"),
            "seq_6".into(),
            "seq_18".into(),
            "seq_20".into(),
        ]
        .contains(&id)
            || id.starts_with("poseidon_round_keys_")
            || [
                "range_check_3_3_3_3_3_column_",
                "range_check_4_4_4_4_column_",
                "range_check_4_4_column_",
                "range_check_9_9_column_",
            ]
            .iter()
            .any(|p| id.starts_with(p))
    });
    pre.column_indices = pre
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id(), i))
        .collect();
    // The enum is an upstream storage field, not canonical-root authority. This subset is custom.
    pre.variant = PreProcessedTraceVariant::CanonicalWithoutPedersen;
    Arc::new(pre)
}

pub fn witness(
    data: &PublicData,
    pre: Arc<PreProcessedTrace>,
) -> (Vec<Evaluation>, Claims, Generators) {
    let mem = Memory {
        config: MemoryConfig::default(),
        address_to_id: Vec::new(),
        f252_values: data
            .values
            .iter()
            .map(|v| {
                let bytes = v.to_bytes_le();
                std::array::from_fn(|i| {
                    u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap())
                })
            })
            .collect(),
        small_values: Vec::new(),
    };
    let memory = witness::memory_id_to_big::ClaimGenerator::new(Arc::new(mem));
    let aggregator = witness::poseidon_aggregator::ClaimGenerator::new();
    for (r, n) in &data.unique {
        aggregator.mults.insert(*r, AtomicU32::new(*n));
    }
    let mut full = witness::poseidon_full_round_chain::ClaimGenerator::new();
    let mut partial = witness::poseidon_3_partial_rounds_chain::ClaimGenerator::new();
    let mut cube = witness::cube_252::ClaimGenerator::new();
    let mut width = witness::range_check_252_width_27::ClaimGenerator::new();
    let keys = witness::poseidon_round_keys::ClaimGenerator::new(pre.clone());
    let rc3 = witness::range_check_3_3_3_3_3::ClaimGenerator::new(pre.clone());
    let rc4 = witness::range_check_4_4_4_4::ClaimGenerator::new(pre.clone());
    let rc44 = witness::range_check_4_4::ClaimGenerator::new(pre.clone());
    let rc99 = witness::range_check_9_9::ClaimGenerator::new(pre.clone());
    let rc20 = witness::range_check_20::ClaimGenerator::new(pre.clone());
    let rc18 = witness::range_check_18::ClaimGenerator::new(pre);
    let mut evals = Vec::new();
    let (trace, ac, ag) = aggregator.write_trace(
        &memory,
        &mut full,
        &mut width,
        &mut cube,
        &rc3,
        &rc4,
        &rc44,
        &mut partial,
    );
    evals.extend(trace.to_evals());
    drop(memory);
    let (trace, fc, fg) = full.write_trace(&mut cube, &keys, &rc3);
    evals.extend(trace.to_evals());
    let (trace, pc, pg) = partial.write_trace(&keys, &mut cube, &rc4, &rc44, &mut width);
    evals.extend(trace.to_evals());
    let (trace, cc, cg) = cube.write_trace(&rc99, &rc20);
    evals.extend(trace.to_evals());
    let (trace, wc, wg) = width.write_trace(&rc99, &rc18);
    evals.extend(trace.to_evals());
    let (trace, kc, kg) = keys.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r3c, r3g) = rc3.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r4c, r4g) = rc4.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r44c, r44g) = rc44.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r99c, r99g) = rc99.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r20c, r20g) = rc20.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r18c, r18g) = rc18.write_trace();
    evals.extend(trace.to_evals());
    (
        evals,
        Claims {
            poseidon_aggregator: ac,
            poseidon_full_round_chain: fc,
            poseidon_3_partial_rounds_chain: pc,
            cube_252: cc,
            range_check_252_width_27: wc,
            poseidon_round_keys: kc,
            range_check_3_3_3_3_3: r3c,
            range_check_4_4_4_4: r4c,
            range_check_4_4: r44c,
            range_check_9_9: r99c,
            range_check_20: r20c,
            range_check_18: r18c,
        },
        Generators {
            poseidon_aggregator: ag,
            poseidon_full_round_chain: fg,
            poseidon_3_partial_rounds_chain: pg,
            cube_252: cg,
            range_check_252_width_27: wg,
            poseidon_round_keys: kg,
            range_check_3_3_3_3_3: r3g,
            range_check_4_4_4_4: r4g,
            range_check_4_4: r44g,
            range_check_9_9: r99g,
            range_check_20: r20g,
            range_check_18: r18g,
        },
    )
}
