//! Exact single-component mirror of frozen m31-tree/client/src/m31.rs::Eval.
//! This evaluates constraints at the verifier's OOD point, not the public hashes.
use core::num::traits::Zero;
use stwo_constraint_framework::{CommonLookupElements,LookupElementsImpl};
use stwo_verifier_core::circle::CirclePoint;
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::fields::qm31::{QM31,QM31Trait};
use stwo_verifier_core::verifier::Air;
use stwo_verifier_core::{ColumnSpan,TreeSpan};
use super::constants::{initial_constants,internal_constants,final_constants};
use super::statement::{PublicData,RELATION_ID};

pub const TRACE_COLUMNS: usize=1172;
pub const INTERACTION_COLUMNS: usize=4;
fn scalar(x: u32) -> QM31 { let base: M31=x.try_into().unwrap(); base.into() }
fn next(ref columns: ColumnSpan<Span<QM31>>) -> QM31 {
    let values=*columns.pop_front().expect('TRACE_COLUMN_MISSING');
    assert(values.len()==1,'TRACE_MASK_LENGTH');
    *values.at(0)
}
fn constrain(ref sum: QM31,random: QM31,constraint: QM31) { sum=sum*random+constraint; }
fn external(state: Span<QM31>) -> Array<QM31> {
    let two=scalar(2); let three=scalar(3);
    let mut blocks=array![];
    let mut i: usize=0;
    while i<24 {
        let a=*state.at(i); let b=*state.at(i+1); let c=*state.at(i+2); let d=*state.at(i+3);
        blocks.append(two*a+three*b+c+d); blocks.append(a+two*b+three*c+d);
        blocks.append(a+b+two*c+three*d); blocks.append(three*a+b+c+two*d);
        i+=4;
    };
    let mut sums=array![];
    for k in 0_usize..4 {
        let mut sum: QM31=Zero::zero(); let mut j=k;
        while j<24 { sum+=*blocks.at(j); j+=4; };
        sums.append(sum);
    };
    let mut result=array![];
    for j in 0_usize..24 { result.append(*blocks.at(j)+*sums.at(j%4)); };
    result
}
fn internal(state: Span<QM31>) -> Array<QM31> {
    let mut sum: QM31=Zero::zero();
    for value in state { sum+=*value; };
    let mut result=array![sum-scalar(2)*(*state.at(0))];
    let mut diagonal: u32=1;
    for i in 1_usize..24 { result.append(sum+scalar(diagonal)*(*state.at(i))); diagonal*=2; };
    result
}
fn nonlinear(x: QM31,ref trace: ColumnSpan<Span<QM31>>,ref sum: QM31,random: QM31) -> QM31 {
    let x2=next(ref trace); let x4=next(ref trace);
    constrain(ref sum,random,x2-x*x); constrain(ref sum,random,x4-x2*x2);
    x4*x
}
fn materialize(values: Span<QM31>,ref trace: ColumnSpan<Span<QM31>>,ref sum: QM31,random: QM31) -> Array<QM31> {
    let mut result=array![];
    for value in values {
        let stored=next(ref trace); constrain(ref sum,random,stored-*value); result.append(stored);
    };
    result
}
fn full_rounds(mut state: Array<QM31>,constants: Span<u32>,ref trace: ColumnSpan<Span<QM31>>,ref sum: QM31,random: QM31) -> Array<QM31> {
    for round in 0_usize..4 {
        let mut values=array![];
        for i in 0_usize..24 { values.append(nonlinear(*state.at(i)+scalar(*constants.at(round*24+i)),ref trace,ref sum,random)); };
        state=materialize(external(values.span()).span(),ref trace,ref sum,random);
    };
    state
}
#[derive(Drop)]
pub struct M31Air { pub log_size: u32,pub claimed_sum: QM31,pub lookup: CommonLookupElements }

/// Public so differential tests can check arbitrary OOD masks against Rust directly.
pub fn evaluate(air: @M31Air,mut trace: ColumnSpan<Span<QM31>>,interaction: ColumnSpan<Span<QM31>>,random: QM31) -> QM31 {
    assert(trace.len()==TRACE_COLUMNS,'TRACE_COLUMNS');
    assert(interaction.len()==INTERACTION_COLUMNS,'INTERACTION_COLUMNS');
    let mut input=array![];
    for _ in 0_u32..24 { input.append(next(ref trace)); };
    let mut state=external(input.span());
    let mut sum: QM31=Zero::zero();
    state=full_rounds(state,initial_constants().span(),ref trace,ref sum,random);
    for constant in internal_constants().span() {
        let first=nonlinear(*state.at(0)+scalar(*constant),ref trace,ref sum,random);
        let mut values=array![first];
        for i in 1_usize..24 { values.append(*state.at(i)); };
        state=materialize(internal(values.span()).span(),ref trace,ref sum,random);
    };
    state=full_rounds(state,final_constants().span(),ref trace,ref sum,random);
    assert(trace.is_empty(),'UNUSED_TRACE');
    let mut tuple=array![scalar(RELATION_ID)];
    for value in input.span() { tuple.append(*value); };
    for value in state.span() { tuple.append(*value); };
    let denominator=air.lookup.combine_qm31(tuple.span());
    let mut previous=array![]; let mut current=array![];
    for column in interaction {
        assert(column.len()==2,'INTERACTION_MASK_LENGTH');
        previous.append(*column.at(0)); current.append(*column.at(1));
    };
    let prev=QM31Trait::from_partial_evals((*previous.span().try_into().unwrap()).unbox());
    let cur=QM31Trait::from_partial_evals((*current.span().try_into().unwrap()).unbox());
    let rows=if *air.log_size==8 { 256 } else { assert(*air.log_size==9,'AIR_LOG'); 512 };
    // Single negative relation entry, centered last-column LogUp constraint.
    constrain(ref sum,random,(cur-prev+*air.claimed_sum*scalar(rows).inverse())*denominator+scalar(1));
    sum
}
pub impl M31AirImpl of Air<M31Air> {
    fn eval_composition_polynomial_at_point(self: @M31Air,point: CirclePoint<QM31>,mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,random_coeff: QM31) -> QM31 {
        let _=point;
        assert(mask_values.len()==4,'MASK_TREES');
        assert(mask_values.at(0).is_empty(),'PREPROCESSED_MASKS');
        // Generic core validates the8 single-valued composition masks and divides by vanishing.
        evaluate(self,*mask_values.at(1),*mask_values.at(2),random_coeff)
    }
}
pub fn public_boundary(data: @PublicData,lookup: @CommonLookupElements) -> QM31 {
    let mut sum: QM31=Zero::zero();
    for row in 0_u32..*data.rows {
        let index=if row<data.requests.len() { row } else { 0 };
        let request=data.requests.at(index);
        let mut tuple: Array<M31>=array![RELATION_ID.try_into().unwrap()];
        for word in request.input { tuple.append((*word).try_into().unwrap()); };
        for word in request.output { tuple.append((*word).try_into().unwrap()); };
        sum+=lookup.combine(tuple.span()).inverse();
    };
    sum
}
