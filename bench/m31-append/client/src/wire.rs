//! Bridge-local full-config serializer with empty-preprocessing-safe query transposition.
use super::Envelope;
use crate::statement::{Statement, felt};
use anyhow::{Result, ensure};
use starknet_ff::FieldElement;
use stwo::core::fields::m31::M31;
use stwo_cairo_serialize::CairoSerialize;
fn field(value: &str, out: &mut Vec<FieldElement>) -> Result<()> {
    out.push(FieldElement::from_bytes_be(&felt(value)?.to_bytes_be())?);
    Ok(())
}
fn statement(s: &Statement, out: &mut Vec<FieldElement>) -> Result<()> {
    field(&s.chain_id, out)?;
    field(&s.pool, out)?;
    s.old_count.serialize(out);
    s.new_count.serialize(out);
    s.old_root.to_vec().serialize(out);
    s.new_root.to_vec().serialize(out);
    s.commitments.len().serialize(out);
    for cm in &s.commitments {
        field(cm, out)?;
    }
    s.steps.len().serialize(out);
    for step in &s.steps {
        step.siblings.len().serialize(out);
        for sibling in &step.siblings {
            sibling.to_vec().serialize(out);
        }
        step.requests.len().serialize(out);
        for request in &step.requests {
            request.input.to_vec().serialize(out);
            request.output.to_vec().serialize(out);
        }
    }
    Ok(())
}
pub fn serialize(e: &Envelope) -> Result<Vec<FieldElement>> {
    let mut out = vec![];
    statement(&e.statement, &mut out)?;
    e.interaction_pow.serialize(&mut out);
    e.claimed_sum.serialize(&mut out);
    let p = &e.proof;
    p.config.pow_bits.serialize(&mut out);
    p.config.fri_config.serialize(&mut out);
    p.config.lifting_log_size.serialize(&mut out);
    p.commitments.0.serialize(&mut out);
    p.sampled_values.0.serialize(&mut out);
    p.decommitments.0.serialize(&mut out);
    transpose_queries(&p.queried_values, p.config.fri_config.n_queries)?.serialize(&mut out);
    p.proof_of_work.serialize(&mut out);
    p.fri_proof.serialize(&mut out);
    Ok(out)
}

fn transpose_queries(values: &[Vec<Vec<M31>>], configured_queries: usize) -> Result<Vec<Vec<M31>>> {
    ensure!(values.len() == 4 && values[0].is_empty(), "wire tree shape");
    let q = values[1]
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing base columns"))?
        .len();
    // Both verifiers draw the configured number of positions, then sort and deduplicate.
    // The serialized columns contain one opening per distinct position.
    ensure!(q > 0 && q <= configured_queries, "wire query count");
    let mut trees = vec![vec![]];
    for (tree, columns) in values[1..].iter().zip([crate::m31::COLUMNS, 4, 8]) {
        ensure!(
            tree.len() == columns && tree.iter().all(|c| c.len() == q),
            "wire column/query shape"
        );
        trees.push(
            (0..q)
                .flat_map(|i| tree.iter().map(move |c| c[i]))
                .collect::<Vec<_>>(),
        );
    }
    Ok(trees)
}

pub fn serialize_statement(s: &Statement) -> Result<Vec<FieldElement>> {
    let mut out = vec![];
    statement(s, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn columns(q: usize) -> Vec<Vec<Vec<M31>>> {
        std::iter::once(vec![])
            .chain([crate::m31::COLUMNS, 4, 8].map(|n| {
                (0..n)
                    .map(|column| {
                        (0..q)
                            .map(|query| M31::from((column * 100 + query) as u32))
                            .collect()
                    })
                    .collect()
            }))
            .collect()
    }

    #[test]
    fn deduplicated_queries_keep_query_major_order() {
        for q in [1, 22, 23] {
            let wire = transpose_queries(&columns(q), 23).unwrap();
            assert!(wire[0].is_empty());
            for (tree, n) in wire[1..].iter().zip([crate::m31::COLUMNS, 4, 8]) {
                assert_eq!(tree.len(), n * q);
                for query in 0..q {
                    for column in 0..n {
                        assert_eq!(
                            tree[query * n + column],
                            M31::from((column * 100 + query) as u32)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn inconsistent_query_and_column_shapes_are_rejected() {
        for q in [0, 24] {
            assert!(transpose_queries(&columns(q), 23).is_err());
        }
        for tree in 1..4 {
            let mut bad = columns(22);
            bad[tree][0].pop();
            assert!(transpose_queries(&bad, 23).is_err());
            let mut bad = columns(22);
            bad[tree][0].push(M31::from(0));
            assert!(transpose_queries(&bad, 23).is_err());
            let mut bad = columns(22);
            bad[tree].pop();
            assert!(transpose_queries(&bad, 23).is_err());
            let mut bad = columns(22);
            bad[tree].push(vec![M31::from(0); 22]);
            assert!(transpose_queries(&bad, 23).is_err());
        }
        let mut bad = columns(22);
        bad.pop();
        assert!(transpose_queries(&bad, 23).is_err());
        let mut bad = columns(22);
        bad[0].push(vec![]);
        assert!(transpose_queries(&bad, 23).is_err());
    }
}
