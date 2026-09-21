//! Exact reviewed Plonky3 width24 Poseidon2, expressed as a quadratic S-two AIR.
use crate::{
    Evaluation,
    constants::{EXTERNAL_FINAL, EXTERNAL_INITIAL, INTERNAL},
};
use anyhow::{Result, ensure};
use cairo_air::relations::CommonLookupElements;
use num_traits::One;
use serde::{Deserialize, Serialize};
use stwo::core::{
    fields::{m31::M31, qm31::QM31},
    poly::circle::CanonicCoset,
};
use stwo::prover::{
    backend::simd::{column::BaseColumn, m31::PackedBaseField, qm31::PackedSecureField},
    poly::circle::CircleEvaluation,
};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
};

pub const P: u32 = 2147483647;
pub const WIDTH: usize = 24;
pub const RATE: usize = 15;
pub const WORDS: usize = 9;
pub const COLUMNS: usize = 1172;
pub const RELATION_ID: u32 = 0x4d333150;
pub type Digest = [u32; WORDS];
pub type State = [u32; WIDTH];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub input: State,
    pub output: State,
}

pub fn canonical(words: &[u32]) -> Result<()> {
    ensure!(words.iter().all(|&x| x < P), "noncanonical M31 word");
    Ok(())
}

fn external<F>(s: &mut [F; WIDTH])
where
    F: Clone + std::ops::Add<Output = F> + std::ops::Mul<M31, Output = F>,
{
    // Upstream MDSMat4, not the different Horizon Labs matrix in S-two's example.
    for offset in (0..WIDTH).step_by(4) {
        let x: [F; 4] = std::array::from_fn(|i| s[offset + i].clone());
        let matrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
        for i in 0..4 {
            s[offset + i] = (0..4)
                .map(|j| x[j].clone() * M31::from(matrix[i][j]))
                .reduce(|a, b| a + b)
                .unwrap();
        }
    }
    let sums: [F; 4] = std::array::from_fn(|k| {
        (0..WIDTH)
            .step_by(4)
            .map(|i| s[i + k].clone())
            .reduce(|a, b| a + b)
            .unwrap()
    });
    for i in 0..WIDTH {
        s[i] = s[i].clone() + sums[i % 4].clone();
    }
}
fn internal<F>(s: &mut [F; WIDTH])
where
    F: Clone + std::ops::Add<Output = F> + std::ops::Mul<M31, Output = F>,
{
    let total = s.iter().cloned().reduce(|a, b| a + b).unwrap();
    for i in 0..WIDTH {
        let diagonal = if i == 0 {
            M31::from(P - 2)
        } else {
            M31::from(1u32 << (i - 1))
        };
        s[i] = total.clone() + s[i].clone() * diagonal;
    }
}

/// Recording and arithmetic share exactly the same round order. The independent oracle uses
/// upstream Plonky3 code and does not call this implementation.
fn execute(input: State, mut record: impl FnMut(M31)) -> State {
    let mut state = input.map(M31::from);
    state.iter().copied().for_each(&mut record);
    external(&mut state);
    for constants in &EXTERNAL_INITIAL {
        for i in 0..WIDTH {
            let x = state[i] + M31::from(constants[i]);
            let x2 = x * x;
            let x4 = x2 * x2;
            record(x2);
            record(x4);
            state[i] = x4 * x;
        }
        external(&mut state);
        state.iter().copied().for_each(&mut record);
    }
    for &constant in &INTERNAL {
        let x = state[0] + M31::from(constant);
        let x2 = x * x;
        let x4 = x2 * x2;
        record(x2);
        record(x4);
        state[0] = x4 * x;
        internal(&mut state);
        state.iter().copied().for_each(&mut record);
    }
    for constants in &EXTERNAL_FINAL {
        for i in 0..WIDTH {
            let x = state[i] + M31::from(constants[i]);
            let x2 = x * x;
            let x4 = x2 * x2;
            record(x2);
            record(x4);
            state[i] = x4 * x;
        }
        external(&mut state);
        state.iter().copied().for_each(&mut record);
    }
    state.map(|x| x.0 % P)
}
pub fn permute(input: State) -> State {
    execute(input, |_| {})
}

/// Upstream Pad10Sponge overwrite semantics, including capacity-domain full-block padding.
pub fn sponge(message: &[u32]) -> (Digest, Vec<Request>) {
    assert!(message.iter().all(|&x| x < P));
    let mut state = [0; WIDTH];
    let mut offset = 0;
    let mut requests = Vec::new();
    loop {
        let take = (message.len() - offset).min(RATE);
        state[..take].copy_from_slice(&message[offset..offset + take]);
        offset += take;
        let done = offset == message.len();
        if take < RATE {
            state[take] = 1;
            state[take + 1..RATE].fill(0);
        } else if done {
            state[RATE] = (state[RATE] + 1) % P;
        }
        let input = state;
        state = permute(state);
        requests.push(Request {
            input,
            output: state,
        });
        if done {
            return (state[..WORDS].try_into().unwrap(), requests);
        }
    }
}
pub fn frame(kind: u32, level: u32, payload: &[u32]) -> Vec<u32> {
    let mut v = vec![0x544d5031, 1, kind, level];
    v.extend(payload);
    v
}

/// Verifier-only structural checks: no permutation/hash computation here.
pub fn check_sponge(message: &[u32], requests: &[Request]) -> Result<Digest> {
    canonical(message)?;
    ensure!(!requests.is_empty(), "missing sponge requests");
    let mut state = [0; WIDTH];
    let mut offset = 0;
    for (i, r) in requests.iter().enumerate() {
        canonical(&r.input)?;
        canonical(&r.output)?;
        let take = (message.len() - offset).min(RATE);
        state[..take].copy_from_slice(&message[offset..offset + take]);
        offset += take;
        let done = offset == message.len();
        if take < RATE {
            state[take] = 1;
            state[take + 1..RATE].fill(0);
        } else if done {
            state[RATE] = (state[RATE] + 1) % P;
        }
        ensure!(r.input == state, "sponge absorption/capacity/padding");
        state = r.output;
        ensure!(
            done == (i + 1 == requests.len()),
            "sponge permutation count"
        );
    }
    Ok(state[..WORDS].try_into().unwrap())
}
pub fn padded(requests: &[Request]) -> Result<Vec<Request>> {
    ensure!(
        !requests.is_empty() && requests.len() <= 1024,
        "permutation count bound"
    );
    let mut rows = requests.to_vec();
    rows.resize(
        requests.len().next_power_of_two().max(16),
        requests[0].clone(),
    );
    Ok(rows)
}
pub fn boundary(rows: &[Request], lookup: &CommonLookupElements) -> QM31 {
    rows.iter()
        .map(|r| {
            let tuple: Vec<M31> = std::iter::once(RELATION_ID)
                .chain(r.input)
                .chain(r.output)
                .map(M31::from)
                .collect();
            let denom: QM31 = lookup.combine(&tuple);
            QM31::one() / denom
        })
        .sum()
}

#[derive(Clone)]
pub struct Eval {
    pub log_size: u32,
    pub lookup: CommonLookupElements,
}
pub type Component = FrameworkComponent<Eval>;
impl FrameworkEval for Eval {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let input: [E::F; WIDTH] = std::array::from_fn(|_| eval.next_trace_mask());
        let mut state = input.clone();
        external(&mut state);
        for constants in &EXTERNAL_INITIAL {
            for i in 0..WIDTH {
                let x = state[i].clone() + E::F::from(M31::from(constants[i]));
                let x2 = eval.next_trace_mask();
                let x4 = eval.next_trace_mask();
                eval.add_constraint(x2.clone() - x.clone() * x.clone());
                eval.add_constraint(x4.clone() - x2.clone() * x2);
                state[i] = x4 * x;
            }
            external(&mut state);
            for s in &mut state {
                let next = eval.next_trace_mask();
                eval.add_constraint(next.clone() - s.clone());
                *s = next;
            }
        }
        for &constant in &INTERNAL {
            let x = state[0].clone() + E::F::from(M31::from(constant));
            let x2 = eval.next_trace_mask();
            let x4 = eval.next_trace_mask();
            eval.add_constraint(x2.clone() - x.clone() * x.clone());
            eval.add_constraint(x4.clone() - x2.clone() * x2);
            state[0] = x4 * x;
            internal(&mut state);
            for s in &mut state {
                let next = eval.next_trace_mask();
                eval.add_constraint(next.clone() - s.clone());
                *s = next;
            }
        }
        for constants in &EXTERNAL_FINAL {
            for i in 0..WIDTH {
                let x = state[i].clone() + E::F::from(M31::from(constants[i]));
                let x2 = eval.next_trace_mask();
                let x4 = eval.next_trace_mask();
                eval.add_constraint(x2.clone() - x.clone() * x.clone());
                eval.add_constraint(x4.clone() - x2.clone() * x2);
                state[i] = x4 * x;
            }
            external(&mut state);
            for s in &mut state {
                let next = eval.next_trace_mask();
                eval.add_constraint(next.clone() - s.clone());
                *s = next;
            }
        }
        let tuple: Vec<E::F> = std::iter::once(E::F::from(M31::from(RELATION_ID)))
            .chain(input)
            .chain(state)
            .collect();
        eval.add_to_relation(RelationEntry::new(&self.lookup, -E::EF::one(), &tuple));
        eval.finalize_logup_in_pairs();
        eval
    }
}
pub fn witness(rows: &[Request]) -> Result<Vec<Evaluation>> {
    let log = rows.len().ilog2();
    ensure!(rows.len().is_power_of_two() && log >= 4, "trace shape");
    let mut columns = vec![Vec::with_capacity(rows.len()); COLUMNS];
    for row in rows {
        canonical(&row.input)?;
        let mut i = 0;
        let output = execute(row.input, |value| {
            columns[i].push(value);
            i += 1;
        });
        ensure!(
            i == COLUMNS && output == row.output,
            "permutation witness mismatch"
        );
    }
    Ok(columns
        .into_iter()
        .map(|c| {
            CircleEvaluation::new(
                CanonicCoset::new(log).circle_domain(),
                BaseColumn::from_cpu(&c),
            )
        })
        .collect())
}
pub fn interaction(rows: &[Request], lookup: &CommonLookupElements) -> (Vec<Evaluation>, QM31) {
    let mut generator = LogupTraceGenerator::new(rows.len().ilog2());
    generator.col_from_iter(rows.chunks_exact(16).map(|chunk| {
        let tuple: Vec<PackedBaseField> = (0..49)
            .map(|i| {
                PackedBaseField::from_array(std::array::from_fn(|lane| {
                    M31::from(if i == 0 {
                        RELATION_ID
                    } else if i <= WIDTH {
                        chunk[lane].input[i - 1]
                    } else {
                        chunk[lane].output[i - 1 - WIDTH]
                    })
                }))
            })
            .collect();
        let denom: PackedSecureField = lookup.combine(&tuple);
        (-PackedSecureField::one(), denom)
    }));
    generator.finalize_last()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;
    use stwo::core::pcs::TreeVec;
    use stwo::prover::backend::Column;
    use stwo_constraint_framework::{
        InfoEvaluator, assert_constraints_on_trace, expr::ExprEvaluator,
    };
    #[test]
    fn independent_plonky3_permutation_and_padding_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/golden-vectors.json")).unwrap();
        for x in v["permutations"].as_array().unwrap() {
            let input: State = serde_json::from_value(x["input"].clone()).unwrap();
            let expected: State = serde_json::from_value(x["output"].clone()).unwrap();
            assert_eq!(permute(input), expected);
        }
        for x in v["sponges"].as_array().unwrap() {
            let input: Vec<u32> = serde_json::from_value(x["input"].clone()).unwrap();
            let expected: Digest = serde_json::from_value(x["digest"].clone()).unwrap();
            let (d, r) = sponge(&input);
            assert_eq!(d, expected);
            assert_eq!(check_sponge(&input, &r).unwrap(), expected);
        }
    }
    #[test]
    fn quadratic_constraints_and_witness() {
        let lookup = CommonLookupElements::dummy();
        let eval = Eval {
            log_size: 4,
            lookup: lookup.clone(),
        };
        let info = eval.evaluate(InfoEvaluator::empty());
        assert_eq!(info.mask_offsets[1].len(), COLUMNS);
        assert_eq!(info.mask_offsets[2].len(), 4);
        let expr = eval.evaluate(ExprEvaluator::new());
        assert_eq!(expr.constraint_degree_bounds().into_iter().max(), Some(2));
        let input = std::array::from_fn(|i| i as u32);
        let rows = vec![
            Request {
                input,
                output: permute(input)
            };
            16
        ];
        let base = witness(&rows).unwrap();
        let (interaction, sum) = interaction(&rows, &lookup);
        assert_eq!(sum + boundary(&rows, &lookup), QM31::zero());
        let base: Vec<_> = base.iter().map(|c| c.values.to_cpu()).collect();
        let interaction: Vec<_> = interaction.iter().map(|c| c.values.to_cpu()).collect();
        let refs = TreeVec::new(vec![
            vec![],
            base.iter().collect(),
            interaction.iter().collect(),
        ]);
        assert_constraints_on_trace(
            &refs,
            4,
            |e| {
                eval.evaluate(e);
            },
            sum,
        );
        for column in [24, 25, 24 + 4 * 72 + 2, COLUMNS - 1] {
            let mut broken = base.clone();
            broken[column][0] += M31::one();
            let refs = TreeVec::new(vec![
                vec![],
                broken.iter().collect(),
                interaction.iter().collect(),
            ]);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    assert_constraints_on_trace(
                        &refs,
                        4,
                        |e| {
                            eval.evaluate(e);
                        },
                        sum,
                    )
                }))
                .is_err()
            );
        }
    }
}
