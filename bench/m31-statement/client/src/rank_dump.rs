//! Rank-substrate dump for the L2-lemma empirical probe.
//!
//! For the payment-shaped M31 statement (log 8, 256 rows, 1,172 columns):
//! dumps, for 1 OOD-style point + 23 query-style points, the barycentric
//! weight vectors of the trace coset (QM31 weights = 4 M31 functionals per
//! point, matching the observation accounting), the observation deltas
//! between two statements with independent private parameters (secant
//! family samples), and single-pad observation contributions. Analysis runs
//! offline in ../../results/rank-analysis.py.
//!
//! Measurement infrastructure only; no privacy claim.
use anyhow::{Result, ensure};
use serde_json::json;
use stwo::core::{
    circle::CirclePoint,
    channel::{Blake2sChannel, Channel},
    fields::m31::M31,
    fields::qm31::{QM31, SecureField},
    poly::circle::CanonicCoset,
};
use stwo::prover::backend::Column;
use stwo::prover::poly::BitReversedOrder;
use crate::{m31, statement};

fn m31s(v: SecureField) -> [u32; 4] {
    v.to_m31_array().map(|x| x.0)
}

pub fn dump(out_path: &str) -> Result<()> {
    let log_size = 8u32;
    let rows = 1usize << log_size;
    let coset = CanonicCoset::new(log_size);

    let mut ch = Blake2sChannel::default();
    ch.mix_u64(0x52414e4b); // "RANK"
    let mut point = || CirclePoint::<SecureField>::get_random_point(&mut ch);

    // 1 OOD-style point (generic: off odds(8) and odds(11) almost surely)
    // + 23 query-style points on the evaluation coset odds(11).
    let mut points = vec![point()];
    for _ in 0..23 {
        let p = point();
        points.push(p.mul(1u128 << 11));
    }
    // weights[t][i] = QM31 barycentric weight of trace row i at point t.
    let weights: Vec<Vec<[u32; 4]>> = points
        .iter()
        .map(|p| {
            let w = stwo::prover::poly::circle::CircleEvaluation::<
                stwo::prover::backend::simd::SimdBackend,
                M31,
                BitReversedOrder,
            >::barycentric_weights(coset, *p)
            .to_cpu();
            w.iter().take(rows).map(|x| m31s(*x)).collect()
        })
        .collect();

    // Secant family samples: observation deltas between statements with
    // independent private parameters (multiple pairs for a rank estimate).
    let mut secant_samples: Vec<serde_json::Value> = Vec::new();
    let mut secant_rows_samples: Vec<serde_json::Value> = Vec::new();
    let mut ncols_out = None;
    for pair in 0..24u64 {
        let a = statement::synthetic("0x434841494e", "0x456", 1 + pair)?;
        let b = statement::synthetic("0x434841494e", "0x456", 0xdead0000 + pair)?;
        let da = a.validate()?;
        let db = b.validate()?;
        ensure!(
            da.rows.len() == db.rows.len(),
            "row-count mismatch; probe needs equal log sizes"
        );
        let trace_a = m31::witness(&da.rows)?;
        let trace_b = m31::witness(&db.rows)?;
        let ncols = trace_a.len();
        ensure!(ncols == m31::COLUMNS, "column count");
        ncols_out = Some(ncols);
        let mut secant_delta = vec![vec![[0u32; 4]; ncols]; points.len()];
        for (t, w) in weights.iter().enumerate() {
            for j in 0..ncols {
                let va = trace_a[j].values.as_slice();
                let vb = trace_b[j].values.as_slice();
                let mut acc = QM31::from_m31_array(std::array::from_fn(|_| M31::from(0)));
                for i in 0..rows {
                    let wq = SecureField::from_m31_array(
                        std::array::from_fn(|k| M31::from(w[i][k])),
                    );
                    acc += wq * (va[i] - vb[i]);
                }
                secant_delta[t][j] = m31s(acc);
            }
        }
        secant_samples.push(json!({
            "pair": pair,
            "delta": secant_delta,
        }));
        if pair < 2 {
            let mut delta_rows = Vec::new();
            for i in 0..rows {
                let mut r = Vec::new();
                for j in 0..ncols {
                    let va = trace_a[j].values.as_slice();
                    let vb = trace_b[j].values.as_slice();
                    r.push((va[i] - vb[i]).0);
                }
                delta_rows.push(r);
            }
            secant_rows_samples.push(json!({ "pair": pair, "delta_rows": delta_rows }));
        }
    }
    let _ = &secant_rows_samples;
    let ncols = ncols_out.unwrap();

    // Single-pad contributions: pad row at position pos with values v; the
    // contribution to (t, j) is weights[t][pos] * v_j. Dump the weight
    // column and the pad values; Python composes the products.
    let mut pads = Vec::new();
    let mut prng = 0x50414444u64;
    let mut next_word = move || {
        prng = prng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((prng >> 33) as u32) % m31::P
    };
    for _ in 0..200 {
        let input: [u32; 24] = std::array::from_fn(|_| next_word());
        let output = m31::permute(input);
        let pos = (next_word() as usize) % rows;
        let values: Vec<u32> = input.iter().chain(output.iter()).copied().collect();
        let wcol: Vec<[u32; 4]> = weights.iter().map(|w| w[pos]).collect();
        pads.push(json!({ "position": pos, "values": values, "weights": wcol }));
    }
    // Row-expansion samples: the witness column expansion of K random valid
    // rows (each at a distinct position in an otherwise-zero-row trace),
    // minus the all-zero trace — the manifold-span substrate.
    let mut expansion_samples: Vec<serde_json::Value> = Vec::new();
    {
        let zero_input = [0u32; 24];
        let zero_output = m31::permute(zero_input);
        let zero_row = m31::Request { input: zero_input, output: zero_output };
        let zero_rows = vec![zero_row.clone(); rows];
        let zero_trace = m31::witness(&zero_rows)?;
        for k in 0..892usize {
            let mut rows_k = zero_rows.clone();
            let input: [u32; 24] = std::array::from_fn(|_| next_word());
            let output = m31::permute(input);
            let pos = (next_word() as usize) % rows;
            rows_k[pos] = m31::Request { input, output };
            let trace_k = m31::witness(&rows_k)?;
            let mut values = Vec::new();
            for j in 0..ncols {
                let va = trace_k[j].values.as_slice();
                let vz = zero_trace[j].values.as_slice();
                values.push((va[pos] - vz[pos]).0);
            }
            expansion_samples.push(json!({ "k": k, "position": pos, "values": values }));
        }
    }

    let report = json!({
        "scope": "rank-substrate dump for the L2 empirical probe; no privacy claim",
        "log_size": log_size,
        "rows": rows,
        "columns": ncols,
        "points": points.len(),
        "point_kinds": ["ood", "query x23"],
        "weights": weights,
        "secant_samples": secant_samples,
        "secant_rows_samples": secant_rows_samples,
        "expansion_samples": expansion_samples,
        "pads": pads,
    });
    std::fs::write(out_path, serde_json::to_vec_pretty(&report)?)?;
    println!("wrote {out_path}");

    // Compact binary companion: expansion matrix only (892 x 1172 u32 LE) for fast rank analysis.
    let bin_path = out_path.replace(".json", "-expansion.bin");
    let mut bytes = Vec::with_capacity(expansion_samples.len() * ncols * 4);
    for s in &expansion_samples {
        for v in s["values"].as_array().unwrap() {
            bytes.extend_from_slice(&(v.as_u64().unwrap() as u32).to_le_bytes());
        }
    }
    std::fs::write(&bin_path, &bytes)?;
    println!("wrote {bin_path} ({}x{})", expansion_samples.len(), ncols);
    Ok(())
}
