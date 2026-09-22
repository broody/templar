//! Empirical Gauss-Newton solve probe for the L2-equalization construction.
//!
//! The per-position problem: given a target d (in the 68-dim statement-delta
//! space), find K input pairs (a_j, b_j) such that
//!   Σ_j (E(a_j) − E(b_j)) = d
//! where E is the 1,172-column expansion of a valid permutation row. Known
//! preimages (the two statements' rows) provide exact initialization; the
//! probe measures how far the solve reaches from there.
//!
//! Measurement infrastructure only; no privacy claim.
use crate::constants::{EXTERNAL_FINAL, EXTERNAL_INITIAL, INTERNAL};
use crate::dual::Dual;
use crate::m31::{self, P};
use anyhow::{Result, ensure};
use serde_json::json;

type D = Dual<24>;

#[derive(Clone)]
struct DRow {
    values: Vec<u32>,
    jac: Vec<[u32; 24]>,
}

fn external_dual(s: &mut [D; 24]) {
    for offset in (0..24).step_by(4) {
        let x: [D; 4] = std::array::from_fn(|i| s[offset + i]);
        let matrix = [[2u32, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
        for i in 0..4 {
            s[offset + i] = (0..4)
                .map(|j| x[j] * D::c(matrix[i][j]))
                .reduce(|a, b| a + b)
                .unwrap();
        }
    }
    let sums: [D; 4] = std::array::from_fn(|k| {
        (0..24)
            .step_by(4)
            .map(|i| s[i + k])
            .reduce(|a, b| a + b)
            .unwrap()
    });
    for i in 0..24 {
        s[i] = s[i] + sums[i % 4];
    }
}
fn internal_dual(s: &mut [D; 24]) {
    for i in 1..24 {
        s[i] = s[i] * D::c(8) + D::c(1);
    }
    let sums: [D; 4] = std::array::from_fn(|k| {
        (0..24)
            .step_by(4)
            .map(|i| s[i + k])
            .reduce(|a, b| a + b)
            .unwrap()
    });
    let out: [D; 24] = std::array::from_fn(|i| s[i] + sums[i % 4]);
    *s = out;
}

/// Dual expansion mirroring m31::execute (same recording order, 1,172 columns).
fn execute_dual(input: &[u32; 24]) -> Result<DRow> {
    let mut state: [D; 24] = std::array::from_fn(|i| D::var(input[i], i));
    let mut values = Vec::with_capacity(m31::COLUMNS);
    let mut jac = Vec::with_capacity(m31::COLUMNS);
    let mut record = |d: &D| {
        values.push(d.v);
        jac.push(d.g);
    };
    state.iter().for_each(|d| record(d));
    external_dual(&mut state);
    for constants in &EXTERNAL_INITIAL {
        for i in 0..24 {
            let x = state[i] + constants[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            record(&x2);
            record(&x4);
            state[i] = x4 * x;
        }
        external_dual(&mut state);
        state.iter().for_each(|d| record(d));
    }
    for &constant in &INTERNAL {
        let x = state[0] + constant;
        let x2 = x * x;
        let x4 = x2 * x2;
        record(&x2);
        record(&x4);
        state[0] = x4 * x;
        internal_dual(&mut state);
        state.iter().for_each(|d| record(d));
    }
    for constants in &EXTERNAL_FINAL {
        for i in 0..24 {
            let x = state[i] + constants[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            record(&x2);
            record(&x4);
            state[i] = x4 * x;
        }
        external_dual(&mut state);
        state.iter().for_each(|d| record(d));
    }
    if values.len() != m31::COLUMNS {
        anyhow::bail!("dual expansion column count");
    }
    Ok(DRow { values, jac })
}

fn modinv(x: i64) -> i64 {
    let x = x.rem_euclid(P as i64);
    let e = (P - 2) as u32;
    ((x as i128).pow(e).rem_euclid(P as i128)) as i64
}

/// Mod-p linear solve via Gaussian elimination (any-nonzero pivoting).
/// Returns None if a column has no pivot (singular).
fn solve_modp(a: &mut Vec<Vec<i64>>, b: &mut Vec<i64>, n: usize) -> Option<Vec<i64>> {
    for col in 0..n {
        let mut pr = None;
        for r in col..n {
            if a[r][col].rem_euclid(P as i64) != 0 {
                pr = Some(r);
                break;
            }
        }
        a.swap(col, pr?);
        b.swap(col, pr.unwrap());
        let inv = modinv(a[col][col]);
        for j in 0..n {
            a[col][j] = a[col][j] * inv % (P as i64);
        }
        b[col] = b[col] * inv % (P as i64);
        for r in 0..n {
            if r != col && a[r][col].rem_euclid(P as i64) != 0 {
                let f = a[r][col];
                for j in 0..n {
                    a[r][j] = (a[r][j] - f * a[col][j]) % (P as i64);
                }
                b[r] = (b[r] - f * b[col]) % (P as i64);
            }
        }
    }
    Some((0..n).map(|i| b[i].rem_euclid(P as i64)).collect())
}

/// One Gauss-Newton attempt (24K unknowns, 1,172 residual equations).
/// Returns Some(steps) on exact success (residual identically zero).
fn gauss_newton(
    xs: &mut Vec<[u32; 24]>,
    target: &[u32],
    max_steps: usize,
    damp: u32,
) -> Option<usize> {
    let k = xs.len();
    let n_unknown = 24 * k;
    for step in 0..max_steps {
        let mut j_cols: Vec<DRow> = Vec::new();
        for x in xs.iter() {
            match execute_dual(x) {
                Ok(r) => j_cols.push(r),
                Err(_) => return None,
            }
        }
        let mut rows_f = vec![0i64; m31::COLUMNS];
        for (idx, er) in j_cols.iter().enumerate() {
            let sign = if idx % 2 == 0 { 1i64 } else { -1i64 };
            for r in 0..m31::COLUMNS {
                rows_f[r] += sign * er.values[r] as i64;
            }
        }
        for r in 0..m31::COLUMNS {
            rows_f[r] = (rows_f[r] - target[r] as i64) % (P as i64);
        }
        if rows_f.iter().all(|v| v.rem_euclid(P as i64) == 0) {
            return Some(step);
        }
        let mut jt_j = vec![vec![0i64; n_unknown]; n_unknown];
        let mut jt_f = vec![0i64; n_unknown];
        for c1 in 0..n_unknown {
            let (g1, s1c) = (c1 / 24, c1 % 24);
            let s1 = if g1 % 2 == 0 { 1i64 } else { -1i64 };
            for c2 in c1..n_unknown {
                let (g2, s2c) = (c2 / 24, c2 % 24);
                let s2 = if g2 % 2 == 0 { 1i64 } else { -1i64 };
                let mut acc = 0i64;
                for r in 0..m31::COLUMNS {
                    acc += (j_cols[g1].jac[r][s1c] as i64)
                        * (j_cols[g2].jac[r][s2c] as i64)
                        * s1
                        * s2;
                }
                jt_j[c1][c2] = acc % (P as i64);
                jt_j[c2][c1] = jt_j[c1][c2];
            }
            let mut accf = 0i64;
            for r in 0..m31::COLUMNS {
                accf += (j_cols[g1].jac[r][s1c] as i64) * s1 * rows_f[r];
            }
            jt_f[c1] = accf % (P as i64);
        }
        for i in 0..n_unknown {
            jt_j[i][i] = (jt_j[i][i] + damp as i64) % (P as i64);
        }
        let delta = solve_modp(&mut jt_j, &mut jt_f, n_unknown)?;
        for (idx, x) in xs.iter_mut().enumerate() {
            for c in 0..24 {
                x[c] = (x[c] as i64 + delta[idx * 24 + c]).rem_euclid(P as i64) as u32;
            }
        }
    }
    None
}

fn rand_row(s: u64) -> [u32; 24] {
    let mut state = s.wrapping_mul(0x9e3779b97f4a7c15) | 1;
    std::array::from_fn(|_| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((state >> 33) as u32) % m31::P
    })
}
fn perturb(x: &[u32; 24], s: u64) -> [u32; 24] {
    let mut out = *x;
    let mut state = s.wrapping_mul(0x51ed270b) | 1;
    for c in out.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *c = (*c + (state >> 33) as u32) % m31::P;
    }
    out
}

pub fn run(out_path: &str) -> Result<()> {
    let a = crate::statement::synthetic("0x434841494e", "0x456", 1)?;
    let b = crate::statement::synthetic("0x434841494e", "0x456", 0xdeadbeef)?;
    let da = a.validate()?;
    let db = b.validate()?;
    ensure!(da.rows.len() == db.rows.len(), "row mismatch");
    let count = 70usize;
    let mut diffs = Vec::new();
    for i in 0..count {
        let ea = execute_dual(&da.rows[i].input)?;
        let eb = execute_dual(&db.rows[i].input)?;
        let d: Vec<u32> = (0..m31::COLUMNS)
            .map(|r| (ea.values[r] + P - eb.values[r]) % P)
            .collect();
        diffs.push((d, da.rows[i].input, db.rows[i].input));
    }
    let mut reports = Vec::new();

    // T1: K=1 on single known differences.
    for i in [0usize, 17, 40] {
        let (d, xa, xb) = (diffs[i].0.clone(), diffs[i].1, diffs[i].2);
        let mut xs = vec![xa, xb];
        let steps = gauss_newton(&mut xs, &*d, 8, 0);
        reports.push(json!({"test": "T1-known-start", "i": i, "k": 1, "steps": steps}));
        let mut ok = 0;
        for s in 0..8u64 {
            let mut xs = vec![rand_row(s * 2 + 1), rand_row(s * 2 + 2)];
            if gauss_newton(&mut xs, &d, 40, 1).is_some() {
                ok += 1;
            }
        }
        reports.push(json!({"test": "T1-random-starts", "i": i, "k": 1, "successes": ok, "of": 8}));
    }

    // T2: K=2 on two-difference sums; known start, then perturbed starts on a perturbed target.
    for (i1, i2) in [(0usize, 1usize), (10usize, 33usize)] {
        let d: Vec<u32> = (0..m31::COLUMNS)
            .map(|r| (diffs[i1].0[r] + diffs[i2].0[r]) % P)
            .collect();
        let mut xs = vec![diffs[i1].1, diffs[i1].2, diffs[i2].1, diffs[i2].2];
        let steps = gauss_newton(&mut xs, &*d, 8, 0);
        reports.push(json!({"test": "T2-known-start", "i": format!("{i1}+{i2}"), "k": 2, "steps": steps}));
        let (i3, lam) = (5usize, 3u32);
        let d2: Vec<u32> = (0..m31::COLUMNS)
            .map(|r| (d[r] + lam * diffs[i3].0[r]) % P)
            .collect();
        let mut ok = 0;
        for s in 0..8u64 {
            let mut xs = vec![
                perturb(&diffs[i1].1, s),
                perturb(&diffs[i1].2, s + 100),
                perturb(&diffs[i2].1, s + 200),
                perturb(&diffs[i2].2, s + 300),
            ];
            if gauss_newton(&mut xs, &*d2, 40, 1).is_some() {
                ok += 1;
            }
        }
        reports.push(json!({"test": "T2-perturbed", "i": format!("{i1}+{i2}+{lam}*{i3}"), "k": 2, "successes": ok, "of": 8}));
    }

    // T3: K=4 on random delta-space targets, perturbed starts.
    let mut ok = 0;
    for s in 0..8u64 {
        let mut d = [0u32; 1172];
        let mut xs = Vec::new();
        for j in 0..4usize {
            let i = (s as usize * 7 + j * 3) % count;
            let lam = 1 + ((s * 11 + j as u64) as u32) % 97;
            for r in 0..m31::COLUMNS {
                d[r] = (d[r] + lam * diffs[i].0[r]) % P;
            }
            xs.push(perturb(&diffs[i].1, s + j as u64));
            xs.push(perturb(&diffs[i].2, s + j as u64 + 50));
        }
        if gauss_newton(&mut xs, &d, 40, 1).is_some() {
            ok += 1;
        }
    }
    reports.push(json!({"test": "T3-random-combos", "k": 4, "successes": ok, "of": 8}));

    let report = json!({
        "scope": "empirical Gauss-Newton solve probe for the L2 equalization construction; no privacy claim",
        "expansion_columns": m31::COLUMNS,
        "delta_sample_rows": count,
        "notes": "known-preimage starts give zero residual (sanity); informative columns are perturbed/random-start convergence",
        "reports": reports,
    });
    std::fs::write(out_path, serde_json::to_vec_pretty(&report)?)?;
    println!("wrote {out_path}");
    Ok(())
}
