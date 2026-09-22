use crate::hash::{self, PERM_COLS, TAG};
use anyhow::{Result, ensure};
use num_traits::Zero;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use stwo::core::fields::{Field, m31::M31};

pub const W: usize = PERM_COLS + 19;
pub const N: usize = 128;
pub const C: usize = 1273;
pub const SELS: usize = 6;
pub const CUR: usize = PERM_COLS;
pub const SIB: usize = CUR + 9;
pub const BIT: usize = SIB + 9;
pub const OUTPUT: usize = PERM_COLS - 24;
pub const P: u32 = 2147483647;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Public {
    pub chain: String,
    pub pool: String,
    pub root: [u32; 9],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Private {
    pub secret: [u32; 9],
    pub siblings: Vec<[u32; 9]>,
    pub bits: Vec<u32>,
}

fn context(s: &str, pool: bool) -> Result<()> {
    ensure!(
        s.starts_with("0x") && s.len() > 2 && s.len() <= 66,
        "context encoding"
    );
    let h = &s.as_bytes()[2..];
    ensure!(
        h[0] != b'0'
            && h.iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)),
        "canonical nonzero context"
    );
    let mut bytes = [0u8; 32];
    for (i, c) in h.iter().rev().enumerate() {
        let n = if c.is_ascii_digit() {
            c - b'0'
        } else {
            c - b'a' + 10
        };
        bytes[31 - i / 2] |= n << ((i % 2) * 4);
    }
    // Stark field 2^251+17*2^192+1; address upper bound 2^251-256.
    let mut bound = [0u8; 32];
    if pool {
        bound.fill(255);
        bound[0] = 7;
        bound[31] = 0;
    } else {
        bound[0] = 8;
        bound[7] = 17;
        bound[31] = 1;
    }
    ensure!(bytes < bound, "context range");
    Ok(())
}
impl Public {
    pub fn validate(&self) -> Result<()> {
        context(&self.chain, false)?;
        context(&self.pool, true)?;
        ensure!(self.root.iter().all(|x| *x < P), "root field encoding");
        Ok(())
    }
}
impl Private {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.siblings.len() == 32 && self.bits.len() == 32,
            "path length"
        );
        ensure!(
            self.secret
                .iter()
                .chain(self.siblings.iter().flatten())
                .all(|v| *v < P),
            "private field encoding"
        );
        ensure!(self.bits.iter().all(|b| *b <= 1), "direction bits");
        Ok(())
    }
}
pub fn selectors(row: usize) -> [M31; SELS] {
    [
        u32::from(row == 0),
        u32::from((1..=63).contains(&row) && row % 2 == 1),
        u32::from((2..=64).contains(&row) && row % 2 == 0),
        u32::from(row == 64),
        u32::from(row >= 65),
        if (1..=63).contains(&row) && row % 2 == 1 {
            ((row - 1) / 2) as u32
        } else {
            0
        },
    ]
    .map(M31::from)
}
pub fn constraints<F: Field + From<M31>>(
    row: &[F],
    prev: &[F],
    s: &[F],
    root: &[u32; 9],
) -> Vec<F> {
    let mut out = Vec::with_capacity(C);
    hash::constraints(row, &mut out);
    let f = |v| F::from(M31::from(v));
    for i in [0, 1, 2, 3, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23] {
        let expected = match i {
            0 => TAG,
            1 | 2 | 13 => 1,
            _ => 0,
        };
        out.push(s[0] * (row[i] - f(expected)));
    }
    let bit = row[BIT];
    let left: [F; 9] = std::array::from_fn(|j| row[CUR + j] + bit * (row[SIB + j] - row[CUR + j]));
    let right: [F; 9] = std::array::from_fn(|j| row[SIB + j] + bit * (row[CUR + j] - row[SIB + j]));
    for i in 0..24 {
        let expected = match i {
            0 => f(TAG),
            1 => f(1),
            2 => f(3),
            3 => s[5],
            4..=12 => left[i - 4],
            13..=14 => right[i - 13],
            _ => F::zero(),
        };
        out.push(s[1] * (row[i] - expected));
    }
    for i in 0..24 {
        let expected = match i {
            0..=6 => right[i + 2],
            7 => F::one(),
            8..=14 => F::zero(),
            _ => prev[OUTPUT + i],
        };
        out.push(s[2] * (row[i] - expected));
    }
    for j in 0..9 {
        out.push(s[1] * (row[CUR + j] - prev[OUTPUT + j]));
    }
    for j in CUR..W {
        out.push(s[2] * (row[j] - prev[j]));
    }
    out.push(s[1] * bit * (bit - F::one()));
    for j in 0..9 {
        out.push(s[3] * (row[OUTPUT + j] - f(root[j])));
    }
    for i in 0..24 {
        out.push(s[4] * row[i]);
    }
    assert_eq!(out.len(), C);
    out
}
pub fn witness(private: &Private) -> Result<(Vec<Vec<M31>>, [u32; 9])> {
    private.validate()?;
    let frame = |kind: u32, level: u32, payload: &[M31]| {
        let mut x = [TAG, 1, kind, level].map(M31::from).to_vec();
        x.extend_from_slice(payload);
        x
    };
    let mut rows = Vec::with_capacity(N);
    let leaf = hash::sponge(&frame(1, 0, &private.secret.map(M31::from)));
    ensure!(leaf.len() == 1, "leaf shape");
    let mut row = hash::record(leaf[0].0).0;
    row.resize(W, M31::zero());
    rows.push(row);
    let mut cur: [M31; 9] = leaf[0].1[..9].try_into().unwrap();
    for level in 0..32 {
        let sib = private.siblings[level].map(M31::from);
        let bit = private.bits[level];
        let (left, right) = if bit == 0 { (cur, sib) } else { (sib, cur) };
        let mut payload = left.to_vec();
        payload.extend(right);
        let perms = hash::sponge(&frame(3, level as u32, &payload));
        ensure!(perms.len() == 2, "node shape");
        for (input, _) in &perms {
            let mut row = hash::record(*input).0;
            row.extend(cur);
            row.extend(sib);
            row.push(M31::from(bit));
            rows.push(row);
        }
        cur = perms[1].1[..9].try_into().unwrap();
    }
    let mut pad = hash::record([M31::zero(); 24]).0;
    pad.resize(W, M31::zero());
    rows.resize(N, pad);
    Ok((rows, cur.map(|x| x.0)))
}
pub fn validate_trace(rows: &[Vec<M31>], public: &Public) -> Result<()> {
    ensure!(
        rows.len() == N && rows.iter().all(|r| r.len() == W),
        "trace dimensions"
    );
    for i in 0..N {
        ensure!(
            constraints(
                &rows[i],
                &rows[(i + N - 1) % N],
                &selectors(i),
                &public.root
            )
            .iter()
            .all(Zero::is_zero),
            "AIR violation row {i}"
        );
    }
    Ok(())
}
pub fn fresh(rng: &mut impl RngCore) -> Result<(Public, Private)> {
    let mut word = || rng.gen_range(0..P);
    let private = Private {
        secret: std::array::from_fn(|_| word()),
        siblings: (0..32).map(|_| std::array::from_fn(|_| word())).collect(),
        bits: (0..32).map(|_| word() % 2).collect(),
    };
    let (_, root) = witness(&private)?;
    Ok((
        Public {
            chain: "0x534e5f5345504f4c4941".into(),
            pool: "0x123".into(),
            root,
        },
        private,
    ))
}
