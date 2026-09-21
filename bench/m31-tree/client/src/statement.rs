//! Public membership bookkeeping. Verification checks wiring; the AIR proves permutations.
use crate::{
    felt_statement::{self, Workload, felt, hex},
    m31::{self, Digest, Request},
};
use anyhow::{Result, ensure};
use cairo_air::relations::CommonLookupElements;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::collections::{BTreeMap, BTreeSet};
use stwo::core::{
    channel::{Blake2sChannel, Channel},
    fields::qm31::QM31,
};
pub const ALGORITHM: &str =
    "Plonky3-00fe0a98/Poseidon2-M31-width24-RF8-RP22/Pad10-rate15-digest9/Templar-frame-v1";
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    TreeOnly,
    Mixed,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Hash {
    pub digest: Digest,
    pub permutations: Vec<Request>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Path {
    pub index: u32,
    pub leaf: String,
    pub siblings: Vec<Digest>,
    pub leaf_hash: Hash,
    pub nodes: Vec<Hash>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Statement {
    pub version: u32,
    pub algorithm: String,
    pub mode: Mode,
    pub depth: u32,
    pub root: Digest,
    pub packed_root: [String; 2],
    pub paths: Vec<Path>,
    pub residual: Option<Workload>,
}
pub struct PublicData {
    pub m31_requests: Vec<Request>,
    pub m31_rows: Vec<Request>,
    pub residual: Option<felt_statement::PublicData>,
}
pub fn mix_serialized<T: Serialize>(channel: &mut Blake2sChannel, value: &T) {
    let bytes = serde_json::to_vec(value).unwrap();
    channel.mix_u64(bytes.len() as u64);
    channel.mix_u32s(
        &bytes
            .chunks(4)
            .map(|chunk| {
                let mut w = [0; 4];
                w[..chunk.len()].copy_from_slice(chunk);
                u32::from_le_bytes(w)
            })
            .collect::<Vec<_>>(),
    );
}
pub fn leaf_limbs(value: Felt) -> [u32; 9] {
    let bytes = value.to_bytes_le();
    std::array::from_fn(|i| {
        let mut v = 0;
        for bit in 0..28 {
            let pos = i * 28 + bit;
            v |= (((bytes[pos / 8] >> (pos % 8)) & 1) as u32) << bit;
        }
        v
    })
}
pub fn pack(d: Digest) -> Result<[String; 2]> {
    m31::canonical(&d)?;
    let mut bytes = [0u8; 32];
    for (i, &digit) in d[..8].iter().enumerate() {
        for bit in 0..31 {
            if digit & (1 << bit) != 0 {
                let pos = i * 31 + bit;
                bytes[pos / 8] |= 1 << (pos % 8);
            }
        }
    }
    Ok([hex(Felt::from_bytes_le(&bytes)), hex(Felt::from(d[8]))])
}
pub fn unpack(packed: &[String; 2]) -> Result<Digest> {
    let low = felt(&packed[0])?.to_bytes_le();
    let high = felt(&packed[1])?.to_bytes_le();
    ensure!(low[31] == 0, "packed digest low overflow");
    ensure!(
        high[4..].iter().all(|&b| b == 0),
        "packed digest high overflow"
    );
    let h = u32::from_le_bytes(high[..4].try_into().unwrap());
    let mut d = [0; 9];
    for (i, v) in d[..8].iter_mut().enumerate() {
        for bit in 0..31 {
            let pos = i * 31 + bit;
            *v |= (((low[pos / 8] >> (pos % 8)) & 1) as u32) << bit;
        }
    }
    d[8] = h;
    m31::canonical(&d)?;
    Ok(d)
}
fn hash(kind: u32, level: u32, payload: &[u32]) -> Hash {
    let (digest, permutations) = m31::sponge(&m31::frame(kind, level, payload));
    Hash {
        digest,
        permutations,
    }
}
fn node(level: u32, left: Digest, right: Digest) -> Hash {
    hash(2, level, &[left.as_slice(), right.as_slice()].concat())
}
impl Statement {
    pub fn synthetic(mode: Mode) -> Result<Self> {
        let residual = if mode == Mode::Mixed {
            Some(Workload::synthetic().regenerate()?)
        } else {
            None
        };
        let leaves = if let Some(w) = &residual {
            w.validate()?.1
        } else {
            [Felt::from(1001u32), Felt::from(1002u32)]
        };
        let indices = [0x13579bdfu32, 0xeca86420];
        let mut empty = vec![hash(3, 0, &[]).digest];
        for level in 1..=32 {
            empty.push(node(level, empty[level as usize - 1], empty[level as usize - 1]).digest);
        }
        let mut table = BTreeMap::new();
        for i in 0..2 {
            table.insert(
                (0u32, indices[i]),
                hash(1, 0, &leaf_limbs(leaves[i])).digest,
            );
        }
        let mut active = indices.to_vec();
        for level in 0..32 {
            let parents = active.iter().map(|i| i >> 1).collect::<BTreeSet<_>>();
            for &index in &parents {
                let l = *table
                    .get(&(level, index * 2))
                    .unwrap_or(&empty[level as usize]);
                let r = *table
                    .get(&(level, index * 2 + 1))
                    .unwrap_or(&empty[level as usize]);
                table.insert((level + 1, index), node(level + 1, l, r).digest);
            }
            active = parents.into_iter().collect();
        }
        let root = table[&(32, 0)];
        let mut paths = vec![];
        for i in 0..2 {
            let mut index = indices[i];
            let mut siblings = vec![];
            for level in 0..32 {
                siblings.push(
                    *table
                        .get(&(level, index ^ 1))
                        .unwrap_or(&empty[level as usize]),
                );
                index >>= 1;
            }
            paths.push(Path {
                index: indices[i],
                leaf: hex(leaves[i]),
                siblings,
                leaf_hash: hash(1, 0, &leaf_limbs(leaves[i])),
                nodes: vec![],
            });
        }
        let mut s = Self {
            version: 1,
            algorithm: ALGORITHM.into(),
            mode,
            depth: 32,
            root,
            packed_root: pack(root)?,
            paths,
            residual,
        };
        s.fill_paths()?;
        s.validate()?;
        Ok(s)
    }
    fn fill_paths(&mut self) -> Result<()> {
        for path in &mut self.paths {
            ensure!(path.siblings.len() == 32, "path depth");
            path.leaf_hash = hash(1, 0, &leaf_limbs(felt(&path.leaf)?));
            path.nodes.clear();
            let mut cur = path.leaf_hash.digest;
            for (level, &sibling) in path.siblings.iter().enumerate() {
                m31::canonical(&sibling)?;
                let h = if (path.index >> level) & 1 == 0 {
                    node(level as u32 + 1, cur, sibling)
                } else {
                    node(level as u32 + 1, sibling, cur)
                };
                cur = h.digest;
                path.nodes.push(h);
            }
            ensure!(cur == self.root, "regenerated root mismatch");
        }
        Ok(())
    }
    pub fn regenerate(&self) -> Result<Self> {
        let mut out = self.clone();
        if let Some(w) = &self.residual {
            out.residual = Some(w.regenerate()?);
        }
        out.fill_paths()?;
        ensure!(&out == self, "fixture/reference transcript mismatch");
        Ok(out)
    }
    pub fn validate(&self) -> Result<PublicData> {
        ensure!(
            self.version == 1
                && self.algorithm == ALGORITHM
                && self.depth == 32
                && self.paths.len() == 2,
            "statement identity/shape"
        );
        m31::canonical(&self.root)?;
        ensure!(
            unpack(&self.packed_root)? == self.root,
            "packed root binding"
        );
        let residual = match (&self.mode, &self.residual) {
            (Mode::TreeOnly, None) => None,
            (Mode::Mixed, Some(w)) => {
                let (data, cms) = w.validate()?;
                for i in 0..2 {
                    ensure!(
                        felt(&self.paths[i].leaf)? == cms[i],
                        "residual commitment to M31 leaf"
                    );
                    ensure!(
                        self.paths[i].index == w.inputs[i].index,
                        "residual leaf index"
                    );
                }
                Some(data)
            }
            _ => anyhow::bail!("workload mode mismatch"),
        };
        ensure!(
            self.paths[0].index != self.paths[1].index,
            "duplicate path index"
        );
        let mut requests = vec![];
        for path in &self.paths {
            ensure!(
                path.siblings.len() == 32 && path.nodes.len() == 32,
                "path depth"
            );
            let leaf = felt(&path.leaf)?;
            let first = &path.leaf_hash;
            let mut cur =
                m31::check_sponge(&m31::frame(1, 0, &leaf_limbs(leaf)), &first.permutations)?;
            ensure!(cur == first.digest, "leaf digest binding");
            requests.extend(first.permutations.clone());
            for level in 0..32 {
                let sibling = path.siblings[level];
                m31::canonical(&sibling)?;
                let (left, right) = if (path.index >> level) & 1 == 0 {
                    (cur, sibling)
                } else {
                    (sibling, cur)
                };
                let h = &path.nodes[level];
                cur = m31::check_sponge(
                    &m31::frame(
                        2,
                        level as u32 + 1,
                        &[left.as_slice(), right.as_slice()].concat(),
                    ),
                    &h.permutations,
                )?;
                ensure!(cur == h.digest, "node digest binding");
                requests.extend(h.permutations.clone());
            }
            ensure!(cur == self.root, "root endpoint");
        }
        ensure!(requests.len() == 130, "M31 permutation count");
        let rows = m31::padded(&requests)?;
        ensure!(rows.len() == 256, "M31 padded shape");
        Ok(PublicData {
            m31_requests: requests,
            m31_rows: rows,
            residual,
        })
    }
}
impl PublicData {
    pub fn m31_log(&self) -> u32 {
        self.m31_rows.len().ilog2()
    }
    pub fn boundary(&self, lookup: &CommonLookupElements) -> QM31 {
        m31::boundary(&self.m31_rows, lookup)
            + self
                .residual
                .as_ref()
                .map_or(QM31::from(0), |r| r.boundary(lookup))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_encodings_and_oracle_tree_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/golden-vectors.json")).unwrap();
        for x in v["leaves"].as_array().unwrap() {
            let f = felt(x["felt"].as_str().unwrap()).unwrap();
            let d: Digest = serde_json::from_value(x["digest"].clone()).unwrap();
            assert_eq!(hash(1, 0, &leaf_limbs(f)).digest, d);
            assert_eq!(unpack(&pack(d).unwrap()).unwrap(), d);
        }
        let d = [m31::P - 1; 9];
        assert_eq!(unpack(&pack(d).unwrap()).unwrap(), d);
        assert!(pack([m31::P; 9]).is_err());
        let mut p = pack(d).unwrap();
        p[1] = "0x7fffffff".into();
        assert!(unpack(&p).is_err());
        p = pack(d).unwrap();
        let mut bytes = [0; 32];
        bytes[31] = 1;
        p[0] = hex(Felt::from_bytes_le(&bytes));
        assert!(unpack(&p).is_err());
        assert!(unpack(&["0x7fffffff".into(), "0x0".into()]).is_err());
        assert!(felt("0x800000000000011000000000000000000000000000000000000000000000001").is_err());
        assert_ne!(
            hash(1, 0, &leaf_limbs(Felt::ZERO)).digest,
            hash(3, 0, &[]).digest
        );
        let mut empty = hash(3, 0, &[]).digest;
        for level in 0..=32 {
            let expected: Digest = serde_json::from_value(v["empty"][level].clone()).unwrap();
            assert_eq!(empty, expected);
            if level < 32 {
                empty = node(level as u32 + 1, empty, empty).digest;
            }
        }
    }
    #[test]
    fn both_workloads_bind_all_public_calls() {
        for mode in [Mode::TreeOnly, Mode::Mixed] {
            let s = Statement::synthetic(mode).unwrap();
            assert_eq!(s.regenerate().unwrap(), s);
            let d = s.validate().unwrap();
            assert_eq!(d.m31_requests.len(), 130);
            assert_eq!(d.m31_rows.len(), 256);
            if let Some(r) = d.residual {
                assert_eq!(r.requests.len(), 62);
            }
            let mut bad = s.clone();
            bad.paths[0].index ^= 1;
            assert!(bad.validate().is_err());
            let mut bad = s;
            bad.paths[0].nodes[0].permutations[1].input[7] = 0;
            assert!(bad.validate().is_err());
        }
    }
}
