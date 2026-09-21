//! All values in this experiment are public. These checks are part of verification.
use anyhow::{Result, ensure};
use cairo_air::relations::{CommonLookupElements, MEMORY_ID_TO_BIG_RELATION_ID};
use serde::{Deserialize, Serialize};
use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};
use std::collections::{BTreeMap, BTreeSet};
use stwo::core::{
    channel::{Blake2sChannel, Channel},
    fields::{m31::M31, qm31::QM31},
};
use stwo_cairo_common::{memory::LARGE_MEMORY_VALUE_ID_BASE, prover_types::cpu::Felt252};
use stwo_constraint_framework::Relation;

pub const MODULUS: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
pub const HASH: &str = "core::poseidon::poseidon_hash_span([left,right])";
const POSEIDON_RELATION_ID: u32 = 1551892206;

#[derive(Clone, Serialize, Deserialize)]
pub struct Statement {
    pub version: u32,
    pub depth: u32,
    pub field_modulus: String,
    pub hash: String,
    pub root: String,
    pub paths: Vec<Path>,
    pub parent_hash_count: usize,
    pub permutation_count: usize,
    pub permutations: Vec<Permutation>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Path {
    pub index: u32,
    pub leaf: String,
    pub siblings: Vec<String>,
    pub levels: Vec<Level>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Level {
    pub level: usize,
    pub direction_bit: u32,
    pub left: String,
    pub right: String,
    pub parent: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Permutation {
    pub path: usize,
    pub level: usize,
    pub phase: String,
    pub input: [String; 3],
    pub output: [String; 3],
}
pub type Request = ([M31; 3], [M31; 3]);
pub struct PublicData {
    pub values: Vec<Felt>,
    pub requests: Vec<Request>,
    pub rows: Vec<Request>,
    pub unique: Vec<(Request, u32)>,
}

pub fn felt(s: &str) -> Result<Felt> {
    let f = Felt::from_hex(s)?;
    // Reject reduction modulo p, alternate encodings, negative values and leading zeroes.
    ensure!(format!("{f:#x}") == s, "noncanonical felt encoding");
    Ok(f)
}
fn triple(a: &[String; 3]) -> Result<[Felt; 3]> {
    Ok([felt(&a[0])?, felt(&a[1])?, felt(&a[2])?])
}
fn hex(f: Felt) -> String {
    format!("{f:#x}")
}
pub fn mix_serialized<T: Serialize>(channel: &mut Blake2sChannel, value: &T) {
    let bytes = serde_json::to_vec(value).unwrap();
    channel.mix_u64(bytes.len() as u64);
    channel.mix_u32s(
        &bytes
            .chunks(4)
            .map(|x| {
                let mut a = [0; 4];
                a[..x.len()].copy_from_slice(x);
                u32::from_le_bytes(a)
            })
            .collect::<Vec<_>>(),
    );
}

impl Statement {
    /// Native witness construction is timed. The saved fixture is only a parity oracle.
    pub fn regenerate(&self) -> Result<Self> {
        ensure!(self.depth == 32 && self.paths.len() == 2, "fixture shape");
        let mut out = self.clone();
        out.permutations.clear();
        for (p, path) in out.paths.iter_mut().enumerate() {
            ensure!(path.siblings.len() == 32, "siblings length");
            path.levels.clear();
            let mut node = felt(&path.leaf)?;
            for l in 0..32 {
                let sibling = felt(&path.siblings[l])?;
                let bit = (path.index >> l) & 1;
                let (left, right) = if bit == 0 {
                    (node, sibling)
                } else {
                    (sibling, node)
                };
                let input = [left, right, Felt::ZERO];
                let mut state = input;
                Poseidon::hades_permutation(&mut state);
                out.permutations.push(Permutation {
                    path: p,
                    level: l,
                    phase: "absorb".into(),
                    input: input.map(hex),
                    output: state.map(hex),
                });
                state[0] += Felt::ONE;
                let input = state;
                Poseidon::hades_permutation(&mut state);
                ensure!(
                    Poseidon::hash_array(&[left, right]) == state[0],
                    "hash_span parity"
                );
                out.permutations.push(Permutation {
                    path: p,
                    level: l,
                    phase: "finalize".into(),
                    input: input.map(hex),
                    output: state.map(hex),
                });
                node = state[0];
                path.levels.push(Level {
                    level: l,
                    direction_bit: bit,
                    left: hex(left),
                    right: hex(right),
                    parent: hex(node),
                });
            }
            ensure!(node == felt(&out.root)?, "fixture root mismatch");
        }
        ensure!(
            serde_json::to_vec(self)? == serde_json::to_vec(&out)?,
            "independent Rust fixture parity failed"
        );
        Ok(out)
    }

    /// No hash/permutation execution occurs here: those obligations are proven by the STARK.
    pub fn validate(&self) -> Result<PublicData> {
        ensure!(
            self.version == 1 && self.depth == 32 && self.paths.len() == 2,
            "statement shape"
        );
        ensure!(
            self.field_modulus == MODULUS && self.hash == HASH,
            "field/hash identity"
        );
        ensure!(
            self.parent_hash_count == 64
                && self.permutation_count == 128
                && self.permutations.len() == 128,
            "call counts"
        );
        let root = felt(&self.root)?;
        let mut all = Vec::new();
        for (p, path) in self.paths.iter().enumerate() {
            ensure!(
                path.siblings.len() == 32 && path.levels.len() == 32,
                "path depth"
            );
            let mut child = felt(&path.leaf)?;
            for l in 0..32 {
                let level = &path.levels[l];
                let bit = (path.index >> l) & 1;
                let sibling = felt(&path.siblings[l])?;
                let pair = if bit == 0 {
                    [child, sibling]
                } else {
                    [sibling, child]
                };
                ensure!(
                    level.level == l && level.direction_bit == bit,
                    "index bit order"
                );
                ensure!(
                    [felt(&level.left)?, felt(&level.right)?] == pair,
                    "child/sibling chain"
                );
                let a = &self.permutations[(p * 32 + l) * 2];
                let b = &self.permutations[(p * 32 + l) * 2 + 1];
                ensure!(
                    a.path == p
                        && a.level == l
                        && a.phase == "absorb"
                        && b.path == p
                        && b.level == l
                        && b.phase == "finalize",
                    "permutation order"
                );
                let ai = triple(&a.input)?;
                let ao = triple(&a.output)?;
                let bi = triple(&b.input)?;
                let bo = triple(&b.output)?;
                ensure!(ai == [pair[0], pair[1], Felt::ZERO], "absorption");
                ensure!(bi == [ao[0] + Felt::ONE, ao[1], ao[2]], "hash_span padding");
                child = felt(&level.parent)?;
                ensure!(child == bo[0], "parent binding");
                all.extend([(ai, ao), (bi, bo)]);
            }
            ensure!(child == root, "root endpoint");
        }
        let values = all
            .iter()
            .flat_map(|(a, b)| a.iter().chain(b))
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let ids = values
            .iter()
            .enumerate()
            .map(|(i, v)| (*v, M31::from(LARGE_MEMORY_VALUE_ID_BASE + i as u32)))
            .collect::<BTreeMap<_, _>>();
        let requests = all
            .into_iter()
            .map(|(a, b)| (a.map(|v| ids[&v]), b.map(|v| ids[&v])))
            .collect::<Vec<_>>();
        let (unique, rows) = derive_rows(&requests)?;
        Ok(PublicData {
            values,
            requests,
            rows,
            unique,
        })
    }
}

pub fn derive_rows(requests: &[Request]) -> Result<(Vec<(Request, u32)>, Vec<Request>)> {
    ensure!(
        !requests.is_empty() && requests.len() <= 128,
        "request bound"
    );
    let mut map = BTreeMap::new();
    for &(input, output) in requests {
        let (previous, n) = map.entry(input).or_insert((output, 0u32));
        ensure!(*previous == output, "conflicting permutation outputs");
        *n += 1;
    }
    let unique = map
        .into_iter()
        .map(|(a, (b, n))| ((a, b), n))
        .collect::<Vec<_>>();
    let mut rows = unique.iter().map(|(r, _)| *r).collect::<Vec<_>>();
    rows.resize(rows.len().next_power_of_two().max(16), rows[0]);
    Ok((unique, rows))
}
impl PublicData {
    pub fn aggregator_log_size(&self) -> u32 {
        self.rows.len().ilog2()
    }
    pub fn boundary(&self, lookup: &CommonLookupElements) -> QM31 {
        let mut total = QM31::from(0);
        for (input, output) in &self.requests {
            let tuple = [
                M31::from(POSEIDON_RELATION_ID),
                input[0],
                input[1],
                input[2],
                output[0],
                output[1],
                output[2],
            ];
            let denom: QM31 = lookup.combine(&tuple);
            total += QM31::from(1) / denom;
        }
        for (input, output) in &self.rows {
            for id in input.iter().chain(output) {
                let value = self.values[(id.0 - LARGE_MEMORY_VALUE_ID_BASE) as usize];
                let mut tuple = vec![MEMORY_ID_TO_BIG_RELATION_ID, *id];
                tuple.extend(Felt252::from(value).get_limbs());
                let denom: QM31 = lookup.combine(&tuple);
                total -= QM31::from(1) / denom;
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Statement {
        serde_json::from_str(include_str!(
            "../../../poseidon-membership/fixtures/two-paths.json"
        ))
        .unwrap()
    }
    #[test]
    fn reference_and_verifier_bookkeeping() {
        let s = fixture().regenerate().unwrap();
        let d = s.validate().unwrap();
        assert_eq!(d.requests.len(), 128);
        assert_eq!(d.rows.len(), 128);
    }
    #[test]
    fn reject_public_link_mutations() {
        let s = fixture();
        let mut cases = Vec::new();
        let mut c = s.clone();
        c.root = "0x0".into();
        cases.push(c);
        let mut c = s.clone();
        c.paths[0].index ^= 1;
        cases.push(c);
        let mut c = s.clone();
        c.paths[0].siblings[0] = "0x1".into();
        cases.push(c);
        let mut c = s.clone();
        c.permutations[1].input[0] = "0x1".into();
        cases.push(c);
        let mut c = s.clone();
        c.permutations.swap(0, 1);
        cases.push(c);
        let mut c = s.clone();
        c.paths[0].leaf = "0x00".into();
        cases.push(c);
        let mut c = s.clone();
        c.paths[0].siblings.pop();
        cases.push(c);
        for c in cases {
            assert!(c.validate().is_err());
        }
    }
    #[test]
    fn duplicate_and_padding_accounting() {
        let a = ([M31::from(1); 3], [M31::from(2); 3]);
        let b = ([M31::from(3); 3], [M31::from(4); 3]);
        let (u, r) = derive_rows(&[a, b, a]).unwrap();
        assert_eq!(u, vec![(a, 2), (b, 1)]);
        assert_eq!(r.len(), 16);
        assert_eq!(&r[2..], &vec![a; 14]);
        assert!(derive_rows(&[a, (a.0, b.1)]).is_err());
        assert!(felt(MODULUS).is_err());
    }
}
