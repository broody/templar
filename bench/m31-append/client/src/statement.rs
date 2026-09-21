//! Public append bookkeeping. Every check here is mirrored inside the Cairo verifier program.
use crate::m31::{self, Digest, Request};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};
use std::collections::BTreeMap;
use stwo::core::{
    channel::{Blake2sChannel, Channel},
    fields::{m31::M31, qm31::QM31},
};

pub const CAPACITY: u64 = 1u64 << 32;
pub const DOMAIN_WORD: u32 = 0x544d5041;
pub const VERSION: u32 = 1;
pub const REQUESTS_PER_APPEND: usize = 129;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub siblings: Vec<Digest>,
    pub requests: Vec<Request>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub chain_id: String,
    pub pool: String,
    pub old_count: u64,
    pub new_count: u64,
    pub old_root: Digest,
    pub new_root: Digest,
    pub commitments: Vec<String>,
    pub steps: Vec<Step>,
}
pub struct PublicData {
    pub requests: Vec<Request>,
    pub rows: Vec<Request>,
    pub words: Vec<u32>,
}
impl PublicData {
    pub fn log_size(&self) -> u32 {
        self.rows.len().ilog2()
    }
}
pub fn felt(s: &str) -> Result<Felt> {
    let f = Felt::from_hex(s)?;
    ensure!(format!("{f:#x}") == s, "noncanonical felt252");
    Ok(f)
}
pub fn hex(f: Felt) -> String {
    format!("{f:#x}")
}
pub fn felt_words(f: Felt) -> [u32; 9] {
    let bytes = f.to_bytes_le();
    std::array::from_fn(|i| {
        (0..28).fold(0, |v, b| {
            v | ((((bytes[(i * 28 + b) / 8] >> ((i * 28 + b) % 8)) & 1) as u32) << b)
        })
    })
}
pub fn pack(d: Digest) -> Result<[Felt; 2]> {
    m31::canonical(&d)?;
    let mut bytes = [0u8; 32];
    for (i, &v) in d[..8].iter().enumerate() {
        for bit in 0..31 {
            if v & (1 << bit) != 0 {
                let p = i * 31 + bit;
                bytes[p / 8] |= 1 << (p % 8);
            }
        }
    }
    Ok([Felt::from_bytes_le(&bytes), Felt::from(d[8])])
}
pub fn empty_leaf() -> Digest {
    // Pinned independently generated Plonky3 vector, not leaf(0).
    [
        588219270, 1912894104, 1451304488, 1990490117, 350701116, 1513791928, 68338834, 1281125379,
        519559439,
    ]
}
pub fn transition_domain() -> Felt {
    Felt::from_bytes_be_slice(b"M31_APPEND_V1")
}
pub fn checked_shape(old: u64, new: u64, n: usize) -> Result<u32> {
    ensure!((1..=2).contains(&n), "active append count");
    ensure!(
        old <= CAPACITY - n as u64 && new == old + n as u64,
        "append count/capacity"
    );
    Ok((REQUESTS_PER_APPEND * n).next_power_of_two().ilog2())
}
fn consume_hash(kind: u32, level: u32, payload: &[u32], requests: &[Request]) -> Result<Digest> {
    m31::check_sponge(&m31::frame(kind, level, payload), requests)
}
impl Statement {
    pub fn validate(&self) -> Result<PublicData> {
        let n = self.commitments.len();
        let log = checked_shape(self.old_count, self.new_count, n)?;
        ensure!(self.steps.len() == n, "step count");
        let chain = felt(&self.chain_id)?;
        let pool = felt(&self.pool)?;
        let pool_number = num_bigint::BigUint::from_bytes_le(&pool.to_bytes_le());
        ensure!(
            pool_number > num_bigint::BigUint::from(0u32)
                && pool_number
                    < (num_bigint::BigUint::from(1u32) << 251) - num_bigint::BigUint::from(256u32),
            "pool address bounds"
        );
        m31::canonical(&self.old_root)?;
        m31::canonical(&self.new_root)?;
        let commitments = self
            .commitments
            .iter()
            .map(|x| felt(x))
            .collect::<Result<Vec<_>>>()?;
        let mut words = vec![DOMAIN_WORD, VERSION, n as u32];
        words.extend(felt_words(chain));
        words.extend(felt_words(pool));
        for count in [self.old_count, self.new_count] {
            words.extend([(count & ((1 << 28) - 1)) as u32, (count >> 28) as u32]);
        }
        words.extend(self.old_root);
        words.extend(self.new_root);
        for &cm in &commitments {
            words.extend(felt_words(cm));
        }
        let mut root = self.old_root;
        let mut requests = Vec::new();
        for (i, step) in self.steps.iter().enumerate() {
            ensure!(
                step.siblings.len() == 32 && step.requests.len() == REQUESTS_PER_APPEND,
                "append witness shape"
            );
            let index = self.old_count + i as u64;
            let mut old = empty_leaf();
            let mut new = consume_hash(1, 0, &felt_words(commitments[i]), &step.requests[..1])?;
            for (level, &sibling) in step.siblings.iter().enumerate() {
                m31::canonical(&sibling)?;
                let ordered = |cur: Digest| {
                    if (index >> level) & 1 == 0 {
                        [cur.as_slice(), sibling.as_slice()].concat()
                    } else {
                        [sibling.as_slice(), cur.as_slice()].concat()
                    }
                };
                let offset = 1 + level * 4;
                old = consume_hash(
                    2,
                    level as u32 + 1,
                    &ordered(old),
                    &step.requests[offset..offset + 2],
                )?;
                new = consume_hash(
                    2,
                    level as u32 + 1,
                    &ordered(new),
                    &step.requests[offset + 2..offset + 4],
                )?;
            }
            ensure!(old == root, "old empty path/root");
            root = new;
            for sibling in &step.siblings {
                words.extend(sibling);
            }
            for request in &step.requests {
                words.extend(request.input);
                words.extend(request.output);
            }
            requests.extend(step.requests.clone());
        }
        ensure!(root == self.new_root, "new root/step chaining");
        m31::canonical(&words)?;
        ensure!(
            words.len() == 43 + 6489 * n,
            "canonical transcript word count"
        );
        let rows = m31::padded(&requests)?;
        ensure!(
            rows.len() == 1usize << log && rows.len() * 2 < m31::P as usize,
            "derived rows/relation bound"
        );
        Ok(PublicData {
            requests,
            rows,
            words,
        })
    }
    pub fn transition_preimage(&self) -> Result<Vec<Felt>> {
        let old = pack(self.old_root)?;
        let new = pack(self.new_root)?;
        let mut fields = vec![
            transition_domain(),
            felt(&self.chain_id)?,
            felt(&self.pool)?,
            old[0],
            old[1],
            Felt::from(self.old_count),
            Felt::from(self.commitments.len()),
        ];
        fields.extend(
            self.commitments
                .iter()
                .map(|s| felt(s))
                .collect::<Result<Vec<_>>>()?,
        );
        fields.extend([new[0], new[1], Felt::from(self.new_count)]);
        Ok(fields)
    }
    pub fn public_output(&self) -> Result<[Felt; 8]> {
        let old = pack(self.old_root)?;
        Ok([
            transition_domain(),
            felt(&self.chain_id)?,
            felt(&self.pool)?,
            old[0],
            old[1],
            Felt::from(self.old_count),
            Poseidon::hash_array(&self.transition_preimage()?),
            Felt::from(self.commitments.len()),
        ])
    }
}
pub fn mix_words(channel: &mut Blake2sChannel, words: &[u32]) {
    channel.mix_u64(words.len() as u64);
    let packed = words
        .chunks(4)
        .map(|c| {
            let mut a = [M31::from(0); 4];
            for (i, &v) in c.iter().enumerate() {
                a[i] = M31::from(v);
            }
            QM31::from_m31_array(a)
        })
        .collect::<Vec<_>>();
    channel.mix_felts(&packed);
}
fn node(level: u32, l: Digest, r: Digest) -> (Digest, Vec<Request>) {
    m31::sponge(&m31::frame(
        2,
        level,
        &[l.as_slice(), r.as_slice()].concat(),
    ))
}
fn tree(leaves: &[Felt]) -> (Digest, BTreeMap<(u32, u64), Digest>, Vec<Digest>) {
    let mut empty = vec![empty_leaf()];
    for level in 1..=32 {
        empty.push(node(level, empty[level as usize - 1], empty[level as usize - 1]).0);
    }
    let mut table = BTreeMap::new();
    for (i, &cm) in leaves.iter().enumerate() {
        table.insert(
            (0, i as u64),
            m31::sponge(&m31::frame(1, 0, &felt_words(cm))).0,
        );
    }
    for level in 0..32 {
        let count = (leaves.len() as u64).div_ceil(1u64 << (level + 1));
        for index in 0..count {
            let l = *table
                .get(&(level, index * 2))
                .unwrap_or(&empty[level as usize]);
            let r = *table
                .get(&(level, index * 2 + 1))
                .unwrap_or(&empty[level as usize]);
            table.insert((level + 1, index), node(level + 1, l, r).0);
        }
    }
    (*table.get(&(32, 0)).unwrap_or(&empty[32]), table, empty)
}
pub fn synthetic(
    chain: Felt,
    pool: Felt,
    initial: &[Felt],
    appended: &[Felt],
) -> Result<Statement> {
    checked_shape(
        initial.len() as u64,
        (initial.len() + appended.len()) as u64,
        appended.len(),
    )?;
    let mut leaves = initial.to_vec();
    let old_root = tree(&leaves).0;
    let mut steps = vec![];
    for &cm in appended {
        let (root, table, empty) = tree(&leaves);
        let index = leaves.len() as u64;
        let siblings = (0..32)
            .map(|level| {
                *table
                    .get(&(level, (index >> level) ^ 1))
                    .unwrap_or(&empty[level as usize])
            })
            .collect::<Vec<_>>();
        let (mut new, mut requests) = m31::sponge(&m31::frame(1, 0, &felt_words(cm)));
        let mut old = empty_leaf();
        for (level, &sibling) in siblings.iter().enumerate() {
            let pair = |cur: Digest| {
                if (index >> level) & 1 == 0 {
                    (cur, sibling)
                } else {
                    (sibling, cur)
                }
            };
            let (l, r) = pair(old);
            let (o, req) = node(level as u32 + 1, l, r);
            old = o;
            requests.extend(req);
            let (l, r) = pair(new);
            let (o, req) = node(level as u32 + 1, l, r);
            new = o;
            requests.extend(req);
        }
        ensure!(old == root, "fixture old root");
        leaves.push(cm);
        ensure!(new == tree(&leaves).0, "fixture new root");
        steps.push(Step { siblings, requests });
    }
    let s = Statement {
        chain_id: hex(chain),
        pool: hex(pool),
        old_count: initial.len() as u64,
        new_count: leaves.len() as u64,
        old_root,
        new_root: tree(&leaves).0,
        commitments: appended.iter().copied().map(hex).collect(),
        steps,
    };
    s.validate()?;
    Ok(s)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_encoding_and_capacity() {
        assert_eq!(checked_shape(CAPACITY - 1, CAPACITY, 1).unwrap(), 8);
        assert_eq!(checked_shape(CAPACITY - 2, CAPACITY, 2).unwrap(), 9);
        assert!(checked_shape(CAPACITY, CAPACITY, 1).is_err());
        assert!(checked_shape(CAPACITY - 1, CAPACITY, 2).is_err());
        assert!(checked_shape(0, 0, 0).is_err());
        assert!(checked_shape(u64::MAX, 0, 1).is_err());
        assert!(felt("0x800000000000011000000000000000000000000000000000000000000000001").is_err());
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/golden-vectors.json")).unwrap();
        let expected: Digest = serde_json::from_value(vectors["empty"][0].clone()).unwrap();
        assert_eq!(empty_leaf(), expected);
        assert_ne!(
            m31::sponge(&m31::frame(1, 0, &felt_words(Felt::ZERO))).0,
            empty_leaf()
        );
    }
    #[test]
    fn append_shapes_order_and_refresh() {
        let one = synthetic(Felt::ONE, Felt::TWO, &[], &[Felt::from(1)]).unwrap();
        assert_eq!(one.validate().unwrap().rows.len(), 256);
        let batch = synthetic(Felt::ONE, Felt::TWO, &[], &[Felt::from(1), Felt::from(2)]).unwrap();
        assert_eq!(batch.validate().unwrap().rows.len(), 512);
        let refreshed =
            synthetic(Felt::ONE, Felt::TWO, &[Felt::from(1)], &[Felt::from(2)]).unwrap();
        assert_eq!(batch.new_root, refreshed.new_root);
        let mut swapped = batch.clone();
        swapped.commitments.swap(0, 1);
        assert!(swapped.validate().is_err());
        assert_ne!(
            batch.public_output().unwrap(),
            swapped.public_output().unwrap()
        );
        let mut bad = one.clone();
        bad.old_count = 1;
        bad.new_count = 2;
        assert!(bad.validate().is_err());
    }
}
