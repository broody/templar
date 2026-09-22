//! Fixed-block BCS private Merkle trees and domain-separated transcript.
use crate::{
    air::P,
    poly::{self, Point},
};
use anyhow::{Result, bail, ensure};
use rand::RngCore;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use stwo::core::fields::{m31::M31, qm31::QM31};
pub const HASH: usize = 96;
pub const SALT: usize = 192;
pub type Digest = [u8; HASH];
pub const MAX_PROOF: usize = 16 * 1024 * 1024;
pub fn ro(tag: &[u8], parts: &[&[u8]]) -> Digest {
    let mut h = Shake256::default();
    h.update(b"Templar-private-membership-BCS-v1");
    h.update(&(tag.len() as u64).to_le_bytes());
    h.update(tag);
    h.update(&(parts.len() as u64).to_le_bytes());
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let mut out = [0; HASH];
    h.finalize_xof().read(&mut out);
    out
}
pub fn field_bytes(values: &[M31]) -> Vec<u8> {
    values.iter().flat_map(|x| x.0.to_le_bytes()).collect()
}
fn leaf(id: u32, index: usize, values: &[M31], salt: &[u8; SALT]) -> Digest {
    ro(
        b"leaf",
        &[
            &id.to_le_bytes(),
            &(index as u64).to_le_bytes(),
            &field_bytes(values),
            salt,
        ],
    )
}
fn parent(id: u32, depth: u32, a: &Digest, b: &Digest) -> Digest {
    ro(b"node", &[&id.to_le_bytes(), &depth.to_le_bytes(), a, b])
}
pub struct Tree {
    pub columns: Vec<Vec<M31>>,
    pub salts: Vec<[u8; SALT]>,
    pub levels: Vec<Vec<Digest>>,
}
impl Tree {
    pub fn new(columns: Vec<Vec<M31>>, id: u32, rng: &mut impl RngCore) -> Self {
        assert!(!columns.is_empty());
        let n = columns[0].len();
        assert!(n.is_power_of_two());
        assert!(columns.iter().all(|c| c.len() == n));
        let salts: Vec<_> = (0..n)
            .map(|_| {
                let mut s = [0; SALT];
                rng.fill_bytes(&mut s);
                s
            })
            .collect();
        let first = (0..n)
            .map(|i| {
                leaf(
                    id,
                    i,
                    &columns.iter().map(|c| c[i]).collect::<Vec<_>>(),
                    &salts[i],
                )
            })
            .collect();
        let mut levels: Vec<Vec<Digest>> = vec![first];
        while levels.last().unwrap().len() > 1 {
            let depth = levels.len() as u32 - 1;
            let next = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|p| parent(id, depth, &p[0], &p[1]))
                .collect();
            levels.push(next);
        }
        Self {
            columns,
            salts,
            levels,
        }
    }
    pub fn root(&self) -> Digest {
        self.levels.last().unwrap()[0]
    }
    pub fn open(&self, i: usize, out: &mut Vec<u8>) {
        for c in &self.columns {
            out.extend(c[i].0.to_le_bytes());
        }
        out.extend(self.salts[i]);
        let mut index = i;
        for level in &self.levels[..self.levels.len() - 1] {
            out.extend(level[index ^ 1]);
            index >>= 1;
        }
    }
}
pub struct Reader<'a> {
    bytes: &'a [u8],
    pub offset: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_PROOF, "proof size limit");
        Ok(Self { bytes, offset: 0 })
    }
    pub fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        ensure!(end <= self.bytes.len(), "truncated proof");
        let b = self.bytes[self.offset..end].try_into().unwrap();
        self.offset = end;
        Ok(b)
    }
    pub fn field(&mut self) -> Result<M31> {
        let v = u32::from_le_bytes(self.take()?);
        ensure!(v < P, "noncanonical field");
        Ok(M31::from(v))
    }
    pub fn finish(self) -> Result<()> {
        ensure!(self.offset == self.bytes.len(), "trailing proof bytes");
        Ok(())
    }
}
pub fn open(
    reader: &mut Reader,
    id: u32,
    root: &Digest,
    index: usize,
    n: usize,
    width: usize,
) -> Result<Vec<M31>> {
    ensure!(
        n.is_power_of_two() && index < n && width > 0 && width <= 12000,
        "trusted tree dimensions"
    );
    let values = (0..width)
        .map(|_| reader.field())
        .collect::<Result<Vec<_>>>()?;
    let salt = reader.take::<SALT>()?;
    let mut h = leaf(id, index, &values, &salt);
    let mut i = index;
    for depth in 0..n.ilog2() {
        let sibling = reader.take::<HASH>()?;
        h = if i & 1 == 0 {
            parent(id, depth, &h, &sibling)
        } else {
            parent(id, depth, &sibling, &h)
        };
        i >>= 1;
    }
    ensure!(&h == root, "Merkle authentication tree {id}");
    Ok(values)
}
pub struct Transcript {
    x: Vec<u8>,
    pub sigma: Digest,
    phase: u32,
}
impl Transcript {
    pub fn new(x: Vec<u8>) -> Self {
        let sigma = ro(b"public", &[&x]);
        Self { x, sigma, phase: 0 }
    }
    pub fn commit(&mut self, root: &Digest) {
        self.sigma = ro(b"state", &[&self.phase.to_le_bytes(), root, &self.sigma]);
        self.phase += 1;
    }
    pub fn coins(&self) -> Coins {
        Coins {
            x: self.x.clone(),
            sigma: self.sigma,
            phase: self.phase,
            block: 0,
            bytes: [0; HASH],
            at: HASH,
        }
    }
}
pub struct Coins {
    x: Vec<u8>,
    sigma: Digest,
    phase: u32,
    block: u32,
    bytes: Digest,
    at: usize,
}
impl Coins {
    fn word(&mut self) -> u32 {
        if self.at + 4 > HASH {
            self.bytes = ro(
                b"coins",
                &[
                    &self.x,
                    &self.sigma,
                    &self.phase.to_le_bytes(),
                    &self.block.to_le_bytes(),
                ],
            );
            self.block += 1;
            self.at = 0;
        }
        let v = u32::from_le_bytes(self.bytes[self.at..self.at + 4].try_into().unwrap());
        self.at += 4;
        v
    }
    pub fn field(&mut self) -> Result<QM31> {
        for _ in 0..12 {
            let v: [u32; 4] = std::array::from_fn(|_| self.word() & 0x7fff_ffff);
            if v.iter().all(|x| *x < P) {
                return Ok(QM31::from_m31_array(v.map(M31::from)));
            }
        }
        bail!("public field sampler exhausted")
    }
    pub fn ood(&mut self) -> Result<Point> {
        for _ in 0..12 {
            if let Some(p) = poly::rational(self.field()?) {
                if poly::valid_ood(p) {
                    return Ok(p);
                }
            }
        }
        bail!("public OOD sampler exhausted")
    }
    pub fn queries(&mut self) -> Vec<usize> {
        let mut q = (0..poly::QUERIES)
            .map(|_| self.word() as usize & (poly::D - 1))
            .collect::<Vec<_>>();
        q.sort_unstable();
        q.dedup();
        q
    }
}
pub fn secure_columns(v: &[QM31]) -> Vec<Vec<M31>> {
    (0..4)
        .map(|j| v.iter().map(|x| x.to_m31_array()[j]).collect())
        .collect()
}
pub fn secure_values(v: &[M31]) -> Vec<QM31> {
    assert!(v.len() % 4 == 0);
    v.chunks_exact(4)
        .map(|x| QM31::from_m31_array(x.try_into().unwrap()))
        .collect()
}
