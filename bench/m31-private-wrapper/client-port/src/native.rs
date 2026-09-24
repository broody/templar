//! Native mirror of the TMPZK002 verifier's parsing and transcript, used only to
//! prepare circuit witnesses. Acceptance is decided by the circuit, never here.
//! `parse` consumes the proof in exactly `proof::verify`'s order.
use anyhow::{Result, ensure};
use blake2::{Blake2s256, Digest as _};
use std::collections::{BTreeMap, BTreeSet};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::M31;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;

use crate::air::{self, N, P, Public, SELS, W};

pub const MAGIC: &[u8; 8] = b"TMPZK002";
pub const HASH: usize = 32;
pub const SALT: usize = 96;
pub const LOG_H: u32 = 7;
pub const LOG_D: u32 = 13;
pub const D: usize = 1 << LOG_D;
pub const FOLDS: usize = 10;
pub const QUERIES: usize = 120;
pub const ROOTS: usize = 4 + FOLDS + 1;
pub const CLAIMS: usize = 4 * (2 * W + 4);

pub fn ro(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(crate::ro::DOMAIN);
    h.update((tag.len() as u64).to_le_bytes());
    h.update(tag);
    h.update((parts.len() as u64).to_le_bytes());
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// `proof::public_bytes`, including the digest of the client's own sources.
pub fn public_bytes(public: &Public) -> Result<Vec<u8>> {
    public.validate()?;
    let circuit = ro(
        b"circuit",
        &[
            include_bytes!("../../../m31-private-blake/client/src/air.rs"),
            include_bytes!("../../../m31-private-blake/client/src/hash.rs"),
            include_bytes!("../../../m31-private-blake/client/src/constants.rs"),
            include_bytes!("../../../m31-private-blake/client/src/poly.rs"),
            include_bytes!("../../../m31-private-blake/client/src/crypto.rs"),
            include_bytes!("../../../m31-private-blake/client/src/proof.rs"),
        ],
    );
    let mut bytes = MAGIC.to_vec();
    bytes.extend(circuit);
    bytes.extend(serde_json::to_vec(public)?);
    Ok(bytes)
}

pub struct Transcript {
    pub x: Vec<u8>,
    pub sigma: [u8; 32],
    pub phase: u32,
}
impl Transcript {
    pub fn new(x: Vec<u8>) -> Self {
        let sigma = ro(b"public", &[&x]);
        Self { x, sigma, phase: 0 }
    }
    pub fn commit(&mut self, root: &[u8; 32]) {
        self.sigma = ro(b"state", &[&self.phase.to_le_bytes(), root, &self.sigma]);
        self.phase += 1;
    }
    pub fn words(&self, n: usize) -> Vec<u32> {
        let mut out = vec![];
        let mut block = 0u32;
        while out.len() < n {
            let d = ro(b"coins", &[&self.x, &self.sigma, &self.phase.to_le_bytes(), &block.to_le_bytes()]);
            out.extend(d.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())));
            block += 1;
        }
        out.truncate(n);
        out
    }
}

pub fn point(log: u32, i: usize) -> CirclePoint<M31> {
    CanonicCoset::new(log).circle_domain().at(bit_reverse_index(i, log))
}
pub fn previous_indices(log: u32) -> Vec<usize> {
    let map: std::collections::HashMap<_, _> =
        (0..1usize << log).map(|i| { let p = point(log, i); ((p.x.0, p.y.0), i) }).collect();
    let step = CanonicCoset::new(LOG_H).step();
    (0..1usize << log).map(|i| { let p = point(log, i) - step; map[&(p.x.0, p.y.0)] }).collect()
}

#[derive(Clone, Debug)]
pub struct Opening {
    pub index: usize,
    pub values: Vec<u32>,
    pub salt: [u8; SALT],
    pub siblings: Vec<[u8; HASH]>,
}

pub struct Parsed {
    pub x: Vec<u8>,
    pub roots: Vec<[u8; HASH]>,
    pub sigma: [u8; HASH],
    pub claims: Opening,
    pub last: Opening,
    /// Query indices in draw order (not deduplicated), as the circuit uses them.
    pub draws: Vec<usize>,
    pub base: BTreeMap<usize, Opening>,
    pub q: BTreeMap<usize, Opening>,
    pub r: BTreeMap<usize, Opening>,
    pub fri: Vec<BTreeMap<usize, Opening>>,
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        ensure!(self.at + N <= self.b.len(), "truncated proof");
        let v = self.b[self.at..self.at + N].try_into().unwrap();
        self.at += N;
        Ok(v)
    }
    fn open(&mut self, index: usize, n: usize, width: usize) -> Result<Opening> {
        let values = (0..width)
            .map(|_| {
                let v = u32::from_le_bytes(self.take()?);
                ensure!(v < P, "noncanonical field");
                Ok(v)
            })
            .collect::<Result<_>>()?;
        let salt = self.take()?;
        let siblings = (0..n.ilog2()).map(|_| self.take()).collect::<Result<_>>()?;
        Ok(Opening { index, values, salt, siblings })
    }
}

pub fn trace_queries(q: &[usize]) -> Vec<usize> {
    let prev = previous_indices(LOG_D);
    q.iter().flat_map(|i| [*i, prev[*i]]).collect::<BTreeSet<_>>().into_iter().collect()
}
pub fn fri_queries(q: &[usize], layer: usize) -> Vec<usize> {
    q.iter()
        .flat_map(|i| { let j = i >> layer; [j & !1, (j & !1) + 1] })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn parse(public: &Public, bytes: &[u8]) -> Result<Parsed> {
    let mut rd = Reader { b: bytes, at: 0 };
    ensure!(&rd.take::<8>()? == MAGIC, "proof version");
    let roots: Vec<[u8; HASH]> = (0..ROOTS).map(|_| rd.take()).collect::<Result<_>>()?;
    let sigma = rd.take()?;
    let x = public_bytes(public)?;
    let mut t = Transcript::new(x.clone());
    let claims = rd.open(0, 1, CLAIMS)?;
    for root in &roots {
        t.commit(root);
    }
    ensure!(t.sigma == sigma, "transcript state");
    let last = rd.open(0, 1, 4)?;
    let draws: Vec<usize> = t.words(QUERIES).into_iter().map(|w| w as usize & (D - 1)).collect();
    let mut sorted = draws.clone();
    sorted.sort_unstable();
    sorted.dedup();
    let mut base = BTreeMap::new();
    for i in trace_queries(&sorted) {
        base.insert(i, rd.open(i, D, W)?);
    }
    let mut q = BTreeMap::new();
    for i in &sorted {
        q.insert(*i, rd.open(*i, D, 4)?);
    }
    let mut r = BTreeMap::new();
    for i in &sorted {
        r.insert(*i, rd.open(*i, D, 4)?);
    }
    let mut fri = vec![];
    for layer in 0..FOLDS {
        let mut m = BTreeMap::new();
        for i in fri_queries(&sorted, layer) {
            m.insert(i, rd.open(i, D >> layer, 4)?);
        }
        fri.push(m);
    }
    ensure!(rd.at == bytes.len(), "trailing proof bytes");
    Ok(Parsed { x, roots, sigma, claims, last, draws, base, q, r, fri })
}

/// Coefficients of `poly::selector_polys()`, computed exactly as `from_cyclic`.
pub fn selector_coeffs() -> Vec<Vec<M31>> {
    use stwo::prover::backend::cpu::CpuBackend;
    use stwo::prover::poly::BitReversedOrder;
    use stwo::prover::poly::circle::CircleEvaluation;
    let h = CanonicCoset::new(LOG_H);
    (0..SELS)
        .map(|j| {
            let map: std::collections::HashMap<_, _> =
                (0..N).map(|i| { let p = h.at(i); ((p.x.0, p.y.0), air::selectors(i)[j]) }).collect();
            let values: Vec<M31> = (0..N).map(|i| { let p = point(LOG_H, i); map[&(p.x.0, p.y.0)] }).collect();
            let domain = CanonicCoset::new(LOG_H).circle_domain();
            CircleEvaluation::<CpuBackend, M31, BitReversedOrder>::new(domain, values).interpolate().coeffs
        })
        .collect()
}
