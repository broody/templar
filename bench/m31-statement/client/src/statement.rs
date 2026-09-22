//! Payment-shaped M31 statement for client-cost measurement. This is
//! measurement pathfinding only: no privacy claim, no format commitment,
//! synthetic secrets carried in the clear (the hiding stage replaces this).
//!
//! AIR provenance: `m31.rs`/`constants.rs` are byte-identical copies of the
//! reviewed `bench/m31-append/client/src` files
//! (m31.rs sha256 645c5200692f1fbe387ff118efb0b319d23d273e6c2fedccef487ea0ea5bdd13,
//! constants.rs sha256 46ea8e2ffb0149af567fd09622d3ddfc73ce08f6c7f3f64ef3960f929ce064f3).
use crate::m31::{self, Digest, Request};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use stwo::core::channel::Channel;

pub const DOMAIN_WORD: u32 = 0x4d335053; // "M31S"
pub const VERSION: u32 = 1;
pub const KIND_LEAF: u32 = 1;
pub const KIND_NULLIFIER: u32 = 2;
pub const KIND_NODE: u32 = 3;
pub const DEPTH: usize = 32;
pub const PATHS: usize = 2;
/// 2 leaf + 2 nullifier + 2 x 32 node hashes.
pub const REQUESTS: usize = 2 + 2 + PATHS * DEPTH;

pub fn felt(s: &str) -> Result<Felt> {
    let f = Felt::from_hex(s).map_err(|_| anyhow::anyhow!("bad felt literal {s}"))?;
    ensure!(f.to_bytes_le()[31] & 0x80 == 0, "felt at or above 2^251");
    Ok(f)
}
pub fn hex(f: Felt) -> String {
    format!("{f:#x}")
}
/// Little-endian 28-bit words (252 bits), matching the append transcript convention.
pub fn felt_words(f: Felt) -> [u32; 9] {
    let be = f.to_bytes_le();
    let mut words = [0u32; 9];
    for (i, w) in words.iter_mut().enumerate() {
        let mut v = 0u32;
        for b in 0..4u32 {
            let idx = i as u32 * 4 + b;
            if idx < 31 {
                v |= (be[idx as usize] as u32) << (8 * b);
            } else if idx == 31 {
                v |= ((be[31] as u32) & 0x0f) << 24;
            }
        }
        *w = v & ((1 << 28) - 1);
    }
    words
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentStatement {
    pub chain_id: String,
    pub pool: String,
    pub root: Digest,
    /// Public nullifier per spent note.
    pub nullifiers: [Digest; PATHS],
    /// Public tree leaf (commitment) per spent note.
    pub leaves: [Digest; PATHS],
    /// Private tree positions (in the clear for this measurement).
    pub indices: [u64; PATHS],
    /// Private note secrets (in the clear for this measurement).
    pub secrets: [Digest; PATHS],
    /// Private sibling digests per path, levels 0..32.
    pub siblings: [[Digest; DEPTH]; PATHS],
    /// Amount per spent note, bounded < 2^30 (host-checked here; in-proof
    /// range enforcement is a v2 component — see inventory §2 note). Bound
    /// into the leaf preimage: leaf = H(secret ++ amount).
    pub amounts: [u32; PATHS],
    /// Pad-probe knobs (measurement only): B random valid permutation rows
    /// appended before power-of-two padding. Deterministic from `pad_seed`
    /// so prover and verifier derive identical rows. NOTE: real hiding pads
    /// are prover-private; this probes their COST, which is identical.
    #[serde(default)]
    pub pad_seed: u64,
    #[serde(default)]
    pub pad_count: usize,
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

fn node_msg(bit: u64, level: usize, cur: &Digest, sibling: &Digest) -> Vec<u32> {
    if bit == 0 {
        m31::frame(KIND_NODE, level as u32, &[cur.as_slice(), sibling.as_slice()].concat())
    } else {
        m31::frame(KIND_NODE, level as u32, &[sibling.as_slice(), cur.as_slice()].concat())
    }
}

impl PaymentStatement {
    /// Derives every sponge request from the statement fields, checks the
    /// semantic claims (leaf preimages, nullifier preimages, both paths end
    /// at the root), and returns the proving/verification inputs.
    pub fn validate(&self) -> Result<PublicData> {
        let chain = felt(&self.chain_id)?;
        let pool = felt(&self.pool)?;
        m31::canonical(&self.root)?;
        for p in 0..PATHS {
            m31::canonical(&self.nullifiers[p])?;
            m31::canonical(&self.leaves[p])?;
            m31::canonical(&self.secrets[p])?;
            for s in &self.siblings[p] {
                m31::canonical(s)?;
            }
            ensure!(self.indices[p] < (1 << DEPTH), "index out of depth");
        }

        let mut requests = Vec::new();
        for p in 0..PATHS {
            ensure!(self.amounts[p] < (1 << 30), "amount above the no-carry bound (host-checked; in-proof range is a v2 component)");
            let mut leaf_payload = self.secrets[p].to_vec();
            leaf_payload.push(self.amounts[p]);
            let (leaf, reqs) = m31::sponge(&m31::frame(KIND_LEAF, 0, &leaf_payload));
            requests.extend(reqs);
            ensure!(leaf == self.leaves[p], "leaf preimage mismatch {p}");
            let (nul, reqs) = m31::sponge(&m31::frame(KIND_NULLIFIER, 0, &self.secrets[p]));
            requests.extend(reqs);
            ensure!(nul == self.nullifiers[p], "nullifier preimage mismatch {p}");
        }
        for p in 0..PATHS {
            let mut cur = self.leaves[p];
            for level in 0..DEPTH {
                let bit = (self.indices[p] >> level) & 1;
                let (digest, reqs) = m31::sponge(&node_msg(bit, level, &cur, &self.siblings[p][level]));
                requests.extend(reqs);
                cur = digest;
            }
            ensure!(cur == self.root, "path {p} does not reach the root");
        }
        // Pad instances: random valid permutation rows (output = permute(input)).
        let mut prng = self.pad_seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
        let mut next_word = move || {
            prng = prng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((prng >> 33) as u32) % m31::P
        };
        for _ in 0..self.pad_count {
            let input = [0u32; 24].map(|_| next_word());
            let output = m31::permute(input);
            requests.push(Request { input, output });
        }

        let mut words = vec![DOMAIN_WORD, VERSION];
        words.extend(felt_words(chain));
        words.extend(felt_words(pool));
        words.extend(self.root);
        for p in 0..PATHS {
            words.push(self.amounts[p]);
            words.extend(self.nullifiers[p]);
            words.extend(self.leaves[p]);
            words.extend([
                (self.indices[p] & ((1 << 28) - 1)) as u32,
                (self.indices[p] >> 28) as u32,
            ]);
        }
        m31::canonical(&words)?;

        let rows = m31::padded(&requests)?;
        ensure!(
            rows.len() == 1usize << rows.len().ilog2() && rows.len() * 2 < m31::P as usize,
            "derived rows/relation bound"
        );
        Ok(PublicData { requests, rows, words })
    }
}

pub fn mix_words(channel: &mut stwo::core::channel::Blake2sChannel, words: &[u32]) {
    let felts: Vec<stwo::core::fields::qm31::QM31> = words
        .chunks(4)
        .map(|c| {
            let mut a = [0u32; 4];
            a[..c.len()].copy_from_slice(c);
            stwo::core::fields::qm31::QM31::from_m31_array(std::array::from_fn(|i| {
                stwo::core::fields::m31::M31::from(a[i])
            }))
        })
        .collect();
    channel.mix_felts(&felts);
}

/// Deterministic synthetic fixture: two notes whose leaves are siblings of
/// each other at level 0 (indices differ only in bit 0), merging both paths
/// onto one shared spine up to depth 32. Both paths end at one root.
pub fn synthetic(chain: &str, pool: &str, seed: u64) -> Result<PaymentStatement> {
    let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15);
    let mut word = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((state >> 33) as u32) % m31::P
    };
    let secrets = [[0u32; 9].map(|_| word()), [0u32; 9].map(|_| word())];
    let mut amounts = [0u32; PATHS];
    let mut leaves = [[0u32; 9]; PATHS];
    let mut nullifiers = [[0u32; 9]; PATHS];
    for p in 0..PATHS {
        let mut leaf_payload = secrets[p].to_vec();
        leaf_payload.push(word() % (1 << 30));
        amounts[p] = *leaf_payload.last().unwrap();
        leaves[p] = m31::sponge(&m31::frame(KIND_LEAF, 0, &leaf_payload)).0;
        nullifiers[p] = m31::sponge(&m31::frame(KIND_NULLIFIER, 0, &secrets[p])).0;
    }
    // index1 = index0 ^ 1: opposite orderings at level 0 hash the identical
    // message, merging both paths; all higher bits agree.
    let index0 = (word() as u64) % (1 << DEPTH);
    let indices = [index0 & !1, index0 | 1];
    let mut siblings = [[[0u32; 9]; DEPTH]; PATHS];
    siblings[0][0] = leaves[1];
    siblings[1][0] = leaves[0];
    for level in 1..DEPTH {
        let filler = [0u32; 9].map(|_| word());
        siblings[0][level] = filler;
        siblings[1][level] = filler;
    }
    // Derive the root from the merged walk (path 0's view).
    let mut root = leaves[0];
    for level in 0..DEPTH {
        let bit = (indices[0] >> level) & 1;
        let (digest, _) = m31::sponge(&node_msg(bit, level, &root, &siblings[0][level]));
        root = digest;
    }
    Ok(PaymentStatement {
        chain_id: chain.to_string(),
        pool: pool.to_string(),
        root,
        nullifiers,
        leaves,
        indices,
        secrets,
        siblings,
        amounts,
        pad_seed: 0,
        pad_count: 0,
    })
}
