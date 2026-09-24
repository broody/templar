//! Receiving (spec §6): trial decryption of published notes, accepted only through the fixed
//! sequence of checks, never panicking on hostile input (SDK-M1, SDK-M2, SDK-M7).
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::felt::Felt32;
use crate::note::{self, ERC20};
use crate::sealbox;
use crate::{Digest, Result};

/// A published leaf: `NotePublished(index, commitment, digest, ciphertext)`.
#[derive(Clone, Debug)]
pub struct Published {
    pub index: u64,
    pub commitment: Digest,
    /// The delivery digest the pool recorded.
    pub digest: Felt32,
    pub words: Vec<Felt32>,
}

/// `PolicySettled`: the split outputs at `first_index` (side 0) and `first_index + 1` (side 1).
#[derive(Clone, Copy, Debug)]
pub struct Settlement {
    pub first_index: u64,
    pub x: u128,
}

/// `AssetRegistered(asset, standard, contract, id)`.
#[derive(Clone, Copy, Debug)]
pub struct Registered {
    pub standard: u16,
    pub contract: Felt32,
    pub id: (u128, u128),
}

/// What decrypts notes and what can compute nullifiers.
pub struct ScanKey {
    /// The account index (or 0 for an imported viewing key).
    pub index: u32,
    pub receiver: Digest,
    pub ivk: [u8; 32],
    /// With spending keys or a full viewing key.
    pub nk: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetKind {
    Erc20,
    Erc721 { contract: String, id: (String, String) },
    Erc1155 { contract: String, id: (String, String) },
    /// Not registered, and the registry is not yet synced through the note's block.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owned {
    pub index: u64,
    pub account: u32,
    pub commitment: Digest,
    pub asset: Felt32,
    pub kind: AssetKind,
    pub amount: u128,
    pub rho: Digest,
    pub receiver: Digest,
    pub nullifier: Option<Digest>,
}

pub struct Context<'a> {
    pub chain: Felt32,
    pub pool: Felt32,
    pub registry: &'a HashMap<Felt32, Registered>,
    /// Whether the registry is synced through every scanned note's block (spec §6 rule 7).
    pub registry_complete: bool,
    pub settlements: &'a [Settlement],
}

/// One published note against the keys; `None` means "not ours" for any failure.
pub fn scan_one(ctx: &Context, keys: &[ScanKey], n: &Published) -> Option<Owned> {
    // 1. Ten canonical words.
    let sealed = sealbox::from_words(&n.words).ok()?;
    for k in keys {
        // 2. Opens under a scanned key (nonzero shared secret).
        let Some(x) = sealbox::open(&k.ivk, &sealed) else { continue };
        // 3–4. Version, zero padding, field ranges (before any hashing).
        let pt = note::parse(&x)?;
        let amount = match pt.side {
            None => pt.amount,
            Some(side) => {
                let s = ctx.settlements.iter().find(|s| s.x > 0 && s.first_index.checked_add(side as u64) == Some(n.index))?;
                if side == 0 { s.x } else { pt.amount.checked_sub(s.x)? }
            }
        };
        if amount == 0 {
            return None;
        }
        // 5. The receiver is one of the scanned accounts'.
        let owner = keys.iter().find(|j| j.receiver == pt.receiver)?;
        // 6. The commitment recomputed from the decrypted fields equals the leaf.
        let cm = note::commitment(&ctx.chain, &ctx.pool, &pt.asset, amount, &pt.receiver, &pt.rho).ok()?;
        if cm != n.commitment {
            return None;
        }
        // 7. The asset: registered NFTs re-derive; others are ERC20 once the registry is synced.
        let kind = match ctx.registry.get(&pt.asset) {
            Some(r) => {
                if note::asset_id(r.standard, &r.contract, r.id).ok()? != pt.asset {
                    return None;
                }
                let (contract, id) = (crate::felt::to_hex(&r.contract), (r.id.0.to_string(), r.id.1.to_string()));
                match r.standard {
                    note::ERC721 => AssetKind::Erc721 { contract, id },
                    note::ERC1155 => AssetKind::Erc1155 { contract, id },
                    ERC20 => AssetKind::Erc20,
                    _ => return None,
                }
            }
            None if ctx.registry_complete => AssetKind::Erc20,
            None => AssetKind::Unknown,
        };
        let position = u32::try_from(n.index).ok()?;
        return Some(Owned {
            index: n.index,
            account: owner.index,
            commitment: cm,
            asset: pt.asset,
            kind,
            amount,
            rho: pt.rho,
            receiver: pt.receiver,
            nullifier: owner.nk.map(|nk| note::nullifier(&nk, &cm, position)),
        });
    }
    None
}

/// The outcome of a scan: owned notes (deduplicated by leaf index) and the leaves whose recorded
/// delivery digest does not match their words, which make the sync incomplete (SDK-M7).
#[derive(Debug, Default)]
pub struct Scanned {
    pub owned: Vec<Owned>,
    pub bad_digests: Vec<u64>,
}

pub fn scan(ctx: &Context, keys: &[ScanKey], notes: &[Published]) -> Result<Scanned> {
    let mut out = Scanned::default();
    for n in notes {
        let words: Option<[Felt32; 10]> = n.words.clone().try_into().ok();
        if words.map(|w| sealbox::delivery(&w)) != Some(n.digest) {
            out.bad_digests.push(n.index);
            continue;
        }
        if let Some(o) = scan_one(ctx, keys, n) {
            if !out.owned.iter().any(|x| x.index == o.index) {
                out.owned.push(o);
            }
        }
    }
    Ok(out)
}
