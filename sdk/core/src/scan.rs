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

/// What decrypts notes and what can compute nullifiers (zeroized on drop, SDK-IM9).
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt;
    use crate::keys::Seed;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    struct Fx {
        chain: Felt32,
        pool: Felt32,
        key: ScanKey,
        pk: [u8; 32],
        asset: Felt32,
    }

    fn fx() -> Fx {
        let chain = felt::from_short_string("SN_SEPOLIA").unwrap();
        let pool = felt::parse("0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9").unwrap();
        let a = Seed::from_bytes(&[3u8; 32]).unwrap().account(&chain, &pool, 0).unwrap();
        let asset = felt::parse("0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8").unwrap();
        Fx { chain, pool, key: ScanKey { index: 0, receiver: a.receiver, ivk: a.ivk, nk: Some(a.nk) }, pk: a.pk, asset }
    }

    /// A published note of `plaintext` to `pk`, committed as `cm` (the honest commitment unless given).
    fn publish(f: &Fx, index: u64, plaintext: [u8; 256], cm: Digest) -> Published {
        let sealed = sealbox::seal(&f.pk, &plaintext, &mut ChaCha20Rng::seed_from_u64(index)).unwrap();
        let words = sealbox::to_words(&sealed).unwrap();
        Published { index, commitment: cm, digest: sealbox::delivery(&words), words: words.to_vec() }
    }

    fn run(f: &Fx, notes: &[Published], registry: &HashMap<Felt32, Registered>, complete: bool, settlements: &[Settlement]) -> Scanned {
        let ctx = Context { chain: f.chain, pool: f.pool, registry, registry_complete: complete, settlements };
        scan(&ctx, std::slice::from_ref(&f.key), notes).unwrap()
    }

    /// Every rule of spec §6, and hostile plaintexts that must not panic (SDK-IM3, SDK-M2).
    #[test]
    fn scan_rules() {
        let f = fx();
        let empty = HashMap::new();
        let rho = [5u32; 9];
        let cm = |asset: &Felt32, amount: u128| note::commitment(&f.chain, &f.pool, asset, amount, &f.key.receiver, &rho).unwrap();
        let ok = note::m301(&f.asset, &f.key.receiver, &rho, 10);
        let found = run(&f, &[publish(&f, 0, ok, cm(&f.asset, 10))], &empty, true, &[]);
        assert_eq!(found.owned.len(), 1);
        assert_eq!(found.owned[0].kind, AssetKind::Erc20);
        assert!(found.owned[0].nullifier.is_some());

        let none = |name: &str, pt: [u8; 256], c: Digest| {
            let r = run(&f, &[publish(&f, 0, pt, c)], &empty, true, &[]);
            assert!(r.owned.is_empty(), "{name} credited");
        };
        let mut x = ok;
        x[200] = 1;
        none("nonzero padding", x, cm(&f.asset, 10));
        let mut x = ok;
        x[72..76].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        none("rho word = p", x, cm(&f.asset, 10));
        none("zero rho", note::m301(&f.asset, &f.key.receiver, &[0; 9], 10), cm(&f.asset, 10));
        let mut big = f.asset;
        big[0] = 0x10;
        none("asset at 2^252 (no panic)", note::m301(&big, &f.key.receiver, &rho, 10), cm(&f.asset, 10));
        big[0] = 0x08;
        none("asset at 2^251", note::m301(&big, &f.key.receiver, &rho, 10), cm(&f.asset, 10));
        none("amount zero", note::m301(&f.asset, &f.key.receiver, &rho, 0), cm(&f.asset, 0));
        none("commitment mismatch", ok, cm(&f.asset, 11));
        none("another receiver", note::m301(&f.asset, &[9; 9], &rho, 10), cm(&f.asset, 10));
        let mut x = ok;
        x[..4].copy_from_slice(b"X301");
        none("unknown version", x, cm(&f.asset, 10));

        // Words out of range and a digest mismatch: never credited, the digest reported.
        let mut bad = publish(&f, 0, ok, cm(&f.asset, 10));
        bad.words[0][0] = 1;
        let r = run(&f, &[bad], &empty, true, &[]);
        assert!(r.owned.is_empty() && r.bad_digests == vec![0]);
        let mut bad = publish(&f, 0, ok, cm(&f.asset, 10));
        bad.digest = [1; 32];
        assert_eq!(run(&f, &[bad], &empty, true, &[]).bad_digests, vec![0]);

        // PS01: amounts come from the matching settlement only.
        let ps01 = |side: u8, amount: u128| {
            let mut x = note::m301(&f.asset, &f.key.receiver, &rho, amount);
            x[..4].copy_from_slice(b"PS01");
            x[124] = side;
            x
        };
        let s = [Settlement { first_index: 4, x: 3 }];
        assert_eq!(run(&f, &[publish(&f, 4, ps01(0, 0), cm(&f.asset, 3))], &empty, true, &s).owned[0].amount, 3);
        assert_eq!(run(&f, &[publish(&f, 5, ps01(1, 10), cm(&f.asset, 7))], &empty, true, &s).owned[0].amount, 7);
        assert!(run(&f, &[publish(&f, 5, ps01(0, 0), cm(&f.asset, 3))], &empty, true, &s).owned.is_empty(), "wrong index for side");
        assert!(run(&f, &[publish(&f, 4, ps01(0, 0), cm(&f.asset, 3))], &empty, true, &[]).owned.is_empty(), "no settlement");
        assert!(run(&f, &[publish(&f, 4, ps01(0, 0), cm(&f.asset, 3))], &empty, true, &[Settlement { first_index: 4, x: 0 }]).owned.is_empty(), "x = 0");
        let under = [Settlement { first_index: 4, x: 11 }];
        assert!(run(&f, &[publish(&f, 5, ps01(1, 10), cm(&f.asset, 1))], &empty, true, &under).owned.is_empty(), "x > amount (no panic)");
        let mut x = ps01(0, 0);
        x[124] = 2;
        assert!(run(&f, &[publish(&f, 4, x, cm(&f.asset, 3))], &empty, true, &s).owned.is_empty(), "side 2");

        // The registry: an NFT re-derives; a forged registration does not; unknown before sync.
        let contract = felt::parse("0x535ca4").unwrap();
        let nft = note::asset_id(note::ERC721, &contract, (2, 0)).unwrap();
        let pt = note::m301(&nft, &f.key.receiver, &rho, 1);
        let reg: HashMap<_, _> = [(nft, Registered { standard: note::ERC721, contract, id: (2, 0) })].into_iter().collect();
        assert!(matches!(run(&f, &[publish(&f, 0, pt, cm(&nft, 1))], &reg, true, &[]).owned[0].kind, AssetKind::Erc721 { .. }));
        let forged: HashMap<_, _> = [(nft, Registered { standard: note::ERC721, contract, id: (3, 0) })].into_iter().collect();
        assert!(run(&f, &[publish(&f, 0, pt, cm(&nft, 1))], &forged, true, &[]).owned.is_empty());
        assert_eq!(run(&f, &[publish(&f, 0, ok, cm(&f.asset, 10))], &empty, false, &[]).owned[0].kind, AssetKind::Unknown);

        // A repeated leaf is credited once.
        let n = publish(&f, 0, ok, cm(&f.asset, 10));
        assert_eq!(run(&f, &[n.clone(), n], &empty, true, &[]).owned.len(), 1);
    }
}
