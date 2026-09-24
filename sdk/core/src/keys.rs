//! Wallet keys (spec §3): a 32-byte seed, its 24-word BIP-39 backup, and the per-pool, per-account
//! spending, incoming and store keys. Derived secrets are zeroized on drop.
use hkdf::Hkdf;
use sha2::Sha256;
use templar_client_verifier_circuit::payment::{AUTH, NK, OWNER, h};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::felt::Felt32;
use crate::sealbox;
use crate::{Digest, Error, P, Result};

/// Highest account index the gap limit allows above the highest used one (spec §3.2, SDK-M3).
pub const GAP: u32 = 3;

pub const SALT: &[u8] = b"TEMPLAR_WALLET_V1";
pub const SPEND: &[u8] = b"TEMPLAR_SPEND_V1";
pub const INCOMING: &[u8] = b"TEMPLAR_INCOMING_V1";
pub const STORE: &[u8] = b"TEMPLAR_STORE_V1";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 32]);

impl Seed {
    pub fn from_bytes(b: &[u8]) -> Result<Seed> {
        let b: [u8; 32] = b.try_into().map_err(|_| Error::input("seed: not 32 bytes"))?;
        Ok(Seed(b))
    }

    pub fn generate(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Seed {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Seed(b)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 24-word English backup (the seed is the BIP-39 entropy; spec §3.1).
    pub fn mnemonic(&self) -> String {
        bip39::Mnemonic::from_entropy_in(bip39::Language::English, &self.0).expect("32 bytes").to_string()
    }

    pub fn from_mnemonic(words: &str) -> Result<Seed> {
        let m = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, words)
            .map_err(|e| Error::input(&format!("mnemonic: {e}")))?;
        if m.word_count() != 24 {
            return Err(Error::input("mnemonic: not 24 words"));
        }
        let e = Zeroizing::new(m.to_entropy());
        Seed::from_bytes(&e)
    }

    fn prk(&self) -> Hkdf<Sha256> {
        Hkdf::<Sha256>::new(Some(SALT), &self.0)
    }

    fn expand(&self, label: &[u8], ctx: &[u8], out: &mut [u8]) {
        let info = [label, ctx].concat();
        self.prk().expand(&info, out).expect("HKDF output length within bounds");
    }

    /// The keys of account `i` in the pool `(chain, pool)`.
    pub fn account(&self, chain: &Felt32, pool: &Felt32, i: u32) -> Result<Account> {
        let ctx = [chain.as_slice(), pool.as_slice(), &i.to_be_bytes()].concat();
        let mut wide = Zeroizing::new([0u8; 144]);
        self.expand(SPEND, &ctx, wide.as_mut());
        let sk = wide9(&wide)?;
        let mut raw = Zeroizing::new([0u8; 32]);
        self.expand(INCOMING, &ctx, raw.as_mut());
        let ivk = sealbox::clamp(*raw);
        Ok(Account::from_secrets(sk, ivk, i))
    }

    /// The store key of a pool (spec §3.2, §10.3).
    pub fn store_key(&self, chain: &Felt32, pool: &Felt32) -> Zeroizing<[u8; 32]> {
        let mut k = Zeroizing::new([0u8; 32]);
        self.expand(STORE, &[chain.as_slice(), pool.as_slice()].concat(), k.as_mut());
        k
    }
}

/// Nine M31 words, each a 16-byte big-endian chunk reduced mod p (spec §3.2).
pub fn wide9(b: &[u8; 144]) -> Result<Digest> {
    let d: Digest = std::array::from_fn(|k| (u128::from_be_bytes(b[16 * k..16 * k + 16].try_into().unwrap()) % P as u128) as u32);
    if d.iter().all(|w| *w == 0) {
        return Err(Error::new("derivation", "an all-zero spending key"));
    }
    Ok(d)
}

/// One account's keys. `sk` and `ivk` never leave the core except by an explicit viewing-key
/// export (spec §2).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Account {
    pub index: u32,
    pub sk: Digest,
    pub ak: Digest,
    pub nk: Digest,
    pub receiver: Digest,
    pub ivk: [u8; 32],
    pub pk: [u8; 32],
}

impl Account {
    fn from_secrets(sk: Digest, ivk: [u8; 32], index: u32) -> Account {
        let ak = h(AUTH, 0, &sk);
        let nk = h(NK, 0, &sk);
        let receiver = h(OWNER, 0, &[ak, nk].concat());
        let pk = sealbox::public_key(&ivk);
        Account { index, sk, ak, nk, receiver, ivk, pk }
    }
}

/// `H(OWNER, ak ‖ nk)`.
pub fn receiver_of(ak: &Digest, nk: &Digest) -> Digest {
    h(OWNER, 0, &[*ak, *nk].concat())
}

/// Refuses account indexes past the gap limit (spec §3.2).
pub fn check_index(i: u32, highest_used: u32) -> Result<()> {
    if i > highest_used.saturating_add(GAP) {
        return Err(Error::new("gap_limit", format!("account {i} is past the recovery gap limit ({highest_used} + {GAP})")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt;

    #[test]
    fn mnemonic_round_trip_and_rejections() {
        let s = Seed::from_bytes(&[5u8; 32]).unwrap();
        let m = s.mnemonic();
        assert_eq!(m.split(' ').count(), 24);
        assert_eq!(Seed::from_mnemonic(&m).unwrap().bytes(), s.bytes());
        let mut words: Vec<&str> = m.split(' ').collect();
        words.swap(0, 1);
        assert!(Seed::from_mnemonic(&words.join(" ")).is_err() || words[0] == words[1]);
        assert!(Seed::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_err());
    }

    #[test]
    fn accounts_are_scoped() {
        let s = Seed::from_bytes(&[1u8; 32]).unwrap();
        let chain = felt::from_short_string("SN_SEPOLIA").unwrap();
        let (p1, p2) = (felt::parse("0x1234").unwrap(), felt::parse("0x1235").unwrap());
        let a = s.account(&chain, &p1, 0).unwrap();
        assert_ne!(a.receiver, s.account(&chain, &p2, 0).unwrap().receiver);
        assert_ne!(a.receiver, s.account(&chain, &p1, 1).unwrap().receiver);
        assert_eq!(a.receiver, receiver_of(&a.ak, &a.nk));
        assert_eq!(a.ivk, sealbox::clamp(a.ivk));
        assert!(a.sk.iter().all(|w| *w < P));
        assert!(check_index(3, 0).is_ok() && check_index(4, 0).is_err());
    }
}
