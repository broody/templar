//! Wallet keys (spec §3): a 32-byte seed, its 24-word BIP-39 backup, and the per-pool, per-account
//! spending, incoming and store keys. Derived secrets are zeroized on drop.
//!
//! A **bound wallet** (product 1, `docs/account-bound-note-spec.md` §6) has its own seed: 28 random
//! bytes with a 21-word backup, never interchangeable with a Templar wallet's 24 words. Every key
//! context includes the account `A`, and every receiver is bound to `A`
//! (`H(OWNER, H(WAUTH, felt_limbs(A) ‖ sk) ‖ H(NK, sk))`), so the same words under another account
//! give unrelated keys. A bound wallet has no ordinary receiver and no policy seed (§6.4).
use hkdf::Hkdf;
use sha2::Sha256;
use templar_client_verifier_circuit::payment::{AUTH, NK, OWNER, h};
use templar_client_verifier_circuit::payment5;
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
pub const STORE_ID: &[u8] = b"TEMPLAR_STORE_ID_V1";

pub const BOUND_SALT: &[u8] = b"TEMPLAR_BOUND_WALLET_V1";
pub const BOUND_SPEND: &[u8] = b"TEMPLAR_BOUND_SPEND_V1";
pub const BOUND_INCOMING: &[u8] = b"TEMPLAR_BOUND_INCOMING_V1";
pub const BOUND_STORE: &[u8] = b"TEMPLAR_BOUND_STORE_V1";
pub const BOUND_STORE_ID: &[u8] = b"TEMPLAR_BOUND_STORE_ID_V1";

/// A source of store keys: a wallet's, per pool (spec §10.3).
pub trait StoreKeys {
    /// The key encrypting a pool's store records.
    fn store_key(&self, chain: &Felt32, pool: &Felt32) -> Zeroizing<[u8; 32]>;
    /// The key naming a pool's store records, separate from the encryption key (SDK-IM11).
    fn store_id_key(&self, chain: &Felt32, pool: &Felt32) -> Zeroizing<[u8; 32]>;
}

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

    /// The key naming a pool's store records, separate from the encryption key (SDK-IM11).
    pub fn store_id_key(&self, chain: &Felt32, pool: &Felt32) -> Zeroizing<[u8; 32]> {
        let mut k = Zeroizing::new([0u8; 32]);
        self.expand(STORE_ID, &[chain.as_slice(), pool.as_slice()].concat(), k.as_mut());
        k
    }
}

impl StoreKeys for Seed {
    fn store_key(&self, chain: &Felt32, pool: &Felt32) -> Zeroizing<[u8; 32]> {
        Seed::store_key(self, chain, pool)
    }
    fn store_id_key(&self, chain: &Felt32, pool: &Felt32) -> Zeroizing<[u8; 32]> {
        Seed::store_id_key(self, chain, pool)
    }
}

/// A bound wallet's seed `S_w` (spec §6.1): 28 bytes from the CSPRNG, backed up as 21 words.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BoundSeed([u8; 28]);

impl BoundSeed {
    pub fn from_bytes(b: &[u8]) -> Result<BoundSeed> {
        let b: [u8; 28] = b.try_into().map_err(|_| Error::input("bound seed: not 28 bytes"))?;
        Ok(BoundSeed(b))
    }

    pub fn generate(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> BoundSeed {
        let mut b = [0u8; 28];
        rng.fill_bytes(&mut b);
        BoundSeed(b)
    }

    pub fn bytes(&self) -> &[u8; 28] {
        &self.0
    }

    /// The 21-word English backup (224 bits of entropy plus BIP-39's 7-bit checksum).
    pub fn mnemonic(&self) -> String {
        bip39::Mnemonic::from_entropy_in(bip39::Language::English, &self.0).expect("28 bytes").to_string()
    }

    /// Only 21 words: the word count marks the origin, so a Templar wallet's 24 words are refused
    /// here, as 21 words are refused by [`Seed::from_mnemonic`].
    pub fn from_mnemonic(words: &str) -> Result<BoundSeed> {
        let m = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, words)
            .map_err(|e| Error::input(&format!("mnemonic: {e}")))?;
        if m.word_count() != 21 {
            return Err(Error::input("mnemonic: a bound wallet's backup is 21 words"));
        }
        let e = Zeroizing::new(m.to_entropy());
        BoundSeed::from_bytes(&e)
    }

    /// The wallet for account `A`: a nonzero address below 2^251, taken from the connected wallet.
    pub fn wallet(&self, account: &Felt32) -> Result<BoundWallet> {
        crate::felt::check_address(account, "account")?;
        Ok(BoundWallet { seed: self.clone(), account: *account })
    }
}

/// A bound seed with its account `A`: the keys of product 1 (spec §6.2).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BoundWallet {
    seed: BoundSeed,
    account: Felt32,
}

impl BoundWallet {
    pub fn account_address(&self) -> &Felt32 {
        &self.account
    }

    fn expand(&self, label: &[u8], ctx: &[u8], out: &mut [u8]) {
        let info = [label, ctx].concat();
        Hkdf::<Sha256>::new(Some(BOUND_SALT), &self.seed.0).expand(&info, out).expect("HKDF output length within bounds");
    }

    /// `actx = felt₃₂(chain) ‖ felt₃₂(pool) ‖ felt₃₂(A)`.
    fn actx(&self, chain: &Felt32, pool: &Felt32) -> Vec<u8> {
        [chain.as_slice(), pool.as_slice(), self.account.as_slice()].concat()
    }

    /// The keys of account index `i` in `pool`, every receiver bound to `A`. Refused for a pool
    /// that does not settle R0 V5, where a bound note could never be spent (AB-SM1).
    pub fn keys(&self, pool: &crate::pool::PoolRef, i: u32) -> Result<Account> {
        pool.check_bound()?;
        let ctx = [self.actx(pool.chain(), pool.pool()), i.to_be_bytes().to_vec()].concat();
        let mut wide = Zeroizing::new([0u8; 144]);
        self.expand(BOUND_SPEND, &ctx, wide.as_mut());
        let sk = wide9(&wide)?;
        let mut raw = Zeroizing::new([0u8; 32]);
        self.expand(BOUND_INCOMING, &ctx, raw.as_mut());
        let ivk = sealbox::clamp(*raw);
        Account::bound(sk, ivk, i, &crate::felt::limbs(&self.account)?)
    }
}

impl StoreKeys for BoundWallet {
    fn store_key(&self, chain: &Felt32, pool: &Felt32) -> Zeroizing<[u8; 32]> {
        let mut k = Zeroizing::new([0u8; 32]);
        self.expand(BOUND_STORE, &self.actx(chain, pool), k.as_mut());
        k
    }
    fn store_id_key(&self, chain: &Felt32, pool: &Felt32) -> Zeroizing<[u8; 32]> {
        let mut k = Zeroizing::new([0u8; 32]);
        self.expand(BOUND_STORE_ID, &self.actx(chain, pool), k.as_mut());
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

    /// A bound account: `ak = H(WAUTH, felt_limbs(A) ‖ sk)`, the relation's own derivation
    /// (`payment5::receiver_of`).
    fn bound(sk: Digest, ivk: [u8; 32], index: u32, account: &[u32; 9]) -> Result<Account> {
        if account.iter().all(|w| *w == 0) {
            return Err(Error::input("account: zero"));
        }
        let ak = payment5::ak_of(account, &sk);
        let (receiver, nk) = payment5::receiver_of(account, &sk);
        let pk = sealbox::public_key(&ivk);
        Ok(Account { index, sk, ak, nk, receiver, ivk, pk })
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
    fn bound_mnemonics_are_21_words_and_never_24() {
        let b = BoundSeed::from_bytes(&[9u8; 28]).unwrap();
        let m = b.mnemonic();
        assert_eq!(m.split(' ').count(), 21);
        assert_eq!(BoundSeed::from_mnemonic(&m).unwrap().bytes(), b.bytes());
        // The word count marks the origin, in both directions.
        assert!(Seed::from_mnemonic(&m).is_err());
        let ordinary = Seed::from_bytes(&[9u8; 32]).unwrap().mnemonic();
        assert!(BoundSeed::from_mnemonic(&ordinary).is_err());
        assert!(BoundSeed::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn bound_keys_are_scoped_by_the_account() {
        use crate::pool::{KNOWN_V4_POOLS, PoolRef, Version};
        let chain = felt::from_short_string("SN_SEPOLIA").unwrap();
        let pool = felt::parse("0x1234").unwrap();
        let v5 = |p: Felt32| PoolRef::new(chain, p, Version::V5).unwrap();
        let (a1, a2) = (felt::parse("0x54f2b25").unwrap(), felt::parse("0x665f820").unwrap());
        let b = BoundSeed::from_bytes(&[3u8; 28]).unwrap();
        let (w1, w2) = (b.wallet(&a1).unwrap(), b.wallet(&a2).unwrap());
        let (k1, k2) = (w1.keys(&v5(pool), 0).unwrap(), w2.keys(&v5(pool), 0).unwrap());
        // No bound keys for a pool that settles R0 V4 (AB-SM1).
        assert!(w1.keys(&PoolRef::new(chain, pool, Version::V4).unwrap(), 0).is_err());
        assert!(PoolRef::new(chain, felt::parse(KNOWN_V4_POOLS[0].1).unwrap(), Version::V5).is_err());
        // Another account: unrelated spending, nullifier and incoming keys.
        assert!(k1.sk != k2.sk && k1.nk != k2.nk && k1.ivk != k2.ivk && k1.receiver != k2.receiver);
        assert_ne!(w1.store_key(&chain, &pool).as_ref(), w2.store_key(&chain, &pool).as_ref());
        // Bound receivers: WAUTH over the account's limbs, never the ordinary AUTH key.
        assert_eq!(k1.ak, h(templar_client_verifier_circuit::payment5::WAUTH, 0, &[felt::limbs(&a1).unwrap().as_slice(), &k1.sk].concat()));
        assert_ne!(k1.ak, h(AUTH, 0, &k1.sk));
        assert_eq!(k1.receiver, receiver_of(&k1.ak, &k1.nk));
        // Scoped by pool and index too; the store id key is not the store key.
        assert_ne!(k1.receiver, w1.keys(&v5(felt::parse("0x1235").unwrap()), 0).unwrap().receiver);
        assert_ne!(k1.receiver, w1.keys(&v5(pool), 1).unwrap().receiver);
        assert_ne!(w1.store_key(&chain, &pool).as_ref(), w1.store_id_key(&chain, &pool).as_ref());
        // The same bytes as a Templar seed prefix give unrelated keys (another salt and labels).
        let mut long = [0u8; 32];
        long[..28].copy_from_slice(b.bytes());
        assert_ne!(Seed::from_bytes(&long).unwrap().account(&chain, &pool, 0).unwrap().sk, k1.sk);
        // A must be a nonzero address.
        assert!(b.wallet(&[0; 32]).is_err());
        assert!(b.wallet(&felt::parse("0x800000000000000000000000000000000000000000000000000000000000000").unwrap()).is_err());
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
