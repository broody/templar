//! Receiving addresses and viewing keys (spec §4): a versioned, typed payload, F4Jumble over the
//! payload and a zero-padded HRP block (as ZIP-316), then Bech32m. Each decoder accepts exactly
//! one type and the HRPs of that type.
use bech32::{Bech32m, Hrp};
use sha2::{Digest as _, Sha256};

use crate::felt::{self, Felt32};
use crate::keys::{self, Account};
use crate::sealbox;
use crate::{Digest, Error, Result, digest_ok};

pub const VERSION: u8 = 1;
const MAX_LEN: usize = 1023;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Address = 1,
    Incoming = 2,
    Full = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Sepolia,
}

impl Network {
    pub fn of_chain(chain: &Felt32) -> Result<Network> {
        if *chain == felt::from_short_string("SN_MAIN")? {
            Ok(Network::Mainnet)
        } else if *chain == felt::from_short_string("SN_SEPOLIA")? {
            Ok(Network::Sepolia)
        } else {
            Err(Error::input("chain: not SN_MAIN or SN_SEPOLIA"))
        }
    }

    fn hrp(self, kind: Kind) -> &'static str {
        match (kind, self) {
            (Kind::Address, Network::Mainnet) => "templar",
            (Kind::Address, Network::Sepolia) => "templarsep",
            (Kind::Incoming, Network::Mainnet) => "templarivk",
            (Kind::Incoming, Network::Sepolia) => "templarivksep",
            (Kind::Full, Network::Mainnet) => "templarfvk",
            (Kind::Full, Network::Sepolia) => "templarfvksep",
        }
    }
}

fn digest_bytes(d: &Digest) -> [u8; 36] {
    let mut out = [0u8; 36];
    for (i, w) in d.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

fn bytes_digest(b: &[u8]) -> Digest {
    std::array::from_fn(|i| u32::from_be_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
}

fn encode(kind: Kind, chain: &Felt32, body: &[u8]) -> Result<String> {
    let hrp_s = Network::of_chain(chain)?.hrp(kind);
    let mut data = vec![VERSION, kind as u8];
    data.extend_from_slice(body);
    let mut pad = [0u8; 16];
    pad[..hrp_s.len()].copy_from_slice(hrp_s.as_bytes());
    data.extend_from_slice(&pad);
    let jumbled = f4jumble::f4jumble(&data).map_err(|_| Error::new("internal", "f4jumble"))?;
    let hrp = Hrp::parse(hrp_s).map_err(|_| Error::new("internal", "hrp"))?;
    bech32::encode::<Bech32m>(hrp, &jumbled).map_err(|e| Error::new("internal", format!("bech32m: {e}")))
}

/// Decodes a string of `kind`, returning the network and the body after the version and type.
fn decode(kind: Kind, s: &str, body_len: usize) -> Result<(Network, Vec<u8>)> {
    if s.len() > MAX_LEN {
        return Err(Error::input("too long"));
    }
    // Rejects mixed case; then works on the lowercase form.
    bech32::decode(s).map_err(|e| Error::input(&format!("bech32m: {e}")))?;
    let s = s.to_ascii_lowercase();
    let (hrp, data) = bech32::decode(&s).map_err(|e| Error::input(&format!("bech32m: {e}")))?;
    // Canonical: Bech32m (not Bech32), zero padding bits, one case. Re-encoding must reproduce it.
    let canonical = bech32::encode::<Bech32m>(hrp, &data).map_err(|_| Error::input("bech32m"))?;
    if canonical != s {
        return Err(Error::input("not a canonical Bech32m string"));
    }
    let network = [Network::Mainnet, Network::Sepolia]
        .into_iter()
        .find(|n| n.hrp(kind) == hrp.as_str())
        .ok_or_else(|| Error::input("wrong prefix for this kind of string"))?;
    if data.len() != 2 + body_len + 16 {
        return Err(Error::input("wrong length"));
    }
    let data = f4jumble::f4jumble_inv(&data).map_err(|_| Error::input("f4jumble"))?;
    let (payload, pad) = data.split_at(2 + body_len);
    let hrp_s = hrp.as_str().as_bytes();
    if &pad[..hrp_s.len()] != hrp_s || pad[hrp_s.len()..].iter().any(|b| *b != 0) {
        return Err(Error::input("padding block"));
    }
    if payload[0] != VERSION {
        return Err(Error::input("unknown version"));
    }
    if payload[1] != kind as u8 {
        return Err(Error::input("wrong type"));
    }
    Ok((network, payload[2..].to_vec()))
}

fn context(body: &[u8], network: Network) -> Result<(Felt32, Felt32)> {
    let chain: Felt32 = body[..32].try_into().unwrap();
    let pool: Felt32 = body[32..64].try_into().unwrap();
    if Network::of_chain(&chain)? != network {
        return Err(Error::input("prefix does not match the chain"));
    }
    felt::check_address(&pool, "pool")?;
    Ok((chain, pool))
}

/// A decoded receiving address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub chain: Felt32,
    pub pool: Felt32,
    pub receiver: Digest,
    pub pk: [u8; 32],
}

impl Address {
    pub fn of(chain: &Felt32, pool: &Felt32, a: &Account) -> Address {
        Address { chain: *chain, pool: *pool, receiver: a.receiver, pk: a.pk }
    }

    fn body(&self) -> Vec<u8> {
        [self.chain.as_slice(), &self.pool, &digest_bytes(&self.receiver), &self.pk].concat()
    }

    pub fn encode(&self) -> Result<String> {
        encode(Kind::Address, &self.chain, &self.body())
    }

    pub fn decode(s: &str) -> Result<Address> {
        let (network, body) = decode(Kind::Address, s, 132)?;
        let (chain, pool) = context(&body, network)?;
        let receiver = bytes_digest(&body[64..100]);
        if !digest_ok(&receiver) {
            return Err(Error::input("receiver"));
        }
        let pk: [u8; 32] = body[100..132].try_into().unwrap();
        if !sealbox::public_key_ok(&pk) {
            return Err(Error::input("encryption key"));
        }
        Ok(Address { chain, pool, receiver, pk })
    }

    /// The only supported human check: the first 10 bytes of `SHA-256(label ‖ payload)` as five
    /// groups of four hex digits (spec §4.1).
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"TEMPLAR_ADDRESS_FP_V1");
        h.update([VERSION, Kind::Address as u8]);
        h.update(self.body());
        let d = hex::encode(&h.finalize()[..10]);
        (0..5).map(|i| &d[4 * i..4 * i + 4]).collect::<Vec<_>>().join("-")
    }
}

/// A viewing key: incoming (receiver and `ivk`) or full (`ak`, `nk` and `ivk`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewingKey {
    pub chain: Felt32,
    pub pool: Felt32,
    pub receiver: Digest,
    /// Present for a full viewing key.
    pub nk: Option<(Digest, Digest)>,
    pub ivk: [u8; 32],
}

impl ViewingKey {
    pub fn of(chain: &Felt32, pool: &Felt32, a: &Account, full: bool) -> ViewingKey {
        ViewingKey { chain: *chain, pool: *pool, receiver: a.receiver, nk: full.then_some((a.ak, a.nk)), ivk: a.ivk }
    }

    pub fn encode(&self) -> Result<String> {
        let ctx = [self.chain.as_slice(), &self.pool].concat();
        match self.nk {
            None => encode(Kind::Incoming, &self.chain, &[ctx.as_slice(), &digest_bytes(&self.receiver), &self.ivk].concat()),
            Some((ak, nk)) => {
                encode(Kind::Full, &self.chain, &[ctx.as_slice(), &digest_bytes(&ak), &digest_bytes(&nk), &self.ivk].concat())
            }
        }
    }

    /// Decodes a viewing key and checks it against the independently authenticated address it is
    /// claimed to view (spec §4.2).
    pub fn import(s: &str, expected: &Address) -> Result<ViewingKey> {
        let full = s.to_ascii_lowercase().starts_with("templarfvk");
        let (network, body) = decode(if full { Kind::Full } else { Kind::Incoming }, s, if full { 168 } else { 132 })?;
        let (chain, pool) = context(&body, network)?;
        let (receiver, nk, ivk) = if full {
            let (ak, nk) = (bytes_digest(&body[64..100]), bytes_digest(&body[100..136]));
            if !digest_ok(&ak) || !digest_ok(&nk) {
                return Err(Error::input("viewing key digests"));
            }
            (keys::receiver_of(&ak, &nk), Some((ak, nk)), &body[136..168])
        } else {
            (bytes_digest(&body[64..100]), None, &body[100..132])
        };
        let ivk: [u8; 32] = ivk.try_into().unwrap();
        if ivk != sealbox::clamp(ivk) {
            return Err(Error::input("incoming key not clamped"));
        }
        if chain != expected.chain || pool != expected.pool || receiver != expected.receiver || sealbox::public_key(&ivk) != expected.pk {
            return Err(Error::new("viewing_key_mismatch", "the key does not view the expected address"));
        }
        Ok(ViewingKey { chain, pool, receiver, nk, ivk })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Seed;

    fn setup() -> (Felt32, Felt32, Account) {
        let chain = felt::from_short_string("SN_SEPOLIA").unwrap();
        let pool = felt::parse("0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9").unwrap();
        let a = Seed::from_bytes(&[4u8; 32]).unwrap().account(&chain, &pool, 0).unwrap();
        (chain, pool, a)
    }

    #[test]
    fn address_round_trip_and_rejections() {
        let (chain, pool, a) = setup();
        let addr = Address::of(&chain, &pool, &a);
        let s = addr.encode().unwrap();
        assert!(s.starts_with("templarsep1"));
        assert!(s.len() < 300, "{}", s.len());
        assert_eq!(Address::decode(&s).unwrap(), addr);
        assert_eq!(Address::decode(&s.to_ascii_uppercase()).unwrap(), addr);
        // One changed character fails the checksum.
        let mut bad: Vec<char> = s.chars().collect();
        let k = bad.len() - 10;
        bad[k] = if bad[k] == 'q' { 'p' } else { 'q' };
        assert!(Address::decode(&bad.into_iter().collect::<String>()).is_err());
        // A viewing key never decodes as an address, nor the other way round.
        let ivk = ViewingKey::of(&chain, &pool, &a, false).encode().unwrap();
        assert!(Address::decode(&ivk).is_err());
        assert!(ViewingKey::import(&s, &addr).is_err());
        assert_eq!(addr.fingerprint().len(), 24);
    }

    /// Encodes raw data bytes (version, type, body) with an HRP, as `encode` does.
    fn raw(hrp_s: &str, data: &[u8], pad: Option<&[u8]>) -> String {
        let mut d = data.to_vec();
        let mut p = [0u8; 16];
        p[..hrp_s.len()].copy_from_slice(hrp_s.as_bytes());
        d.extend_from_slice(pad.unwrap_or(&p));
        bech32::encode::<Bech32m>(Hrp::parse(hrp_s).unwrap(), &f4jumble::f4jumble(&d).unwrap()).unwrap()
    }

    /// Every decoding rejection of spec §4.1 and §4.2 (SDK-IM3).
    #[test]
    fn address_rejections() {
        let (chain, pool, a) = setup();
        let addr = Address::of(&chain, &pool, &a);
        let body = addr.body();
        let good = [&[VERSION, 1][..], &body].concat();
        assert_eq!(Address::decode(&raw("templarsep", &good, None)).unwrap(), addr);
        let with = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut d = good.clone();
            f(&mut d);
            d
        };
        let reject = |name: &str, s: String| assert!(Address::decode(&s).is_err(), "{name} accepted");
        reject("version", raw("templarsep", &with(&|d| d[0] = 2), None));
        reject("type", raw("templarsep", &with(&|d| d[1] = 2), None));
        reject("hrp for another chain", raw("templar", &good, None));
        reject("unknown hrp", raw("templarx", &good, None));
        reject("zero pool", raw("templarsep", &with(&|d| d[34..66].fill(0)), None));
        reject("pool at 2^251", raw("templarsep", &with(&|d| d[34] = 0x08), None));
        reject("receiver word = p", raw("templarsep", &with(&|d| d[66..70].copy_from_slice(&0x7fff_ffffu32.to_be_bytes())), None));
        reject("zero receiver", raw("templarsep", &with(&|d| d[66..102].fill(0)), None));
        reject("pk bit 255", raw("templarsep", &with(&|d| d[133] |= 0x80), None));
        reject("pk = p - 1", raw("templarsep", &with(&|d| {
            d[102] = 0xec;
            d[103..133].fill(0xff);
            d[133] = 0x7f;
        }), None));
        reject("pk >= p", raw("templarsep", &with(&|d| {
            d[102] = 0xee;
            d[103..133].fill(0xff);
            d[133] = 0x7f;
        }), None));
        reject("pk zero", raw("templarsep", &with(&|d| d[102..134].fill(0)), None));
        reject("pk one", raw("templarsep", &with(&|d| {
            d[102..134].fill(0);
            d[102] = 1;
        }), None));
        reject("short", raw("templarsep", &good[..good.len() - 1], None));
        reject("long", raw("templarsep", &[&good[..], &[0]].concat(), None));
        reject("padding", raw("templarsep", &good, Some(&[0u8; 16])));
        let s = addr.encode().unwrap();
        let mixed: String = s.chars().enumerate().map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c }).collect();
        reject("mixed case", mixed);
        let bech32 = bech32::encode::<bech32::Bech32>(Hrp::parse("templarsep").unwrap(), &f4jumble::f4jumble(&[&good[..], b"templarsep\0\0\0\0\0\0"].concat()).unwrap()).unwrap();
        reject("bech32 checksum", bech32);
        reject("too long", format!("templarsep1{}", "q".repeat(1100)));
        // Viewing keys: an unclamped ivk, and a key for another address.
        let ivk_body = [&[VERSION, 2][..], &chain, &pool, &digest_bytes(&a.receiver), &{
            let mut k = a.ivk;
            k[0] |= 1;
            k
        }]
        .concat();
        assert!(ViewingKey::import(&raw("templarivksep", &ivk_body, None), &addr).is_err(), "unclamped ivk accepted");
        let upper = ViewingKey::of(&chain, &pool, &a, true).encode().unwrap().to_ascii_uppercase();
        assert!(ViewingKey::import(&upper, &addr).is_ok(), "uppercase full viewing key");
    }

    #[test]
    fn viewing_keys() {
        let (chain, pool, a) = setup();
        let addr = Address::of(&chain, &pool, &a);
        for full in [false, true] {
            let k = ViewingKey::of(&chain, &pool, &a, full);
            let s = k.encode().unwrap();
            assert_eq!(ViewingKey::import(&s, &addr).unwrap(), k);
            let other = Address::of(&chain, &pool, &Seed::from_bytes(&[5u8; 32]).unwrap().account(&chain, &pool, 0).unwrap());
            assert!(ViewingKey::import(&s, &other).is_err());
        }
    }
}
