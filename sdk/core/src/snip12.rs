//! The spend message a bound account signs (`docs/account-bound-note-spec.md` §5.3): SNIP-12
//! revision 1, built entirely from statement fields, with the binding salted.
//!
//! ```text
//! StarknetDomain { name: 'Templar', version: 'V5', chainId: <chain>, revision: 1 }
//! TemplarSpend { pool, binding_commitment = Poseidon(binding, salt), token_out,
//!                withdrawal_recipient, withdrawal_amount, intent }
//! hash = Poseidon('StarkNet Message', domain_hash, account, struct_hash)
//! ```
//!
//! The same encoding as the statement account's Cairo module (`client-port/cairo-r5/bridge/src/
//! snip12.cairo`) and starknet.js 10.8 `typedData.getMessageHash`; the tests check this module
//! against starknet.js's known answers (`client-port/cairo-r5/kat/kat.json`).
use rand_core::{CryptoRng, RngCore};
use serde_json::{Value, json};
use templar_client_verifier_circuit::payment5::{self, Public};

use crate::felt::{self, Felt32};
use crate::{Error, Result};

/// sn_keccak of `"StarknetDomain"("name":"shortstring","version":"shortstring",
/// "chainId":"shortstring","revision":"shortstring")`.
pub const DOMAIN_TYPE_HASH: &str = "0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210";
/// sn_keccak of `"TemplarSpend"("pool":"ContractAddress","binding_commitment":"felt",
/// "token_out":"ContractAddress","withdrawal_recipient":"ContractAddress",
/// "withdrawal_amount":"u128","intent":"felt")`.
pub const SPEND_TYPE_HASH: &str = "0x26f4b4434596eda927640d80fc0e5f4e6d80e82289e112d306843f5e9df3873";
pub const DOMAIN_NAME: &str = "Templar";
/// Non-numeric, so no wallet encodes it as a number (P0b S1).
pub const DOMAIN_VERSION: &str = "V5";

/// A fresh salt, uniform in `[1, 2^251)` (spec §5.3).
pub fn random_salt(rng: &mut (impl RngCore + CryptoRng)) -> Felt32 {
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b[0] &= 0x07;
        if !felt::is_zero(&b) {
            return b;
        }
    }
}

/// The statement with every felt field rebuilt from its parsed value: the relation's encoders
/// panic on text that is not canonical hex, so nothing reaches them unparsed (SDK-IM1, AB-SP14).
fn canonical(s: &Public) -> Result<Public> {
    let c = |x: &str| felt::parse(x).map(|f| felt::to_hex(&f));
    Ok(Public {
        chain: c(&s.chain)?,
        pool: c(&s.pool)?,
        token_out: c(&s.token_out)?,
        deliveries: [c(&s.deliveries[0])?, c(&s.deliveries[1])?],
        withdrawal_recipient: c(&s.withdrawal_recipient)?,
        intent: c(&s.intent)?,
        account: c(&s.account)?,
        ..s.clone()
    })
}

/// The Templar domain's struct hash on `chain` (a shortstring felt).
pub fn domain_hash(chain: &Felt32) -> Result<Felt32> {
    Ok(felt::poseidon(&[
        felt::parse(DOMAIN_TYPE_HASH)?,
        felt::from_short_string(DOMAIN_NAME)?,
        felt::from_short_string(DOMAIN_VERSION)?,
        *chain,
        felt::from_u128(1),
    ]))
}

/// `Poseidon(binding, salt)`.
pub fn binding_commitment(binding: &Felt32, salt: &Felt32) -> Felt32 {
    felt::poseidon(&[*binding, *salt])
}

/// The signed fields, all from the decoded statement except `salt`. Production code builds it only
/// with [`SpendMessage::of`], which takes every field from a bridge-checked statement; the fields
/// are public for the known-answer tests.
pub struct SpendMessage {
    pub chain: Felt32,
    pub account: Felt32,
    pub pool: Felt32,
    pub binding: Felt32,
    pub salt: Felt32,
    pub token_out: Felt32,
    pub withdrawal_recipient: Felt32,
    pub withdrawal_amount: u128,
    pub intent: Felt32,
}

impl SpendMessage {
    /// The message for a bound V5 statement and a nonzero salt. The binding is the statement's own
    /// `TMR0_BIND_V5`, computed here, never taken from the caller (AB-SM2), and the statement must
    /// pass the bridge's checks.
    pub fn of(statement: &Public, salt: &Felt32) -> Result<SpendMessage> {
        let statement = &canonical(statement)?;
        payment5::bridge_checks(statement).map_err(|e| Error::new("bridge_would_reject", e))?;
        let binding = &crate::spend::binding5(statement)?;
        let account = felt::parse(&statement.account)?;
        if felt::is_zero(&account) {
            return Err(Error::input("an ordinary statement has no spend message"));
        }
        if felt::is_zero(salt) || !felt::below_2_251(salt) {
            return Err(Error::input("salt: zero or not below 2^251"));
        }
        Ok(SpendMessage {
            chain: felt::parse(&statement.chain)?,
            account,
            pool: felt::parse(&statement.pool)?,
            binding: *binding,
            salt: *salt,
            token_out: felt::parse(&statement.token_out)?,
            withdrawal_recipient: felt::parse(&statement.withdrawal_recipient)?,
            withdrawal_amount: statement.withdrawal_amount,
            intent: felt::parse(&statement.intent)?,
        })
    }

    /// The setup check's message (spec §6.3): a `TemplarSpend` with `pool = 0` and a random
    /// binding commitment, which exercises the exact spend encoding and can never authorize a
    /// spend (every spend names its pool).
    pub fn setup_check(chain: &Felt32, account: &Felt32, rng: &mut (impl RngCore + CryptoRng)) -> Result<SpendMessage> {
        felt::check_address(account, "account")?;
        short_string_text(chain)?;
        Ok(SpendMessage {
            chain: *chain, account: *account, pool: [0; 32], binding: random_salt(rng), salt: random_salt(rng),
            token_out: [0; 32], withdrawal_recipient: [0; 32], withdrawal_amount: 0, intent: [0; 32],
        })
    }

    pub fn struct_hash(&self) -> Result<Felt32> {
        Ok(felt::poseidon(&[
            felt::parse(SPEND_TYPE_HASH)?,
            self.pool,
            binding_commitment(&self.binding, &self.salt),
            self.token_out,
            self.withdrawal_recipient,
            felt::from_u128(self.withdrawal_amount),
            self.intent,
        ]))
    }

    /// The hash the account's `is_valid_signature` is asked about.
    pub fn hash(&self) -> Result<Felt32> {
        Ok(felt::poseidon(&[felt::from_short_string("StarkNet Message")?, domain_hash(&self.chain)?, self.account, self.struct_hash()?]))
    }

    /// The typed data for the wallet's `signTypedData`, as starknet.js takes it: felts and
    /// addresses as canonical hex, the u128 amount as a decimal string (never a JSON number, which
    /// a browser would round above 2^53).
    pub fn typed_data(&self) -> Result<Value> {
        let chain = short_string_text(&self.chain)?;
        Ok(json!({
            "types": {
                "StarknetDomain": [
                    {"name": "name", "type": "shortstring"},
                    {"name": "version", "type": "shortstring"},
                    {"name": "chainId", "type": "shortstring"},
                    {"name": "revision", "type": "shortstring"},
                ],
                "TemplarSpend": [
                    {"name": "pool", "type": "ContractAddress"},
                    {"name": "binding_commitment", "type": "felt"},
                    {"name": "token_out", "type": "ContractAddress"},
                    {"name": "withdrawal_recipient", "type": "ContractAddress"},
                    {"name": "withdrawal_amount", "type": "u128"},
                    {"name": "intent", "type": "felt"},
                ],
            },
            "primaryType": "TemplarSpend",
            "domain": {"name": DOMAIN_NAME, "version": DOMAIN_VERSION, "chainId": chain, "revision": "1"},
            "message": {
                "pool": felt::to_hex(&self.pool),
                "binding_commitment": felt::to_hex(&binding_commitment(&self.binding, &self.salt)),
                "token_out": felt::to_hex(&self.token_out),
                "withdrawal_recipient": felt::to_hex(&self.withdrawal_recipient),
                "withdrawal_amount": self.withdrawal_amount.to_string(),
                "intent": felt::to_hex(&self.intent),
            },
        }))
    }
}

/// A shortstring felt as its ASCII text (the chain id).
fn short_string_text(f: &Felt32) -> Result<String> {
    let bytes: Vec<u8> = f.iter().copied().skip_while(|b| *b == 0).collect();
    if bytes.is_empty() || bytes.len() > 31 || !bytes.iter().all(|b| b.is_ascii_graphic()) {
        return Err(Error::input("chain: not a shortstring"));
    }
    Ok(String::from_utf8(bytes).expect("ASCII"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const KAT: &str = include_str!("../../../bench/m31-private-wrapper/client-port/cairo-r5/kat/kat.json");

    fn f(v: &Value) -> Felt32 {
        felt::parse(v.as_str().unwrap()).unwrap()
    }

    /// The core's hashes and typed data equal starknet.js's for every known-answer spend.
    #[test]
    fn matches_starknet_js() {
        let kat: Value = serde_json::from_str(KAT).unwrap();
        assert_eq!(kat["constants"]["domain_type_hash"], DOMAIN_TYPE_HASH);
        assert_eq!(kat["constants"]["spend_type_hash"], SPEND_TYPE_HASH);
        let spends = kat["spends"].as_array().unwrap();
        assert!(spends.len() >= 3);
        for s in spends {
            let m = SpendMessage {
                chain: f(&s["chain"]),
                account: f(&s["account"]),
                pool: f(&s["pool"]),
                binding: f(&s["binding"]),
                salt: f(&s["salt"]),
                token_out: f(&s["token_out"]),
                withdrawal_recipient: f(&s["withdrawal_recipient"]),
                withdrawal_amount: s["withdrawal_amount"].as_str().unwrap().parse().unwrap(),
                intent: f(&s["intent"]),
            };
            let name = s["name"].as_str().unwrap();
            assert_eq!(binding_commitment(&m.binding, &m.salt), f(&s["binding_commitment"]), "{name}");
            assert_eq!(domain_hash(&m.chain).unwrap(), f(&s["domain_hash"]), "{name}");
            assert_eq!(m.struct_hash().unwrap(), f(&s["struct_hash"]), "{name}");
            assert_eq!(m.hash().unwrap(), f(&s["message_hash"]), "{name}");
            let td = m.typed_data().unwrap();
            for k in ["types", "primaryType", "domain", "message"] {
                assert_eq!(td[k], s["typed_data"][k], "{name}: typed_data.{k}");
            }
        }
    }

    /// Malformed felt text is an error, never a panic in the relation's encoders (AB-SP14).
    #[test]
    fn malformed_statement_text_is_an_error() {
        let base = Public {
            chain: "0x534e5f5345504f4c4941".into(), pool: "0x7e57b301".into(), token_out: "0x0".into(), root: [1; 9],
            nullifiers: [[1; 9], [2; 9]], commitments: [[3; 9], [4; 9]], deliveries: ["0x5".into(), "0x6".into()],
            withdrawal_recipient: "0x0".into(), withdrawal_amount: 0, intent: "0x0".into(), identity: [0; 9],
            account: "0xacc".into(), valid_until: 6500,
        };
        for bad in ["534e5f5345504f4c4941", "0xzz", "", "0x"] {
            let s = Public { chain: bad.into(), ..base.clone() };
            assert!(std::panic::catch_unwind(|| SpendMessage::of(&s, &[1; 32])).expect("no panic").is_err(), "{bad:?}");
            let s = Public { deliveries: [bad.into(), "0x6".into()], ..base.clone() };
            assert!(std::panic::catch_unwind(|| SpendMessage::of(&s, &[1; 32])).expect("no panic").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn salts_are_nonzero_and_below_2_251() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for _ in 0..1000 {
            let s = random_salt(&mut rng);
            assert!(!felt::is_zero(&s) && felt::below_2_251(&s));
        }
    }
}
