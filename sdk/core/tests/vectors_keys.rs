//! Known-answer vectors for the new formats (spec §3, §4, §12.1): seed backups, key derivation,
//! addresses, viewing keys, fingerprints, sealed boxes and store keys. The core writes
//! `sdk/vectors/keys.json` (with `TEMPLAR_WRITE_VECTORS=1`) and checks it otherwise; the
//! independent Python reference `sdk/vectors/check_keys.py` recomputes it.
use serde_json::{Value, json};
use templar_core::address::{Address, ViewingKey};
use templar_core::felt;
use templar_core::keys::Seed;
use templar_core::sealbox;
use x25519_dalek::StaticSecret;

const VECTOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/keys.json");

fn generate() -> Value {
    let chain = felt::from_short_string("SN_SEPOLIA").unwrap();
    let pool = felt::parse("0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9").unwrap();
    let mut wallets = vec![];
    for seed_byte in [0u8, 0x5a, 0xff] {
        let seed = Seed::from_bytes(&[seed_byte; 32]).unwrap();
        let mut accounts = vec![];
        for i in [0u32, 1, 7] {
            let a = seed.account(&chain, &pool, i).unwrap();
            let addr = Address::of(&chain, &pool, &a);
            accounts.push(json!({
                "index": i,
                "sk": a.sk,
                "ak": a.ak,
                "nk": a.nk,
                "receiver": a.receiver,
                "ivk": hex::encode(a.ivk),
                "pk": hex::encode(a.pk),
                "address": addr.encode().unwrap(),
                "fingerprint": addr.fingerprint(),
                "incoming_viewing_key": ViewingKey::of(&chain, &pool, &a, false).encode().unwrap(),
                "full_viewing_key": ViewingKey::of(&chain, &pool, &a, true).encode().unwrap(),
            }));
        }
        wallets.push(json!({
            "seed": hex::encode(seed.bytes()),
            "mnemonic": seed.mnemonic(),
            "store_key": hex::encode(seed.store_key(&chain, &pool).as_ref()),
            "accounts": accounts,
        }));
    }
    // Sealed boxes with fixed ephemeral secrets, to the first account of the first wallet.
    let a = Seed::from_bytes(&[0u8; 32]).unwrap().account(&chain, &pool, 0).unwrap();
    let boxes: Vec<Value> = [1u8, 2]
        .into_iter()
        .map(|e| {
            let esk = [e; 32];
            let message: Vec<u8> = (0..256).map(|k| (k as u8).wrapping_mul(e)).collect();
            let sealed = sealbox::seal_with(&a.pk, &message, &StaticSecret::from(esk)).unwrap();
            json!({"esk": hex::encode(esk), "message": hex::encode(&message), "sealed": hex::encode(&sealed),
                   "words": sealbox::to_words(&sealed).unwrap().iter().map(felt::to_hex).collect::<Vec<_>>(),
                   "delivery": felt::to_hex(&sealbox::delivery(&sealbox::to_words(&sealed).unwrap()))})
        })
        .collect();
    json!({
        "description": "templar-core key, address, viewing-key, sealed-box and store-key vectors (docs/sdk-spec.md §3-§5)",
        "chain": "SN_SEPOLIA",
        "pool": "0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9",
        "wallets": wallets,
        "sealed_boxes": {"recipient_ivk": hex::encode(a.ivk), "recipient_pk": hex::encode(a.pk), "boxes": boxes},
    })
}

#[test]
fn key_vectors() {
    let got = generate();
    if std::env::var("TEMPLAR_WRITE_VECTORS").is_ok() {
        std::fs::write(VECTOR, serde_json::to_vec_pretty(&got).unwrap()).unwrap();
        return;
    }
    let want: Value = serde_json::from_slice(&std::fs::read(VECTOR).unwrap()).unwrap();
    assert_eq!(got, want);
    // Every address and key decodes back, and each only as its own kind.
    for w in want["wallets"].as_array().unwrap() {
        for a in w["accounts"].as_array().unwrap() {
            let addr = Address::decode(a["address"].as_str().unwrap()).unwrap();
            for k in ["incoming_viewing_key", "full_viewing_key"] {
                let key = a[k].as_str().unwrap();
                assert!(ViewingKey::import(key, &addr).is_ok());
                assert!(Address::decode(key).is_err());
            }
            assert_eq!(addr.fingerprint(), a["fingerprint"].as_str().unwrap());
        }
    }
    // Opening the vector boxes.
    let sb = &want["sealed_boxes"];
    let ivk: [u8; 32] = hex::decode(sb["recipient_ivk"].as_str().unwrap()).unwrap().try_into().unwrap();
    for b in sb["boxes"].as_array().unwrap() {
        let sealed = hex::decode(b["sealed"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(sealbox::open(&ivk, &sealed).unwrap()), b["message"].as_str().unwrap());
    }
}
