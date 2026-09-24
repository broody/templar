//! Reproducibility: with seeded RNGs the plan and proof are fixed, so their SHA-256 is a vector
//! (`sdk/vectors/determinism.json`) that native, WASM and dependency changes must reproduce
//! byte for byte (spec §12.2). `TEMPLAR_WRITE_VECTORS=1` rewrites it.
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest as _, Sha256};
use templar_core::address::Address;
use templar_core::felt::{self, Felt32};
use templar_core::keys::Seed;
use templar_core::spend::{self, NoteRef, PlanInput, Request};
use templar_core::tree::Tree;
use templar_core::{note, random_digest};

const VECTOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/determinism.json");

pub fn fixture() -> (Seed, String, Tree, Vec<NoteRef>) {
    let chain: Felt32 = felt::from_short_string("SN_SEPOLIA").unwrap();
    let pool = felt::parse("0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9").unwrap();
    let token = felt::parse("0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8").unwrap();
    let alice = Seed::from_bytes(&[0xa1; 32]).unwrap();
    let a = alice.account(&chain, &pool, 0).unwrap();
    let bob = Address::of(&chain, &pool, &Seed::from_bytes(&[0xb0; 32]).unwrap().account(&chain, &pool, 0).unwrap());
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let rho = random_digest(&mut rng);
    let cm = note::commitment(&chain, &pool, &token, 1000, &a.receiver, &rho).unwrap();
    let mut tree = Tree::new();
    tree.append(&[[1, 2, 3, 4, 5, 6, 7, 8, 9], cm]).unwrap();
    let notes = vec![NoteRef { index: 1, account: 0, asset: felt::to_hex(&token), amount: "1000".into(), rho, commitment: cm }];
    let request = serde_json::to_string(&Request::Transfer { asset: felt::to_hex(&token), amount: "600".into(), to: bob.encode().unwrap() }).unwrap();
    (alice, request, tree, notes)
}

fn sha(v: &impl serde::Serialize) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap()))
}

#[test]
fn seeded_plan_and_proof_are_fixed() {
    let (alice, request, tree, notes) = fixture();
    let plan = spend::plan(
        PlanInput {
            seed: &alice,
            chain: felt::from_short_string("SN_SEPOLIA").unwrap(),
            pool: felt::parse("0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9").unwrap(),
            request: serde_json::from_str(&request).unwrap(),
            notes: &notes,
            companions: &[],
            required_inputs: None,
            tree: &tree,
        },
        &mut ChaCha20Rng::seed_from_u64(7),
    )
    .unwrap();
    let proved = spend::prove_plan(&alice, &plan, &mut ChaCha20Rng::seed_from_u64(8)).unwrap();
    let got = serde_json::json!({
        "plan_sha256": sha(&plan),
        "proof_sha256": sha(&proved.proof),
        "proof_felts": proved.proof.len() - 1,
        "binding": proved.binding,
        "circuit_hash_u32_le": proved.circuit_hash,
    });
    if std::env::var("TEMPLAR_WRITE_VECTORS").is_ok() {
        let doc = serde_json::json!({
            "description": "Seeded plan (ChaCha20 seed 7) and proof (seed 8) of a 600-of-1000 transfer; see core/tests/determinism.rs",
            "plan": plan,
            "expected": got,
        });
        std::fs::write(VECTOR, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        return;
    }
    let want: serde_json::Value = serde_json::from_slice(&std::fs::read(VECTOR).unwrap()).unwrap();
    assert_eq!(got, want["expected"]);
}
