//! A whole client flow in the core: a deposit's note, a hidden transfer with change, both parties
//! scanning, a withdrawal and an ERC721 transfer with the sticky companion, each proved and
//! self-verified. Writes the server submissions to `$TEMPLAR_SDK_OUT` when set, for
//! `templar-prover check`.
use std::collections::HashMap;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use templar_core::address::Address;
use templar_core::felt::{self, Felt32};
use templar_core::keys::Seed;
use templar_core::scan::{self, Context, Published, Registered, ScanKey};
use templar_core::spend::{self, NoteRef, PlanInput, Request};
use templar_core::tree::Tree;
use templar_core::{note, random_digest, sealbox};

fn chain() -> Felt32 {
    felt::from_short_string("SN_SEPOLIA").unwrap()
}
fn pool() -> Felt32 {
    felt::parse("0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9").unwrap()
}

/// What a deposit publishes: the leaf, its digest and its ciphertext words.
fn deposit(to: &Address, asset: &Felt32, amount: u128, rng: &mut ChaCha20Rng) -> (templar_core::Digest, Felt32, Vec<Felt32>) {
    let rho = random_digest(rng);
    let sealed = sealbox::seal(&to.pk, &note::m301(asset, &to.receiver, &rho, amount), rng).unwrap();
    let words = sealbox::to_words(&sealed).unwrap();
    let cm = note::commitment(&to.chain, &to.pool, asset, amount, &to.receiver, &rho).unwrap();
    (cm, sealbox::delivery(&words), words.to_vec())
}

fn keys(seed: &Seed, full: bool) -> Vec<ScanKey> {
    let a = seed.account(&chain(), &pool(), 0).unwrap();
    vec![ScanKey { index: 0, receiver: a.receiver, ivk: a.ivk, nk: full.then_some(a.nk) }]
}

fn refs(owned: &[scan::Owned]) -> Vec<NoteRef> {
    owned
        .iter()
        .map(|o| NoteRef {
            index: o.index,
            account: o.account,
            asset: felt::to_hex(&o.asset),
            amount: o.amount.to_string(),
            rho: o.rho,
            commitment: o.commitment,
        })
        .collect()
}

fn publish(tree: &mut Tree, published: &mut Vec<Published>, proved: &spend::Proved, plan: &spend::Plan) {
    for (cm, out) in proved.statement.commitments.iter().zip(&plan.outputs) {
        let words: Vec<Felt32> = out.ciphertext.iter().map(|w| felt::parse(w).unwrap()).collect();
        published.push(Published { index: tree.len(), commitment: *cm, digest: felt::parse(&out.delivery).unwrap(), words });
        tree.append(&[*cm]).unwrap();
    }
}

fn save(name: &str, proved: &spend::Proved) {
    if let Ok(dir) = std::env::var("TEMPLAR_SDK_OUT") {
        let body = serde_json::json!({"relation": "r4", "proof": proved.proof, "statement": proved.statement});
        std::fs::write(format!("{dir}/{name}.json"), serde_json::to_vec(&body).unwrap()).unwrap();
    }
}

#[test]
fn deposit_transfer_scan_withdraw_nft() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (alice, bob) = (Seed::from_bytes(&[0xa1; 32]).unwrap(), Seed::from_bytes(&[0xb0; 32]).unwrap());
    let a_addr = Address::of(&chain(), &pool(), &alice.account(&chain(), &pool(), 0).unwrap());
    let b_addr = Address::of(&chain(), &pool(), &bob.account(&chain(), &pool(), 0).unwrap());
    let token = felt::parse("0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8").unwrap();
    let nft_contract = felt::parse("0x535ca4f5d12d72d05ab6d954ca7939b73b5a20cec680241c6020735e751de0f").unwrap();
    let nft = note::asset_id(note::ERC721, &nft_contract, (2, 0)).unwrap();
    let registry: HashMap<Felt32, Registered> =
        [(nft, Registered { standard: note::ERC721, contract: nft_contract, id: (2, 0) })].into_iter().collect();

    let mut tree = Tree::new();
    let mut published = vec![];
    // Someone else's leaf, then Alice's 1000 and her NFT.
    for (to, asset, amount) in [(&b_addr, token, 5u128), (&a_addr, token, 1000), (&a_addr, nft, 1)] {
        let (cm, digest, words) = deposit(to, &asset, amount, &mut rng);
        published.push(Published { index: tree.len(), commitment: cm, digest, words });
        tree.append(&[cm]).unwrap();
    }
    let ctx = Context { chain: chain(), pool: pool(), registry: &registry, registry_complete: true, settlements: &[] };
    let found = scan::scan(&ctx, &keys(&alice, true), &published).unwrap();
    assert!(found.bad_digests.is_empty());
    assert_eq!(found.owned.iter().map(|o| o.amount).collect::<Vec<_>>(), vec![1000, 1]);
    assert!(matches!(found.owned[1].kind, scan::AssetKind::Erc721 { .. }));
    let notes = refs(&found.owned);

    // A hidden transfer of 600 to Bob, one input and a fresh companion.
    let plan = spend::plan(
        PlanInput {
            seed: &alice,
            chain: chain(),
            pool: pool(),
            request: Request::Transfer { asset: felt::to_hex(&token), amount: "600".into(), to: b_addr.encode().unwrap() },
            notes: &notes,
            companions: &[],
            required_inputs: None,
            tree: &tree,
        },
        &mut rng,
    )
    .unwrap();
    assert_eq!(plan.inputs.len(), 1);
    assert!(plan.companion_is_new);
    let companion = (plan.inputs[0].index, plan.companion.clone().unwrap());
    let proved = spend::prove_plan(&alice, &plan, &mut rng).unwrap();
    assert_eq!(proved.statement.token_out, "0x0", "a transfer publishes no asset");
    assert_eq!(proved.calldata.last().unwrap(), "0x0");
    save("transfer", &proved);
    publish(&mut tree, &mut published, &proved, &plan);

    // Bob finds 600; Alice finds her 400 change and nothing else new.
    let bob_found = scan::scan(&ctx, &keys(&bob, true), &published).unwrap().owned;
    assert_eq!(bob_found.iter().map(|o| o.amount).collect::<Vec<_>>(), vec![5, 600]);
    let alice_found = scan::scan(&ctx, &keys(&alice, true), &published).unwrap().owned;
    assert_eq!(alice_found.iter().map(|o| o.amount).collect::<Vec<_>>(), vec![1000, 1, 400]);
    // The spent input's nullifier is the statement's first.
    assert_eq!(alice_found[0].nullifier.unwrap(), proved.nullifiers[0]);
    // An incoming viewing key sees the same notes without nullifiers.
    assert!(scan::scan(&ctx, &keys(&alice, false), &published).unwrap().owned.iter().all(|o| o.nullifier.is_none()));

    // A re-plan of the same note reuses its companion (sticky, SDK-M17).
    let again = spend::plan(
        PlanInput {
            seed: &alice,
            chain: chain(),
            pool: pool(),
            request: Request::Transfer { asset: felt::to_hex(&token), amount: "100".into(), to: b_addr.encode().unwrap() },
            notes: &notes[..1],
            companions: std::slice::from_ref(&companion),
            required_inputs: Some(&[notes[0].index]),
            tree: &tree,
        },
        &mut rng,
    )
    .unwrap();
    assert_eq!(again.companion.as_ref(), Some(&companion.1));
    assert!(!again.companion_is_new);

    // Withdraw the NFT: the asset is published; two dummy outputs.
    let nft_notes = refs(&alice_found[1..2]);
    let plan = spend::plan(
        PlanInput {
            seed: &alice,
            chain: chain(),
            pool: pool(),
            request: Request::Withdraw { asset: felt::to_hex(&nft), amount: "1".into(), recipient: "0xb0b".into() },
            notes: &nft_notes,
            companions: &[],
            required_inputs: None,
            tree: &tree,
        },
        &mut rng,
    )
    .unwrap();
    let proved = spend::prove_plan(&alice, &plan, &mut rng).unwrap();
    assert_eq!(felt::parse(&proved.statement.token_out).unwrap(), nft);
    save("withdraw-nft", &proved);

    // Refusals before proving.
    let plan_err = |request: Request, notes: &[NoteRef]| {
        spend::plan(
            PlanInput { seed: &alice, chain: chain(), pool: pool(), request, notes, companions: &[], required_inputs: None, tree: &tree },
            &mut ChaCha20Rng::seed_from_u64(1),
        )
        .unwrap_err()
        .code
    };
    let t = felt::to_hex(&token);
    assert_eq!(plan_err(Request::Transfer { asset: t.clone(), amount: "5000".into(), to: b_addr.encode().unwrap() }, &notes), "insufficient_notes");
    let other_pool = Address { pool: felt::parse("0x1234").unwrap(), ..b_addr.clone() };
    assert_eq!(plan_err(Request::Transfer { asset: t.clone(), amount: "1".into(), to: other_pool.encode().unwrap() }, &notes), "wrong_pool");
    // Bob's note is not Alice's.
    assert_eq!(plan_err(Request::Transfer { asset: t, amount: "1".into(), to: b_addr.encode().unwrap() }, &refs(&bob_found[..1])), "not_ours");
}
