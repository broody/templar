//! R0 V6 spends for pool V3 (`docs/pool-v3-spec.md` §4, §5.2, §10): `TMR0_BIND_V5` against
//! starknet.js's known answers (`cairo-r6/kat`, the V5 anchors and the ciphertext-derived vectors),
//! V6's statement and pool calldata equal to V5-ordinary's with a zero account, and a V6 transfer
//! and withdrawal planned, proved and verified. Writes the proofs as bridge inputs and `r6` job
//! bodies to `$TEMPLAR_SDK_OUT` when set, for the R6 bridge's standalone check and the server.
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use templar_core::address::Address;
use templar_core::felt::{self, Felt32};
use templar_core::keys::Seed;
use templar_core::payment6::Public;
use templar_core::scan::{self, Context, Published, ScanKey};
use templar_core::spend::{self, Expiry, NoteRef, PlanInput, Request, Statement, Version};
use templar_core::tree::Tree;
use templar_core::{note, random_digest, sealbox};

const KAT: &str = include_str!("../../../bench/m31-private-wrapper/client-port/cairo-r6/kat/kat.json");

fn chain() -> Felt32 {
    felt::from_short_string("SN_SEPOLIA").unwrap()
}
fn pool() -> Felt32 {
    felt::parse("0x7e57b301").unwrap()
}
fn expiry(latest: u64) -> Expiry {
    Expiry { latest_block: latest, window: 1500, quantum: 100 }
}

/// `TMR0_BIND_V5` equals starknet.js's for every `cairo-r6/kat` statement: V5's four anchors,
/// `valid_until` 1, and the ciphertext-derived vectors (re-check F3).
#[test]
fn binding_matches_starknet_js() {
    let kat: serde_json::Value = serde_json::from_str(KAT).unwrap();
    let bindings = kat["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 8);
    for b in bindings {
        let s = &b["statement"];
        let hex = |v: &serde_json::Value| felt::to_hex(&felt::parse(&format!("0x{}", v.as_str().unwrap().trim_start_matches("0x"))).unwrap());
        let words = |v: &serde_json::Value| -> [u32; 9] { std::array::from_fn(|k| v[k].as_str().unwrap().parse().unwrap()) };
        let int = |v: &serde_json::Value| -> u128 {
            let t = v.as_str().unwrap();
            match t.strip_prefix("0x") {
                Some(h) => u128::from_str_radix(h, 16).unwrap(),
                None => t.parse().unwrap(),
            }
        };
        let p = Public {
            chain: hex(&s["chain"]), pool: hex(&s["pool"]), token_out: hex(&s["token_out"]), root: words(&s["root"]),
            nullifiers: [words(&s["nullifiers"][0]), words(&s["nullifiers"][1])],
            commitments: [words(&s["commitments"][0]), words(&s["commitments"][1])],
            deliveries: [hex(&s["deliveries"][0]), hex(&s["deliveries"][1])],
            withdrawal_recipient: hex(&s["withdrawal_recipient"]), withdrawal_amount: int(&s["withdrawal_amount"]),
            intent: hex(&s["intent"]), identity: words(&s["identity"]), valid_until: int(&s["valid_until"]) as u64,
        };
        let want = felt::parse(b["binding"].as_str().unwrap()).unwrap();
        assert_eq!(spend::Statement::V6(p.clone()).binding().unwrap(), want, "{}", b["name"]);
        // Each ciphertext-derived vector's delivery digests are the pool's own.
        if let Some(cts) = b.get("ciphertexts") {
            for j in 0..2 {
                let words: Vec<Felt32> = cts[j].as_array().unwrap().iter().map(|w| felt::parse(w.as_str().unwrap()).unwrap()).collect();
                let words: [Felt32; 10] = words.try_into().unwrap();
                assert_eq!(felt::to_hex(&sealbox::delivery(&words)), p.deliveries[j], "{} delivery {j}", b["name"]);
            }
        }
    }
}

fn deposit(to: &Address, asset: &Felt32, amount: u128, rng: &mut ChaCha20Rng) -> Published {
    let rho = random_digest(rng);
    let sealed = sealbox::seal(&to.pk, &note::m301(asset, &to.receiver, &rho, amount), rng).unwrap();
    let words = sealbox::to_words(&sealed).unwrap();
    let cm = note::commitment(&to.chain, &to.pool, asset, amount, &to.receiver, &rho).unwrap();
    Published { index: 0, commitment: cm, digest: sealbox::delivery(&words), words: words.to_vec() }
}

fn save(name: &str, proved: &spend::Proved) {
    if let Ok(dir) = std::env::var("TEMPLAR_SDK_OUT") {
        let d = format!("{dir}/{name}");
        std::fs::create_dir_all(&d).unwrap();
        let args: Vec<String> = proved.proof.clone();
        std::fs::write(format!("{d}/cairo-arguments.json"), serde_json::to_vec(&args).unwrap()).unwrap();
        std::fs::write(format!("{d}/public.json"), serde_json::to_vec_pretty(&proved.statement).unwrap()).unwrap();
        std::fs::write(format!("{d}/binding.txt"), &proved.binding).unwrap();
        // The prover server's job body (spec §9): proof, statement, the pool call that settles it.
        let body = serde_json::json!({
            "relation": "r6", "proof": proved.proof, "statement": proved.statement,
            "pool_call": {"entry_point": "apply_spend", "calldata": proved.calldata},
        });
        std::fs::write(format!("{d}/submission.json"), serde_json::to_vec(&body).unwrap()).unwrap();
    }
}

fn save_free(name: &str, proved: &spend::Proved, openings: &[templar_core::Digest; 2]) {
    if let Ok(dir) = std::env::var("TEMPLAR_SDK_OUT") {
        let body = serde_json::json!({
            "relation": "r6", "proof": proved.proof, "statement": proved.statement,
            "pool_call": {"entry_point": "apply_spend", "calldata": proved.calldata},
            "payment": {"free_full_withdrawal": {"openings": openings}},
        });
        std::fs::create_dir_all(format!("{dir}/{name}")).unwrap();
        std::fs::write(format!("{dir}/{name}/free-submission.json"), serde_json::to_vec(&body).unwrap()).unwrap();
    }
}

/// Pool V3 calldata: V4's `Spend`, then `valid_until`, the binding and the empty proof span; the
/// same as V5-ordinary's.
fn check_calldata(p: &Public, proved: &spend::Proved, ciphertexts: &[Vec<String>; 2]) {
    let v5 = templar_core::payment5::Public {
        chain: p.chain.clone(), pool: p.pool.clone(), token_out: p.token_out.clone(), root: p.root, nullifiers: p.nullifiers,
        commitments: p.commitments, deliveries: p.deliveries.clone(), withdrawal_recipient: p.withdrawal_recipient.clone(),
        withdrawal_amount: p.withdrawal_amount, intent: p.intent.clone(), identity: p.identity, account: "0x0".into(),
        valid_until: p.valid_until,
    };
    assert_eq!(proved.calldata, spend::calldata5(&v5, ciphertexts).unwrap());
    assert_eq!(felt::parse(&proved.binding).unwrap(), spend::binding5(&v5).unwrap());
    let v4 = spend::calldata(
        &templar_core::payment4::Public {
            chain: p.chain.clone(), pool: p.pool.clone(), token_out: p.token_out.clone(), root: p.root, nullifiers: p.nullifiers,
            commitments: p.commitments, deliveries: p.deliveries.clone(), withdrawal_recipient: p.withdrawal_recipient.clone(),
            withdrawal_amount: p.withdrawal_amount, intent: p.intent.clone(), identity: p.identity,
        },
        ciphertexts,
    )
    .unwrap();
    let c = &proved.calldata;
    assert_eq!(c.len(), v4.len() + 1);
    assert_eq!(c[..v4.len() - 2], v4[..v4.len() - 2]);
    assert_eq!(c[c.len() - 3], format!("0x{:x}", p.valid_until));
    assert_eq!(c[c.len() - 2], proved.binding);
    assert_eq!(c[c.len() - 1], "0x0");
}

#[test]
fn v6_transfer_and_withdrawal() {
    let mut rng = ChaCha20Rng::seed_from_u64(55);
    let (alice, bob) = (Seed::from_bytes(&[0xa5; 32]).unwrap(), Seed::from_bytes(&[0xb5; 32]).unwrap());
    let a = alice.account(&chain(), &pool(), 0).unwrap();
    let a_addr = Address::of(&chain(), &pool(), &a);
    let b_addr = Address::of(&chain(), &pool(), &bob.account(&chain(), &pool(), 0).unwrap());
    let token = felt::parse("0x7e57b3a1").unwrap();
    let mut tree = Tree::new();
    let mut published = vec![];
    for amount in [1000u128, 700] {
        let mut d = deposit(&a_addr, &token, amount, &mut rng);
        d.index = tree.len();
        tree.append(&[d.commitment]).unwrap();
        published.push(d);
    }
    let registry = Default::default();
    let ctx = Context { chain: chain(), pool: pool(), registry: &registry, registry_complete: true, settlements: &[] };
    let keys = vec![ScanKey { index: 0, receiver: a.receiver, ivk: a.ivk, nk: Some(a.nk) }];
    let notes: Vec<NoteRef> = scan::scan(&ctx, &keys, &published)
        .unwrap()
        .owned
        .iter()
        .map(|o| NoteRef { index: o.index, account: o.account, asset: felt::to_hex(&o.asset), amount: o.amount.to_string(), rho: o.rho, commitment: o.commitment })
        .collect();
    assert_eq!(notes.len(), 2);
    let latest = 123_456;
    let plan_for = |request: Request, rng: &mut ChaCha20Rng| {
        spend::plan(
            PlanInput {
                keys: &alice, version: Version::V6, expiry: Some(expiry(latest)), chain: chain(), pool: pool(), request,
                notes: &notes, companions: &[], required_inputs: None, spent: &[], tree: &tree,
            },
            rng,
        )
    };
    // A V6 spend needs the expiry inputs.
    let no_expiry = spend::plan(
        PlanInput {
            keys: &alice, version: Version::V6, expiry: None, chain: chain(), pool: pool(),
            request: Request::Consolidate { asset: felt::to_hex(&token) }, notes: &notes, companions: &[], required_inputs: None,
            spent: &[], tree: &tree,
        },
        &mut rng,
    );
    assert!(no_expiry.is_err());

    for (name, request) in [
        ("v6-transfer", Request::Transfer { asset: felt::to_hex(&token), amount: "600".into(), to: b_addr.encode().unwrap() }),
        ("v6-withdrawal", Request::Withdraw { asset: felt::to_hex(&token), amount: "1700".into(), recipient: "0xb0b".into() }),
    ] {
        let plan = plan_for(request, &mut rng).unwrap();
        assert_eq!(plan.version, Version::V6);
        assert_eq!(plan.valid_until, 125_000);
        // A V6 plan records its version and expiry; tampering with the expiry is refused.
        let mut bad = plan.clone();
        bad.valid_until = 0;
        assert!(spend::witness(&alice, &bad).is_err());
        // Proving checks the plan can still land (AB-SM4): not once the latest block passed it.
        let late = Expiry { latest_block: plan.valid_until, ..expiry(latest) };
        assert_eq!(spend::prove_plan(&alice, &plan, Some(&late), &mut rng).unwrap_err().code, "stale_plan");
        assert!(spend::prove_plan(&alice, &plan, None, &mut rng).is_err(), "a V6 plan needs the pool's rules");
        let proved = spend::prove_plan(&alice, &plan, Some(&expiry(latest + 50)), &mut rng).unwrap();
        let Statement::V6(p) = &proved.statement else { panic!("a V6 statement") };
        assert_eq!(p.valid_until, 125_000);
        assert_eq!(proved.version, Version::V6);
        let ciphertexts = [plan.outputs[0].ciphertext.clone(), plan.outputs[1].ciphertext.clone()];
        check_calldata(p, &proved, &ciphertexts);
        // A full withdrawal (both outputs zero-value) can reveal its openings instead of a ticket;
        // each opening recomputes its output's commitment with the asset and amount 0.
        let openings = spend::free_withdrawal_openings(&plan).unwrap();
        assert_eq!(openings.is_some(), name == "v6-withdrawal");
        if let Some(o) = openings {
            for k in 0..2 {
                assert_eq!(note::commitment_of_inner(&chain(), &pool(), &token, 0, &o[k]).unwrap(), p.commitments[k]);
            }
            save_free(name, &proved, &o);
        }
        // The server's statement JSON has no account and carries valid_until exactly.
        let json = serde_json::to_string(&proved.statement).unwrap();
        assert!(!json.contains("account") && json.contains("\"valid_until\":125000"));
        // The same plan proved as V5 (a zero account) gives the same binding and calldata.
        let mut v5 = plan.clone();
        v5.version = Version::V5;
        let p5 = spend::prove_plan(&alice, &v5, Some(&expiry(latest + 50)), &mut rng).unwrap();
        assert_eq!((p5.binding.clone(), p5.calldata.clone()), (proved.binding.clone(), proved.calldata.clone()));
        assert_eq!(p5.nullifiers, proved.nullifiers);
        save(name, &proved);
    }
}
