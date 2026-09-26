//! R0 V5 spends for pool V3 (`docs/account-bound-note-spec.md` §4, §5.2, §8): the SDK's
//! `valid_until`, `TMR0_BIND_V5` against starknet.js's known answers, pool V3's calldata, and an
//! ordinary V5 transfer and withdrawal planned, proved and verified. Writes the proofs as bridge
//! inputs to `$TEMPLAR_SDK_OUT` when set, for the R5 bridge's standalone check.
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use templar_core::address::Address;
use templar_core::felt::{self, Felt32};
use templar_core::keys::Seed;
use templar_core::payment5::Public;
use templar_core::scan::{self, Context, Published, ScanKey};
use templar_core::spend::{self, Expiry, NoteRef, PlanInput, Request, Statement, Version};
use templar_core::tree::Tree;
use templar_core::{note, random_digest, sealbox};

const KAT: &str = include_str!("../../../bench/m31-private-wrapper/client-port/cairo-r5/kat/kat.json");

fn chain() -> Felt32 {
    felt::from_short_string("SN_SEPOLIA").unwrap()
}
fn pool() -> Felt32 {
    felt::parse("0x7e57b301").unwrap()
}
fn expiry(latest: u64) -> Expiry {
    Expiry { latest_block: latest, window: 1500, quantum: 100 }
}

#[test]
fn valid_until_follows_the_sdk_rule() {
    for (latest, want) in [(1000, 2500), (1001, 2600), (1099, 2600), (1100, 2600), (1101, 2700), (0, 1500)] {
        assert_eq!(spend::valid_until(&expiry(latest)).unwrap(), want, "latest {latest}");
    }
    // Always on the grid, at least E and at most E + Q − 1 ahead.
    for latest in 5000..5300 {
        let v = spend::valid_until(&expiry(latest)).unwrap();
        assert!(v.is_multiple_of(100) && v >= latest + 1500 && v < latest + 1600);
    }
    assert!(spend::valid_until(&Expiry { latest_block: 1, window: 1500, quantum: 0 }).is_err(), "Q = 0");
    assert!(spend::valid_until(&Expiry { latest_block: u64::MAX, window: 1500, quantum: 100 }).is_err(), "overflow");
    assert!(spend::valid_until(&Expiry { latest_block: 1 << 56, window: 1500, quantum: 100 }).is_err(), "above 2^56");
}

/// `TMR0_BIND_V5` equals starknet.js's for the four known-answer statements (which omit the
/// account: the binding never includes it).
#[test]
fn binding_matches_starknet_js() {
    let kat: serde_json::Value = serde_json::from_str(KAT).unwrap();
    let bindings = kat["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 4);
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
            intent: hex(&s["intent"]), identity: words(&s["identity"]), account: "0x0".into(),
            valid_until: int(&s["valid_until"]) as u64,
        };
        let want = felt::parse(b["binding"].as_str().unwrap()).unwrap();
        assert_eq!(spend::binding5(&p).unwrap(), want, "{}", b["name"]);
        // The account is not bound.
        let bound = Public { account: "0x123".into(), ..p };
        assert_eq!(spend::binding5(&bound).unwrap(), want);
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
            "relation": "r5", "proof": proved.proof, "statement": proved.statement,
            "pool_call": {"entry_point": "apply_spend", "calldata": proved.calldata},
        });
        std::fs::write(format!("{d}/submission.json"), serde_json::to_vec(&body).unwrap()).unwrap();
    }
}

fn save_free(name: &str, proved: &spend::Proved, openings: &[templar_core::Digest; 2]) {
    if let Ok(dir) = std::env::var("TEMPLAR_SDK_OUT") {
        let body = serde_json::json!({
            "relation": "r5", "proof": proved.proof, "statement": proved.statement,
            "pool_call": {"entry_point": "apply_spend", "calldata": proved.calldata},
            "payment": {"free_full_withdrawal": {"openings": openings}},
        });
        std::fs::create_dir_all(format!("{dir}/{name}")).unwrap();
        std::fs::write(format!("{dir}/{name}/free-submission.json"), serde_json::to_vec(&body).unwrap()).unwrap();
    }
}

/// Pool V3 calldata: V4's `Spend`, then `valid_until`, the binding and the empty proof span.
fn check_calldata(p: &Public, proved: &spend::Proved, ciphertexts: &[Vec<String>; 2]) {
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
fn ordinary_v5_transfer_and_withdrawal() {
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
                keys: &alice, version: Version::V5, expiry: Some(expiry(latest)), chain: chain(), pool: pool(), request,
                notes: &notes, companions: &[], required_inputs: None, spent: &[], tree: &tree,
            },
            rng,
        )
    };
    // A V5 spend needs the expiry inputs.
    let no_expiry = spend::plan(
        PlanInput {
            keys: &alice, version: Version::V5, expiry: None, chain: chain(), pool: pool(),
            request: Request::Consolidate { asset: felt::to_hex(&token) }, notes: &notes, companions: &[], required_inputs: None,
            spent: &[], tree: &tree,
        },
        &mut rng,
    );
    assert!(no_expiry.is_err());

    for (name, request) in [
        ("v5-transfer", Request::Transfer { asset: felt::to_hex(&token), amount: "600".into(), to: b_addr.encode().unwrap() }),
        ("v5-withdrawal", Request::Withdraw { asset: felt::to_hex(&token), amount: "1700".into(), recipient: "0xb0b".into() }),
    ] {
        let plan = plan_for(request, &mut rng).unwrap();
        assert_eq!(plan.version, Version::V5);
        assert_eq!(plan.valid_until, 125_000);
        assert_eq!(plan.bound_account, "0x0");
        // A V5 plan records its version and expiry; tampering either is refused.
        let mut bad = plan.clone();
        bad.valid_until = 0;
        assert!(spend::witness(&alice, &bad).is_err());
        let mut bad = plan.clone();
        bad.bound_account = "0x123".into();
        assert!(spend::witness(&alice, &bad).is_err());
        // Proving checks the plan can still land (AB-SM4): not once the latest block passed it.
        let late = Expiry { latest_block: plan.valid_until, ..expiry(latest) };
        assert_eq!(spend::prove_plan(&alice, &plan, Some(&late), &mut rng).unwrap_err().code, "stale_plan");
        assert!(spend::prove_plan(&alice, &plan, None, &mut rng).is_err(), "a V5 plan needs the pool's rules");
        let proved = spend::prove_plan(&alice, &plan, Some(&expiry(latest + 50)), &mut rng).unwrap();
        let Statement::V5(p) = &proved.statement else { panic!("a V5 statement") };
        assert_eq!(p.account, "0x0");
        assert_eq!(p.valid_until, 125_000);
        assert_eq!(felt::parse(&proved.binding).unwrap(), spend::binding5(p).unwrap());
        let ciphertexts = [plan.outputs[0].ciphertext.clone(), plan.outputs[1].ciphertext.clone()];
        check_calldata(p, &proved, &ciphertexts);
        // A full withdrawal (both outputs zero-value) can reveal its openings instead of a ticket;
        // each opening recomputes its output's commitment with the asset and amount 0.
        let openings = spend::free_withdrawal_openings(&plan).unwrap();
        assert_eq!(openings.is_some(), name == "v5-withdrawal");
        if let Some(o) = openings {
            for k in 0..2 {
                assert_eq!(note::commitment_of_inner(&chain(), &pool(), &token, 0, &o[k]).unwrap(), p.commitments[k]);
            }
            save_free(name, &proved, &o);
        }
        // The server's statement JSON carries both V5 fields, the amount as an exact integer.
        let json = serde_json::to_string(&proved.statement).unwrap();
        assert!(json.contains("\"account\":\"0x0\"") && json.contains("\"valid_until\":125000"));
        save(name, &proved);
    }
}
