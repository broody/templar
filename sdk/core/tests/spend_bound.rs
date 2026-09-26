//! Bound-wallet spends (product 1, `docs/account-bound-note-spec.md` §3, §6): a deposit to a bound
//! address, scanning, and R0 V5 bound spends planned and proved; the statement names the account,
//! the companion is bound to it, a bound wallet cannot spend an ordinary note, and the spend
//! message is built from the statement. Writes the proofs to `$TEMPLAR_SDK_OUT` when set.
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use templar_core::address::Address;
use templar_core::felt::{self, Felt32};
use templar_core::keys::{BoundSeed, BoundWallet, Seed};
use templar_core::scan::{self, Context, Published, ScanKey};
use templar_core::snip12::{self, SpendMessage};
use templar_core::pool::{KNOWN_V4_POOLS, PoolRef};
use templar_core::spend::{self, Expiry, KeySource, NoteRef, PlanInput, Request, Statement, Version};
use templar_core::tree::Tree;
use templar_core::{note, random_digest, sealbox};

fn chain() -> Felt32 {
    felt::from_short_string("SN_SEPOLIA").unwrap()
}
fn pool() -> Felt32 {
    felt::parse("0x7e57b301").unwrap()
}
fn account() -> Felt32 {
    felt::parse("0x7e57b3c0").unwrap()
}

fn deposit(to: &Address, asset: &Felt32, amount: u128, index: u64, rng: &mut ChaCha20Rng) -> Published {
    let rho = random_digest(rng);
    let sealed = sealbox::seal(&to.pk, &note::m301(asset, &to.receiver, &rho, amount), rng).unwrap();
    let words = sealbox::to_words(&sealed).unwrap();
    let cm = note::commitment(&to.chain, &to.pool, asset, amount, &to.receiver, &rho).unwrap();
    Published { index, commitment: cm, digest: sealbox::delivery(&words), words: words.to_vec() }
}

fn v5() -> PoolRef {
    PoolRef::new(chain(), pool(), Version::V5).unwrap()
}

fn notes_of(w: &dyn KeySource, published: &[Published]) -> Vec<NoteRef> {
    let a = w.account(&v5(), 0).unwrap();
    let registry = Default::default();
    let ctx = Context { chain: chain(), pool: pool(), registry: &registry, registry_complete: true, settlements: &[] };
    let keys = vec![ScanKey { index: 0, receiver: a.receiver, ivk: a.ivk, nk: Some(a.nk) }];
    scan::scan(&ctx, &keys, published)
        .unwrap()
        .owned
        .iter()
        .map(|o| NoteRef { index: o.index, account: o.account, asset: felt::to_hex(&o.asset), amount: o.amount.to_string(), rho: o.rho, commitment: o.commitment })
        .collect()
}

fn save(name: &str, proved: &spend::Proved) {
    if let Ok(dir) = std::env::var("TEMPLAR_SDK_OUT") {
        let d = format!("{dir}/{name}");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(format!("{d}/cairo-arguments.json"), serde_json::to_vec(&proved.proof).unwrap()).unwrap();
        std::fs::write(format!("{d}/public.json"), serde_json::to_vec_pretty(&proved.statement).unwrap()).unwrap();
        std::fs::write(format!("{d}/binding.txt"), &proved.binding).unwrap();
        // The prover server's job body (spec §9): proof, statement, the pool call that settles it.
        let body = serde_json::json!({
            "relation": "r5", "proof": proved.proof, "statement": proved.statement,
            "pool_call": {"entry_point": "apply_spend", "calldata": proved.calldata},        "salt": "0x5a17", "signature": ["0x1", "0x2"],
        });
        std::fs::write(format!("{d}/submission.json"), serde_json::to_vec(&body).unwrap()).unwrap();
    }
}

#[test]
fn bound_wallet_deposits_scans_and_spends() {
    let mut rng = ChaCha20Rng::seed_from_u64(77);
    let w: BoundWallet = BoundSeed::generate(&mut rng).wallet(&account()).unwrap();
    let k = w.keys(&v5(), 0).unwrap();
    // No bound keys (so no address, no deposit) on a pool that settles R0 V4 (AB-SM1).
    assert_eq!(w.keys(&PoolRef::new(chain(), pool(), Version::V4).unwrap(), 0).err().expect("refused").code, "wrong_relation");
    assert!(PoolRef::new(chain(), felt::parse(KNOWN_V4_POOLS[0].1).unwrap(), Version::V5).is_err());
    let addr = Address::of(&chain(), &pool(), &k);
    let token = felt::parse("0x7e57b3a1").unwrap();
    // A bound note, and an ordinary note from a Templar wallet at the same pool.
    let templar = Seed::from_bytes(&[0x33; 32]).unwrap();
    let t_addr = Address::of(&chain(), &pool(), &templar.account(&chain(), &pool(), 0).unwrap());
    let mut tree = Tree::new();
    let mut published = vec![];
    for (to, amount) in [(&addr, 1000u128), (&t_addr, 500)] {
        let d = deposit(to, &token, amount, tree.len(), &mut rng);
        tree.append(&[d.commitment]).unwrap();
        published.push(d);
    }
    let bound_notes = notes_of(&w, &published);
    assert_eq!(bound_notes.iter().map(|n| n.amount.as_str()).collect::<Vec<_>>(), vec!["1000"]);
    let ordinary_notes = notes_of(&templar, &published);
    assert_eq!(ordinary_notes.len(), 1);
    let expiry = Expiry { latest_block: 5000, window: 1500, quantum: 100 };
    let plan_with = |keys: &dyn KeySource, version, notes: &[NoteRef], request, rng: &mut ChaCha20Rng| {
        spend::plan(
            PlanInput {
                keys, version, expiry: Some(expiry), chain: chain(), pool: pool(), request, notes, companions: &[],
                required_inputs: None, spent: &[], tree: &tree,
            },
            rng,
        )
    };
    let withdraw = |amount: &str| Request::Withdraw { asset: felt::to_hex(&token), amount: amount.into(), recipient: "0xb0b".into() };
    // A bound wallet spends only with R0 V5, and never an ordinary note.
    assert!(plan_with(&w, Version::V4, &bound_notes, withdraw("400"), &mut rng).is_err());
    let err = plan_with(&w, Version::V5, &ordinary_notes, withdraw("400"), &mut rng).unwrap_err();
    assert_eq!(err.code, "not_ours");
    // Nor can the Templar wallet spend the bound note.
    assert_eq!(plan_with(&templar, Version::V5, &bound_notes, withdraw("400"), &mut rng).unwrap_err().code, "not_ours");

    let plan = plan_with(&w, Version::V5, &bound_notes, withdraw("400"), &mut rng).unwrap();
    assert_eq!(plan.bound_account, felt::to_hex(&account()));
    assert_eq!(plan.valid_until, 6500);
    // A plan made for this account cannot be proved under the Templar wallet's keys.
    assert!(spend::witness(&templar, &plan).is_err());
    let proved = spend::prove_plan(&w, &plan, Some(&expiry), &mut rng).unwrap();
    let Statement::V5(p) = &proved.statement else { panic!("a V5 statement") };
    assert_eq!(felt::parse(&p.account).unwrap(), account());
    assert_eq!(p.valid_until, 6500);
    // The companion is a dummy input bound to the same account (spec §6.2, AB-M14).
    let companion = plan.companion.as_ref().expect("single input");
    let cnf = companion.nullifier(&chain(), &pool(), &token, &account()).unwrap();
    assert!(proved.nullifiers.contains(&cnf));
    assert!(!proved.nullifiers.contains(&companion.nullifier(&chain(), &pool(), &token, &[0; 32]).unwrap()));
    // The change goes back to a bound receiver of the same account.
    let change = plan.outputs.iter().find(|o| o.amount == "600").expect("change");
    assert_eq!(change.receiver, k.receiver);
    // The spend message: every field from the statement, the salt from the core.
    let salt = snip12::random_salt(&mut rng);
    let binding = felt::parse(&proved.binding).unwrap();
    let m = SpendMessage::of(p, &salt).unwrap();
    // The message binds the statement's own binding (AB-SM2).
    assert_eq!(m.binding, binding);
    assert_eq!(m.account, account());
    assert_eq!(m.withdrawal_amount, 400);
    let td = m.typed_data().unwrap();
    assert_eq!(td["message"]["withdrawal_amount"], "400");
    assert_eq!(td["message"]["binding_commitment"], felt::to_hex(&snip12::binding_commitment(&binding, &salt)));
    assert_ne!(m.hash().unwrap(), SpendMessage::of(p, &snip12::random_salt(&mut rng)).unwrap().hash().unwrap());
    assert!(SpendMessage::of(p, &[0; 32]).is_err(), "a zero salt");
    let mut wrong = p.clone();
    wrong.valid_until = 0;
    assert!(SpendMessage::of(&wrong, &salt).is_err(), "a statement the bridge rejects");
    save("bound-withdrawal", &proved);

    // A bound in-pool transfer to a Templar wallet's address.
    let plan = plan_with(&w, Version::V5, &bound_notes, Request::Transfer { asset: felt::to_hex(&token), amount: "250".into(), to: t_addr.encode().unwrap() }, &mut rng).unwrap();
    let proved = spend::prove_plan(&w, &plan, Some(&expiry), &mut rng).unwrap();
    let Statement::V5(p) = &proved.statement else { panic!("a V5 statement") };
    assert_eq!(p.token_out, "0x0");
    assert!(SpendMessage::of(p, &salt).is_ok());
    save("bound-transfer", &proved);
}
