//! Wallet commands for the Sepolia run (option A pool, R0 V2, single-permutation nodes). Every
//! value is JSON on stdout; digests are nine M31 words.
//!
//! - `wallet keys SK_JSON`: `{receiver, nk}` for a 9-word spending secret.
//! - `wallet inner RECEIVER_JSON RHO_JSON`: the note's `inner` hash (a deposit's argument).
//! - `wallet commitment CHAIN POOL TOKEN AMOUNT INNER_JSON`: the note commitment the pool computes.
//! - `wallet prove SPEND_JSON OUT [MAX_FRI_COLUMNS]`: an R0 proof for a spend described by
//!   `{chain, pool, token, leaves, inputs: [{sk, rho, amount, position}] x2,
//!     outputs: [{active, receiver, rho, amount, delivery}] x2, withdrawal: {recipient, amount}}`,
//!   with paths computed from `leaves` (the pool's commitments in order). Writes the Cairo
//!   arguments, public statement, trusted manifest and report, as `prove_payment_r0` does.
//! - `wallet policy-note POLICY_JSON CAP_JSON CHAIN POOL TOKEN AMOUNT`: a policy note's
//!   `{policy, pnk, receiver, policy_id, slots, rest}` (`docs/policy-note-spec.md`).
//! - `wallet prove-policy SPEND_JSON OUT [MAX_FRI_COLUMNS]`: a P1 proof settling a policy note,
//!   `{chain, pool, token, leaves, note: {cap, rho, amount, position}, policy, index, x, data}`.
//! - `wallet policy-digest HEADER REFUND REST CAP CHAIN POOL TOKEN AMOUNT RHO`: a note rebuilt from
//!   seed recovery (header, refund outcome, `orest`): `{policy, receiver, commitment, policy_id}`.
//! - `wallet prove-refund SPEND_JSON OUT [MAX_FRI_COLUMNS]`: a P1 refund (outcome 0) from
//!   `{chain, pool, token, leaves, note, header, refund, rest, data}`, without the other outcomes.
//! - `wallet root LEAVES_JSON`: the pool's tree root over `leaves` in order.
//! - `wallet prove4 SPEND_JSON OUT [MAX_FRI_COLUMNS]`: an R0 V4 proof (`docs/hidden-asset-spec.md`
//!   §4) for `{chain, pool, token (the asset), leaves, inputs: [{sk, rho, amount, position}] x1
//!   or x2, outputs: [{receiver, rho, amount, delivery}] x2, withdrawal, intent?,
//!   identity_scope?}`. With one input, input 1 is a dummy drawn fresh from the OS CSPRNG for this
//!   proof (spec §6); outputs of amount zero are dummies the caller built.
//! - `wallet keys5 SK_JSON ACCOUNT`: `{receiver, nk, ak}` of an R0 V5 key bound to `ACCOUNT` (`0x0`:
//!   an ordinary key, as `keys`) (`docs/account-bound-note-spec.md` §3.2).
//! - `wallet prove5 SPEND_JSON OUT [MAX_FRI_COLUMNS]`: an R0 V5 proof (spec §4): `prove4`'s spend
//!   plus `account` (`0x0` for an ordinary spend; both inputs are bound to it) and `valid_until`.
use std::{fs, path::Path, time::Instant};
#[path = "support/mod.rs"]
mod support;
use serde::Deserialize;
use serde_json::json;
use templar_client_verifier_circuit::payment::{
    self, Digest, INNER, Identity, Input, NOTE, Output, Private, Public, Tree, amount_limbs, felt_limbs, h, receiver_of,
    tree_paths,
};
use templar_client_verifier_circuit::{payment4, payment5, payment6, policy, prove};

const TREE: Tree = Tree::Compress;

#[derive(Deserialize)]
struct SpendIn {
    sk: Digest,
    rho: Digest,
    amount: String,
    position: u32,
}
#[derive(Deserialize)]
struct SpendOut {
    active: bool,
    receiver: Digest,
    rho: Digest,
    amount: String,
    delivery: String,
}
#[derive(Deserialize)]
struct WithdrawalIn {
    recipient: String,
    amount: String,
}
#[derive(Deserialize)]
struct SpendJson {
    chain: String,
    pool: String,
    token: String,
    leaves: Vec<Digest>,
    inputs: [SpendIn; 2],
    outputs: [SpendOut; 2],
    withdrawal: WithdrawalIn,
    /// V3: the open-note execution intent (a felt; `0x0` for none).
    #[serde(default = "no_intent")]
    intent: String,
    /// V3: the shadow-account identity scope, when the spend publishes an identity handle.
    #[serde(default)]
    identity_scope: Option<Digest>,
}

fn no_intent() -> String {
    "0x0".into()
}

/// The relation a proof is for: an R0 spend, an R0 V4 or V5 spend, or a P1 policy settlement.
enum Relation {
    R0(Public, Private),
    R4(payment4::Public, payment4::Private),
    R5(payment5::Public, payment5::Private),
    R6(payment6::Public, payment6::Private),
    P1(policy::Public, policy::Private),
}

impl Relation {
    fn purpose(&self) -> &'static str {
        match self {
            Relation::R0(..) => "tmpzr0-client-payment",
            Relation::R4(..) => "tmpzr4-client-payment",
            Relation::R5(..) => "tmpzr5-client-payment",
            Relation::R6(..) => "tmpzr6-client-payment",
            Relation::P1(..) => "tmpzp1-client-policy",
        }
    }

    fn statement_tag(&self) -> [u32; 2] {
        match self {
            Relation::R0(..) => payment::statement_tag(TREE),
            Relation::R4(..) => payment4::statement_tag(TREE),
            Relation::R5(..) => payment5::statement_tag(TREE),
            Relation::R6(..) => payment6::statement_tag(TREE),
            Relation::P1(..) => policy::statement_tag(TREE),
        }
    }

    fn public_json(&self) -> Vec<u8> {
        match self {
            Relation::R0(p, _) => serde_json::to_vec_pretty(p).unwrap(),
            Relation::R4(p, _) => serde_json::to_vec_pretty(p).unwrap(),
            Relation::R5(p, _) => serde_json::to_vec_pretty(p).unwrap(),
            Relation::R6(p, _) => serde_json::to_vec_pretty(p).unwrap(),
            Relation::P1(p, _) => serde_json::to_vec_pretty(p).unwrap(),
        }
    }
}

fn prove(spec: SpendJson, out: &Path, max_fri_columns: Option<usize>) {
    fs::create_dir_all(out).unwrap();
    let u128_of = |s: &str| s.parse::<u128>().expect("decimal u128");
    let positions = [spec.inputs[0].position, spec.inputs[1].position];
    let (root, paths) = tree_paths(TREE, &spec.leaves, &positions);
    let private = Private {
        inputs: std::array::from_fn(|i| Input {
            sk: spec.inputs[i].sk,
            rho: spec.inputs[i].rho,
            amount: u128_of(&spec.inputs[i].amount),
            position: positions[i],
            siblings: paths[i].clone(),
        }),
        outputs: std::array::from_fn(|j| Output {
            active: spec.outputs[j].active,
            receiver: spec.outputs[j].receiver,
            rho: spec.outputs[j].rho,
            amount: u128_of(&spec.outputs[j].amount),
        }),
        identity: Identity { active: spec.identity_scope.is_some(), scope: spec.identity_scope.unwrap_or([0; 9]) },
    };
    let deliveries = [spec.outputs[0].delivery.clone(), spec.outputs[1].delivery.clone()];
    let public = payment::statement(
        TREE, &spec.chain, &spec.pool, &spec.token, deliveries,
        (spec.withdrawal.recipient.clone(), u128_of(&spec.withdrawal.amount)), &spec.intent, &private,
    )
    .unwrap_or_else(|e| panic!("invalid spend: {e}"));
    assert_eq!(public.root, root);
    prove_relation(Relation::R0(public, private), out, max_fri_columns);
}

#[derive(Deserialize)]
struct SpendOut4 {
    receiver: Digest,
    rho: Digest,
    amount: String,
    delivery: String,
}
#[derive(Deserialize)]
struct SpendJson4 {
    chain: String,
    pool: String,
    token: String,
    leaves: Vec<Digest>,
    inputs: Vec<SpendIn>,
    outputs: [SpendOut4; 2],
    withdrawal: WithdrawalIn,
    #[serde(default = "no_intent")]
    intent: String,
    #[serde(default)]
    identity_scope: Option<Digest>,
}

/// Nine canonical M31 words from the OS CSPRNG, not all zero.
fn fresh_digest() -> Digest {
    use rand::Rng;
    loop {
        let d: Digest = std::array::from_fn(|_| rand::rngs::OsRng.gen_range(0..payment::P));
        if d.iter().any(|w| *w != 0) {
            return d;
        }
    }
}

fn prove4(spec: SpendJson4, out: &Path, max_fri_columns: Option<usize>) {
    fs::create_dir_all(out).unwrap();
    let u128_of = |s: &str| s.parse::<u128>().expect("decimal u128");
    assert!(spec.inputs.len() == 1 || spec.inputs.len() == 2, "one or two inputs");
    let positions: Vec<u32> = spec.inputs.iter().map(|i| i.position).collect();
    let (root, paths) = tree_paths(TREE, &spec.leaves, &positions);
    let mut inputs: Vec<Input> = spec
        .inputs
        .iter()
        .zip(paths)
        .map(|(i, siblings)| Input { sk: i.sk, rho: i.rho, amount: u128_of(&i.amount), position: i.position, siblings })
        .collect();
    let dummy = inputs.len() == 1;
    if dummy {
        // Fresh for every proof, never derived from the seed (spec §6, HA-M6).
        let position = rand::RngCore::next_u32(&mut rand::rngs::OsRng);
        let siblings = (0..payment::DEPTH).map(|_| fresh_digest()).collect();
        inputs.push(Input { sk: fresh_digest(), rho: fresh_digest(), amount: 0, position, siblings });
    }
    let private = payment4::Private {
        token: spec.token.clone(),
        inputs: [inputs[0].clone(), inputs[1].clone()],
        dummy,
        outputs: std::array::from_fn(|j| payment4::Output {
            receiver: spec.outputs[j].receiver,
            rho: spec.outputs[j].rho,
            amount: u128_of(&spec.outputs[j].amount),
        }),
        identity: Identity { active: spec.identity_scope.is_some(), scope: spec.identity_scope.unwrap_or([0; 9]) },
    };
    let deliveries = [spec.outputs[0].delivery.clone(), spec.outputs[1].delivery.clone()];
    let public = payment4::statement(
        TREE, &spec.chain, &spec.pool, deliveries,
        (spec.withdrawal.recipient.clone(), u128_of(&spec.withdrawal.amount)), &spec.intent, &private,
    )
    .unwrap_or_else(|e| panic!("invalid spend: {e}"));
    payment4::bridge_checks(&public).unwrap_or_else(|e| panic!("the bridge would reject: {e}"));
    assert_eq!(public.root, root);
    prove_relation(Relation::R4(public, private), out, max_fri_columns);
}

#[derive(Deserialize)]
struct SpendJson5 {
    #[serde(flatten)]
    v4: SpendJson4,
    /// The account both inputs are bound to, `0x0` for an ordinary spend.
    #[serde(default = "no_intent")]
    account: String,
    valid_until: u64,
}

/// `prove4` for R0 V5: the inputs' receivers are bound to `account`, and `valid_until` is public.
fn prove5(spec: SpendJson5, out: &Path, max_fri_columns: Option<usize>) {
    fs::create_dir_all(out).unwrap();
    let SpendJson5 { v4: spec, account, valid_until } = spec;
    let u128_of = |s: &str| s.parse::<u128>().expect("decimal u128");
    assert!(spec.inputs.len() == 1 || spec.inputs.len() == 2, "one or two inputs");
    let positions: Vec<u32> = spec.inputs.iter().map(|i| i.position).collect();
    let (root, paths) = tree_paths(TREE, &spec.leaves, &positions);
    let mut inputs: Vec<Input> = spec
        .inputs
        .iter()
        .zip(paths)
        .map(|(i, siblings)| Input { sk: i.sk, rho: i.rho, amount: u128_of(&i.amount), position: i.position, siblings })
        .collect();
    let dummy = inputs.len() == 1;
    if dummy {
        let position = rand::RngCore::next_u32(&mut rand::rngs::OsRng);
        let siblings = (0..payment::DEPTH).map(|_| fresh_digest()).collect();
        inputs.push(Input { sk: fresh_digest(), rho: fresh_digest(), amount: 0, position, siblings });
    }
    let private = payment5::Private {
        token: spec.token.clone(),
        account,
        inputs: [inputs[0].clone(), inputs[1].clone()],
        dummy,
        outputs: std::array::from_fn(|j| payment4::Output {
            receiver: spec.outputs[j].receiver,
            rho: spec.outputs[j].rho,
            amount: u128_of(&spec.outputs[j].amount),
        }),
        identity: Identity { active: spec.identity_scope.is_some(), scope: spec.identity_scope.unwrap_or([0; 9]) },
    };
    let deliveries = [spec.outputs[0].delivery.clone(), spec.outputs[1].delivery.clone()];
    let public = payment5::statement(
        TREE, &spec.chain, &spec.pool, deliveries,
        (spec.withdrawal.recipient.clone(), u128_of(&spec.withdrawal.amount)), &spec.intent, valid_until, &private,
    )
    .unwrap_or_else(|e| panic!("invalid spend: {e}"));
    payment5::bridge_checks(&public).unwrap_or_else(|e| panic!("the bridge would reject: {e}"));
    assert_eq!(public.root, root);
    prove_relation(Relation::R5(public, private), out, max_fri_columns);
}

#[derive(Deserialize)]
struct SpendJson6 {
    #[serde(flatten)]
    v4: SpendJson4,
    valid_until: u64,
}

/// An R0 V6 spend (`docs/pool-v3-spec.md` §4): ordinary notes, a public expiry, no account.
fn prove6(spec: SpendJson6, out: &Path, max_fri_columns: Option<usize>) {
    fs::create_dir_all(out).unwrap();
    let SpendJson6 { v4: spec, valid_until } = spec;
    let u128_of = |s: &str| s.parse::<u128>().expect("decimal u128");
    assert!(spec.inputs.len() == 1 || spec.inputs.len() == 2, "one or two inputs");
    let positions: Vec<u32> = spec.inputs.iter().map(|i| i.position).collect();
    let (root, paths) = tree_paths(TREE, &spec.leaves, &positions);
    let mut inputs: Vec<Input> = spec
        .inputs
        .iter()
        .zip(paths)
        .map(|(i, siblings)| Input { sk: i.sk, rho: i.rho, amount: u128_of(&i.amount), position: i.position, siblings })
        .collect();
    let dummy = inputs.len() == 1;
    if dummy {
        let position = rand::RngCore::next_u32(&mut rand::rngs::OsRng);
        let siblings = (0..payment::DEPTH).map(|_| fresh_digest()).collect();
        inputs.push(Input { sk: fresh_digest(), rho: fresh_digest(), amount: 0, position, siblings });
    }
    let private = payment6::Private {
        token: spec.token.clone(),
        inputs: [inputs[0].clone(), inputs[1].clone()],
        dummy,
        outputs: std::array::from_fn(|j| payment4::Output {
            receiver: spec.outputs[j].receiver,
            rho: spec.outputs[j].rho,
            amount: u128_of(&spec.outputs[j].amount),
        }),
        identity: Identity { active: spec.identity_scope.is_some(), scope: spec.identity_scope.unwrap_or([0; 9]) },
    };
    let deliveries = [spec.outputs[0].delivery.clone(), spec.outputs[1].delivery.clone()];
    let public = payment6::statement(
        TREE, &spec.chain, &spec.pool, deliveries,
        (spec.withdrawal.recipient.clone(), u128_of(&spec.withdrawal.amount)), &spec.intent, valid_until, &private,
    )
    .unwrap_or_else(|e| panic!("invalid spend: {e}"));
    payment6::bridge_checks(&public).unwrap_or_else(|e| panic!("the bridge would reject: {e}"));
    assert_eq!(public.root, root);
    prove_relation(Relation::R6(public, private), out, max_fri_columns);
}

#[derive(Deserialize)]
struct PolicyNoteIn {
    cap: Digest,
    rho: Digest,
    amount: String,
    position: u32,
}

#[derive(Deserialize)]
struct PolicySpendJson {
    chain: String,
    pool: String,
    token: String,
    leaves: Vec<Digest>,
    note: PolicyNoteIn,
    policy: policy::Policy,
    index: u8,
    x: String,
    data: String,
}

fn prove_policy(spec: PolicySpendJson, out: &Path, max_fri_columns: Option<usize>) {
    fs::create_dir_all(out).unwrap();
    let u128_of = |s: &str| s.parse::<u128>().expect("decimal u128");
    let (root, paths) = tree_paths(TREE, &spec.leaves, &[spec.note.position]);
    let amount = u128_of(&spec.note.amount);
    let private = policy::private_for(&spec.policy, spec.index, spec.note.cap, spec.note.rho, amount, spec.note.position, paths[0].clone());
    let public = policy::statement(TREE, &spec.chain, &spec.pool, &spec.token, u128_of(&spec.x), &spec.data, &private)
        .unwrap_or_else(|e| panic!("invalid policy spend: {e}"));
    assert_eq!(public.root, root, "the note is not at that position");
    prove_relation(Relation::P1(public, private), out, max_fri_columns);
}

#[derive(Deserialize)]
struct RefundSpendJson {
    chain: String,
    pool: String,
    token: String,
    leaves: Vec<Digest>,
    note: PolicyNoteIn,
    header: policy::Header,
    refund: policy::Outcome,
    rest: Digest,
    data: String,
}

fn prove_refund(spec: RefundSpendJson, out: &Path, max_fri_columns: Option<usize>) {
    fs::create_dir_all(out).unwrap();
    let (root, paths) = tree_paths(TREE, &spec.leaves, &[spec.note.position]);
    let amount: u128 = spec.note.amount.parse().expect("decimal u128");
    // Only the refund's preimage and `orest` are needed: the other slots feed a hash the selector
    // discards for index 0.
    let private = policy::Private {
        cap: spec.note.cap,
        rho: spec.note.rho,
        amount,
        position: spec.note.position,
        siblings: paths[0].clone(),
        header: spec.header,
        index: 0,
        selected: spec.refund.clone(),
        slots: [policy::outcome_digest(&spec.refund), [0; 9], [0; 9], [0; 9]],
        rest: spec.rest,
    };
    let public = policy::statement(TREE, &spec.chain, &spec.pool, &spec.token, 0, &spec.data, &private)
        .unwrap_or_else(|e| panic!("invalid refund: {e}"));
    assert_eq!(public.root, root, "the note is not at that position");
    prove_relation(Relation::P1(public, private), out, max_fri_columns);
}

fn prove_relation(rel: Relation, out: &Path, max_fri_columns: Option<usize>) {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let started = Instant::now();
    // The library prover (`prove::prove`): blinding budget, proof, hiding-budget check and native
    // verification, the same path the SDK runs.
    let proved = match &rel {
        Relation::R0(p, w) => prove::prove(&prove::R0(p, w), seed, max_fri_columns),
        Relation::R4(p, w) => prove::prove(&prove::R4(p, w), seed, max_fri_columns),
        Relation::R5(p, w) => prove::prove(&prove::R5(p, w), seed, max_fri_columns),
        Relation::R6(p, w) => prove::prove(&prove::R6(p, w), seed, max_fri_columns),
        Relation::P1(p, w) => prove::prove(&prove::P1(p, w), seed, max_fri_columns),
    };
    let mut proved = proved.unwrap_or_else(|e| panic!("{e}"));
    let proving_seconds = started.elapsed().as_secs_f64();
    let negatives = support::negatives(&mut proved.proof, &proved.pp, proved.pp_root, &proved.wanted);
    support::write(&out.join("trusted-config.json"), &support::manifest(
        rel.purpose(), &proved.pp, &proved.cfg, proved.pp_root, proved.circuit_hash,
        json!({
            "stack": "broody/proving templar/arithmetic-profile (on starkware-libs/proving@5a7c5ed), arithmetic profile, bridge FRI",
            "statement_tag_u32": rel.statement_tag(),
            "blinding_rows": proved.blinding,
            "tree_nodes": "Compress",
        }),
    ));
    let (trace_log_size, blinding, revealed) = (proved.pp.trace_log_size(), proved.blinding, proved.revealed);
    let arguments = prove::cairo_arguments(proved);
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    fs::write(out.join("public.json"), rel.public_json()).unwrap();
    let report = json!({
        "scope": format!("{} wallet proof (Tree::Compress)", rel.purpose()),
        "trace_log_size": trace_log_size,
        "blinding_rows": blinding,
        "revealed_fri_values": revealed,
        "proving_seconds": proving_seconds,
        "proof_felts": arguments.len() - 1,
        "native_negatives": negatives,
    });
    support::write(&out.join("report.json"), &report);
    println!("{report}");
}

fn digest(arg: &str) -> Digest {
    serde_json::from_str(arg).expect("digest JSON: nine words")
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keys") => {
            let (receiver, nk) = receiver_of(&digest(&a[2]));
            println!("{}", json!({"receiver": receiver, "nk": nk}));
        }
        Some("inner") => {
            println!("{}", json!(h(INNER, 0, &[digest(&a[2]), digest(&a[3])].concat())));
        }
        Some("commitment") => {
            let context = [felt_limbs(&a[2]), felt_limbs(&a[3]), felt_limbs(&a[4])].concat();
            let amount: u128 = a[5].parse().unwrap();
            let cm = h(NOTE, 0, &[context, amount_limbs(amount).to_vec(), digest(&a[6]).to_vec()].concat());
            println!("{}", json!(cm));
        }
        Some("prove") => {
            let spec: SpendJson = serde_json::from_slice(&fs::read(&a[2]).unwrap()).unwrap();
            prove(spec, Path::new(&a[3]), a.get(4).map(|n| n.parse().unwrap()));
        }
        Some("policy-note") => {
            let pol: policy::Policy = serde_json::from_str(&a[2]).expect("policy JSON");
            let cap = digest(&a[3]);
            let d = pol.digest();
            let amount: u128 = a[7].parse().unwrap();
            println!("{}", json!({
                "policy": d,
                "pnk": policy::pnk_of(&cap),
                "receiver": policy::receiver(&cap, &d),
                "policy_id": policy::policy_id(&a[4], &a[5], &a[6], amount, &d),
                "slots": pol.slots(),
                "rest": pol.rest(),
            }));
        }
        Some("policy-digest") => {
            let header: policy::Header = serde_json::from_str(&a[2]).expect("header JSON");
            let refund: policy::Outcome = serde_json::from_str(&a[3]).expect("outcome JSON");
            let rest = digest(&a[4]);
            let cap = digest(&a[5]);
            let amount: u128 = a[9].parse().unwrap();
            let d = policy::policy_digest(&header, &policy::outcome_digest(&refund), &rest);
            let receiver = policy::receiver(&cap, &d);
            let context = [felt_limbs(&a[6]), felt_limbs(&a[7]), felt_limbs(&a[8])].concat();
            let cm = payment::commitment(&context, amount, &receiver, &digest(&a[10]));
            println!("{}", json!({
                "policy": d, "receiver": receiver, "commitment": cm,
                "policy_id": policy::policy_id(&a[6], &a[7], &a[8], amount, &d),
            }));
        }
        Some("prove-refund") => {
            let spec: RefundSpendJson = serde_json::from_slice(&fs::read(&a[2]).unwrap()).unwrap();
            prove_refund(spec, Path::new(&a[3]), a.get(4).map(|n| n.parse().unwrap()));
        }
        Some("root") => {
            let leaves: Vec<Digest> = serde_json::from_str(&a[2]).expect("leaves JSON");
            println!("{}", json!(tree_paths(TREE, &leaves, &[]).0));
        }
        Some("prove4") => {
            let spec: SpendJson4 = serde_json::from_slice(&fs::read(&a[2]).unwrap()).unwrap();
            prove4(spec, Path::new(&a[3]), a.get(4).map(|n| n.parse().unwrap()));
        }
        Some("keys5") => {
            let (account, sk) = (felt_limbs(&a[3]), digest(&a[2]));
            let (receiver, nk) = payment5::receiver_of(&account, &sk);
            println!("{}", json!({"receiver": receiver, "nk": nk, "ak": payment5::ak_of(&account, &sk)}));
        }
        Some("prove5") => {
            let spec: SpendJson5 = serde_json::from_slice(&fs::read(&a[2]).unwrap()).unwrap();
            prove5(spec, Path::new(&a[3]), a.get(4).map(|n| n.parse().unwrap()));
        }
        Some("prove6") => {
            let spec: SpendJson6 = serde_json::from_slice(&fs::read(&a[2]).unwrap()).unwrap();
            prove6(spec, Path::new(&a[3]), a.get(4).map(|n| n.parse().unwrap()));
        }
        Some("prove-policy") => {
            let spec: PolicySpendJson = serde_json::from_slice(&fs::read(&a[2]).unwrap()).unwrap();
            prove_policy(spec, Path::new(&a[3]), a.get(4).map(|n| n.parse().unwrap()));
        }
        _ => panic!("wallet keys|keys5|inner|commitment|prove|prove4|prove5|prove6|policy-note|prove-policy ..."),
    }
}
