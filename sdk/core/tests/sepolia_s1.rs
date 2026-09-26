//! Known answers from the Sepolia S1 hidden-asset spend (`bench/m31-sepolia/results/v4-hidden-asset`):
//! the core's binding, calldata, message hash and result checks reproduce what the bench produced
//! and the chain simulated.
use serde_json::Value;
use templar_core::result::{self, Pins, ServerResult};
use templar_core::spend;
use templar_client_verifier_circuit::payment4::Public;

const VECTOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/sepolia-s1.json");

fn vector() -> Value {
    serde_json::from_slice(&std::fs::read(VECTOR).unwrap()).unwrap()
}

fn norm(s: &str) -> String {
    let t = s.trim_start_matches("0x").trim_start_matches('0');
    format!("0x{}", if t.is_empty() { "0" } else { t })
}

#[test]
fn binding_calldata_and_result() {
    let v = vector();
    let public: Public = serde_json::from_value(v["public"].clone()).unwrap();
    let server = &v["server"];
    let binding = spend::binding(&public).unwrap();
    assert_eq!(templar_core::felt::to_hex(&binding), norm(server["binding"].as_str().unwrap()));

    // The ciphertexts are inside the bench calldata: after chain, pool, token, root span (10),
    // nullifier span (19) and the output count, each output is a 9-word span then a 10-word span.
    let bench: Vec<String> = v["calldata"].as_array().unwrap().iter().map(|x| norm(x.as_str().unwrap())).collect();
    let at = 3 + 10 + 19 + 1;
    let ct0: Vec<String> = bench[at + 10 + 1..at + 10 + 11].to_vec();
    let ct1: Vec<String> = bench[at + 21 + 10 + 1..at + 21 + 10 + 11].to_vec();
    let ours = spend::calldata(&public, &[ct0, ct1]).unwrap();
    assert_eq!(ours, bench, "calldata differs from the bench's");

    let r = ServerResult {
        proof: "AAAA".into(),
        proof_facts: server["facts"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect(),
        base_block: server["base_block"].as_u64().unwrap(),
        binding: server["binding"].as_str().unwrap().into(),
    };
    let p: Pins = serde_json::from_value(v["pins"].clone()).unwrap();
    assert_eq!(templar_core::felt::to_hex(&result::message_hash(&p, &binding).unwrap()), norm(server["message_hash"].as_str().unwrap()));
    let w = result::check(&p, server["binding"].as_str().unwrap(), &r, r.base_block + 20, None).unwrap();
    assert_eq!((w.submit_after, w.valid_until), (r.base_block + 11, r.base_block + 4096));
    // Every pinned fact is enforced.
    for i in [0usize, 1, 2, 3, 4, 6, 7, 8] {
        let mut bad = r.clone();
        bad.proof_facts[i] = "0x1234".into();
        assert!(result::check(&p, &r.binding, &bad, r.base_block + 20, None).is_err(), "fact {i}");
    }
    let mut short = r.clone();
    short.proof_facts.pop();
    assert!(result::check(&p, &r.binding, &short, r.base_block + 20, None).is_err());
    assert!(result::check(&p, &r.binding, &r, r.base_block - 1, None).is_err(), "base block in the future");
    let mut other = p.clone();
    other.statement_class = "0x1".into();
    assert!(result::check(&other, &r.binding, &r, r.base_block + 20, None).is_err(), "other class");
}
