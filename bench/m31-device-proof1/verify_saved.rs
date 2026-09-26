use std::{fs, sync::Arc, time::Instant};
use starknet_api::transaction::fields::{Proof, ProofFacts};
use starknet_proof_verifier::verify_proof;
fn main() {
    let root = std::env::args().nth(1).expect("results directory");
    let data = fs::read(format!("{root}/proof.bin")).unwrap();
    let facts: ProofFacts = ProofFacts(Arc::new( fs::read_to_string(format!("{root}/proof-facts.txt")).unwrap()
        .trim().split(',').map(|s| s.parse().unwrap()).collect()));
    let start = Instant::now();
    verify_proof(facts.clone(), Proof::from(data.clone())).expect("valid proof rejected");
    println!("valid proof: PASS; verification_ms={}", start.elapsed().as_millis());
    for (name,index) in [("changed message digest",facts.0.len()-1),("changed program hash",2)] {
        let mut changed = facts.0.to_vec(); let x = changed[index]; changed[index] += x;
        let result = verify_proof(ProofFacts(Arc::new(changed)), Proof::from(data.clone()));
        assert!(result.is_err(), "mutation accepted: {name}");
        println!("{name}: rejected ({})", result.unwrap_err());
    }
    let mut changed = data; let i = changed.len()-12; changed[i] ^= 1;
    let result = verify_proof(facts, Proof::from(changed));
    assert!(result.is_err(), "corrupted proof accepted");
    println!("corrupted proof bytes: rejected ({})", result.unwrap_err());
}
