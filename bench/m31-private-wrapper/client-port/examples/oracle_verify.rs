//! Verify retained TMPZK002 proofs with the oracle rebuilt against the server stwo pin.
use templar_client_verifier_circuit::oracle as client;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let public = serde_json::from_slice(&std::fs::read(&a[1]).unwrap()).unwrap();
    for path in &a[2..] {
        let ok = client::verify(&public, &std::fs::read(path).unwrap()).is_ok();
        println!("{path}: {}", if ok { "accepted" } else { "REJECTED" });
    }
}
