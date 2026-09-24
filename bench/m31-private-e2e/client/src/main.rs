use anyhow::{Result, bail, ensure};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::Instant,
};
use templar_private_membership::{
    MAX_PROOF,
    air::{Private, Public},
    prove, verify,
};
fn read(path: &str, cap: usize) -> Result<Vec<u8>> {
    let mut out = vec![];
    fs::File::open(path)?
        .take(cap as u64 + 1)
        .read_to_end(&mut out)?;
    ensure!(out.len() <= cap, "input size limit");
    Ok(out)
}
fn write(path: &str, data: &[u8], private: bool) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = opts.open(path)?;
    file.write_all(data)?;
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let start = Instant::now();
    match a.get(1).map(String::as_str) {
        Some("fixture") if a.len() == 4 => {
            let (public, private) = templar_private_membership::air::fresh(&mut rand::rngs::OsRng)?;
            ensure!(
                !Path::new(&a[2]).exists() && !Path::new(&a[3]).exists(),
                "output already exists"
            );
            write(&a[2], &serde_json::to_vec_pretty(&public)?, false)?;
            write(&a[3], &serde_json::to_vec_pretty(&private)?, true)?;
            println!(
                "{}",
                serde_json::json!({"fixture":"fresh synthetic private membership","depth":32})
            );
        }
        Some("prove") if a.len() == 5 => {
            let public: Public = serde_json::from_slice(&read(&a[2], 8192)?)?;
            let private: Private = serde_json::from_slice(&read(&a[3], 65536)?)?;
            let proof = prove(&public, &private, &mut rand::rngs::OsRng)?;
            write(&a[4], &proof, false)?;
            println!(
                "{}",
                serde_json::json!({"action":"prove","seconds":start.elapsed().as_secs_f64(),"proof_bytes":proof.len(),"relation":"private depth32 membership","deployment":"research only; no PROOF1"})
            );
        }
        Some("verify") if a.len() == 4 => {
            let public: Public = serde_json::from_slice(&read(&a[2], 8192)?)?;
            let proof = read(&a[3], MAX_PROOF)?;
            verify(&public, &proof)?;
            println!(
                "{}",
                serde_json::json!({"action":"verify","accepted":true,"seconds":start.elapsed().as_secs_f64(),"proof_bytes":proof.len()})
            );
        }
        _ => bail!(
            "usage: fixture PUBLIC PRIVATE | prove PUBLIC PRIVATE PROOF | verify PUBLIC PROOF"
        ),
    }
    Ok(())
}
