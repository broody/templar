//! CLI for the payment-shaped M31 statement measurement.
use anyhow::{Result, ensure};
use std::path::PathBuf;
use templar_m31_statement::{
    mutations, prove_fixture, statement, verify_bytes,
};
fn fresh(path: &str) -> Result<PathBuf> {
    let p = PathBuf::from(path);
    ensure!(!p.exists(), "fresh output directory required");
    std::fs::create_dir_all(&p)?;
    Ok(p)
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args[1] == "--dump-rank-substrate" {
        ensure!(args.len() == 3, "--dump-rank-substrate OUT.json");
        templar_m31_statement::rank_dump::dump(&args[2])?;
        return Ok(());
    }
    if args[1] == "--probe-pads" {
        // Pad-cost sweep: B random valid rows per level; proves, verifies,
        // measures, and writes one summary per B into DIR.
        ensure!(args.len() == 3, "--probe-pads OUT_DIR");
        let out = fresh(&args[2])?;
        let base = statement::synthetic("0x434841494e", "0x456", 1)?;
        let mut reports = Vec::new();
        // 132 real requests; B chosen to land rows at 512 / 1024 / 2048.
        for b in [0usize, 380, 892] {
            let mut s = base.clone();
            s.pad_seed = 0x504144; // "PAD"
            s.pad_count = b;
            let fixture = serde_json::to_string_pretty(&s)?;
            let dir = out.join(format!("pad-{b}"));
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("fixture.json"), &fixture)?;
            let a = prove_fixture(&fixture)?;
            verify_bytes(&a.proof)?;
            std::fs::write(dir.join("proof.bin"), &a.proof)?;
            std::fs::write(dir.join("summary.json"), &a.summary)?;
            reports.push(serde_json::from_str::<serde_json::Value>(&a.summary)?.as_object().unwrap().to_owned());
            println!("pad={b}: {}", a.summary);
        }
        std::fs::write(
            out.join("probe-summary.json"),
            serde_json::to_vec_pretty(&reports)?,
        )?;
        return Ok(());
    }
    ensure!(
        args.len() >= 2,
        "usage: --make-fixtures CHAIN POOL SEED DIR | FIXTURE.json DIR | --verify PROOF.bin | --verify-tests PROOF.bin DIR | --probe-pads OUT_DIR"
    );
    if args[1] == "--make-fixtures" {
        ensure!(args.len() == 6, "--make-fixtures CHAIN POOL SEED DIR");
        let out = fresh(&args[5])?;
        for (name, seed) in [("payment-2x32", 1u64), ("payment-2x32-b", 0x5eed)] {
            let s = statement::synthetic(&args[2], &args[3], seed)?;
            std::fs::write(out.join(format!("{name}.json")), serde_json::to_string_pretty(&s)?)?;
        }
        return Ok(());
    }
    if args[1] == "--verify" {
        ensure!(args.len() == 3, "--verify PROOF.bin");
        verify_bytes(&std::fs::read(&args[2])?)?;
        println!("accepted");
        return Ok(());
    }
    if args[1] == "--verify-tests" {
        ensure!(args.len() == 4, "--verify-tests PROOF.bin DIR");
        let out = fresh(&args[3])?;
        let report = mutations(&std::fs::read(&args[2])?)?;
        std::fs::write(out.join("negative-tests.json"), &report)?;
        println!("{report}");
        return Ok(());
    }
    ensure!(args.len() == 3, "FIXTURE.json DIR");
    let out = fresh(&args[2])?;
    let a = prove_fixture(&std::fs::read_to_string(&args[1])?)?;
    std::fs::write(out.join("proof.bin"), a.proof)?;
    std::fs::write(out.join("proof.json"), a.proof_json)?;
    std::fs::write(out.join("statement.json"), a.statement)?;
    std::fs::write(out.join("summary.json"), &a.summary)?;
    println!("{}", a.summary);
    Ok(())
}
