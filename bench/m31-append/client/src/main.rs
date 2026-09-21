use anyhow::{Result, ensure};
use starknet_types_core::felt::Felt;
use std::path::PathBuf;
use templar_m31_append::{
    arbitrary_ood_fixtures, mutations, prove_fixture,
    statement::{self, synthetic},
};
fn fresh(path: &str) -> Result<PathBuf> {
    let p = PathBuf::from(path);
    ensure!(!p.exists(), "fresh output directory required");
    std::fs::create_dir_all(&p)?;
    Ok(p)
}
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() >= 2,
        "usage: --make-fixtures CHAIN POOL DIR | FIXTURE DIR | --verify-tests PROOF DIR"
    );
    if args[1] == "--make-fixtures" {
        ensure!(args.len() == 5, "--make-fixtures CHAIN POOL DIR");
        let chain = statement::felt(&args[2])?;
        let pool = statement::felt(&args[3])?;
        let out = fresh(&args[4])?;
        for (name, initial, append) in [
            ("single-empty-to-one", vec![], vec![1u32]),
            ("batch-empty-to-two", vec![], vec![1, 2]),
            ("concurrent-a-to-b", vec![1], vec![2]),
            ("concurrent-a-to-c", vec![1], vec![3]),
            ("refresh-b-to-d", vec![1, 2], vec![3]),
        ] {
            let old = initial.into_iter().map(Felt::from).collect::<Vec<_>>();
            let new = append.into_iter().map(Felt::from).collect::<Vec<_>>();
            let s = synthetic(chain, pool, &old, &new)?;
            std::fs::write(
                out.join(format!("{name}.json")),
                serde_json::to_string_pretty(&s)?,
            )?;
            std::fs::write(
                out.join(format!("{name}-transcript.json")),
                serde_json::to_string_pretty(&templar_m31_append::transcript_vectors(&s)?)?,
            )?;
        }
        std::fs::write(
            out.join("ood-arbitrary.json"),
            serde_json::to_string_pretty(&arbitrary_ood_fixtures())?,
        )?;
        return Ok(());
    }
    if args[1] == "--verify-tests" {
        ensure!(args.len() == 4, "--verify-tests PROOF DIR");
        let out = fresh(&args[3])?;
        let report = mutations(&std::fs::read(&args[2])?)?;
        std::fs::write(out.join("negative-tests.json"), &report)?;
        println!("{report}");
        return Ok(());
    }
    ensure!(args.len() == 3, "FIXTURE DIR");
    let out = fresh(&args[2])?;
    let a = prove_fixture(&std::fs::read_to_string(&args[1])?)?;
    std::fs::write(out.join("proof.bin"), a.proof)?;
    std::fs::write(out.join("proof.json"), a.proof_json)?;
    for (name, contents) in [
        ("cairo-arguments.json", a.cairo_arguments),
        ("cairo-proof.json", a.cairo_proof),
        ("statement.json", a.statement),
        ("public-output.json", a.public_output),
        ("transcript.json", a.transcript),
        ("ood.json", a.ood),
    ] {
        std::fs::write(out.join(name), contents)?;
    }
    std::fs::write(out.join("summary.json"), &a.summary)?;
    println!("{}", a.summary);
    Ok(())
}
