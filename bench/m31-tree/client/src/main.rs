use anyhow::{Result, ensure};
use std::path::PathBuf;
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 3 || args.len() == 4,
        "usage: templar-m31-tree FIXTURE NEW_DIR | --verify-tests PROOF_BIN NEW_DIR"
    );
    if args[1] == "--make-fixtures" {
        ensure!(args.len() == 3, "--make-fixtures NEW_DIR");
        let out = PathBuf::from(&args[2]);
        ensure!(!out.exists(), "fresh output directory required");
        std::fs::create_dir_all(&out)?;
        std::fs::write(
            out.join("tree-only.json"),
            templar_m31_tree::fixture_json(false)?,
        )?;
        std::fs::write(
            out.join("mixed.json"),
            templar_m31_tree::fixture_json(true)?,
        )?;
        return Ok(());
    }
    if args[1] == "--verify-tests" {
        ensure!(args.len() == 4, "--verify-tests PROOF_BIN NEW_DIR");
        let out = PathBuf::from(&args[3]);
        ensure!(!out.exists(), "fresh output directory required");
        std::fs::create_dir_all(&out)?;
        let report = templar_m31_tree::mutation_checks(&std::fs::read(&args[2])?)?;
        std::fs::write(out.join("negative-tests.json"), &report)?;
        println!("{report}");
        return Ok(());
    }
    ensure!(
        args.len() == 3,
        "bounded16 mode is fixed for this portability experiment"
    );
    let out = PathBuf::from(&args[2]);
    ensure!(!out.exists(), "fresh output directory required");
    std::fs::create_dir_all(&out)?;
    let a = templar_m31_tree::prove_fixture(&std::fs::read_to_string(&args[1])?)?;
    std::fs::write(out.join("proof.bin"), a.proof_bytes)?;
    std::fs::write(out.join("proof.json"), a.proof_json)?;
    std::fs::write(out.join("shape.json"), a.shape_json)?;
    std::fs::write(out.join("summary.json"), &a.summary_json)?;
    println!("{}", a.summary_json);
    Ok(())
}
