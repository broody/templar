//! Read-only probe: replay the captured PIE through the privacy bootloader and
//! attribute every Blake compression to the code segment (and call stack) that
//! issued it. No AIR claim or proof is generated.
use std::{collections::BTreeMap, error::Error, fs, path::Path, rc::Rc};
use cairo_program_runner_lib::types::{HashFunc, PrivacySimpleBootloaderInput, SimpleBootloaderInput};
use cairo_program_runner_lib::{cairo_run_program, ProgramInput, Task, TaskSpec};
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use privacy_circuit_verify::get_privacy_bootloader_program;
use privacy_prove::consts::CAIRO_RUN_CONFIG;
use serde_json::json;
use tempfile::NamedTempFile;

type Mem = Vec<Vec<Option<MaybeRelocatable>>>;

fn get(mem: &Mem, r: Relocatable) -> Option<&MaybeRelocatable> {
    let seg = if r.segment_index >= 0 { r.segment_index as usize } else { return None };
    mem.get(seg)?.get(r.offset)?.as_ref()
}
fn reloc(mem: &Mem, r: Relocatable) -> Option<Relocatable> {
    match get(mem, r)? { MaybeRelocatable::RelocatableValue(v) => Some(*v), _ => None }
}
fn key(r: Relocatable) -> String { format!("{}:{}", r.segment_index, r.offset) }

fn main() -> Result<(), Box<dyn Error>> {
    let a: Vec<_> = std::env::args().collect();
    assert_eq!(a.len(), 3, "blake_sites PIE OUT_DIR");
    let pie = CairoPie::read_zip_file(Path::new(&a[1]))?;
    let temp = NamedTempFile::new()?;
    let input = PrivacySimpleBootloaderInput {
        simple_bootloader_input: SimpleBootloaderInput {
            fact_topologies_path: None,
            single_page: true,
            tasks: vec![TaskSpec { task: Rc::new(Task::Pie(pie)), program_hash_function: HashFunc::Blake }],
        },
        output_preimage_dump_path: temp.path().to_path_buf(),
    };
    let runner = cairo_run_program(&get_privacy_bootloader_program()?, Some(ProgramInput::Value(Box::new(input))), CAIRO_RUN_CONFIG, None)?;
    let mem = runner.get_relocatable_memory();
    let trace = runner.get_relocatable_trace()?;

    let mut steps_by_seg: BTreeMap<isize, u64> = BTreeMap::new();
    let mut visited19: std::collections::BTreeSet<usize> = Default::default();
    let mut blake_by_seg: BTreeMap<isize, [u64; 2]> = BTreeMap::new();
    let mut blake_by_pc: BTreeMap<String, u64> = BTreeMap::new();
    // Call stack of return addresses, up to 6 frames, per blake instruction.
    let mut blake_by_stack: BTreeMap<String, u64> = BTreeMap::new();
    for e in trace {
        *steps_by_seg.entry(e.pc.segment_index).or_default() += 1;
        if e.pc.segment_index == 19 { visited19.insert(e.pc.offset); }
        let Some(MaybeRelocatable::Int(instr)) = get(&mem, e.pc) else { continue };
        let ext = (instr.to_biguint() >> 63u32).to_u64_digits().first().copied().unwrap_or(0);
        if ext != 1 && ext != 2 { continue; }
        blake_by_seg.entry(e.pc.segment_index).or_default()[(ext - 1) as usize] += 1;
        *blake_by_pc.entry(key(e.pc)).or_default() += 1;
        let mut stack = vec![key(e.pc)];
        let mut fp = Relocatable::from((1, e.fp));
        for _ in 0..6 {
            if fp.offset < 2 { break; }
            let (Some(ret), Some(prev)) = (reloc(&mem, (fp - 1)?), reloc(&mem, (fp - 2)?)) else { break };
            stack.push(key(ret));
            fp = prev;
        }
        *blake_by_stack.entry(stack.join(" <- ")).or_default() += 1;
    }
    let seg_sizes: Vec<usize> = mem.iter().map(|s| s.len()).collect();
    let out = Path::new(&a[2]);
    fs::create_dir_all(out)?;
    let total: u64 = blake_by_seg.values().map(|v| v[0] + v[1]).sum();
    fs::write(out.join("blake-sites.json"), serde_json::to_vec_pretty(&json!({
        "total_steps": trace.len(),
        "blake_total": total,
        "segment_sizes": seg_sizes,
        "steps_by_pc_segment": steps_by_seg,
        "blake_by_pc_segment_[compress,finalize]": blake_by_seg,
        "blake_by_pc": blake_by_pc,
        "blake_by_stack": blake_by_stack,
        "visited_seg19": visited19,
        "seg19_head": mem[19].iter().take(120).map(|v| format!("{:?}", v)).collect::<Vec<_>>(),
    }))?)?;
    eprintln!("blake total {total}");
    Ok(())
}
