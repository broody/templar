//! Regenerates the two GENERATED sections of the vendored Cairo `circuit_air` for a circuit's
//! trusted manifest: `multiverifier_consts.cairo` (FRI config, component and column log sizes)
//! and `preprocessed_columns.cairo` (column indices). Rendering is copied from upstream's
//! `crates/circuit_params/tests/cairo_consts_test.rs` (proving@5a7c5ed); the column order comes
//! from the same library function the prover uses, `layout_from_component_sizes`.
use std::fmt::Write as _;
use std::path::Path;

use circuit_common::finalize::ComponentSizes;
use circuit_common::preprocessed::layout_from_component_sizes;
use serde_json::Value;
use stwo::core::fri::FriConfig;

const BEGIN_MARKER: &str =
    "// === BEGIN GENERATED (see cairo_consts_test.rs; running it with FIX=1 regenerates) ===";
const END_MARKER: &str = "// === END GENERATED ===";

fn layout(target_sizes: &ComponentSizes) -> Vec<(String, u32)> {
    layout_from_component_sizes(target_sizes).iter().map(|(id, l)| (id.id.clone(), *l)).collect()
}

fn cairo_component(id: &str) -> &'static str {
    match id {
        _ if id.starts_with("eq_") => "eq",
        _ if id.starts_with("qm31_ops_") => "qm31_ops",
        _ if id.starts_with("triple_xor_") => "triple_xor",
        _ if id.starts_with("m31_to_u32_") => "m_31_to_u_32",
        _ if id.starts_with("blake_g_gate_") => "blake_g_gate",
        "seq_16" => "range_check_16",
        _ if id.starts_with("bitwise_xor_4_") => "verify_bitwise_xor_4",
        _ if id.starts_with("bitwise_xor_7_") => "verify_bitwise_xor_7",
        _ if id.starts_with("bitwise_xor_8_") => "verify_bitwise_xor_8",
        _ if id.starts_with("bitwise_xor_9_") => "verify_bitwise_xor_9",
        _ if id.starts_with("bitwise_xor_10_") => "verify_bitwise_xor_12",
        _ => panic!("unknown preprocessed column id {id:?}"),
    }
}

fn idx_const_name(id: &str) -> String {
    let renamed = match id {
        "qm31_ops_add_flag" => "add_flag",
        "qm31_ops_sub_flag" => "sub_flag",
        "qm31_ops_mul_flag" => "mul_flag",
        "qm31_ops_pointwise_mul_flag" => "pointwise_mul_flag",
        "qm31_ops_in0_address" => "op_0_addr",
        "qm31_ops_in1_address" => "op_1_addr",
        "qm31_ops_out_address" => "dst_addr",
        "qm31_ops_mults" => "qm_31_ops_multiplicity",
        "blake_g_gate_input_addr_f0" => "blake_g_gate_input_addr_f_0",
        "blake_g_gate_input_addr_f1" => "blake_g_gate_input_addr_f_1",
        _ if id.starts_with("m31_to_u32_") => {
            return format!("M_31_TO_U_32_{}_IDX", id["m31_to_u32_".len()..].to_uppercase());
        }
        _ => id,
    };
    format!("{}_IDX", renamed.to_uppercase())
}

fn render_multiverifier_consts(fri: FriConfig, target: &ComponentSizes) -> String {
    let layout = layout(target);
    let log_of = |id: &str| layout.iter().find(|(c, _)| c == id).unwrap_or_else(|| panic!("missing {id}")).1;
    let FriConfig { pow_bits, log_blowup_factor, log_last_layer_degree_bound, n_queries, fold_step } = fri;
    let mut w = String::new();
    writeln!(w, "{BEGIN_MARKER}\n").unwrap();
    writeln!(w, "/// Expected FRI config of the verified circuit's proof (Templar trusted manifest).").unwrap();
    writeln!(w, "/// Note `pow_bits + log_blowup_factor * n_queries = {pow_bits} + {log_blowup_factor} * {n_queries} = {}`.", pow_bits as usize + log_blowup_factor as usize * n_queries).unwrap();
    writeln!(w, "pub fn circuit_fri_config() -> FriConfig {{\n    FriConfig {{").unwrap();
    writeln!(w, "        pow_bits: {pow_bits},\n        log_blowup_factor: {log_blowup_factor},").unwrap();
    writeln!(w, "        log_last_layer_degree_bound: {log_last_layer_degree_bound},").unwrap();
    writeln!(w, "        n_queries: {n_queries},\n        fold_step: {fold_step},\n    }}\n}}\n").unwrap();
    writeln!(w, "/// Each component's log size.").unwrap();
    writeln!(w, "pub const COMPONENT_LOG_SIZES: PerComponent<u32> = PerComponent {{").unwrap();
    for (field, id) in [
        ("eq", "eq_in0_address"), ("qm31_ops", "qm31_ops_add_flag"), ("triple_xor", "triple_xor_input_addr_0"),
        ("m_31_to_u_32", "m31_to_u32_input_addr"), ("blake_g_gate", "blake_g_gate_input_addr_a"),
        ("verify_bitwise_xor_8", "bitwise_xor_8_0"), ("verify_bitwise_xor_12", "bitwise_xor_10_0"),
        ("verify_bitwise_xor_4", "bitwise_xor_4_0"), ("verify_bitwise_xor_7", "bitwise_xor_7_0"),
        ("verify_bitwise_xor_9", "bitwise_xor_9_0"), ("range_check_16", "seq_16"),
    ] {
        writeln!(w, "    {field}: {},", log_of(id)).unwrap();
    }
    writeln!(w, "}};\n").unwrap();
    writeln!(w, "/// Per-column log sizes of the preprocessed trace, in size-sorted column order.").unwrap();
    writeln!(w, "pub const PREPROCESSED_COLUMN_LOG_SIZES: [u32; {}] = [", layout.len()).unwrap();
    for (i, (id, _)) in layout.iter().enumerate() {
        let sep = if i + 1 == layout.len() { "" } else { "," };
        writeln!(w, "    COMPONENT_LOG_SIZES.{}{sep} // {id}", cairo_component(id)).unwrap();
    }
    writeln!(w, "];\n\n{END_MARKER}").unwrap();
    w
}

fn render_preprocessed_columns(target: &ComponentSizes) -> String {
    let layout = layout(target);
    let mut w = String::new();
    writeln!(w, "{BEGIN_MARKER}\n").unwrap();
    writeln!(w, "pub const NUM_PREPROCESSED_COLUMNS: u32 = {};", layout.len()).unwrap();
    let mut idx = 0;
    while idx < layout.len() {
        let component = cairo_component(&layout[idx].0);
        let end = layout[idx..].iter().position(|(o, _)| cairo_component(o) != component).map(|l| idx + l).unwrap_or(layout.len());
        writeln!(w).unwrap();
        for (id, _) in &layout[idx..end] {
            writeln!(w, "pub const {}: PreprocessedColumnIdx = {idx};", idx_const_name(id)).unwrap();
            idx += 1;
        }
    }
    writeln!(w, "\n{END_MARKER}").unwrap();
    w
}

fn replace_section(path: &Path, rendered: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    let begin = text.find(BEGIN_MARKER).expect("BEGIN marker");
    let end = text.find(END_MARKER).expect("END marker") + END_MARKER.len();
    std::fs::write(path, format!("{}{}{}", &text[..begin], rendered.trim_end(), &text[end..])).unwrap();
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert_eq!(a.len(), 3, "gen_cairo_consts TRUSTED_CONFIG CIRCUIT_AIR_SRC");
    let m: Value = serde_json::from_slice(&std::fs::read(&a[1]).unwrap()).unwrap();
    let fri: FriConfig = serde_json::from_value(m["fri_config"].clone()).unwrap();
    let logs: Vec<u32> = serde_json::from_value(m["component_log_sizes"].clone()).unwrap();
    // PerComponent order: eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate, then fixed tables.
    let target = ComponentSizes {
        eq: 1 << logs[0], qm31_ops: 1 << logs[1], triple_xor: 1 << logs[2], m31_to_u32: 1 << logs[3], blake_g_gate: 1 << logs[4],
    };
    let src = Path::new(&a[2]);
    replace_section(&src.join("multiverifier_consts.cairo"), &render_multiverifier_consts(fri, &target));
    replace_section(&src.join("preprocessed_columns.cairo"), &render_preprocessed_columns(&target));
    // The rendered layout must reproduce the manifest's own column list exactly.
    let rendered: Vec<(String, u32)> = layout(&target);
    let manifest: Vec<(String, u32)> = m["preprocessed_columns"].as_array().unwrap().iter()
        .map(|c| (c["id"].as_str().unwrap().to_string(), c["log_size"].as_u64().unwrap() as u32)).collect();
    assert_eq!(rendered, manifest, "layout differs from the trusted manifest");
    println!("generated {} columns", rendered.len());
}
