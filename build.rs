use std::env;
use std::fs;
use std::path::Path;

/// Generates `OUT_DIR/<out_file>`, a `pub const <const_name>: &[&str]` array
/// with one `include_str!` per matching file in `dir` (relative to the
/// crate root) — see `src/tagging/builtin.rs` and `src/parsers/evtx/
/// templates.rs`, which `include!` the two files this produces. Scanning
/// the directory at build time (rather than listing files by hand) means a
/// new file just needs to exist under `dir` with the right prefix to ship
/// in the built binary; nothing in the Rust source has to change to pick it
/// up.
///
/// Sorted by filename for determinism (forensic principle: same inputs,
/// same build, every time) — `read_dir`'s own order is not guaranteed to
/// be consistent across platforms/filesystems.
fn embed_toml_dir(manifest_dir: &str, dir: &str, prefix: &str, const_name: &str, out_file: &str) {
    let full_dir = Path::new(manifest_dir).join(dir);
    println!("cargo::rerun-if-changed={}", full_dir.display());

    let mut file_names: Vec<String> = fs::read_dir(&full_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", full_dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(prefix) && name.ends_with(".toml"))
        .collect();
    file_names.sort();

    let mut generated = format!("pub const {const_name}: &[&str] = &[\n");
    for file_name in &file_names {
        generated.push_str(&format!(
            "    include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{dir}/{file_name}\")),\n"
        ));
    }
    generated.push_str("];\n");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join(out_file);
    fs::write(&dest, generated)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", dest.display()));
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    embed_toml_dir(
        &manifest_dir,
        "rules/examples",
        "aul_",
        "AUL_RULE_TOMLS",
        "aul_builtin_rules.rs",
    );
    embed_toml_dir(
        &manifest_dir,
        "message_templates/examples",
        "evtx_",
        "EVTX_TEMPLATE_TOMLS",
        "evtx_builtin_templates.rs",
    );
}
