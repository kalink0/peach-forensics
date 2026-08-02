use std::env;
use std::fs;
use std::path::Path;

/// Generates `OUT_DIR/aul_builtin_rules.rs`, a `pub const AUL_RULE_TOMLS:
/// &[&str]` array with one `include_str!` per `rules/examples/aul_*.toml`
/// file — see `src/tagging/builtin.rs`, which `include!`s this. Scanning
/// the directory at build time (rather than listing files by hand) means a
/// new AUL rule file just needs to exist under `rules/examples/` to ship in
/// the built binary; nothing in the Rust source has to change to pick it up.
///
/// Sorted by filename for determinism (forensic principle: same inputs,
/// same build, every time) — `read_dir`'s own order is not guaranteed to
/// be consistent across platforms/filesystems.
fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let rules_dir = Path::new(&manifest_dir).join("rules/examples");
    println!("cargo::rerun-if-changed={}", rules_dir.display());

    let mut file_names: Vec<String> = fs::read_dir(&rules_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", rules_dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("aul_") && name.ends_with(".toml"))
        .collect();
    file_names.sort();

    let mut generated = String::from("pub const AUL_RULE_TOMLS: &[&str] = &[\n");
    for file_name in &file_names {
        generated.push_str(&format!(
            "    include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/rules/examples/{file_name}\")),\n"
        ));
    }
    generated.push_str("];\n");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("aul_builtin_rules.rs");
    fs::write(&dest, generated)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", dest.display()));
}
