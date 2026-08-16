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
    embed_toml_dir(
        &manifest_dir,
        "rules/examples",
        "evtx_",
        "EVTX_RULE_TOMLS",
        "evtx_builtin_rules.rs",
    );
    embed_toml_dir(
        &manifest_dir,
        "rules/examples",
        "journald_",
        "JOURNALD_RULE_TOMLS",
        "journald_builtin_rules.rs",
    );

    #[cfg(windows)]
    embed_windows_icon();
}

/// Embeds `resources/windows/peach.ico` as the compiled `.exe`'s icon
/// resource — what shows in Explorer, the taskbar, and Alt-Tab even before
/// Peach is running, which `egui::ViewportBuilder::with_icon` (the
/// *running* window's icon, see `app::run`) can't provide on its own: that
/// one only takes effect once a window actually exists.
///
/// `#[cfg(windows)]`, both on this function and gating its one call site
/// above, not a `CARGO_CFG_TARGET_OS` runtime check — `build.rs` itself
/// always runs on (and, unlike the crate it builds, is *itself* compiled
/// for) the host, so `#[cfg(windows)]` here reflects the host, not
/// necessarily a cross-compilation target; see `winresource`'s own README
/// on this exact pitfall for the general case. `release.yml`'s matrix
/// builds Windows natively on a `windows-latest` runner, never
/// cross-compiles to it from Linux/macOS, so host and target are always the
/// same triple family for every build this project actually ships — the
/// simpler host-based gate is correct here, not a corner cut.
#[cfg(windows)]
fn embed_windows_icon() {
    println!("cargo::rerun-if-changed=resources/windows/peach.ico");
    winresource::WindowsResource::new()
        .set_icon("resources/windows/peach.ico")
        .compile()
        .expect("failed to embed the Windows .exe icon resource");
}
