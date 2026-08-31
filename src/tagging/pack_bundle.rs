//! Loads and validates a downloaded/drag-and-dropped rule-pack bundle
//! (`peach-rules-vN.zip`, built by `scripts/publish_rule_pack.py` — see
//! `docs/design/rule-pack-updates.md`) before anything in it is trusted:
//! valid zip, parseable `manifest.toml`, a Peach new enough to understand
//! it, and every listed file present with a matching SHA-256. Nothing here
//! decides *where* the verified files end up living (tier-2 storage,
//! `docs/design/rule-pack-updates.md` step 5) — this module only answers
//! "is this bundle safe to trust at all".
//!
//! Deliberately mirrors `session::portable_case`'s import path (same
//! `ScratchDir` + `extract_zip` + per-manifest-entry SHA-256 shape) rather
//! than sharing code with it: those helpers are private to that module,
//! and duplicating ~30 lines of generic zip-extraction here is simpler
//! than restructuring visibility across two otherwise-unrelated domain
//! modules for one shared piece — especially since what happens to the
//! verified files next (tier-2 storage) will look nothing like moving a
//! multi-GB DuckDB/SQLite pair into place the way portable_case does.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use sha2::{Digest, Sha256};

/// The running Peach's own version — a bundle whose `min_peach_version` is
/// newer is rejected rather than loaded best-effort.
const PEACH_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct PackManifest {
    pub pack: PackInfo,
    #[serde(default)]
    pub files: Vec<PackFileEntry>,
}

impl PackManifest {
    /// This manifest's `rule_name → rule_version` — the candidate side of
    /// `tagging::pack_diff::diff`'s comparison (the active side comes from
    /// `tagging::builtin::active_rule_versions`), for the "Rule packs..."
    /// preview.
    pub fn rule_versions(&self) -> crate::tagging::pack_diff::RuleVersions {
        self.files
            .iter()
            .map(|entry| (entry.rule_name.clone(), entry.rule_version.clone()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct PackInfo {
    pub pack_version: u32,
    pub released_at: String,
    pub min_peach_version: String,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct PackFileEntry {
    pub name: String,
    pub sha256: String,
    pub rule_name: String,
    pub rule_version: String,
}

/// A bundle that passed every check in [`load_pack_bundle`] — `manifest`
/// and `extracted_dir` (containing exactly the files the manifest lists,
/// each hash-verified, plus `manifest.toml` itself) are safe for the
/// tier-2 storage step to move into place.
#[derive(Debug)]
pub struct LoadedPackBundle {
    pub manifest: PackManifest,
    pub extracted_dir: PathBuf,
}

/// RAII scratch directory, cleaned up on drop so an early `?`-propagated
/// failure (bad zip, hash mismatch, ...) never leaves extracted rule files
/// lying around in the OS temp directory. Same convention as
/// `session::portable_case::ScratchDir`.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(prefix: &str) -> anyhow::Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "peach-{prefix}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create scratch directory {}", dir.display()))?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn extract_zip(zip_path: &Path, dest_dir: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(zip_path)
        .with_context(|| format!("failed to open {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .context("not a valid zip file — is this actually a Peach rule pack bundle?")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        // `enclosed_name` is zip's own zip-slip protection — an entry name
        // it considers unsafe (absolute, or escaping via `..`) is skipped
        // rather than failing the whole load over one untrusted name; the
        // manifest-vs-directory reconciliation below then rejects the
        // bundle anyway once that name turns out to be missing or
        // unaccounted for.
        let Some(relative_path) = entry.enclosed_name() else {
            continue;
        };
        let dest_path = dest_dir.join(relative_path);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest_path)?;
            continue;
        }
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out_file = std::fs::File::create(&dest_path)
            .with_context(|| format!("failed to create {}", dest_path.display()))?;
        std::io::copy(&mut entry, &mut out_file)
            .with_context(|| format!("failed to extract {}", dest_path.display()))?;
    }
    Ok(())
}

/// Streaming SHA-256 of a file — never reads the whole file into memory.
/// Overkill for the small rule TOMLs this module actually hashes, but
/// matches `session::portable_case::sha256_file`'s approach rather than a
/// one-shot `std::fs::read` for no real reason to diverge.
fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Parses a plain `MAJOR.MINOR.PATCH`-style version string (Peach's own
/// versioning scheme — no pre-release/build metadata to worry about) into
/// a comparable tuple. `None` for anything else, including a malformed
/// value from a tampered bundle — callers treat that as "can't verify,
/// don't trust it", never as "assume it's fine".
fn parse_plain_version(v: &str) -> Option<Vec<u32>> {
    v.split('.').map(|part| part.parse::<u32>().ok()).collect()
}

/// Whether the running Peach (`PEACH_VERSION`) meets a bundle's
/// `min_peach_version` — `false` (refuse) if either side doesn't parse,
/// which also means the same-length-assumption below is never compared
/// against a mismatched-arity version like "0.3" vs. "0.3.0": both
/// `PEACH_VERSION` and every `min_peach_version` this project's own
/// `publish_rule_pack.py` writes come from a `Cargo.toml` `version` field,
/// always three dotted integers, so a lexicographic `Vec<u32>` comparison
/// is exact here — this isn't a general-purpose semver comparison.
fn peach_version_satisfies(min_required: &str) -> bool {
    match (
        parse_plain_version(min_required),
        parse_plain_version(PEACH_VERSION),
    ) {
        (Some(min), Some(running)) => running >= min,
        _ => false,
    }
}

/// Extracts, parses, and fully verifies a rule-pack bundle. Every check
/// below fails loudly (a descriptive `Err`, never a silent best-effort
/// partial load) — a corrupted download, a bundle built for a newer Peach,
/// a tampered file, or an unaccounted-for extra file smuggled into the zip
/// are all refused outright, not applied with a warning.
pub fn load_pack_bundle(zip_path: &Path) -> anyhow::Result<LoadedPackBundle> {
    let scratch = ScratchDir::new("rule-pack-bundle")?;
    extract_zip(zip_path, scratch.path())?;

    let manifest_path = scratch.path().join("manifest.toml");
    let manifest_toml = std::fs::read_to_string(&manifest_path)
        .context("not a valid Peach rule pack: no manifest.toml found in the bundle")?;
    let manifest: PackManifest = toml::from_str(&manifest_toml)
        .context("not a valid Peach rule pack: manifest.toml could not be parsed")?;

    anyhow::ensure!(
        peach_version_satisfies(&manifest.pack.min_peach_version),
        "this rule pack requires Peach {} or newer (running {PEACH_VERSION}) — update Peach to apply it",
        manifest.pack.min_peach_version,
    );

    let mut expected_names: BTreeSet<&str> =
        manifest.files.iter().map(|f| f.name.as_str()).collect();
    anyhow::ensure!(
        expected_names.len() == manifest.files.len(),
        "not a valid Peach rule pack: manifest.toml lists the same file name more than once"
    );

    for entry in &manifest.files {
        let file_path = scratch.path().join(&entry.name);
        anyhow::ensure!(
            file_path.is_file(),
            "rule pack is missing {} (listed in manifest.toml but not found in the bundle)",
            entry.name
        );
        let actual_sha256 = sha256_file(&file_path)?;
        anyhow::ensure!(
            actual_sha256 == entry.sha256,
            "rule pack failed integrity verification: {}'s hash doesn't match the manifest \
             (the bundle may be corrupted or was modified after it was built)",
            entry.name
        );
    }

    // The loop above already proved every *expected* name is present and
    // correct; this pass catches the other direction — an extra file in
    // the zip that manifest.toml never mentioned. Trusting it anyway
    // would mean the manifest's own promise ("this bundle is exactly
    // these N files") isn't actually being enforced.
    for extracted in std::fs::read_dir(scratch.path())
        .with_context(|| format!("failed to read {}", scratch.path().display()))?
    {
        let extracted = extracted?;
        let name = extracted.file_name();
        let name = name.to_string_lossy();
        if name == "manifest.toml" {
            continue;
        }
        anyhow::ensure!(
            expected_names.remove(name.as_ref()),
            "rule pack contains {name} which isn't listed in manifest.toml — refusing to \
             trust an unaccounted-for file"
        );
    }

    Ok(LoadedPackBundle {
        manifest,
        extracted_dir: scratch.into_path(),
    })
}

impl ScratchDir {
    /// Consumes the guard without deleting the directory — used once a
    /// bundle has fully verified and the caller (eventually, tier-2
    /// storage) needs the extracted files to survive past this function
    /// returning. The directory becomes the caller's responsibility to
    /// clean up.
    fn into_path(self) -> PathBuf {
        let path = self.0.clone();
        std::mem::forget(self);
        path
    }
}

/// Moves a verified bundle's files into `dest_dir` — the applied tier-2
/// rule pack directory, `tagging::rule_file::default_applied_pack_dir()` —
/// replacing whatever was there before entirely. `dest_dir` is emptied
/// first, then every file from `bundle.extracted_dir` (the rule TOMLs plus
/// `manifest.toml`, already SHA-256-verified by [`load_pack_bundle`]) is
/// moved in — wholesale, per the three-tier model's precedence decision
/// (`docs/design/rule-pack-updates.md` §3): tier 2 is either fully absent
/// or a complete, internally-consistent pack, never a partial merge with
/// whatever was applied before.
///
/// `bundle.extracted_dir` (a temp directory `load_pack_bundle` deliberately
/// left un-deleted for this handoff) is removed once its files have been
/// moved out of it, regardless of whether the move itself succeeds — this
/// function is the one responsible for cleaning it up, since
/// [`load_pack_bundle`] no longer owns it once it returned a
/// [`LoadedPackBundle`].
pub fn apply_bundle(bundle: LoadedPackBundle, dest_dir: &Path) -> anyhow::Result<()> {
    let result = apply_bundle_inner(&bundle, dest_dir);
    let _ = std::fs::remove_dir_all(&bundle.extracted_dir);
    result
}

fn apply_bundle_inner(bundle: &LoadedPackBundle, dest_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("failed to create {}", dest_dir.display()))?;

    for existing in std::fs::read_dir(dest_dir)
        .with_context(|| format!("failed to read {}", dest_dir.display()))?
    {
        let existing = existing?;
        if existing.file_type()?.is_dir() {
            std::fs::remove_dir_all(existing.path())
        } else {
            std::fs::remove_file(existing.path())
        }
        .with_context(|| format!("failed to remove {}", existing.path().display()))?;
    }

    for extracted in std::fs::read_dir(&bundle.extracted_dir).with_context(|| {
        format!(
            "failed to read extracted bundle directory {}",
            bundle.extracted_dir.display()
        )
    })? {
        let extracted = extracted?;
        let dest_path = dest_dir.join(extracted.file_name());
        move_or_copy(&extracted.path(), &dest_path)?;
    }
    Ok(())
}

/// `fs::rename`, falling back to copy+delete for a cross-filesystem move
/// (the OS temp directory and the per-user data directory can easily live
/// on different filesystems/drives) — `rename` alone fails in that case on
/// every major OS. Same approach as
/// `session::portable_case::move_or_copy`, not shared with it for the same
/// reason the rest of this module isn't (see the module doc comment).
fn move_or_copy(from: &Path, to: &Path) -> anyhow::Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to)
        .with_context(|| format!("failed to copy {} to {}", from.display(), to.display()))?;
    std::fs::remove_file(from)
        .with_context(|| format!("failed to remove {} after copying", from.display()))?;
    Ok(())
}

/// Best-effort read of `dir`'s `manifest.toml` — for *displaying* what's
/// currently applied (the "Rule packs..." dialog's status line), not for
/// deciding whether to trust it. `None` for anything short of "the file is
/// there and parses" (no directory, no manifest, corrupt TOML) — the same
/// tolerant, non-panicking spirit as
/// `tagging::builtin::active_builtin_rules`'s own fallback, since a
/// missing/unreadable manifest here just means the status line shows
/// "built-in baseline" instead of a version number, not a hard error.
pub fn read_applied_manifest(dir: &Path) -> Option<PackManifest> {
    let text = std::fs::read_to_string(dir.join("manifest.toml")).ok()?;
    toml::from_str(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_path(name: &str, ext: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "peach-pack-bundle-test-{}-{}-{name}.{ext}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn temp_dir_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "peach-pack-bundle-test-dir-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn write_test_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for (name, contents) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap();
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sample_manifest_toml(entries: &[(&str, &[u8])]) -> String {
        let mut manifest = String::from(
            "[pack]\npack_version = 1\nreleased_at = \"2026-09-01\"\nmin_peach_version = \"0.0.1\"\n\n",
        );
        for (name, contents) in entries {
            manifest.push_str(&format!(
                "[[files]]\nname = \"{name}\"\nsha256 = \"{}\"\nrule_name = \"{name}\"\nrule_version = \"1\"\n\n",
                sha256_hex(contents),
            ));
        }
        manifest
    }

    #[test]
    fn loads_a_well_formed_bundle() {
        let rule_a: &[u8] = b"[rule]\nname = \"a\"\n";
        let rule_b: &[u8] = b"[rule]\nname = \"b\"\n";
        let entries: Vec<(&str, &[u8])> = vec![("aul_a.toml", rule_a), ("aul_b.toml", rule_b)];
        let manifest_toml = sample_manifest_toml(&entries);

        let mut zip_entries = entries.clone();
        let manifest_bytes = manifest_toml.as_bytes();
        zip_entries.push(("manifest.toml", manifest_bytes));

        let zip_path = temp_path("wellformed", "zip");
        write_test_zip(&zip_path, &zip_entries);

        let bundle = load_pack_bundle(&zip_path).unwrap();
        assert_eq!(bundle.manifest.pack.pack_version, 1);
        assert_eq!(bundle.manifest.files.len(), 2);
        assert!(bundle.extracted_dir.join("aul_a.toml").is_file());
        assert!(bundle.extracted_dir.join("aul_b.toml").is_file());

        std::fs::remove_file(&zip_path).ok();
        std::fs::remove_dir_all(&bundle.extracted_dir).ok();
    }

    #[test]
    fn rejects_a_bundle_with_no_manifest() {
        let zip_path = temp_path("no-manifest", "zip");
        write_test_zip(&zip_path, &[("aul_a.toml", b"[rule]\nname = \"a\"\n")]);

        let result = load_pack_bundle(&zip_path);

        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("manifest.toml"));
        std::fs::remove_file(&zip_path).ok();
    }

    #[test]
    fn rejects_an_unparseable_manifest() {
        let zip_path = temp_path("bad-manifest", "zip");
        write_test_zip(
            &zip_path,
            &[("manifest.toml", b"this is not valid toml [[[")],
        );

        let result = load_pack_bundle(&zip_path);

        assert!(result.is_err());
        std::fs::remove_file(&zip_path).ok();
    }

    #[test]
    fn rejects_a_bundle_requiring_a_newer_peach() {
        let manifest_toml = "\
[pack]
pack_version = 1
released_at = \"2026-09-01\"
min_peach_version = \"9999.0.0\"
";
        let zip_path = temp_path("future-peach", "zip");
        write_test_zip(&zip_path, &[("manifest.toml", manifest_toml.as_bytes())]);

        let result = load_pack_bundle(&zip_path);

        assert!(result.is_err());
        assert!(
            format!("{:#}", result.unwrap_err()).contains("newer"),
            "expected a min_peach_version rejection message"
        );
        std::fs::remove_file(&zip_path).ok();
    }

    #[test]
    fn rejects_a_bundle_missing_a_listed_file() {
        let manifest_toml = "\
[pack]
pack_version = 1
released_at = \"2026-09-01\"
min_peach_version = \"0.0.1\"

[[files]]
name = \"aul_missing.toml\"
sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"
rule_name = \"aul_missing\"
rule_version = \"1\"
";
        let zip_path = temp_path("missing-file", "zip");
        write_test_zip(&zip_path, &[("manifest.toml", manifest_toml.as_bytes())]);

        let result = load_pack_bundle(&zip_path);

        assert!(result.is_err());
        assert!(
            format!("{:#}", result.unwrap_err()).contains("missing"),
            "expected a missing-file rejection message"
        );
        std::fs::remove_file(&zip_path).ok();
    }

    #[test]
    fn rejects_a_bundle_with_a_tampered_file() {
        let rule_a: &[u8] = b"[rule]\nname = \"a\"\n";
        let entries: Vec<(&str, &[u8])> = vec![("aul_a.toml", rule_a)];
        let manifest_toml = sample_manifest_toml(&entries);

        let zip_path = temp_path("tampered", "zip");
        write_test_zip(
            &zip_path,
            &[
                ("manifest.toml", manifest_toml.as_bytes()),
                // Different bytes than what the manifest's sha256 was
                // computed from — same file name, tampered content.
                ("aul_a.toml", b"[rule]\nname = \"tampered\"\n"),
            ],
        );

        let result = load_pack_bundle(&zip_path);

        assert!(result.is_err());
        assert!(
            format!("{:#}", result.unwrap_err()).contains("integrity"),
            "expected an integrity-check failure message"
        );
        std::fs::remove_file(&zip_path).ok();
    }

    #[test]
    fn rejects_a_bundle_with_an_extra_unlisted_file() {
        let rule_a: &[u8] = b"[rule]\nname = \"a\"\n";
        let entries: Vec<(&str, &[u8])> = vec![("aul_a.toml", rule_a)];
        let manifest_toml = sample_manifest_toml(&entries);

        let zip_path = temp_path("extra-file", "zip");
        write_test_zip(
            &zip_path,
            &[
                ("manifest.toml", manifest_toml.as_bytes()),
                ("aul_a.toml", rule_a),
                // Not in the manifest at all.
                ("aul_sneaky.toml", b"[rule]\nname = \"sneaky\"\n"),
            ],
        );

        let result = load_pack_bundle(&zip_path);

        assert!(result.is_err());
        assert!(
            format!("{:#}", result.unwrap_err()).contains("aul_sneaky.toml"),
            "expected the unaccounted-for file to be named in the error"
        );
        std::fs::remove_file(&zip_path).ok();
    }

    #[test]
    fn rejects_a_manifest_with_a_duplicate_file_name() {
        let manifest_toml = "\
[pack]
pack_version = 1
released_at = \"2026-09-01\"
min_peach_version = \"0.0.1\"

[[files]]
name = \"aul_a.toml\"
sha256 = \"a\"
rule_name = \"aul_a\"
rule_version = \"1\"

[[files]]
name = \"aul_a.toml\"
sha256 = \"b\"
rule_name = \"aul_a\"
rule_version = \"2\"
";
        let zip_path = temp_path("dup-name", "zip");
        write_test_zip(&zip_path, &[("manifest.toml", manifest_toml.as_bytes())]);

        let result = load_pack_bundle(&zip_path);

        assert!(result.is_err());
        std::fs::remove_file(&zip_path).ok();
    }

    #[test]
    fn not_a_zip_file_at_all_is_rejected_not_a_panic() {
        let path = temp_path("not-a-zip", "zip");
        std::fs::write(&path, b"definitely not a zip file").unwrap();

        let result = load_pack_bundle(&path);

        assert!(result.is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_plain_version_accepts_dotted_integers_and_rejects_garbage() {
        assert_eq!(parse_plain_version("0.3.0"), Some(vec![0, 3, 0]));
        assert_eq!(parse_plain_version("12.34.56"), Some(vec![12, 34, 56]));
        assert_eq!(parse_plain_version("0.3.0-beta"), None);
        assert_eq!(parse_plain_version("not.a.version"), None);
        assert_eq!(parse_plain_version(""), None);
    }

    #[test]
    fn peach_version_satisfies_compares_dotted_versions() {
        assert!(peach_version_satisfies("0.0.1"));
        assert!(peach_version_satisfies(PEACH_VERSION));
        assert!(!peach_version_satisfies("9999.0.0"));
        assert!(!peach_version_satisfies("not a version"));
    }

    #[test]
    fn apply_bundle_moves_verified_files_into_an_empty_dest_dir() {
        let rule_a: &[u8] = b"[rule]\nname = \"a\"\nversion = \"1\"\n";
        let entries: Vec<(&str, &[u8])> = vec![("aul_a.toml", rule_a)];
        let manifest_toml = sample_manifest_toml(&entries);

        let zip_path = temp_path("apply-empty", "zip");
        write_test_zip(
            &zip_path,
            &[
                ("manifest.toml", manifest_toml.as_bytes()),
                ("aul_a.toml", rule_a),
            ],
        );
        let bundle = load_pack_bundle(&zip_path).unwrap();
        let extracted_dir = bundle.extracted_dir.clone();

        let dest_dir = temp_dir_path("apply-empty-dest");
        apply_bundle(bundle, &dest_dir).unwrap();

        assert!(dest_dir.join("aul_a.toml").is_file());
        assert!(dest_dir.join("manifest.toml").is_file());
        assert!(
            !extracted_dir.exists(),
            "the scratch extraction directory should be cleaned up after apply"
        );

        std::fs::remove_file(&zip_path).ok();
        std::fs::remove_dir_all(&dest_dir).ok();
    }

    #[test]
    fn apply_bundle_wholesale_replaces_a_previously_applied_pack() {
        let dest_dir = temp_dir_path("apply-replace-dest");
        std::fs::create_dir_all(&dest_dir).unwrap();
        std::fs::write(dest_dir.join("aul_old.toml"), b"[rule]\nname = \"old\"\n").unwrap();
        std::fs::write(dest_dir.join("manifest.toml"), b"stale manifest").unwrap();

        let rule_new: &[u8] = b"[rule]\nname = \"new\"\nversion = \"1\"\n";
        let entries: Vec<(&str, &[u8])> = vec![("aul_new.toml", rule_new)];
        let manifest_toml = sample_manifest_toml(&entries);
        let zip_path = temp_path("apply-replace", "zip");
        write_test_zip(
            &zip_path,
            &[
                ("manifest.toml", manifest_toml.as_bytes()),
                ("aul_new.toml", rule_new),
            ],
        );
        let bundle = load_pack_bundle(&zip_path).unwrap();

        apply_bundle(bundle, &dest_dir).unwrap();

        assert!(
            !dest_dir.join("aul_old.toml").exists(),
            "the previous pack's rule file must not survive a wholesale replacement"
        );
        assert!(dest_dir.join("aul_new.toml").is_file());
        let manifest_contents = std::fs::read_to_string(dest_dir.join("manifest.toml")).unwrap();
        assert!(
            manifest_contents.contains("aul_new.toml"),
            "manifest.toml itself must also be replaced, not left stale"
        );

        std::fs::remove_file(&zip_path).ok();
        std::fs::remove_dir_all(&dest_dir).ok();
    }

    #[test]
    fn apply_bundle_creates_the_dest_dir_if_it_does_not_exist_yet() {
        let rule_a: &[u8] = b"[rule]\nname = \"a\"\nversion = \"1\"\n";
        let entries: Vec<(&str, &[u8])> = vec![("aul_a.toml", rule_a)];
        let manifest_toml = sample_manifest_toml(&entries);
        let zip_path = temp_path("apply-missing-dest", "zip");
        write_test_zip(
            &zip_path,
            &[
                ("manifest.toml", manifest_toml.as_bytes()),
                ("aul_a.toml", rule_a),
            ],
        );
        let bundle = load_pack_bundle(&zip_path).unwrap();

        let dest_dir = temp_dir_path("apply-missing-dest-dir");
        assert!(!dest_dir.exists());

        apply_bundle(bundle, &dest_dir).unwrap();

        assert!(dest_dir.join("aul_a.toml").is_file());

        std::fs::remove_file(&zip_path).ok();
        std::fs::remove_dir_all(&dest_dir).ok();
    }

    #[test]
    fn manifest_rule_versions_maps_rule_name_to_rule_version() {
        let manifest = PackManifest {
            pack: PackInfo {
                pack_version: 1,
                released_at: "2026-09-01".to_string(),
                min_peach_version: "0.0.1".to_string(),
            },
            files: vec![
                PackFileEntry {
                    name: "aul_a.toml".to_string(),
                    sha256: "x".to_string(),
                    rule_name: "aul_a".to_string(),
                    rule_version: "3".to_string(),
                },
                PackFileEntry {
                    name: "aul_b.toml".to_string(),
                    sha256: "y".to_string(),
                    rule_name: "aul_b".to_string(),
                    rule_version: "1".to_string(),
                },
            ],
        };

        let versions = manifest.rule_versions();

        assert_eq!(versions.get("aul_a"), Some(&"3".to_string()));
        assert_eq!(versions.get("aul_b"), Some(&"1".to_string()));
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn read_applied_manifest_returns_none_for_a_missing_directory() {
        let dir = temp_dir_path("read-manifest-missing");
        assert_eq!(read_applied_manifest(&dir), None);
    }

    #[test]
    fn read_applied_manifest_returns_none_for_a_directory_with_no_manifest() {
        let dir = temp_dir_path("read-manifest-empty");
        std::fs::create_dir_all(&dir).unwrap();

        assert_eq!(read_applied_manifest(&dir), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_applied_manifest_reads_a_valid_manifest() {
        let dir = temp_dir_path("read-manifest-valid");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.toml"),
            "[pack]\npack_version = 5\nreleased_at = \"2026-09-01\"\nmin_peach_version = \"0.0.1\"\n",
        )
        .unwrap();

        let manifest = read_applied_manifest(&dir).unwrap();

        assert_eq!(manifest.pack.pack_version, 5);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
