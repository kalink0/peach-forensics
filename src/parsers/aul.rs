use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use macos_unifiedlogs::filesystem::LogarchiveProvider;
use macos_unifiedlogs::parser::{build_log, collect_timesync, parse_log};
use macos_unifiedlogs::traits::{FileProvider, SourceFile};
use macos_unifiedlogs::unified_log::{LogData, UnifiedLogData};

use crate::model::log_entry::ParsedRecord;
use crate::parsers::{LogParser, ParserConfig, SkippedRecord, StreamingProgress};

mod bounded_cache;
mod raw_extraction_provider;
use bounded_cache::BoundedStringCache;
use raw_extraction_provider::RawExtractionProvider;

/// Wraps the `macos-unifiedlogs` crate to parse Apple Unified Log
/// `.logarchive` bundles.
///
/// Unlike the other sourcetypes, an AUL source is a whole **directory**
/// (`Persist`/`Special`/`Signpost`/`HighVolume` subfolders holding
/// `.tracev3` files, plus `dsc`/`uuidtext`/`timesync` reference data needed
/// to resolve the actual log strings), not a single file. That's fine here:
/// since [`crate::model::event_id::SourceFileId`] is a randomly-assigned id
/// rather than a content hash, nothing about `event_id` assignment cares
/// whether `path` is a file or a directory.
///
/// One `.logarchive` = one peach source. It typically holds several
/// `.tracev3` files whose entries are interleaved in time. Entries are
/// handed on in source order — `.tracev3` files in the provider's sorted
/// path order, entries in their order within each file — so
/// [`crate::parsers::parse_source`] assigns the same sequence numbers to the
/// same input every time. Chronological order is the timeline query's job
/// (`ORDER BY timestamp_utc, event_id_source, event_id_seq`), not the
/// parser's, so only one `.tracev3` file's entries are ever in memory at
/// once. Collecting and sorting every entry of the whole archive up front
/// instead grew past 20 GB of RSS on a real 817 MB iOS `.logarchive` (601
/// MB of `.tracev3` data) and wrote nothing to DuckDB until parsing had
/// finished. `parse` (the non-streaming trait method) is just a thin
/// `parse_streaming` + collect for callers that want the whole `Vec` at once
/// — it holds every entry in memory, so it is unsuitable for real archives.
///
/// Deliberately out of scope for this first version: the crate's
/// oversize-string second pass (entries whose format string lives in a
/// *different* `.tracev3` file's oversize data than the entry itself only
/// get a single-pass resolution attempt; unresolved ones surface as an
/// explicit "Failed to get string message..." message rather than being
/// dropped) — worth revisiting once this is exercised against real
/// fixtures. Also: no config-driven field-mapping (`ParserConfig.extra` is
/// unused) — the mapping below is fixed.
///
/// Testing note: this module's tests exercise the mapping/ordering logic
/// against hand-built [`LogData`] values, not a real `.logarchive` — the
/// binary tracev3 parsing itself is already covered by
/// `macos-unifiedlogs`'s own extensive test suite, not re-verified here.
pub struct AulParser;

impl LogParser for AulParser {
    fn sourcetype(&self) -> &str {
        "aul"
    }

    fn parse(
        &self,
        path: &Path,
        config: &ParserConfig,
        skip_bad_records: bool,
    ) -> anyhow::Result<(Vec<ParsedRecord>, Vec<SkippedRecord>)> {
        let mut records = Vec::new();
        let skipped = self.parse_streaming(
            path,
            config,
            &mut |record| {
                records.push(record);
                Ok(())
            },
            &mut StreamingProgress {
                on_bytes: &mut |_| {},
            },
            skip_bad_records,
        )?;
        Ok((records, skipped))
    }

    /// Calls `progress.on_bytes` once per `.tracev3` file finished, after
    /// that file's entries have all reached `sink` — the finest granularity
    /// available, since a `.tracev3` file is decompressed and resolved as a
    /// whole before its first entry exists.
    fn parse_streaming(
        &self,
        path: &Path,
        _config: &ParserConfig,
        sink: &mut dyn FnMut(ParsedRecord) -> anyhow::Result<()>,
        progress: &mut StreamingProgress,
        skip_bad_records: bool,
    ) -> anyhow::Result<Vec<SkippedRecord>> {
        if !path.is_dir() {
            bail!(
                "AUL source {} is not a directory (expected a .logarchive bundle)",
                path.display()
            );
        }

        match select_provider(path)? {
            AulProvider::Bundle(provider) => {
                parse_with_provider(provider, path, sink, progress, skip_bad_records)
            }
            AulProvider::RawExtraction(provider) => {
                parse_with_provider(provider, path, sink, progress, skip_bad_records)
            }
        }
    }
}

/// Either of the two AUL layouts DFIR analysts actually hand Peach — see
/// [`select_provider`] for how one gets picked.
enum AulProvider {
    /// A flattened `.logarchive` bundle, as `log collect` produces:
    /// `Persist`/`Special`/etc. and the `dsc`/uuidtext hex directories all
    /// sit directly under one root.
    Bundle(LogarchiveProvider),
    /// A raw filesystem extraction, where the tracev3 data and the
    /// uuidtext/dsc reference data live in two separate directory trees —
    /// see [`raw_extraction_provider`] for why that split matters.
    RawExtraction(RawExtractionProvider),
}

/// Shared body of [`AulParser::parse_streaming`], generic over which concrete
/// [`AulProvider`] variant is in play.
///
/// `macos-unifiedlogs` 0.7 made `FileProvider`/`SourceFile` return `impl
/// Trait` from their iterator/reader methods, which means neither trait is
/// object-safe any more — the `&dyn FileProvider` indirection this used
/// before (`AulProvider::as_dyn`/`as_dyn_mut`) no longer compiles. Generics
/// are the replacement: this function gets monomorphized once per concrete
/// provider type instead, which is also why `provider` no longer needs to be
/// `&mut` — `build_log` takes it by shared reference now that per-provider
/// uuidtext/dsc caching has moved to the `cache` parameter below.
fn parse_with_provider(
    provider: impl FileProvider,
    path: &Path,
    sink: &mut dyn FnMut(ParsedRecord) -> anyhow::Result<()>,
    progress: &mut StreamingProgress,
    skip_bad_records: bool,
) -> anyhow::Result<Vec<SkippedRecord>> {
    let timesync_data = collect_timesync(&provider).context("failed to read AUL timesync data")?;

    let tracev3_files: Vec<_> = provider.tracev3_files().collect();
    if tracev3_files.is_empty() {
        bail!("no .tracev3 files found under {}", path.display());
    }

    // Byte-budgeted rather than `MemoryStringCache::default()`'s plain
    // unbounded `HashMap` — see `BoundedStringCache` for why neither that
    // nor a small count cap works.
    let cache = BoundedStringCache::new();

    let mut skipped = Vec::new();
    for mut file in tracev3_files {
        let source_path = file.source_path().to_string();
        // A malformed `.tracev3` file within the archive — every other
        // file in the `.logarchive` is independently readable, so skip
        // mode just moves on to the next one rather than losing
        // everything in the whole directory over one bad sub-file.
        let unified_log_data = match read_tracev3(&mut file, &source_path) {
            Ok(Some(data)) => data,
            Ok(None) => continue,
            Err(err) if skip_bad_records => {
                skipped.push(SkippedRecord {
                    location: source_path.clone(),
                    reason: format!("{err:#}"),
                });
                continue;
            }
            Err(err) => return Err(err),
        };

        let (log_data, _unresolved_oversize) =
            build_log(&unified_log_data, &provider, &cache, &timesync_data, false);
        // `unified_log_data` holds this file's decompressed chunks; drop it
        // before handing entries on so only one file's data is alive.
        drop(unified_log_data);
        for (index, entry) in log_data.into_iter().enumerate() {
            // Each `entry` already came out of a successfully-parsed
            // tracev3 file — a failure here is `to_parsed_record`'s own
            // JSON-serialization step on one already-resolved entry, fully
            // independent of every other entry, so it's always safe to skip
            // and continue (unlike journald's structural case).
            match to_parsed_record(entry) {
                Ok(record) => sink(record)?,
                Err(err) if skip_bad_records => skipped.push(SkippedRecord {
                    location: format!("{source_path}, entry {index}"),
                    reason: format!("{err:#}"),
                }),
                Err(err) => return Err(err),
            }
        }
        let file_bytes = std::fs::metadata(&source_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        (progress.on_bytes)(file_bytes);
    }
    Ok(skipped)
}

/// First four bytes of an AppleDouble file.
const APPLE_DOUBLE_MAGIC: [u8; 4] = [0x00, 0x05, 0x16, 0x07];

/// Parses one `.tracev3` file, or returns `None` if it is an AppleDouble
/// file rather than log data.
///
/// macOS writes a `._<name>` AppleDouble companion next to every file it
/// copies to a volume without native extended-attribute support (exFAT,
/// FAT, SMB shares), so a `.logarchive` that passed through one carries a
/// `._<hex>.tracev3` beside each real `.tracev3`. The crate's providers
/// match those by extension alone. They hold only extended attributes, not
/// log entries, so they are ignored like the archive's other non-log files
/// (`Info.plist`, `logd.0.log`). A `._` name alone is not enough: only a
/// file whose content starts with the AppleDouble magic is ignored, and
/// anything else is parsed — and fails visibly — like any other file.
fn read_tracev3(
    file: &mut impl SourceFile,
    source_path: &str,
) -> anyhow::Result<Option<UnifiedLogData>> {
    let is_apple_double_name = Path::new(source_path)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("._"));

    let parsed = if is_apple_double_name {
        let mut data = Vec::new();
        file.reader()
            .read_to_end(&mut data)
            .with_context(|| format!("failed to read tracev3 file {source_path}"))?;
        if data.starts_with(&APPLE_DOUBLE_MAGIC) {
            return Ok(None);
        }
        parse_log(data.as_slice(), source_path)
    } else {
        parse_log(file.reader(), source_path)
    };
    parsed
        .map(Some)
        .with_context(|| format!("failed to parse tracev3 file {source_path}"))
}

/// Names of the `diagnostics` subfolders that hold `.tracev3` files.
/// Matching at least [`DIAGNOSTICS_MIN_MATCHES`] of these (rather than
/// requiring all of them) tolerates a partial extraction that's missing
/// one category.
const DIAGNOSTICS_SUBDIRS: &[&str] = &["Persist", "Special", "Signpost", "HighVolume", "timesync"];
const DIAGNOSTICS_MIN_MATCHES: usize = 2;

/// Picks the right provider for `path`, distinguishing a flattened
/// `.logarchive` bundle from a raw filesystem extraction — the two layouts
/// actually seen in practice (mobile acquisitions are almost always the
/// latter; a `log collect` export is the former). Three cases, checked in
/// order:
///
/// 1. `path` itself looks like a flat bundle (has `diagnostics`-style
///    subfolders *and* `dsc`/uuidtext-hex-dirs directly inside it) →
///    [`LogarchiveProvider`], unchanged from before.
/// 2. `path` looks like a raw `diagnostics` folder on its own (has the
///    subfolders but not the string-resolution data) → look for a sibling
///    `uuidtext` folder next to it.
/// 3. `path` has `diagnostics` and `uuidtext` as children (the parent of
///    both was selected) → use those two directly.
///
/// Anything else falls back to treating `path` as a flat bundle — the
/// original, only behavior before raw-extraction support existed, so
/// nothing already working regresses.
fn select_provider(path: &Path) -> anyhow::Result<AulProvider> {
    if looks_like_flat_bundle(path) {
        return Ok(AulProvider::Bundle(LogarchiveProvider::new(path)));
    }

    if is_diagnostics_dir(path) {
        let uuidtext_root = path
            .parent()
            .and_then(|parent| find_child_case_insensitive(parent, "uuidtext"))
            .ok_or_else(|| {
                anyhow!(
                    "{} looks like a raw AUL 'diagnostics' folder, but no sibling \
                     'uuidtext' folder was found next to it — AUL string resolution \
                     needs both. Place the extraction's uuidtext folder next to this one.",
                    path.display()
                )
            })?;
        return Ok(AulProvider::RawExtraction(RawExtractionProvider::new(
            path.to_path_buf(),
            uuidtext_root,
        )));
    }

    if let (Some(diagnostics_root), Some(uuidtext_root)) = (
        find_child_case_insensitive(path, "diagnostics"),
        find_child_case_insensitive(path, "uuidtext"),
    ) {
        return Ok(AulProvider::RawExtraction(RawExtractionProvider::new(
            diagnostics_root,
            uuidtext_root,
        )));
    }

    Ok(AulProvider::Bundle(LogarchiveProvider::new(path)))
}

fn looks_like_flat_bundle(path: &Path) -> bool {
    is_diagnostics_dir(path) && has_direct_string_resolution_data(path)
}

fn is_diagnostics_dir(path: &Path) -> bool {
    let Ok(names) = dir_names(path) else {
        return false;
    };
    DIAGNOSTICS_SUBDIRS
        .iter()
        .filter(|name| names.iter().any(|n| n.eq_ignore_ascii_case(name)))
        .count()
        >= DIAGNOSTICS_MIN_MATCHES
}

fn has_direct_string_resolution_data(path: &Path) -> bool {
    let Ok(names) = dir_names(path) else {
        return false;
    };
    names.iter().any(|name| {
        name.eq_ignore_ascii_case("dsc")
            || (name.len() == 2 && name.chars().all(|c| c.is_ascii_hexdigit()))
    })
}

fn find_child_case_insensitive(dir: &Path, wanted: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .find_map(|entry| {
            if !entry.file_type().ok()?.is_dir() {
                return None;
            }
            entry
                .file_name()
                .to_str()?
                .eq_ignore_ascii_case(wanted)
                .then(|| entry.path())
        })
}

/// Names of the direct subdirectories of `path` (files are ignored).
fn dir_names(path: &Path) -> std::io::Result<Vec<String>> {
    Ok(std::fs::read_dir(path)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect())
}

/// Maps one resolved AUL [`LogData`] entry to a [`ParsedRecord`].
///
/// `level` is the [`macos_unifiedlogs::unified_log::LogType`] variant name
/// verbatim (e.g. `"Error"`, `"ProcessSignpostStart"`) rather than being
/// forced into an INFO/WARN/ERROR scheme nobody asked for. `raw`/`fields`
/// both hold the full serialized `LogData` — for a binary source there's no
/// literal "original line", so the complete structured extraction before
/// any field-mapping is the most faithful equivalent of "raw".
///
/// `fields` is serialized from `entry` once; `raw` is then rendered from
/// `fields` rather than serialized from `entry` a second time — same bytes
/// (`Value`'s `Display` impl produces the identical compact JSON
/// `serde_json::to_string` would), one fewer full independent copy of every
/// entry's data held at once. At AUL's typical entry volume that's not a
/// cosmetic saving — see the module-level doc comment.
fn to_parsed_record(entry: LogData) -> anyhow::Result<ParsedRecord> {
    // `entry.time` is unix-epoch nanoseconds as f64; at this magnitude f64
    // only has ~256ns resolution (already the crate's own precision limit),
    // so round-then-cast is as faithful as the source data allows.
    let timestamp_utc = DateTime::<Utc>::from_timestamp_nanos(entry.time.round() as i64);
    let level = Some(format!("{:?}", entry.log_type));
    let message = Some(entry.message.clone());
    let fields = serde_json::to_value(&entry).context("failed to serialize AUL log entry")?;
    let raw = fields.to_string();

    Ok(ParsedRecord {
        timestamp_utc,
        level,
        message,
        raw,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use macos_unifiedlogs::unified_log::{EventType, LogType};

    fn sample_log_data(time: f64, message: &str, log_type: LogType) -> LogData {
        LogData {
            subsystem: "com.example.peach".to_string(),
            thread_id: 1,
            pid: 100,
            euid: 0,
            library: "/usr/lib/example".to_string(),
            library_uuid: "AAAA".to_string(),
            activity_id: 0,
            parent_activity_id: 0,
            time,
            category: "general".to_string(),
            event_type: EventType::Log,
            log_type,
            process: "/usr/bin/example".to_string(),
            process_uuid: "BBBB".to_string(),
            message: message.to_string(),
            raw_message: message.to_string(),
            boot_uuid: "CCCC".to_string(),
            timezone_name: "UTC".to_string(),
            message_entries: Vec::new(),
            timestamp: String::new(),
            message_flags: Vec::new(),
            evidence: "test.tracev3".to_string(),
        }
    }

    #[test]
    fn to_parsed_record_converts_nanosecond_epoch_time_to_utc() {
        // 2022-01-01T00:00:00Z in unix-epoch nanoseconds.
        let entry = sample_log_data(1_640_995_200_000_000_000.0, "hello", LogType::Info);

        let record = to_parsed_record(entry).unwrap();

        assert_eq!(
            record.timestamp_utc,
            DateTime::parse_from_rfc3339("2022-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn to_parsed_record_uses_log_type_variant_name_as_level() {
        let entry = sample_log_data(0.0, "hello", LogType::ProcessSignpostStart);

        let record = to_parsed_record(entry).unwrap();

        assert_eq!(record.level.as_deref(), Some("ProcessSignpostStart"));
    }

    #[test]
    fn to_parsed_record_preserves_message_and_full_entry_in_raw_and_fields() {
        let entry = sample_log_data(0.0, "something happened", LogType::Error);

        let record = to_parsed_record(entry).unwrap();

        assert_eq!(record.message.as_deref(), Some("something happened"));
        assert!(record.raw.contains("something happened"));
        assert!(record.raw.contains("com.example.peach"));
        assert_eq!(
            record.fields.get("subsystem").and_then(|v| v.as_str()),
            Some("com.example.peach")
        );
        assert_eq!(
            record.fields.get("message").and_then(|v| v.as_str()),
            Some("something happened")
        );
    }

    #[test]
    fn raw_is_derived_from_fields_not_reserialized_independently() {
        let entry = sample_log_data(0.0, "something happened", LogType::Error);

        let record = to_parsed_record(entry).unwrap();

        // `raw` must round-trip to exactly the same JSON tree as `fields` —
        // it's rendered from `fields`, not from a second independent
        // serialization of the source `LogData`.
        let raw_reparsed: serde_json::Value = serde_json::from_str(&record.raw).unwrap();
        assert_eq!(raw_reparsed, record.fields);
    }

    #[test]
    fn parse_rejects_a_path_that_is_not_a_directory() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "peach-aul-test-not-a-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"not a logarchive").unwrap();

        let config =
            ParserConfig::from_toml_str("[parser]\nname = \"aul\"\nsourcetype = \"aul\"\n")
                .unwrap();
        let result = AulParser.parse(&path, &config, false);

        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }

    /// Regression test for the "skip bad records" invariant: `false` must
    /// still hard-fail when a `.tracev3` file can't be parsed, exactly as
    /// before this parameter existed. Real tracev3 binary parsing itself
    /// isn't hand-buildable in a unit test (same reasoning as this module's
    /// other tests, see its "Testing note") — garbage bytes are enough to
    /// exercise the failure path regardless of what's actually inside.
    #[test]
    fn skip_bad_records_false_still_hard_fails_on_a_malformed_tracev3_file() {
        let root = temp_test_dir("malformed-tracev3-skip-off");
        std::fs::create_dir_all(root.join("Persist")).unwrap();
        std::fs::create_dir_all(root.join("dsc")).unwrap();
        std::fs::create_dir_all(root.join("00")).unwrap();
        std::fs::write(
            root.join("Persist").join("0000001.tracev3"),
            b"not a real tracev3",
        )
        .unwrap();

        let config =
            ParserConfig::from_toml_str("[parser]\nname = \"aul\"\nsourcetype = \"aul\"\n")
                .unwrap();
        let result = AulParser.parse(&root, &config, false);

        assert!(result.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skip_bad_records_true_skips_a_malformed_tracev3_file_instead_of_failing() {
        let root = temp_test_dir("malformed-tracev3-skip-on");
        std::fs::create_dir_all(root.join("Persist")).unwrap();
        std::fs::create_dir_all(root.join("dsc")).unwrap();
        std::fs::create_dir_all(root.join("00")).unwrap();
        std::fs::write(
            root.join("Persist").join("0000001.tracev3"),
            b"not a real tracev3",
        )
        .unwrap();

        let config =
            ParserConfig::from_toml_str("[parser]\nname = \"aul\"\nsourcetype = \"aul\"\n")
                .unwrap();
        let (records, skipped) = AulParser.parse(&root, &config, true).unwrap();

        assert!(records.is_empty(), "the only tracev3 file was malformed");
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].location.ends_with(".tracev3"));

        std::fs::remove_dir_all(root).unwrap();
    }

    /// A `._*.tracev3` AppleDouble file must not fail the load, even with
    /// skip mode off.
    #[test]
    fn an_apple_double_tracev3_companion_is_ignored_not_parsed() {
        let root = temp_test_dir("apple-double");
        std::fs::create_dir_all(root.join("Persist")).unwrap();
        std::fs::create_dir_all(root.join("dsc")).unwrap();
        std::fs::create_dir_all(root.join("00")).unwrap();
        let mut apple_double = APPLE_DOUBLE_MAGIC.to_vec();
        apple_double.extend_from_slice(b"\x00\x02\x00\x00Mac OS X        ");
        std::fs::write(root.join("Persist").join("._0000001.tracev3"), apple_double).unwrap();

        let config =
            ParserConfig::from_toml_str("[parser]\nname = \"aul\"\nsourcetype = \"aul\"\n")
                .unwrap();
        let (records, skipped) = AulParser.parse(&root, &config, false).unwrap();

        assert!(records.is_empty());
        assert!(skipped.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    /// The `._` name alone must not hide a file: without the AppleDouble
    /// magic it is parsed like any other `.tracev3` and fails visibly.
    #[test]
    fn a_dot_underscore_name_without_apple_double_magic_is_still_parsed() {
        let root = temp_test_dir("dot-underscore-not-apple-double");
        std::fs::create_dir_all(root.join("Persist")).unwrap();
        std::fs::create_dir_all(root.join("dsc")).unwrap();
        std::fs::create_dir_all(root.join("00")).unwrap();
        std::fs::write(
            root.join("Persist").join("._0000001.tracev3"),
            b"not a real tracev3",
        )
        .unwrap();

        let config =
            ParserConfig::from_toml_str("[parser]\nname = \"aul\"\nsourcetype = \"aul\"\n")
                .unwrap();
        let err = AulParser.parse(&root, &config, false).unwrap_err();

        assert!(format!("{err:#}").contains("._0000001.tracev3"));

        std::fs::remove_dir_all(root).unwrap();
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "peach-aul-layout-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn select_provider_picks_bundle_for_a_flat_logarchive_layout() {
        let root = temp_test_dir("flat-bundle");
        std::fs::create_dir_all(root.join("Persist")).unwrap();
        std::fs::create_dir_all(root.join("Special")).unwrap();
        std::fs::create_dir_all(root.join("dsc")).unwrap();
        std::fs::create_dir_all(root.join("00")).unwrap();

        let provider = select_provider(&root).unwrap();

        assert!(matches!(provider, AulProvider::Bundle(_)));
    }

    #[test]
    fn select_provider_picks_raw_extraction_when_diagnostics_has_a_sibling_uuidtext() {
        let parent = temp_test_dir("sibling-parent");
        let diagnostics = parent.join("diagnostics");
        std::fs::create_dir_all(diagnostics.join("Persist")).unwrap();
        std::fs::create_dir_all(diagnostics.join("Special")).unwrap();
        std::fs::create_dir_all(parent.join("uuidtext")).unwrap();

        let provider = select_provider(&diagnostics).unwrap();

        assert!(matches!(provider, AulProvider::RawExtraction(_)));
    }

    #[test]
    fn select_provider_errors_clearly_when_diagnostics_has_no_sibling_uuidtext() {
        let parent = temp_test_dir("no-sibling-parent");
        let diagnostics = parent.join("diagnostics");
        std::fs::create_dir_all(diagnostics.join("Persist")).unwrap();
        std::fs::create_dir_all(diagnostics.join("Special")).unwrap();

        let result = select_provider(&diagnostics);

        let Err(err) = result else {
            panic!("expected an error when uuidtext is missing");
        };
        assert!(err.to_string().contains("uuidtext"));
    }

    #[test]
    fn select_provider_picks_raw_extraction_when_parent_holds_both_children() {
        let parent = temp_test_dir("parent-with-both");
        std::fs::create_dir_all(parent.join("diagnostics").join("Persist")).unwrap();
        std::fs::create_dir_all(parent.join("diagnostics").join("Special")).unwrap();
        std::fs::create_dir_all(parent.join("uuidtext").join("00")).unwrap();

        let provider = select_provider(&parent).unwrap();

        assert!(matches!(provider, AulProvider::RawExtraction(_)));
    }

    #[test]
    fn select_provider_matching_is_case_insensitive_for_uuidtext_and_diagnostics() {
        let parent = temp_test_dir("case-insensitive");
        std::fs::create_dir_all(parent.join("Diagnostics").join("Persist")).unwrap();
        std::fs::create_dir_all(parent.join("Diagnostics").join("Special")).unwrap();
        std::fs::create_dir_all(parent.join("UUIDText").join("00")).unwrap();

        let provider = select_provider(&parent).unwrap();

        assert!(matches!(provider, AulProvider::RawExtraction(_)));
    }

    #[test]
    fn select_provider_falls_back_to_bundle_for_an_unrecognized_layout() {
        let root = temp_test_dir("unrecognized");
        std::fs::create_dir_all(root.join("some_other_folder")).unwrap();

        let provider = select_provider(&root).unwrap();

        assert!(matches!(provider, AulProvider::Bundle(_)));
    }
}
