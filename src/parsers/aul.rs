use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use macos_unifiedlogs::filesystem::LogarchiveProvider;
use macos_unifiedlogs::parser::{build_log, collect_timesync, parse_log};
use macos_unifiedlogs::traits::FileProvider;
use macos_unifiedlogs::unified_log::LogData;

use crate::model::log_entry::ParsedRecord;
use crate::parsers::{LogParser, ParserConfig, StreamingProgress};

mod raw_extraction_provider;
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
/// `.tracev3` files whose entries are interleaved in time, so there's no
/// single natural "file order" — entries are combined and sorted by
/// (resolved timestamp, source `.tracev3` path, position within that file)
/// before [`crate::parsers::parse_source`] assigns sequence numbers, so the
/// same input always produces the same order. That sort needs every
/// resolved entry in memory at once (there's no getting around it without a
/// proper streaming k-way merge across files, which is a bigger project for
/// if this ever stops being enough) — but the actual [`LogParser::parse`]
/// implementation lives in `parse_streaming` and hands each entry to its
/// caller as soon as it's converted, instead of *also* collecting a second,
/// fully-JSON-serialized `Vec<ParsedRecord>` on top of the sorted
/// `Vec<LogData>`. That second collection is what turned a 219 MB real-device
/// `.logarchive` into 45+ GB of RSS during testing: every entry existed
/// three times over (the resolved `LogData`, plus independently-serialized
/// `raw` and `fields` copies) before a single row reached DuckDB. `parse`
/// (the non-streaming trait method) is now just a thin `parse_streaming` +
/// collect for callers that still want the whole `Vec` at once.
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

    fn parse(&self, path: &Path, config: &ParserConfig) -> anyhow::Result<Vec<ParsedRecord>> {
        let mut records = Vec::new();
        self.parse_streaming(
            path,
            config,
            &mut |record| {
                records.push(record);
                Ok(())
            },
            &mut StreamingProgress {
                on_bytes: &mut |_| {},
                on_total_known: &mut |_| {},
            },
        )?;
        Ok(records)
    }

    /// Calls `progress.on_bytes` once per `.tracev3` file finished, not
    /// once per entry: entries only start reaching `sink` in the second
    /// loop below, after every file has already been parsed and resolved
    /// (see the module doc comment on why the cross-file sort needs that) —
    /// an entry-count-based signal would stay at zero for the entire first
    /// pass, which on a real multi-hundred-MB `.logarchive` is most of the
    /// wall-clock time. Byte progress checkpointed per source file, the way
    /// iLEAPP's own `unifiedlog_iterator`-driven import does it, is the
    /// finest granularity available without re-architecting around a
    /// streaming k-way merge (see that same doc comment).
    ///
    /// `progress.on_total_known` fires exactly once, right before the
    /// second loop starts: `collected.len()` is the final entry count at
    /// that point (every file has been parsed, nothing more will be
    /// added), and it's the only moment AUL can offer this — before it,
    /// the count isn't finished growing; during the second loop, `sink`
    /// already needs a total to be useful, not a value arriving alongside
    /// it. Reported here instead of always being unknown (the default
    /// [`LogParser::parse_streaming`] behavior) is what lets a caller show
    /// a real percentage for the DB insert/tagging work that follows
    /// parsing, instead of just a raw climbing count with no sense of how
    /// much is left — the exact gap a flat byte-progress bar leaves once
    /// parsing itself finishes but insert/tagging (usually the larger
    /// share of total load time) is still running.
    fn parse_streaming(
        &self,
        path: &Path,
        _config: &ParserConfig,
        sink: &mut dyn FnMut(ParsedRecord) -> anyhow::Result<()>,
        progress: &mut StreamingProgress,
    ) -> anyhow::Result<()> {
        if !path.is_dir() {
            bail!(
                "AUL source {} is not a directory (expected a .logarchive bundle)",
                path.display()
            );
        }

        let mut provider = select_provider(path)?;
        let timesync_data =
            collect_timesync(provider.as_dyn()).context("failed to read AUL timesync data")?;

        let tracev3_files: Vec<_> = provider.as_dyn().tracev3_files().collect();
        if tracev3_files.is_empty() {
            bail!("no .tracev3 files found under {}", path.display());
        }

        let mut collected: Vec<(f64, String, usize, LogData)> = Vec::new();
        for mut file in tracev3_files {
            let source_path = file.source_path().to_string();
            let unified_log_data = parse_log(file.reader(), &source_path)
                .with_context(|| format!("failed to parse tracev3 file {source_path}"))?;

            let (log_data, _unresolved_oversize) = build_log(
                &unified_log_data,
                provider.as_dyn_mut(),
                &timesync_data,
                false,
            );
            for (index, entry) in log_data.into_iter().enumerate() {
                collected.push((entry.time, source_path.clone(), index, entry));
            }
            let file_bytes = std::fs::metadata(&source_path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            (progress.on_bytes)(file_bytes);
        }

        (progress.on_total_known)(collected.len());
        for entry in order_entries(collected) {
            sink(to_parsed_record(entry)?)?;
        }
        Ok(())
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

impl AulProvider {
    fn as_dyn(&self) -> &dyn FileProvider {
        match self {
            AulProvider::Bundle(provider) => provider,
            AulProvider::RawExtraction(provider) => provider,
        }
    }

    fn as_dyn_mut(&mut self) -> &mut dyn FileProvider {
        match self {
            AulProvider::Bundle(provider) => provider,
            AulProvider::RawExtraction(provider) => provider,
        }
    }
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

/// Sorts combined entries from every `.tracev3` file in one logarchive into
/// a single deterministic order: by resolved timestamp, then by which
/// `.tracev3` file it came from, then by its position within that file.
fn order_entries(mut entries: Vec<(f64, String, usize, LogData)>) -> Vec<LogData> {
    entries.sort_by(|a, b| {
        a.0.total_cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    entries.into_iter().map(|(_, _, _, entry)| entry).collect()
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
    fn order_entries_sorts_by_time_then_source_path_then_index() {
        let entries = vec![
            (
                2.0,
                "b.tracev3".to_string(),
                0,
                sample_log_data(2.0, "second", LogType::Info),
            ),
            (
                1.0,
                "a.tracev3".to_string(),
                1,
                sample_log_data(1.0, "first-b", LogType::Info),
            ),
            (
                1.0,
                "a.tracev3".to_string(),
                0,
                sample_log_data(1.0, "first-a", LogType::Info),
            ),
        ];

        let ordered = order_entries(entries);

        assert_eq!(
            ordered
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>(),
            vec!["first-a", "first-b", "second"]
        );
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
        let result = AulParser.parse(&path, &config);

        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
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
