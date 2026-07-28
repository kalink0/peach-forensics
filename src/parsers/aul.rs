use std::path::Path;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use macos_unifiedlogs::filesystem::LogarchiveProvider;
use macos_unifiedlogs::parser::{build_log, collect_timesync, parse_log};
use macos_unifiedlogs::traits::FileProvider;
use macos_unifiedlogs::unified_log::LogData;

use crate::model::log_entry::ParsedRecord;
use crate::parsers::{LogParser, ParserConfig};

/// Wraps the `macos-unifiedlogs` crate to parse Apple Unified Log
/// `.logarchive` bundles — section 5/9 of CLAUDE.md.
///
/// Unlike the other sourcetypes, an AUL source is a whole **directory**
/// (`Persist`/`Special`/`Signpost`/`HighVolume` subfolders holding
/// `.tracev3` files, plus `dsc`/`uuidtext`/`timesync` reference data needed
/// to resolve the actual log strings), not a single file. That's fine here:
/// since [`crate::model::event_id::SourceFileId`] is a randomly-assigned id
/// rather than a content hash (see the `source-file-id-design` project
/// note), nothing about `event_id` assignment cares whether `path` is a
/// file or a directory.
///
/// One `.logarchive` = one peach source. It typically holds several
/// `.tracev3` files whose entries are interleaved in time, so there's no
/// single natural "file order" — entries are combined and sorted by
/// (resolved timestamp, source `.tracev3` path, position within that file)
/// before [`crate::parsers::parse_source`] assigns sequence numbers, so the
/// same input always produces the same order.
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

    fn parse(&self, path: &Path, _config: &ParserConfig) -> anyhow::Result<Vec<ParsedRecord>> {
        if !path.is_dir() {
            bail!(
                "AUL source {} is not a directory (expected a .logarchive bundle)",
                path.display()
            );
        }

        let mut provider = LogarchiveProvider::new(path);
        let timesync_data =
            collect_timesync(&provider).context("failed to read AUL timesync data")?;

        let tracev3_files: Vec<_> = provider.tracev3_files().collect();
        if tracev3_files.is_empty() {
            bail!("no .tracev3 files found under {}", path.display());
        }

        let mut collected: Vec<(f64, String, usize, LogData)> = Vec::new();
        for mut file in tracev3_files {
            let source_path = file.source_path().to_string();
            let unified_log_data = parse_log(file.reader(), &source_path)
                .with_context(|| format!("failed to parse tracev3 file {source_path}"))?;

            let (log_data, _unresolved_oversize) =
                build_log(&unified_log_data, &mut provider, &timesync_data, false);
            for (index, entry) in log_data.into_iter().enumerate() {
                collected.push((entry.time, source_path.clone(), index, entry));
            }
        }

        order_entries(collected)
            .into_iter()
            .map(to_parsed_record)
            .collect()
    }
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
/// any field-mapping is the most faithful equivalent of "raw" (section 0.1).
fn to_parsed_record(entry: LogData) -> anyhow::Result<ParsedRecord> {
    // `entry.time` is unix-epoch nanoseconds as f64; at this magnitude f64
    // only has ~256ns resolution (already the crate's own precision limit),
    // so round-then-cast is as faithful as the source data allows.
    let timestamp_utc = DateTime::<Utc>::from_timestamp_nanos(entry.time.round() as i64);
    let level = Some(format!("{:?}", entry.log_type));
    let message = Some(entry.message.clone());
    let raw = serde_json::to_string(&entry).context("failed to serialize AUL log entry")?;
    let fields = serde_json::to_value(&entry).context("failed to serialize AUL log entry")?;

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
}
