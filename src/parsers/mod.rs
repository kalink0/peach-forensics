use std::path::Path;

use thiserror::Error;

use crate::model::event_id::{EventId, SequenceCounter, SourceFileId};
use crate::model::log_entry::{LogEntry, ParsedRecord};

pub mod aul;
pub mod evtx;
pub mod journald;
pub mod text_config;

/// Configuration for one parser instance, deserialized from a parser TOML
/// file. `name`/`sourcetype` are typed since every
/// parser needs them (e.g. for onboarding/registry lookups); everything
/// else stays as a raw [`toml::Table`] because the shape differs sharply
/// between text-based parsers (regex + capture-group mapping,
/// `multiline_start_pattern`) and binary parsers (field-mapping only) —
/// each concrete [`LogParser`] implementation (milestones 6-9) interprets
/// its own slice of `extra`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ParserConfig {
    pub parser: ParserConfigBody,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ParserConfigBody {
    pub name: String,
    pub sourcetype: String,
    #[serde(flatten)]
    pub extra: toml::Table,
}

#[derive(Debug, Error)]
#[error("invalid parser config: {0}")]
pub struct ParserConfigError(#[from] toml::de::Error);

impl ParserConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, ParserConfigError> {
        Ok(toml::from_str(s)?)
    }
}

/// Implemented by every concrete parser (text-config, EVTX, AUL, journald).
///
/// `parse` returns [`ParsedRecord`]s rather than [`LogEntry`]s on purpose:
/// assigning the stable [`EventId`] is centralized in [`parse_source`], so
/// `source_file_id`/`sequence_number` assignment is identical and
/// deterministic no matter which parser produced the data.
///
/// `: Sync` so a `&dyn LogParser` can be shared with the parser worker
/// threads `app.rs::run_load` spawns for a multi-file folder load — every
/// implementor here is a stateless unit struct, so this costs nothing.
pub trait LogParser: Sync {
    fn sourcetype(&self) -> &str;
    fn parse(&self, path: &Path, config: &ParserConfig) -> anyhow::Result<Vec<ParsedRecord>>;

    /// Streams parsed records to `sink` one at a time instead of collecting
    /// them all into memory first. The default implementation just calls
    /// [`Self::parse`] and replays its result through `sink` — fine for
    /// sourcetypes that haven't shown a memory problem in practice.
    ///
    /// AUL overrides this: a real device's `.logarchive` can resolve into
    /// millions of entries, and materializing all of them (each carrying a
    /// serialized `raw`/`fields` JSON copy) in one `Vec` before the first
    /// row reaches DuckDB is what drove a 219 MB source past 45 GB of RSS
    /// during testing — DuckDB, not the Rust heap, is supposed to hold the
    /// bulk timeline.
    fn parse_streaming(
        &self,
        path: &Path,
        config: &ParserConfig,
        sink: &mut dyn FnMut(ParsedRecord) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        for record in self.parse(path, config)? {
            sink(record)?;
        }
        Ok(())
    }
}

/// Parses `path` with `parser` and assigns each resulting record a stable
/// [`EventId`]: a fresh [`SourceFileId`] (assigned once per call, not
/// derived from `path`) shared by every record, and a
/// [`SequenceNumber`](crate::model::event_id::SequenceNumber) strictly
/// ascending in parse order.
pub fn parse_source(
    parser: &dyn LogParser,
    path: &Path,
    config: &ParserConfig,
) -> anyhow::Result<Vec<LogEntry>> {
    let source_file_id = SourceFileId::new_random();
    let records = parser.parse(path, config)?;

    let mut sequence_counter = SequenceCounter::new();
    Ok(records
        .into_iter()
        .map(|record| LogEntry {
            event_id: EventId {
                source_file_id,
                sequence_number: sequence_counter.next_sequence_number(),
            },
            timestamp_utc: record.timestamp_utc,
            level: record.level,
            message: record.message,
            raw: record.raw,
            fields: record.fields,
        })
        .collect())
}

/// Streaming counterpart to [`parse_source`]: hands each [`LogEntry`] to
/// `sink` as soon as its [`EventId`] is assigned, rather than collecting a
/// `Vec<LogEntry>` first. Returns the [`SourceFileId`] assigned for this
/// parse run (generated up front, independent of how many records — if
/// any — `sink` ends up seeing), so callers can still record a `sources`
/// row without needing to hold onto a first entry.
pub fn parse_source_streaming(
    parser: &dyn LogParser,
    path: &Path,
    config: &ParserConfig,
    mut sink: impl FnMut(LogEntry) -> anyhow::Result<()>,
) -> anyhow::Result<SourceFileId> {
    let source_file_id = SourceFileId::new_random();
    let mut sequence_counter = SequenceCounter::new();

    parser.parse_streaming(path, config, &mut |record| {
        sink(LogEntry {
            event_id: EventId {
                source_file_id,
                sequence_number: sequence_counter.next_sequence_number(),
            },
            timestamp_utc: record.timestamp_utc,
            level: record.level,
            message: record.message,
            raw: record.raw,
            fields: record.fields,
        })
    })?;

    Ok(source_file_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::io::Write;
    use std::path::PathBuf;

    struct DummyParser {
        record_count: usize,
    }

    impl LogParser for DummyParser {
        fn sourcetype(&self) -> &str {
            "dummy"
        }

        fn parse(&self, _path: &Path, _config: &ParserConfig) -> anyhow::Result<Vec<ParsedRecord>> {
            Ok((0..self.record_count)
                .map(|i| ParsedRecord {
                    timestamp_utc: Utc::now(),
                    level: None,
                    message: Some(format!("entry {i}")),
                    raw: format!("raw entry {i}"),
                    fields: serde_json::Value::Null,
                })
                .collect())
        }
    }

    fn write_temp_file(name: &str, content: &[u8]) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "peach-parsers-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content).unwrap();
        path
    }

    fn dummy_config() -> ParserConfig {
        ParserConfig::from_toml_str("[parser]\nname = \"dummy\"\nsourcetype = \"dummy\"\n").unwrap()
    }

    #[test]
    fn parse_source_assigns_consistent_source_file_id_and_ascending_sequence_numbers() {
        let path = write_temp_file("a", b"dummy source content");
        let parser = DummyParser { record_count: 3 };
        let config = dummy_config();

        let entries = parse_source(&parser, &path, &config).unwrap();

        assert_eq!(entries.len(), 3);
        let source_file_id = entries[0].event_id.source_file_id;
        for entry in &entries {
            assert_eq!(entry.event_id.source_file_id, source_file_id);
        }
        assert_eq!(entries[0].event_id.sequence_number.value(), 0);
        assert_eq!(entries[1].event_id.sequence_number.value(), 1);
        assert_eq!(entries[2].event_id.sequence_number.value(), 2);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn parse_source_streaming_assigns_the_same_ids_as_the_collecting_version() {
        let path = write_temp_file("b", b"dummy source content");
        let parser = DummyParser { record_count: 3 };
        let config = dummy_config();

        let mut streamed = Vec::new();
        let source_file_id = parse_source_streaming(&parser, &path, &config, |entry| {
            streamed.push(entry);
            Ok(())
        })
        .unwrap();

        assert_eq!(streamed.len(), 3);
        for entry in &streamed {
            assert_eq!(entry.event_id.source_file_id, source_file_id);
        }
        assert_eq!(streamed[0].event_id.sequence_number.value(), 0);
        assert_eq!(streamed[1].event_id.sequence_number.value(), 1);
        assert_eq!(streamed[2].event_id.sequence_number.value(), 2);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn default_parse_streaming_replays_parse_results_in_order() {
        let path = write_temp_file("c", b"dummy source content");
        let parser = DummyParser { record_count: 3 };
        let config = dummy_config();

        let mut seen = Vec::new();
        parser
            .parse_streaming(&path, &config, &mut |record| {
                seen.push(record.message.clone());
                Ok(())
            })
            .unwrap();

        assert_eq!(
            seen,
            vec![
                Some("entry 0".to_string()),
                Some("entry 1".to_string()),
                Some("entry 2".to_string()),
            ]
        );

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn parser_config_round_trips_the_nginx_example() {
        let toml_text = r#"
[parser]
name = "nginx_access"
sourcetype = "nginx"

[parser.pattern]
regex = '^(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+)'
timestamp_format = "%d/%b/%Y:%H:%M:%S %z"

[parser.field_mapping]
level = "status"
message = "request"
"#;

        let config = ParserConfig::from_toml_str(toml_text).unwrap();

        assert_eq!(config.parser.name, "nginx_access");
        assert_eq!(config.parser.sourcetype, "nginx");
        assert!(config.parser.extra.contains_key("pattern"));
        assert!(config.parser.extra.contains_key("field_mapping"));
    }

    #[test]
    fn malformed_parser_config_is_an_error_not_a_panic() {
        let result = ParserConfig::from_toml_str("this is not valid toml [[[");

        assert!(result.is_err());
    }
}
