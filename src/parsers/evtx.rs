use std::path::Path;

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use evtx::{EvtxParser as EvtxCrateParser, SerializedEvtxRecord};

use crate::model::log_entry::ParsedRecord;
use crate::parsers::{LogParser, ParserConfig};

/// Wraps the `evtx` crate to parse Windows Event Log (`.evtx`) files —
/// section 5/9 of CLAUDE.md.
///
/// `level` is the raw `Event.System.Level` JSON value verbatim (usually a
/// small integer per the Windows Event Schema, e.g. 2=Error, 3=Warning,
/// 4=Informational) — not remapped into an invented ERROR/WARN/INFO scheme,
/// consistent with how [`crate::parsers::aul`] handles `LogType`.
///
/// `message` is always `None`: the crate doesn't render human-readable
/// event text (that needs the OS's message-resource DLLs/templates, which
/// it deliberately doesn't ship). `EventData` is preserved in full in
/// `raw`/`fields` instead, so nothing is lost — it's just not in the
/// at-a-glance column for this sourcetype.
///
/// No config-driven field-mapping, like AUL — `ParserConfig.extra` is
/// unused.
///
/// A single unparseable record aborts the whole parse with context (which
/// record index), consistent with the text and AUL parsers — the crate's
/// per-record `Result` carries no partial data on error (not even a
/// timestamp), so there's nothing to represent as a visible-but-broken
/// timeline entry the way AUL's oversize-string failures can be. A
/// per-source opt-in "skip and log bad records" mode is planned but not
/// built yet (see the `parser-error-handling-roadmap` project note) — it
/// needs a shared change to `LogParser::parse`'s return shape, not a
/// one-off here.
///
/// Testing note: like `aul.rs`, this module's tests exercise the
/// mapping/conversion logic against hand-built records, not a real
/// `.evtx` file — the binary chunk/record parsing itself is already
/// covered by the `evtx` crate's own test suite.
pub struct EvtxFileParser;

impl LogParser for EvtxFileParser {
    fn sourcetype(&self) -> &str {
        "evtx"
    }

    fn parse(&self, path: &Path, _config: &ParserConfig) -> anyhow::Result<Vec<ParsedRecord>> {
        let mut parser = EvtxCrateParser::from_path(path)
            .with_context(|| format!("failed to open EVTX file {}", path.display()))?;

        parser
            .records_json_value()
            .enumerate()
            .map(|(index, record)| {
                let record = record.with_context(|| format!("record {index}: failed to parse"))?;
                to_parsed_record(record)
            })
            .collect()
    }
}

fn to_parsed_record(
    record: SerializedEvtxRecord<serde_json::Value>,
) -> anyhow::Result<ParsedRecord> {
    let event_record_id = record.event_record_id;
    let timestamp_utc = jiff_timestamp_to_utc(record.timestamp)
        .with_context(|| format!("record {event_record_id}: invalid timestamp"))?;

    let level = record
        .data
        .pointer("/Event/System/Level")
        .and_then(json_value_to_plain_string);

    let event = record
        .data
        .get("Event")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let fields = serde_json::json!({
        "event_record_id": event_record_id,
        "Event": event,
    });
    let raw = serde_json::to_string(&fields).context("failed to serialize EVTX record")?;

    Ok(ParsedRecord {
        timestamp_utc,
        level,
        message: None,
        raw,
        fields,
    })
}

/// EVTX timestamps are already absolute (UTC) — unlike the text parser,
/// there's no source-timezone ambiguity to resolve here.
fn jiff_timestamp_to_utc(ts: jiff::Timestamp) -> anyhow::Result<DateTime<Utc>> {
    let text = ts.to_string();
    DateTime::parse_from_rfc3339(&text)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| anyhow!("'{text}' is not valid RFC3339: {err}"))
}

fn json_value_to_plain_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(
        event_record_id: u64,
        timestamp: jiff::Timestamp,
        data: serde_json::Value,
    ) -> SerializedEvtxRecord<serde_json::Value> {
        SerializedEvtxRecord {
            event_record_id,
            timestamp,
            data,
        }
    }

    #[test]
    fn jiff_timestamp_converts_to_the_same_instant_in_utc() {
        let ts = jiff::Timestamp::from_second(1_735_689_600).unwrap(); // 2025-01-01T00:00:00Z
        let converted = jiff_timestamp_to_utc(ts).unwrap();
        assert_eq!(
            converted,
            DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn level_is_taken_verbatim_as_a_plain_string() {
        let record = sample_record(
            1,
            jiff::Timestamp::from_second(0).unwrap(),
            serde_json::json!({"Event": {"System": {"Level": 2}}}),
        );

        let parsed = to_parsed_record(record).unwrap();

        assert_eq!(parsed.level.as_deref(), Some("2"));
    }

    #[test]
    fn message_is_always_none() {
        let record = sample_record(
            1,
            jiff::Timestamp::from_second(0).unwrap(),
            serde_json::json!({"Event": {"System": {}, "EventData": {"TargetUserName": "bob"}}}),
        );

        let parsed = to_parsed_record(record).unwrap();

        assert_eq!(parsed.message, None);
    }

    #[test]
    fn raw_and_fields_carry_the_event_record_id_and_full_event() {
        let record = sample_record(
            42,
            jiff::Timestamp::from_second(0).unwrap(),
            serde_json::json!({"Event": {"System": {"EventID": 4625}}}),
        );

        let parsed = to_parsed_record(record).unwrap();

        assert_eq!(
            parsed
                .fields
                .get("event_record_id")
                .and_then(|v| v.as_u64()),
            Some(42)
        );
        assert_eq!(
            parsed
                .fields
                .pointer("/Event/System/EventID")
                .and_then(|v| v.as_u64()),
            Some(4625)
        );
        assert!(parsed.raw.contains("4625"));
    }

    #[test]
    fn missing_level_is_none_not_an_error() {
        let record = sample_record(
            1,
            jiff::Timestamp::from_second(0).unwrap(),
            serde_json::json!({"Event": {"System": {}}}),
        );

        let parsed = to_parsed_record(record).unwrap();

        assert_eq!(parsed.level, None);
    }
}
