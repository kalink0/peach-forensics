use std::path::Path;

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use evtx::{EvtxParser as EvtxCrateParser, ParserSettings, SerializedEvtxRecord};

use crate::model::log_entry::ParsedRecord;
use crate::parsers::evtx_templates;
use crate::parsers::{LogParser, ParserConfig};

/// Wraps the `evtx` crate to parse Windows Event Log (`.evtx`) files.
///
/// `level` is the raw `Event.System.Level` JSON value verbatim (usually a
/// small integer per the Windows Event Schema, e.g. 2=Error, 3=Warning,
/// 4=Informational) — not remapped into an invented ERROR/WARN/INFO scheme,
/// consistent with how [`crate::parsers::aul`] handles `LogType`.
///
/// `message` is `Event.RenderingInfo.Message` when present, falling back to
/// [`evtx_templates::render_for_event`]'s built-in template for this
/// `(provider, event_id)` when there is one, `None` otherwise.
/// `RenderingInfo` is an *optional* sibling of `System`/`EventData` under
/// `Event` (`RenderingInfoType`, `minOccurs="0"` in Microsoft's own
/// MS-EVEN6 schema, bundled with the `evtx` crate) — present when the file
/// was produced by something that rendered the event before writing it out
/// (e.g. Windows Event Forwarding's collector side), absent for a plain
/// live `winevt\Logs\*.evtx` read directly, since real rendering needs the
/// source machine's message-resource DLLs/templates, which this crate
/// deliberately doesn't ship or emulate — the template fallback exists for
/// exactly that common case. A template-rendered message is Peach's own
/// reconstruction, not source-provided text, so it's visibly prefixed (see
/// `evtx_templates`'s module doc comment) rather than presented as if it
/// were a real `RenderingInfo.Message`; a real one always takes precedence
/// when present. `EventData` is preserved in full in `raw`/`fields`
/// regardless, so nothing is lost either way.
///
/// No config-driven field-mapping, like AUL — `ParserConfig.extra` is
/// unused.
///
/// Parsed with `separate_json_attributes(true)`: many XML elements in the
/// Windows Event Schema carry an attribute alongside their text content
/// (most commonly `<EventID Qualifiers="16384">4111</EventID>` on
/// older/manifest-free providers like MsiInstaller or the Service Control
/// Manager, common in `Application.evtx`). With the crate's default
/// settings, such an element serializes as a nested object
/// (`{"#text": 4111, "#attributes": {"Qualifiers": 16384}}`) rather than a
/// plain value — `timeline_queries::extracted_field_sql`'s
/// `json_extract_string($.Event.System.EventID)` would then return that
/// whole object stringified instead of just `4111`. `separate_json_attributes`
/// moves the attribute out to a sibling `EventID_attributes` key and leaves
/// `EventID` a plain value in both cases (with or without an attribute),
/// which is what every `extracted_field_sql` JSON path here assumes. Nothing
/// is lost either way — the attribute is still in `fields` under its
/// `_attributes` sibling key, just addressed differently; see
/// `extracted_field_sql`'s doc comment for the exact paths this affects.
///
/// A single unparseable record aborts the whole parse with context (which
/// record index), consistent with the text and AUL parsers — the crate's
/// per-record `Result` carries no partial data on error (not even a
/// timestamp), so there's nothing to represent as a visible-but-broken
/// timeline entry the way AUL's oversize-string failures can be. A
/// per-source opt-in "skip and log bad records" mode would need a shared
/// change to `LogParser::parse`'s return shape, not a one-off here, so it
/// isn't built yet.
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
            .with_context(|| format!("failed to open EVTX file {}", path.display()))?
            .with_configuration(ParserSettings::new().separate_json_attributes(true));

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
    let message = record
        .data
        .pointer("/Event/RenderingInfo/Message")
        .and_then(json_value_to_plain_string)
        .or_else(|| template_rendered_message(&record.data));

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
        message,
        raw,
        fields,
    })
}

/// [`evtx_templates::render_for_event`]'s result for this record's
/// `(Event.System.Provider_attributes.Name, Event.System.EventID)`, or
/// `None` when either is missing/not the expected JSON type — a record
/// this malformed has no template lookup to even attempt, not an error
/// worth surfacing (the record's raw `Event.System` is preserved in
/// `fields`/`raw` regardless). `Provider_attributes` (not `Provider`) and a
/// plain-number `EventID` are both a direct consequence of parsing with
/// `separate_json_attributes(true)`, same as `timeline_queries::
/// extracted_field_sql`'s paths — see this module's struct-level doc
/// comment.
fn template_rendered_message(data: &serde_json::Value) -> Option<String> {
    let provider = data
        .pointer("/Event/System/Provider_attributes/Name")
        .and_then(|v| v.as_str())?;
    let event_id = data
        .pointer("/Event/System/EventID")
        .and_then(|v| v.as_u64())? as u32;
    let event_data = data.pointer("/Event/EventData");
    evtx_templates::render_for_event(provider, event_id, event_data)
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
    fn message_is_none_without_rendering_info_or_a_matching_template() {
        // No RenderingInfo (the common case for a plain live
        // winevt\Logs\*.evtx read directly) and no `Provider`/`EventID` to
        // even attempt a built-in-template lookup against — message stays
        // empty, not fabricated from EventData or anything else.
        let record = sample_record(
            1,
            jiff::Timestamp::from_second(0).unwrap(),
            serde_json::json!({"Event": {"System": {}, "EventData": {"TargetUserName": "bob"}}}),
        );

        let parsed = to_parsed_record(record).unwrap();

        assert_eq!(parsed.message, None);
    }

    #[test]
    fn message_falls_back_to_a_built_in_template_when_the_provider_and_event_id_match() {
        // 4624 ("An account was successfully logged on") is one of the
        // shipped `message_templates/examples/evtx_security_auditing.toml`
        // entries — this exercises the real embedded template, not a
        // hand-built stand-in, so a change to the shipped wording that
        // breaks the placeholder contract would show up here too.
        let record = sample_record(
            1,
            jiff::Timestamp::from_second(0).unwrap(),
            serde_json::json!({
                "Event": {
                    "System": {
                        "Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"},
                        "EventID": 4624
                    },
                    "EventData": {"TargetUserName": "bob", "TargetDomainName": "CORP"}
                }
            }),
        );

        let parsed = to_parsed_record(record).unwrap();

        let message = parsed
            .message
            .expect("expected a template-rendered message");
        assert!(
            message.starts_with(evtx_templates::RENDERED_PREFIX),
            "template-rendered messages must be visibly marked as Peach's own \
             reconstruction, not source-provided text: {message}"
        );
        assert!(message.contains("bob"));
        assert!(message.contains("CORP"));
    }

    #[test]
    fn rendering_info_message_takes_precedence_over_a_matching_template() {
        // A real, source-provided message must never be overwritten by
        // Peach's own reconstruction — even when a built-in template for
        // this exact (provider, event_id) also exists.
        let record = sample_record(
            1,
            jiff::Timestamp::from_second(0).unwrap(),
            serde_json::json!({
                "Event": {
                    "System": {
                        "Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"},
                        "EventID": 4624
                    },
                    "EventData": {"TargetUserName": "bob"},
                    "RenderingInfo": {"Message": "the real, source-provided text"}
                }
            }),
        );

        let parsed = to_parsed_record(record).unwrap();

        assert_eq!(
            parsed.message.as_deref(),
            Some("the real, source-provided text")
        );
    }

    #[test]
    fn message_is_taken_from_rendering_info_when_present() {
        // RenderingInfo appears when the source file was produced by
        // something that rendered the event before writing it out (e.g.
        // Windows Event Forwarding) — confirmed via Microsoft's own
        // MS-EVEN6 schema (`RenderingInfoType`, bundled with the `evtx`
        // crate), not guessed.
        let record = sample_record(
            1,
            jiff::Timestamp::from_second(0).unwrap(),
            serde_json::json!({
                "Event": {
                    "System": {},
                    "RenderingInfo": {
                        "Message": "An account failed to log on.",
                        "Level": "Information"
                    }
                }
            }),
        );

        let parsed = to_parsed_record(record).unwrap();

        assert_eq!(
            parsed.message.as_deref(),
            Some("An account failed to log on.")
        );
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
