//! Parser for Apple's Biome/SEGB pattern-of-life logs: `.../biome/streams/`
//! folders holding one subdirectory per stream (e.g.
//! `restricted/Device.Wireless.Bluetooth/local/<file>`), each file a SEGB
//! envelope (see [`segb`]) wrapping schema-less protobuf records (see
//! [`protobuf`]).
//!
//! Unlike AUL/Android Intrusion Log (which treat their whole picked
//! directory as one atomic source, since their own cross-file needs force
//! that), **each individual SEGB file is its own independent source**
//! here — `app::collect_source_files` walks the picked `streams` folder
//! and hands this parser one file at a time (see [`is_segb_candidate`]
//! for which files even qualify). There's no cross-file resolution need
//! for Biome the way AUL's `dsc`/`uuidtext` lookups have, so nothing is
//! lost by keeping every file independent — and a lot is gained: one bad
//! or unsupported file (a currently-unimplemented SEGB v1 file, say)
//! only takes down that one source instead of the entire folder, the
//! `Source` column shows each record's *actual* originating file
//! directly (`sources.path`) rather than the whole folder, and a
//! multi-file load can run in parallel like EVTX/journald.
//!
//! Only SEGB v2 is decoded — see `segb`'s module doc comment and
//! `docs/design/biome-rule-pack-research.md` for why v1 is deliberately
//! left unimplemented rather than guessed at. A v1 file is detected and
//! surfaces a clear, visible error instead of being silently misread or
//! skipped.
//!
//! `fields` shape per record: a flat `"stream"` key (the stream name
//! derived purely from the file's path — see [`stream_name_from_path`]),
//! `"entry_state"` (`"written"`/`"deleted"`), `"crc_valid"` (bool),
//! `"record_offset"` (byte offset within the source file, for forensic
//! traceability), `"payload_hex"` (the entire undecoded payload, always
//! present regardless of decode success), and `"payload"` (the
//! [`protobuf::decode_message`] output tree, field-number-keyed). Unlike
//! iLEAPP's own curated extraction (which only attempts a protobuf decode
//! for `Written` records), every record's payload is decoded here
//! regardless of state: peach's schema-less decoder is bounded and
//! panic-free by construction (see `protobuf`'s doc comment), so there's
//! no equivalent reason to withhold the attempt for `Deleted` records,
//! whose bytes may still be perfectly intact.

pub mod protobuf;
pub mod segb;

use std::path::Path;

use anyhow::{Context, bail};
use serde_json::{Map, Value, json};

use crate::model::log_entry::ParsedRecord;
use crate::parsers::{LogParser, ParserConfig, SkippedRecord};

pub struct BiomeParser;

impl LogParser for BiomeParser {
    fn sourcetype(&self) -> &str {
        "biome"
    }

    fn parse(
        &self,
        path: &Path,
        _config: &ParserConfig,
        skip_bad_records: bool,
    ) -> anyhow::Result<(Vec<ParsedRecord>, Vec<SkippedRecord>)> {
        let stream = stream_name_from_path(path);
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read {} as a binary file", path.display()))?;

        match segb::detect_version(&bytes)? {
            segb::SegbVersion::V1 => bail!(
                "SEGB v1 file — not yet supported by Peach (only v2 is currently \
                 implemented; see docs/design/biome-rule-pack-research.md)"
            ),
            segb::SegbVersion::V2 => {
                let segb_records = segb::read_v2_records(&bytes)?;
                let mut records = Vec::new();
                let mut skipped = Vec::new();
                for (index, result) in segb_records.into_iter().enumerate() {
                    match result {
                        Ok(record) => {
                            records.push(segb_record_to_parsed_record(record, stream.as_deref()))
                        }
                        Err(err) if skip_bad_records => skipped.push(SkippedRecord {
                            location: format!("record {index}"),
                            reason: format!("{err:#}"),
                        }),
                        Err(err) => return Err(err.context(format!("record {index}"))),
                    }
                }
                Ok((records, skipped))
            }
        }
    }
}

/// Whether `p` is worth even attempting to open as a SEGB envelope —
/// `app::collect_source_files`'s filter for which files under a picked
/// `streams` folder become their own source at all. Requires the
/// immediate parent directory to be named `local` or `remote`
/// (case-insensitive) — the only place a real device export has been
/// observed to put actual stream data (verified against a real macOS
/// `.../biome/streams` export, not assumed): every single stream
/// directory in that export also carries a `lock` and a `metadata` file
/// directly under `<StreamName>/` — normal Biome runtime housekeeping
/// (a filesystem lock, per-stream bookkeeping), never log data — so
/// unlike a genuinely malformed file, encountering one of these is the
/// *guaranteed default* for every stream, not a rare exception worth
/// treating as a failed source. Also excludes hidden (dotfile) entries
/// and anything under a directory literally named `tombstone` — the same
/// filter iLEAPP's own `_stream_files` applies to this exact layout — as
/// defense in depth, even though real `tombstone/` data has also been
/// observed to nest *inside* a `local/` directory
/// (`<StreamName>/local/tombstone/<file>`), where the local/remote-parent
/// check above already excludes it on its own.
pub fn is_segb_candidate(p: &Path) -> bool {
    let parts: Vec<&str> = p
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    let under_local_or_remote = parts.len() >= 2
        && (parts[parts.len() - 2].eq_ignore_ascii_case("local")
            || parts[parts.len() - 2].eq_ignore_ascii_case("remote"));
    let hidden = p
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'));
    let tombstone = parts
        .iter()
        .any(|part| part.eq_ignore_ascii_case("tombstone"));
    under_local_or_remote && !hidden && !tombstone
}

/// Mirrors crush's `_stream_name` (`crush/parsers/segb_parser.py`) exactly:
/// the directory named after the stream, one level above a "local"/
/// "remote" leaf — pure path metadata, no payload inspection, so it works
/// identically for streams whose semantics are completely undocumented.
/// `None` for a path with too few components to contain a stream
/// directory at all. Works the same whether `file_path` is absolute (as
/// it will be in practice, since `app::collect_source_files` passes
/// whatever `walkdir` yields) or relative (as most tests use): only the
/// last 2-3 components are ever inspected.
fn stream_name_from_path(file_path: &Path) -> Option<String> {
    let parts: Vec<&str> = file_path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    if parts.len() < 2 {
        return None;
    }
    if parts[parts.len() - 2].eq_ignore_ascii_case("local")
        || parts[parts.len() - 2].eq_ignore_ascii_case("remote")
    {
        (parts.len() >= 3).then(|| parts[parts.len() - 3].to_string())
    } else {
        Some(parts[parts.len() - 2].to_string())
    }
}

fn segb_record_to_parsed_record(record: segb::SegbRecord, stream: Option<&str>) -> ParsedRecord {
    let payload_json = protobuf::decode_message(&record.payload);

    let mut fields = Map::new();
    if let Some(stream) = stream {
        fields.insert("stream".to_string(), Value::String(stream.to_string()));
    }
    fields.insert(
        "entry_state".to_string(),
        Value::String(record.state.as_str().to_string()),
    );
    fields.insert("crc_valid".to_string(), Value::Bool(record.crc_valid));
    fields.insert("record_offset".to_string(), json!(record.record_offset));
    fields.insert(
        "payload_hex".to_string(),
        Value::String(hex_encode(&record.payload)),
    );
    fields.insert("payload".to_string(), payload_json.clone());

    precompute_derived_fields(stream, &payload_json, &mut fields);

    let message = biome_message(stream, record.state, &record.payload, &payload_json);
    let fields = Value::Object(fields);
    let raw = fields.to_string();

    ParsedRecord {
        timestamp_utc: record.timestamp_utc,
        level: None,
        message: Some(message),
        raw,
        fields,
    }
}

/// Builds the human-readable `message` for a record: a named summary for
/// the dozen streams whose fields peach has documented semantics for (see
/// [`named_message_summary`]), a generic crush-style compact rendering of
/// every decoded field for anything else (see
/// `protobuf::render_payload_summary` — the same rendering crush's SEGB
/// viewer shows in its one "Payload" column, so *something* readable
/// shows even for streams nobody has ever named a field on), and only the
/// bare stream name (or nothing, if even that's unknown) when there's
/// truly no payload content to show at all. Always `"[Peach] "`-prefixed,
/// same convention as `evtx_templates`/`intrusion_log`: this is peach's
/// own reconstruction, never text the source embedded verbatim.
///
/// An all-zero-bytes payload gets its own distinct message ahead of
/// everything else, rather than falling through to
/// `render_payload_summary` and producing `"decode error: invalid field
/// number 0 at byte 0"` — technically accurate (a zero byte's tag decodes
/// to field number 0, which is invalid) but reads like something broke,
/// when in reality this is just what a deleted SEGB slot's zeroed leftover
/// bytes look like. Confirmed empirically against a real device export
/// (23,587 records): every single `_decode_error` case, with zero
/// exceptions, was an all-zero payload on an `EntryState::Deleted` record
/// — never a genuinely malformed *non-zero* payload — so this is the
/// overwhelmingly common case (not a rare edge case worth leaving
/// unclear), not a guess about what "probably" happened.
fn biome_message(
    stream: Option<&str>,
    state: segb::EntryState,
    payload_bytes: &[u8],
    payload: &Value,
) -> String {
    let Some(stream) = stream else {
        return "[Peach] Biome record (stream undetermined from path)".to_string();
    };
    if is_all_zero(payload_bytes) {
        return format!(
            "[Peach] {stream}: (no data — {} record, payload is {} zero bytes)",
            state.as_str(),
            payload_bytes.len()
        );
    }
    let detail = named_message_summary(stream, payload)
        .or_else(|| protobuf::render_payload_summary(payload));
    match detail {
        Some(detail) => format!("[Peach] {stream}: {detail}"),
        None => format!("[Peach] Biome stream: {stream}"),
    }
}

fn is_all_zero(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| b == 0)
}

/// Named, human-readable summaries for the streams peach has documented
/// field semantics for — the same dozen streams `tagging::rule`'s biome
/// `normalized_field` arm resolves `state_raw`/`wifi_ssid`/`timezone_name`/
/// etc. against (see that function's doc comment for the sourcing). `None`
/// falls through to the generic crush-style renderer in [`biome_message`],
/// not to a hard failure — a stream landing here with an unexpected shape
/// (a real device sending something the documented mapping didn't
/// anticipate) still gets *some* readable content instead of nothing.
fn named_message_summary(stream: &str, payload: &Value) -> Option<String> {
    match stream {
        "Device.ScreenLocked" | "Device.KeybagLocked" => {
            state_label(payload, 1, "Locked", "Unlocked")
        }
        "CarPlay.Connected" => state_label(payload, 1, "Connected", "Disconnected"),
        "Device.Wireless.AirplaneMode" | "Device.Power.LowPowerMode" => {
            state_label(payload, 1, "On", "Off")
        }
        "Device.Wireless.CellularDataEnabled" => state_label(payload, 1, "Enabled", "Disabled"),
        "Device.Power.PluggedIn" => state_label(payload, 1, "Plugged In", "Not Plugged In"),
        "Device.Wireless.WiFi" => {
            let ssid = payload.pointer("/1/utf8").and_then(Value::as_str);
            let state = state_label(payload, 2, "Connected", "Disconnected");
            match (ssid, state) {
                (Some(ssid), Some(state)) => Some(format!("{ssid} ({state})")),
                (Some(ssid), None) => Some(ssid.to_string()),
                (None, state) => state,
            }
        }
        "Device.TimeZone" => string_field(payload, "/2/utf8"),
        "Safari.Navigations" => string_field(payload, "/1/utf8"),
        "ProactiveHarvesting.Messages" => string_field(payload, "/10/utf8"),
        "ProactiveHarvesting.Mail" => string_field(payload, "/11/utf8"),
        "Messages.Read" => payload.pointer("/1").map(|id| format!("message id {id}")),
        "Device.Wireless.Bluetooth" => {
            let mac = string_field(payload, "/1/utf8");
            let name = string_field(payload, "/2/utf8");
            match (mac, name) {
                (Some(mac), Some(name)) => Some(format!("{name} ({mac})")),
                (Some(mac), None) => Some(mac),
                (None, name) => name,
            }
        }
        "ScreenTime.AppUsage" => string_field(payload, "/3/utf8"),
        "Keyboard.TokenFrequency" => string_field(payload, "/1/nested/1/utf8"),
        "App.Intent" => {
            let app_id = string_field(payload, "/2/utf8");
            let action = string_field(payload, "/5/utf8");
            match (app_id, action) {
                (Some(app_id), Some(action)) => Some(format!("{app_id}: {action}")),
                (Some(app_id), None) => Some(app_id),
                (None, action) => action,
            }
        }
        _ => None,
    }
}

fn string_field(payload: &Value, pointer: &str) -> Option<String> {
    payload
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// `on`/`off` label for a plain 0/1 integer field — the same `state_raw`
/// shape `tagging::rule::normalized_field` resolves, just rendered as text
/// here rather than matched. A value other than 0/1 is shown as-is rather
/// than silently mapped to one of the two labels: SEGB's own reference
/// readers document these as raw, unconfirmed values, so a surprising one
/// is worth seeing exactly, not hidden behind a guess.
fn state_label(payload: &Value, field: u64, on: &str, off: &str) -> Option<String> {
    match payload
        .pointer(&format!("/{field}"))
        .and_then(Value::as_i64)
    {
        Some(1) => Some(on.to_string()),
        Some(0) => Some(off.to_string()),
        Some(other) => Some(format!("state {other}")),
        None => None,
    }
}

/// Precomputes flat, tagging-friendly fields that can't be expressed as a
/// plain JSON-pointer lookup into `payload` — currently just
/// `ProactiveHarvesting.Mail`'s message date, whose protobuf field 3 is a
/// CFAbsoluteTime double stored as the raw bit pattern of a varint rather
/// than a literal fixed64 field, so it needs `f64::from_bits`
/// reinterpretation `tagging::rule::normalized_field` (a `Value` pointer
/// lookup, not a value-transforming function) can't perform on its own.
/// See `docs/design/biome-rule-pack-research.md`'s Tier 2 section.
fn precompute_derived_fields(
    stream: Option<&str>,
    payload: &Value,
    fields: &mut Map<String, Value>,
) {
    if stream != Some("ProactiveHarvesting.Mail") {
        return;
    }
    let Some(raw_bits) = payload.get("3").and_then(Value::as_i64) else {
        return;
    };
    let as_double = f64::from_bits(raw_bits as u64);
    if let Ok(timestamp) = segb::decode_cocoa_time(as_double) {
        fields.insert(
            "mail_message_date_utc".to_string(),
            Value::String(timestamp.to_rfc3339()),
        );
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn write_temp_dir() -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "peach-biome-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn dummy_config() -> ParserConfig {
        ParserConfig::from_toml_str("[parser]\nname = \"biome\"\nsourcetype = \"biome\"\n").unwrap()
    }

    /// A minimal, valid SEGB v2 file with a single `Written` record whose
    /// payload is a single varint field (field 1 = `value`) — enough to
    /// exercise the parser end-to-end without needing a real device
    /// export.
    fn minimal_segb2(value: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0x08); // tag: field 1, wire type 0 (varint)
        let mut v = value;
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                payload.push(byte);
                break;
            }
            payload.push(byte | 0x80);
        }

        let crc = crc32fast::hash(&payload);
        let mut entry = Vec::new();
        entry.extend_from_slice(&crc.to_le_bytes());
        entry.extend_from_slice(&0i32.to_le_bytes());
        entry.extend_from_slice(&payload);
        let end_offset = entry.len() as i32;

        let mut out = Vec::new();
        out.extend_from_slice(b"SEGB");
        out.extend_from_slice(&1i32.to_le_bytes());
        out.extend_from_slice(&0f64.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&entry);
        out.extend_from_slice(&end_offset.to_le_bytes());
        out.extend_from_slice(&1i32.to_le_bytes()); // Written
        out.extend_from_slice(&0f64.to_le_bytes());
        out
    }

    #[test]
    fn sourcetype_is_biome() {
        assert_eq!(BiomeParser.sourcetype(), "biome");
    }

    #[test]
    fn stream_name_from_path_derives_from_local_leaf() {
        let path = Path::new("restricted/Device.Wireless.Bluetooth/local/00001.segb");
        assert_eq!(
            stream_name_from_path(path),
            Some("Device.Wireless.Bluetooth".to_string())
        );
    }

    #[test]
    fn stream_name_from_path_derives_from_remote_leaf_case_insensitively() {
        let path = Path::new("public/App.Activity/REMOTE/00001.segb");
        assert_eq!(
            stream_name_from_path(path),
            Some("App.Activity".to_string())
        );
    }

    #[test]
    fn stream_name_from_path_falls_back_to_parent_dir_without_a_local_remote_leaf() {
        let path = Path::new("SomeStream/file.segb");
        assert_eq!(stream_name_from_path(path), Some("SomeStream".to_string()));
    }

    #[test]
    fn stream_name_from_path_is_none_for_too_few_components() {
        assert_eq!(stream_name_from_path(Path::new("file.segb")), None);
    }

    #[test]
    fn is_segb_candidate_requires_a_local_or_remote_parent() {
        assert!(is_segb_candidate(Path::new(
            "restricted/Device.ScreenLocked/local/0"
        )));
        assert!(is_segb_candidate(Path::new(
            "restricted/Device.ScreenLocked/REMOTE/0"
        )));
        assert!(!is_segb_candidate(Path::new(
            "restricted/Device.ScreenLocked/lock"
        )));
        assert!(!is_segb_candidate(Path::new(
            "restricted/Device.ScreenLocked/metadata"
        )));
    }

    #[test]
    fn is_segb_candidate_excludes_hidden_and_tombstone_entries() {
        assert!(!is_segb_candidate(Path::new(
            "restricted/Device.ScreenLocked/local/.DS_Store"
        )));
        assert!(!is_segb_candidate(Path::new(
            "restricted/Device.ScreenLocked/local/tombstone/0"
        )));
    }

    #[test]
    fn parses_a_single_realistic_segb_file() {
        let dir = write_temp_dir();
        let local_dir = dir.join("restricted/Device.ScreenLocked/local");
        std::fs::create_dir_all(&local_dir).unwrap();
        let file = local_dir.join("0.segb");
        std::fs::write(&file, minimal_segb2(1)).unwrap();

        let (records, skipped) = BiomeParser.parse(&file, &dummy_config(), false).unwrap();

        assert!(skipped.is_empty());
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].fields.get("stream").and_then(Value::as_str),
            Some("Device.ScreenLocked")
        );
        assert_eq!(
            records[0].fields.get("entry_state").and_then(Value::as_str),
            Some("written")
        );
        assert_eq!(
            records[0].fields.get("crc_valid").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            records[0]
                .fields
                .pointer("/payload/1")
                .and_then(Value::as_i64),
            Some(1)
        );
        assert_eq!(
            records[0].message.as_deref(),
            Some("[Peach] Device.ScreenLocked: Locked")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_non_segb_file_is_a_hard_failure_by_default_and_recorded_when_skipping() {
        let dir = write_temp_dir();
        let local_dir = dir.join("restricted/Some.Stream/local");
        std::fs::create_dir_all(&local_dir).unwrap();
        let file = local_dir.join("0.segb");
        std::fs::write(&file, b"not a segb file at all").unwrap();

        let result = BiomeParser.parse(&file, &dummy_config(), false);
        assert!(result.is_err());

        // A whole-file structural failure (bad magic) is not a per-record
        // skip — `skip_bad_records` only affects records *within* an
        // otherwise-readable file, same contract as EVTX/journald. The
        // caller (`app::run_sequential`) is what turns this `Err` into a
        // per-source skip entry, so this stays an `Err` regardless of
        // `skip_bad_records`.
        let result = BiomeParser.parse(&file, &dummy_config(), true);
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_segb_v1_file_produces_a_clear_not_yet_supported_error() {
        let dir = write_temp_dir();
        let local_dir = dir.join("restricted/Some.Stream/local");
        std::fs::create_dir_all(&local_dir).unwrap();
        let file = local_dir.join("0.segb");
        let mut v1_header = vec![0u8; 56];
        v1_header[52..56].copy_from_slice(b"SEGB");
        std::fs::write(&file, v1_header).unwrap();

        let result = BiomeParser.parse(&file, &dummy_config(), false);
        let err = result.unwrap_err();
        assert!(format!("{err:#}").contains("v1"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn deleted_records_still_appear_rather_than_vanishing() {
        let dir = write_temp_dir();
        let local_dir = dir.join("restricted/Some.Stream/local");
        std::fs::create_dir_all(&local_dir).unwrap();
        let file = local_dir.join("0.segb");

        // Build a file with a single Deleted-state record by hand.
        let payload = vec![0x08, 0x01]; // field 1 = 1
        let crc = crc32fast::hash(&payload);
        let mut entry = Vec::new();
        entry.extend_from_slice(&crc.to_le_bytes());
        entry.extend_from_slice(&0i32.to_le_bytes());
        entry.extend_from_slice(&payload);
        let end_offset = entry.len() as i32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SEGB");
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0f64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&entry);
        bytes.extend_from_slice(&end_offset.to_le_bytes());
        bytes.extend_from_slice(&3i32.to_le_bytes()); // Deleted
        bytes.extend_from_slice(&0f64.to_le_bytes());
        std::fs::write(&file, bytes).unwrap();

        let (records, _) = BiomeParser.parse(&file, &dummy_config(), false).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].fields.get("entry_state").and_then(Value::as_str),
            Some("deleted")
        );
        // The payload is still decoded even though the record is deleted.
        assert_eq!(
            records[0]
                .fields
                .pointer("/payload/1")
                .and_then(Value::as_i64),
            Some(1)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn precompute_derived_fields_decodes_proactive_mail_message_date() {
        let mut fields = Map::new();
        let date = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let cocoa_seconds = date.timestamp() as f64 - 978_307_200.0;
        let raw_bits = cocoa_seconds.to_bits() as i64;
        let payload = json!({ "3": raw_bits });

        precompute_derived_fields(Some("ProactiveHarvesting.Mail"), &payload, &mut fields);

        let stored = fields
            .get("mail_message_date_utc")
            .and_then(Value::as_str)
            .unwrap();
        let parsed = DateTime::parse_from_rfc3339(stored).unwrap();
        assert_eq!(parsed.timestamp(), date.timestamp());
    }

    #[test]
    fn precompute_derived_fields_does_nothing_for_other_streams() {
        let mut fields = Map::new();
        let payload = json!({ "3": 12345 });

        precompute_derived_fields(Some("ScreenTime.AppUsage"), &payload, &mut fields);

        assert!(fields.is_empty());
    }

    #[test]
    fn biome_message_uses_the_named_summary_when_one_exists() {
        let payload = json!({"1": 1});
        assert_eq!(
            biome_message(
                Some("Device.KeybagLocked"),
                segb::EntryState::Written,
                b"\x08\x01",
                &payload
            ),
            "[Peach] Device.KeybagLocked: Locked"
        );
        assert_eq!(
            biome_message(
                Some("Device.Power.PluggedIn"),
                segb::EntryState::Written,
                b"\x08\x00",
                &json!({"1": 0})
            ),
            "[Peach] Device.Power.PluggedIn: Not Plugged In"
        );
    }

    #[test]
    fn biome_message_falls_back_to_the_generic_renderer_for_unnamed_streams() {
        let payload = json!({"1": 42});
        assert_eq!(
            biome_message(
                Some("Some.Unmapped.Stream"),
                segb::EntryState::Written,
                b"\x08\x2a",
                &payload
            ),
            "[Peach] Some.Unmapped.Stream: 1: 42"
        );
    }

    #[test]
    fn biome_message_falls_back_to_the_bare_stream_name_when_payload_is_empty() {
        assert_eq!(
            biome_message(
                Some("Some.Unmapped.Stream"),
                segb::EntryState::Written,
                b"",
                &json!({})
            ),
            "[Peach] Biome stream: Some.Unmapped.Stream"
        );
    }

    #[test]
    fn biome_message_handles_an_undetermined_stream() {
        assert_eq!(
            biome_message(None, segb::EntryState::Written, b"", &json!({})),
            "[Peach] Biome record (stream undetermined from path)"
        );
    }

    /// Regression guard for the exact bug report this was built for: an
    /// all-zero-bytes payload (what a deleted SEGB slot's leftover data
    /// looks like) must never surface as
    /// `"decode error: invalid field number 0 at byte 0"` — technically
    /// true but reads like something broke.
    #[test]
    fn biome_message_gives_an_all_zero_payload_a_clear_message_naming_the_state() {
        assert_eq!(
            biome_message(
                Some("Device.Charging.SmartCharging"),
                segb::EntryState::Deleted,
                &[0u8; 6],
                &json!({"_decode_error": "invalid field number 0 at byte 0"})
            ),
            "[Peach] Device.Charging.SmartCharging: (no data — deleted record, payload is 6 zero bytes)"
        );
    }

    #[test]
    fn named_message_summary_combines_ssid_and_state_for_wifi() {
        let payload = json!({
            "1": {"utf8": "HomeNet", "nested": null, "hex": "..."},
            "2": 1
        });
        assert_eq!(
            named_message_summary("Device.Wireless.WiFi", &payload),
            Some("HomeNet (Connected)".to_string())
        );
    }

    #[test]
    fn named_message_summary_combines_app_id_and_action_for_app_intent() {
        let payload = json!({
            "2": {"utf8": "com.example.app", "nested": null, "hex": "..."},
            "5": {"utf8": "SHARE", "nested": null, "hex": "..."}
        });
        assert_eq!(
            named_message_summary("App.Intent", &payload),
            Some("com.example.app: SHARE".to_string())
        );
    }

    #[test]
    fn state_label_shows_the_raw_value_for_anything_other_than_0_or_1() {
        let payload = json!({"1": 4});
        assert_eq!(
            state_label(&payload, 1, "On", "Off"),
            Some("state 4".to_string())
        );
    }
}
