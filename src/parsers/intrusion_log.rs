//! Parser for Android's **Intrusion Logging** feature (Advanced Protection
//! Mode, Android 16+, built by Google with Amnesty International's
//! Security Lab specifically for spyware/"consensual" forensic analysis —
//! see the Amnesty Security Lab's announcement:
//! <https://securitylab.amnesty.org/latest/2026/05/android-intrusion-logging-as-a-new-source-of-data-for-consensual-forensic-analysis/>).
//!
//! The logs themselves are collected once daily on-device, end-to-end
//! encrypted, and stored in the user's Google account — decrypting and
//! exporting them is outside Peach's scope (a cloud/account-credential
//! operation, not a local read-only file), and is handled by
//! [AndroidQF](https://github.com/mvt-project/androidqf) or the [Mobile
//! Verification Toolkit](https://github.com/mvt-project/mvt) (both from
//! Amnesty's Security Lab), or by a dedicated Android acquisition tool
//! like [ALEX](https://github.com/prosch88/ALEX), during acquisition.
//! This parser picks up from
//! there: once already extracted to a local `intrusion-logs/` directory
//! (AndroidQF's own output layout), it reads exactly the same
//! newline-delimited JSON format MVT's own `mvt-android
//! check-intrusion-logs` command does.
//!
//! **Format**, verified directly against MVT's `intrusion_logs` module
//! (`src/mvt/android/modules/intrusion_logs/`, MVT License 1.1) and
//! cross-confirmed against ALEAPP's independent `intrusion_logging.py`
//! artifact (both parse real device exports of this format), rather than
//! guessed from documentation: every `.txt` file under the source directory
//! (searched recursively — AndroidQF's daily rotations can nest) holds one
//! JSON object per line, each wrapping a single event under one top-level
//! key naming its type:
//!
//! ```text
//! {"dns_event": {"event_time": 1746979200000, "hostname": "example.com", "ip_addresses": ["93.184.216.34"], "package_name": "com.example.app"}}
//! {"connect_event": {"event_time": 1746979201000, "ip_address": "93.184.216.34", "port": 443, "package_name": "com.example.app"}}
//! {"security_event": {"event_time": 1746979202000, "keyguard_dismiss_auth_attempt": {"success": false, "method_strength": 1}}}
//! ```
//!
//! `event_time` is Unix epoch, but **the unit differs by event type** —
//! milliseconds for `dns_event`/`connect_event`, nanoseconds for
//! `security_event` (confirmed in MVT's `process_event` for each: the
//! former divide by `1000.0`, the latter by `1_000_000_000.0`). Getting
//! this wrong would silently misplace every security event by roughly a
//! million-fold in the timeline, so it's handled per event type explicitly
//! here rather than with one shared conversion.
//!
//! `security_event` nests one level deeper than the other two: alongside
//! `event_time` there's exactly one more key naming the specific event
//! (e.g. `keyguard_dismiss_auth_attempt`, `adb_shell_cmd`,
//! `cert_authority_installed` — the ~46 tags Android's own [SecurityLog
//! API](https://developer.android.com/reference/android/app/admin/SecurityLog)
//! defines, verified against AOSP's own `SecurityLogTags.logtags` — see
//! [`security_event_display_name`]), whose value is that
//! event's own detail object. `fields` preserves this nesting exactly as
//! found (forensic traceability — nothing here is flattened away), and adds
//! two derived, flat lookup keys on top: `event_type` (the outer key, always
//! present) and, for `security_event` specifically, `security_event_tag`
//! (the inner key) — so a tagging rule can match on
//! `security_event_tag = "keyguard_dismiss_auth_attempt"` without needing
//! "does this object have key X" semantics `tagging::rule::Rule::matches`
//! doesn't support. Neither derived key ever overwrites real event data:
//! `event_type`/`security_event_tag` aren't field names Android's own
//! schema uses for anything else.
//!
//! `message` is a reconstructed, human-readable one-line summary — not
//! present verbatim in the source JSON, so (same convention as
//! `parsers::evtx_templates`) always prefixed `"[Peach] "` to mark it as
//! derived rather than source text. Unlike MVT's own ~46 hand-written
//! per-tag sentences, this renders the event's detail object generically
//! (sorted `key=value` pairs) rather than a bespoke sentence per tag —
//! simpler to keep correct across a catalogue this size, and arguably more
//! faithful: it shows the actual field names Android recorded rather than a
//! paraphrase of them. The full structured detail is always in `fields`
//! regardless.
//!
//! An event whose one-and-only top-level key isn't `dns_event`,
//! `connect_event`, or `security_event` is not silently dropped: since
//! Android's own docs describe this feature as one "the supported events is
//! likely to be expanded over time" (MVT's own methodology notes the same),
//! guessing a timestamp unit for an unrecognized event type would risk
//! silently misplacing it in the timeline — worse than surfacing it as an
//! unparseable line via `skip_bad_records`/a hard error, same treatment any
//! other malformed record gets.

use std::path::Path;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use crate::model::log_entry::ParsedRecord;
use crate::parsers::{LogParser, ParserConfig, SkippedRecord};

/// `security_event`'s own metadata keys — everything in that event's inner
/// object that *isn't* one of these is the tag name (see the module doc
/// comment's nesting explanation). `event_type`/`timestamp` never appear in
/// the raw JSON this parser reads (only `event_id`/`event_time` do — see
/// AOSP's `SecurityLogTags.logtags`) but are kept out of the tag-name
/// search anyway, in case a future Android version starts emitting them
/// directly.
const SECURITY_EVENT_METADATA_KEYS: &[&str] =
    &["event_id", "event_time", "event_type", "timestamp"];

/// A human-readable display name for [`security_event_message`], derived
/// mechanically from `tag_key` (the same string this module matches
/// `security_event_tag` against, verified against AOSP's own
/// `SecurityLogTags.logtags` — see the module doc comment): snake_case
/// underscores become spaces, each word capitalized, with a short list of
/// acronyms kept fully uppercase rather than title-cased. Deliberately
/// *not* a lookup table transcribed from anywhere — this only ever
/// produces cosmetic text, not something used in matching, so mirroring
/// the "SecurityLogTags name minus `security_` prefix" pattern
/// algorithmically here means never asserting one more "this exact display
/// string is accurate" claim than [`SECURITY_EVENT_METADATA_KEYS`]'s tag
/// key list itself already does. Falls back to the tag key wrapped
/// unmodified if it's not made of ASCII letters/digits/underscores, rather
/// than producing something misleading for input this function wasn't
/// designed for.
fn security_event_display_name(tag_key: &str) -> String {
    const ACRONYMS: &[&str] = &["ADB", "OS", "NFC", "DNS"];

    if !tag_key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return tag_key.to_string();
    }

    tag_key
        .split('_')
        .filter(|word| !word.is_empty())
        .map(|word| {
            if let Some(acronym) = ACRONYMS
                .iter()
                .find(|acronym| acronym.eq_ignore_ascii_case(word))
            {
                acronym.to_string()
            } else {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().chain(chars).collect(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

/// Reads Android Intrusion Logging exports: `path` a directory (searched
/// recursively for `.txt` files, matching AndroidQF's own
/// `intrusion-logs/` layout) — same "one directory = one source" shape as
/// [`crate::parsers::aul::AulParser`], for the same reason: these events
/// don't naturally split into one-source-per-file the way EVTX/journald
/// do, and [`crate::model::event_id::SourceFileId`] being a random id
/// rather than a content hash means nothing about event-id assignment
/// cares whether `path` is a file or a directory either way.
///
/// No config-driven field-mapping, like AUL/EVTX/journald —
/// `ParserConfig.extra` is unused.
pub struct IntrusionLogParser;

impl LogParser for IntrusionLogParser {
    fn sourcetype(&self) -> &str {
        "intrusion_log"
    }

    fn parse(
        &self,
        path: &Path,
        _config: &ParserConfig,
        skip_bad_records: bool,
    ) -> anyhow::Result<(Vec<ParsedRecord>, Vec<SkippedRecord>)> {
        let mut files: Vec<std::path::PathBuf> = walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
            })
            .collect();
        files.sort();

        if files.is_empty() {
            bail!("no intrusion-log .txt files found under {}", path.display());
        }

        let mut records = Vec::new();
        let mut skipped = Vec::new();

        for file in &files {
            let file_label = file
                .strip_prefix(path)
                .unwrap_or(file)
                .display()
                .to_string();
            let content = std::fs::read_to_string(file)
                .with_context(|| format!("failed to read {} as UTF-8 text", file.display()))?;

            for (line_num, line) in content.lines().enumerate() {
                let line_num = line_num + 1;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match parse_line(line) {
                    Ok(record) => records.push(record),
                    Err(err) if skip_bad_records => skipped.push(SkippedRecord {
                        location: format!("{file_label}:{line_num}"),
                        reason: format!("{err:#}"),
                    }),
                    Err(err) => {
                        return Err(err.context(format!("{file_label}:{line_num}")));
                    }
                }
            }
        }

        Ok((records, skipped))
    }
}

fn parse_line(line: &str) -> anyhow::Result<ParsedRecord> {
    let value: Value = serde_json::from_str(line).context("not valid JSON")?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("expected a JSON object"))?;
    if obj.len() != 1 {
        bail!(
            "expected exactly one top-level event-type key, found {}",
            obj.len()
        );
    }
    let (event_type, event_data) = obj.iter().next().expect("checked len() == 1 above");
    let event_data = event_data
        .as_object()
        .ok_or_else(|| anyhow!("'{event_type}' value is not a JSON object"))?;

    let (timestamp_utc, message) = match event_type.as_str() {
        "dns_event" => (
            timestamp_from_millis(event_data)?,
            dns_event_message(event_data),
        ),
        "connect_event" => (
            timestamp_from_millis(event_data)?,
            connect_event_message(event_data),
        ),
        "security_event" => (
            timestamp_from_nanos(event_data)?,
            security_event_message(event_data),
        ),
        other => bail!("unrecognized intrusion-log event type '{other}'"),
    };

    let mut fields = event_data.clone();
    fields.insert("event_type".to_string(), Value::String(event_type.clone()));
    if event_type == "security_event"
        && let Some(tag) = security_event_tag(event_data)
    {
        fields.insert(
            "security_event_tag".to_string(),
            Value::String(tag.to_string()),
        );
    }

    Ok(ParsedRecord {
        timestamp_utc,
        level: None,
        message: Some(message),
        raw: line.to_string(),
        fields: Value::Object(fields),
    })
}

fn event_time(obj: &Map<String, Value>) -> anyhow::Result<i64> {
    obj.get("event_time")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("missing or non-integer 'event_time'"))
}

/// `dns_event`/`connect_event`'s `event_time` is milliseconds since epoch —
/// confirmed against MVT's `DnsEvent`/`ConnectEvent.process_event`, both of
/// which divide by `1000.0` before converting.
fn timestamp_from_millis(obj: &Map<String, Value>) -> anyhow::Result<DateTime<Utc>> {
    let ms = event_time(obj)?;
    DateTime::from_timestamp_millis(ms).ok_or_else(|| anyhow!("event_time {ms} out of range"))
}

/// `security_event`'s `event_time` is nanoseconds since epoch — confirmed
/// against MVT's `SecurityEvent.process_event`, which divides by
/// `1_000_000_000.0`. A different unit than the other two event types on
/// purpose (not a typo carried over): getting this wrong would silently
/// misplace every security event in the timeline by roughly a
/// million-fold, so it's split into its own function rather than sharing
/// [`timestamp_from_millis`] with a parameter that's easy to pass wrong.
fn timestamp_from_nanos(obj: &Map<String, Value>) -> anyhow::Result<DateTime<Utc>> {
    let ns = event_time(obj)?;
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    DateTime::from_timestamp(secs, nanos).ok_or_else(|| anyhow!("event_time {ns} out of range"))
}

/// The one key in a `security_event`'s detail object that isn't metadata —
/// same lookup MVT's `_get_event_tag` does. `None` only if a
/// `security_event` line somehow carries no tag at all (metadata-only),
/// which real Intrusion Logging output never produces but isn't assumed
/// impossible here.
fn security_event_tag(obj: &Map<String, Value>) -> Option<&str> {
    obj.keys()
        .find(|key| !SECURITY_EVENT_METADATA_KEYS.contains(&key.as_str()))
        .map(String::as_str)
}

fn clean_ip(raw: &str) -> &str {
    // MVT strips a leading "/" (java.net.InetAddress's own toString()
    // prefixes the textual address with one when no hostname resolved) and,
    // for shapes like "ip6-localhost/::1", takes the part after the slash —
    // same handling `ConnectEvent.serialize` does.
    raw.rsplit('/').next().unwrap_or(raw)
}

fn dns_event_message(obj: &Map<String, Value>) -> String {
    let hostname = obj.get("hostname").and_then(Value::as_str).unwrap_or("");
    let package_name = obj
        .get("package_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let ips: Vec<&str> = obj
        .get("ip_addresses")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(clean_ip)
                .filter(|ip| !ip.is_empty() && *ip != "0.0.0.0")
                .collect()
        })
        .unwrap_or_default();

    if ips.is_empty() {
        format!("[Peach] DNS query for {hostname} by {package_name}")
    } else {
        format!(
            "[Peach] DNS query for {hostname} by {package_name} [IPs: {}]",
            ips.join(", ")
        )
    }
}

fn connect_event_message(obj: &Map<String, Value>) -> String {
    let ip = obj
        .get("ip_address")
        .and_then(Value::as_str)
        .map(clean_ip)
        .unwrap_or("");
    let port = obj.get("port").and_then(Value::as_i64).unwrap_or(0);
    let package_name = obj
        .get("package_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("[Peach] Connection to {ip}:{port} by {package_name}")
}

fn security_event_message(obj: &Map<String, Value>) -> String {
    let Some(tag) = security_event_tag(obj) else {
        return "[Peach] Security event (no tag)".to_string();
    };
    let display_name = security_event_display_name(tag);

    let detail = obj.get(tag).and_then(Value::as_object);
    match detail {
        Some(detail) if !detail.is_empty() => {
            let mut pairs: Vec<String> = detail
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect();
            pairs.sort();
            format!("[Peach] {display_name}: {}", pairs.join(", "))
        }
        _ => format!("[Peach] {display_name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_dir_with_file(name: &str, file_name: &str, content: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "peach-intrusion-log-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut file = std::fs::File::create(dir.join(file_name)).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        dir
    }

    fn dummy_config() -> ParserConfig {
        ParserConfig::from_toml_str(
            "[parser]\nname = \"intrusion_log\"\nsourcetype = \"intrusion_log\"\n",
        )
        .unwrap()
    }

    #[test]
    fn sourcetype_is_intrusion_log() {
        assert_eq!(IntrusionLogParser.sourcetype(), "intrusion_log");
    }

    #[test]
    fn parses_a_dns_event_with_correct_millisecond_timestamp() {
        let dir = write_temp_dir_with_file(
            "dns",
            "intrusion-logs-0.txt",
            r#"{"dns_event": {"event_time": 1746979200000, "hostname": "example.com", "ip_addresses": ["93.184.216.34"], "package_name": "com.example.app"}}"#,
        );

        let (records, skipped) = IntrusionLogParser
            .parse(&dir, &dummy_config(), false)
            .unwrap();

        assert!(skipped.is_empty());
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(
            record.timestamp_utc,
            DateTime::from_timestamp_millis(1746979200000).unwrap()
        );
        assert_eq!(
            record.message.as_deref(),
            Some("[Peach] DNS query for example.com by com.example.app [IPs: 93.184.216.34]")
        );
        assert_eq!(
            record.fields.get("event_type").and_then(Value::as_str),
            Some("dns_event")
        );
        assert_eq!(
            record.fields.get("hostname").and_then(Value::as_str),
            Some("example.com")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parses_a_connect_event_with_correct_millisecond_timestamp() {
        let dir = write_temp_dir_with_file(
            "connect",
            "intrusion-logs-0.txt",
            r#"{"connect_event": {"event_time": 1746979201000, "ip_address": "/93.184.216.34", "port": 443, "package_name": "com.example.app"}}"#,
        );

        let (records, _) = IntrusionLogParser
            .parse(&dir, &dummy_config(), false)
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::from_timestamp_millis(1746979201000).unwrap()
        );
        assert_eq!(
            records[0].message.as_deref(),
            Some("[Peach] Connection to 93.184.216.34:443 by com.example.app")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parses_a_security_event_with_correct_nanosecond_timestamp_and_derived_tag_field() {
        let dir = write_temp_dir_with_file(
            "security",
            "intrusion-logs-0.txt",
            r#"{"security_event": {"event_time": 1746979202123456789, "keyguard_dismiss_auth_attempt": {"success": false, "method_strength": 1}}}"#,
        );

        let (records, _) = IntrusionLogParser
            .parse(&dir, &dummy_config(), false)
            .unwrap();

        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(
            record.timestamp_utc,
            DateTime::from_timestamp(1746979202, 123456789).unwrap()
        );
        assert_eq!(
            record.message.as_deref(),
            Some("[Peach] Keyguard Dismiss Auth Attempt: method_strength=1, success=false")
        );
        assert_eq!(
            record
                .fields
                .get("security_event_tag")
                .and_then(Value::as_str),
            Some("keyguard_dismiss_auth_attempt")
        );
        assert_eq!(
            record.fields.get("event_type").and_then(Value::as_str),
            Some("security_event")
        );
        // Original nested structure preserved, not flattened away.
        assert!(record.fields.get("keyguard_dismiss_auth_attempt").is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unrecognized_top_level_event_type_is_a_bad_record_not_a_silent_guess() {
        let dir = write_temp_dir_with_file(
            "unknown",
            "intrusion-logs-0.txt",
            r#"{"some_future_event": {"event_time": 1}}"#,
        );

        let result = IntrusionLogParser.parse(&dir, &dummy_config(), false);
        assert!(result.is_err());

        let (records, skipped) = IntrusionLogParser
            .parse(&dir, &dummy_config(), true)
            .unwrap();
        assert!(records.is_empty());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("some_future_event"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn skip_bad_records_false_still_hard_fails_on_the_first_bad_line() {
        let dir =
            write_temp_dir_with_file("bad-hard-fail", "intrusion-logs-0.txt", "not valid json\n");

        let result = IntrusionLogParser.parse(&dir, &dummy_config(), false);
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn skip_bad_records_true_keeps_good_lines_and_records_the_bad_one() {
        let dir = write_temp_dir_with_file(
            "bad-skip",
            "intrusion-logs-0.txt",
            "not valid json\n{\"dns_event\": {\"event_time\": 1746979200000, \"hostname\": \"a\", \"ip_addresses\": [], \"package_name\": \"p\"}}\n",
        );

        let (records, skipped) = IntrusionLogParser
            .parse(&dir, &dummy_config(), true)
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].location, "intrusion-logs-0.txt:1");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blank_lines_are_skipped_without_being_counted_as_bad_records() {
        let dir = write_temp_dir_with_file(
            "blank",
            "intrusion-logs-0.txt",
            "\n   \n{\"dns_event\": {\"event_time\": 1746979200000, \"hostname\": \"a\", \"ip_addresses\": [], \"package_name\": \"p\"}}\n\n",
        );

        let (records, skipped) = IntrusionLogParser
            .parse(&dir, &dummy_config(), false)
            .unwrap();

        assert_eq!(records.len(), 1);
        assert!(skipped.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn recursively_finds_txt_files_in_nested_subdirectories() {
        let dir = write_temp_dir_with_file(
            "nested",
            "top.txt",
            r#"{"dns_event": {"event_time": 1746979200000, "hostname": "a", "ip_addresses": [], "package_name": "p"}}"#,
        );
        let sub = dir.join("2026-08-31");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("nested.txt"),
            r#"{"connect_event": {"event_time": 1746979201000, "ip_address": "1.2.3.4", "port": 80, "package_name": "p"}}"#,
        )
        .unwrap();

        let (records, _) = IntrusionLogParser
            .parse(&dir, &dummy_config(), false)
            .unwrap();

        assert_eq!(records.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_directory_with_no_txt_files_is_an_error() {
        let dir = write_temp_dir_with_file("empty", "not-a-log.json", "{}");
        std::fs::remove_file(dir.join("not-a-log.json")).unwrap();

        let result = IntrusionLogParser.parse(&dir, &dummy_config(), false);
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn security_event_tag_finds_the_one_non_metadata_key() {
        let mut obj = Map::new();
        obj.insert("event_time".to_string(), Value::from(1));
        obj.insert("wipe_failure".to_string(), Value::Object(Map::new()));
        assert_eq!(security_event_tag(&obj), Some("wipe_failure"));
    }

    #[test]
    fn clean_ip_strips_a_leading_slash() {
        assert_eq!(clean_ip("/93.184.216.34"), "93.184.216.34");
        assert_eq!(clean_ip("ip6-localhost/::1"), "::1");
        assert_eq!(clean_ip("93.184.216.34"), "93.184.216.34");
    }

    #[test]
    fn security_event_display_name_title_cases_plain_tag_keys() {
        assert_eq!(
            security_event_display_name("keyguard_dismissed"),
            "Keyguard Dismissed"
        );
        assert_eq!(
            security_event_display_name("keyguard_dismiss_auth_attempt"),
            "Keyguard Dismiss Auth Attempt"
        );
        assert_eq!(
            security_event_display_name("cert_authority_installed"),
            "Cert Authority Installed"
        );
    }

    #[test]
    fn security_event_display_name_keeps_known_acronyms_uppercase() {
        assert_eq!(
            security_event_display_name("adb_shell_interactive"),
            "ADB Shell Interactive"
        );
        assert_eq!(security_event_display_name("os_startup"), "OS Startup");
        assert_eq!(security_event_display_name("nfc_enabled"), "NFC Enabled");
        assert_eq!(security_event_display_name("dns_event"), "DNS Event");
    }

    #[test]
    fn security_event_display_name_falls_back_to_the_raw_key_for_unexpected_input() {
        assert_eq!(
            security_event_display_name("some future.tag!"),
            "some future.tag!"
        );
    }
}
