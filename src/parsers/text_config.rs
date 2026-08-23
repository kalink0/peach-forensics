use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use regex::Regex;

use crate::model::log_entry::ParsedRecord;
use crate::model::timezone_spec::TimezoneSpec;
use crate::parsers::{LogParser, ParserConfig};

/// `pub(crate)` — also deserialized directly by
/// [`crate::parsers::text_config_file`] to load an existing config file
/// back into the "Define format..." dialog's editable fields, so that
/// dialog can never drift from what this module actually reads.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct PatternConfig {
    pub(crate) regex: String,
    pub(crate) timestamp_format: String,
    pub(crate) multiline_start_pattern: Option<String>,
    /// Fixed offset (`"+02:00"`, `"UTC"`) or IANA zone name
    /// (`"Europe/Berlin"`) applied when `timestamp_format` doesn't carry
    /// its own timezone — see [`TimezoneSpec`]. Set explicitly per source —
    /// takes precedence over `Settings::default_source_timezone`
    /// (`TextConfigParser::default_assume_offset`), since a per-source
    /// override reflects the analyst's specific knowledge about that one
    /// source and shouldn't be silently overruled by a broader setting.
    pub(crate) assume_offset: Option<String>,
    /// Year applied when `timestamp_format` doesn't carry one — some very
    /// common real-world formats genuinely never do (syslog RFC 3164,
    /// Android logcat's brief format), and there's no way to infer the
    /// right year from the log line itself. Same reasoning as
    /// `assume_offset`: an explicit, per-source, analyst-supplied value
    /// rather than a silent guess (e.g. "today's year", which would be
    /// flatly wrong for the historical log files forensic work usually
    /// deals with).
    pub(crate) assume_year: Option<i32>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct TextParserFields {
    pub(crate) pattern: PatternConfig,
    #[serde(default)]
    pub(crate) field_mapping: HashMap<String, String>,
}

/// Fully TOML-configurable parser for text-based sources (Apache/Nginx,
/// Syslog, Logcat, unrecognized user formats).
///
/// One `TextConfigParser` instance serves every text sourcetype; which
/// concrete sourcetype a given file is depends entirely on the
/// [`ParserConfig`] passed to [`LogParser::parse`], not on this type, so
/// [`LogParser::sourcetype`] returns a fixed generic marker rather than a
/// real sourcetype name.
#[derive(Debug, Clone, Default)]
pub struct TextConfigParser {
    /// `Settings::default_source_timezone` — the session-wide fallback
    /// used when a source's own `pattern.assume_offset` isn't set.
    /// Resolved once by the caller (`app::run_load`) from `Settings`, not
    /// read from `Settings` here: this module stays settings-agnostic,
    /// same as every other parser — it only ever sees an already-resolved
    /// value, never reaches into app-level config itself.
    pub default_assume_offset: Option<String>,
}

impl LogParser for TextConfigParser {
    fn sourcetype(&self) -> &str {
        "text_config"
    }

    fn parse(&self, path: &Path, config: &ParserConfig) -> anyhow::Result<Vec<ParsedRecord>> {
        let fields_config: TextParserFields = toml::Value::Table(config.parser.extra.clone())
            .try_into()
            .context("invalid text parser config")?;

        for target in fields_config.field_mapping.keys() {
            if target != "level" && target != "message" {
                bail!(
                    "unsupported field_mapping target '{target}': only 'level' and 'message' are supported"
                );
            }
        }

        let main_regex = Regex::new(&fields_config.pattern.regex)
            .with_context(|| format!("invalid pattern.regex '{}'", fields_config.pattern.regex))?;

        let capture_names: Vec<&str> = main_regex.capture_names().flatten().collect();
        if !capture_names.contains(&"timestamp") {
            bail!("pattern.regex must contain a named capture group 'timestamp'");
        }
        for (target, group_name) in &fields_config.field_mapping {
            if !capture_names.contains(&group_name.as_str()) {
                bail!("field_mapping.{target} refers to unknown capture group '{group_name}'");
            }
        }

        let multiline_start_regex = fields_config
            .pattern
            .multiline_start_pattern
            .as_deref()
            .map(Regex::new)
            .transpose()
            .context("invalid pattern.multiline_start_pattern")?;

        let assume_offset = fields_config
            .pattern
            .assume_offset
            .clone()
            .or_else(|| self.default_assume_offset.clone())
            .as_deref()
            .map(TimezoneSpec::parse)
            .transpose()?;
        let assume_year = fields_config.pattern.assume_year;

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {} as UTF-8 text", path.display()))?;
        let lines: Vec<&str> = content.lines().collect();
        let blocks = group_lines(&lines, multiline_start_regex.as_ref());

        blocks
            .into_iter()
            .map(|(start_line, block_lines)| {
                parse_block(
                    start_line,
                    &block_lines,
                    &main_regex,
                    &fields_config.pattern.timestamp_format,
                    assume_offset,
                    assume_year,
                    &fields_config.field_mapping,
                )
            })
            .collect()
    }
}

fn group_lines<'a>(
    lines: &[&'a str],
    multiline_start: Option<&Regex>,
) -> Vec<(usize, Vec<&'a str>)> {
    let mut blocks: Vec<(usize, Vec<&str>)> = Vec::new();
    for (index, &line) in lines.iter().enumerate() {
        let starts_new_block = match multiline_start {
            Some(start_regex) => blocks.is_empty() || start_regex.is_match(line),
            None => true,
        };
        if starts_new_block {
            blocks.push((index + 1, vec![line]));
        } else {
            blocks
                .last_mut()
                .expect("first line always starts a block")
                .1
                .push(line);
        }
    }
    blocks
}

/// `pub(crate)` — also called directly by
/// [`crate::parsers::text_config_file`]'s "Define format..." preview, so
/// the preview shows exactly what a real load would produce (or fail
/// with) for a given line, rather than a separately-maintained
/// approximation that could drift from this.
#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_block(
    start_line: usize,
    block_lines: &[&str],
    main_regex: &Regex,
    timestamp_format: &str,
    assume_offset: Option<TimezoneSpec>,
    assume_year: Option<i32>,
    field_mapping: &HashMap<String, String>,
) -> anyhow::Result<ParsedRecord> {
    let raw = block_lines.join("\n");

    let captures = main_regex
        .captures(&raw)
        .ok_or_else(|| anyhow!("line {start_line}: does not match pattern.regex: {raw:?}"))?;

    let timestamp_text = captures
        .name("timestamp")
        .ok_or_else(|| anyhow!("line {start_line}: 'timestamp' capture group did not match"))?
        .as_str();
    let timestamp_utc =
        parse_timestamp(timestamp_text, timestamp_format, assume_offset, assume_year)
            .with_context(|| {
                format!("line {start_line}: failed to parse timestamp '{timestamp_text}'")
            })?;

    let mut fields = serde_json::Map::new();
    for name in main_regex.capture_names().flatten() {
        let value = captures
            .name(name)
            .map(|m| serde_json::Value::String(m.as_str().to_string()))
            .unwrap_or(serde_json::Value::Null);
        fields.insert(name.to_string(), value);
    }

    let level = field_mapping
        .get("level")
        .and_then(|group| captures.name(group))
        .map(|m| m.as_str().to_string());
    let message = field_mapping
        .get("message")
        .and_then(|group| captures.name(group))
        .map(|m| m.as_str().to_string());

    Ok(ParsedRecord {
        timestamp_utc,
        level,
        message,
        raw,
        fields: serde_json::Value::Object(fields),
    })
}

/// Parses via `chrono::format`'s lower-level `Parsed` rather than the
/// `DateTime`/`NaiveDateTime::parse_from_str` convenience functions this
/// used before `assume_year` existed: those require every field the format
/// string doesn't itself supply (year included) to already be present in
/// `text`, with no way to fill one in afterwards. `Parsed` parses
/// leniently into whatever fields `text`/`format` actually provide, so a
/// missing year (never present in some very common real-world formats —
/// syslog RFC 3164, Android logcat's brief format) can be filled in from
/// `assume_year` before the date is finalized, the same way `assume_offset`
/// already fills in a missing timezone below.
fn parse_timestamp(
    text: &str,
    format: &str,
    assume_offset: Option<TimezoneSpec>,
    assume_year: Option<i32>,
) -> anyhow::Result<DateTime<Utc>> {
    use chrono::format::{Parsed, StrftimeItems, parse};

    let mut parsed = Parsed::new();
    parse(&mut parsed, text, StrftimeItems::new(format))
        .with_context(|| format!("does not match timestamp_format '{format}'"))?;

    if parsed.year.is_none() {
        let year = assume_year.ok_or_else(|| {
            anyhow!(
                "timestamp has no year and no pattern.assume_year is configured for this source"
            )
        })?;
        parsed
            .set_year(i64::from(year))
            .with_context(|| format!("invalid pattern.assume_year {year}"))?;
    }

    if let Ok(offset_aware) = parsed.to_datetime() {
        return Ok(offset_aware.with_timezone(&Utc));
    }

    let naive = parsed.to_naive_datetime_with_offset(0).with_context(|| {
        format!("timestamp '{text}' does not match timestamp_format '{format}'")
    })?;

    let spec = assume_offset.ok_or_else(|| {
        anyhow!(
            "timestamp has no timezone and no pattern.assume_offset is configured for this source"
        )
    })?;

    spec.resolve_local(naive)
        .ok_or_else(|| anyhow!("timestamp '{text}' is ambiguous or nonexistent under {spec:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::parse_source;
    use std::io::Write;
    use std::path::PathBuf;

    fn write_temp_file(name: &str, content: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "peach-text_config-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    fn config(toml_body: &str) -> ParserConfig {
        let full = format!("[parser]\nname = \"test\"\nsourcetype = \"test\"\n{toml_body}");
        ParserConfig::from_toml_str(&full).unwrap()
    }

    #[test]
    fn single_line_offset_aware_timestamp_is_parsed_and_mapped() {
        let path = write_temp_file("a", "2026-07-28T12:00:00+0200 ERROR something broke\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+) (?P<level_raw>\w+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%dT%H:%M:%S%z"

[parser.field_mapping]
level = "level_raw"
message = "msg"
"#,
        );

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(
            record.timestamp_utc,
            DateTime::parse_from_rfc3339("2026-07-28T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(record.level.as_deref(), Some("ERROR"));
        assert_eq!(record.message.as_deref(), Some("something broke"));
        assert_eq!(
            record.fields.get("level_raw").and_then(|v| v.as_str()),
            Some("ERROR")
        );

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn multiline_block_with_assume_offset_is_grouped_and_parsed() {
        let path = write_temp_file(
            "b",
            "2026-07-28 12:00:00 ERROR something broke\n  at foo.bar()\n  at baz.qux()\n",
        );
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+ \S+) (?P<level_raw>\w+) (?P<msg>.*)'
timestamp_format = "%Y-%m-%d %H:%M:%S"
multiline_start_pattern = '^\d{4}-\d{2}-\d{2}'
assume_offset = "+02:00"

[parser.field_mapping]
level = "level_raw"
message = "msg"
"#,
        );

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(
            record.raw,
            "2026-07-28 12:00:00 ERROR something broke\n  at foo.bar()\n  at baz.qux()"
        );
        assert_eq!(
            record.timestamp_utc,
            DateTime::parse_from_rfc3339("2026-07-28T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(record.message.as_deref(), Some("something broke"));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn default_assume_offset_is_used_when_the_source_config_sets_none() {
        let path = write_temp_file("d", "2026-07-28 12:00:00 ERROR something broke\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+ \S+) (?P<level_raw>\w+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%d %H:%M:%S"
"#,
        );

        let parser = TextConfigParser {
            default_assume_offset: Some("Europe/Berlin".to_string()),
        };
        let records = parser.parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2026-07-28T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_source_configs_own_assume_offset_takes_precedence_over_the_session_default() {
        let path = write_temp_file("e", "2026-07-28 12:00:00 ERROR something broke\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+ \S+) (?P<level_raw>\w+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%d %H:%M:%S"
assume_offset = "+05:00"

[parser.field_mapping]
level = "level_raw"
message = "msg"
"#,
        );

        // Session default disagrees with the source's own setting — the
        // source's own `assume_offset` must win, same precedence
        // `PatternConfig.assume_offset`'s doc comment documents.
        let parser = TextConfigParser {
            default_assume_offset: Some("Europe/Berlin".to_string()),
        };
        let records = parser.parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2026-07-28T07:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn naive_timestamp_without_assume_offset_is_an_error() {
        let path = write_temp_file("c", "2026-07-28 12:00:00 ERROR something broke\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+ \S+) (?P<level_raw>\w+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%d %H:%M:%S"
"#,
        );

        let result = TextConfigParser::default().parse(&path, &cfg);

        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }

    /// Regression coverage for the reason `assume_year` exists at all:
    /// syslog RFC 3164's `Mon DD HH:MM:SS` has no year in it whatsoever —
    /// confirmed directly against `chrono` before this feature was built,
    /// `NaiveDateTime::parse_from_str` errors "input is not enough for
    /// unique date and time" on a year-less format with no way to supply
    /// one after the fact, which is exactly why `parse_timestamp` was
    /// rewritten on `chrono::format::Parsed` instead.
    #[test]
    fn yearless_timestamp_without_assume_year_is_an_error() {
        let path = write_temp_file(
            "year-missing",
            "Jul 28 12:00:00 host proc: something broke\n",
        );
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\w+ +\d+ \d{2}:\d{2}:\d{2}) \S+ (?P<msg>.*)$'
timestamp_format = "%b %e %H:%M:%S"
assume_offset = "UTC"

[parser.field_mapping]
message = "msg"
"#,
        );

        let result = TextConfigParser::default().parse(&path, &cfg);

        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn yearless_timestamp_with_assume_year_is_parsed() {
        let path = write_temp_file("year-set", "Jul 28 12:00:00 host proc: something broke\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\w+ +\d+ \d{2}:\d{2}:\d{2}) \S+ (?P<msg>.*)$'
timestamp_format = "%b %e %H:%M:%S"
assume_offset = "UTC"
assume_year = 2026

[parser.field_mapping]
message = "msg"
"#,
        );

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2026-07-28T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        std::fs::remove_file(path).unwrap();
    }

    /// A format string that *does* carry a year must keep working exactly
    /// as before — `assume_year` only fills in when the year is genuinely
    /// absent, never overrides one that was actually parsed.
    #[test]
    fn assume_year_is_ignored_when_the_format_already_has_a_year() {
        let path = write_temp_file("year-present", "2020-01-01 00:00:00 something broke\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+ \S+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%d %H:%M:%S"
assume_offset = "UTC"
assume_year = 1999

[parser.field_mapping]
message = "msg"
"#,
        );

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        std::fs::remove_file(path).unwrap();
    }

    /// Fetches the real embedded TOML for a built-in format
    /// (`parsers/examples/*.toml`) by its `sourcetype`, with `assume_offset`/
    /// `assume_year` spliced in — exactly the two per-source fields the
    /// built-in deliberately leaves blank for the analyst to fill in via
    /// "Define format...". Testing against this instead of a hand-copied
    /// duplicate of the regex/timestamp_format means these tests can't
    /// silently drift from what's actually shipped.
    fn builtin_config_with_source_details(sourcetype: &str) -> ParserConfig {
        use crate::parsers::builtin_text_formats::builtin_text_formats;
        let format = builtin_text_formats()
            .into_iter()
            .find(|f| f.sourcetype == sourcetype)
            .unwrap_or_else(|| panic!("no built-in format with sourcetype '{sourcetype}'"));
        let with_details = format.toml.replacen(
            "[parser.pattern]",
            "[parser.pattern]\nassume_offset = \"UTC\"\nassume_year = 2026",
            1,
        );
        ParserConfig::from_toml_str(&with_details).unwrap()
    }

    #[test]
    fn builtin_generic_timestamp_format_parses_a_realistic_line() {
        let path = write_temp_file(
            "builtin-generic",
            "2026-08-17 14:23:01.500 something happened\n  continuation line\n",
        );
        let cfg = builtin_config_with_source_details("text_generic");

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2026-08-17T14:23:01.5Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(
            records[0].message.as_deref(),
            Some("something happened\n  continuation line")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn builtin_syslog_rfc3164_format_parses_a_realistic_line() {
        let path = write_temp_file(
            "builtin-syslog",
            "Jan  1 00:00:00 myhost sshd[1234]: Accepted password for alice\n",
        );
        let cfg = builtin_config_with_source_details("syslog");

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(
            records[0].message.as_deref(),
            Some("Accepted password for alice")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn builtin_logcat_brief_format_parses_a_realistic_line() {
        let path = write_temp_file(
            "builtin-logcat",
            "08-17 14:23:01.123  1234  1234 E ActivityManager: something crashed\n",
        );
        let cfg = builtin_config_with_source_details("logcat");

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2026-08-17T14:23:01.123Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(records[0].level.as_deref(), Some("E"));
        assert_eq!(records[0].message.as_deref(), Some("something crashed"));
        std::fs::remove_file(path).unwrap();
    }

    /// Line taken directly from a real `/var/log/pacman.log`, not
    /// hand-constructed — same "test against real representative data"
    /// approach as the other built-in formats.
    #[test]
    fn builtin_pacman_log_format_parses_a_realistic_line() {
        let path = write_temp_file(
            "builtin-pacman",
            "[2026-08-15T17:50:10+0200] [ALPM] upgraded brave-browser (1.93.134-1 -> 1.93.136-1)\n",
        );
        let cfg = builtin_config_with_source_details("pacman");

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2026-08-15T15:50:10Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(
            records[0].message.as_deref(),
            Some("upgraded brave-browser (1.93.134-1 -> 1.93.136-1)")
        );
        assert_eq!(
            records[0].fields.get("category").and_then(|v| v.as_str()),
            Some("ALPM")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn builtin_apache_common_format_parses_a_realistic_line() {
        let path = write_temp_file(
            "builtin-apache-common",
            "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /index.html HTTP/1.0\" 200 2326\n",
        );
        let cfg = builtin_config_with_source_details("apache_common");

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2000-10-10T20:55:36Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(records[0].level.as_deref(), Some("200"));
        assert_eq!(
            records[0].message.as_deref(),
            Some("GET /index.html HTTP/1.0")
        );
        assert_eq!(
            records[0].fields.get("ip").and_then(|v| v.as_str()),
            Some("127.0.0.1")
        );
        assert_eq!(
            records[0].fields.get("bytes").and_then(|v| v.as_str()),
            Some("2326")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn builtin_apache_combined_format_parses_a_realistic_line() {
        let path = write_temp_file(
            "builtin-apache-combined",
            "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /index.html HTTP/1.0\" 200 2326 \"http://example.com/\" \"Mozilla/5.0\"\n",
        );
        let cfg = builtin_config_with_source_details("apache_combined");

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level.as_deref(), Some("200"));
        assert_eq!(
            records[0].message.as_deref(),
            Some("GET /index.html HTTP/1.0")
        );
        assert_eq!(
            records[0].fields.get("referer").and_then(|v| v.as_str()),
            Some("http://example.com/")
        );
        assert_eq!(
            records[0].fields.get("agent").and_then(|v| v.as_str()),
            Some("Mozilla/5.0")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn builtin_nginx_access_format_parses_a_realistic_line() {
        let path = write_temp_file(
            "builtin-nginx-access",
            "192.168.1.10 - - [10/Oct/2023:13:55:36 +0000] \"GET /index.html HTTP/1.1\" 404 612 \"-\" \"Mozilla/5.0\"\n",
        );
        let cfg = builtin_config_with_source_details("nginx_access");

        let records = TextConfigParser::default().parse(&path, &cfg).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2023-10-10T13:55:36Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(records[0].level.as_deref(), Some("404"));
        assert_eq!(
            records[0].message.as_deref(),
            Some("GET /index.html HTTP/1.1")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_regex_in_config_is_an_error() {
        let path = write_temp_file("d", "irrelevant\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '(?P<timestamp>['
timestamp_format = "%Y-%m-%d %H:%M:%S"
"#,
        );

        let result = TextConfigParser::default().parse(&path, &cfg);

        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn line_not_matching_pattern_is_an_error_with_context() {
        let path = write_temp_file("e", "this line matches nothing useful\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\d+)-(?P<level_raw>\w+)$'
timestamp_format = "%Y-%m-%d %H:%M:%S"
assume_offset = "UTC"
"#,
        );

        let result = TextConfigParser::default().parse(&path, &cfg);

        let err = result.unwrap_err();
        assert!(err.to_string().contains("line 1"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn field_mapping_unknown_target_is_an_error() {
        let path = write_temp_file("f", "2026-07-28T12:00:00+0200 hello\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%dT%H:%M:%S%z"

[parser.field_mapping]
sourcehost = "msg"
"#,
        );

        let result = TextConfigParser::default().parse(&path, &cfg);

        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn field_mapping_unknown_capture_group_is_an_error() {
        let path = write_temp_file("g", "2026-07-28T12:00:00+0200 hello\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%dT%H:%M:%S%z"

[parser.field_mapping]
message = "does_not_exist"
"#,
        );

        let result = TextConfigParser::default().parse(&path, &cfg);

        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_timestamp_capture_group_is_an_error() {
        let path = write_temp_file("h", "2026-07-28T12:00:00+0200 hello\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<ts>\S+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%dT%H:%M:%S%z"
"#,
        );

        let result = TextConfigParser::default().parse(&path, &cfg);

        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn end_to_end_through_parse_source_assigns_event_ids() {
        let path = write_temp_file(
            "i",
            "2026-07-28T12:00:00+0200 ERROR first\n2026-07-28T12:00:01+0200 INFO second\n",
        );
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+) (?P<level_raw>\w+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%dT%H:%M:%S%z"

[parser.field_mapping]
level = "level_raw"
message = "msg"
"#,
        );

        let entries = parse_source(&TextConfigParser::default(), &path, &cfg).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].event_id.source_file_id,
            entries[1].event_id.source_file_id
        );
        assert_eq!(entries[0].event_id.sequence_number.value(), 0);
        assert_eq!(entries[1].event_id.sequence_number.value(), 1);
        assert_eq!(entries[0].message.as_deref(), Some("first"));
        assert_eq!(entries[1].message.as_deref(), Some("second"));

        std::fs::remove_file(path).unwrap();
    }
}
