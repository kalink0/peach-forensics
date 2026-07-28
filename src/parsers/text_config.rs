use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use regex::Regex;

use crate::model::log_entry::ParsedRecord;
use crate::parsers::{LogParser, ParserConfig};

#[derive(Debug, Clone, serde::Deserialize)]
struct PatternConfig {
    regex: String,
    timestamp_format: String,
    multiline_start_pattern: Option<String>,
    /// Fixed UTC offset (e.g. `"+02:00"`, `"UTC"`) applied when
    /// `timestamp_format` doesn't carry its own timezone. Set explicitly per
    /// source; see the `timezone-offset-precedence` project note for how
    /// this is meant to interact with a future session-level default.
    assume_offset: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TextParserFields {
    pattern: PatternConfig,
    #[serde(default)]
    field_mapping: HashMap<String, String>,
}

/// Fully TOML-configurable parser for text-based sources (Apache/Nginx,
/// Syslog, Logcat, unrecognized user formats) — section 5 of CLAUDE.md.
///
/// One `TextConfigParser` instance serves every text sourcetype; which
/// concrete sourcetype a given file is depends entirely on the
/// [`ParserConfig`] passed to [`LogParser::parse`], not on this type, so
/// [`LogParser::sourcetype`] returns a fixed generic marker rather than a
/// real sourcetype name.
pub struct TextConfigParser;

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
            .as_deref()
            .map(parse_fixed_offset)
            .transpose()?;

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

#[allow(clippy::too_many_arguments)]
fn parse_block(
    start_line: usize,
    block_lines: &[&str],
    main_regex: &Regex,
    timestamp_format: &str,
    assume_offset: Option<FixedOffset>,
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
    let timestamp_utc = parse_timestamp(timestamp_text, timestamp_format, assume_offset)
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

fn parse_timestamp(
    text: &str,
    format: &str,
    assume_offset: Option<FixedOffset>,
) -> anyhow::Result<DateTime<Utc>> {
    if let Ok(offset_aware) = DateTime::parse_from_str(text, format) {
        return Ok(offset_aware.with_timezone(&Utc));
    }

    let naive = NaiveDateTime::parse_from_str(text, format)
        .with_context(|| format!("does not match timestamp_format '{format}'"))?;

    let offset = assume_offset.ok_or_else(|| {
        anyhow!(
            "timestamp has no timezone and no pattern.assume_offset is configured for this source"
        )
    })?;

    use chrono::TimeZone;
    offset
        .from_local_datetime(&naive)
        .single()
        .map(|dt| dt.with_timezone(&Utc))
        .ok_or_else(|| anyhow!("timestamp '{text}' is ambiguous under offset {offset}"))
}

fn parse_fixed_offset(s: &str) -> anyhow::Result<FixedOffset> {
    let trimmed = s.trim();
    if trimmed.eq_ignore_ascii_case("utc") || trimmed == "Z" || trimmed == "z" {
        return Ok(FixedOffset::east_opt(0).unwrap());
    }

    let invalid = || anyhow!("invalid assume_offset '{s}': expected '+HH:MM', '-HH:MM', or 'UTC'");

    let (sign, rest) = match trimmed.as_bytes().first() {
        Some(b'+') => (1, &trimmed[1..]),
        Some(b'-') => (-1, &trimmed[1..]),
        _ => return Err(invalid()),
    };
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(invalid());
    }
    let hours: i32 = digits[0..2].parse().map_err(|_| invalid())?;
    let minutes: i32 = digits[2..4].parse().map_err(|_| invalid())?;
    let total_seconds = sign * (hours * 3600 + minutes * 60);

    FixedOffset::east_opt(total_seconds).ok_or_else(invalid)
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

        let records = TextConfigParser.parse(&path, &cfg).unwrap();

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

        let records = TextConfigParser.parse(&path, &cfg).unwrap();

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
    fn naive_timestamp_without_assume_offset_is_an_error() {
        let path = write_temp_file("c", "2026-07-28 12:00:00 ERROR something broke\n");
        let cfg = config(
            r#"
[parser.pattern]
regex = '^(?P<timestamp>\S+ \S+) (?P<level_raw>\w+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%d %H:%M:%S"
"#,
        );

        let result = TextConfigParser.parse(&path, &cfg);

        assert!(result.is_err());
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

        let result = TextConfigParser.parse(&path, &cfg);

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

        let result = TextConfigParser.parse(&path, &cfg);

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

        let result = TextConfigParser.parse(&path, &cfg);

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

        let result = TextConfigParser.parse(&path, &cfg);

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

        let result = TextConfigParser.parse(&path, &cfg);

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

        let entries = parse_source(&TextConfigParser, &path, &cfg).unwrap();

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
