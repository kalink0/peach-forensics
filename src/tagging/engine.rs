use chrono::Utc;
use duckdb::{Connection, params};

use crate::model::log_entry::LogEntry;
use crate::tagging::rule::Rule;

/// Evaluates `rules` against `entries` and persists matches into
/// `import_tags` via the DuckDB Appender (bulk insert) — the import-time
/// mode from section 6 of CLAUDE.md. Re-tag and ad-hoc modes (not yet
/// implemented) are meant to reuse the same [`Rule::matches`] evaluation;
/// only the persistence path should differ.
pub fn apply_import_time(
    conn: &Connection,
    rules: &[Rule],
    entries: &[LogEntry],
    sourcetype: &str,
) -> anyhow::Result<usize> {
    if rules.is_empty() || entries.is_empty() {
        return Ok(0);
    }

    let applied_at = Utc::now().naive_utc();
    let mut appender = conn.appender("import_tags")?;
    let mut applied = 0usize;

    for entry in entries {
        for rule in rules {
            if rule.matches(entry, sourcetype) {
                appender.append_row(params![
                    entry.event_id.source_file_id.to_string(),
                    entry.event_id.sequence_number.value() as i64,
                    rule.rule.name.as_str(),
                    rule.rule.tag.value.as_str(),
                    applied_at,
                ])?;
                applied += 1;
            }
        }
    }

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::timeline_schema::setup_timeline_schema;
    use crate::model::event_id::{EventId, SequenceNumber, SourceFileId};

    fn sample_entry(level: Option<&str>, fields: serde_json::Value) -> LogEntry {
        LogEntry {
            event_id: EventId {
                source_file_id: SourceFileId::new_random(),
                sequence_number: SequenceNumber::from_raw(0),
            },
            timestamp_utc: Utc::now(),
            level: level.map(str::to_string),
            message: None,
            raw: "raw".to_string(),
            fields,
        }
    }

    fn open_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        setup_timeline_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn matching_entries_get_tagged_and_persisted() {
        let conn = open_test_db();
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"generic_error\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"error\"\n",
        )
        .unwrap();
        let matching = sample_entry(Some("ERROR"), serde_json::Value::Null);
        let non_matching = sample_entry(Some("INFO"), serde_json::Value::Null);
        let entries = vec![matching.clone(), non_matching];

        let applied = apply_import_time(&conn, &[rule], &entries, "text_config").unwrap();

        assert_eq!(applied, 1);

        let (rule_name, tag_value): (String, String) = conn
            .query_row(
                "SELECT rule_name, tag_value FROM import_tags
                 WHERE event_id_source = ? AND event_id_seq = ?",
                duckdb::params![
                    matching.event_id.source_file_id.to_string(),
                    matching.event_id.sequence_number.value() as i64
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rule_name, "generic_error");
        assert_eq!(tag_value, "error");
    }

    #[test]
    fn one_entry_can_get_multiple_tags_from_multiple_rules() {
        let conn = open_test_db();
        let rule_a = Rule::from_toml_str(
            "[rule]\nname = \"a\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"tag_a\"\n",
        )
        .unwrap();
        let rule_b = Rule::from_toml_str(
            "[rule]\nname = \"b\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"tag_b\"\n",
        )
        .unwrap();
        let entry = sample_entry(Some("ERROR"), serde_json::Value::Null);

        let applied = apply_import_time(&conn, &[rule_a, rule_b], &[entry], "aul").unwrap();

        assert_eq!(applied, 2);
    }

    #[test]
    fn no_rules_or_no_entries_is_a_cheap_no_op() {
        let conn = open_test_db();
        let entry = sample_entry(Some("ERROR"), serde_json::Value::Null);

        assert_eq!(apply_import_time(&conn, &[], &[entry], "aul").unwrap(), 0);
        assert_eq!(apply_import_time(&conn, &[], &[], "aul").unwrap(), 0);
    }
}
