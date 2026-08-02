use chrono::Utc;
use duckdb::{Connection, params};

use crate::model::event_id::{EventId, SequenceNumber, SourceFileId};
use crate::model::log_entry::LogEntry;
use crate::tagging::rule::Rule;

/// Evaluates `rules` against `entries` and persists matches into
/// `import_tags` via the DuckDB Appender (bulk insert) — the import-time
/// tagging mode.
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
            if rule.matches(
                sourcetype,
                entry.level.as_deref(),
                entry.message.as_deref(),
                &entry.fields,
            ) {
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

/// Re-evaluates `rules` against every entry already in `log_entries` and
/// replaces `import_tags` with the result. Deliberately "clear and
/// recompute" rather than incremental: `import_tags` always reflects
/// exactly what the *current* rule set produces — a changed or removed
/// rule can't leave a stale tag behind, and re-running the same rule set
/// twice can't create duplicates.
///
/// Streams rows straight out of DuckDB (a source-file-id/sourcetype join,
/// `level`/`message`/`fields` only) instead of collecting a `Vec<LogEntry>`
/// first — a `.logarchive` can mean millions of rows.
pub fn re_tag(conn: &Connection, rules: &[Rule]) -> anyhow::Result<usize> {
    conn.execute("DELETE FROM import_tags", [])?;
    if rules.is_empty() {
        return Ok(0);
    }

    let mut matches: Vec<(String, i64, &str, &str)> = Vec::new();
    for_each_taggable_row(
        conn,
        |source_file_id, sequence_number, sourcetype, level, message, fields| {
            for rule in rules {
                if rule.matches(sourcetype, level, message, fields) {
                    matches.push((
                        source_file_id.to_string(),
                        sequence_number.value() as i64,
                        rule.rule.name.as_str(),
                        rule.rule.tag.value.as_str(),
                    ));
                }
            }
            Ok(())
        },
    )?;

    let applied_at = Utc::now().naive_utc();
    let mut appender = conn.appender("import_tags")?;
    for (source_file_id, sequence_number, rule_name, tag_value) in &matches {
        appender.append_row(params![
            source_file_id,
            *sequence_number,
            *rule_name,
            *tag_value,
            applied_at
        ])?;
    }

    Ok(matches.len())
}

/// Query-time-only, ad-hoc evaluation — evaluates `rules`
/// against every entry currently in `log_entries` and returns the matching
/// [`EventId`]s without writing anything to `import_tags`. An entry
/// matching any one of `rules` is included once, not repeated per rule.
pub fn evaluate_ad_hoc(conn: &Connection, rules: &[Rule]) -> anyhow::Result<Vec<EventId>> {
    let mut matched = Vec::new();
    if rules.is_empty() {
        return Ok(matched);
    }

    for_each_taggable_row(
        conn,
        |source_file_id, sequence_number, sourcetype, level, message, fields| {
            if rules
                .iter()
                .any(|rule| rule.matches(sourcetype, level, message, fields))
            {
                matched.push(EventId {
                    source_file_id,
                    sequence_number,
                });
            }
            Ok(())
        },
    )?;

    Ok(matched)
}

/// Streams every `log_entries` row (joined with `sources` for its
/// sourcetype) through `f`, one row at a time — shared by [`re_tag`] and
/// [`evaluate_ad_hoc`] so neither has to materialize the whole timeline as
/// `LogEntry` values just to run [`Rule::matches`].
fn for_each_taggable_row<F>(conn: &Connection, mut f: F) -> anyhow::Result<()>
where
    F: FnMut(
        SourceFileId,
        SequenceNumber,
        &str,
        Option<&str>,
        Option<&str>,
        &serde_json::Value,
    ) -> anyhow::Result<()>,
{
    let mut stmt = conn.prepare(
        "SELECT log_entries.event_id_source, log_entries.event_id_seq,
                log_entries.level, log_entries.message, log_entries.fields,
                sources.sourcetype
         FROM log_entries
         JOIN sources ON log_entries.event_id_source = sources.source_file_id",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let source_file_id: String = row.get(0)?;
        let sequence_number: i64 = row.get(1)?;
        let level: Option<String> = row.get(2)?;
        let message: Option<String> = row.get(3)?;
        let fields: serde_json::Value = row.get(4)?;
        let sourcetype: String = row.get(5)?;

        let source_file_id: SourceFileId = source_file_id
            .parse()
            .map_err(|err| anyhow::anyhow!("invalid source_file_id in database: {err}"))?;

        f(
            source_file_id,
            SequenceNumber::from_raw(sequence_number as u64),
            &sourcetype,
            level.as_deref(),
            message.as_deref(),
            &fields,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::timeline_schema::setup_timeline_schema;
    use crate::model::event_id::SequenceCounter;

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

    fn insert_source(conn: &Connection, source_file_id: SourceFileId, sourcetype: &str) {
        conn.execute(
            "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
             VALUES (?, ?, ?, NULL, NULL)",
            params![source_file_id.to_string(), "/evidence/test.log", sourcetype],
        )
        .unwrap();
    }

    fn insert_entry(conn: &Connection, entry: &LogEntry) {
        conn.execute(
            "INSERT INTO log_entries
                (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                entry.event_id.source_file_id.to_string(),
                entry.event_id.sequence_number.value() as i64,
                entry.timestamp_utc.naive_utc(),
                entry.level,
                entry.message,
                entry.raw,
                entry.fields,
            ],
        )
        .unwrap();
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

    #[test]
    fn re_tag_recomputes_import_tags_from_scratch() {
        let conn = open_test_db();
        let source_file_id = SourceFileId::new_random();
        insert_source(&conn, source_file_id, "aul");

        let mut counter = SequenceCounter::new();
        let matching = LogEntry {
            event_id: EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            },
            ..sample_entry(Some("ERROR"), serde_json::Value::Null)
        };
        let non_matching = LogEntry {
            event_id: EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            },
            ..sample_entry(Some("INFO"), serde_json::Value::Null)
        };
        insert_entry(&conn, &matching);
        insert_entry(&conn, &non_matching);

        // A stale tag from a rule that no longer exists/matches.
        conn.execute(
            "INSERT INTO import_tags (event_id_source, event_id_seq, rule_name, tag_value, applied_at)
             VALUES (?, ?, 'stale_rule', 'stale_tag', ?)",
            params![
                non_matching.event_id.source_file_id.to_string(),
                non_matching.event_id.sequence_number.value() as i64,
                Utc::now().naive_utc(),
            ],
        )
        .unwrap();

        let rule = Rule::from_toml_str(
            "[rule]\nname = \"generic_error\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"error\"\n",
        )
        .unwrap();

        let applied = re_tag(&conn, std::slice::from_ref(&rule)).unwrap();

        assert_eq!(applied, 1);
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM import_tags", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 1, "stale tag must be gone after re-tag");
    }

    #[test]
    fn re_tag_with_no_rules_clears_all_tags() {
        let conn = open_test_db();
        let source_file_id = SourceFileId::new_random();
        insert_source(&conn, source_file_id, "aul");
        conn.execute(
            "INSERT INTO import_tags (event_id_source, event_id_seq, rule_name, tag_value, applied_at)
             VALUES (?, 0, 'old', 'old', ?)",
            params![source_file_id.to_string(), Utc::now().naive_utc()],
        )
        .unwrap();

        let applied = re_tag(&conn, &[]).unwrap();

        assert_eq!(applied, 0);
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM import_tags", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 0);
    }

    #[test]
    fn ad_hoc_matches_are_not_persisted() {
        let conn = open_test_db();
        let source_file_id = SourceFileId::new_random();
        insert_source(&conn, source_file_id, "aul");
        let entry = LogEntry {
            event_id: EventId {
                source_file_id,
                sequence_number: SequenceNumber::from_raw(0),
            },
            ..sample_entry(Some("ERROR"), serde_json::Value::Null)
        };
        insert_entry(&conn, &entry);

        let rule = Rule::from_toml_str(
            "[rule]\nname = \"generic_error\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"error\"\n",
        )
        .unwrap();

        let matched = evaluate_ad_hoc(&conn, &[rule]).unwrap();

        assert_eq!(matched, vec![entry.event_id]);
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM import_tags", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 0, "ad-hoc must not write to import_tags");
    }
}
