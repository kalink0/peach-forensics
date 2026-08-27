use duckdb::{Connection, Result};

/// Creates the bulk-timeline tables if they don't already exist:
/// `log_entries`, `sources`, `import_tags`.
///
/// `event_id_source` / `source_file_id` are `VARCHAR` holding the string
/// form of the UUID from [`crate::model::event_id::SourceFileId`], not a
/// `BIGINT` as originally sketched. `raw` carries `NOT NULL`: normalization
/// must never lose the original source data.
pub fn setup_timeline_schema(conn: &Connection) -> Result<()> {
    setup_timeline_schema_in(conn, "")
}

/// Same DDL as [`setup_timeline_schema`], with every table name prefixed by
/// `catalog_prefix` (e.g. `"export_db.main."` after an `ATTACH ... AS
/// export_db`) — a single source of truth for the schema (including its
/// `PRIMARY KEY`/`NOT NULL` constraints) so `session::portable_case` can
/// stand up a freshly attached database with the exact same guarantees as a
/// live session, instead of a second, hand-duplicated copy of this DDL that
/// could silently drift. Deliberately *not* implemented via
/// `CREATE TABLE ... AS SELECT`: DuckDB's CTAS infers a constraint-free
/// schema from the query's output types, which would let a corrupted or
/// duplicated portable-case bundle accept duplicate `event_id`s instead of
/// failing loudly — unacceptable for forensic data.
pub fn setup_timeline_schema_in(conn: &Connection, catalog_prefix: &str) -> Result<()> {
    conn.execute_batch(&format!(
        "
        CREATE TABLE IF NOT EXISTS {catalog_prefix}log_entries (
            event_id_source   VARCHAR NOT NULL,
            event_id_seq      BIGINT NOT NULL,
            timestamp_utc     TIMESTAMP NOT NULL,
            level             VARCHAR,
            message           VARCHAR,
            raw               VARCHAR NOT NULL,
            fields            JSON,
            PRIMARY KEY (event_id_source, event_id_seq)
        );

        CREATE TABLE IF NOT EXISTS {catalog_prefix}sources (
            source_file_id    VARCHAR PRIMARY KEY,
            path              VARCHAR NOT NULL,
            sourcetype        VARCHAR NOT NULL,
            original_tz       VARCHAR,
            parser_config     VARCHAR
        );

        CREATE TABLE IF NOT EXISTS {catalog_prefix}import_tags (
            event_id_source   VARCHAR NOT NULL,
            event_id_seq      BIGINT NOT NULL,
            rule_name         VARCHAR NOT NULL,
            tag_value         VARCHAR NOT NULL,
            applied_at        TIMESTAMP NOT NULL
        );
        "
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::event_id::{EventId, SequenceCounter, SequenceNumber, SourceFileId};
    use crate::model::log_entry::LogEntry;
    use chrono::{TimeZone, Utc};
    use duckdb::params;

    fn open_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        setup_timeline_schema(&conn).unwrap();
        conn
    }

    fn sample_source_file_id() -> SourceFileId {
        SourceFileId::new_random()
    }

    #[test]
    fn schema_setup_is_idempotent() {
        let conn = open_test_db();
        setup_timeline_schema(&conn).unwrap();
    }

    #[test]
    fn log_entry_round_trips_through_log_entries_table() {
        let conn = open_test_db();

        let mut counter = SequenceCounter::new();
        let event_id = EventId {
            source_file_id: sample_source_file_id(),
            sequence_number: counter.next_sequence_number(),
        };
        let entry = LogEntry {
            event_id,
            timestamp_utc: Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap(),
            level: Some("ERROR".to_string()),
            message: Some("something failed".to_string()),
            raw: "2026-07-28T12:00:00Z ERROR something failed".to_string(),
            fields: serde_json::json!({"subsystem": "com.example.peach"}),
        };

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

        let mut stmt = conn
            .prepare(
                "SELECT event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields
                 FROM log_entries",
            )
            .unwrap();
        let read_back: LogEntry = stmt
            .query_row([], |row| {
                let source_file_id: String = row.get(0)?;
                let sequence_number: i64 = row.get(1)?;
                let timestamp_utc: chrono::NaiveDateTime = row.get(2)?;
                let fields: serde_json::Value = row.get(6)?;
                Ok(LogEntry {
                    event_id: EventId {
                        source_file_id: source_file_id.parse().unwrap(),
                        sequence_number: SequenceNumber::from_raw(sequence_number as u64),
                    },
                    timestamp_utc: timestamp_utc.and_utc(),
                    level: row.get(3)?,
                    message: row.get(4)?,
                    raw: row.get(5)?,
                    fields,
                })
            })
            .unwrap();

        assert_eq!(read_back, entry);
    }

    #[test]
    fn source_round_trips_through_sources_table() {
        let conn = open_test_db();
        let source_file_id = sample_source_file_id();

        conn.execute(
            "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
             VALUES (?, ?, ?, ?, ?)",
            params![
                source_file_id.to_string(),
                "/evidence/system.log",
                "syslog",
                "Europe/Berlin",
                Option::<String>::None,
            ],
        )
        .unwrap();

        let (path, sourcetype): (String, String) = conn
            .query_row(
                "SELECT path, sourcetype FROM sources WHERE source_file_id = ?",
                params![source_file_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(path, "/evidence/system.log");
        assert_eq!(sourcetype, "syslog");
    }

    #[test]
    fn import_tag_round_trips_through_import_tags_table() {
        let conn = open_test_db();
        let source_file_id = sample_source_file_id();

        conn.execute(
            "INSERT INTO import_tags
                (event_id_source, event_id_seq, rule_name, tag_value, applied_at)
             VALUES (?, ?, ?, ?, ?)",
            params![
                source_file_id.to_string(),
                0i64,
                "failed_logon",
                "auth_failure",
                Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
                    .unwrap()
                    .naive_utc(),
            ],
        )
        .unwrap();

        let tag_value: String = conn
            .query_row(
                "SELECT tag_value FROM import_tags WHERE event_id_source = ? AND event_id_seq = ?",
                params![source_file_id.to_string(), 0i64],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(tag_value, "auth_failure");
    }

    #[test]
    fn raw_is_required_by_schema() {
        let conn = open_test_db();
        let source_file_id = sample_source_file_id();

        let result = conn.execute(
            "INSERT INTO log_entries
                (event_id_source, event_id_seq, timestamp_utc, raw)
             VALUES (?, ?, ?, NULL)",
            params![
                source_file_id.to_string(),
                0i64,
                Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
                    .unwrap()
                    .naive_utc(),
            ],
        );

        assert!(result.is_err());
    }

    /// Regression test for the CTAS pitfall documented on
    /// [`setup_timeline_schema_in`]: a catalog-qualified schema, stood up in
    /// an attached database via this function, must keep the same
    /// `PRIMARY KEY` constraint as the unqualified schema — a duplicate
    /// `event_id` must still be rejected, not silently accepted the way a
    /// `CREATE TABLE ... AS SELECT`-built table would.
    #[test]
    fn schema_in_attached_database_keeps_primary_key_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        let mut attached_path = std::env::temp_dir();
        attached_path.push(format!(
            "peach-timeline_schema-test-attached-{}-{}.duckdb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        conn.execute_batch(&format!(
            "ATTACH '{}' AS export_db;",
            attached_path.display()
        ))
        .unwrap();
        setup_timeline_schema_in(&conn, "export_db.main.").unwrap();

        let source_file_id = sample_source_file_id();
        let insert = "INSERT INTO export_db.main.log_entries
                (event_id_source, event_id_seq, timestamp_utc, raw)
             VALUES (?, ?, ?, ?)";
        let ts = Utc
            .with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
            .unwrap()
            .naive_utc();
        conn.execute(
            insert,
            params![source_file_id.to_string(), 0i64, ts, "raw line"],
        )
        .unwrap();

        let duplicate = conn.execute(
            insert,
            params![source_file_id.to_string(), 0i64, ts, "raw line"],
        );
        assert!(
            duplicate.is_err(),
            "duplicate event_id must be rejected by the PRIMARY KEY constraint"
        );

        drop(conn);
        std::fs::remove_file(&attached_path).ok();
        std::fs::remove_file(attached_path.with_extension("duckdb.wal")).ok();
    }
}
