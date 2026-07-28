use rusqlite::{Connection, Result};

/// Creates the session-DB tables (section 4.3 of CLAUDE.md) if they don't
/// already exist: `analyst_tags`, `session_state`.
///
/// `event_id_source` is `TEXT` holding the string form of the UUID from
/// [`crate::model::event_id::SourceFileId`] — same reasoning as the DuckDB
/// timeline schema (see [`crate::db::timeline_schema`]).
pub fn setup_session_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS analyst_tags (
            id                INTEGER PRIMARY KEY,
            event_id_source   TEXT NOT NULL,
            event_id_seq      INTEGER NOT NULL,
            tag_value         TEXT NOT NULL,
            note              TEXT,
            created_at        INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS session_state (
            key    TEXT PRIMARY KEY,
            value  TEXT
        );
        ",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::event_id::SourceFileId;

    fn open_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        conn
    }

    fn sample_source_file_id() -> SourceFileId {
        SourceFileId::new_random()
    }

    #[test]
    fn schema_setup_is_idempotent() {
        let conn = open_test_db();
        setup_session_schema(&conn).unwrap();
    }

    #[test]
    fn analyst_tag_round_trips_through_analyst_tags_table() {
        let conn = open_test_db();
        let source_file_id = sample_source_file_id();

        conn.execute(
            "INSERT INTO analyst_tags
                (event_id_source, event_id_seq, tag_value, note, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                source_file_id.to_string(),
                0i64,
                "reviewed",
                "looks suspicious, follow up",
                1_753_704_000i64,
            ],
        )
        .unwrap();

        let (tag_value, note): (String, Option<String>) = conn
            .query_row(
                "SELECT tag_value, note FROM analyst_tags
                 WHERE event_id_source = ?1 AND event_id_seq = ?2",
                rusqlite::params![source_file_id.to_string(), 0i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(tag_value, "reviewed");
        assert_eq!(note.as_deref(), Some("looks suspicious, follow up"));
    }

    #[test]
    fn session_state_round_trips_through_session_state_table() {
        let conn = open_test_db();

        conn.execute(
            "INSERT INTO session_state (key, value) VALUES (?1, ?2)",
            rusqlite::params!["loaded_sources", r#"["/evidence/system.log"]"#],
        )
        .unwrap();

        let value: String = conn
            .query_row(
                "SELECT value FROM session_state WHERE key = ?1",
                rusqlite::params!["loaded_sources"],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(value, r#"["/evidence/system.log"]"#);
    }

    #[test]
    fn schema_and_round_trip_work_on_a_real_file_backed_database() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "peach-session_schema-test-file-db-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let conn = Connection::open(&path).unwrap();
        setup_session_schema(&conn).unwrap();

        conn.execute(
            "INSERT INTO session_state (key, value) VALUES (?1, ?2)",
            rusqlite::params!["case_name", "case-2026-0728"],
        )
        .unwrap();

        let value: String = conn
            .query_row(
                "SELECT value FROM session_state WHERE key = ?1",
                rusqlite::params!["case_name"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, "case-2026-0728");

        drop(conn);
        std::fs::remove_file(&path).unwrap();
    }
}
