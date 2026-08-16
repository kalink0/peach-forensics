use rusqlite::{Connection, Result};

/// Creates the session-DB tables if they don't already exist:
/// `analyst_tags`, `event_notes`, `session_state`.
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

        -- Free-text notes on an event, independent of `analyst_tags` —
        -- deliberately not the `note` column above: that one only ever
        -- exists attached to a tag, and a note shouldn't require picking
        -- or inventing a tag first. See
        -- `session::persist::insert_event_note`'s doc comment.
        CREATE TABLE IF NOT EXISTS event_notes (
            id                INTEGER PRIMARY KEY,
            event_id_source   TEXT NOT NULL,
            event_id_seq      INTEGER NOT NULL,
            note              TEXT NOT NULL,
            created_at        INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS session_state (
            key    TEXT PRIMARY KEY,
            value  TEXT
        );

        -- One row per completed (or failed) load/re-tag operation this
        -- session ever ran — a durable activity log: what was loaded or
        -- re-tagged, when, how many entries/tags resulted, and which files
        -- (if any) were skipped and why. Logged on both success and
        -- failure, per the forensic principle of not letting a problem
        -- quietly disappear (see `ui::activity_log_dialog`). `skipped`,
        -- `per_file`, and `tags_by_rule` are all JSON arrays (`'[]'` when
        -- there's nothing to report) rather than their own tables — same
        -- reasoning as `fields` in the DuckDB timeline schema for a small,
        -- source-shaped value: `per_file` is `{\"path\": ..., \"inserted\":
        -- ...}` per successfully-loaded file (a multi-file load's per-file
        -- breakdown; empty for a re-tag), `tags_by_rule` is `{\"rule_name\":
        -- ..., \"count\": ...}` per rule that matched anything (keyed by
        -- rule *name*, not tag value — several rules can deliberately share
        -- a tag value, e.g. EVTX's group-membership-change rules).
        CREATE TABLE IF NOT EXISTS activity_log (
            id                INTEGER PRIMARY KEY,
            operation         TEXT NOT NULL,
            started_at        INTEGER NOT NULL,
            finished_at       INTEGER NOT NULL,
            source_path       TEXT,
            sourcetype        TEXT,
            status            TEXT NOT NULL,
            error             TEXT,
            entries_inserted  INTEGER,
            tags_applied      INTEGER,
            skipped           TEXT NOT NULL,
            per_file          TEXT NOT NULL,
            tags_by_rule      TEXT NOT NULL
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
    fn event_note_round_trips_through_event_notes_table() {
        let conn = open_test_db();
        let source_file_id = sample_source_file_id();

        conn.execute(
            "INSERT INTO event_notes
                (event_id_source, event_id_seq, note, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                source_file_id.to_string(),
                0i64,
                "looks suspicious, follow up",
                1_753_704_000i64,
            ],
        )
        .unwrap();

        let note: String = conn
            .query_row(
                "SELECT note FROM event_notes
                 WHERE event_id_source = ?1 AND event_id_seq = ?2",
                rusqlite::params![source_file_id.to_string(), 0i64],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(note, "looks suspicious, follow up");
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
    fn activity_log_round_trips_through_activity_log_table() {
        let conn = open_test_db();

        conn.execute(
            "INSERT INTO activity_log
                (operation, started_at, finished_at, source_path, sourcetype,
                 status, error, entries_inserted, tags_applied, skipped,
                 per_file, tags_by_rule)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                "load",
                1_753_704_000i64,
                1_753_704_010i64,
                "/evidence/system.evtx",
                "evtx",
                "ok",
                Option::<String>::None,
                1000i64,
                12i64,
                "[]",
                r#"[{"path":"/evidence/system.evtx","inserted":1000}]"#,
                r#"[{"rule_name":"evtx_logon_success","count":12}]"#,
            ],
        )
        .unwrap();

        let (operation, status, entries_inserted): (String, String, i64) = conn
            .query_row(
                "SELECT operation, status, entries_inserted FROM activity_log WHERE source_path = ?1",
                rusqlite::params!["/evidence/system.evtx"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(operation, "load");
        assert_eq!(status, "ok");
        assert_eq!(entries_inserted, 1000);
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
