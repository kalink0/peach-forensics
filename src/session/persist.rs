use std::path::{Path, PathBuf};

use anyhow::Context;
use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::session_schema::setup_session_schema;
use crate::model::event_id::EventId;

/// Default per-user directory for session files (XDG on Linux, `AppData` on
/// Windows, `Application Support` on macOS) — not user-configurable yet
/// (per the `source-file-id-design`-style incremental approach: a real
/// override UI is a later, separate step, not built preemptively here).
pub fn default_sessions_dir() -> anyhow::Result<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "peach")
        .context("could not determine a per-user data directory on this platform")?;
    let dir = project_dirs.data_dir().join("sessions");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create sessions directory {}", dir.display()))?;
    Ok(dir)
}

pub fn new_session_id() -> String {
    chrono::Utc::now()
        .format("session-%Y%m%d-%H%M%S")
        .to_string()
}

/// A session is its own `<id>/` subdirectory of the sessions directory,
/// holding an `<id>.duckdb` + `<id>.sqlite` pair (filenames still carry the
/// timestamp-embedding id, not just the directory — self-describing even if
/// a file ends up separated from its directory) — the DuckDB file holds the
/// already-parsed timeline (so re-opening a session never re-parses
/// evidence), the SQLite file holds analyst tags and `session_state`
/// (loaded-source list, search query). One directory per session (rather
/// than all sessions' files side by side in one shared directory) means the
/// whole session is exactly one thing to copy/move/zip for a hand-off —
/// see `ui/session_dialog.rs`'s "Open folder" action.
#[derive(Debug, Clone)]
pub struct SessionPaths {
    pub id: String,
    pub duckdb_path: PathBuf,
    pub sqlite_path: PathBuf,
}

impl SessionPaths {
    /// Pure path computation, no filesystem access — a fresh session's
    /// directory doesn't exist on disk yet at this point. Callers that are
    /// actually creating a new session (not just deriving paths for one
    /// that's already there, e.g. `from_sqlite_path`) must call
    /// [`Self::ensure_dir`] before opening either file.
    pub fn new_in(dir: &Path, id: impl Into<String>) -> Self {
        let id = id.into();
        let session_dir = dir.join(&id);
        Self {
            duckdb_path: session_dir.join(format!("{id}.duckdb")),
            sqlite_path: session_dir.join(format!("{id}.sqlite")),
            id,
        }
    }

    /// Derives the sibling `<id>.duckdb` path from a chosen `<id>.sqlite`
    /// file (e.g. from a "Load session..." file dialog) — the session's
    /// directory already exists in this case, so unlike `new_in` at
    /// session-creation time, there's nothing to create here.
    pub fn from_sqlite_path(sqlite_path: &Path) -> anyhow::Result<Self> {
        let id = sqlite_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid session file name: {}", sqlite_path.display()))?
            .to_string();
        let session_dir = sqlite_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("session file has no parent directory"))?;
        let sessions_dir = session_dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("session directory has no parent directory"))?;
        Ok(Self::new_in(sessions_dir, id))
    }

    /// Creates this session's directory if it doesn't exist yet — call
    /// before opening `duckdb_path`/`sqlite_path` for a session just minted
    /// by [`new_session_id`]. A no-op (not an error) if it's already there.
    pub fn ensure_dir(&self) -> anyhow::Result<()> {
        let dir = self
            .sqlite_path
            .parent()
            .expect("sqlite_path always has a parent — it's `session_dir/<id>.sqlite`");
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create session directory {}", dir.display()))
    }
}

/// One source loaded into a session — enough to show the analyst what's in
/// this session without needing the original evidence file to still exist
/// (the actual timeline data already lives in the session's `.duckdb`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LoadedSource {
    pub path: String,
    pub sourcetype: String,
    pub parser_config_path: Option<String>,
}

const LOADED_SOURCES_KEY: &str = "loaded_sources";
const SEARCH_QUERY_KEY: &str = "search_query";

pub fn open_session_db(sqlite_path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(sqlite_path)?;
    setup_session_schema(&conn)?;
    Ok(conn)
}

fn set_session_state(conn: &Connection, key: &str, value: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO session_state (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn get_session_state(conn: &Connection, key: &str) -> anyhow::Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM session_state WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

pub fn save_loaded_sources(conn: &Connection, sources: &[LoadedSource]) -> anyhow::Result<()> {
    set_session_state(conn, LOADED_SOURCES_KEY, &serde_json::to_string(sources)?)
}

pub fn load_loaded_sources(conn: &Connection) -> anyhow::Result<Vec<LoadedSource>> {
    match get_session_state(conn, LOADED_SOURCES_KEY)? {
        Some(json) => Ok(serde_json::from_str(&json)?),
        None => Ok(Vec::new()),
    }
}

pub fn save_search_query(conn: &Connection, query_text: &str) -> anyhow::Result<()> {
    set_session_state(conn, SEARCH_QUERY_KEY, query_text)
}

pub fn load_search_query(conn: &Connection) -> anyhow::Result<Option<String>> {
    get_session_state(conn, SEARCH_QUERY_KEY)
}

/// Records a manual, analyst-driven tag on one entry — a fourth tagging
/// layer alongside import-time/re-tag/ad-hoc rule matching, kept separate
/// from rule-produced `import_tags` precisely because it isn't rule-based:
/// no `rule_name` to attribute it to. Allows duplicates on purpose (no
/// uniqueness check) — a second manual tag with the same value is harmless
/// and simpler than silently swallowing a re-click.
pub fn insert_analyst_tag(
    conn: &Connection,
    event_id: EventId,
    tag_value: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO analyst_tags (event_id_source, event_id_seq, tag_value, note, created_at)
         VALUES (?1, ?2, ?3, NULL, ?4)",
        params![
            event_id.source_file_id.to_string(),
            event_id.sequence_number.value() as i64,
            tag_value,
            chrono::Utc::now().timestamp(),
        ],
    )?;
    Ok(())
}

/// Distinct `tag_value`s already used as analyst tags in this session —
/// feeds the "existing tags" picker in the tagging UI alongside
/// `timeline_queries::distinct_tags` (import_tags), so the picker offers
/// one combined vocabulary regardless of which table a tag happened to
/// come from.
pub fn distinct_analyst_tag_values(conn: &Connection) -> anyhow::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT DISTINCT tag_value FROM analyst_tags ORDER BY tag_value")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Every analyst tag in this session, grouped by [`EventId`] — loaded
/// wholesale rather than filtered per visible window: analyst tags are
/// manually curated one at a time, so this table stays small (unlike
/// `import_tags`, which can hold millions of rule-produced rows), and a
/// row-value `IN` filter would be awkward to express portably in SQLite.
/// Used to merge analyst tags into the timeline's Tags column, which
/// otherwise only reflects `import_tags` (a different database file
/// entirely — DuckDB vs. this SQLite session DB).
pub fn all_analyst_tags(
    conn: &Connection,
) -> anyhow::Result<std::collections::HashMap<EventId, Vec<String>>> {
    let mut stmt =
        conn.prepare("SELECT event_id_source, event_id_seq, tag_value FROM analyst_tags")?;
    let rows = stmt.query_map([], |row| {
        let source_file_id: String = row.get(0)?;
        let sequence_number: i64 = row.get(1)?;
        let tag_value: String = row.get(2)?;
        Ok((source_file_id, sequence_number, tag_value))
    })?;

    let mut by_event: std::collections::HashMap<EventId, Vec<String>> =
        std::collections::HashMap::new();
    for row in rows {
        let (source_file_id, sequence_number, tag_value) = row?;
        let event_id = EventId {
            source_file_id: source_file_id
                .parse()
                .map_err(|err| anyhow::anyhow!("invalid source_file_id in database: {err}"))?,
            sequence_number: crate::model::event_id::SequenceNumber::from_raw(
                sequence_number as u64,
            ),
        };
        by_event.entry(event_id).or_default().push(tag_value);
    }
    Ok(by_event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_paths_derive_matching_duckdb_and_sqlite_files_in_their_own_subdir() {
        let paths = SessionPaths::new_in(Path::new("/sessions"), "session-20260729-153000");
        assert_eq!(
            paths.duckdb_path,
            Path::new("/sessions/session-20260729-153000/session-20260729-153000.duckdb")
        );
        assert_eq!(
            paths.sqlite_path,
            Path::new("/sessions/session-20260729-153000/session-20260729-153000.sqlite")
        );
    }

    #[test]
    fn from_sqlite_path_round_trips_the_id() {
        let paths = SessionPaths::from_sqlite_path(Path::new(
            "/sessions/session-20260729-153000/session-20260729-153000.sqlite",
        ))
        .unwrap();
        assert_eq!(paths.id, "session-20260729-153000");
        assert_eq!(
            paths.duckdb_path,
            Path::new("/sessions/session-20260729-153000/session-20260729-153000.duckdb")
        );
    }

    #[test]
    fn ensure_dir_creates_the_session_subdirectory() {
        let dir = std::env::temp_dir().join(format!(
            "peach-persist-test-ensure-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = SessionPaths::new_in(&dir, "session-20260729-153000");
        assert!(!paths.sqlite_path.parent().unwrap().exists());

        paths.ensure_dir().unwrap();

        assert!(paths.sqlite_path.parent().unwrap().is_dir());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn new_session_id_is_stable_length_and_prefixed() {
        let id = new_session_id();
        assert!(id.starts_with("session-"));
    }

    #[test]
    fn loaded_sources_round_trip_through_session_state() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        assert_eq!(load_loaded_sources(&conn).unwrap(), Vec::new());

        let sources = vec![
            LoadedSource {
                path: "/evidence/a.log".to_string(),
                sourcetype: "syslog".to_string(),
                parser_config_path: Some("/configs/syslog.toml".to_string()),
            },
            LoadedSource {
                path: "/evidence/b.logarchive".to_string(),
                sourcetype: "aul".to_string(),
                parser_config_path: None,
            },
        ];
        save_loaded_sources(&conn, &sources).unwrap();

        assert_eq!(load_loaded_sources(&conn).unwrap(), sources);
    }

    #[test]
    fn saving_loaded_sources_again_overwrites_not_duplicates() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        let first = vec![LoadedSource {
            path: "/a".to_string(),
            sourcetype: "aul".to_string(),
            parser_config_path: None,
        }];
        let second = vec![
            LoadedSource {
                path: "/a".to_string(),
                sourcetype: "aul".to_string(),
                parser_config_path: None,
            },
            LoadedSource {
                path: "/b".to_string(),
                sourcetype: "evtx".to_string(),
                parser_config_path: None,
            },
        ];
        save_loaded_sources(&conn, &first).unwrap();
        save_loaded_sources(&conn, &second).unwrap();

        assert_eq!(load_loaded_sources(&conn).unwrap(), second);
    }

    #[test]
    fn search_query_round_trips_and_defaults_to_none() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        assert_eq!(load_search_query(&conn).unwrap(), None);

        save_search_query(&conn, "level=ERROR").unwrap();
        assert_eq!(
            load_search_query(&conn).unwrap(),
            Some("level=ERROR".to_string())
        );

        save_search_query(&conn, "tag=reviewed").unwrap();
        assert_eq!(
            load_search_query(&conn).unwrap(),
            Some("tag=reviewed".to_string())
        );
    }

    use crate::model::event_id::{SequenceCounter, SourceFileId};

    #[test]
    fn insert_analyst_tag_is_readable_back_via_distinct_values() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceCounter::new().next_sequence_number(),
        };

        insert_analyst_tag(&conn, event_id, "reviewed").unwrap();

        assert_eq!(
            distinct_analyst_tag_values(&conn).unwrap(),
            vec!["reviewed".to_string()]
        );
    }

    #[test]
    fn all_analyst_tags_groups_by_event_id() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let source_file_id = SourceFileId::new_random();
        let mut counter = SequenceCounter::new();
        let a = EventId {
            source_file_id,
            sequence_number: counter.next_sequence_number(),
        };
        let b = EventId {
            source_file_id,
            sequence_number: counter.next_sequence_number(),
        };

        insert_analyst_tag(&conn, a, "reviewed").unwrap();
        insert_analyst_tag(&conn, a, "follow_up").unwrap();
        insert_analyst_tag(&conn, b, "reviewed").unwrap();

        let by_event = all_analyst_tags(&conn).unwrap();

        let mut a_tags = by_event.get(&a).unwrap().clone();
        a_tags.sort();
        assert_eq!(a_tags, vec!["follow_up", "reviewed"]);
        assert_eq!(by_event.get(&b).unwrap(), &vec!["reviewed".to_string()]);
    }

    #[test]
    fn all_analyst_tags_is_empty_when_none_recorded() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        assert!(all_analyst_tags(&conn).unwrap().is_empty());
    }
}
