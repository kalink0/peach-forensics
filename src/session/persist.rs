use std::path::{Path, PathBuf};

use anyhow::Context;
use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::session_schema::setup_session_schema;

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

/// A session is a `<id>.duckdb` + `<id>.sqlite` pair in the same directory
/// — the DuckDB file holds the already-parsed timeline (so re-opening a
/// session never re-parses evidence), the SQLite file holds analyst tags
/// and `session_state` (loaded-source list, search query).
#[derive(Debug, Clone)]
pub struct SessionPaths {
    pub id: String,
    pub duckdb_path: PathBuf,
    pub sqlite_path: PathBuf,
}

impl SessionPaths {
    pub fn new_in(dir: &Path, id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            duckdb_path: dir.join(format!("{id}.duckdb")),
            sqlite_path: dir.join(format!("{id}.sqlite")),
            id,
        }
    }

    /// Derives the paired `.duckdb` path from a chosen `.sqlite` session
    /// file (e.g. from a "Load session..." file dialog).
    pub fn from_sqlite_path(sqlite_path: &Path) -> anyhow::Result<Self> {
        let id = sqlite_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid session file name: {}", sqlite_path.display()))?
            .to_string();
        let dir = sqlite_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("session file has no parent directory"))?;
        Ok(Self::new_in(dir, id))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_paths_derive_matching_duckdb_and_sqlite_files() {
        let paths = SessionPaths::new_in(Path::new("/sessions"), "session-20260729-153000");
        assert_eq!(
            paths.duckdb_path,
            Path::new("/sessions/session-20260729-153000.duckdb")
        );
        assert_eq!(
            paths.sqlite_path,
            Path::new("/sessions/session-20260729-153000.sqlite")
        );
    }

    #[test]
    fn from_sqlite_path_round_trips_the_id() {
        let paths =
            SessionPaths::from_sqlite_path(Path::new("/sessions/session-20260729-153000.sqlite"))
                .unwrap();
        assert_eq!(paths.id, "session-20260729-153000");
        assert_eq!(
            paths.duckdb_path,
            Path::new("/sessions/session-20260729-153000.duckdb")
        );
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
}
