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

/// A fresh, one-off directory under the OS temp directory for
/// `--ephemeral-session` runs — deliberately *not* under
/// [`default_sessions_dir`]/the configured sessions dir: the whole point of
/// `--ephemeral-session` is that this run's `.duckdb`/`.sqlite` (an
/// unencrypted copy of whatever was loaded — potentially a temp-extracted
/// or decrypted evidence source handed off by crush via `--add-source`/
/// `--cleanup-dir`) never lands in the persistent sessions directory in the
/// first place, rather than landing there and being deleted afterwards.
/// PID + nanosecond timestamp in the name, same collision-avoidance
/// approach as `Settings::sessions_dir`'s own test helper — concurrent
/// Peach instances must never share this directory.
pub fn new_ephemeral_sessions_dir() -> anyhow::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "peach-ephemeral-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).with_context(|| {
        format!(
            "failed to create ephemeral session directory {}",
            dir.display()
        )
    })?;
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
    /// This load's `source_file_id` (see
    /// [`crate::model::event_id::SourceFileId`]), as a string — what
    /// `ui::filter_bar`'s per-source visibility chips target with a
    /// `source_id=` term. `#[serde(default)]` so a session saved before
    /// this field existed still deserializes: it just decodes to an empty
    /// string, which never matches a real `source_file_id` and so simply
    /// can't be individually hidden until that source is reloaded — a
    /// graceful degradation, not a broken session.
    #[serde(default)]
    pub source_file_id: String,
}

const LOADED_SOURCES_KEY: &str = "loaded_sources";
const SEARCH_QUERY_KEY: &str = "search_query";
const DISPLAY_NAME_KEY: &str = "display_name";

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

/// A human-chosen display name for this session, shown instead of its id
/// (`session-YYYYMMDD-HHMMSS`) wherever the analyst sees the session
/// listed — never the underlying files: `SessionPaths::from_sqlite_path`
/// derives the id straight from `<id>.sqlite`'s file stem, so renaming the
/// files themselves would mean either keeping id and filename in sync
/// forever or breaking that derivation. A separate `session_state` entry
/// sidesteps both — the on-disk name never has to change for the analyst's
/// own label to.
pub fn save_display_name(conn: &Connection, name: &str) -> anyhow::Result<()> {
    set_session_state(conn, DISPLAY_NAME_KEY, name)
}

pub fn load_display_name(conn: &Connection) -> anyhow::Result<Option<String>> {
    get_session_state(conn, DISPLAY_NAME_KEY)
}

/// Records a manual, analyst-driven tag on one entry — a fourth tagging
/// layer alongside import-time/re-tag/ad-hoc rule matching, kept separate
/// from rule-produced `import_tags` precisely because it isn't rule-based:
/// no `rule_name` to attribute it to. Allows duplicates on purpose (no
/// uniqueness check) — a second manual tag with the same value is harmless
/// and simpler than silently swallowing a re-click. `analyst_tags.note`
/// stays unused here on purpose — a free-text note is its own concept, not
/// something that only exists attached to a tag, so it's recorded via
/// [`insert_event_note`]/[`event_notes`] instead, not this column.
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

/// Records a free-text note on one entry — independent of tags entirely
/// (no `tag_value`, no dependency on one existing): an analyst should be
/// able to jot down an observation on any event without first having to
/// invent or pick a tag for it. A separate table from `analyst_tags`
/// rather than reusing its unused `note` column for exactly that reason —
/// conflating "a tag with optional commentary" and "a standalone
/// annotation" into one table would make the tag-less case awkward to
/// express (what tag value would a note-only row even have?) and mix two
/// different concepts the analyst thinks of separately. Allows duplicates
/// on purpose, same reasoning as [`insert_analyst_tag`] — a running list of
/// observations over time is a legitimate use, not something to dedupe
/// away.
pub fn insert_event_note(conn: &Connection, event_id: EventId, note: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO event_notes (event_id_source, event_id_seq, note, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            event_id.source_file_id.to_string(),
            event_id.sequence_number.value() as i64,
            note,
            chrono::Utc::now().timestamp(),
        ],
    )?;
    Ok(())
}

/// Every note in this session, grouped by [`EventId`] and ordered oldest
/// first — loaded wholesale, same reasoning as [`all_analyst_tags`] (notes
/// are manually curated one at a time, so this table stays small). Used to
/// merge notes into the timeline's Tags column hover text.
pub fn all_event_notes(
    conn: &Connection,
) -> anyhow::Result<std::collections::HashMap<EventId, Vec<String>>> {
    let mut stmt = conn.prepare(
        // `id` (autoincrement) as the primary sort key, not `created_at`:
        // the latter is second-resolution (`chrono::Utc::now().timestamp()`),
        // so two notes added within the same second would otherwise have no
        // stable order between them.
        "SELECT event_id_source, event_id_seq, note FROM event_notes ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        let source_file_id: String = row.get(0)?;
        let sequence_number: i64 = row.get(1)?;
        let note: String = row.get(2)?;
        Ok((source_file_id, sequence_number, note))
    })?;

    let mut by_event: std::collections::HashMap<EventId, Vec<String>> =
        std::collections::HashMap::new();
    for row in rows {
        let (source_file_id, sequence_number, note) = row?;
        let event_id = EventId {
            source_file_id: source_file_id
                .parse()
                .map_err(|err| anyhow::anyhow!("invalid source_file_id in database: {err}"))?,
            sequence_number: crate::model::event_id::SequenceNumber::from_raw(
                sequence_number as u64,
            ),
        };
        by_event.entry(event_id).or_default().push(note);
    }
    Ok(by_event)
}

/// `(id, note)` pairs for one event, oldest first — unlike [`all_event_notes`]
/// (bulk, text-only, for the Tags column's hover preview), this keeps each
/// note's row id so the "Notes" dialog can target a specific one for
/// [`update_event_note`]/[`delete_event_note`]. Fetched fresh whenever that
/// dialog opens or changes something, rather than filtered out of a bulk
/// load — a single event's notes are always few, so a per-event query costs
/// nothing extra and stays correct without the dialog having to track
/// indices into a larger structure.
pub fn notes_for_event(conn: &Connection, event_id: EventId) -> anyhow::Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT id, note FROM event_notes
         WHERE event_id_source = ?1 AND event_id_seq = ?2
         ORDER BY id",
    )?;
    let rows = stmt.query_map(
        params![
            event_id.source_file_id.to_string(),
            event_id.sequence_number.value() as i64
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Overwrites one note's text in place, identified by its row id (from
/// [`notes_for_event`]) — an analyst correcting a typo or refining an
/// observation edits the existing note rather than leaving a stale one
/// behind and adding a new one.
pub fn update_event_note(conn: &Connection, note_id: i64, note: &str) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE event_notes SET note = ?1 WHERE id = ?2",
        params![note, note_id],
    )?;
    Ok(())
}

/// Removes one note by its row id (from [`notes_for_event`]) — a real
/// filesystem-level SQL delete, no undo, same as
/// `session_dialog::delete_session_files`'s reasoning: an analyst managing
/// their own annotations should be able to retract one that turned out to
/// be wrong, without that requiring a confirmation dialog the way deleting
/// a whole session does (a single note is much lower stakes than a whole
/// case's data).
pub fn delete_event_note(conn: &Connection, note_id: i64) -> anyhow::Result<()> {
    conn.execute("DELETE FROM event_notes WHERE id = ?1", params![note_id])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ephemeral_sessions_dir_creates_a_fresh_directory_under_os_temp() {
        let dir = new_ephemeral_sessions_dir().unwrap();

        assert!(dir.is_dir());
        assert!(dir.starts_with(std::env::temp_dir()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn new_ephemeral_sessions_dir_is_unique_per_call() {
        let a = new_ephemeral_sessions_dir().unwrap();
        let b = new_ephemeral_sessions_dir().unwrap();

        assert_ne!(a, b);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

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
                source_file_id: "11111111-1111-1111-1111-111111111111".to_string(),
            },
            LoadedSource {
                path: "/evidence/b.logarchive".to_string(),
                sourcetype: "aul".to_string(),
                parser_config_path: None,
                source_file_id: "22222222-2222-2222-2222-222222222222".to_string(),
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
            source_file_id: "id-a".to_string(),
        }];
        let second = vec![
            LoadedSource {
                path: "/a".to_string(),
                sourcetype: "aul".to_string(),
                parser_config_path: None,
                source_file_id: "id-a".to_string(),
            },
            LoadedSource {
                path: "/b".to_string(),
                sourcetype: "evtx".to_string(),
                parser_config_path: None,
                source_file_id: "id-b".to_string(),
            },
        ];
        save_loaded_sources(&conn, &first).unwrap();
        save_loaded_sources(&conn, &second).unwrap();

        assert_eq!(load_loaded_sources(&conn).unwrap(), second);
    }

    /// Regression test: a session saved before `source_file_id` existed on
    /// `LoadedSource` has that field simply absent from its stored JSON.
    /// `#[serde(default)]` must let that still deserialize (as an empty
    /// string, not an error) — without it, every session saved before this
    /// field was added would fail to load at all the moment this shipped.
    #[test]
    fn loaded_sources_without_a_source_file_id_deserialize_as_a_pre_upgrade_session_would() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let legacy_json = serde_json::to_string(&serde_json::json!([{
            "path": "/evidence/old.log",
            "sourcetype": "syslog",
            "parser_config_path": null,
        }]))
        .unwrap();
        conn.execute(
            "INSERT INTO session_state (key, value) VALUES (?1, ?2)",
            params![LOADED_SOURCES_KEY, legacy_json],
        )
        .unwrap();

        let loaded = load_loaded_sources(&conn).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].path, "/evidence/old.log");
        assert_eq!(loaded[0].source_file_id, "");
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

    #[test]
    fn display_name_round_trips_and_defaults_to_none() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        assert_eq!(load_display_name(&conn).unwrap(), None);

        save_display_name(&conn, "Suspect laptop, 2026-08-01").unwrap();
        assert_eq!(
            load_display_name(&conn).unwrap(),
            Some("Suspect laptop, 2026-08-01".to_string())
        );

        save_display_name(&conn, "renamed").unwrap();
        assert_eq!(
            load_display_name(&conn).unwrap(),
            Some("renamed".to_string())
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

    #[test]
    fn insert_event_note_does_not_require_a_tag() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceCounter::new().next_sequence_number(),
        };

        insert_event_note(&conn, event_id, "looks suspicious").unwrap();

        let by_event = all_event_notes(&conn).unwrap();
        assert_eq!(
            by_event.get(&event_id).unwrap(),
            &vec!["looks suspicious".to_string()]
        );
        // No analyst tag was ever inserted for this event — the note stands
        // entirely on its own.
        assert!(all_analyst_tags(&conn).unwrap().is_empty());
    }

    #[test]
    fn all_event_notes_orders_multiple_notes_on_one_event_oldest_first() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceCounter::new().next_sequence_number(),
        };

        insert_event_note(&conn, event_id, "first observation").unwrap();
        insert_event_note(&conn, event_id, "second observation").unwrap();

        let by_event = all_event_notes(&conn).unwrap();

        assert_eq!(
            by_event.get(&event_id).unwrap(),
            &vec![
                "first observation".to_string(),
                "second observation".to_string()
            ]
        );
    }

    #[test]
    fn all_event_notes_is_empty_when_none_recorded() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        assert!(all_event_notes(&conn).unwrap().is_empty());
    }

    #[test]
    fn notes_for_event_returns_ids_ordered_oldest_first() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceCounter::new().next_sequence_number(),
        };
        let other_event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceCounter::new().next_sequence_number(),
        };

        insert_event_note(&conn, event_id, "first").unwrap();
        insert_event_note(&conn, event_id, "second").unwrap();
        insert_event_note(&conn, other_event_id, "unrelated").unwrap();

        let notes = notes_for_event(&conn, event_id).unwrap();

        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].1, "first");
        assert_eq!(notes[1].1, "second");
        assert!(notes[0].0 < notes[1].0, "ids must be in insertion order");
    }

    #[test]
    fn update_event_note_overwrites_the_text_in_place() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceCounter::new().next_sequence_number(),
        };
        insert_event_note(&conn, event_id, "typoo").unwrap();
        let note_id = notes_for_event(&conn, event_id).unwrap()[0].0;

        update_event_note(&conn, note_id, "typo fixed").unwrap();

        let notes = notes_for_event(&conn, event_id).unwrap();
        assert_eq!(notes.len(), 1, "update must not add a new row");
        assert_eq!(notes[0], (note_id, "typo fixed".to_string()));
    }

    #[test]
    fn delete_event_note_removes_only_the_targeted_note() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceCounter::new().next_sequence_number(),
        };
        insert_event_note(&conn, event_id, "keep me").unwrap();
        insert_event_note(&conn, event_id, "delete me").unwrap();
        let notes = notes_for_event(&conn, event_id).unwrap();
        let to_delete = notes
            .iter()
            .find(|(_, text)| text == "delete me")
            .unwrap()
            .0;

        delete_event_note(&conn, to_delete).unwrap();

        let remaining = notes_for_event(&conn, event_id).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].1, "keep me");
    }
}
