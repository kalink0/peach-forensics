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

/// A fresh, one-off directory under `base` (the OS temp directory by
/// default, or `Settings::staging_dir`'s override) for `--ephemeral-session`
/// runs — deliberately *not* under [`default_sessions_dir`]/the configured
/// sessions dir: the whole point of `--ephemeral-session` is that this
/// run's `.duckdb`/`.sqlite` (an unencrypted copy of whatever was loaded —
/// potentially a temp-extracted or decrypted evidence source handed off by
/// crush via `--add-source`/`--cleanup-dir`) never lands in the persistent
/// sessions directory in the first place, rather than landing there and
/// being deleted afterwards. `base` is caller-supplied rather than hardcoded
/// to `std::env::temp_dir()` so an analyst can point it at a volume with
/// room for a full-size bulk timeline instead of a small/constrained OS
/// temp directory (see `Settings::staging_dir`'s doc comment). PID +
/// nanosecond timestamp in the name, same collision-avoidance approach as
/// `Settings::sessions_dir`'s own test helper — concurrent Peach instances
/// must never share this directory.
pub fn new_ephemeral_sessions_dir(base: &Path) -> anyhow::Result<PathBuf> {
    let dir = base.join(format!(
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

/// Mints a fresh, collision-safe session directory for a `portable_case`
/// import — never reuses the bundle's original session id (see
/// `session::portable_case`'s design notes: a portable case must never be
/// able to clobber an existing local session, even the same bundle imported
/// twice back to back).
///
/// `new_session_id()` is only second-resolution and [`SessionPaths::ensure_dir`]
/// is a silent no-op on an already-existing directory, so two imports within
/// the same wall-clock second (a plausible fast double-click, or importing
/// the same bundle twice back to back — the exact scenario a test drives
/// deliberately) could otherwise land in the same directory undetected.
/// This claims the directory with `fs::create_dir` (which fails with
/// `AlreadyExists` unlike `create_dir_all`, which can't tell "created" from
/// "already there") and retries with a freshly minted id on collision, using
/// [`new_import_session_id`] (not plain [`new_session_id`]) so that retry
/// has real teeth: a random suffix makes a same-second collision
/// astronomically unlikely on the very first attempt, rather than the loop
/// having to sit and wait out a wall-clock tick that may not even help
/// (`new_session_id()` alone would return the exact same string every time
/// within that second).
pub fn new_session_dir_for_import(sessions_dir: &Path) -> anyhow::Result<SessionPaths> {
    new_session_dir_with_id_fn(sessions_dir, new_import_session_id)
}

/// Id generator for [`new_session_dir_for_import`] — unlike
/// [`new_session_id`] (second resolution, fine for a human clicking "New
/// session" once at a time), a fast double-import of the same bundle can
/// easily land in the same second, so this appends a short random suffix
/// for practical uniqueness even then.
fn new_import_session_id() -> String {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    format!("{}-{}", new_session_id(), &suffix[..8])
}

fn new_session_dir_with_id_fn(
    sessions_dir: &Path,
    mut next_id: impl FnMut() -> String,
) -> anyhow::Result<SessionPaths> {
    const MAX_ATTEMPTS: u32 = 20;
    for _ in 0..MAX_ATTEMPTS {
        let id = next_id();
        let session_dir = sessions_dir.join(&id);
        match std::fs::create_dir(&session_dir) {
            Ok(()) => return Ok(SessionPaths::new_in(sessions_dir, id)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to create session directory {}",
                        session_dir.display()
                    )
                });
            }
        }
    }
    anyhow::bail!("could not allocate a unique session id after {MAX_ATTEMPTS} attempts")
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

const IMPORTED_FROM_KEY: &str = "imported_from";

/// Provenance record for a session that arrived via a `portable_case`
/// import — written once at import time so an analyst can see where a
/// session came from (which original session, when it was exported, by
/// which Peach version, under what filter) without digging through
/// `activity_log`, which also gets a matching `"import"` entry but is meant
/// for the operation history, not a quick-glance provenance check.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImportedFrom {
    pub original_session_id: String,
    pub exported_at: chrono::DateTime<chrono::Utc>,
    pub exporting_peach_version: String,
    /// The search query the export was filtered by, `""` if it was a whole,
    /// unfiltered session export.
    pub filter_query: String,
}

pub fn save_imported_from(conn: &Connection, info: &ImportedFrom) -> anyhow::Result<()> {
    set_session_state(conn, IMPORTED_FROM_KEY, &serde_json::to_string(info)?)
}

pub fn load_imported_from(conn: &Connection) -> anyhow::Result<Option<ImportedFrom>> {
    match get_session_state(conn, IMPORTED_FROM_KEY)? {
        Some(json) => Ok(Some(serde_json::from_str(&json)?)),
        None => Ok(None),
    }
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

/// One file `run_load` skipped, as recorded in an [`ActivityLogEntry`]/written
/// via [`NewActivityLogEntry`] — a session-DB-persisted mirror of `app.rs`'s
/// own (private, DuckDB-load-only) `SkippedFile`, not the same type: this
/// module can't depend on `app` (the dependency runs the other way), and
/// the two exist for different reasons — `app::SkippedFile` is transient
/// per-load UI state, this is what actually gets written to `activity_log`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ActivitySkippedFile {
    pub path: String,
    pub reason: String,
}

/// One successfully-loaded file's contribution to a load, as recorded in
/// `activity_log.per_file` — a multi-file load's per-file breakdown (e.g. a
/// folder pick). Always empty for a `"retag"` operation: a re-tag applies
/// across whatever's already loaded, not to individual files.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ActivityFileCount {
    pub path: String,
    pub inserted: usize,
    /// How many records from this file were skipped instead of aborting
    /// the whole file, under "skip bad records" mode — see
    /// `parsers::SkippedRecord`. `#[serde(default)]` so a `per_file` JSON
    /// blob written before this field existed still deserializes (as `0`,
    /// same as if skip mode had never been used).
    #[serde(default)]
    pub records_skipped: usize,
}

/// One rule's contribution to a load or re-tag's tagging pass, as recorded
/// in `activity_log.tags_by_rule` — keyed by rule *name*, not `tag.value`:
/// several rules can deliberately share a tag value (e.g. EVTX's
/// group-membership-change rules), so a tag-value breakdown wouldn't answer
/// "how many did rule X tag" at all.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ActivityRuleCount {
    pub rule_name: String,
    pub count: usize,
    /// This rule's `tagging::rule::RuleBody::version` at the moment this
    /// load/re-tag ran — `None` for a rule with no `version` field (an
    /// older or hand-written rule outside the shipped/downloaded packs,
    /// see `docs/design/rule-pack-updates.md` §5) and, via `#[serde(default)]`,
    /// for any `activity_log` row written before this field existed.
    /// This is what answers "which rule-pack version tagged this source"
    /// for a given load/re-tag — deliberately not a separate "pack was
    /// updated" log event, since that wouldn't be tied to any particular
    /// run; see §5 for the full reasoning.
    #[serde(default)]
    pub version: Option<String>,
}

/// One row from `activity_log` — what one load or re-tag operation did, read
/// back via [`all_activity_log_entries`]. See [`NewActivityLogEntry`] for what's
/// written; the two aren't the same type because `id` only exists once a
/// row is actually in the database.
#[derive(Debug, Clone, PartialEq)]
pub struct ActivityLogEntry {
    pub id: i64,
    pub operation: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub source_path: Option<String>,
    pub sourcetype: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub entries_inserted: Option<i64>,
    pub tags_applied: Option<i64>,
    pub skipped: Vec<ActivitySkippedFile>,
    pub per_file: Vec<ActivityFileCount>,
    pub tags_by_rule: Vec<ActivityRuleCount>,
    /// Whether this load ran with "skip bad records instead of failing"
    /// turned on — the analyst's choice to tolerate corruption is itself
    /// forensically relevant and must stay visible, not just the resulting
    /// skip counts. Always `false` for a `"retag"` operation (the toggle
    /// only ever applies to loads).
    pub skip_bad_records_enabled: bool,
}

/// What [`insert_activity_log_entry`] writes — every field owned rather than
/// borrowed: callers (`app.rs`'s background load/re-tag threads) build this
/// from temporaries (`format!`, `.display().to_string()`, a freshly mapped
/// `Vec`) that don't outlive the call, so borrowing would just make the
/// call site fight the borrow checker for no benefit.
pub struct NewActivityLogEntry {
    pub operation: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub source_path: Option<String>,
    pub sourcetype: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub entries_inserted: Option<i64>,
    pub tags_applied: Option<i64>,
    pub skipped: Vec<ActivitySkippedFile>,
    pub per_file: Vec<ActivityFileCount>,
    pub tags_by_rule: Vec<ActivityRuleCount>,
    pub skip_bad_records_enabled: bool,
}

/// Records one completed or failed load/re-tag operation — the durable
/// activity log (see `db::session_schema::setup_session_schema`'s doc
/// comment on `activity_log`). Called on both success and failure: a failed
/// load is exactly the kind of thing this log must not let quietly
/// disappear.
pub fn insert_activity_log_entry(
    conn: &Connection,
    entry: NewActivityLogEntry,
) -> anyhow::Result<()> {
    let skipped_json = serde_json::to_string(&entry.skipped)
        .context("failed to serialize activity_log skipped-files list")?;
    let per_file_json = serde_json::to_string(&entry.per_file)
        .context("failed to serialize activity_log per-file breakdown")?;
    let tags_by_rule_json = serde_json::to_string(&entry.tags_by_rule)
        .context("failed to serialize activity_log per-rule breakdown")?;
    conn.execute(
        "INSERT INTO activity_log
            (operation, started_at, finished_at, source_path, sourcetype,
             status, error, entries_inserted, tags_applied, skipped,
             per_file, tags_by_rule, skip_bad_records_enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            entry.operation,
            entry.started_at,
            entry.finished_at,
            entry.source_path,
            entry.sourcetype,
            entry.status,
            entry.error,
            entry.entries_inserted,
            entry.tags_applied,
            skipped_json,
            per_file_json,
            tags_by_rule_json,
            entry.skip_bad_records_enabled,
        ],
    )?;
    Ok(())
}

/// Every activity log entry in this session, newest first — loaded wholesale
/// like [`all_analyst_tags`]/[`all_event_notes`]: one row per load/re-tag
/// operation, never per timeline entry, so this table stays small
/// regardless of how large the loaded evidence is.
pub fn all_activity_log_entries(conn: &Connection) -> anyhow::Result<Vec<ActivityLogEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, operation, started_at, finished_at, source_path, sourcetype,
                status, error, entries_inserted, tags_applied, skipped,
                per_file, tags_by_rule, skip_bad_records_enabled
         FROM activity_log ORDER BY id DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        let skipped_json: String = row.get(10)?;
        let per_file_json: String = row.get(11)?;
        let tags_by_rule_json: String = row.get(12)?;
        Ok((
            ActivityLogEntry {
                id: row.get(0)?,
                operation: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                source_path: row.get(4)?,
                sourcetype: row.get(5)?,
                status: row.get(6)?,
                error: row.get(7)?,
                entries_inserted: row.get(8)?,
                tags_applied: row.get(9)?,
                skipped: Vec::new(),
                per_file: Vec::new(),
                tags_by_rule: Vec::new(),
                skip_bad_records_enabled: row.get(13)?,
            },
            skipped_json,
            per_file_json,
            tags_by_rule_json,
        ))
    })?;

    rows.map(|row| {
        let (mut entry, skipped_json, per_file_json, tags_by_rule_json) = row?;
        entry.skipped = serde_json::from_str(&skipped_json)
            .context("failed to deserialize activity_log skipped-files list")?;
        entry.per_file = serde_json::from_str(&per_file_json)
            .context("failed to deserialize activity_log per-file breakdown")?;
        entry.tags_by_rule = serde_json::from_str(&tags_by_rule_json)
            .context("failed to deserialize activity_log per-rule breakdown")?;
        Ok(entry)
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ephemeral_sessions_dir_creates_a_fresh_directory_under_the_given_base() {
        let base = std::env::temp_dir();
        let dir = new_ephemeral_sessions_dir(&base).unwrap();

        assert!(dir.is_dir());
        assert!(dir.starts_with(&base));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn new_ephemeral_sessions_dir_is_unique_per_call() {
        let base = std::env::temp_dir();
        let a = new_ephemeral_sessions_dir(&base).unwrap();
        let b = new_ephemeral_sessions_dir(&base).unwrap();

        assert_ne!(a, b);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn new_ephemeral_sessions_dir_honors_a_custom_base() {
        let base = std::env::temp_dir().join(format!(
            "peach-persist-test-ephemeral-base-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();

        let dir = new_ephemeral_sessions_dir(&base).unwrap();

        assert!(dir.starts_with(&base));
        std::fs::remove_dir_all(&base).unwrap();
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

    #[test]
    fn imported_from_round_trips_and_defaults_to_none() {
        use chrono::TimeZone;

        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        assert_eq!(load_imported_from(&conn).unwrap(), None);

        let info = ImportedFrom {
            original_session_id: "session-20260801-120000".to_string(),
            exported_at: chrono::Utc.with_ymd_and_hms(2026, 8, 26, 14, 0, 0).unwrap(),
            exporting_peach_version: "0.2.1".to_string(),
            filter_query: "level=ERROR".to_string(),
        };
        save_imported_from(&conn, &info).unwrap();

        assert_eq!(load_imported_from(&conn).unwrap(), Some(info));
    }

    #[test]
    fn new_session_dir_for_import_creates_the_directory() {
        let dir = std::env::temp_dir().join(format!(
            "peach-persist-test-import-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let paths = new_session_dir_for_import(&dir).unwrap();

        assert!(paths.sqlite_path.parent().unwrap().is_dir());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Regression test for the collision described on
    /// [`new_session_dir_for_import`]'s doc comment: two imports minting the
    /// same id (plausible within the same wall-clock second) must not land
    /// in the same directory — the second attempt must retry with a fresh
    /// id instead of silently reusing the first one's directory.
    #[test]
    fn new_session_dir_with_id_fn_retries_past_a_colliding_id() {
        let dir = std::env::temp_dir().join(format!(
            "peach-persist-test-import-collision-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir(dir.join("session-collide")).unwrap();

        let mut ids = ["session-collide", "session-collide", "session-unique"].into_iter();
        let paths = new_session_dir_with_id_fn(&dir, || ids.next().unwrap().to_string()).unwrap();

        assert_eq!(paths.id, "session-unique");
        assert!(dir.join("session-unique").is_dir());
        std::fs::remove_dir_all(&dir).unwrap();
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

    fn sample_load_entry(source_path: &str, status: &str) -> NewActivityLogEntry {
        NewActivityLogEntry {
            operation: "load".to_string(),
            started_at: 1_753_704_000,
            finished_at: 1_753_704_010,
            source_path: Some(source_path.to_string()),
            sourcetype: Some("evtx".to_string()),
            status: status.to_string(),
            error: if status == "failed" {
                Some("boom".to_string())
            } else {
                None
            },
            entries_inserted: Some(1000),
            tags_applied: Some(12),
            skipped: vec![ActivitySkippedFile {
                path: "/evidence/bad.evtx".to_string(),
                reason: "not a valid EVTX file".to_string(),
            }],
            per_file: vec![ActivityFileCount {
                path: source_path.to_string(),
                inserted: 1000,
                records_skipped: 3,
            }],
            tags_by_rule: vec![ActivityRuleCount {
                rule_name: "evtx_logon_success".to_string(),
                count: 12,
                version: Some("2".to_string()),
            }],
            skip_bad_records_enabled: true,
        }
    }

    #[test]
    fn insert_activity_log_entry_round_trips_every_field() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        insert_activity_log_entry(&conn, sample_load_entry("/evidence/system.evtx", "ok")).unwrap();

        let entries = all_activity_log_entries(&conn).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.operation, "load");
        assert_eq!(entry.started_at, 1_753_704_000);
        assert_eq!(entry.finished_at, 1_753_704_010);
        assert_eq!(entry.source_path.as_deref(), Some("/evidence/system.evtx"));
        assert_eq!(entry.sourcetype.as_deref(), Some("evtx"));
        assert_eq!(entry.status, "ok");
        assert_eq!(entry.error, None);
        assert_eq!(entry.entries_inserted, Some(1000));
        assert_eq!(entry.tags_applied, Some(12));
        assert_eq!(
            entry.skipped,
            vec![ActivitySkippedFile {
                path: "/evidence/bad.evtx".to_string(),
                reason: "not a valid EVTX file".to_string(),
            }]
        );
        assert_eq!(
            entry.per_file,
            vec![ActivityFileCount {
                path: "/evidence/system.evtx".to_string(),
                inserted: 1000,
                records_skipped: 3,
            }]
        );
        assert_eq!(
            entry.tags_by_rule,
            vec![ActivityRuleCount {
                rule_name: "evtx_logon_success".to_string(),
                count: 12,
                version: Some("2".to_string()),
            }]
        );
        assert!(entry.skip_bad_records_enabled);
    }

    #[test]
    fn insert_activity_log_entry_records_a_failure_with_its_error() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        insert_activity_log_entry(&conn, sample_load_entry("/evidence/broken.evtx", "failed"))
            .unwrap();

        let entries = all_activity_log_entries(&conn).unwrap();
        assert_eq!(entries[0].status, "failed");
        assert_eq!(entries[0].error.as_deref(), Some("boom"));
    }

    #[test]
    fn all_activity_log_entries_is_empty_with_nothing_recorded() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        assert!(all_activity_log_entries(&conn).unwrap().is_empty());
    }

    #[test]
    fn all_activity_log_entries_orders_newest_first() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        insert_activity_log_entry(&conn, sample_load_entry("/evidence/first.evtx", "ok")).unwrap();
        insert_activity_log_entry(&conn, sample_load_entry("/evidence/second.evtx", "ok")).unwrap();

        let entries = all_activity_log_entries(&conn).unwrap();
        assert_eq!(
            entries[0].source_path.as_deref(),
            Some("/evidence/second.evtx")
        );
        assert_eq!(
            entries[1].source_path.as_deref(),
            Some("/evidence/first.evtx")
        );
    }

    #[test]
    fn activity_log_entry_with_no_skipped_files_round_trips_as_an_empty_list() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        let mut entry = sample_load_entry("/evidence/clean.evtx", "ok");
        entry.skipped = Vec::new();

        insert_activity_log_entry(&conn, entry).unwrap();

        assert!(
            all_activity_log_entries(&conn).unwrap()[0]
                .skipped
                .is_empty()
        );
    }

    #[test]
    fn retag_activity_log_entry_has_no_source_path_or_skipped_files() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();

        insert_activity_log_entry(
            &conn,
            NewActivityLogEntry {
                operation: "retag".to_string(),
                started_at: 1_753_704_000,
                finished_at: 1_753_704_005,
                source_path: None,
                sourcetype: None,
                status: "ok".to_string(),
                error: None,
                entries_inserted: None,
                tags_applied: Some(42),
                skipped: Vec::new(),
                per_file: Vec::new(),
                tags_by_rule: vec![ActivityRuleCount {
                    rule_name: "generic_error".to_string(),
                    count: 42,
                    version: None,
                }],
                skip_bad_records_enabled: false,
            },
        )
        .unwrap();

        let entries = all_activity_log_entries(&conn).unwrap();
        assert_eq!(entries[0].operation, "retag");
        assert_eq!(entries[0].source_path, None);
        assert_eq!(entries[0].entries_inserted, None);
        assert_eq!(entries[0].tags_applied, Some(42));
        assert!(entries[0].per_file.is_empty());
        assert_eq!(
            entries[0].tags_by_rule,
            vec![ActivityRuleCount {
                rule_name: "generic_error".to_string(),
                count: 42,
                version: None,
            }]
        );
    }

    /// A `tags_by_rule` JSON blob written before `version` existed
    /// (`'{"rule_name": "x", "count": 1}'`, no `version` key at all) must
    /// still deserialize — `#[serde(default)]` on `ActivityRuleCount::version`
    /// is what makes an old Activity Log entry readable after upgrading
    /// Peach, not a schema migration (there's nothing to migrate: this
    /// column is a JSON blob, not fixed SQL columns — see
    /// `db::session_schema::setup_session_schema`'s doc comment).
    #[test]
    fn tags_by_rule_without_a_version_key_deserializes_as_none() {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO activity_log
                (operation, started_at, finished_at, source_path, sourcetype,
                 status, error, entries_inserted, tags_applied, skipped,
                 per_file, tags_by_rule, skip_bad_records_enabled)
             VALUES ('retag', 1, 2, NULL, NULL, 'ok', NULL, NULL, 1, '[]', '[]', ?1, 0)",
            params!["[{\"rule_name\": \"generic_error\", \"count\": 1}]"],
        )
        .unwrap();

        let entries = all_activity_log_entries(&conn).unwrap();

        assert_eq!(
            entries[0].tags_by_rule,
            vec![ActivityRuleCount {
                rule_name: "generic_error".to_string(),
                count: 1,
                version: None,
            }]
        );
    }
}
