//! "Manage sessions" dialog — lists every session found in the sessions
//! directory (`<id>.sqlite` + `<id>.duckdb` pair, see
//! [`crate::session::persist::SessionPaths`]) with Open/Delete actions.
//!
//! A session's `.sqlite` file is created as soon as the app starts (see
//! `PeachApp::new`), before any data is ever loaded — so a fresh session
//! with no `.duckdb` yet is an expected, normal state here, not an error;
//! it just shows as "(empty)".
//!
//! Delete is a real filesystem removal (no undo, no trash) — worth an
//! explicit confirm step for what is, in this tool, forensic case data.
//! It's also refused for the session currently open in this run: deleting
//! the files still backing the running app out from under it would leave
//! every subsequent read/write pointed at nothing.

use std::path::{Path, PathBuf};
use std::sync::mpsc;

use anyhow::Context;
use eframe::egui;

use crate::db::timeline_queries::{self, Query};

pub enum SessionManagerOutcome {
    /// The analyst picked a session to switch to — `app.rs` still owns
    /// actually loading it (`PeachApp::load_session`), same division of
    /// labor as `TagDialogOutcome`.
    Open(PathBuf),
}

pub struct SessionEntry {
    id: String,
    sqlite_path: PathBuf,
    duckdb_path: PathBuf,
    has_data: bool,
    /// `None` until the background count (see `spawn_event_counts`) lands
    /// for this session, or forever for a `has_data: false` (empty)
    /// session — never counted, there's nothing to count.
    event_count: Option<usize>,
    /// Combined on-disk size of this session's `.sqlite`, `.duckdb`, and (if
    /// present) `.duckdb.wal` files — a plain `stat()`, cheap enough to
    /// compute synchronously in `scan_sessions` rather than backgrounded
    /// like `event_count` (which needs an actual DuckDB query).
    size_bytes: u64,
}

pub enum SessionManagerDialog {
    Closed,
    Open {
        entries: Vec<SessionEntry>,
        /// Id of the session awaiting a "really delete?" confirmation, if
        /// any — at most one row is ever mid-confirm at a time.
        pending_delete: Option<String>,
        error: Option<String>,
        /// Streams one `(id, count)` per data-backed session as its count
        /// finishes — see `spawn_event_counts` for why this is
        /// backgrounded rather than computed inline in `open`.
        count_rx: Option<mpsc::Receiver<(String, usize)>>,
    },
}

impl SessionManagerDialog {
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Scans `sessions_dir` and opens the dialog listing whatever's there,
    /// kicking off a background count of each data-backed session's
    /// events. `current_conn` is a `TimelineView::try_clone_conn()` clone
    /// for `current_session_id` (the running app's own session) if it has
    /// data — used instead of independently re-opening that one session's
    /// `.duckdb` file, since that file may well still be open via the
    /// running app's own connection; see `try_clone_conn`'s doc comment for
    /// why a second, unrelated open of the same file can fail on Windows.
    /// Every other session in the list is safe to open fresh — nothing
    /// else in this process has them open.
    pub fn open(
        sessions_dir: &Path,
        current_session_id: &str,
        current_conn: Option<duckdb::Connection>,
    ) -> Self {
        let entries = scan_sessions(sessions_dir);
        let count_rx = spawn_event_counts(&entries, current_session_id, current_conn);
        Self::Open {
            entries,
            pending_delete: None,
            error: None,
            count_rx,
        }
    }

    /// Applies whatever event counts have finished computing since the
    /// last call, returning whether more are still expected — pulled out
    /// from `ui()` so tests can poll it without needing an active egui
    /// frame, same reason `TimelineView` separates `poll_count` from `ui`.
    fn poll_counts(&mut self) -> bool {
        let Self::Open {
            entries, count_rx, ..
        } = self
        else {
            return false;
        };
        let Some(rx) = count_rx else {
            return false;
        };
        loop {
            match rx.try_recv() {
                Ok((id, count)) => {
                    if let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) {
                        entry.event_count = Some(count);
                    }
                }
                Err(mpsc::TryRecvError::Empty) => return true,
                Err(mpsc::TryRecvError::Disconnected) => {
                    *count_rx = None;
                    return false;
                }
            }
        }
    }

    /// Renders the dialog if open (a no-op otherwise). `current_session_id`
    /// is the running app's own session — its row's Delete button is
    /// disabled, see the module doc.
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        current_session_id: &str,
    ) -> Option<SessionManagerOutcome> {
        let mut outcome = None;
        let mut close = false;

        if self.poll_counts() {
            ctx.request_repaint();
        }

        if let Self::Open {
            entries,
            pending_delete,
            error,
            ..
        } = self
        {
            egui::Window::new("Manage sessions")
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    if let Some(err) = error {
                        ui.colored_label(egui::Color32::RED, err.as_str());
                    }
                    if entries.is_empty() {
                        ui.label("No saved sessions found.");
                    }

                    let mut just_deleted = None;
                    for entry in entries.iter() {
                        let is_current = entry.id == current_session_id;
                        ui.horizontal(|ui| {
                            let label = if entry.has_data {
                                let size = format_bytes(entry.size_bytes);
                                match entry.event_count {
                                    Some(count) => {
                                        format!("{} — {count} events, {size}", entry.id)
                                    }
                                    None => format!("{} (counting…), {size}", entry.id),
                                }
                            } else {
                                format!("{} (empty)", entry.id)
                            };
                            ui.label(label);
                            if is_current {
                                ui.weak("(current)");
                            }

                            if ui
                                .add_enabled(!is_current, egui::Button::new("Open"))
                                .clicked()
                            {
                                outcome =
                                    Some(SessionManagerOutcome::Open(entry.sqlite_path.clone()));
                                close = true;
                            }

                            if ui
                                .button("Open folder")
                                .on_hover_text(
                                    "Show this session's .sqlite/.duckdb files in the file \
                                     manager — handy for copying the session elsewhere",
                                )
                                .clicked()
                                && let Err(err) = reveal_in_file_manager(&entry.sqlite_path)
                            {
                                *error = Some(format!("{err:#}"));
                            }

                            if pending_delete.as_deref() == Some(entry.id.as_str()) {
                                ui.colored_label(egui::Color32::RED, "Really delete?");
                                if ui.button("Delete").clicked() {
                                    match delete_session_files(entry) {
                                        Ok(()) => just_deleted = Some(entry.id.clone()),
                                        Err(err) => *error = Some(format!("{err:#}")),
                                    }
                                    *pending_delete = None;
                                }
                                if ui.button("Cancel").clicked() {
                                    *pending_delete = None;
                                }
                            } else {
                                let delete_button =
                                    ui.add_enabled(!is_current, egui::Button::new("Delete..."));
                                let delete_button = if is_current {
                                    delete_button.on_hover_text(
                                        "Cannot delete the session currently open in this window",
                                    )
                                } else {
                                    delete_button
                                };
                                if delete_button.clicked() {
                                    *pending_delete = Some(entry.id.clone());
                                }
                            }
                        });
                    }
                    if let Some(id) = just_deleted {
                        entries.retain(|entry| entry.id != id);
                    }

                    ui.separator();
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
        }

        if close {
            *self = Self::Closed;
        }
        outcome
    }
}

/// Every subdirectory of `dir` named `<id>` containing an `<id>.sqlite` is a
/// session (see `session::persist::SessionPaths`), paired with `<id>.duckdb`
/// if data has been loaded into it (see the module doc for why a missing
/// `.duckdb` isn't treated as an error). Sorted newest-first — session ids
/// embed a `session-YYYYMMDD-HHMMSS` timestamp, so a plain string sort
/// already orders chronologically.
fn scan_sessions(dir: &Path) -> Vec<SessionEntry> {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries: Vec<SessionEntry> = read_dir
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let session_dir = entry.path();
            let id = session_dir.file_name()?.to_str()?.to_string();
            let sqlite_path = session_dir.join(format!("{id}.sqlite"));
            if !sqlite_path.is_file() {
                return None;
            }
            let duckdb_path = session_dir.join(format!("{id}.duckdb"));
            let has_data = duckdb_path.exists();
            let wal_path = session_dir.join(format!("{id}.duckdb.wal"));
            let size_bytes = [&sqlite_path, &duckdb_path, &wal_path]
                .iter()
                .filter_map(|path| std::fs::metadata(path).ok())
                .map(|metadata| metadata.len())
                .sum();
            Some(SessionEntry {
                id,
                sqlite_path,
                duckdb_path,
                has_data,
                event_count: None,
                size_bytes,
            })
        })
        .collect();
    entries.sort_by(|a, b| b.id.cmp(&a.id));
    entries
}

/// Human-readable file size — B/KB/MB/GB, one decimal place from KB up
/// (matches the load-progress bar's `MB` formatting elsewhere in the UI,
/// just picking the right unit instead of assuming MB always fits).
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = UNITS[0];
    for &next_unit in &UNITS[1..] {
        if value < 1000.0 {
            break;
        }
        value /= 1000.0;
        unit = next_unit;
    }
    if unit == "B" {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {unit}")
    }
}

/// Counts `log_entries` for every data-backed session in `entries`, one
/// DuckDB connection at a time on a single background thread — sequential
/// rather than one thread per session so a "Manage sessions" open with many
/// large sessions doesn't try to hold that many DuckDB connections/file
/// handles open at once. Streams results back as they finish (rather than
/// collecting a `Vec` and sending it all at once) so the dialog can show
/// each session's count the moment it's known instead of waiting for the
/// slowest one. `None` if there's nothing to count at all, so `ui()` never
/// shows a spinner for an all-empty sessions directory.
///
/// `current_session_id`'s target uses `current_conn` (if given) instead of
/// opening its `.duckdb` file independently — see `open`'s doc comment.
fn spawn_event_counts(
    entries: &[SessionEntry],
    current_session_id: &str,
    current_conn: Option<duckdb::Connection>,
) -> Option<mpsc::Receiver<(String, usize)>> {
    let targets: Vec<(String, PathBuf)> = entries
        .iter()
        .filter(|entry| entry.has_data)
        .map(|entry| (entry.id.clone(), entry.duckdb_path.clone()))
        .collect();
    if targets.is_empty() {
        return None;
    }

    let current_session_id = current_session_id.to_string();
    let mut current_conn = current_conn;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for (id, duckdb_path) in targets {
            let conn = if id == current_session_id {
                current_conn.take()
            } else {
                duckdb::Connection::open(&duckdb_path).ok()
            };
            let count = conn
                .and_then(|conn| timeline_queries::count_matching(&conn, &Query::default()).ok())
                .unwrap_or(0);
            if tx.send((id, count)).is_err() {
                // The dialog closed (receiver dropped) — no point counting
                // the rest of the sessions nobody's looking at anymore.
                break;
            }
        }
    });
    Some(rx)
}

/// Opens the OS file manager at `path`'s containing folder — every one of a
/// session's files (`<id>.sqlite`, `<id>.duckdb`, its `.wal`) lives in that
/// session's own dedicated subdirectory (see
/// `session::persist::SessionPaths`), so revealing any one of them (here,
/// always `<id>.sqlite` — it's the one path every session, even an empty
/// one, is guaranteed to have) opens exactly that session's folder, nothing
/// else's — the whole point being a one-drag copy for a hand-off.
/// Explorer/Finder select the file itself; `xdg-open` on Linux just opens
/// the containing folder — there's no cross-desktop convention for "open
/// and select a specific file" to rely on there. Best-effort: spawns and
/// returns, doesn't wait for or check an exit status (`explorer.exe` in
/// particular is well known to report a nonzero exit code even on success).
fn reveal_in_file_manager(path: &Path) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(format!("/select,{}", path.display()))
            .spawn()
            .context("failed to launch Explorer")?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg("-R")
            .arg(path)
            .spawn()
            .context("failed to launch Finder")?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let dir = path.parent().unwrap_or(path);
        std::process::Command::new("xdg-open")
            .arg(dir)
            .spawn()
            .context("failed to launch the file manager (is xdg-open installed?)")?;
    }
    Ok(())
}

/// Removes a session's whole directory — `<id>.sqlite`, `<id>.duckdb`, and
/// DuckDB's `.wal` write-ahead log (present if the app closed, or crashed,
/// before a checkpoint) all live there, so one `remove_dir_all` replaces
/// what used to be three separate per-file removals. Tolerates the
/// directory already being absent rather than treating that as failure.
fn delete_session_files(entry: &SessionEntry) -> anyhow::Result<()> {
    let session_dir = entry
        .sqlite_path
        .parent()
        .expect("sqlite_path is always session_dir/<id>.sqlite");
    remove_dir_if_exists(session_dir)
}

/// Deletes the session directory backing `sqlite_path` only if it's empty
/// (no `<id>.duckdb` — see the module doc for why that means "nothing
/// was ever loaded into it"). Used by `PeachApp::on_exit` so quitting
/// without loading anything doesn't leave behind a session directory that
/// just clutters "Manage sessions" forever; a session with data is left
/// untouched even if asked, as a safety net against ever calling this on
/// the wrong path.
pub fn delete_if_empty(sqlite_path: &Path) -> anyhow::Result<()> {
    let duckdb_path = sqlite_path.with_extension("duckdb");
    if duckdb_path.exists() {
        return Ok(());
    }
    let Some(session_dir) = sqlite_path.parent() else {
        return Ok(());
    };
    remove_dir_if_exists(session_dir)
}

/// Removes every empty session (no `<id>.duckdb`) currently in
/// `sessions_dir` — called once at startup (`PeachApp::new`), before that
/// run's own new session is created. This is the reliable backstop for the
/// same cleanup `on_exit`/`delete_if_empty` do best-effort on a graceful
/// shutdown: `on_exit` only runs when the window closes normally, so a
/// killed process, a crash, or a forced quit leaves an empty session
/// behind that nothing cleans up until *some later* startup sweeps it
/// away. Best-effort per session — one failing removal (e.g. a permissions
/// issue) doesn't stop the rest from being swept.
pub fn sweep_empty_sessions(sessions_dir: &Path) {
    for entry in scan_sessions(sessions_dir) {
        if !entry.has_data
            && let Some(session_dir) = entry.sqlite_path.parent()
        {
            let _ = remove_dir_if_exists(session_dir);
        }
    }
}

fn remove_dir_if_exists(dir: &Path) -> anyhow::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            Err(anyhow::Error::from(err).context(format!("failed to remove {}", dir.display())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_sessions_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "peach-session-dialog-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Creates `dir/<id>/<id>.sqlite` (and `<id>.duckdb` too, if
    /// `with_duckdb`) — the on-disk shape `scan_sessions` et al. expect.
    /// Returns `(sqlite_path, duckdb_path)`; `duckdb_path` is returned even
    /// when not created, since callers need it either way to build a
    /// `SessionEntry`.
    fn make_session(dir: &Path, id: &str, with_duckdb: bool) -> (PathBuf, PathBuf) {
        let session_dir = dir.join(id);
        std::fs::create_dir_all(&session_dir).unwrap();
        let sqlite_path = session_dir.join(format!("{id}.sqlite"));
        let duckdb_path = session_dir.join(format!("{id}.duckdb"));
        std::fs::write(&sqlite_path, b"").unwrap();
        if with_duckdb {
            std::fs::write(&duckdb_path, b"").unwrap();
        }
        (sqlite_path, duckdb_path)
    }

    #[test]
    fn scan_sessions_lists_both_empty_and_data_backed_sessions_newest_first() {
        let dir = temp_sessions_dir("scan");
        make_session(&dir, "session-20260101-000000", false);
        make_session(&dir, "session-20260102-000000", true);
        // Not a session directory at all — must be ignored.
        std::fs::write(dir.join("notes.txt"), b"").unwrap();

        let entries = scan_sessions(&dir);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "session-20260102-000000");
        assert!(entries[0].has_data);
        assert_eq!(entries[1].id, "session-20260101-000000");
        assert!(!entries[1].has_data);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scan_sessions_sums_sqlite_duckdb_and_wal_sizes() {
        let dir = temp_sessions_dir("scan-size");
        let (sqlite_path, duckdb_path) = make_session(&dir, "session-20260101-000000", true);
        std::fs::write(&sqlite_path, vec![0u8; 100]).unwrap();
        std::fs::write(&duckdb_path, vec![0u8; 250]).unwrap();
        std::fs::write(duckdb_path.with_extension("duckdb.wal"), vec![0u8; 50]).unwrap();

        let entries = scan_sessions(&dir);

        assert_eq!(entries[0].size_bytes, 400);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn format_bytes_picks_the_right_unit() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_500), "1.5 KB");
        assert_eq!(format_bytes(2_500_000), "2.5 MB");
        assert_eq!(format_bytes(3_500_000_000), "3.5 GB");
    }

    #[test]
    fn delete_session_files_removes_the_whole_session_directory() {
        let dir = temp_sessions_dir("delete");
        let (sqlite_path, duckdb_path) = make_session(&dir, "session-20260101-000000", true);
        std::fs::write(duckdb_path.with_extension("duckdb.wal"), b"").unwrap();
        let session_dir = sqlite_path.parent().unwrap().to_path_buf();
        let entry = SessionEntry {
            id: "session-20260101-000000".to_string(),
            sqlite_path,
            duckdb_path,
            has_data: true,
            event_count: None,
            size_bytes: 0,
        };

        delete_session_files(&entry).unwrap();

        assert!(!session_dir.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_session_files_is_fine_with_an_empty_session_that_never_had_a_duckdb_file() {
        let dir = temp_sessions_dir("delete-empty");
        let (sqlite_path, duckdb_path) = make_session(&dir, "session-20260101-000000", false);
        let session_dir = sqlite_path.parent().unwrap().to_path_buf();
        let entry = SessionEntry {
            id: "session-20260101-000000".to_string(),
            sqlite_path,
            duckdb_path,
            has_data: false,
            event_count: None,
            size_bytes: 0,
        };

        delete_session_files(&entry).unwrap();

        assert!(!session_dir.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_session_files_tolerates_an_already_removed_directory() {
        let dir = temp_sessions_dir("delete-already-gone");
        let (sqlite_path, duckdb_path) = make_session(&dir, "session-20260101-000000", true);
        let session_dir = sqlite_path.parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&session_dir).unwrap();
        let entry = SessionEntry {
            id: "session-20260101-000000".to_string(),
            sqlite_path,
            duckdb_path,
            has_data: true,
            event_count: None,
            size_bytes: 0,
        };

        delete_session_files(&entry).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_if_empty_removes_a_session_with_no_duckdb_file() {
        let dir = temp_sessions_dir("delete-if-empty-empty");
        let (sqlite_path, _) = make_session(&dir, "session-20260101-000000", false);
        let session_dir = sqlite_path.parent().unwrap().to_path_buf();

        delete_if_empty(&sqlite_path).unwrap();

        assert!(!session_dir.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_if_empty_leaves_a_session_with_data_untouched() {
        let dir = temp_sessions_dir("delete-if-empty-data");
        let (sqlite_path, duckdb_path) = make_session(&dir, "session-20260101-000000", true);

        delete_if_empty(&sqlite_path).unwrap();

        assert!(
            sqlite_path.exists(),
            "must not delete a session that has data"
        );
        assert!(duckdb_path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sweep_empty_sessions_removes_only_the_ones_without_a_duckdb_file() {
        let dir = temp_sessions_dir("sweep");
        let (empty_a, _) = make_session(&dir, "session-20260101-000000", false);
        let (empty_b, _) = make_session(&dir, "session-20260101-000001", false);
        let (data_sqlite, data_duckdb) = make_session(&dir, "session-20260102-000000", true);

        sweep_empty_sessions(&dir);

        assert!(!empty_a.parent().unwrap().exists());
        assert!(!empty_b.parent().unwrap().exists());
        assert!(data_sqlite.exists(), "must not touch a session with data");
        assert!(data_duckdb.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn seed_duckdb(path: &Path, message_count: usize) {
        use crate::db::timeline_schema::setup_timeline_schema;
        use crate::model::event_id::{EventId, SequenceCounter, SourceFileId};

        let conn = duckdb::Connection::open(path).unwrap();
        setup_timeline_schema(&conn).unwrap();
        let source_file_id = SourceFileId::new_random();
        let mut sequence_counter = SequenceCounter::new();
        for _ in 0..message_count {
            let event_id = EventId {
                source_file_id,
                sequence_number: sequence_counter.next_sequence_number(),
            };
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, NULL, 'm', 'm', '{}')",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    chrono::Utc::now().naive_utc(),
                ],
            )
            .unwrap();
        }
    }

    #[test]
    fn open_counts_events_for_data_backed_sessions_in_the_background() {
        let dir = temp_sessions_dir("event-counts");
        // An empty session (no `.duckdb`) alongside a data-backed one —
        // only the latter should ever get a count.
        make_session(&dir, "session-20260101-000000", false);
        let (_, duckdb_path) = make_session(&dir, "session-20260102-000000", false);
        seed_duckdb(&duckdb_path, 3);

        let mut dialog = SessionManagerDialog::open(&dir, "no-such-session", None);
        for _ in 0..500 {
            if !dialog.poll_counts() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let SessionManagerDialog::Open { entries, .. } = &dialog else {
            panic!("dialog should still be open");
        };
        let empty = entries
            .iter()
            .find(|entry| entry.id == "session-20260101-000000")
            .unwrap();
        let data_backed = entries
            .iter()
            .find(|entry| entry.id == "session-20260102-000000")
            .unwrap();
        assert_eq!(empty.event_count, None);
        assert_eq!(data_backed.event_count, Some(3));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
