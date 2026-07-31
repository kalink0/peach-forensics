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
    /// events.
    pub fn open(sessions_dir: &Path) -> Self {
        let entries = scan_sessions(sessions_dir);
        let count_rx = spawn_event_counts(&entries);
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
                                match entry.event_count {
                                    Some(count) => format!("{} — {count} events", entry.id),
                                    None => format!("{} (counting…)", entry.id),
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

/// Every `<id>.sqlite` in `dir` is a session, paired with `<id>.duckdb` if
/// data has been loaded into it (see the module doc for why a missing
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
            let sqlite_path = entry.path();
            if sqlite_path.extension().and_then(|ext| ext.to_str()) != Some("sqlite") {
                return None;
            }
            let id = sqlite_path.file_stem()?.to_str()?.to_string();
            let duckdb_path = dir.join(format!("{id}.duckdb"));
            let has_data = duckdb_path.exists();
            Some(SessionEntry {
                id,
                sqlite_path,
                duckdb_path,
                has_data,
                event_count: None,
            })
        })
        .collect();
    entries.sort_by(|a, b| b.id.cmp(&a.id));
    entries
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
fn spawn_event_counts(entries: &[SessionEntry]) -> Option<mpsc::Receiver<(String, usize)>> {
    let targets: Vec<(String, PathBuf)> = entries
        .iter()
        .filter(|entry| entry.has_data)
        .map(|entry| (entry.id.clone(), entry.duckdb_path.clone()))
        .collect();
    if targets.is_empty() {
        return None;
    }

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for (id, duckdb_path) in targets {
            let count = duckdb::Connection::open(&duckdb_path)
                .ok()
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

/// Removes every file that can belong to a session — `.sqlite`, `.duckdb`,
/// and DuckDB's `.duckdb.wal` write-ahead log (present if the app closed,
/// or crashed, before a checkpoint) — tolerating any of them already being
/// absent (an empty session has no `.duckdb`/`.wal` at all) rather than
/// treating that as failure.
fn delete_session_files(entry: &SessionEntry) -> anyhow::Result<()> {
    remove_if_exists(&entry.sqlite_path)?;
    remove_if_exists(&entry.duckdb_path)?;
    remove_if_exists(&entry.duckdb_path.with_extension("duckdb.wal"))?;
    Ok(())
}

/// Deletes the session at `sqlite_path` only if it's empty (no `.duckdb` —
/// see the module doc for why that means "nothing was ever loaded into
/// it"). Used by `PeachApp::on_exit` so quitting without loading anything
/// doesn't leave behind a session file that just clutters "Manage
/// sessions" forever; a session with data is left untouched even if asked,
/// as a safety net against ever calling this on the wrong path.
pub fn delete_if_empty(sqlite_path: &Path) -> anyhow::Result<()> {
    let duckdb_path = sqlite_path.with_extension("duckdb");
    if duckdb_path.exists() {
        return Ok(());
    }
    remove_if_exists(sqlite_path)
}

/// Removes every empty session (no `.duckdb`) currently in `sessions_dir`
/// — called once at startup (`PeachApp::new`), before that run's own new
/// session is created. This is the reliable backstop for the same cleanup
/// `on_exit`/`delete_if_empty` do best-effort on a graceful shutdown:
/// `on_exit` only runs when the window closes normally, so a killed
/// process, a crash, or a forced quit leaves an empty session behind that
/// nothing cleans up until *some later* startup sweeps it away. Best-effort
/// per session — one failing removal (e.g. a permissions issue) doesn't
/// stop the rest from being swept.
pub fn sweep_empty_sessions(sessions_dir: &Path) {
    for entry in scan_sessions(sessions_dir) {
        if !entry.has_data {
            let _ = remove_if_exists(&entry.sqlite_path);
        }
    }
}

fn remove_if_exists(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            Err(anyhow::Error::from(err).context(format!("failed to remove {}", path.display())))
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

    #[test]
    fn scan_sessions_lists_both_empty_and_data_backed_sessions_newest_first() {
        let dir = temp_sessions_dir("scan");
        std::fs::write(dir.join("session-20260101-000000.sqlite"), b"").unwrap();
        std::fs::write(dir.join("session-20260102-000000.sqlite"), b"").unwrap();
        std::fs::write(dir.join("session-20260102-000000.duckdb"), b"").unwrap();
        // Not a session file at all — must be ignored.
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
    fn delete_session_files_removes_the_whole_triple_and_tolerates_missing_ones() {
        let dir = temp_sessions_dir("delete");
        let sqlite_path = dir.join("session-20260101-000000.sqlite");
        let duckdb_path = dir.join("session-20260101-000000.duckdb");
        let wal_path = dir.join("session-20260101-000000.duckdb.wal");
        std::fs::write(&sqlite_path, b"").unwrap();
        std::fs::write(&duckdb_path, b"").unwrap();
        std::fs::write(&wal_path, b"").unwrap();
        let entry = SessionEntry {
            id: "session-20260101-000000".to_string(),
            sqlite_path: sqlite_path.clone(),
            duckdb_path: duckdb_path.clone(),
            has_data: true,
            event_count: None,
        };

        delete_session_files(&entry).unwrap();

        assert!(!sqlite_path.exists());
        assert!(!duckdb_path.exists());
        assert!(!wal_path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn delete_session_files_is_fine_with_an_empty_session_that_never_had_a_duckdb_file() {
        let dir = temp_sessions_dir("delete-empty");
        let sqlite_path = dir.join("session-20260101-000000.sqlite");
        std::fs::write(&sqlite_path, b"").unwrap();
        let entry = SessionEntry {
            id: "session-20260101-000000".to_string(),
            sqlite_path: sqlite_path.clone(),
            duckdb_path: dir.join("session-20260101-000000.duckdb"),
            has_data: false,
            event_count: None,
        };

        delete_session_files(&entry).unwrap();

        assert!(!sqlite_path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn delete_if_empty_removes_a_session_with_no_duckdb_file() {
        let dir = temp_sessions_dir("delete-if-empty-empty");
        let sqlite_path = dir.join("session-20260101-000000.sqlite");
        std::fs::write(&sqlite_path, b"").unwrap();

        delete_if_empty(&sqlite_path).unwrap();

        assert!(!sqlite_path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn delete_if_empty_leaves_a_session_with_data_untouched() {
        let dir = temp_sessions_dir("delete-if-empty-data");
        let sqlite_path = dir.join("session-20260101-000000.sqlite");
        let duckdb_path = dir.join("session-20260101-000000.duckdb");
        std::fs::write(&sqlite_path, b"").unwrap();
        std::fs::write(&duckdb_path, b"").unwrap();

        delete_if_empty(&sqlite_path).unwrap();

        assert!(
            sqlite_path.exists(),
            "must not delete a session that has data"
        );
        assert!(duckdb_path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sweep_empty_sessions_removes_only_the_ones_without_a_duckdb_file() {
        let dir = temp_sessions_dir("sweep");
        let empty_a = dir.join("session-20260101-000000.sqlite");
        let empty_b = dir.join("session-20260101-000001.sqlite");
        let data_sqlite = dir.join("session-20260102-000000.sqlite");
        let data_duckdb = dir.join("session-20260102-000000.duckdb");
        std::fs::write(&empty_a, b"").unwrap();
        std::fs::write(&empty_b, b"").unwrap();
        std::fs::write(&data_sqlite, b"").unwrap();
        std::fs::write(&data_duckdb, b"").unwrap();

        sweep_empty_sessions(&dir);

        assert!(!empty_a.exists());
        assert!(!empty_b.exists());
        assert!(data_sqlite.exists(), "must not touch a session with data");
        assert!(data_duckdb.exists());
        std::fs::remove_dir_all(dir).unwrap();
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
        std::fs::write(dir.join("session-20260101-000000.sqlite"), b"").unwrap();
        // An empty session (no `.duckdb`) alongside a data-backed one —
        // only the latter should ever get a count.
        std::fs::write(dir.join("session-20260102-000000.sqlite"), b"").unwrap();
        seed_duckdb(&dir.join("session-20260102-000000.duckdb"), 3);

        let mut dialog = SessionManagerDialog::open(&dir);
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
