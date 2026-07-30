use std::path::PathBuf;
use std::sync::mpsc;

use duckdb::Connection;
use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::db::timeline_queries::{self, DisplayRow, Query};
use crate::model::event_id::EventId;
use crate::session::persist;
use crate::ui::colors::categorical_color;

/// An action requested via a row's right-click context menu — handled by
/// the caller (`PeachApp`), which owns the session/rule-file/search state
/// these need (`TimelineView` only knows the DuckDB timeline itself).
pub enum RowAction {
    /// "Tag this event..." — a single manual, analyst-driven tag.
    TagSingle { event_id: EventId },
    /// "Tag all matching (advanced)..." — the clicked row's message seeds
    /// the pattern for a `message_contains` rule.
    TagAllMatching { event_id: EventId, message: String },
    /// "Show context around this event" — replaces the search query with
    /// an `after=.../before=...` window centered on the clicked row.
    /// Computed here (not in `app.rs`) since it needs the row's own
    /// timestamp, which `DisplayRow` already carries as a formatted
    /// string.
    ShowContext { query_text: String },
}

/// How many rows to fetch per DuckDB query when the visible scroll window
/// moves. Keeps memory bounded (never holds the full result set — section
/// "nicht im RAM halten") while avoiding a query per visible row.
const WINDOW_SIZE: usize = 200;

struct RowCache {
    offset: usize,
    rows: Vec<DisplayRow>,
}

/// Virtualized, filterable timeline table: reads only the currently visible
/// window of rows matching the current [`Query`] from the on-disk DuckDB
/// file via `LIMIT`/`OFFSET`, never the full `log_entries` table into
/// memory at once.
///
/// The row count backing `total_rows` runs on a background thread
/// ([`Self::recount`]) rather than inline in [`Self::set_query`]: at AUL
/// scale (millions of rows), a free-text filter is a `LIKE '%...%'` scan
/// with a leading wildcard — can't use an index, and `set_query` fires on
/// every keystroke. Run synchronously on the UI thread (the original
/// implementation), that's a multi-second freeze on every character typed;
/// backgrounding it keeps typing responsive at the cost of the displayed
/// count trailing a query or two behind while a count is in flight.
pub struct TimelineView {
    db_path: PathBuf,
    session_sqlite_path: PathBuf,
    conn: Option<Connection>,
    session_conn: Option<rusqlite::Connection>,
    query: Query,
    total_rows: usize,
    cache: Option<RowCache>,
    count_rx: Option<mpsc::Receiver<usize>>,
    counting: bool,
}

impl TimelineView {
    /// `session_sqlite_path` is the session's `.sqlite` file — used to
    /// merge `analyst_tags` (manual, per-entry tags) into the Tags column
    /// alongside `import_tags` (rule-produced, lives in `db_path`'s
    /// DuckDB file instead). Two separate database files by design (see
    /// CLAUDE.md §4) — merging them is this view's job, not either
    /// engine's.
    pub fn new(db_path: PathBuf, session_sqlite_path: PathBuf) -> Self {
        Self {
            db_path,
            session_sqlite_path,
            conn: None,
            session_conn: None,
            query: Query::default(),
            total_rows: 0,
            cache: None,
            count_rx: None,
            counting: false,
        }
    }

    pub fn total_rows(&self) -> usize {
        self.total_rows
    }

    /// Re-reads the row count for the current query and drops the window
    /// cache. Call after a load finishes.
    pub fn refresh(&mut self) {
        self.recount();
    }

    /// Sets the active search query. Filters apply immediately (no separate
    /// "search" action) — see `filter_bar.rs`.
    pub fn set_query(&mut self, query: Query) {
        if query == self.query {
            return;
        }
        self.query = query;
        self.recount();
    }

    /// Kicks off the count on a background thread with its own connection
    /// (`Connection` isn't `Send`, so the existing one can't just be moved
    /// over) and drops the window cache immediately — the visible rows are
    /// for the *old* query and shouldn't linger once it's changed, even
    /// though the new count hasn't arrived yet.
    ///
    /// Replacing `count_rx` here is also what keeps a stale result from a
    /// since-superseded query from ever landing: it drops whatever
    /// receiver was there before, so that query's thread finds its send
    /// side disconnected and its result silently goes nowhere — at most
    /// one receiver is ever live, and it always belongs to the query
    /// that's current when `poll_count` reads it.
    fn recount(&mut self) {
        self.cache = None;
        self.counting = true;
        let query = self.query.clone();
        let db_path = self.db_path.clone();
        let (tx, rx) = mpsc::channel();
        self.count_rx = Some(rx);
        std::thread::spawn(move || {
            let total = Connection::open(&db_path)
                .ok()
                .and_then(|conn| timeline_queries::count_matching(&conn, &query).ok())
                .unwrap_or(0);
            let _ = tx.send(total);
        });
    }

    /// Applies a finished background count, and requests a repaint while
    /// one is outstanding so the result gets picked up promptly instead of
    /// waiting for the next user-triggered frame.
    fn poll_count(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.count_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(total) => {
                self.total_rows = total;
                self.cache = None;
                self.counting = false;
                self.count_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {
                ctx.request_repaint();
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.count_rx = None;
                self.counting = false;
            }
        }
    }

    pub fn distinct_levels(&mut self) -> Vec<String> {
        self.connection()
            .and_then(|conn| timeline_queries::distinct_levels(conn).ok())
            .unwrap_or_default()
    }

    pub fn distinct_tags(&mut self) -> Vec<String> {
        self.connection()
            .and_then(|conn| timeline_queries::distinct_tags(conn).ok())
            .unwrap_or_default()
    }

    fn connection(&mut self) -> Option<&Connection> {
        if self.conn.is_none() {
            self.conn = Connection::open(&self.db_path).ok();
        }
        self.conn.as_ref()
    }

    fn session_connection(&mut self) -> Option<&rusqlite::Connection> {
        if self.session_conn.is_none() {
            self.session_conn = rusqlite::Connection::open(&self.session_sqlite_path).ok();
        }
        self.session_conn.as_ref()
    }

    fn ensure_window(&mut self, row_index: usize) {
        if let Some(cache) = &self.cache
            && row_index >= cache.offset
            && row_index < cache.offset + cache.rows.len()
        {
            return;
        }
        let offset = row_index.saturating_sub(WINDOW_SIZE / 4);
        let query = self.query.clone();
        let Some(conn) = self.connection() else {
            return;
        };
        let Ok(mut rows) = timeline_queries::fetch_window(conn, &query, offset, WINDOW_SIZE) else {
            return;
        };

        // Merge in analyst_tags (SQLite, a different database file than
        // the DuckDB timeline) so the Tags column reflects both the
        // rule-produced and manually-set tags on an entry, not just one
        // of them — best-effort: a failure here just means analyst tags
        // don't show up this frame, not that the timeline fails to render.
        if let Some(session_conn) = self.session_connection()
            && let Ok(analyst_tags) = persist::all_analyst_tags(session_conn)
        {
            for row in &mut rows {
                if let Some(extra) = analyst_tags.get(&row.event_id) {
                    row.tags.extend(extra.iter().cloned());
                    row.tags.sort();
                    row.tags.dedup();
                }
            }
        }

        self.cache = Some(RowCache { offset, rows });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<RowAction> {
        self.poll_count(ui.ctx());
        if self.counting {
            ui.label("Filtering…");
        }

        if self.total_rows == 0 {
            if !self.counting {
                ui.label("No entries match.");
            }
            return None;
        }

        let mut requested = None;
        let total_rows = self.total_rows;
        TableBuilder::new(ui)
            .striped(true)
            // Rows only sense hover by default — a right-click context
            // menu needs click sensing on the row's `response()`, or
            // `.context_menu()` never fires no matter what's inside it.
            .sense(egui::Sense::click())
            .column(Column::auto().at_least(170.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(140.0))
            .column(Column::remainder())
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Timestamp (UTC)");
                });
                header.col(|ui| {
                    ui.strong("Level");
                });
                header.col(|ui| {
                    ui.strong("Tags");
                });
                header.col(|ui| {
                    ui.strong("Message");
                });
            })
            .body(|body| {
                body.rows(18.0, total_rows, |mut row| {
                    let row_index = row.index();
                    self.ensure_window(row_index);
                    let display = self.cache.as_ref().and_then(|cache| {
                        row_index
                            .checked_sub(cache.offset)
                            .and_then(|i| cache.rows.get(i))
                    });

                    let (ts_rect, _) = row.col(|ui| {
                        ui.label(display.map(|d| d.timestamp_utc.as_str()).unwrap_or(""));
                    });
                    let (level_rect, _) = row.col(|ui| {
                        if let Some(d) = display
                            && !d.level.is_empty()
                        {
                            let color = categorical_color(&d.level, ui.visuals().dark_mode);
                            ui.colored_label(color, &d.level);
                        }
                    });
                    let (tags_rect, _) = row.col(|ui| {
                        if let Some(d) = display {
                            ui.horizontal_wrapped(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                for tag in &d.tags {
                                    let color = categorical_color(tag, ui.visuals().dark_mode);
                                    ui.colored_label(color, tag);
                                }
                            });
                        }
                    });
                    row.col(|ui| {
                        ui.label(display.map(|d| d.message.as_str()).unwrap_or(""));

                        if let Some(d) = display {
                            let event_id = d.event_id;
                            let message = d.message.clone();
                            let db_path = self.db_path.clone();
                            let timestamp = chrono::NaiveDateTime::parse_from_str(
                                &d.timestamp_utc,
                                "%Y-%m-%d %H:%M:%S%.f",
                            )
                            .ok();

                            // Not `row.response().context_menu(...)`: that
                            // response is a union of each cell's own
                            // interact state, and empirically only the
                            // Level/Tags cells ever registered hover or a
                            // right-click — Timestamp/Message never did,
                            // for reasons not fully pinned down in
                            // egui_extras' per-cell layout internals.
                            // Explicitly interacting over the whole row's
                            // rect (spanning all four cells, computed from
                            // what `row.col` already returned) sidesteps
                            // that entirely.
                            let full_row_rect = ts_rect
                                .union(level_rect)
                                .union(tags_rect)
                                .union(ui.max_rect());
                            let row_response = ui.interact(
                                full_row_rect,
                                ui.id().with(("row_context_menu", row_index)),
                                egui::Sense::click(),
                            );

                            row_response.context_menu(|ui| {
                                if ui.button("Copy message").clicked() {
                                    ui.ctx().copy_text(message.clone());
                                    ui.close();
                                }
                                if ui.button("Copy whole event as text").clicked() {
                                    if let Some(text) = Connection::open(&db_path)
                                        .ok()
                                        .and_then(|conn| {
                                            timeline_queries::fetch_full_entry(&conn, event_id).ok()
                                        })
                                        .flatten()
                                        .map(|entry| entry.to_text())
                                    {
                                        ui.ctx().copy_text(text);
                                    }
                                    ui.close();
                                }
                                ui.separator();
                                if let Some(timestamp) = timestamp {
                                    ui.menu_button("Show context around this event", |ui| {
                                        for minutes in [1, 5, 15, 60] {
                                            if ui.button(format!("± {minutes} min")).clicked() {
                                                requested = Some(RowAction::ShowContext {
                                                    query_text: context_window_query(
                                                        timestamp, minutes,
                                                    ),
                                                });
                                                ui.close();
                                            }
                                        }
                                    });
                                }
                                ui.separator();
                                if ui.button("Tag this event...").clicked() {
                                    requested = Some(RowAction::TagSingle { event_id });
                                    ui.close();
                                }
                                if ui.button("Tag all matching (advanced)...").clicked() {
                                    requested =
                                        Some(RowAction::TagAllMatching { event_id, message });
                                    ui.close();
                                }
                            });
                        }
                    });
                });
            });
        requested
    }
}

/// Builds the `after=.../before=...` query text for "Show context around
/// this event" — always an ISO `T`-separated, whitespace-free timestamp on
/// each side (never the space-separated display format), since this
/// becomes literal query-box text and the query tokenizer splits on
/// whitespace.
fn context_window_query(timestamp: chrono::NaiveDateTime, minutes: i64) -> String {
    let after = timestamp - chrono::Duration::minutes(minutes);
    let before = timestamp + chrono::Duration::minutes(minutes);
    format!(
        "after={} before={}",
        after.format("%Y-%m-%dT%H:%M:%S%.3f"),
        before.format("%Y-%m-%dT%H:%M:%S%.3f")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::timeline_schema::setup_timeline_schema;
    use crate::model::event_id::{EventId, SequenceCounter, SourceFileId};
    use chrono::Utc;

    #[test]
    fn context_window_query_writes_a_whitespace_free_iso_bound_on_each_side() {
        let timestamp = chrono::NaiveDate::from_ymd_opt(2026, 7, 29)
            .unwrap()
            .and_hms_milli_opt(10, 0, 0, 0)
            .unwrap();

        let query = context_window_query(timestamp, 5);

        assert_eq!(
            query,
            "after=2026-07-29T09:55:00.000 before=2026-07-29T10:05:00.000"
        );
        // Every token must be whitespace-free — this becomes literal query
        // box text, and the tokenizer splits on whitespace.
        assert_eq!(query.split_whitespace().count(), 2);
    }

    fn temp_db_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "peach-timeline-view-test-{}-{}-{name}.duckdb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// No test here exercises the analyst-tags merge, so this just needs to
    /// be some path `rusqlite::Connection::open` can create — doesn't need
    /// cleanup, the OS temp dir is expected to be transient.
    fn temp_sqlite_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "peach-timeline-view-test-{}-{}-{name}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn seed_db(path: &std::path::Path, messages: &[&str]) {
        let conn = Connection::open(path).unwrap();
        setup_timeline_schema(&conn).unwrap();
        let source_file_id = SourceFileId::new_random();
        let mut sequence_counter = SequenceCounter::new();
        for message in messages {
            let event_id = EventId {
                source_file_id,
                sequence_number: sequence_counter.next_sequence_number(),
            };
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, NULL, ?, ?, '{}')",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    Utc::now().naive_utc(),
                    message,
                    message,
                ],
            )
            .unwrap();
        }
    }

    /// Polls until the in-flight background count lands (or times out) —
    /// mirrors what `ui()` does every frame, without needing an actual
    /// egui frame loop.
    fn wait_for_count(view: &mut TimelineView, ctx: &egui::Context) {
        for _ in 0..500 {
            view.poll_count(ctx);
            if view.count_rx.is_none() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("timed out waiting for the background count");
    }

    #[test]
    fn recount_runs_in_the_background_and_updates_total_rows() {
        let db_path = temp_db_path("basic");
        seed_db(&db_path, &["hello", "world", "hello again"]);
        let ctx = egui::Context::default();

        let mut view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        view.set_query(Query::parse("hello"));
        wait_for_count(&mut view, &ctx);

        assert_eq!(view.total_rows(), 2);
        assert!(!view.counting);
        std::fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_result_for_a_superseded_query_never_lands() {
        let db_path = temp_db_path("superseded");
        // Distinct counts per query, so a stale "alpha" result landing
        // would be numerically distinguishable from the correct "beta" one.
        seed_db(&db_path, &["alpha", "beta", "beta", "beta"]);
        let ctx = egui::Context::default();

        let mut view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        view.set_query(Query::parse("alpha"));
        // Supersede immediately, before the first background count can
        // possibly have landed — simulates fast typing outrunning a query.
        view.set_query(Query::parse("beta"));
        wait_for_count(&mut view, &ctx);

        assert_eq!(view.total_rows(), 3); // "beta"'s count, never the stale "alpha" count of 1
        std::fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn refresh_recounts_for_the_current_query() {
        let db_path = temp_db_path("refresh");
        seed_db(&db_path, &["one", "two", "three"]);
        let ctx = egui::Context::default();

        let mut view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        view.refresh();
        wait_for_count(&mut view, &ctx);

        assert_eq!(view.total_rows(), 3);
        std::fs::remove_file(db_path).unwrap();
    }
}
