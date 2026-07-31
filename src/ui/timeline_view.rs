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
    query: Query,
    total_rows: usize,
    /// Row count for the whole loaded timeline, ignoring the current
    /// filter — separate from `total_rows` (which tracks the *filtered*
    /// count and is what drives the table's virtual row count) so the UI
    /// can show "N of M events" instead of just the filtered count.
    total_unfiltered_rows: usize,
    cache: Option<RowCache>,
    count_rx: Option<mpsc::Receiver<usize>>,
    /// Background count for `total_unfiltered_rows`. Deliberately not
    /// recomputed on every `set_query` like `count_rx` is — the unfiltered
    /// total only changes when the loaded data itself changes (a load or
    /// re-tag finishing, a session switch), so this only fires from
    /// `refresh()`.
    total_rx: Option<mpsc::Receiver<usize>>,
    counting: bool,
    window_rx: Option<mpsc::Receiver<(usize, Vec<DisplayRow>)>>,
    /// Offset of the window fetch currently in flight, if any — gates
    /// `ensure_window` so a fast scroll doesn't spawn a new DuckDB
    /// connection + query on every frame while one is already running; the
    /// next frame after it lands re-checks whatever row is visible by then.
    pending_window_offset: Option<usize>,
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
            query: Query::default(),
            total_rows: 0,
            total_unfiltered_rows: 0,
            cache: None,
            count_rx: None,
            total_rx: None,
            counting: false,
            window_rx: None,
            pending_window_offset: None,
        }
    }

    pub fn total_rows(&self) -> usize {
        self.total_rows
    }

    pub fn total_unfiltered_rows(&self) -> usize {
        self.total_unfiltered_rows
    }

    /// Re-reads the row count for the current query and the whole-timeline
    /// total, and drops the window cache. Call after the loaded data
    /// itself changes (a load or re-tag finishing, a session switch) —
    /// unlike `set_query`, which only needs the filtered count to move.
    pub fn refresh(&mut self) {
        self.recount();
        self.recount_total();
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
        // Drop any in-flight window fetch too: it was reading rows for the
        // *old* query, and letting it land after the query has already
        // moved on would (best case) show stale rows, or (worst case, if
        // its offset happens to coincide with a later request against the
        // new query) silently serve rows for the wrong query. Dropping the
        // receiver here is enough — the fetch thread's `tx.send` then finds
        // nobody listening and its result silently goes nowhere, same
        // mechanism as the count below.
        self.window_rx = None;
        self.pending_window_offset = None;
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

    /// Kicks off the whole-timeline (unfiltered) count on a background
    /// thread — same reasoning as `recount`, its own connection since
    /// `Connection` isn't `Send`.
    fn recount_total(&mut self) {
        let db_path = self.db_path.clone();
        let (tx, rx) = mpsc::channel();
        self.total_rx = Some(rx);
        std::thread::spawn(move || {
            let total = Connection::open(&db_path)
                .ok()
                .and_then(|conn| timeline_queries::count_matching(&conn, &Query::default()).ok())
                .unwrap_or(0);
            let _ = tx.send(total);
        });
    }

    /// Applies a finished background whole-timeline count — same pattern as
    /// `poll_count`.
    fn poll_total(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.total_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(total) => {
                self.total_unfiltered_rows = total;
                self.total_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {
                ctx.request_repaint();
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.total_rx = None;
            }
        }
    }

    /// Opens a fresh connection per call rather than reusing a cached one
    /// — same reasoning as `recount`/`fetch_window`: a load or re-tag
    /// writes `import_tags`/`log_entries` from its own, separate
    /// connection on a background thread, and a long-lived connection kept
    /// around on this side isn't guaranteed to see those writes on its
    /// next query. That bug was real, not hypothetical: without this, the
    /// Tag filter row's vocabulary could stay stuck at whatever
    /// `import_tags` looked like the *first* time this was called, even
    /// after later tagging added rows — see
    /// `distinct_tags_sees_tags_written_by_a_different_connection_afterward`.
    pub fn distinct_levels(&self) -> Vec<String> {
        Connection::open(&self.db_path)
            .ok()
            .and_then(|conn| timeline_queries::distinct_levels(&conn).ok())
            .unwrap_or_default()
    }

    pub fn distinct_tags(&self) -> Vec<String> {
        Connection::open(&self.db_path)
            .ok()
            .and_then(|conn| timeline_queries::distinct_tags(&conn).ok())
            .unwrap_or_default()
    }

    /// Requests the window covering `row_index`, if it isn't already cached
    /// or already being fetched. Runs the query in the background (see
    /// [`Self::spawn_window_fetch`]) — with a filter that matches most of a
    /// multi-million-row table (e.g. the "Untagged" toggle), the
    /// `ORDER BY ... LIMIT/OFFSET` behind it can take real time, and this is
    /// called from inside the table's row-rendering closure, i.e. on the UI
    /// thread. Running it there synchronously (the original implementation)
    /// froze the whole window for the duration of the query.
    fn ensure_window(&mut self, row_index: usize) {
        if let Some(cache) = &self.cache
            && row_index >= cache.offset
            && row_index < cache.offset + cache.rows.len()
        {
            return;
        }
        if self.pending_window_offset.is_some() {
            // Already fetching a window this frame (or a recent one) — the
            // row renders blank for now; once it lands, `poll_window` clears
            // `pending_window_offset` and the next frame's `ensure_window`
            // call re-evaluates against wherever the view has scrolled to
            // by then. Avoids spawning a new connection + query per visible
            // row per frame while scrolling through an uncached region.
            return;
        }
        let offset = row_index.saturating_sub(WINDOW_SIZE / 4);
        self.spawn_window_fetch(offset);
    }

    /// Fetches one window on a background thread with its own connections
    /// (`Connection`/`rusqlite::Connection` aren't `Send`, so the existing
    /// ones can't just be moved over) and merges in `analyst_tags` there too
    /// — same reasoning as [`Self::recount`].
    fn spawn_window_fetch(&mut self, offset: usize) {
        self.pending_window_offset = Some(offset);
        let query = self.query.clone();
        let db_path = self.db_path.clone();
        let session_sqlite_path = self.session_sqlite_path.clone();
        let (tx, rx) = mpsc::channel();
        self.window_rx = Some(rx);
        std::thread::spawn(move || {
            let Ok(conn) = Connection::open(&db_path) else {
                return;
            };
            let Ok(mut rows) = timeline_queries::fetch_window(&conn, &query, offset, WINDOW_SIZE)
            else {
                return;
            };

            // Merge in analyst_tags (SQLite, a different database file than
            // the DuckDB timeline) so the Tags column reflects both the
            // rule-produced and manually-set tags on an entry, not just one
            // of them — best-effort: a failure here just means analyst tags
            // don't show up for this window, not that the fetch fails.
            if let Ok(session_conn) = rusqlite::Connection::open(&session_sqlite_path)
                && let Ok(analyst_tags) = persist::all_analyst_tags(&session_conn)
            {
                for row in &mut rows {
                    if let Some(extra) = analyst_tags.get(&row.event_id) {
                        row.tags.extend(extra.iter().cloned());
                        row.tags.sort();
                        row.tags.dedup();
                    }
                }
            }

            let _ = tx.send((offset, rows));
        });
    }

    /// Applies a finished background window fetch, and requests a repaint
    /// while one is outstanding — same pattern as [`Self::poll_count`].
    fn poll_window(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.window_rx else {
            return;
        };
        match rx.try_recv() {
            Ok((offset, rows)) => {
                self.cache = Some(RowCache { offset, rows });
                self.window_rx = None;
                self.pending_window_offset = None;
            }
            Err(mpsc::TryRecvError::Empty) => {
                ctx.request_repaint();
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.window_rx = None;
                self.pending_window_offset = None;
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<RowAction> {
        self.poll_count(ui.ctx());
        self.poll_window(ui.ctx());
        self.poll_total(ui.ctx());

        if self.query.is_empty() {
            ui.label(format!("{} events loaded", self.total_unfiltered_rows));
        } else {
            ui.label(format!(
                "{} of {} events loaded match the filter",
                self.total_rows, self.total_unfiltered_rows
            ));
        }

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

    /// Polls until the in-flight background whole-timeline count lands (or
    /// times out) — mirrors `wait_for_count` for `total_unfiltered_rows`.
    fn wait_for_total(view: &mut TimelineView, ctx: &egui::Context) {
        for _ in 0..500 {
            view.poll_total(ctx);
            if view.total_rx.is_none() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("timed out waiting for the background total count");
    }

    #[test]
    fn refresh_updates_the_unfiltered_total_independently_of_the_filtered_count() {
        let db_path = temp_db_path("unfiltered-total");
        seed_db(&db_path, &["hello", "world", "hello again"]);
        let ctx = egui::Context::default();

        let mut view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        view.set_query(Query::parse("hello"));
        wait_for_count(&mut view, &ctx);
        // `set_query` alone must not touch the unfiltered total — it only
        // changes when the underlying data does.
        assert_eq!(view.total_unfiltered_rows(), 0);

        view.refresh();
        wait_for_count(&mut view, &ctx);
        wait_for_total(&mut view, &ctx);

        assert_eq!(view.total_rows(), 2); // "hello" still matches only 2 of the 3 seeded rows
        assert_eq!(view.total_unfiltered_rows(), 3);
        std::fs::remove_file(db_path).unwrap();
    }

    /// Regression test: a real load with no tagging rules selected calls
    /// `distinct_tags()` once (via `LoadOutcome::Done`) while `import_tags`
    /// is still empty. Loading a *second* source with rules selected, or
    /// clicking "Re-tag now" afterward, writes new rows into `import_tags`
    /// from a completely different `Connection` (its own background
    /// thread, exactly like `run_load`/`run_retag`) and then calls
    /// `distinct_tags()` again. That second call must see the new tag —
    /// not whatever `import_tags` looked like when the first call happened
    /// to run.
    #[test]
    fn distinct_tags_sees_tags_written_by_a_different_connection_afterward() {
        let db_path = temp_db_path("distinct-tags-fresh-read");
        seed_db(&db_path, &["hello"]);

        let view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        assert_eq!(view.distinct_tags(), Vec::<String>::new());

        {
            let conn = Connection::open(&db_path).unwrap();
            let event_id = EventId {
                source_file_id: SourceFileId::new_random(),
                sequence_number: SequenceCounter::new().next_sequence_number(),
            };
            conn.execute(
                "INSERT INTO import_tags
                    (event_id_source, event_id_seq, rule_name, tag_value, applied_at)
                 VALUES (?, ?, 'rule', 'my_tag', ?)",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();
        }

        assert_eq!(view.distinct_tags(), vec!["my_tag".to_string()]);
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

    /// Polls until the in-flight background window fetch lands (or times
    /// out) — mirrors [`wait_for_count`] for `ensure_window`/`poll_window`.
    fn wait_for_window(view: &mut TimelineView, ctx: &egui::Context) {
        for _ in 0..500 {
            view.poll_window(ctx);
            if view.window_rx.is_none() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("timed out waiting for the background window fetch");
    }

    /// Regression test for the freeze this backgrounding fixes: previously
    /// `ensure_window` ran `fetch_window` synchronously on the caller's
    /// thread. Here, calling it must return immediately with the row still
    /// uncached, and the cache only fills in once `poll_window` picks up the
    /// background result — proving the fetch actually happens off-thread.
    #[test]
    fn ensure_window_runs_in_the_background_and_populates_the_cache() {
        let db_path = temp_db_path("window-basic");
        seed_db(&db_path, &["one", "two", "three"]);
        let ctx = egui::Context::default();

        let mut view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        view.set_query(Query::default());
        wait_for_count(&mut view, &ctx);

        view.ensure_window(0);
        assert!(view.cache.is_none(), "must not fetch synchronously");
        assert!(view.pending_window_offset.is_some());

        wait_for_window(&mut view, &ctx);

        let cache = view
            .cache
            .as_ref()
            .expect("window fetch should have landed");
        assert_eq!(cache.rows.len(), 3);
        std::fs::remove_file(db_path).unwrap();
    }

    /// While scrolling, the table calls `ensure_window` once per visible row
    /// per frame. Without gating on `pending_window_offset`, an uncached
    /// region would spawn a new DuckDB connection + query for every one of
    /// those rows before the first fetch even lands.
    #[test]
    fn ensure_window_does_not_spawn_a_second_fetch_while_one_is_in_flight() {
        let db_path = temp_db_path("window-gate");
        seed_db(&db_path, &["one", "two", "three"]);
        let ctx = egui::Context::default();

        let mut view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        view.set_query(Query::default());
        wait_for_count(&mut view, &ctx);

        view.ensure_window(0);
        let first_offset = view.pending_window_offset;
        // A row far enough away to compute a different offset, if a new
        // fetch were (wrongly) spawned for it.
        view.ensure_window(1000);
        assert_eq!(
            view.pending_window_offset, first_offset,
            "a second visible row must not preempt the in-flight fetch"
        );

        wait_for_window(&mut view, &ctx);
        std::fs::remove_file(db_path).unwrap();
    }

    /// Mirrors `a_result_for_a_superseded_query_never_lands` for window
    /// fetches: changing the query while a window fetch for the old query is
    /// still in flight must not let its rows land in the cache afterwards.
    #[test]
    fn a_window_fetch_for_a_superseded_query_never_lands() {
        let db_path = temp_db_path("window-superseded");
        seed_db(&db_path, &["alpha", "beta", "beta"]);
        let ctx = egui::Context::default();

        let mut view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        view.set_query(Query::parse("alpha"));
        wait_for_count(&mut view, &ctx);
        view.ensure_window(0);

        // Supersede immediately, before the "alpha" window fetch can
        // possibly have landed — simulates the query changing (e.g. via the
        // "Untagged" toggle) while a scroll-triggered fetch is in flight.
        view.set_query(Query::parse("beta"));
        assert!(
            view.pending_window_offset.is_none(),
            "recount() must clear the stale in-flight fetch's tracking"
        );
        wait_for_count(&mut view, &ctx);
        view.ensure_window(0);
        wait_for_window(&mut view, &ctx);

        let cache = view.cache.as_ref().unwrap();
        assert_eq!(cache.rows.len(), 2);
        assert!(cache.rows.iter().all(|r| r.message == "beta"));
        std::fs::remove_file(db_path).unwrap();
    }
}
