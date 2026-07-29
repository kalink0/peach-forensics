use std::path::PathBuf;
use std::sync::mpsc;

use duckdb::Connection;
use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::db::timeline_queries::{self, DisplayRow, Query};

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
    conn: Option<Connection>,
    query: Query,
    total_rows: usize,
    cache: Option<RowCache>,
    count_rx: Option<mpsc::Receiver<usize>>,
    counting: bool,
}

impl TimelineView {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            conn: None,
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

    fn connection(&mut self) -> Option<&Connection> {
        if self.conn.is_none() {
            self.conn = Connection::open(&self.db_path).ok();
        }
        self.conn.as_ref()
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
        if let Some(conn) = self.connection()
            && let Ok(rows) = timeline_queries::fetch_window(conn, &query, offset, WINDOW_SIZE)
        {
            self.cache = Some(RowCache { offset, rows });
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        self.poll_count(ui.ctx());
        if self.counting {
            ui.label("Filtering…");
        }

        if self.total_rows == 0 {
            if !self.counting {
                ui.label("No entries match.");
            }
            return;
        }

        let total_rows = self.total_rows;
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::auto().at_least(170.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::remainder())
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Timestamp (UTC)");
                });
                header.col(|ui| {
                    ui.strong("Level");
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

                    row.col(|ui| {
                        ui.label(display.map(|d| d.timestamp_utc.as_str()).unwrap_or(""));
                    });
                    row.col(|ui| {
                        ui.label(display.map(|d| d.level.as_str()).unwrap_or(""));
                    });
                    row.col(|ui| {
                        ui.label(display.map(|d| d.message.as_str()).unwrap_or(""));
                    });
                });
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::timeline_schema::setup_timeline_schema;
    use crate::model::event_id::{EventId, SequenceCounter, SourceFileId};
    use chrono::Utc;

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

        let mut view = TimelineView::new(db_path.clone());
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

        let mut view = TimelineView::new(db_path.clone());
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

        let mut view = TimelineView::new(db_path.clone());
        view.refresh();
        wait_for_count(&mut view, &ctx);

        assert_eq!(view.total_rows(), 3);
        std::fs::remove_file(db_path).unwrap();
    }
}
