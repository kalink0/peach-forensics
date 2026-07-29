use std::path::PathBuf;

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
pub struct TimelineView {
    db_path: PathBuf,
    conn: Option<Connection>,
    query: Query,
    total_rows: usize,
    cache: Option<RowCache>,
}

impl TimelineView {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            conn: None,
            query: Query::default(),
            total_rows: 0,
            cache: None,
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

    fn recount(&mut self) {
        self.cache = None;
        let query = self.query.clone();
        self.total_rows = self
            .connection()
            .and_then(|conn| timeline_queries::count_matching(conn, &query).ok())
            .unwrap_or(0);
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
        if self.total_rows == 0 {
            ui.label("No entries match.");
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
