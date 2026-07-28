use std::path::PathBuf;

use duckdb::Connection;
use eframe::egui;
use egui_extras::{Column, TableBuilder};

/// How many rows to fetch per DuckDB query when the visible scroll window
/// moves. Keeps memory bounded (never holds the full result set — section
/// "nicht im RAM halten") while avoiding a query per visible row.
const WINDOW_SIZE: usize = 200;

struct DisplayRow {
    timestamp_utc: String,
    level: String,
    message: String,
}

struct RowCache {
    offset: usize,
    rows: Vec<DisplayRow>,
}

/// Virtualized timeline table: reads only the currently visible window of
/// rows from the on-disk DuckDB file via `LIMIT`/`OFFSET`, never the full
/// `log_entries` table into memory at once.
pub struct TimelineView {
    db_path: PathBuf,
    conn: Option<Connection>,
    total_rows: usize,
    cache: Option<RowCache>,
}

impl TimelineView {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            conn: None,
            total_rows: 0,
            cache: None,
        }
    }

    /// Re-reads the row count from DuckDB and drops the window cache. Call
    /// after a load finishes.
    pub fn refresh(&mut self) {
        self.cache = None;
        self.total_rows = self
            .connection()
            .and_then(|conn| {
                conn.query_row("SELECT COUNT(*) FROM log_entries", [], |row| {
                    row.get::<_, i64>(0)
                })
                .ok()
            })
            .map(|count| count as usize)
            .unwrap_or(0);
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
        if let Some(rows) = self.fetch_window(offset, WINDOW_SIZE) {
            self.cache = Some(RowCache { offset, rows });
        }
    }

    fn fetch_window(&mut self, offset: usize, limit: usize) -> Option<Vec<DisplayRow>> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT timestamp_utc, level, message FROM log_entries
                 ORDER BY timestamp_utc, event_id_source, event_id_seq
                 LIMIT ? OFFSET ?",
            )
            .ok()?;
        let rows = stmt
            .query_map(duckdb::params![limit as i64, offset as i64], |row| {
                let timestamp_utc: chrono::NaiveDateTime = row.get(0)?;
                let level: Option<String> = row.get(1)?;
                let message: Option<String> = row.get(2)?;
                Ok(DisplayRow {
                    timestamp_utc: timestamp_utc.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                    level: level.unwrap_or_default(),
                    message: message.unwrap_or_default(),
                })
            })
            .ok()?
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        Some(rows)
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        if self.total_rows == 0 {
            ui.label("No entries loaded yet.");
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
