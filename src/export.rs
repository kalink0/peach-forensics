//! Exports the timeline's *currently filtered* result set (the same
//! [`Query`] the table is showing, not necessarily the whole loaded
//! timeline) to CSV or JSON. Exporting "everything" is just exporting with
//! an empty filter — there's deliberately no separate "export all" path,
//! since one would only ever duplicate what clearing the search box already
//! does.
//!
//! Streamed in chunks via the same [`timeline_queries::fetch_window`] the
//! table itself uses for one page at a time — walking it end to end with
//! increasing offsets instead of collecting the whole filtered set into a
//! `Vec` first, so an export of millions of rows stays bounded to one
//! chunk's worth of memory at a time (the "nicht im RAM halten" principle
//! this codebase applies everywhere else).

use std::io::Write;
use std::path::Path;
use std::sync::mpsc;

use anyhow::Context;

use crate::db::timeline_queries::{self, DisplayRow, Query};
use crate::session::persist;

/// Rows fetched and written per chunk — same order of magnitude as
/// [`crate::app::LOAD_BATCH_SIZE`], for the same reason: big enough to
/// amortize per-query overhead, small enough that memory stays bounded
/// regardless of how large the full filtered result is.
const EXPORT_CHUNK_SIZE: usize = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Json,
}

impl ExportFormat {
    /// Infers the format from `path`'s extension — `.json` for JSON,
    /// anything else (including no extension) defaults to CSV, the more
    /// broadly-openable format for whoever receives the export. The save
    /// dialog offers both extensions as filters, so this only has to
    /// disambiguate what the analyst actually typed/picked, not guess
    /// blind.
    pub fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some(ext) if ext.eq_ignore_ascii_case("json") => Self::Json,
            _ => Self::Csv,
        }
    }
}

/// One exported row — every normalized column [`DisplayRow`] carries.
/// `tags`/`notes` are joined into single fields rather than kept as lists:
/// CSV has no concept of a nested value, and keeping both formats
/// structurally identical means the export is predictable regardless of
/// which one was chosen, not richer in one than the other.
#[derive(serde::Serialize)]
struct ExportRow<'a> {
    timestamp_utc: &'a str,
    level: &'a str,
    source: &'a str,
    sourcetype: &'a str,
    host: &'a str,
    process: &'a str,
    event_code: &'a str,
    subsystem: &'a str,
    category: &'a str,
    tags: String,
    notes: String,
    message: &'a str,
}

impl<'a> From<&'a DisplayRow> for ExportRow<'a> {
    fn from(row: &'a DisplayRow) -> Self {
        Self {
            timestamp_utc: &row.timestamp_utc,
            level: &row.level,
            source: &row.source_path,
            sourcetype: &row.sourcetype,
            host: &row.host,
            process: &row.process,
            event_code: &row.event_code,
            subsystem: &row.subsystem,
            category: &row.category,
            tags: row.tags.join(";"),
            notes: row.notes.join(" | "),
            message: &row.message,
        }
    }
}

/// Sent back over a channel while an export runs, same request/poll shape
/// as [`crate::app::LoadOutcome`].
pub enum ExportOutcome {
    Progress { rows_written: usize },
    Done(Result<usize, String>),
}

/// Owns whichever writer state a format needs — a plain `match` sharing one
/// `BufWriter` between a `csv::Writer` and raw JSON writes doesn't borrow-check
/// (both would need their own live `&mut` on it at once from the compiler's
/// point of view, even though only one is ever actually used at runtime), so
/// each variant holds its writer outright instead. Boxed: `csv::Writer`'s
/// internal buffer makes that variant much larger than `Json`'s, and this
/// value is short-lived and never collected into an array, so the
/// indirection costs nothing that matters.
enum RowWriter<W: Write> {
    Csv(Box<csv::Writer<W>>),
    Json { writer: W, wrote_any: bool },
}

impl<W: Write> RowWriter<W> {
    fn start(format: ExportFormat, mut writer: W) -> anyhow::Result<Self> {
        Ok(match format {
            ExportFormat::Csv => Self::Csv(Box::new(csv::Writer::from_writer(writer))),
            ExportFormat::Json => {
                writer.write_all(b"[\n")?;
                Self::Json {
                    writer,
                    wrote_any: false,
                }
            }
        })
    }

    fn write_row(&mut self, row: &ExportRow) -> anyhow::Result<()> {
        match self {
            Self::Csv(csv_writer) => {
                csv_writer.serialize(row)?;
            }
            Self::Json { writer, wrote_any } => {
                if *wrote_any {
                    writer.write_all(b",\n")?;
                }
                *wrote_any = true;
                serde_json::to_writer(&mut *writer, row)?;
            }
        }
        Ok(())
    }

    fn finish(self) -> anyhow::Result<()> {
        match self {
            Self::Csv(mut csv_writer) => csv_writer.flush()?,
            Self::Json { mut writer, .. } => {
                writer.write_all(b"\n]\n")?;
                writer.flush()?;
            }
        }
        Ok(())
    }
}

/// Runs an export to completion on whatever thread calls it — `app.rs`
/// spawns this on a background thread, same as `run_load`/`run_retag`, so
/// the UI stays responsive for however long a large filtered set takes to
/// walk. Returns the total row count written.
///
/// `session_sqlite_path` is best-effort, same as the table's own window
/// fetch: analyst tags/notes are loaded once upfront (not re-queried per
/// chunk — both tables are small by design, see
/// `session::persist::insert_analyst_tag`/`insert_event_note`'s doc
/// comments, so one load covers the whole export) and merged into every
/// chunk; a failure to open that file just means an export with no
/// tags/notes columns filled in, not a failed export.
pub fn export_to_file(
    conn: &duckdb::Connection,
    session_sqlite_path: &Path,
    query: &Query,
    format: ExportFormat,
    out_path: &Path,
    progress_tx: &mpsc::Sender<ExportOutcome>,
) -> anyhow::Result<usize> {
    let (analyst_tags, event_notes) = rusqlite::Connection::open(session_sqlite_path)
        .ok()
        .map(|session_conn| {
            (
                persist::all_analyst_tags(&session_conn).unwrap_or_default(),
                persist::all_event_notes(&session_conn).unwrap_or_default(),
            )
        })
        .unwrap_or_default();

    let file = std::fs::File::create(out_path)
        .with_context(|| format!("failed to create {}", out_path.display()))?;
    let mut row_writer = RowWriter::start(format, std::io::BufWriter::new(file))?;
    let mut rows_written = 0usize;
    let mut offset = 0usize;

    loop {
        let mut chunk = timeline_queries::fetch_window(conn, query, offset, EXPORT_CHUNK_SIZE)?;
        if chunk.is_empty() {
            break;
        }
        let chunk_len = chunk.len();
        for row in &mut chunk {
            if let Some(extra) = analyst_tags.get(&row.event_id) {
                row.tags.extend(extra.iter().cloned());
                row.tags.sort();
                row.tags.dedup();
            }
            if let Some(extra) = event_notes.get(&row.event_id) {
                row.notes.extend(extra.iter().cloned());
            }
        }

        for row in &chunk {
            row_writer.write_row(&ExportRow::from(row))?;
        }

        rows_written += chunk_len;
        offset += chunk_len;
        let _ = progress_tx.send(ExportOutcome::Progress { rows_written });
        if chunk_len < EXPORT_CHUNK_SIZE {
            break;
        }
    }

    row_writer.finish()?;
    Ok(rows_written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_schema::setup_session_schema;
    use crate::db::timeline_schema::setup_timeline_schema;
    use crate::model::event_id::{EventId, SequenceCounter, SourceFileId};
    use chrono::Utc;

    fn temp_path(name: &str, ext: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "peach-export-test-{}-{}-{name}.{ext}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn seed_db(conn: &duckdb::Connection, messages: &[&str]) -> Vec<EventId> {
        setup_timeline_schema(conn).unwrap();
        let source_file_id = SourceFileId::new_random();
        let mut sequence_counter = SequenceCounter::new();
        let mut ids = Vec::new();
        for message in messages {
            let event_id = EventId {
                source_file_id,
                sequence_number: sequence_counter.next_sequence_number(),
            };
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, 'INFO', ?, ?, '{}')",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    Utc::now().naive_utc(),
                    message,
                    message,
                ],
            )
            .unwrap();
            ids.push(event_id);
        }
        ids
    }

    #[test]
    fn export_format_from_path_recognizes_json_and_defaults_to_csv() {
        assert_eq!(
            ExportFormat::from_path(Path::new("out.json")),
            ExportFormat::Json
        );
        assert_eq!(
            ExportFormat::from_path(Path::new("out.JSON")),
            ExportFormat::Json
        );
        assert_eq!(
            ExportFormat::from_path(Path::new("out.csv")),
            ExportFormat::Csv
        );
        assert_eq!(ExportFormat::from_path(Path::new("out")), ExportFormat::Csv);
    }

    #[test]
    fn export_to_file_writes_every_matching_row_as_csv() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        seed_db(&conn, &["hello", "world", "hello again"]);
        let sqlite_path = temp_path("csv-session", "sqlite");
        let out_path = temp_path("csv-out", "csv");
        let (tx, rx) = mpsc::channel();

        let count = export_to_file(
            &conn,
            &sqlite_path,
            &Query::default(),
            ExportFormat::Csv,
            &out_path,
            &tx,
        )
        .unwrap();

        assert_eq!(count, 3);
        let contents = std::fs::read_to_string(&out_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 4, "header + 3 rows"); // header + 3 rows
        assert!(lines[0].starts_with("timestamp_utc,level,source,"));
        assert!(contents.contains("hello"));
        assert!(contents.contains("world"));
        drop(rx);
        std::fs::remove_file(&out_path).unwrap();
    }

    #[test]
    fn export_to_file_writes_valid_json_array() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        seed_db(&conn, &["hello", "world"]);
        let sqlite_path = temp_path("json-session", "sqlite");
        let out_path = temp_path("json-out", "json");
        let (tx, _rx) = mpsc::channel();

        let count = export_to_file(
            &conn,
            &sqlite_path,
            &Query::default(),
            ExportFormat::Json,
            &out_path,
            &tx,
        )
        .unwrap();

        assert_eq!(count, 2);
        let contents = std::fs::read_to_string(&out_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        let array = parsed.as_array().unwrap();
        assert_eq!(array.len(), 2);
        assert_eq!(array[0]["message"], "hello");
        std::fs::remove_file(&out_path).unwrap();
    }

    #[test]
    fn export_to_file_respects_the_query_filter() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        seed_db(&conn, &["hello", "world", "hello again"]);
        let sqlite_path = temp_path("filtered-session", "sqlite");
        let out_path = temp_path("filtered-out", "csv");
        let (tx, _rx) = mpsc::channel();

        let count = export_to_file(
            &conn,
            &sqlite_path,
            &Query::parse("hello"),
            ExportFormat::Csv,
            &out_path,
            &tx,
        )
        .unwrap();

        assert_eq!(count, 2);
        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(!contents.contains("world"));
        std::fs::remove_file(&out_path).unwrap();
    }

    #[test]
    fn export_to_file_merges_analyst_tags_and_notes() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        let ids = seed_db(&conn, &["hello"]);
        let sqlite_path = temp_path("merge-session", "sqlite");
        {
            let session_conn = rusqlite::Connection::open(&sqlite_path).unwrap();
            setup_session_schema(&session_conn).unwrap();
            persist::insert_analyst_tag(&session_conn, ids[0], "reviewed").unwrap();
            persist::insert_event_note(&session_conn, ids[0], "check this").unwrap();
        }
        let out_path = temp_path("merge-out", "csv");
        let (tx, _rx) = mpsc::channel();

        export_to_file(
            &conn,
            &sqlite_path,
            &Query::default(),
            ExportFormat::Csv,
            &out_path,
            &tx,
        )
        .unwrap();

        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(contents.contains("reviewed"));
        assert!(contents.contains("check this"));
        std::fs::remove_file(&out_path).unwrap();
        std::fs::remove_file(&sqlite_path).unwrap();
    }

    #[test]
    fn export_to_file_reports_progress() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        seed_db(&conn, &["a", "b", "c"]);
        let sqlite_path = temp_path("progress-session", "sqlite");
        let out_path = temp_path("progress-out", "csv");
        let (tx, rx) = mpsc::channel();

        export_to_file(
            &conn,
            &sqlite_path,
            &Query::default(),
            ExportFormat::Csv,
            &out_path,
            &tx,
        )
        .unwrap();

        let progress: Vec<usize> = rx
            .try_iter()
            .map(|outcome| match outcome {
                ExportOutcome::Progress { rows_written } => rows_written,
                ExportOutcome::Done(_) => unreachable!("export_to_file never sends Done itself"),
            })
            .collect();
        assert_eq!(progress, vec![3]);
        std::fs::remove_file(&out_path).unwrap();
    }
}
