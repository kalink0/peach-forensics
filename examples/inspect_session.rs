//! Throwaway diagnostic: prints a level breakdown and a few sample rows
//! from a session's `.duckdb` file, to eyeball AUL string-resolution
//! quality without going through the GUI.
//!
//! Usage: cargo run --example inspect_session -- <path-to-session.duckdb>

use std::env;

fn main() -> anyhow::Result<()> {
    let db_path = env::args()
        .nth(1)
        .expect("usage: inspect_session <path-to-session.duckdb>");
    let conn = duckdb::Connection::open_with_flags(
        &db_path,
        duckdb::Config::default().access_mode(duckdb::AccessMode::ReadOnly)?,
    )?;

    println!("=== level breakdown ===");
    let mut stmt = conn.prepare(
        "SELECT level, COUNT(*) AS n FROM log_entries GROUP BY level ORDER BY n DESC LIMIT 20",
    )?;
    let rows = stmt.query_map([], |row| {
        let level: Option<String> = row.get(0)?;
        let n: i64 = row.get(1)?;
        Ok((level, n))
    })?;
    for row in rows {
        let (level, n) = row?;
        println!("{n:>10}  {:?}", level);
    }

    println!("\n=== message emptiness ===");
    let mut stmt = conn.prepare(
        "SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN message IS NULL OR message = '' THEN 1 ELSE 0 END) AS empty_message,
            SUM(CASE WHEN message LIKE '%Missing message data%' THEN 1 ELSE 0 END) AS missing_marker,
            SUM(CASE WHEN message LIKE '%Failed to get%' THEN 1 ELSE 0 END) AS failed_marker,
            SUM(CASE WHEN message LIKE '%Unknown shared string%' THEN 1 ELSE 0 END) AS unknown_shared,
            SUM(CASE WHEN message LIKE '%Invalid offset%' THEN 1 ELSE 0 END) AS invalid_offset,
            SUM(CASE
                WHEN message IS NULL OR message = ''
                    OR message LIKE '%Missing message data%'
                    OR message LIKE '%Failed to get%'
                    OR message LIKE '%Unknown shared string%'
                    OR message LIKE '%Invalid offset%'
                THEN 1 ELSE 0 END) AS any_unresolved
         FROM log_entries",
    )?;
    stmt.query_row([], |row| {
        let total: i64 = row.get(0)?;
        let empty: i64 = row.get(1)?;
        let missing: i64 = row.get(2)?;
        let failed: i64 = row.get(3)?;
        let unknown_shared: i64 = row.get(4)?;
        let invalid_offset: i64 = row.get(5)?;
        let any_unresolved: i64 = row.get(6)?;
        let pct = 100.0 * any_unresolved as f64 / total as f64;
        println!(
            "total={total} empty_message={empty} missing_marker={missing} failed_marker={failed} \
             unknown_shared={unknown_shared} invalid_offset={invalid_offset} \
             any_unresolved={any_unresolved} ({pct:.1}%)"
        );
        Ok(())
    })?;

    println!("\n=== resolution rate by day ===");
    let mut stmt = conn.prepare(
        "SELECT
            date_trunc('day', timestamp_utc) AS day,
            COUNT(*) AS total,
            SUM(CASE
                WHEN message IS NULL OR message = ''
                    OR message LIKE '%Missing message data%'
                    OR message LIKE '%Failed to get%'
                    OR message LIKE '%Unknown shared string%'
                    OR message LIKE '%Invalid offset%'
                THEN 1 ELSE 0 END) AS unresolved
         FROM log_entries
         GROUP BY day
         ORDER BY day",
    )?;
    let rows = stmt.query_map([], |row| {
        let day: chrono::NaiveDateTime = row.get(0)?;
        let total: i64 = row.get(1)?;
        let unresolved: i64 = row.get(2)?;
        Ok((day, total, unresolved))
    })?;
    for row in rows {
        let (day, total, unresolved) = row?;
        let pct = 100.0 * unresolved as f64 / total as f64;
        println!(
            "{}  total={total:>9}  unresolved={unresolved:>9}  ({pct:.1}%)",
            day.date()
        );
    }

    println!("\n=== 5 sample rows ===");
    let mut stmt =
        conn.prepare("SELECT level, message, fields FROM log_entries USING SAMPLE 5 ROWS")?;
    let rows = stmt.query_map([], |row| {
        let level: Option<String> = row.get(0)?;
        let message: Option<String> = row.get(1)?;
        let fields: String = row.get(2)?;
        Ok((level, message, fields))
    })?;
    for row in rows {
        let (level, message, fields) = row?;
        println!("--- level: {level:?}");
        println!("message: {message:?}");
        let truncated: String = fields.chars().take(400).collect();
        println!("fields (truncated): {truncated}");
    }

    Ok(())
}
