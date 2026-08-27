//! Portable Case: bundles a session (or a filtered subset of one) into a
//! single `.peachcase` ZIP file that another analyst's Peach can import as a
//! brand-new, independent session — `raw`/`fields`/analyst tags/notes/
//! activity log all travel intact, unlike the lossy row-level CSV/JSON
//! export in [`crate::export`].
//!
//! One code path handles both a whole-session export and a filtered-subset
//! export: an empty `filter_query_text` parses to an empty [`Query`], which
//! [`timeline_queries::compile_from_where`] turns into "no `WHERE` clause at
//! all" — i.e. "copy everything" — so there is no separate simple-copy
//! branch to keep in sync.
//!
//! `log_entries`/`import_tags` (the bulk tables) respect the filter;
//! `sources` and every SQLite session table (`analyst_tags`, `event_notes`,
//! `session_state`, `activity_log`) are always copied in full regardless of
//! it. An analyst's manually-authored tag or note must never silently
//! disappear just because a search filter hid its row at export time — the
//! resulting "orphaned" tag/note (pointing at an `event_id` not present in
//! the filtered `log_entries`) is an accepted, documented tradeoff, not a
//! bug, consistent with how [`crate::session::persist::LoadedSource`]
//! already tolerates a missing `source_file_id` on legacy sessions rather
//! than erroring.
//!
//! Every filter and every unreadable-but-referenced parser config is
//! recorded in [`PortableCaseManifest`] rather than silently dropped (see
//! CLAUDE.md §0.1: no silent data manipulation), and a corrupted or
//! tampered bundle fails loudly on import (format-version and SHA-256
//! checks) rather than proceeding best-effort.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use anyhow::Context;
use sha2::{Digest, Sha256};

use crate::db::session_schema::setup_session_schema;
use crate::db::timeline_queries::{self, Query};
use crate::db::timeline_schema::setup_timeline_schema_in;
use crate::session::persist::{self, ImportedFrom, NewActivityLogEntry, SessionPaths};

pub const PORTABLE_CASE_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PortableCaseManifest {
    pub format_version: u32,
    pub peach_version: String,
    pub exported_at: chrono::DateTime<chrono::Utc>,
    pub original_session_id: String,
    /// Informational only, for a quick glance without opening `case.sqlite`
    /// — the authoritative copy lives in the bundled `session_state` table,
    /// which already carries it verbatim, so import never needs to write
    /// this back out.
    pub display_name: Option<String>,
    /// The search query the export was filtered by; `""` for a whole,
    /// unfiltered session export. Single source of truth for "was this
    /// filtered, and how" — shown to the analyst on import.
    pub filter_query: String,
    pub hashes: PortableCaseHashes,
    pub sources: Vec<PortableCaseSourceEntry>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PortableCaseHashes {
    pub duckdb_sha256: String,
    pub sqlite_sha256: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PortableCaseSourceEntry {
    pub source_file_id: String,
    /// The evidence path on the *exporting* analyst's machine — informational
    /// only, never resolved against the importing machine's filesystem,
    /// consistent with [`crate::model::event_id::SourceFileId`]'s existing
    /// "no re-import detection" precedent.
    pub original_path: String,
    pub sourcetype: String,
    /// Bundle-relative path to a reference copy of this source's text-parser
    /// TOML config (`parser_configs/<source_file_id>-<name>.toml`), if it
    /// referenced one and it was still readable at export time.
    pub parser_config: Option<String>,
    /// `true` if this source referenced a parser config that could no
    /// longer be read at export time — recorded rather than silently
    /// omitted.
    pub parser_config_missing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableCaseExportStage {
    CopyingTimeline,
    CopyingSessionData,
    CollectingParserConfigs,
    Hashing,
    Packaging,
}

pub enum PortableCaseExportOutcome {
    Progress(PortableCaseExportStage),
    Done(Result<PortableCaseExportSummary, String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortableCaseExportSummary {
    pub entries_written: usize,
    pub tags_written: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableCaseImportStage {
    Extracting,
    VerifyingFormat,
    VerifyingIntegrity,
    RegisteringSession,
}

pub enum PortableCaseImportOutcome {
    Progress(PortableCaseImportStage),
    Done(Result<SessionPaths, String>),
}

/// RAII scratch directory for an in-progress export/import, cleaned up on
/// drop so an early `?`-propagated failure (bad zip, hash mismatch, ...)
/// never leaves a half-built case lying around in the OS temp directory.
/// Same naming/collision-avoidance convention as
/// `persist::new_ephemeral_sessions_dir`.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(prefix: &str) -> anyhow::Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "peach-{prefix}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create scratch directory {}", dir.display()))?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Escapes a filesystem path for embedding as a single-quoted SQL string
/// literal in an `ATTACH`/`ATTACH DATABASE` statement — both DuckDB and
/// SQLite use a doubled single quote (`''`) to escape a literal quote
/// inside a string.
fn sql_quote_path(path: &Path) -> String {
    path.display().to_string().replace('\'', "''")
}

struct SourceRow {
    source_file_id: String,
    path: String,
    sourcetype: String,
    parser_config: Option<String>,
}

fn fetch_source_rows(conn: &duckdb::Connection) -> anyhow::Result<Vec<SourceRow>> {
    let mut stmt =
        conn.prepare("SELECT source_file_id, path, sourcetype, parser_config FROM sources")?;
    let rows = stmt.query_map([], |row| {
        Ok(SourceRow {
            source_file_id: row.get(0)?,
            path: row.get(1)?,
            sourcetype: row.get(2)?,
            parser_config: row.get(3)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Builds a fresh, filtered (or, for an empty `filter_query_text`, whole)
/// copy of the timeline into `case_duckdb_path` — by attaching that brand
/// new file onto the *live* connection and running `INSERT INTO ...
/// SELECT`, never `CREATE TABLE ... AS SELECT` (see
/// [`setup_timeline_schema_in`]'s doc comment: DuckDB's CTAS silently drops
/// `PRIMARY KEY`/`NOT NULL` constraints, which a forensic case file must
/// keep). `duckdb_conn` must be a *clone* of the live session connection
/// (e.g. `TimelineView::try_clone_conn`), never a fresh, independent
/// `Connection::open` of the live `.duckdb` file — DuckDB only reliably
/// tolerates one independent `Connection::open` of a given file per
/// process.
///
/// Returns the row counts written and every row of `sources` (used
/// afterwards to collect referenced parser configs) — `sources` is always
/// copied in full, see the module doc comment.
fn build_filtered_duckdb(
    duckdb_conn: &duckdb::Connection,
    case_duckdb_path: &Path,
    filter_query_text: &str,
) -> anyhow::Result<(usize, usize, Vec<SourceRow>)> {
    duckdb_conn
        .execute_batch(&format!(
            "ATTACH '{}' AS export_db;",
            sql_quote_path(case_duckdb_path)
        ))
        .context("failed to attach the portable case's new database file")?;

    let result = (|| -> anyhow::Result<(usize, usize, Vec<SourceRow>)> {
        setup_timeline_schema_in(duckdb_conn, "export_db.main.")
            .context("failed to create the portable case's timeline schema")?;

        let query = Query::parse(filter_query_text);
        let (from_where, params) = timeline_queries::compile_from_where(&query);
        duckdb_conn
            .execute(
                &format!("INSERT INTO export_db.main.log_entries SELECT le.* FROM {from_where}"),
                duckdb::params_from_iter(&params),
            )
            .context("failed to copy log_entries into the portable case")?;

        duckdb_conn
            .execute_batch(
                "INSERT INTO export_db.main.import_tags
                 SELECT it.* FROM import_tags it
                 JOIN export_db.main.log_entries le
                   ON it.event_id_source = le.event_id_source
                  AND it.event_id_seq = le.event_id_seq;",
            )
            .context("failed to copy import_tags into the portable case")?;

        duckdb_conn
            .execute_batch("INSERT INTO export_db.main.sources SELECT * FROM sources;")
            .context("failed to copy sources into the portable case")?;

        let entries_written: i64 = duckdb_conn.query_row(
            "SELECT COUNT(*) FROM export_db.main.log_entries",
            [],
            |row| row.get(0),
        )?;
        let tags_written: i64 = duckdb_conn.query_row(
            "SELECT COUNT(*) FROM export_db.main.import_tags",
            [],
            |row| row.get(0),
        )?;
        let sources = fetch_source_rows(duckdb_conn)?;

        Ok((entries_written as usize, tags_written as usize, sources))
    })();

    // `CHECKPOINT` merges `export_db`'s write-ahead log into its main file
    // and truncates it; `DETACH` alone would trigger this too, but doing
    // both explicitly documents the intent. Run even on failure so a
    // half-attached `export_db` never lingers on the live connection for
    // the rest of the app's lifetime.
    let _ = duckdb_conn.execute_batch("CHECKPOINT export_db; DETACH export_db;");

    result
}

/// Builds a fresh copy of the session's SQLite data (`analyst_tags`,
/// `event_notes`, `session_state`, `activity_log`) into `case_sqlite_path`
/// — always copied in full, never filtered (see the module doc comment).
///
/// Connection direction is the mirror image of [`build_filtered_duckdb`],
/// deliberately: the app never holds a persistent SQLite connection open
/// (every operation opens the session's `.sqlite` fresh, see
/// `persist::open_session_db`), so there is no "only one open connection"
/// hazard here — the *target* is opened fresh and the *live* session file
/// is attached onto it, not the reverse.
fn build_session_sqlite(session_sqlite_path: &Path, case_sqlite_path: &Path) -> anyhow::Result<()> {
    let target = rusqlite::Connection::open(case_sqlite_path)
        .with_context(|| format!("failed to create {}", case_sqlite_path.display()))?;
    setup_session_schema(&target)?;
    target
        .execute_batch(&format!(
            "ATTACH DATABASE '{}' AS src;",
            sql_quote_path(session_sqlite_path)
        ))
        .context("failed to attach the live session database for copying")?;
    target
        .execute_batch(
            "INSERT INTO analyst_tags SELECT * FROM src.analyst_tags;
             INSERT INTO event_notes SELECT * FROM src.event_notes;
             INSERT INTO session_state SELECT * FROM src.session_state;
             INSERT INTO activity_log SELECT * FROM src.activity_log;
             DETACH src;",
        )
        .context("failed to copy session data into the portable case")?;
    Ok(())
}

/// Copies every source's referenced text-parser TOML config (if still
/// readable) into `parser_configs_dir`, and turns each [`SourceRow`] into
/// its manifest entry. A config that can no longer be read at export time
/// is recorded as `parser_config_missing = true` rather than silently
/// dropped.
fn collect_parser_configs(
    sources: &[SourceRow],
    parser_configs_dir: &Path,
) -> anyhow::Result<Vec<PortableCaseSourceEntry>> {
    let mut entries = Vec::with_capacity(sources.len());
    for source in sources {
        let (parser_config, parser_config_missing) = match &source.parser_config {
            None => (None, false),
            Some(config_path) => {
                let config_path = Path::new(config_path);
                let file_name = config_path.file_name().and_then(|n| n.to_str());
                match file_name {
                    Some(file_name) if config_path.is_file() => {
                        std::fs::create_dir_all(parser_configs_dir).with_context(|| {
                            format!("failed to create {}", parser_configs_dir.display())
                        })?;
                        let bundled_name = format!("{}-{file_name}", source.source_file_id);
                        std::fs::copy(config_path, parser_configs_dir.join(&bundled_name))
                            .with_context(|| {
                                format!("failed to bundle parser config {}", config_path.display())
                            })?;
                        (Some(format!("parser_configs/{bundled_name}")), false)
                    }
                    _ => (None, true),
                }
            }
        };
        entries.push(PortableCaseSourceEntry {
            source_file_id: source.source_file_id.clone(),
            original_path: source.path.clone(),
            sourcetype: source.sourcetype.clone(),
            parser_config,
            parser_config_missing,
        });
    }
    Ok(entries)
}

/// Streaming SHA-256 of a file — never reads the whole file into memory, so
/// hashing a multi-GB `case.duckdb` stays bounded to one buffer's worth.
fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn add_file_to_zip<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    source_path: &Path,
    name_in_zip: &str,
    options: zip::write::SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file(name_in_zip, options)
        .with_context(|| format!("failed to start zip entry {name_in_zip}"))?;
    let mut source = std::fs::File::open(source_path)
        .with_context(|| format!("failed to open {} for packaging", source_path.display()))?;
    std::io::copy(&mut source, zip)
        .with_context(|| format!("failed to write zip entry {name_in_zip}"))?;
    Ok(())
}

/// Packs `manifest.toml`, `case.duckdb`, `case.sqlite`, and every bundled
/// parser config into a ZIP at `out_path`. `case.duckdb`/`case.sqlite` are
/// stored uncompressed (`CompressionMethod::Stored`) — DuckDB's own storage
/// is already fairly dense, and Deflate-compressing a multi-GB file costs
/// real wall-clock time for limited size benefit. `manifest.toml` and the
/// (small) parser config copies use the crate's default Deflate, where
/// compression is close to free and actually shrinks something — this
/// asymmetry is deliberate, not an inconsistency to "fix" into uniform
/// compression.
///
/// Written first to a `.part` sibling of `out_path` and renamed into place
/// only on success, so a crash mid-export never leaves a truncated
/// `.peachcase` masquerading as a complete one.
fn package_zip(
    manifest_path: &Path,
    case_duckdb_path: &Path,
    case_sqlite_path: &Path,
    parser_configs_dir: &Path,
    out_path: &Path,
) -> anyhow::Result<()> {
    let mut part_name = out_path.as_os_str().to_owned();
    part_name.push(".part");
    let part_path = PathBuf::from(part_name);

    let file = std::fs::File::create(&part_path)
        .with_context(|| format!("failed to create {}", part_path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let deflated = zip::write::SimpleFileOptions::default();

    add_file_to_zip(&mut zip, manifest_path, "manifest.toml", deflated)?;
    add_file_to_zip(&mut zip, case_duckdb_path, "case.duckdb", stored)?;
    add_file_to_zip(&mut zip, case_sqlite_path, "case.sqlite", stored)?;

    if parser_configs_dir.is_dir() {
        for entry in std::fs::read_dir(parser_configs_dir)
            .with_context(|| format!("failed to read {}", parser_configs_dir.display()))?
        {
            let entry = entry?;
            let name_in_zip = format!("parser_configs/{}", entry.file_name().to_string_lossy());
            add_file_to_zip(&mut zip, &entry.path(), &name_in_zip, deflated)?;
        }
    }

    zip.finish()
        .context("failed to finalize the portable case zip")?;
    std::fs::rename(&part_path, out_path).with_context(|| {
        format!(
            "failed to move completed portable case into place at {}",
            out_path.display()
        )
    })?;
    Ok(())
}

/// Exports the session's timeline (or, for a non-empty `filter_query_text`,
/// just the matching subset of it) plus its full session data into a
/// `.peachcase` ZIP at `out_path`. See the module doc comment for exactly
/// what is and isn't filtered.
pub fn export_portable_case(
    duckdb_conn: &duckdb::Connection,
    session_sqlite_path: &Path,
    original_session_id: &str,
    display_name: Option<&str>,
    filter_query_text: &str,
    out_path: &Path,
    progress_tx: &mpsc::Sender<PortableCaseExportOutcome>,
) -> anyhow::Result<PortableCaseExportSummary> {
    let scratch = ScratchDir::new("portable-case-export")?;
    let case_duckdb_path = scratch.path().join("case.duckdb");
    let case_sqlite_path = scratch.path().join("case.sqlite");

    let _ = progress_tx.send(PortableCaseExportOutcome::Progress(
        PortableCaseExportStage::CopyingTimeline,
    ));
    let (entries_written, tags_written, sources) =
        build_filtered_duckdb(duckdb_conn, &case_duckdb_path, filter_query_text)?;

    let _ = progress_tx.send(PortableCaseExportOutcome::Progress(
        PortableCaseExportStage::CopyingSessionData,
    ));
    build_session_sqlite(session_sqlite_path, &case_sqlite_path)?;

    let _ = progress_tx.send(PortableCaseExportOutcome::Progress(
        PortableCaseExportStage::CollectingParserConfigs,
    ));
    let parser_configs_dir = scratch.path().join("parser_configs");
    let source_entries = collect_parser_configs(&sources, &parser_configs_dir)?;

    let _ = progress_tx.send(PortableCaseExportOutcome::Progress(
        PortableCaseExportStage::Hashing,
    ));
    let duckdb_sha256 = sha256_file(&case_duckdb_path)?;
    let sqlite_sha256 = sha256_file(&case_sqlite_path)?;

    let manifest = PortableCaseManifest {
        format_version: PORTABLE_CASE_FORMAT_VERSION,
        peach_version: env!("CARGO_PKG_VERSION").to_string(),
        exported_at: chrono::Utc::now(),
        original_session_id: original_session_id.to_string(),
        display_name: display_name.map(str::to_string),
        filter_query: filter_query_text.to_string(),
        hashes: PortableCaseHashes {
            duckdb_sha256,
            sqlite_sha256,
        },
        sources: source_entries,
    };
    let manifest_toml =
        toml::to_string_pretty(&manifest).context("failed to serialize portable case manifest")?;
    let manifest_path = scratch.path().join("manifest.toml");
    std::fs::write(&manifest_path, &manifest_toml)
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;

    let _ = progress_tx.send(PortableCaseExportOutcome::Progress(
        PortableCaseExportStage::Packaging,
    ));
    package_zip(
        &manifest_path,
        &case_duckdb_path,
        &case_sqlite_path,
        &parser_configs_dir,
        out_path,
    )?;

    Ok(PortableCaseExportSummary {
        entries_written,
        tags_written,
    })
}

fn extract_zip(zip_path: &Path, dest_dir: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(zip_path)
        .with_context(|| format!("failed to open {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .context("not a valid zip file — is this actually a .peachcase bundle?")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        // `enclosed_name` is zip's own zip-slip protection — an entry name
        // it considers unsafe (absolute, or escaping via `..`) is skipped
        // rather than failing the whole import over one untrusted name.
        let Some(relative_path) = entry.enclosed_name() else {
            continue;
        };
        let dest_path = dest_dir.join(relative_path);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest_path)?;
            continue;
        }
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out_file = std::fs::File::create(&dest_path)
            .with_context(|| format!("failed to create {}", dest_path.display()))?;
        std::io::copy(&mut entry, &mut out_file)
            .with_context(|| format!("failed to extract {}", dest_path.display()))?;
    }
    Ok(())
}

/// `fs::rename`, falling back to copy+delete for a cross-filesystem move
/// (e.g. the OS temp directory and the sessions directory living on
/// different filesystems/drives) — `rename` alone fails in that case on
/// every major OS.
fn move_or_copy(from: &Path, to: &Path) -> anyhow::Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to)
        .with_context(|| format!("failed to copy {} to {}", from.display(), to.display()))?;
    std::fs::remove_file(from)
        .with_context(|| format!("failed to remove {} after copying", from.display()))?;
    Ok(())
}

/// Imports a `.peachcase` bundle as a brand-new, independent session under
/// `sessions_dir` — never reuses the bundle's `original_session_id` (see
/// `persist::new_session_dir_for_import`'s doc comment: a portable case must
/// never be able to clobber an existing local session, even the same bundle
/// imported twice back to back).
pub fn import_portable_case(
    zip_path: &Path,
    sessions_dir: &Path,
    progress_tx: &mpsc::Sender<PortableCaseImportOutcome>,
) -> anyhow::Result<SessionPaths> {
    let scratch = ScratchDir::new("portable-case-import")?;

    let _ = progress_tx.send(PortableCaseImportOutcome::Progress(
        PortableCaseImportStage::Extracting,
    ));
    extract_zip(zip_path, scratch.path())?;

    let _ = progress_tx.send(PortableCaseImportOutcome::Progress(
        PortableCaseImportStage::VerifyingFormat,
    ));
    let manifest_path = scratch.path().join("manifest.toml");
    let manifest_toml = std::fs::read_to_string(&manifest_path)
        .context("not a valid Peach portable case: no manifest.toml found in the bundle")?;
    let manifest: PortableCaseManifest = toml::from_str(&manifest_toml)
        .context("not a valid Peach portable case: manifest.toml could not be parsed")?;
    anyhow::ensure!(
        manifest.format_version <= PORTABLE_CASE_FORMAT_VERSION,
        "this portable case was exported by a newer version of Peach (format version {}, this \
         Peach understands up to {PORTABLE_CASE_FORMAT_VERSION}) — update Peach to import it",
        manifest.format_version,
    );

    let _ = progress_tx.send(PortableCaseImportOutcome::Progress(
        PortableCaseImportStage::VerifyingIntegrity,
    ));
    let case_duckdb_path = scratch.path().join("case.duckdb");
    let case_sqlite_path = scratch.path().join("case.sqlite");
    anyhow::ensure!(
        case_duckdb_path.is_file(),
        "not a valid Peach portable case: case.duckdb is missing from the bundle"
    );
    anyhow::ensure!(
        case_sqlite_path.is_file(),
        "not a valid Peach portable case: case.sqlite is missing from the bundle"
    );
    anyhow::ensure!(
        sha256_file(&case_duckdb_path)? == manifest.hashes.duckdb_sha256,
        "portable case failed integrity verification: case.duckdb's hash doesn't match the \
         manifest (the bundle may be corrupted or was modified after export)"
    );
    anyhow::ensure!(
        sha256_file(&case_sqlite_path)? == manifest.hashes.sqlite_sha256,
        "portable case failed integrity verification: case.sqlite's hash doesn't match the \
         manifest (the bundle may be corrupted or was modified after export)"
    );

    let _ = progress_tx.send(PortableCaseImportOutcome::Progress(
        PortableCaseImportStage::RegisteringSession,
    ));
    let session_paths = persist::new_session_dir_for_import(sessions_dir)?;
    move_or_copy(&case_duckdb_path, &session_paths.duckdb_path)?;
    move_or_copy(&case_sqlite_path, &session_paths.sqlite_path)?;

    let parser_configs_src = scratch.path().join("parser_configs");
    if parser_configs_src.is_dir() {
        let parser_configs_dest = session_paths
            .sqlite_path
            .parent()
            .expect("a session's sqlite path always has a parent directory")
            .join("parser_configs");
        std::fs::create_dir_all(&parser_configs_dest)
            .with_context(|| format!("failed to create {}", parser_configs_dest.display()))?;
        for entry in std::fs::read_dir(&parser_configs_src)? {
            let entry = entry?;
            move_or_copy(&entry.path(), &parser_configs_dest.join(entry.file_name()))?;
        }
    }

    let conn = persist::open_session_db(&session_paths.sqlite_path)?;
    persist::save_imported_from(
        &conn,
        &ImportedFrom {
            original_session_id: manifest.original_session_id.clone(),
            exported_at: manifest.exported_at,
            exporting_peach_version: manifest.peach_version.clone(),
            filter_query: manifest.filter_query.clone(),
        },
    )?;
    let now = chrono::Utc::now().timestamp();
    persist::insert_activity_log_entry(
        &conn,
        NewActivityLogEntry {
            operation: "import".to_string(),
            started_at: now,
            finished_at: now,
            source_path: Some(manifest.original_session_id.clone()),
            sourcetype: None,
            status: "ok".to_string(),
            error: None,
            entries_inserted: None,
            tags_applied: None,
            skipped: Vec::new(),
            per_file: Vec::new(),
            tags_by_rule: Vec::new(),
        },
    )?;

    Ok(session_paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::timeline_schema::setup_timeline_schema;
    use crate::model::event_id::{EventId, SequenceCounter, SourceFileId};
    use chrono::TimeZone;

    fn temp_path(name: &str, ext: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "peach-portable_case-test-{}-{}-{name}.{ext}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn sample_manifest() -> PortableCaseManifest {
        PortableCaseManifest {
            format_version: PORTABLE_CASE_FORMAT_VERSION,
            peach_version: "0.2.1".to_string(),
            exported_at: chrono::Utc.with_ymd_and_hms(2026, 8, 26, 14, 0, 0).unwrap(),
            original_session_id: "session-20260801-120000".to_string(),
            display_name: Some("Suspect laptop".to_string()),
            filter_query: "level=ERROR".to_string(),
            hashes: PortableCaseHashes {
                duckdb_sha256: "a".repeat(64),
                sqlite_sha256: "b".repeat(64),
            },
            sources: vec![PortableCaseSourceEntry {
                source_file_id: SourceFileId::new_random().to_string(),
                original_path: "/evidence/system.log".to_string(),
                sourcetype: "syslog".to_string(),
                parser_config: Some("parser_configs/xyz-syslog.toml".to_string()),
                parser_config_missing: false,
            }],
        }
    }

    #[test]
    fn manifest_round_trips_through_toml() {
        let manifest = sample_manifest();
        let toml_text = toml::to_string_pretty(&manifest).unwrap();
        let parsed: PortableCaseManifest = toml::from_str(&toml_text).unwrap();
        assert_eq!(parsed, manifest);
    }

    /// Seeds a live DuckDB with `messages.len()` entries under one source
    /// (with `sourcetype`/`parser_config` set on its `sources` row), tags
    /// entry index 0 with `rule_name`/`tag_value` "seed"/"tagged", and
    /// returns `(source_file_id, event_ids)`.
    fn seed_timeline(conn: &duckdb::Connection, messages: &[&str]) -> (String, Vec<EventId>) {
        setup_timeline_schema(conn).unwrap();
        let source_file_id = SourceFileId::new_random();
        conn.execute(
            "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
             VALUES (?, ?, ?, NULL, NULL)",
            duckdb::params![source_file_id.to_string(), "/evidence/system.log", "syslog"],
        )
        .unwrap();

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
                    chrono::Utc::now().naive_utc(),
                    message,
                    format!("raw: {message}"),
                ],
            )
            .unwrap();
            ids.push(event_id);
        }
        (source_file_id.to_string(), ids)
    }

    fn tag_entry(conn: &duckdb::Connection, event_id: EventId, rule_name: &str, tag_value: &str) {
        conn.execute(
            "INSERT INTO import_tags (event_id_source, event_id_seq, rule_name, tag_value, applied_at)
             VALUES (?, ?, ?, ?, ?)",
            duckdb::params![
                event_id.source_file_id.to_string(),
                event_id.sequence_number.value() as i64,
                rule_name,
                tag_value,
                chrono::Utc::now().naive_utc(),
            ],
        )
        .unwrap();
    }

    #[test]
    fn whole_session_export_then_import_preserves_rows_and_provenance() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        let (_source_id, ids) = seed_timeline(&conn, &["hello", "world", "hello again"]);
        tag_entry(&conn, ids[0], "seed_rule", "tagged");

        let session_sqlite_path = temp_path("whole-session", "sqlite");
        {
            let session_conn = rusqlite::Connection::open(&session_sqlite_path).unwrap();
            setup_session_schema(&session_conn).unwrap();
            persist::insert_analyst_tag(&session_conn, ids[1], "reviewed").unwrap();
            persist::insert_event_note(&session_conn, ids[1], "check this").unwrap();
            persist::save_display_name(&session_conn, "Suspect laptop").unwrap();
        }

        let out_path = temp_path("whole-session-out", "peachcase");
        let (tx, _rx) = mpsc::channel();
        let summary = export_portable_case(
            &conn,
            &session_sqlite_path,
            "session-20260801-120000",
            Some("Suspect laptop"),
            "",
            &out_path,
            &tx,
        )
        .unwrap();
        assert_eq!(summary.entries_written, 3);
        assert_eq!(summary.tags_written, 1);

        let sessions_dir = temp_path("whole-session-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (import_tx, _import_rx) = mpsc::channel();
        let session_paths = import_portable_case(&out_path, &sessions_dir, &import_tx).unwrap();

        let imported_conn = duckdb::Connection::open(&session_paths.duckdb_path).unwrap();
        let entry_count: i64 = imported_conn
            .query_row("SELECT COUNT(*) FROM log_entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(entry_count, 3);
        let raw: String = imported_conn
            .query_row(
                "SELECT raw FROM log_entries WHERE message = 'hello'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw, "raw: hello");

        let imported_sqlite = rusqlite::Connection::open(&session_paths.sqlite_path).unwrap();
        assert_eq!(
            persist::load_display_name(&imported_sqlite).unwrap(),
            Some("Suspect laptop".to_string())
        );
        let analyst_tags = persist::all_analyst_tags(&imported_sqlite).unwrap();
        assert_eq!(
            analyst_tags.get(&ids[1]).unwrap(),
            &vec!["reviewed".to_string()]
        );
        let notes = persist::all_event_notes(&imported_sqlite).unwrap();
        assert_eq!(notes.get(&ids[1]).unwrap(), &vec!["check this".to_string()]);

        let imported_from = persist::load_imported_from(&imported_sqlite)
            .unwrap()
            .unwrap();
        assert_eq!(imported_from.original_session_id, "session-20260801-120000");
        assert_eq!(imported_from.filter_query, "");

        let activity = persist::all_activity_log_entries(&imported_sqlite).unwrap();
        assert!(activity.iter().any(|entry| entry.operation == "import"));

        std::fs::remove_file(&session_sqlite_path).ok();
        std::fs::remove_file(&out_path).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }

    /// Regression test for the CTAS pitfall `setup_timeline_schema_in`'s doc
    /// comment warns about: the reimported `log_entries` table must still
    /// reject a duplicate `event_id`, proving it kept its `PRIMARY KEY`
    /// constraint rather than the constraint-free schema a naive
    /// `CREATE TABLE ... AS SELECT` would have produced.
    #[test]
    fn imported_log_entries_still_enforce_the_primary_key() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        let (_source_id, ids) = seed_timeline(&conn, &["only entry"]);
        let session_sqlite_path = temp_path("pk-session", "sqlite");
        rusqlite::Connection::open(&session_sqlite_path)
            .and_then(|c| {
                setup_session_schema(&c)?;
                Ok(())
            })
            .unwrap();

        let out_path = temp_path("pk-out", "peachcase");
        let (tx, _rx) = mpsc::channel();
        export_portable_case(
            &conn,
            &session_sqlite_path,
            "orig",
            None,
            "",
            &out_path,
            &tx,
        )
        .unwrap();

        let sessions_dir = temp_path("pk-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (import_tx, _import_rx) = mpsc::channel();
        let session_paths = import_portable_case(&out_path, &sessions_dir, &import_tx).unwrap();

        let imported_conn = duckdb::Connection::open(&session_paths.duckdb_path).unwrap();
        let duplicate = imported_conn.execute(
            "INSERT INTO log_entries (event_id_source, event_id_seq, timestamp_utc, raw)
             VALUES (?, ?, ?, 'dup')",
            duckdb::params![
                ids[0].source_file_id.to_string(),
                ids[0].sequence_number.value() as i64,
                chrono::Utc::now().naive_utc(),
            ],
        );
        assert!(
            duplicate.is_err(),
            "reimported log_entries must still reject a duplicate event_id"
        );

        std::fs::remove_file(&session_sqlite_path).ok();
        std::fs::remove_file(&out_path).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }

    #[test]
    fn filtered_export_keeps_matching_entries_and_their_tags_but_not_others() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        let (_source_id, ids) = seed_timeline(&conn, &["hello a", "hello b", "world c"]);
        tag_entry(&conn, ids[0], "rule_a", "tag_a");
        tag_entry(&conn, ids[2], "rule_c", "tag_c");

        let session_sqlite_path = temp_path("filtered-session", "sqlite");
        {
            let session_conn = rusqlite::Connection::open(&session_sqlite_path).unwrap();
            setup_session_schema(&session_conn).unwrap();
            // An analyst tag on the entry the filter will exclude — must
            // still travel (orphaned, but not silently dropped).
            persist::insert_analyst_tag(&session_conn, ids[2], "reviewed").unwrap();
        }

        let out_path = temp_path("filtered-out", "peachcase");
        let (tx, _rx) = mpsc::channel();
        let summary = export_portable_case(
            &conn,
            &session_sqlite_path,
            "orig",
            None,
            "hello",
            &out_path,
            &tx,
        )
        .unwrap();
        assert_eq!(summary.entries_written, 2, "only the two 'hello' entries");
        assert_eq!(
            summary.tags_written, 1,
            "only rule_a's tag survives the filter"
        );

        let sessions_dir = temp_path("filtered-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (import_tx, _import_rx) = mpsc::channel();
        let session_paths = import_portable_case(&out_path, &sessions_dir, &import_tx).unwrap();

        let imported_conn = duckdb::Connection::open(&session_paths.duckdb_path).unwrap();
        let messages: Vec<String> = {
            let mut stmt = imported_conn
                .prepare("SELECT message FROM log_entries ORDER BY message")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(messages, vec!["hello a".to_string(), "hello b".to_string()]);

        // The analyst tag on the filtered-out "world c" entry is still
        // present in the bundle's session data — deliberately orphaned,
        // not dropped.
        let imported_sqlite = rusqlite::Connection::open(&session_paths.sqlite_path).unwrap();
        let analyst_tags = persist::all_analyst_tags(&imported_sqlite).unwrap();
        assert_eq!(
            analyst_tags.get(&ids[2]).unwrap(),
            &vec!["reviewed".to_string()]
        );

        std::fs::remove_file(&session_sqlite_path).ok();
        std::fs::remove_file(&out_path).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }

    #[test]
    fn parser_config_is_bundled_and_missing_config_is_flagged_not_dropped() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        setup_timeline_schema(&conn).unwrap();
        let present_id = SourceFileId::new_random();
        let missing_id = SourceFileId::new_random();
        let config_path = temp_path("real-parser-config", "toml");
        std::fs::write(&config_path, "[parser]\nname = \"test\"\n").unwrap();

        conn.execute(
            "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
             VALUES (?, '/evidence/a.log', 'text', NULL, ?)",
            duckdb::params![present_id.to_string(), config_path.to_str().unwrap()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
             VALUES (?, '/evidence/b.log', 'text', NULL, '/nonexistent/gone.toml')",
            duckdb::params![missing_id.to_string()],
        )
        .unwrap();

        let session_sqlite_path = temp_path("parser-config-session", "sqlite");
        rusqlite::Connection::open(&session_sqlite_path)
            .and_then(|c| {
                setup_session_schema(&c)?;
                Ok(())
            })
            .unwrap();

        let out_path = temp_path("parser-config-out", "peachcase");
        let (tx, _rx) = mpsc::channel();
        export_portable_case(
            &conn,
            &session_sqlite_path,
            "orig",
            None,
            "",
            &out_path,
            &tx,
        )
        .unwrap();

        let sessions_dir = temp_path("parser-config-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (import_tx, _import_rx) = mpsc::channel();
        let session_paths = import_portable_case(&out_path, &sessions_dir, &import_tx).unwrap();

        let manifest_str = {
            let file = std::fs::File::open(&out_path).unwrap();
            let mut archive = zip::ZipArchive::new(file).unwrap();
            let mut manifest_file = archive.by_name("manifest.toml").unwrap();
            let mut contents = String::new();
            manifest_file.read_to_string(&mut contents).unwrap();
            contents
        };
        let manifest: PortableCaseManifest = toml::from_str(&manifest_str).unwrap();
        let present_entry = manifest
            .sources
            .iter()
            .find(|s| s.source_file_id == present_id.to_string())
            .unwrap();
        assert!(!present_entry.parser_config_missing);
        assert!(present_entry.parser_config.is_some());
        let missing_entry = manifest
            .sources
            .iter()
            .find(|s| s.source_file_id == missing_id.to_string())
            .unwrap();
        assert!(missing_entry.parser_config_missing);
        assert!(missing_entry.parser_config.is_none());

        let bundled_configs_dir = session_paths
            .sqlite_path
            .parent()
            .unwrap()
            .join("parser_configs");
        let bundled_files: Vec<_> = std::fs::read_dir(&bundled_configs_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            bundled_files.len(),
            1,
            "only the readable config is bundled"
        );

        std::fs::remove_file(&config_path).ok();
        std::fs::remove_file(&session_sqlite_path).ok();
        std::fs::remove_file(&out_path).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }

    #[test]
    fn import_rejects_a_bundle_with_a_tampered_duckdb_file() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        seed_timeline(&conn, &["hello"]);
        let session_sqlite_path = temp_path("tamper-session", "sqlite");
        rusqlite::Connection::open(&session_sqlite_path)
            .and_then(|c| {
                setup_session_schema(&c)?;
                Ok(())
            })
            .unwrap();

        let out_path = temp_path("tamper-out", "peachcase");
        let (tx, _rx) = mpsc::channel();
        export_portable_case(
            &conn,
            &session_sqlite_path,
            "orig",
            None,
            "",
            &out_path,
            &tx,
        )
        .unwrap();

        // Tamper: append a byte to case.duckdb inside the zip by rewriting
        // the whole archive with one entry's bytes flipped.
        let tampered_path = temp_path("tamper-modified", "peachcase");
        {
            let src = std::fs::File::open(&out_path).unwrap();
            let mut archive = zip::ZipArchive::new(src).unwrap();
            let out_file = std::fs::File::create(&tampered_path).unwrap();
            let mut writer = zip::ZipWriter::new(out_file);
            for i in 0..archive.len() {
                let mut entry = archive.by_index(i).unwrap();
                let name = entry.name().to_string();
                let mut contents = Vec::new();
                entry.read_to_end(&mut contents).unwrap();
                if name == "case.duckdb" {
                    contents.push(0xFF);
                }
                writer
                    .start_file(&name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(&contents).unwrap();
            }
            writer.finish().unwrap();
        }

        let sessions_dir = temp_path("tamper-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (import_tx, _import_rx) = mpsc::channel();
        let result = import_portable_case(&tampered_path, &sessions_dir, &import_tx);
        assert!(result.is_err());
        assert!(
            format!("{:#}", result.unwrap_err()).contains("integrity"),
            "expected an integrity-check failure message"
        );

        std::fs::remove_file(&session_sqlite_path).ok();
        std::fs::remove_file(&out_path).ok();
        std::fs::remove_file(&tampered_path).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }

    #[test]
    fn import_rejects_a_manifest_with_a_newer_format_version() {
        let mut manifest = sample_manifest();
        manifest.format_version = PORTABLE_CASE_FORMAT_VERSION + 1;
        let manifest_toml = toml::to_string_pretty(&manifest).unwrap();

        let scratch_zip = temp_path("future-version", "peachcase");
        {
            let file = std::fs::File::create(&scratch_zip).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            zip.start_file("manifest.toml", zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(manifest_toml.as_bytes()).unwrap();
            // No case.duckdb/case.sqlite needed — format-version rejection
            // must happen before those are even checked for.
            zip.finish().unwrap();
        }

        let sessions_dir = temp_path("future-version-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (tx, _rx) = mpsc::channel();
        let result = import_portable_case(&scratch_zip, &sessions_dir, &tx);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("newer version"));

        std::fs::remove_file(&scratch_zip).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }

    #[test]
    fn import_rejects_a_zip_with_no_manifest() {
        let scratch_zip = temp_path("no-manifest", "peachcase");
        {
            let file = std::fs::File::create(&scratch_zip).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            zip.start_file("readme.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"not a case").unwrap();
            zip.finish().unwrap();
        }

        let sessions_dir = temp_path("no-manifest-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (tx, _rx) = mpsc::channel();
        let result = import_portable_case(&scratch_zip, &sessions_dir, &tx);
        assert!(result.is_err());

        std::fs::remove_file(&scratch_zip).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }

    #[test]
    fn import_rejects_a_file_that_is_not_a_zip_at_all() {
        let not_a_zip = temp_path("not-a-zip", "peachcase");
        std::fs::write(&not_a_zip, b"definitely not a zip file").unwrap();

        let sessions_dir = temp_path("not-a-zip-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (tx, _rx) = mpsc::channel();
        let result = import_portable_case(&not_a_zip, &sessions_dir, &tx);
        assert!(result.is_err());

        std::fs::remove_file(&not_a_zip).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }

    #[test]
    fn importing_the_same_bundle_twice_produces_two_independent_sessions() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        seed_timeline(&conn, &["hello"]);
        let session_sqlite_path = temp_path("double-import-session", "sqlite");
        rusqlite::Connection::open(&session_sqlite_path)
            .and_then(|c| {
                setup_session_schema(&c)?;
                Ok(())
            })
            .unwrap();

        let out_path = temp_path("double-import-out", "peachcase");
        let (tx, _rx) = mpsc::channel();
        export_portable_case(
            &conn,
            &session_sqlite_path,
            "orig",
            None,
            "",
            &out_path,
            &tx,
        )
        .unwrap();

        let sessions_dir = temp_path("double-import-sessions", "dir");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        let (tx1, _rx1) = mpsc::channel();
        let first = import_portable_case(&out_path, &sessions_dir, &tx1).unwrap();
        let (tx2, _rx2) = mpsc::channel();
        let second = import_portable_case(&out_path, &sessions_dir, &tx2).unwrap();

        assert_ne!(first.id, second.id);
        assert!(first.duckdb_path.is_file());
        assert!(second.duckdb_path.is_file());

        std::fs::remove_file(&session_sqlite_path).ok();
        std::fs::remove_file(&out_path).ok();
        std::fs::remove_dir_all(&sessions_dir).ok();
    }
}
