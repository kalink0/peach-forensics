use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use anyhow::Context;
use eframe::egui;

use crate::db::timeline_queries::Query;
use crate::db::timeline_schema::setup_timeline_schema;
use crate::model::event_id::SourceFileId;
use crate::model::log_entry::LogEntry;
use crate::parsers::aul::AulParser;
use crate::parsers::evtx::EvtxFileParser;
use crate::parsers::journald::JournaldFileParser;
use crate::parsers::text_config::TextConfigParser;
use crate::parsers::{LogParser, ParserConfig, parse_source_streaming};
use crate::session::persist::{self, LoadedSource, SessionPaths};
use crate::tagging::engine::{apply_import_time, re_tag};
use crate::tagging::rule::Rule;
use crate::ui::filter_bar::FilterBar;
use crate::ui::timeline_view::TimelineView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Aul,
    Evtx,
    Journald,
    Text,
}

enum LoadOutcome {
    Done(Result<(usize, usize, LoadedSource), String>),
}

enum LoadState {
    Idle,
    Loading,
    Done {
        inserted: usize,
        tags_applied: usize,
    },
    Failed(String),
}

enum RetagOutcome {
    Done(Result<usize, String>),
}

enum RetagState {
    Idle,
    Running,
    Done { applied: usize },
    Failed(String),
}

pub struct PeachApp {
    db_path: PathBuf,
    session_paths: SessionPaths,
    loaded_sources: Vec<LoadedSource>,
    source_kind: SourceKind,
    source_path: Option<PathBuf>,
    parser_config_path: Option<PathBuf>,
    rule_paths: Vec<PathBuf>,
    load_state: LoadState,
    load_rx: Option<mpsc::Receiver<LoadOutcome>>,
    retag_state: RetagState,
    retag_rx: Option<mpsc::Receiver<RetagOutcome>>,
    timeline: TimelineView,
    filter_bar: FilterBar,
    available_levels: Vec<String>,
    pending_cli_sources: VecDeque<PathBuf>,
    cleanup_dirs: Vec<PathBuf>,
}

/// Pops the first `--add-source` path (if any) to pre-fill, determining its
/// sourcetype structurally rather than guessing a text format: a directory
/// can only be AUL (the only directory-based sourcetype), and `.evtx`/
/// `.journal` are unambiguous, well-known extensions. Everything else
/// defaults to Text. Keeps the rest queued for after each load succeeds.
fn queue_from_cli_sources(
    add_sources: Vec<PathBuf>,
) -> (Option<PathBuf>, SourceKind, VecDeque<PathBuf>) {
    let mut queue: VecDeque<PathBuf> = add_sources.into();
    match queue.pop_front() {
        Some(path) => {
            let kind = source_kind_for_path(&path);
            (Some(path), kind, queue)
        }
        None => (None, SourceKind::Aul, queue),
    }
}

fn source_kind_for_path(path: &Path) -> SourceKind {
    if path.is_dir() {
        SourceKind::Aul
    } else if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"))
    {
        SourceKind::Evtx
    } else if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("journal"))
    {
        SourceKind::Journald
    } else {
        SourceKind::Text
    }
}

impl PeachApp {
    fn new(add_sources: Vec<PathBuf>, cleanup_dirs: Vec<PathBuf>) -> Self {
        // Falls back to a plain temp file if the OS data directory can't be
        // determined — better a working, non-persisted session than a
        // crash on startup.
        let sessions_dir = persist::default_sessions_dir().unwrap_or_else(|_| std::env::temp_dir());
        let session_paths = SessionPaths::new_in(&sessions_dir, persist::new_session_id());
        let _ = persist::open_session_db(&session_paths.sqlite_path);
        let db_path = session_paths.duckdb_path.clone();

        let (source_path, source_kind, pending_cli_sources) = queue_from_cli_sources(add_sources);

        Self {
            db_path: db_path.clone(),
            session_paths,
            loaded_sources: Vec::new(),
            source_kind,
            source_path,
            parser_config_path: None,
            rule_paths: Vec::new(),
            load_state: LoadState::Idle,
            load_rx: None,
            retag_state: RetagState::Idle,
            retag_rx: None,
            timeline: TimelineView::new(db_path),
            filter_bar: FilterBar::new(),
            available_levels: Vec::new(),
            pending_cli_sources,
            cleanup_dirs,
        }
    }

    /// Switches to a previously saved session — points at its `.duckdb`
    /// (already-parsed, no re-parsing) and restores the loaded-source list
    /// and search query from its `.sqlite` `session_state`.
    fn load_session(&mut self, sqlite_path: PathBuf) -> anyhow::Result<()> {
        let session_paths = SessionPaths::from_sqlite_path(&sqlite_path)?;
        let conn = persist::open_session_db(&session_paths.sqlite_path)?;
        let loaded_sources = persist::load_loaded_sources(&conn)?;
        let search_query = persist::load_search_query(&conn)?.unwrap_or_default();

        self.db_path = session_paths.duckdb_path.clone();
        self.session_paths = session_paths;
        self.loaded_sources = loaded_sources;
        self.timeline = TimelineView::new(self.db_path.clone());
        self.timeline.refresh();
        self.available_levels = self.timeline.distinct_levels();
        self.filter_bar.set_text(search_query.clone());
        self.timeline.set_query(Query::parse(&search_query));

        Ok(())
    }

    fn start_retag(&mut self) {
        if self.rule_paths.is_empty() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.retag_rx = Some(rx);
        self.retag_state = RetagState::Running;

        let db_path = self.db_path.clone();
        let rule_paths = self.rule_paths.clone();

        std::thread::spawn(move || {
            let result = run_retag(&rule_paths, &db_path).map_err(|err| format!("{err:#}"));
            let _ = tx.send(RetagOutcome::Done(result));
        });
    }

    fn start_load(&mut self) {
        let Some(source_path) = self.source_path.clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.load_rx = Some(rx);
        self.load_state = LoadState::Loading;

        let db_path = self.db_path.clone();
        let source_kind = self.source_kind;
        let parser_config_path = self.parser_config_path.clone();
        let rule_paths = self.rule_paths.clone();

        std::thread::spawn(move || {
            let result = run_load(
                source_kind,
                &source_path,
                parser_config_path.as_deref(),
                &rule_paths,
                &db_path,
            )
            .map_err(|err| format!("{err:#}"));
            let _ = tx.send(LoadOutcome::Done(result));
        });
    }
}

impl eframe::App for PeachApp {
    fn on_exit(&mut self) {
        for dir in &self.cleanup_dirs {
            cleanup_temp_dir(dir);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.load_rx {
            match rx.try_recv() {
                Ok(LoadOutcome::Done(result)) => {
                    match result {
                        Ok((inserted, tags_applied, loaded_source)) => {
                            self.load_state = LoadState::Done {
                                inserted,
                                tags_applied,
                            };
                            self.timeline.refresh();
                            self.available_levels = self.timeline.distinct_levels();
                            self.loaded_sources.push(loaded_source);
                            if let Ok(conn) =
                                persist::open_session_db(&self.session_paths.sqlite_path)
                            {
                                let _ = persist::save_loaded_sources(&conn, &self.loaded_sources);
                            }
                            if let Some(next) = self.pending_cli_sources.pop_front() {
                                self.source_kind = source_kind_for_path(&next);
                                self.source_path = Some(next);
                                self.parser_config_path = None;
                            }
                        }
                        Err(err) => self.load_state = LoadState::Failed(err),
                    }
                    self.load_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ui.ctx().request_repaint();
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.load_state =
                        LoadState::Failed("load worker disconnected unexpectedly".to_string());
                    self.load_rx = None;
                }
            }
        }

        if let Some(rx) = &self.retag_rx {
            match rx.try_recv() {
                Ok(RetagOutcome::Done(result)) => {
                    match result {
                        Ok(applied) => self.retag_state = RetagState::Done { applied },
                        Err(err) => self.retag_state = RetagState::Failed(err),
                    }
                    self.retag_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ui.ctx().request_repaint();
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.retag_state =
                        RetagState::Failed("re-tag worker disconnected unexpectedly".to_string());
                    self.retag_rx = None;
                }
            }
        }

        egui::Panel::top("controls").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Session: {}", self.session_paths.id));
                let can_switch_session = !matches!(self.load_state, LoadState::Loading)
                    && !matches!(self.retag_state, RetagState::Running);
                if ui
                    .add_enabled(can_switch_session, egui::Button::new("Load session..."))
                    .clicked()
                    && let Some(picked) = rfd::FileDialog::new()
                        .set_directory(
                            persist::default_sessions_dir()
                                .unwrap_or_else(|_| std::env::temp_dir()),
                        )
                        .add_filter("Session", &["sqlite"])
                        .pick_file()
                    && let Err(err) = self.load_session(picked)
                {
                    self.load_state = LoadState::Failed(format!("{err:#}"));
                }
            });

            ui.horizontal(|ui| {
                ui.label("Sourcetype:");
                ui.selectable_value(&mut self.source_kind, SourceKind::Aul, "AUL (.logarchive)");
                ui.selectable_value(&mut self.source_kind, SourceKind::Evtx, "EVTX");
                ui.selectable_value(&mut self.source_kind, SourceKind::Journald, "journald");
                ui.selectable_value(
                    &mut self.source_kind,
                    SourceKind::Text,
                    "Text (config-based)",
                );
                if !self.pending_cli_sources.is_empty() {
                    ui.label(format!(
                        "({} more source(s) queued from --add-source)",
                        self.pending_cli_sources.len()
                    ));
                }
            });

            ui.horizontal(|ui| {
                let pick_label = match self.source_kind {
                    SourceKind::Aul => "Choose .logarchive folder...",
                    SourceKind::Evtx => "Choose .evtx file...",
                    SourceKind::Journald => "Choose .journal file...",
                    SourceKind::Text => "Choose log file...",
                };
                if ui.button(pick_label).clicked() {
                    let picked = match self.source_kind {
                        SourceKind::Aul => rfd::FileDialog::new().pick_folder(),
                        SourceKind::Evtx => rfd::FileDialog::new()
                            .add_filter("EVTX", &["evtx"])
                            .pick_file(),
                        SourceKind::Journald => rfd::FileDialog::new()
                            .add_filter("journald", &["journal"])
                            .pick_file(),
                        SourceKind::Text => rfd::FileDialog::new().pick_file(),
                    };
                    if let Some(picked) = picked {
                        self.source_path = Some(picked);
                    }
                }
                if let Some(source_path) = &self.source_path {
                    ui.label(source_path.display().to_string());
                }
            });

            if self.source_kind == SourceKind::Text {
                ui.horizontal(|ui| {
                    if ui.button("Choose parser config (TOML)...").clicked()
                        && let Some(picked) = rfd::FileDialog::new()
                            .add_filter("TOML", &["toml"])
                            .pick_file()
                    {
                        self.parser_config_path = Some(picked);
                    }
                    if let Some(config_path) = &self.parser_config_path {
                        ui.label(config_path.display().to_string());
                    }
                });
            }

            ui.horizontal(|ui| {
                if ui
                    .button("Choose tagging rules (TOML, optional)...")
                    .clicked()
                    && let Some(picked) = rfd::FileDialog::new()
                        .add_filter("TOML", &["toml"])
                        .pick_files()
                {
                    self.rule_paths = picked;
                }
                if self.rule_paths.is_empty() {
                    ui.label("(none selected — import-time tagging skipped)");
                } else {
                    ui.label(format!("{} rule file(s) selected", self.rule_paths.len()));
                }

                let can_retag = !matches!(self.load_state, LoadState::Loading)
                    && !matches!(self.retag_state, RetagState::Running)
                    && !self.rule_paths.is_empty()
                    && self.timeline.total_rows() > 0;
                if ui
                    .add_enabled(can_retag, egui::Button::new("Re-tag now"))
                    .on_hover_text(
                        "Re-evaluate the selected rules against everything already loaded, \
                         replacing import_tags",
                    )
                    .clicked()
                {
                    self.start_retag();
                }
                match &self.retag_state {
                    RetagState::Idle => {}
                    RetagState::Running => {
                        ui.spinner();
                        ui.label("Re-tagging...");
                    }
                    RetagState::Done { applied } => {
                        ui.label(format!("Re-tag applied {applied} tags"));
                    }
                    RetagState::Failed(err) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {err}"));
                    }
                }
            });

            let can_load = !matches!(self.load_state, LoadState::Loading)
                && !matches!(self.retag_state, RetagState::Running)
                && self.source_path.is_some()
                && (self.source_kind != SourceKind::Text || self.parser_config_path.is_some());

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(can_load, egui::Button::new("Load"))
                    .clicked()
                {
                    self.start_load();
                }
                match &self.load_state {
                    LoadState::Idle => {}
                    LoadState::Loading => {
                        ui.spinner();
                        ui.label("Loading...");
                    }
                    LoadState::Done {
                        inserted,
                        tags_applied,
                    } => {
                        ui.label(format!(
                            "Loaded {inserted} entries, applied {tags_applied} tags"
                        ));
                    }
                    LoadState::Failed(err) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {err}"));
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            if let Some(query) = self.filter_bar.ui(ui, &self.available_levels) {
                self.timeline.set_query(query);
                if let Ok(conn) = persist::open_session_db(&self.session_paths.sqlite_path) {
                    let _ = persist::save_search_query(&conn, self.filter_bar.text());
                }
            }
            ui.separator();
            self.timeline.ui(ui);
        });
    }
}

/// Rows held in memory at once between flushes to DuckDB. Bounds peak RSS
/// to O(batch), not O(source size) — see the module doc on `run_load` for
/// why that distinction actually matters here.
const LOAD_BATCH_SIZE: usize = 10_000;

/// Runs on a background thread so the UI stays responsive — this can mean
/// parsing and inserting millions of rows for a large AUL source. Opens its
/// own DuckDB connection (`Connection` isn't `Send`) and bulk-inserts via
/// the DuckDB Appender rather than row-by-row `INSERT` statements.
///
/// Streams entries out of the parser in batches of [`LOAD_BATCH_SIZE`]
/// (`parse_source_streaming`, not `parse_source`) rather than collecting
/// the whole source into one `Vec<LogEntry>` before writing anything to
/// DuckDB: a real AUL `.logarchive` can resolve into millions of entries,
/// and holding all of them — each carrying its own `raw`/`fields` JSON —
/// in the Rust heap at once is what drove a 219 MB source past 45 GB of
/// RSS during testing. DuckDB, not the process heap, is meant to hold the
/// bulk timeline (CLAUDE.md's "nicht im RAM halten" principle).
fn run_load(
    source_kind: SourceKind,
    source_path: &Path,
    parser_config_path: Option<&Path>,
    rule_paths: &[PathBuf],
    db_path: &Path,
) -> anyhow::Result<(usize, usize, LoadedSource)> {
    let conn = duckdb::Connection::open(db_path)?;
    setup_timeline_schema(&conn)?;

    let (parser, config): (&dyn LogParser, ParserConfig) = match source_kind {
        SourceKind::Aul => (
            &AulParser,
            ParserConfig::from_toml_str("[parser]\nname = \"aul\"\nsourcetype = \"aul\"\n")?,
        ),
        SourceKind::Evtx => (
            &EvtxFileParser,
            ParserConfig::from_toml_str("[parser]\nname = \"evtx\"\nsourcetype = \"evtx\"\n")?,
        ),
        SourceKind::Journald => (
            &JournaldFileParser,
            ParserConfig::from_toml_str(
                "[parser]\nname = \"journald\"\nsourcetype = \"journald\"\n",
            )?,
        ),
        SourceKind::Text => {
            let config_path = parser_config_path
                .ok_or_else(|| anyhow::anyhow!("no parser config selected for a text source"))?;
            let config_text = std::fs::read_to_string(config_path)?;
            (
                &TextConfigParser,
                ParserConfig::from_toml_str(&config_text)?,
            )
        }
    };
    // The config's sourcetype is authoritative, not `parser.sourcetype()`:
    // TextConfigParser serves many different sourcetypes (nginx, syslog,
    // ...) depending on which config is loaded, so its own sourcetype() is
    // just a generic marker (see parsers/mod.rs doc comment).
    let sourcetype = config.parser.sourcetype.clone();
    let rules = load_rules(rule_paths)?;

    let mut batch: Vec<LogEntry> = Vec::with_capacity(LOAD_BATCH_SIZE);
    let mut inserted = 0usize;
    let mut tags_applied = 0usize;

    let source_file_id = parse_source_streaming(parser, source_path, &config, |entry| {
        inserted += 1;
        batch.push(entry);
        if batch.len() >= LOAD_BATCH_SIZE {
            tags_applied += flush_batch(&conn, &mut batch, &rules, &sourcetype)?;
        }
        Ok(())
    })?;
    tags_applied += flush_batch(&conn, &mut batch, &rules, &sourcetype)?;

    let loaded_source = LoadedSource {
        path: source_path.display().to_string(),
        sourcetype: sourcetype.clone(),
        parser_config_path: parser_config_path.map(|p| p.display().to_string()),
    };

    if inserted == 0 {
        return Ok((0, 0, loaded_source));
    }
    insert_source_record(&conn, source_file_id, source_path, &sourcetype)?;

    Ok((inserted, tags_applied, loaded_source))
}

/// Appends `batch` to `log_entries` via the DuckDB Appender, applies
/// import-time tagging for exactly those rows, then empties `batch` —
/// called every [`LOAD_BATCH_SIZE`] entries plus once more for the
/// remainder. The appender is dropped (flushed) before tagging: DuckDB
/// doesn't allow an open Appender and other statements on the same
/// connection at once.
fn flush_batch(
    conn: &duckdb::Connection,
    batch: &mut Vec<LogEntry>,
    rules: &[Rule],
    sourcetype: &str,
) -> anyhow::Result<usize> {
    if batch.is_empty() {
        return Ok(0);
    }

    {
        let mut appender = conn.appender("log_entries")?;
        for entry in batch.iter() {
            appender.append_row(duckdb::params![
                entry.event_id.source_file_id.to_string(),
                entry.event_id.sequence_number.value() as i64,
                entry.timestamp_utc.naive_utc(),
                entry.level,
                entry.message,
                entry.raw,
                entry.fields,
            ])?;
        }
    }

    let tags_applied = apply_import_time(conn, rules, batch, sourcetype)?;
    batch.clear();
    Ok(tags_applied)
}

/// Runs on a background thread, like [`run_load`] — re-evaluating rules
/// against every already-loaded entry touches the whole `log_entries`
/// table, so it deserves the same "don't freeze the UI" treatment.
fn run_retag(rule_paths: &[PathBuf], db_path: &Path) -> anyhow::Result<usize> {
    let conn = duckdb::Connection::open(db_path)?;
    let rules = load_rules(rule_paths)?;
    re_tag(&conn, &rules)
}

fn load_rules(rule_paths: &[PathBuf]) -> anyhow::Result<Vec<Rule>> {
    rule_paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read rule file {}", path.display()))?;
            Rule::from_toml_str(&text)
                .with_context(|| format!("invalid rule file {}", path.display()))
        })
        .collect()
}

fn insert_source_record(
    conn: &duckdb::Connection,
    source_file_id: SourceFileId,
    source_path: &Path,
    sourcetype: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
         VALUES (?, ?, ?, ?, ?)",
        duckdb::params![
            source_file_id.to_string(),
            source_path.display().to_string(),
            sourcetype,
            Option::<String>::None,
            Option::<String>::None,
        ],
    )?;
    Ok(())
}

/// `cleanup_dirs` is only ever deleted verbatim and only if it resolves
/// (after following symlinks) to somewhere under the OS temp directory —
/// crush is expected to pass its own extraction temp dir here, and this is
/// a safety net against a mistaken or malicious path, not a guess about
/// what "temporary" means.
fn cleanup_temp_dir(dir: &Path) {
    let os_temp = std::env::temp_dir();
    let (Ok(canonical_dir), Ok(canonical_temp)) = (dir.canonicalize(), os_temp.canonicalize())
    else {
        eprintln!(
            "peach: skipping cleanup of {}: could not resolve path",
            dir.display()
        );
        return;
    };
    if !canonical_dir.starts_with(&canonical_temp) {
        eprintln!(
            "peach: refusing to clean up {}: not under the OS temp directory ({})",
            dir.display(),
            os_temp.display()
        );
        return;
    }
    if let Err(err) = std::fs::remove_dir_all(&canonical_dir) {
        eprintln!(
            "peach: failed to clean up {}: {err}",
            canonical_dir.display()
        );
    }
}

pub fn run(add_sources: Vec<PathBuf>, cleanup_dirs: Vec<PathBuf>) -> anyhow::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Peach",
        native_options,
        Box::new(move |_cc| Ok(Box::new(PeachApp::new(add_sources, cleanup_dirs)))),
    )
    .map_err(|err| anyhow::anyhow!("failed to run peach GUI: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_from_cli_sources_prefills_the_first_and_queues_the_rest() {
        let dir = std::env::temp_dir().join(format!("peach-test-cli-dir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file =
            std::env::temp_dir().join(format!("peach-test-cli-file-{}", uuid::Uuid::new_v4()));
        std::fs::write(&file, b"x").unwrap();

        let (first, kind, rest) = queue_from_cli_sources(vec![dir.clone(), file.clone()]);

        assert_eq!(first, Some(dir.clone()));
        assert_eq!(kind, SourceKind::Aul);
        assert_eq!(rest.into_iter().collect::<Vec<_>>(), vec![file.clone()]);

        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn queue_from_cli_sources_picks_journald_for_a_dot_journal_file() {
        let file = std::env::temp_dir().join(format!(
            "peach-test-cli-journal-{}.journal",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&file, b"x").unwrap();

        let (first, kind, rest) = queue_from_cli_sources(vec![file.clone()]);

        assert_eq!(first, Some(file.clone()));
        assert_eq!(kind, SourceKind::Journald);
        assert!(rest.is_empty());

        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn queue_from_cli_sources_picks_text_for_a_file() {
        let file =
            std::env::temp_dir().join(format!("peach-test-cli-file2-{}", uuid::Uuid::new_v4()));
        std::fs::write(&file, b"x").unwrap();

        let (first, kind, rest) = queue_from_cli_sources(vec![file.clone()]);

        assert_eq!(first, Some(file.clone()));
        assert_eq!(kind, SourceKind::Text);
        assert!(rest.is_empty());

        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn queue_from_cli_sources_with_no_sources_is_empty() {
        let (first, _, rest) = queue_from_cli_sources(vec![]);
        assert_eq!(first, None);
        assert!(rest.is_empty());
    }

    #[test]
    fn cleanup_temp_dir_removes_a_directory_under_os_temp() {
        let dir = std::env::temp_dir().join(format!("peach-test-cleanup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file.txt"), b"evidence").unwrap();

        cleanup_temp_dir(&dir);

        assert!(!dir.exists());
    }

    #[test]
    fn cleanup_temp_dir_refuses_a_directory_outside_os_temp() {
        // CARGO_MANIFEST_DIR is the project root — never under the OS temp dir.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
        assert!(dir.exists(), "expected the build output dir to exist");

        cleanup_temp_dir(&dir);

        assert!(
            dir.exists(),
            "must not delete anything outside the OS temp dir"
        );
    }
}
