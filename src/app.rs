use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use anyhow::Context;
use eframe::egui;
use rayon::prelude::*;

use crate::config::{self, Settings, Theme};
use crate::db::timeline_queries::{self, Query};
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
use crate::tagging::rule_file;
use crate::ui::about_dialog::{self, AboutDialog};
use crate::ui::filter_bar::FilterBar;
use crate::ui::session_dialog::{self, SessionManagerDialog, SessionManagerOutcome};
use crate::ui::settings_dialog::{SettingsDialog, SettingsOutcome};
use crate::ui::tag_dialog::{TagDialog, TagDialogOutcome};
use crate::ui::theme;
use crate::ui::timeline_view::{RowAction, TimelineView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Aul,
    Evtx,
    Journald,
    Text,
}

enum LoadOutcome {
    /// Sent every [`LOAD_BATCH_SIZE`] entries, and whenever a file
    /// finishes, during a load — running totals across every file when
    /// the source is a folder (never reset mid-load). `inserted` isn't a
    /// fraction of a known total: a source's total *entry* count generally
    /// isn't knowable without a full parse pass, which would mean parsing
    /// twice (against the streaming design `run_load`'s doc comment
    /// explains) just to show an ETA. `bytes_done`/`bytes_total` fill that
    /// gap with a real, data-based fraction instead — known upfront from
    /// file sizes, at file-level granularity (jumps per completed file,
    /// not smoothly within one — see `run_load`).
    Progress {
        inserted: usize,
        bytes_done: u64,
        bytes_total: u64,
    },
    Done(Result<(LoadSummary, std::time::Duration), String>),
}

/// A file `run_load` found (via `collect_source_files`) but didn't produce
/// any timeline entries from — either a real parse error, or a file that
/// parsed cleanly but matched nothing (see `load_one_file`). Surfaced to
/// the analyst rather than silently dropped — forensic tooling doesn't get
/// to make a file's evidence quietly disappear from the load result just
/// because it didn't parse.
struct SkippedFile {
    path: PathBuf,
    reason: String,
}

/// What one `run_load` call — one file, or every matching file under a
/// recursively-loaded folder — accomplished.
struct LoadSummary {
    inserted: usize,
    tags_applied: usize,
    loaded_sources: Vec<LoadedSource>,
    skipped: Vec<SkippedFile>,
}

enum LoadState {
    Idle,
    Loading {
        inserted_so_far: usize,
        bytes_done: u64,
        bytes_total: u64,
    },
    Done {
        inserted: usize,
        tags_applied: usize,
        /// Wall-clock time for the whole load (parsing + DuckDB inserts +
        /// import-time tagging) — measured around `run_load` in
        /// `start_load`, not inside it, so it reflects exactly what the
        /// analyst was waiting on. Not a forensic artifact of the evidence
        /// itself, just a quick way to gauge how this source/machine
        /// performs.
        elapsed: std::time::Duration,
        /// Files `collect_source_files` found but that produced no
        /// entries — empty for the common single-good-file case.
        skipped: Vec<SkippedFile>,
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
    /// Every session `.sqlite` path this run has ever pointed
    /// `session_paths` at — including ones since abandoned by switching
    /// away via `load_session`. `on_exit` empty-cleans all of them, not
    /// just the current one: the session auto-created at startup (see
    /// `new`) never gets touched again if the analyst switches to a
    /// different saved session mid-run, so checking only `session_paths`
    /// at exit would silently leak that first one forever.
    visited_sessions: Vec<PathBuf>,
    loaded_sources: Vec<LoadedSource>,
    source_kind: SourceKind,
    source_path: Option<PathBuf>,
    parser_config_path: Option<PathBuf>,
    rule_paths: Vec<PathBuf>,
    /// Whether the embedded AUL pattern-of-life pack
    /// (`tagging::builtin::aul_pattern_of_life_rules`) is applied alongside
    /// `rule_paths` on every load/re-tag. On by default — the analyst can
    /// still see and turn it off, it just isn't opt-in by default, since
    /// pattern-of-life categorization is the normal AUL workflow, not an
    /// advanced feature (see `docs/`).
    use_builtin_aul_rules: bool,
    load_state: LoadState,
    load_rx: Option<mpsc::Receiver<LoadOutcome>>,
    retag_state: RetagState,
    retag_rx: Option<mpsc::Receiver<RetagOutcome>>,
    timeline: TimelineView,
    filter_bar: FilterBar,
    available_levels: Vec<String>,
    available_tags: Vec<String>,
    pending_cli_sources: VecDeque<PathBuf>,
    cleanup_dirs: Vec<PathBuf>,
    tag_dialog: TagDialog,
    session_dialog: SessionManagerDialog,
    settings: Settings,
    settings_dialog: SettingsDialog,
    about_dialog: AboutDialog,
    /// Wall-clock anchor for the `Theme::Rainbow` animation — see
    /// `theme::tick`'s doc comment for why it's elapsed-time-based rather
    /// than a per-frame step.
    rainbow_start: Option<std::time::Instant>,
    tag_preview_rx: Option<mpsc::Receiver<usize>>,
    /// The pattern the current/last `tag_preview` count corresponds to —
    /// lets the UI tell "counting a stale pattern" apart from "count for
    /// what's on screen right now" instead of showing a preview number
    /// that's quietly wrong for what's currently typed.
    tag_preview_pattern: String,
    tag_preview: Option<usize>,
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
        let settings = config::load();
        // Falls back to a plain temp file if the sessions directory (OS
        // default or configured override) can't be created — better a
        // working, non-persisted session than a crash on startup.
        let sessions_dir = settings
            .sessions_dir()
            .unwrap_or_else(|_| std::env::temp_dir());
        // A reliable backstop for the on_exit cleanup below: that one only
        // fires on a graceful shutdown, so this sweeps up whatever a
        // killed/crashed previous run left behind, before this run's own
        // (currently still-empty) session gets created.
        session_dialog::sweep_empty_sessions(&sessions_dir);
        let session_paths = SessionPaths::new_in(&sessions_dir, persist::new_session_id());
        // Best-effort, same reasoning as the `open_session_db` call right
        // after it: a failure here just means this run's session doesn't
        // persist, not a crash on startup.
        let _ = session_paths.ensure_dir();
        let _ = persist::open_session_db(&session_paths.sqlite_path);
        let db_path = session_paths.duckdb_path.clone();

        let (source_path, source_kind, pending_cli_sources) = queue_from_cli_sources(add_sources);

        Self {
            db_path: db_path.clone(),
            timeline: TimelineView::new(db_path, session_paths.sqlite_path.clone()),
            visited_sessions: vec![session_paths.sqlite_path.clone()],
            session_paths,
            loaded_sources: Vec::new(),
            source_kind,
            source_path,
            parser_config_path: None,
            rule_paths: Vec::new(),
            use_builtin_aul_rules: true,
            load_state: LoadState::Idle,
            load_rx: None,
            retag_state: RetagState::Idle,
            retag_rx: None,
            filter_bar: FilterBar::new(),
            available_levels: Vec::new(),
            available_tags: Vec::new(),
            pending_cli_sources,
            cleanup_dirs,
            tag_dialog: TagDialog::Closed,
            session_dialog: SessionManagerDialog::Closed,
            settings,
            settings_dialog: SettingsDialog::Closed,
            about_dialog: AboutDialog::Closed,
            rainbow_start: None,
            tag_preview_rx: None,
            tag_preview_pattern: String::new(),
            tag_preview: None,
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
        self.timeline = TimelineView::new(self.db_path.clone(), session_paths.sqlite_path.clone());
        if !self.visited_sessions.contains(&session_paths.sqlite_path) {
            self.visited_sessions
                .push(session_paths.sqlite_path.clone());
        }
        self.session_paths = session_paths;
        self.loaded_sources = loaded_sources;
        self.timeline.refresh();
        self.available_levels = self.timeline.distinct_levels();
        self.available_tags = self.timeline.distinct_tags();
        self.filter_bar.set_text(search_query.clone());
        self.timeline.set_query(Query::parse(&search_query));

        Ok(())
    }

    fn start_retag(&mut self) {
        if self.rule_paths.is_empty() && !self.use_builtin_aul_rules {
            return;
        }
        let Some(conn) = self.timeline.try_clone_conn() else {
            self.retag_state =
                RetagState::Failed("failed to open a database connection for re-tagging".into());
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.retag_rx = Some(rx);
        self.retag_state = RetagState::Running;

        let rule_paths = self.rule_paths.clone();
        let include_builtin_aul_rules = self.use_builtin_aul_rules;

        std::thread::spawn(move || {
            let result = run_retag(&rule_paths, include_builtin_aul_rules, conn)
                .map_err(|err| format!("{err:#}"));
            let _ = tx.send(RetagOutcome::Done(result));
        });
    }

    fn start_load(&mut self) {
        let Some(source_path) = self.source_path.clone() else {
            return;
        };
        let Some(conn) = self.timeline.try_clone_conn() else {
            self.load_state =
                LoadState::Failed("failed to open a database connection for loading".to_string());
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.load_rx = Some(rx);
        self.load_state = LoadState::Loading {
            inserted_so_far: 0,
            bytes_done: 0,
            bytes_total: 0,
        };

        let source_kind = self.source_kind;
        let parser_config_path = self.parser_config_path.clone();
        let rule_paths = self.rule_paths.clone();
        let include_builtin_aul_rules = self.use_builtin_aul_rules;
        let load_threads = self.settings.effective_load_threads();

        std::thread::spawn(move || {
            let progress_tx = tx.clone();
            let start = std::time::Instant::now();
            let result = run_load(
                source_kind,
                &source_path,
                parser_config_path.as_deref(),
                RuleSelection {
                    paths: &rule_paths,
                    include_builtin_aul: include_builtin_aul_rules,
                },
                conn,
                load_threads,
                &progress_tx,
            )
            .map(|summary| (summary, start.elapsed()))
            .map_err(|err| format!("{err:#}"));
            let _ = tx.send(LoadOutcome::Done(result));
        });
    }

    /// Distinct tag values from both tables tags can come from —
    /// `import_tags` (rule-produced, already tracked in `available_tags`)
    /// and `analyst_tags` (manual) — so the tagging dialogs' "existing
    /// tags" picker offers one combined vocabulary regardless of which
    /// table a tag happened to come from.
    fn combined_tag_vocabulary(&self) -> Vec<String> {
        let mut tags = self.available_tags.clone();
        if let Ok(conn) = persist::open_session_db(&self.session_paths.sqlite_path)
            && let Ok(analyst_tags) = persist::distinct_analyst_tag_values(&conn)
        {
            tags.extend(analyst_tags);
        }
        tags.sort();
        tags.dedup();
        tags
    }

    fn handle_row_action(&mut self, action: RowAction) {
        match action {
            RowAction::TagSingle { event_id } => {
                let existing = self.combined_tag_vocabulary();
                self.tag_dialog = TagDialog::open_single(event_id, existing);
                self.tag_preview = None;
                self.tag_preview_pattern.clear();
            }
            RowAction::TagAllMatching { event_id, message } => {
                let existing = self.combined_tag_vocabulary();
                self.tag_dialog = TagDialog::open_advanced(event_id, message, existing);
                self.tag_preview = None;
                self.tag_preview_pattern.clear();
            }
            RowAction::ShowContext { query_text } => {
                self.filter_bar.set_text(query_text.clone());
                self.timeline.set_query(Query::parse(&query_text));
                if let Ok(conn) = persist::open_session_db(&self.session_paths.sqlite_path) {
                    let _ = persist::save_search_query(&conn, &query_text);
                }
            }
        }
    }

    /// Kicks off a background match count for the Advanced dialog's
    /// current pattern if it changed since the last one — same "don't
    /// freeze the UI on every keystroke" reasoning as
    /// `TimelineView::recount`, since this is the same kind of
    /// leading-wildcard `LIKE` scan.
    fn update_tag_preview_request(&mut self) {
        let Some(pattern) = self.tag_dialog.current_pattern() else {
            return;
        };
        if pattern == self.tag_preview_pattern || self.tag_preview_rx.is_some() {
            return;
        }
        self.tag_preview_pattern = pattern.to_string();
        self.tag_preview = None;
        if pattern.trim().is_empty() {
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.tag_preview_rx = Some(rx);
        let conn = self.timeline.try_clone_conn();
        let pattern = pattern.to_string();
        std::thread::spawn(move || {
            let count = conn
                .and_then(|conn| timeline_queries::count_message_contains(&conn, &pattern).ok())
                .unwrap_or(0);
            let _ = tx.send(count);
        });
    }

    fn poll_tag_preview(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.tag_preview_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(count) => {
                self.tag_preview = Some(count);
                self.tag_preview_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => ctx.request_repaint(),
            Err(mpsc::TryRecvError::Disconnected) => self.tag_preview_rx = None,
        }
    }

    /// Renders whichever tag dialog is open and executes what the analyst
    /// confirmed — the dialog itself only reports the outcome (see
    /// `ui::tag_dialog`), since it doesn't own the session/rule-file state
    /// applying it needs.
    fn handle_tag_dialog(&mut self, ctx: &egui::Context) {
        if !self.tag_dialog.is_open() {
            return;
        }
        let rule_paths = self.rule_paths.clone();
        let preview = self
            .tag_dialog
            .current_pattern()
            .filter(|pattern| *pattern == self.tag_preview_pattern)
            .and(self.tag_preview);
        let Some(outcome) = self.tag_dialog.ui(
            ctx,
            |tag| find_rule_producing_tag(&rule_paths, tag),
            preview,
        ) else {
            return;
        };

        match outcome {
            TagDialogOutcome::TagSingleEvent {
                event_id,
                tag_value,
            } => {
                if let Ok(conn) = persist::open_session_db(&self.session_paths.sqlite_path) {
                    let _ = persist::insert_analyst_tag(&conn, event_id, &tag_value);
                }
                self.timeline.refresh();
            }
            TagDialogOutcome::CreateRule {
                rule_name,
                pattern,
                tag_value,
            } => {
                if let Ok(dir) = rule_file::default_user_rules_dir() {
                    let path = dir.join(format!("{}.toml", rule_file::slugify(&rule_name)));
                    if rule_file::create_message_contains_rule(
                        &path, &rule_name, &pattern, &tag_value,
                    )
                    .is_ok()
                    {
                        if !self.rule_paths.contains(&path) {
                            self.rule_paths.push(path);
                        }
                        self.start_retag();
                    }
                }
            }
            TagDialogOutcome::ExtendRule { path, pattern } => {
                if rule_file::append_message_contains_pattern(&path, &pattern).is_ok() {
                    if !self.rule_paths.contains(&path) {
                        self.rule_paths.push(path);
                    }
                    self.start_retag();
                }
            }
        }
    }

    /// Renders the "Manage sessions" dialog if open and switches to
    /// whichever session the analyst picked via its Open button — deletion
    /// is handled entirely inside the dialog itself (it only ever touches
    /// session files on disk, not `PeachApp`'s own state), so the only
    /// outcome this side needs to react to is `Open`.
    fn handle_session_dialog(&mut self, ctx: &egui::Context) {
        if !self.session_dialog.is_open() {
            return;
        }
        let Some(outcome) = self.session_dialog.ui(ctx, &self.session_paths.id) else {
            return;
        };
        match outcome {
            SessionManagerOutcome::Open(sqlite_path) => {
                if let Err(err) = self.load_session(sqlite_path) {
                    self.load_state = LoadState::Failed(format!("{err:#}"));
                }
            }
        }
    }

    /// Renders the "Settings" dialog if open and persists a confirmed
    /// change — best-effort, same as the rest of this app's local-file
    /// housekeeping (`cleanup_temp_dir`, the empty-session cleanup in
    /// `on_exit`): a failure to *write* `config.toml` shouldn't undo the
    /// analyst's choice for the rest of this run, just mean it doesn't
    /// survive a restart.
    fn handle_settings_dialog(&mut self, ctx: &egui::Context) {
        if !self.settings_dialog.is_open() {
            return;
        }
        let Some(outcome) = self.settings_dialog.ui(ctx) else {
            return;
        };
        match outcome {
            SettingsOutcome::Save(new_settings) => {
                if let Err(err) = config::save(&new_settings) {
                    eprintln!("peach: failed to save settings: {err:#}");
                }
                self.settings = new_settings;
            }
        }
    }
}

/// Which currently-loaded rule file (if exactly one — `None` if zero or
/// several, ambiguous) already produces `tag_value`, so the advanced
/// tagging dialog can offer "extend that rule" instead of always creating
/// a new one.
fn find_rule_producing_tag(rule_paths: &[PathBuf], tag_value: &str) -> Option<PathBuf> {
    let mut candidates = rule_paths.iter().filter(|path| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| Rule::from_toml_str(&text).ok())
            .is_some_and(|rule| rule.rule.tag.value == tag_value)
    });
    let first = candidates.next()?;
    if candidates.next().is_some() {
        None
    } else {
        Some(first.clone())
    }
}

impl eframe::App for PeachApp {
    fn on_exit(&mut self) {
        // Best-effort: a session that was never loaded into (just created
        // by starting the app, or abandoned by switching to a different
        // one via `load_session` mid-run) shouldn't linger and clutter
        // "Manage sessions" forever. Checks *every* session this run ever
        // pointed at, not just the current one — see `visited_sessions`'
        // doc. `delete_if_empty` itself refuses to touch a session that
        // has data, so this is safe for whichever one is still current.
        for sqlite_path in &self.visited_sessions {
            if let Err(err) = session_dialog::delete_if_empty(sqlite_path) {
                eprintln!(
                    "peach: failed to clean up empty session {}: {err:#}",
                    sqlite_path.display()
                );
            }
        }
        for dir in &self.cleanup_dirs {
            cleanup_temp_dir(dir);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        theme::tick(ui.ctx(), self.settings.theme, &mut self.rainbow_start);

        if let Some(rx) = &self.load_rx {
            // Drain everything queued this frame, not just one message: a
            // large source can flush several `Progress` updates between
            // frames, and only the most recent one (or a trailing `Done`)
            // actually matters for what gets displayed.
            loop {
                match rx.try_recv() {
                    Ok(LoadOutcome::Progress {
                        inserted,
                        bytes_done,
                        bytes_total,
                    }) => {
                        self.load_state = LoadState::Loading {
                            inserted_so_far: inserted,
                            bytes_done,
                            bytes_total,
                        };
                    }
                    Ok(LoadOutcome::Done(result)) => {
                        match result {
                            Ok((summary, elapsed)) => {
                                self.load_state = LoadState::Done {
                                    inserted: summary.inserted,
                                    tags_applied: summary.tags_applied,
                                    elapsed,
                                    skipped: summary.skipped,
                                };
                                // Releases the multi-GB DuckDB Appender
                                // memory the bulk load just left attached to
                                // the database instance — see
                                // `TimelineView::reopen_connection`'s doc
                                // comment. Before `refresh()`, not after: its
                                // own `try_clone_conn()` calls should get the
                                // fresh connection, not the about-to-be-freed
                                // one.
                                self.timeline.reopen_connection();
                                self.timeline.refresh();
                                self.available_levels = self.timeline.distinct_levels();
                                self.available_tags = self.timeline.distinct_tags();
                                self.loaded_sources.extend(summary.loaded_sources);
                                if let Ok(conn) =
                                    persist::open_session_db(&self.session_paths.sqlite_path)
                                {
                                    let _ =
                                        persist::save_loaded_sources(&conn, &self.loaded_sources);
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
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        ui.ctx().request_repaint();
                        break;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.load_state =
                            LoadState::Failed("load worker disconnected unexpectedly".to_string());
                        self.load_rx = None;
                        break;
                    }
                }
            }
        }

        if let Some(rx) = &self.retag_rx {
            match rx.try_recv() {
                Ok(RetagOutcome::Done(result)) => {
                    match result {
                        Ok(applied) => {
                            self.retag_state = RetagState::Done { applied };
                            // Same reasoning as the load-completion handler:
                            // `re_tag`'s DELETE+Appender-rewrite of
                            // `import_tags` leaves memory attached to the
                            // database instance until every connection to
                            // it, including this view's own base one, is
                            // dropped — see
                            // `TimelineView::reopen_connection`.
                            self.timeline.reopen_connection();
                            // Drops the row cache so the Tags column
                            // reflects the just-recomputed import_tags
                            // immediately, not only once the visible
                            // window happens to get invalidated some
                            // other way (e.g. scrolling).
                            self.timeline.refresh();
                            self.available_tags = self.timeline.distinct_tags();
                        }
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

        let can_switch_session = !matches!(self.load_state, LoadState::Loading { .. })
            && !matches!(self.retag_state, RetagState::Running);

        egui::Panel::top("menu_bar").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui
                        .add_enabled(can_switch_session, egui::Button::new("Load session..."))
                        .clicked()
                    {
                        ui.close();
                        if let Some(picked) = rfd::FileDialog::new()
                            .set_directory(
                                self.settings
                                    .sessions_dir()
                                    .unwrap_or_else(|_| std::env::temp_dir()),
                            )
                            .add_filter("Session", &["sqlite"])
                            .pick_file()
                            && let Err(err) = self.load_session(picked)
                        {
                            self.load_state = LoadState::Failed(format!("{err:#}"));
                        }
                    }
                    if ui
                        .add_enabled(can_switch_session, egui::Button::new("Manage sessions..."))
                        .clicked()
                    {
                        ui.close();
                        if let Ok(dir) = self.settings.sessions_dir() {
                            // Only clone a connection if the current session's
                            // `.duckdb` already exists — `try_clone_conn`
                            // lazily *creates* it on first call, and this
                            // dialog otherwise has no reason to touch a
                            // session nothing has been loaded into yet. Doing
                            // that unconditionally here used to leave behind
                            // an empty-but-no-longer-"empty" `.duckdb` (data
                            // schema, zero rows) just from opening this
                            // dialog, which then defeated the on-exit
                            // empty-session cleanup (`delete_if_empty`) since
                            // it only checks file *existence*, not row count.
                            let current_conn = if self.db_path.exists() {
                                self.timeline.try_clone_conn()
                            } else {
                                None
                            };
                            self.session_dialog = SessionManagerDialog::open(
                                &dir,
                                &self.session_paths.id,
                                current_conn,
                            );
                        }
                    }
                    ui.separator();
                    if ui.button("Settings...").clicked() {
                        self.settings_dialog = SettingsDialog::open(self.settings.clone());
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("View", |ui| {
                    ui.menu_button("Theme", |ui| {
                        let mut theme_changed = false;
                        theme_changed |= ui
                            .radio_value(&mut self.settings.theme, Theme::System, "System default")
                            .changed();
                        theme_changed |= ui
                            .radio_value(&mut self.settings.theme, Theme::Light, "Light")
                            .changed();
                        theme_changed |= ui
                            .radio_value(&mut self.settings.theme, Theme::Dark, "Dark")
                            .changed();
                        theme_changed |= ui
                            .radio_value(&mut self.settings.theme, Theme::Geek, "Geek")
                            .changed();
                        theme_changed |= ui
                            .radio_value(&mut self.settings.theme, Theme::Rainbow, "Rainbow")
                            .changed();
                        if theme_changed {
                            theme::apply(ui.ctx(), self.settings.theme);
                            if let Err(err) = config::save(&self.settings) {
                                eprintln!("peach: failed to save theme setting: {err:#}");
                            }
                        }
                    });
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About Peach...").clicked() {
                        self.about_dialog = AboutDialog::open();
                        ui.close();
                    }
                });
            });
        });

        egui::Panel::top("controls").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Session: {}", self.session_paths.id));
                if ui
                    .add_enabled(can_switch_session, egui::Button::new("Load session..."))
                    .clicked()
                    && let Some(picked) = rfd::FileDialog::new()
                        .set_directory(
                            self.settings
                                .sessions_dir()
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
                if self.source_kind == SourceKind::Aul {
                    if ui.button("Choose .logarchive folder...").clicked()
                        && let Some(picked) = rfd::FileDialog::new().pick_folder()
                    {
                        self.source_path = Some(picked);
                    }
                } else {
                    let (file_label, extension_filter) = match self.source_kind {
                        SourceKind::Evtx => ("Choose .evtx file...", Some(("EVTX", "evtx"))),
                        SourceKind::Journald => {
                            ("Choose .journal file...", Some(("journald", "journal")))
                        }
                        SourceKind::Text => ("Choose log file...", None),
                        SourceKind::Aul => unreachable!("handled above"),
                    };
                    if ui.button(file_label).clicked() {
                        let mut dialog = rfd::FileDialog::new();
                        if let Some((name, ext)) = extension_filter {
                            dialog = dialog.add_filter(name, &[ext]);
                        }
                        if let Some(picked) = dialog.pick_file() {
                            self.source_path = Some(picked);
                        }
                    }
                    if ui
                        .button("Choose folder...")
                        .on_hover_text(
                            "Recursively loads every matching file found in the folder \
                             (and its subfolders) as separate sources",
                        )
                        .clicked()
                        && let Some(picked) = rfd::FileDialog::new().pick_folder()
                    {
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
                ui.checkbox(
                    &mut self.use_builtin_aul_rules,
                    "Built-in AUL pattern-of-life rules",
                )
                .on_hover_text(
                    "Applies the bundled AUL rule pack (screen lock, WiFi, app launches, \
                         etc.) on every load and re-tag, regardless of which rule files are \
                         also selected below. Only ever matches AUL entries.",
                );

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
                    ui.label("(no extra rule files selected)");
                } else {
                    ui.label(format!("{} rule file(s) selected", self.rule_paths.len()));
                }

                let can_retag = !matches!(self.load_state, LoadState::Loading { .. })
                    && !matches!(self.retag_state, RetagState::Running)
                    && (!self.rule_paths.is_empty() || self.use_builtin_aul_rules)
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

            let can_load = !matches!(self.load_state, LoadState::Loading { .. })
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
                    LoadState::Loading {
                        inserted_so_far,
                        bytes_done,
                        bytes_total,
                    } => {
                        ui.spinner();
                        if *inserted_so_far > 0 {
                            ui.label(format!("Loading... {inserted_so_far} entries so far"));
                        } else {
                            ui.label("Loading...");
                        }
                        // Data-based progress — file-level granularity (jumps
                        // per completed file, not smooth within one large
                        // file; see `run_load`'s doc comment for why entry
                        // count can't drive a real fraction here either).
                        if *bytes_total > 0 {
                            let fraction = *bytes_done as f32 / *bytes_total as f32;
                            ui.add(egui::ProgressBar::new(fraction).desired_width(200.0).text(
                                format!(
                                    "{:.1} / {:.1} MB",
                                    *bytes_done as f64 / 1_000_000.0,
                                    *bytes_total as f64 / 1_000_000.0
                                ),
                            ));
                        }
                    }
                    LoadState::Done {
                        inserted,
                        tags_applied,
                        elapsed,
                        skipped,
                    } => {
                        ui.label(format!(
                            "Loaded {inserted} entries, applied {tags_applied} tags in {:.1}s",
                            elapsed.as_secs_f64()
                        ));
                        if !skipped.is_empty() {
                            ui.colored_label(
                                egui::Color32::from_rgb(230, 160, 0),
                                format!("{} file(s) skipped", skipped.len()),
                            )
                            .on_hover_ui(|ui| {
                                for file in skipped {
                                    ui.label(format!("{}: {}", file.path.display(), file.reason));
                                }
                            });
                        }
                    }
                    LoadState::Failed(err) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {err}"));
                    }
                }
            });
        });

        let mut row_action = None;
        egui::CentralPanel::default().show(ui, |ui| {
            if let Some(query) =
                self.filter_bar
                    .ui(ui, &self.available_levels, &self.available_tags)
            {
                self.timeline.set_query(query);
                if let Ok(conn) = persist::open_session_db(&self.session_paths.sqlite_path) {
                    let _ = persist::save_search_query(&conn, self.filter_bar.text());
                }
            }
            ui.separator();
            row_action = self.timeline.ui(ui);
        });

        if let Some(action) = row_action {
            self.handle_row_action(action);
        }
        self.poll_tag_preview(ui.ctx());
        self.update_tag_preview_request();
        self.handle_tag_dialog(ui.ctx());
        self.handle_session_dialog(ui.ctx());
        self.handle_settings_dialog(ui.ctx());
        self.about_dialog.ui(ui.ctx());
    }
}

/// Rows held in memory at once between flushes to DuckDB. Bounds peak RSS
/// to O(batch), not O(source size) — see the module doc on `run_load` for
/// why that distinction actually matters here.
const LOAD_BATCH_SIZE: usize = 10_000;

/// Resolves `source_path` to the concrete list of files [`run_load`] will
/// parse, one file = one independent parse run = one `source_file_id`/
/// `sources` row (see [`load_one_file`]). AUL's `.logarchive` is always one
/// atomic source (never split up) regardless of `source_path` being a
/// directory, and a plain file pick for any sourcetype is always exactly
/// itself — both short-circuit before ever touching the filesystem beyond
/// `source_path` itself.
///
/// Otherwise (a folder picked for EVTX/journald/Text), walks it
/// recursively. EVTX/journald filter by their own canonical,
/// unambiguous extension (`.evtx`/`.journal`, case-insensitive) — a folder
/// export commonly has unrelated files sitting alongside the real ones.
/// Text has no fixed extension (fully TOML-configurable), so every regular
/// file is attempted — no mandatory auto-detection, the analyst already
/// chose the parser config, so it isn't this function's place to
/// second-guess which files "look like" a match; files that don't actually
/// match end up in [`LoadSummary::skipped`], not silently excluded
/// upfront. Sorted for deterministic load order — same folder + same
/// config must always produce the same result.
fn collect_source_files(source_kind: SourceKind, source_path: &Path) -> Vec<PathBuf> {
    if source_kind == SourceKind::Aul || source_path.is_file() {
        return vec![source_path.to_path_buf()];
    }
    let extension_filter: Option<&str> = match source_kind {
        SourceKind::Evtx => Some("evtx"),
        SourceKind::Journald => Some("journal"),
        SourceKind::Text | SourceKind::Aul => None,
    };
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(source_path)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| match extension_filter {
            Some(ext) => path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case(ext)),
            None => true,
        })
        .collect();
    files.sort();
    files
}

/// Real byte size of `path` — if it's a file, its own size; if it's a
/// directory (AUL's `.logarchive` case), the sum of every file inside it,
/// recursively. `path.metadata().len()` on a directory returns a small,
/// meaningless number (just the directory entry itself, not its contents),
/// so that shortcut can't be used for AUL.
fn path_byte_size(path: &Path) -> u64 {
    if path.is_dir() {
        walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .filter_map(|entry| entry.metadata().ok())
            .map(|metadata| metadata.len())
            .sum()
    } else {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }
}

/// Runs on a background thread so the UI stays responsive — this can mean
/// parsing and inserting millions of rows for a large AUL source, or many
/// files when `source_path` is a recursively-loaded folder. Takes an
/// already-open `conn` (a `TimelineView::try_clone_conn()` clone, made on
/// the UI thread before spawning) rather than opening its own: DuckDB only
/// reliably tolerates one independent `Connection::open` of a file at a
/// time within a process — a second one while the UI's own connection for
/// this session is still alive could lose that race, reliably on Windows.
/// `Connection` itself is `Send` (see `try_clone_conn`'s doc comment), so
/// it can still be handed to background threads directly.
///
/// A file that fails to parse (or parses cleanly but matches nothing)
/// doesn't abort the rest of the folder — it's recorded in
/// [`LoadSummary::skipped`] and the remaining files still get loaded. Only
/// resolving `(parser, config)` (e.g. no parser config selected for Text)
/// or finding zero candidate files at all fails the whole call — those are
/// setup problems, not a single file's problem.
///
/// `thread_count` only matters when [`collect_source_files`] finds more
/// than one file (a folder pick for EVTX/journald/Text) — AUL's
/// `.logarchive` is always exactly one atomic parse unit, and a
/// single-file pick is also always exactly one, so both run
/// [`run_sequential`] regardless of `thread_count`: there's nothing to
/// parallelize across a list of one.
/// Which tagging rules a load/re-tag should apply — user-selected files plus
/// whether the embedded AUL pattern-of-life pack
/// (`tagging::builtin::aul_pattern_of_life_rules`) is also merged in. A
/// struct rather than two more `run_load` parameters, same reasoning as
/// [`LoadContext`] bundling its own fields.
struct RuleSelection<'a> {
    paths: &'a [PathBuf],
    include_builtin_aul: bool,
}

fn run_load(
    source_kind: SourceKind,
    source_path: &Path,
    parser_config_path: Option<&Path>,
    rules: RuleSelection,
    conn: duckdb::Connection,
    thread_count: usize,
    progress_tx: &mpsc::Sender<LoadOutcome>,
) -> anyhow::Result<LoadSummary> {
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
    let rules = load_rules(rules.paths, rules.include_builtin_aul)?;

    let files = collect_source_files(source_kind, source_path);
    if files.is_empty() {
        anyhow::bail!("no matching files found under {}", source_path.display());
    }
    let bytes_total: u64 = files.iter().map(|path| path_byte_size(path)).sum();

    let load_ctx = LoadContext {
        parser,
        config: &config,
        sourcetype: &sourcetype,
        rules: &rules,
        parser_config_path,
    };

    if files.len() <= 1 {
        run_sequential(&load_ctx, files, &conn, bytes_total, progress_tx)
    } else {
        run_parallel(
            &load_ctx,
            files,
            &conn,
            bytes_total,
            thread_count,
            progress_tx,
        )
    }
}

/// Everything about a `run_load` call that's the same for every file it
/// touches — resolved once per call, not per file — bundled together so
/// [`run_sequential`]/[`run_parallel`] take one context argument instead
/// of several. Needs `LogParser: Sync` (see `parsers/mod.rs`) so `&Self`
/// can be shared with [`run_parallel`]'s worker threads.
struct LoadContext<'a> {
    parser: &'a dyn LogParser,
    config: &'a ParserConfig,
    sourcetype: &'a str,
    rules: &'a [Rule],
    parser_config_path: Option<&'a Path>,
}

/// The single-parse-unit path — always used for AUL (its `.logarchive` is
/// one atomic source, never split into multiple files by
/// [`collect_source_files`]) and for a single-file pick of any sourcetype.
/// `files` always has exactly one entry here — `run_load` already bailed
/// on an empty list, and anything with more than one goes through
/// [`run_parallel`] instead.
fn run_sequential(
    ctx: &LoadContext,
    files: Vec<PathBuf>,
    conn: &duckdb::Connection,
    bytes_total: u64,
    progress_tx: &mpsc::Sender<LoadOutcome>,
) -> anyhow::Result<LoadSummary> {
    let mut summary = LoadSummary {
        inserted: 0,
        tags_applied: 0,
        loaded_sources: Vec::new(),
        skipped: Vec::new(),
    };
    let mut total_inserted = 0usize;
    let mut bytes_done = 0u64;

    for file_path in files {
        let file_bytes = path_byte_size(&file_path);
        match load_one_file(
            ctx,
            &file_path,
            conn,
            &mut total_inserted,
            bytes_done,
            bytes_total,
            progress_tx,
        ) {
            Ok(Some((tags_applied, loaded_source))) => {
                summary.tags_applied += tags_applied;
                summary.loaded_sources.push(loaded_source);
            }
            Ok(None) => summary.skipped.push(SkippedFile {
                path: file_path,
                reason: "no matching entries".to_string(),
            }),
            Err(err) => summary.skipped.push(SkippedFile {
                path: file_path,
                reason: format!("{err:#}"),
            }),
        }
        bytes_done += file_bytes;
        let _ = progress_tx.send(LoadOutcome::Progress {
            inserted: total_inserted,
            bytes_done,
            bytes_total,
        });
    }
    summary.inserted = total_inserted;

    Ok(summary)
}

/// Parses one file and, if it produced anything, appends it to
/// `log_entries`/`sources`. `total_inserted` is threaded through by `&mut`
/// rather than returned fresh, so [`LoadOutcome::Progress`] keeps
/// reporting one running total, not a per-file count that resets and
/// confuses "how far along is this." `bytes_done_before`/`bytes_total`
/// are passed straight through into every progress send during this
/// file's parsing — byte progress only advances once a whole file
/// finishes (see [`run_sequential`]/[`run_parallel`]), so it stays flat
/// while this one is in flight; only `inserted` keeps climbing live.
///
/// `Ok(None)` — not an error — when the file parsed cleanly but matched
/// zero entries: still worth a note in the skip report ([`run_load`]), but
/// not a parse failure, so it's kept distinct from `Err`.
fn load_one_file(
    ctx: &LoadContext,
    file_path: &Path,
    conn: &duckdb::Connection,
    total_inserted: &mut usize,
    bytes_done_before: u64,
    bytes_total: u64,
    progress_tx: &mpsc::Sender<LoadOutcome>,
) -> anyhow::Result<Option<(usize, LoadedSource)>> {
    let mut batch: Vec<LogEntry> = Vec::with_capacity(LOAD_BATCH_SIZE);
    let mut inserted_this_file = 0usize;
    let mut tags_applied = 0usize;

    let source_file_id = parse_source_streaming(ctx.parser, file_path, ctx.config, |entry| {
        inserted_this_file += 1;
        *total_inserted += 1;
        batch.push(entry);
        if batch.len() >= LOAD_BATCH_SIZE {
            tags_applied += flush_batch(conn, &mut batch, ctx.rules, ctx.sourcetype)?;
            // Best-effort: if the UI thread has already dropped its
            // receiver (e.g. app shutting down mid-load), there's nobody
            // to tell and the load itself must still proceed.
            let _ = progress_tx.send(LoadOutcome::Progress {
                inserted: *total_inserted,
                bytes_done: bytes_done_before,
                bytes_total,
            });
        }
        Ok(())
    })?;
    tags_applied += flush_batch(conn, &mut batch, ctx.rules, ctx.sourcetype)?;

    if inserted_this_file == 0 {
        return Ok(None);
    }
    insert_source_record(conn, source_file_id, file_path, ctx.sourcetype)?;

    let loaded_source = LoadedSource {
        path: file_path.display().to_string(),
        sourcetype: ctx.sourcetype.to_string(),
        parser_config_path: ctx.parser_config_path.map(|p| p.display().to_string()),
    };
    Ok(Some((tags_applied, loaded_source)))
}

/// One worker's report back to [`run_parallel`]'s writer loop.
enum ParseEvent {
    /// Up to [`LOAD_BATCH_SIZE`] entries from one file, ready to flush —
    /// same batching cadence as [`load_one_file`]'s single-threaded
    /// version. Each `LogEntry` already carries its own
    /// `event_id.source_file_id` (assigned once per file by
    /// `parse_source_streaming`), so batches don't need to carry it
    /// separately.
    Batch { entries: Vec<LogEntry> },
    /// A file finished parsing. `source_file_id` is `None` if it parsed
    /// cleanly but matched zero entries — mirrors [`load_one_file`]'s
    /// `Ok(None)`, not a failure.
    FileDone {
        file_path: PathBuf,
        bytes: u64,
        source_file_id: Option<SourceFileId>,
    },
    FileFailed {
        file_path: PathBuf,
        bytes: u64,
        reason: String,
    },
}

/// The multi-file path — only reached when [`collect_source_files`] finds
/// more than one file (a folder pick for EVTX/journald/Text; AUL and
/// single-file picks always go through [`run_sequential`] instead, see
/// `run_load`). Parses files across up to `thread_count` worker threads,
/// but every DuckDB write still happens on this thread, through the one
/// `conn` — DuckDB's `Appender` is built for fast single-writer sequential
/// bulk loads, and concurrent writers from multiple connections would
/// contend rather than actually speed up the write step, so only the
/// CPU-bound parsing work is fanned out.
///
/// `std::thread::scope` (not a detached `thread::spawn`) so `ctx`/`conn`
/// — borrowed, non-`'static` — can be shared with the worker threads
/// directly, and so this function doesn't return until every worker has
/// actually finished. Each worker streams its file through the same
/// `parse_source_streaming` [`load_one_file`] uses, bounding memory to
/// `LOAD_BATCH_SIZE` per *worker* — with `thread_count` workers now
/// running at once, that matters even more than in the single-threaded
/// case: buffering a whole file per worker would multiply the exact RSS
/// blowup streaming was built to avoid in the first place.
///
/// Result ordering: worker completion order is a race, so
/// `loaded_sources`/`skipped` are sorted by path before returning —
/// same input must always produce the same *result*, even if the
/// parsing happened in a different order this run.
fn run_parallel(
    ctx: &LoadContext,
    files: Vec<PathBuf>,
    conn: &duckdb::Connection,
    bytes_total: u64,
    thread_count: usize,
    progress_tx: &mpsc::Sender<LoadOutcome>,
) -> anyhow::Result<LoadSummary> {
    let thread_count = thread_count.min(files.len()).max(1);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .context("failed to create the parse thread pool")?;

    let mut summary = LoadSummary {
        inserted: 0,
        tags_applied: 0,
        loaded_sources: Vec::new(),
        skipped: Vec::new(),
    };
    let mut total_inserted = 0usize;
    let mut bytes_done = 0u64;
    let mut write_error = None;

    // Bounded, not `mpsc::channel`'s unbounded default: with `thread_count`
    // workers producing `LOAD_BATCH_SIZE`-entry batches purely CPU-bound
    // (fast) and one writer thread consuming them via a DuckDB append plus
    // import-time tagging (slower — real I/O, not just memory copies), an
    // unbounded channel lets production outrun consumption without limit.
    // That's exactly how this OOM'd in practice: nothing capped how many
    // whole batches could pile up in the channel while the writer fell
    // behind. `sync_channel`'s bounded capacity makes `send` block once
    // full, so a fast worker pauses instead of continuing to buffer —
    // real backpressure, not just a smaller unbounded buffer. Capacity is
    // a small multiple of the worker count: enough that a worker isn't
    // stalled waiting on every single batch, not so much that a big
    // backlog can still accumulate.
    let (tx, rx) = mpsc::sync_channel::<ParseEvent>(thread_count * 2);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            pool.install(|| {
                files.into_par_iter().for_each_with(tx, |tx, file_path| {
                    parse_file_for_worker(ctx, &file_path, tx);
                });
            });
        });

        for event in rx {
            match event {
                ParseEvent::Batch { entries } => {
                    total_inserted += entries.len();
                    let mut entries = entries;
                    match flush_batch(conn, &mut entries, ctx.rules, ctx.sourcetype) {
                        Ok(applied) => summary.tags_applied += applied,
                        Err(err) => {
                            write_error = Some(err);
                            break;
                        }
                    }
                }
                ParseEvent::FileDone {
                    file_path,
                    bytes,
                    source_file_id,
                } => {
                    bytes_done += bytes;
                    match source_file_id {
                        Some(id) => {
                            if let Err(err) =
                                insert_source_record(conn, id, &file_path, ctx.sourcetype)
                            {
                                write_error = Some(err);
                                break;
                            }
                            summary.loaded_sources.push(LoadedSource {
                                path: file_path.display().to_string(),
                                sourcetype: ctx.sourcetype.to_string(),
                                parser_config_path: ctx
                                    .parser_config_path
                                    .map(|p| p.display().to_string()),
                            });
                        }
                        None => summary.skipped.push(SkippedFile {
                            path: file_path,
                            reason: "no matching entries".to_string(),
                        }),
                    }
                }
                ParseEvent::FileFailed {
                    file_path,
                    bytes,
                    reason,
                } => {
                    bytes_done += bytes;
                    summary.skipped.push(SkippedFile {
                        path: file_path,
                        reason,
                    });
                }
            }
            let _ = progress_tx.send(LoadOutcome::Progress {
                inserted: total_inserted,
                bytes_done,
                bytes_total,
            });
        }
    });

    if let Some(err) = write_error {
        return Err(err);
    }
    summary.inserted = total_inserted;
    summary.loaded_sources.sort_by(|a, b| a.path.cmp(&b.path));
    summary.skipped.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(summary)
}

/// Runs on a rayon worker thread — parses one file fully (streamed in
/// `LOAD_BATCH_SIZE` chunks, never held whole in memory) and reports
/// results back to [`run_parallel`]'s writer loop. Errors from `tx.send`
/// are ignored (best-effort, same reasoning as [`load_one_file`]'s
/// progress sends): if the writer already stopped listening (e.g. a
/// DB-level error elsewhere aborted the load), there's nobody left to
/// tell, and this worker's own work is already sunk cost at that point.
fn parse_file_for_worker(ctx: &LoadContext, file_path: &Path, tx: &mpsc::SyncSender<ParseEvent>) {
    let bytes = path_byte_size(file_path);
    let mut batch: Vec<LogEntry> = Vec::with_capacity(LOAD_BATCH_SIZE);
    let mut inserted = 0usize;

    let result = parse_source_streaming(ctx.parser, file_path, ctx.config, |entry| {
        inserted += 1;
        batch.push(entry);
        if batch.len() >= LOAD_BATCH_SIZE {
            let full_batch = std::mem::replace(&mut batch, Vec::with_capacity(LOAD_BATCH_SIZE));
            let _ = tx.send(ParseEvent::Batch {
                entries: full_batch,
            });
        }
        Ok(())
    });

    match result {
        Ok(source_file_id) => {
            if !batch.is_empty() {
                let _ = tx.send(ParseEvent::Batch { entries: batch });
            }
            let source_file_id = (inserted > 0).then_some(source_file_id);
            let _ = tx.send(ParseEvent::FileDone {
                file_path: file_path.to_path_buf(),
                bytes,
                source_file_id,
            });
        }
        Err(err) => {
            let _ = tx.send(ParseEvent::FileFailed {
                file_path: file_path.to_path_buf(),
                bytes,
                reason: format!("{err:#}"),
            });
        }
    }
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
/// table, so it deserves the same "don't freeze the UI" treatment. Takes
/// an already-open `conn`, same reasoning as `run_load`.
fn run_retag(
    rule_paths: &[PathBuf],
    include_builtin_aul_rules: bool,
    conn: duckdb::Connection,
) -> anyhow::Result<usize> {
    let rules = load_rules(rule_paths, include_builtin_aul_rules)?;
    re_tag(&conn, &rules)
}

/// `include_builtin_aul_rules` appends the embedded AUL pattern-of-life
/// pack (`tagging::builtin::aul_pattern_of_life_rules`) after the
/// user-selected file-based rules — order doesn't affect tagging (every
/// matching rule applies independently, see `tagging::engine`), it's just
/// where they land in `import_tags`. Every embedded rule already scopes
/// itself to `sourcetype = "aul"`, so merging it in unconditionally (not
/// just when the *current* load/retag's sourcetype happens to be AUL) is
/// safe — it simply never matches non-AUL rows, including during a retag
/// of a session that also has EVTX/journald/Text data alongside AUL.
fn load_rules(
    rule_paths: &[PathBuf],
    include_builtin_aul_rules: bool,
) -> anyhow::Result<Vec<Rule>> {
    let mut rules: Vec<Rule> = rule_paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read rule file {}", path.display()))?;
            Rule::from_toml_str(&text)
                .with_context(|| format!("invalid rule file {}", path.display()))
        })
        .collect::<anyhow::Result<Vec<Rule>>>()?;
    if include_builtin_aul_rules {
        rules.extend(crate::tagging::builtin::aul_pattern_of_life_rules());
    }
    Ok(rules)
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
    let window_title = format!("Peach {}", about_dialog::display_version());
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title(&window_title),
        ..Default::default()
    };
    eframe::run_native(
        &window_title,
        native_options,
        Box::new(move |cc| {
            let app = PeachApp::new(add_sources, cleanup_dirs);
            theme::apply(&cc.egui_ctx, app.settings.theme);
            Ok(Box::new(app))
        }),
    )
    .map_err(|err| anyhow::anyhow!("failed to run peach GUI: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_rules_with_no_files_and_no_builtin_pack_is_empty() {
        let rules = load_rules(&[], false).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn load_rules_merges_the_builtin_aul_pack_with_no_files_selected() {
        let rules = load_rules(&[], true).unwrap();
        assert!(rules.len() >= 33);
        assert!(rules.iter().any(|r| r.rule.tag.value == "wifi_status"));
    }

    #[test]
    fn load_rules_merges_the_builtin_aul_pack_alongside_file_based_rules() {
        let dir = temp_test_dir("load-rules-merge");
        let rule_path = dir.join("custom.toml");
        std::fs::write(
            &rule_path,
            "[rule]\nname = \"custom\"\n[rule.match]\nmessage_contains = \"x\"\n[rule.tag]\nvalue = \"custom_tag\"\n",
        )
        .unwrap();

        let rules = load_rules(std::slice::from_ref(&rule_path), true).unwrap();

        assert!(rules.iter().any(|r| r.rule.tag.value == "custom_tag"));
        assert!(rules.iter().any(|r| r.rule.tag.value == "wifi_status"));
        std::fs::remove_dir_all(dir).unwrap();
    }

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

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "peach-app-test-{}-{}-{name}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn collect_source_files_returns_the_folder_itself_for_aul_even_though_its_a_directory() {
        let dir = temp_test_dir("aul-folder");
        std::fs::write(dir.join("not-an-aul-file.txt"), b"x").unwrap();

        let files = collect_source_files(SourceKind::Aul, &dir);

        assert_eq!(files, vec![dir.clone()]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn collect_source_files_returns_a_single_file_unchanged_for_any_sourcetype() {
        let dir = temp_test_dir("single-file");
        let file = dir.join("source.evtx");
        std::fs::write(&file, b"x").unwrap();

        let files = collect_source_files(SourceKind::Evtx, &file);

        assert_eq!(files, vec![file]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn collect_source_files_recurses_and_filters_by_extension_for_evtx() {
        let dir = temp_test_dir("evtx-folder");
        let sub = dir.join("nested");
        std::fs::create_dir_all(&sub).unwrap();
        let matching_top = dir.join("a.evtx");
        let matching_nested = sub.join("b.EVTX"); // case-insensitive
        let unrelated = dir.join("readme.txt");
        std::fs::write(&matching_top, b"x").unwrap();
        std::fs::write(&matching_nested, b"x").unwrap();
        std::fs::write(&unrelated, b"x").unwrap();

        let mut files = collect_source_files(SourceKind::Evtx, &dir);
        files.sort();
        let mut expected = vec![matching_top, matching_nested];
        expected.sort();

        assert_eq!(files, expected);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn collect_source_files_recurses_and_filters_by_extension_for_journald() {
        let dir = temp_test_dir("journald-folder");
        let matching = dir.join("system.journal");
        let unrelated = dir.join("system.journal.tmp");
        std::fs::write(&matching, b"x").unwrap();
        std::fs::write(&unrelated, b"x").unwrap();

        let files = collect_source_files(SourceKind::Journald, &dir);

        assert_eq!(files, vec![matching]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn collect_source_files_returns_every_file_unfiltered_for_text() {
        let dir = temp_test_dir("text-folder");
        let a = dir.join("a.log");
        let b = dir.join("b.bin");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();

        let mut files = collect_source_files(SourceKind::Text, &dir);
        files.sort();
        let mut expected = vec![a, b];
        expected.sort();

        assert_eq!(files, expected);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn collect_source_files_results_are_sorted() {
        let dir = temp_test_dir("sorted-folder");
        std::fs::write(dir.join("z.evtx"), b"x").unwrap();
        std::fs::write(dir.join("a.evtx"), b"x").unwrap();
        std::fs::write(dir.join("m.evtx"), b"x").unwrap();

        let files = collect_source_files(SourceKind::Evtx, &dir);
        let mut sorted = files.clone();
        sorted.sort();

        assert_eq!(files, sorted);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn text_parser_config() -> String {
        "[parser]\nname = \"test\"\nsourcetype = \"test\"\n\
         [parser.pattern]\n\
         regex = '^(?P<timestamp>\\S+) (?P<level_raw>\\w+) (?P<msg>.*)$'\n\
         timestamp_format = \"%Y-%m-%dT%H:%M:%S%z\"\n\
         [parser.field_mapping]\n\
         level = \"level_raw\"\n\
         message = \"msg\"\n"
            .to_string()
    }

    /// Regression test for the recursive folder-load feature: a folder with
    /// two well-formed log files and one file whose content never matches
    /// `pattern.regex` at all (so `TextConfigParser::parse` returns `Err`
    /// for it, not an empty result) — the two good files must still load
    /// fully and the bad one must land in `skipped` with its reason,
    /// without aborting the other two.
    #[test]
    fn run_load_recurses_a_folder_loading_good_files_and_skipping_a_bad_one() {
        // The parser config lives *outside* the folder being loaded — Text
        // has no extension filter (per `collect_source_files`), so a config
        // file sitting inside the loaded folder would itself become a
        // (failing) load candidate and muddy this test's assertions.
        let base = temp_test_dir("run-load-base");
        let logs_dir = base.join("logs");
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::write(
            logs_dir.join("a.log"),
            "2026-07-28T12:00:00+0200 ERROR something broke\n",
        )
        .unwrap();
        std::fs::write(
            logs_dir.join("b.log"),
            "2026-07-28T12:05:00+0200 INFO all fine\n2026-07-28T12:06:00+0200 WARN careful\n",
        )
        .unwrap();
        std::fs::write(
            logs_dir.join("c-bad.log"),
            "this line matches nothing at all\n",
        )
        .unwrap();

        let config_path = base.join("config.toml");
        std::fs::write(&config_path, text_parser_config()).unwrap();

        let db_path = base.join("test.duckdb");
        let conn = duckdb::Connection::open(&db_path).unwrap();
        let (tx, _rx) = mpsc::channel();

        let summary = run_load(
            SourceKind::Text,
            &logs_dir,
            Some(&config_path),
            RuleSelection {
                paths: &[],
                include_builtin_aul: false,
            },
            conn,
            2, // 3 files > 1, so this exercises run_parallel
            &tx,
        )
        .unwrap();

        assert_eq!(summary.inserted, 3); // 1 from a.log + 2 from b.log
        assert_eq!(summary.loaded_sources.len(), 2); // a.log, b.log
        assert_eq!(summary.skipped.len(), 1); // c-bad.log
        let bad_entry = &summary.skipped[0];
        assert_eq!(bad_entry.path.file_name().unwrap(), "c-bad.log");
        assert!(
            bad_entry.reason.contains("does not match"),
            "unexpected skip reason: {}",
            bad_entry.reason
        );

        std::fs::remove_dir_all(base).unwrap();
    }

    /// A single-file pick always has exactly one entry in
    /// `collect_source_files`, so `run_load` must take the `run_sequential`
    /// path, not `run_parallel` — this pins that down directly (as opposed
    /// to the folder test above, which by construction only ever exercises
    /// the parallel path once there's more than one file).
    #[test]
    fn run_load_with_a_single_file_uses_the_sequential_path() {
        let base = temp_test_dir("run-load-single-file");
        let log_path = base.join("only.log");
        std::fs::write(
            &log_path,
            "2026-07-28T12:00:00+0200 ERROR something broke\n",
        )
        .unwrap();
        let config_path = base.join("config.toml");
        std::fs::write(&config_path, text_parser_config()).unwrap();

        let db_path = base.join("test.duckdb");
        let conn = duckdb::Connection::open(&db_path).unwrap();
        let (tx, _rx) = mpsc::channel();

        let summary = run_load(
            SourceKind::Text,
            &log_path,
            Some(&config_path),
            RuleSelection {
                paths: &[],
                include_builtin_aul: false,
            },
            conn,
            4, // irrelevant with a single file — must still behave correctly
            &tx,
        )
        .unwrap();

        assert_eq!(summary.inserted, 1);
        assert_eq!(summary.loaded_sources.len(), 1);
        assert_eq!(
            summary.loaded_sources[0].path,
            log_path.display().to_string()
        );
        assert!(summary.skipped.is_empty());

        std::fs::remove_dir_all(base).unwrap();
    }

    /// Same folder-load scenario as
    /// `run_load_recurses_a_folder_loading_good_files_and_skipping_a_bad_one`,
    /// but run twice with different `thread_count`s — the aggregate result
    /// must be identical regardless of how many worker threads did the
    /// parsing, only the completion order (invisible here, since results
    /// are sorted before returning) can differ.
    #[test]
    fn run_load_produces_the_same_result_regardless_of_thread_count() {
        let base = temp_test_dir("run-load-thread-counts");
        let logs_dir = base.join("logs");
        std::fs::create_dir_all(&logs_dir).unwrap();
        for (name, content) in [
            ("a.log", "2026-07-28T12:00:00+0200 ERROR one\n"),
            ("b.log", "2026-07-28T12:01:00+0200 ERROR two\n"),
            ("c.log", "2026-07-28T12:02:00+0200 ERROR three\n"),
            ("d.log", "2026-07-28T12:03:00+0200 ERROR four\n"),
        ] {
            std::fs::write(logs_dir.join(name), content).unwrap();
        }
        let config_path = base.join("config.toml");
        std::fs::write(&config_path, text_parser_config()).unwrap();

        let mut results = Vec::new();
        for thread_count in [1usize, 4] {
            let db_path = base.join(format!("test-{thread_count}.duckdb"));
            let conn = duckdb::Connection::open(&db_path).unwrap();
            let (tx, _rx) = mpsc::channel();
            let summary = run_load(
                SourceKind::Text,
                &logs_dir,
                Some(&config_path),
                RuleSelection {
                    paths: &[],
                    include_builtin_aul: false,
                },
                conn,
                thread_count,
                &tx,
            )
            .unwrap();
            let paths: Vec<String> = summary
                .loaded_sources
                .iter()
                .map(|s| s.path.clone())
                .collect();
            results.push((summary.inserted, summary.skipped.len(), paths));
        }

        assert_eq!(results[0], results[1]);
        assert_eq!(results[0].0, 4);

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn path_byte_size_sums_a_directorys_files_recursively() {
        let dir = temp_test_dir("byte-size-dir");
        std::fs::write(dir.join("a"), vec![0u8; 100]).unwrap();
        let nested = dir.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("b"), vec![0u8; 50]).unwrap();

        assert_eq!(path_byte_size(&dir), 150);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn path_byte_size_of_a_plain_file_is_its_own_size() {
        let dir = temp_test_dir("byte-size-file");
        let file = dir.join("only.log");
        std::fs::write(&file, vec![0u8; 42]).unwrap();

        assert_eq!(path_byte_size(&file), 42);

        std::fs::remove_dir_all(dir).unwrap();
    }
}
