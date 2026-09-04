use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use anyhow::Context;
use eframe::egui;
use rayon::prelude::*;

use crate::config::{self, Settings, Theme};
use crate::db::timeline_queries::{self, Connector, Field, Query, Term, TermKind};
use crate::db::timeline_schema::setup_timeline_schema;
use crate::export::{self, ExportOutcome};
use crate::model::event_id::{EventId, SourceFileId};
use crate::model::log_entry::LogEntry;
use crate::model::timezone_spec::TimezoneSpec;
use crate::parsers::aul::AulParser;
use crate::parsers::evtx::EvtxFileParser;
use crate::parsers::intrusion_log::IntrusionLogParser;
use crate::parsers::journald::JournaldFileParser;
use crate::parsers::text_config::TextConfigParser;
use crate::parsers::text_config_file::{self, TextFormatDraft};
use crate::parsers::{LogParser, ParserConfig, StreamingProgress, parse_source_streaming};
use crate::session::persist::{self, LoadedSource, SessionPaths};
use crate::session::portable_case::{
    self, PortableCaseExportOutcome, PortableCaseExportStage, PortableCaseExportSummary,
    PortableCaseImportOutcome, PortableCaseImportStage,
};
use crate::tagging::engine::{RetagSummary, apply_import_time, re_tag};
use crate::tagging::rule::Rule;
use crate::tagging::rule_file;
use crate::ui::about_dialog::{self, AboutDialog};
use crate::ui::activity_log_dialog::ActivityLogDialog;
use crate::ui::builtin_rules_dialog::BuiltinRulesDialog;
use crate::ui::case_summary_dialog::{CaseSummaryDialog, CaseSummaryDialogOutcome};
use crate::ui::display_timezone_dialog::DisplayTimezoneDialog;
use crate::ui::filter_bar::FilterBar;
use crate::ui::format_dialog::{FormatDialog, FormatDialogOutcome};
use crate::ui::note_dialog::{NoteDialog, NoteDialogOutcome};
use crate::ui::raw_fields_dialog::RawFieldsDialog;
use crate::ui::rule_pack_dialog::{RulePackDialog, RulePackDialogOutcome};
use crate::ui::rules_reference_dialog::RulesReferenceDialog;
use crate::ui::session_dialog::{self, SessionManagerDialog, SessionManagerOutcome};
use crate::ui::settings_dialog::{self, SettingsDialog, SettingsOutcome};
use crate::ui::tag_dialog::{PreviewTarget, TagDialog, TagDialogOutcome};
use crate::ui::theme;
use crate::ui::timeline_view::{RowAction, TimelineView, source_display_label};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Aul,
    Evtx,
    Journald,
    Text,
    IntrusionLog,
}

/// What a background-spawned native file/folder dialog resolved to, sent
/// back over [`PeachApp::file_pick_rx`] once the analyst closes it.
///
/// `rfd::FileDialog`'s synchronous `pick_*` methods block the calling
/// thread until the dialog closes — called directly from `ui()` (the only
/// place they used to be called from), that's the UI thread, so the whole
/// window stops repainting and the OS reports it as "not responding" the
/// moment the native dialog loses focus. `rfd::AsyncFileDialog` fixes this,
/// but its `Future` still has to be *created* on the main thread (native
/// dialog setup needs it, most strictly on macOS) — only *awaiting* it can
/// happen elsewhere. So each picker below creates the dialog inline in
/// `ui()`, then hands the resulting `Future` to a spawned thread that
/// blocks on it (via `pollster`, the same minimal blocking-executor
/// approach rfd's own docs use) and reports back through this channel —
/// same `mpsc` request/poll shape as [`LoadOutcome`]/[`RetagOutcome`].
///
/// One shared enum/receiver for every picker rather than one per button:
/// only one native dialog can sensibly be open at a time anyway (see
/// `PeachApp::file_pick_rx`'s doc comment), and `SourcePaths` alone already
/// covers four different buttons (AUL folder, one-or-several EVTX/journald/
/// text files, or a folder of them) — they all just feed the same
/// `source_path`/`pending_cli_sources` pair on success (see
/// `PeachApp::ui`'s handler for how a multi-file pick fans out across the
/// two).
///
/// No `SessionFile` variant: switching sessions goes exclusively through
/// "Manage sessions...", not a raw filesystem picker — see that button's
/// doc comment for why a native file dialog stopped being a good fit for
/// this once sessions could have a display name.
enum FilePickOutcome {
    /// *Should* always be at least one path when `Some` — every producing
    /// site is either a single-path `pick_file`/`pick_folder` result mapped
    /// into a one-element `Vec`, or `pick_files`, which is documented to
    /// never resolve to `Some(vec![])`. Not actually relied on, though: on
    /// Linux, closing the native picker via the window's own X button
    /// (rather than an explicit Cancel) has been observed to come back as
    /// `Some(vec![])` instead of `None` — an `xdg-desktop-portal`/`rfd`
    /// quirk, not something fixable here — so the handler
    /// ([`PeachApp::ui`]'s `SourcePaths(Some(picked))` arm, via
    /// [`source_path_and_queue_from_pick`]) treats an empty `Vec` the same
    /// as a cancelled dialog rather than indexing into it. Indexing `[0]`
    /// unconditionally used to panic with an index-out-of-bounds on exactly
    /// that interaction.
    SourcePaths(Option<Vec<PathBuf>>),
    ParserConfigFile(Option<PathBuf>),
    RuleFiles(Option<Vec<PathBuf>>),
    ExportTarget(Option<PathBuf>),
    /// Save-dialog target for "Export portable case..." — single-path, like
    /// `ExportTarget`, so the Linux X-close-returns-`Some(vec![])` quirk
    /// documented on `SourcePaths` doesn't apply here.
    PortableCaseExportTarget(Option<PathBuf>),
    /// Open-dialog source for "Import portable case..." — same reasoning.
    PortableCaseImportSource(Option<PathBuf>),
    /// Open-dialog source for "Rule packs..."'s "Browse..." button — the
    /// works-everywhere fallback for picking a `peach-rules-vN.zip`
    /// bundle, since drag-and-drop doesn't work on Wayland (see
    /// `ui::rule_pack_dialog`'s module doc). Same single-path reasoning as
    /// `PortableCaseImportSource`.
    RulePackBundle(Option<PathBuf>),
}

/// Spawns a thread that blocks on `task` (an already-created
/// `rfd::AsyncFileDialog` future) and sends its result, converted to a
/// [`FilePickOutcome`] by `to_outcome`, back over the returned channel.
/// `to_outcome` is where the `FileHandle` -> `PathBuf` conversion happens,
/// so this stays generic over both the single-pick (`Option<FileHandle>`)
/// and multi-pick (`Option<Vec<FileHandle>>`) shapes every `pick_*` method
/// returns.
fn spawn_dialog_pick<T, F>(
    task: impl std::future::Future<Output = Option<T>> + Send + 'static,
    to_outcome: F,
) -> mpsc::Receiver<FilePickOutcome>
where
    T: Send + 'static,
    F: FnOnce(Option<T>) -> FilePickOutcome + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let picked = pollster::block_on(task);
        let _ = tx.send(to_outcome(picked));
    });
    rx
}

enum LoadOutcome {
    /// Sent every [`LOAD_BATCH_SIZE`] entries, and whenever a file
    /// finishes, during a load — running totals across every file when
    /// the source is a folder (never reset mid-load). `inserted` isn't
    /// generally a fraction of a known total: a source's total *entry*
    /// count generally isn't knowable without a full parse pass, which
    /// would mean parsing twice (against the streaming design `run_load`'s
    /// doc comment explains) just to show an ETA. `bytes_done`/
    /// `bytes_total` fill that gap with a real, data-based fraction
    /// instead — known upfront from file sizes, at file-level granularity
    /// (jumps per completed file, not smoothly within one — see
    /// `run_load`).
    ///
    /// `total_entries` is the one exception: `Some` only for AUL, and only
    /// once its own parsing phase has finished (see
    /// `AulParser::parse_streaming`'s doc comment on why that's the one
    /// point its total is knowable at all) — from then on `inserted` *is*
    /// a fraction of `total_entries`, covering exactly the phase
    /// (DB insert + tagging) that the byte-progress bar can't: it's
    /// already at 100% by the time parsing hands off to this phase, so
    /// without this field that phase — often the larger share of total
    /// load time — would show only a raw climbing count with no sense of
    /// how much is left. `None` for every other sourcetype, and for AUL
    /// itself before parsing finishes.
    Progress {
        inserted: usize,
        bytes_done: u64,
        bytes_total: u64,
        total_entries: Option<usize>,
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
    /// Entries inserted per successfully-loaded file, keyed by
    /// `LoadedSource::path` — the Activity Log's "how many events came from
    /// file X" breakdown for a multi-file load (a folder pick, or several
    /// files chosen at once). Filled in by `run_sequential`/`run_parallel`
    /// as each file finishes; `run_load` doesn't need to touch it.
    per_file_inserted: std::collections::BTreeMap<String, usize>,
    /// How many records were skipped (under "skip bad records" mode)
    /// per successfully-loaded file — mirrors `per_file_inserted`'s own
    /// path-keyed shape, filled in the same way. A file absent here (but
    /// present in `per_file_inserted`) skipped nothing.
    per_file_records_skipped: std::collections::BTreeMap<String, usize>,
    /// Sum of `per_file_records_skipped`'s values — this load's total
    /// records skipped, across every file.
    records_skipped: usize,
    /// `import_tags` counts for *this load's* files only, grouped by
    /// `rule_name` — filled in by `run_load` itself (a single follow-up
    /// query after `run_sequential`/`run_parallel` returns, scoped to
    /// `loaded_sources`' `source_file_id`s) rather than threaded through
    /// the per-file tagging calls, since `import_tags` already has
    /// everything needed and this avoids touching the hot per-entry
    /// tagging loop in `tagging::engine::apply_import_time`.
    tags_by_rule: HashMap<String, usize>,
    /// Set when the analyst clicked "Abort" mid-load (`LoadContext::cancel`)
    /// — everything else in this summary is still exactly what it would be
    /// for a normal completed load (real inserted/tagged counts, real
    /// `sources` rows), just fewer files/entries than a full run would have
    /// produced. Never set by a genuine parse error — that still surfaces
    /// as an `Err` from `run_load`, same as before.
    cancelled: bool,
}

/// Sentinel returned from [`load_one_file`]'s/[`parse_file_for_worker`]'s
/// streaming sink when `LoadContext::cancel` is set mid-file, so the
/// `anyhow::Error` it propagates through `parse_source_streaming`'s `?` can
/// be told apart from a genuine parse failure (`Error::is::<LoadCancelled>()`)
/// — an aborted load must not be recorded (Activity Log, `LoadState`) as
/// "failed", and the file it fired in must still be treated as a (smaller
/// than usual) success, not skipped.
#[derive(Debug)]
struct LoadCancelled;

impl std::fmt::Display for LoadCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "load cancelled by analyst")
    }
}

impl std::error::Error for LoadCancelled {}

enum LoadState {
    Idle,
    Loading {
        inserted_so_far: usize,
        bytes_done: u64,
        bytes_total: u64,
        /// See [`LoadOutcome::Progress`]'s doc comment.
        total_entries: Option<usize>,
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
        /// Records skipped instead of aborting their file, under "skip bad
        /// records" mode — `0` when that checkbox was off (the common
        /// case), regardless of whether anything would have been skippable.
        records_skipped: usize,
        /// Set when the analyst clicked "Abort" mid-load — `inserted`/
        /// `tags_applied`/`skipped` above are still exactly what actually
        /// happened, just less of it than a full run would have produced.
        cancelled: bool,
    },
    Failed(String),
}

enum RetagOutcome {
    Done(Result<RetagSummary, String>),
}

enum RetagState {
    Idle,
    Running,
    Done {
        applied: usize,
        tags_by_rule: HashMap<String, usize>,
    },
    Failed(String),
}

enum ExportState {
    Idle,
    Running { rows_written: usize, path: PathBuf },
    Done { rows_written: usize, path: PathBuf },
    Failed(String),
}

enum PortableCaseExportState {
    Idle,
    Running {
        stage: PortableCaseExportStage,
        path: PathBuf,
    },
    Done {
        summary: PortableCaseExportSummary,
        path: PathBuf,
    },
    Failed(String),
}

enum PortableCaseImportState {
    Idle,
    Running(PortableCaseImportStage),
    Done { display_name: Option<String> },
    Failed(String),
}

pub struct PeachApp {
    db_path: PathBuf,
    session_paths: SessionPaths,
    /// The current session's analyst-chosen label (`session_state`'s
    /// `display_name`), if one was ever set — shown instead of
    /// `session_paths.id` in the controls panel. Loaded fresh whenever
    /// `session_paths` changes (`new`, `load_session`) and refreshed after
    /// a rename via the "Manage sessions" dialog (see
    /// `handle_session_dialog`).
    session_display_name: Option<String>,
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
    /// "Skip bad records instead of failing" — per-load, off by default
    /// (see `LoadSettings::skip_bad_records`'s doc comment). A plain
    /// checkbox next to "Load", not persisted across loads or sessions:
    /// each load is its own explicit choice.
    skip_bad_records: bool,
    rule_paths: Vec<PathBuf>,
    /// Which built-in rules (from either the AUL or EVTX pack, keyed by
    /// `rule.name`) are applied alongside `rule_paths` on every load/re-tag
    /// — every rule from both `tagging::builtin::aul_pattern_of_life_rules`/
    /// `evtx_security_auditing_rules` by default (the analyst can still see
    /// and narrow this via the "Built-in rules..." dialog
    /// (`ui::builtin_rules_dialog`), it just isn't opt-in by default, since
    /// pattern-of-life/Security-Auditing categorization is the normal
    /// workflow for those sourcetypes, not an advanced feature). A rule
    /// name absent here is simply not applied — no separate "disabled"
    /// list, and no per-pack on/off flag: individual rule selection
    /// subsumes "the whole pack" (select-all in the dialog) without a
    /// second mechanism to keep in sync.
    enabled_builtin_rules: std::collections::BTreeSet<String>,
    /// The still-open native file/folder dialog, if any — see
    /// [`FilePickOutcome`] for the full reasoning. Every picker button
    /// shares this one field rather than getting its own: the OS only ever
    /// shows one native dialog at a time regardless, so tracking more than
    /// one in-flight here would just be state that can never legitimately
    /// hold more than one value.
    file_pick_rx: Option<mpsc::Receiver<FilePickOutcome>>,
    load_state: LoadState,
    load_rx: Option<mpsc::Receiver<LoadOutcome>>,
    /// Set (fresh, to `false`) at the start of every `start_load`, cleared
    /// back to `None` once that load's `LoadOutcome::Done` is handled —
    /// `Some` exactly when the "Abort" button should be shown/enabled. The
    /// "Abort" click just flips this to `true`; the background load thread
    /// (via `LoadContext::cancel`, the same `Arc`) is what actually notices
    /// and winds down.
    load_cancel: Option<Arc<AtomicBool>>,
    retag_state: RetagState,
    retag_rx: Option<mpsc::Receiver<RetagOutcome>>,
    export_state: ExportState,
    export_rx: Option<mpsc::Receiver<ExportOutcome>>,
    portable_case_export_state: PortableCaseExportState,
    portable_case_export_rx: Option<mpsc::Receiver<PortableCaseExportOutcome>>,
    portable_case_import_state: PortableCaseImportState,
    portable_case_import_rx: Option<mpsc::Receiver<PortableCaseImportOutcome>>,
    timeline: TimelineView,
    filter_bar: FilterBar,
    available_levels: Vec<(String, String)>,
    available_tags: Vec<String>,
    /// Whole-loaded-timeline event counts shown next to each value in the
    /// Level/Tag/Sources dropdowns (`ui::filter_bar`) — a snapshot,
    /// refreshed at the same points `available_levels`/`available_tags`
    /// already are, not a live count of what the current filter matches.
    /// See `TimelineView::tag_counts`'s doc comment.
    level_counts: HashMap<String, usize>,
    tag_counts: HashMap<String, usize>,
    source_counts: HashMap<String, usize>,
    pending_cli_sources: VecDeque<PathBuf>,
    cleanup_dirs: Vec<PathBuf>,
    /// Set by `--ephemeral-session` (`PeachApp::new`) — this run's session
    /// lives in a one-off temp directory instead of the persistent sessions
    /// directory, and `on_exit` removes that whole directory unconditionally
    /// (not just when empty, unlike the normal `delete_if_empty` sweep) so
    /// no unencrypted session copy survives the run.
    ephemeral_session_dir: Option<PathBuf>,
    tag_dialog: TagDialog,
    note_dialog: NoteDialog,
    format_dialog: FormatDialog,
    raw_fields_dialog: RawFieldsDialog,
    session_dialog: SessionManagerDialog,
    settings: Settings,
    settings_dialog: SettingsDialog,
    about_dialog: AboutDialog,
    activity_log_dialog: ActivityLogDialog,
    case_summary_dialog: CaseSummaryDialog,
    builtin_rules_dialog: BuiltinRulesDialog,
    rules_reference_dialog: RulesReferenceDialog,
    rule_pack_dialog: RulePackDialog,
    /// Wall-clock anchor for the `Theme::Rainbow` animation — see
    /// `theme::tick`'s doc comment for why it's elapsed-time-based rather
    /// than a per-frame step.
    rainbow_start: Option<std::time::Instant>,
    tag_preview_rx: Option<mpsc::Receiver<usize>>,
    /// The condition the current/last `tag_preview` count corresponds to —
    /// `(field, value)`, where `field` is `None` for a `message_contains`
    /// substring search and `Some(field)` for an exact-match field
    /// condition. Lets the UI tell "counting a stale condition" apart from
    /// "count for what's configured right now" instead of showing a preview
    /// number that's quietly wrong for the dialog's current state.
    tag_preview_key: Option<(Option<&'static str>, String)>,
    tag_preview: Option<usize>,
    /// Free-typed text for `settings.default_source_timezone`, edited
    /// directly in the load controls (shown once `source_kind` is `Text`)
    /// rather than only reachable via the Settings dialog — the session
    /// default is exactly the kind of thing worth seeing and adjusting
    /// right when about to load a text source, not something to remember
    /// to go set up beforehand. Applied and persisted live on every valid
    /// change (see the controls-panel rendering), same immediate-effect
    /// pattern View > Theme already uses, rather than needing a separate
    /// Save step. Kept in sync with `settings_dialog`'s own copy of this
    /// same field whenever Settings is opened/saved, so the two can't
    /// silently disagree.
    default_source_timezone_input: String,
    /// `View > Display timezone` — a small dedicated window rather than
    /// nested directly in the View menu the way `default_source_timezone`'s
    /// quick-access copy is: see [`crate::ui::display_timezone_dialog`]'s
    /// doc comment for why a live `TextEdit` inside a transient popup menu
    /// turned out to be unreliable.
    display_timezone_dialog: DisplayTimezoneDialog,
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

/// Splits a multi-file pick into "becomes `source_path`" (the first path)
/// and "queued after" (the rest, in original order) — `None` for an empty
/// pick, treated the same as the analyst cancelling the dialog outright.
/// Defensive rather than trusting [`FilePickOutcome::SourcePaths`]'s
/// documented "never empty" contract: see that variant's doc comment for
/// the real-world case (closing the native picker via the window's X
/// button on Linux) where it's been observed not to hold.
fn source_path_and_queue_from_pick(mut picked: Vec<PathBuf>) -> Option<(PathBuf, Vec<PathBuf>)> {
    if picked.is_empty() {
        return None;
    }
    let first = picked.remove(0);
    Some((first, picked))
}

/// Whether the "Built-in rules..." button is worth showing at all. Every
/// built-in rule (any of the four packs) only ever matches AUL, EVTX,
/// journald, or intrusion_log entries (a hard-coded `sourcetype` condition
/// on every rule — see `tagging::builtin`), so offering the button while
/// the analyst is about to load something else, with none of those four
/// already loaded either, would offer a control that provably cannot
/// affect anything currently relevant: neither the upcoming load nor a
/// re-tag of what's already in the timeline. True either when one of those
/// four kinds of load is about to happen (current `source_kind`) or when
/// the session already holds at least one loaded source of one of those
/// four sourcetypes that "Re-tag now" could apply the rules to.
fn builtin_rules_button_is_relevant(
    source_kind: SourceKind,
    loaded_sources: &[LoadedSource],
) -> bool {
    matches!(
        source_kind,
        SourceKind::Aul | SourceKind::Evtx | SourceKind::Journald | SourceKind::IntrusionLog
    ) || loaded_sources.iter().any(|source| {
        matches!(
            source.sourcetype.as_str(),
            "aul" | "evtx" | "journald" | "intrusion_log"
        )
    })
}

impl PeachApp {
    fn new(add_sources: Vec<PathBuf>, cleanup_dirs: Vec<PathBuf>, ephemeral_session: bool) -> Self {
        let settings = config::load();
        // `--ephemeral-session` (crush handing off a temp-extracted or
        // decrypted source): use a one-off directory under the configured
        // staging base (OS temp by default, see `Settings::staging_dir`)
        // instead of the persistent sessions directory, so the unencrypted
        // `.duckdb`/`.sqlite` never lands there in the first place. Falls
        // back to the plain OS temp dir if even that can't be created —
        // same better-a-working-non-persisted-session-than-a-crash
        // reasoning as the non-ephemeral fallback below.
        let ephemeral_session_dir = if ephemeral_session {
            let staging_base = settings
                .staging_dir()
                .unwrap_or_else(|_| std::env::temp_dir());
            Some(
                persist::new_ephemeral_sessions_dir(&staging_base)
                    .unwrap_or_else(|_| std::env::temp_dir()),
            )
        } else {
            None
        };
        // Falls back to a plain temp file if the sessions directory (OS
        // default or configured override) can't be created — better a
        // working, non-persisted session than a crash on startup.
        let sessions_dir = match &ephemeral_session_dir {
            Some(dir) => dir.clone(),
            None => settings
                .sessions_dir()
                .unwrap_or_else(|_| std::env::temp_dir()),
        };
        // A reliable backstop for the on_exit cleanup below: that one only
        // fires on a graceful shutdown, so this sweeps up whatever a
        // killed/crashed previous run left behind, before this run's own
        // (currently still-empty) session gets created. Skipped for an
        // ephemeral run — `sessions_dir` is a just-created, empty temp
        // directory, nothing to sweep.
        if ephemeral_session_dir.is_none() {
            session_dialog::sweep_empty_sessions(&sessions_dir);
        }
        let session_paths = SessionPaths::new_in(&sessions_dir, persist::new_session_id());
        // Best-effort, same reasoning as the `open_session_db` call right
        // after it: a failure here just means this run's session doesn't
        // persist, not a crash on startup.
        let _ = session_paths.ensure_dir();
        let _ = persist::open_session_db(&session_paths.sqlite_path);
        let db_path = session_paths.duckdb_path.clone();

        let (source_path, source_kind, pending_cli_sources) = queue_from_cli_sources(add_sources);

        let mut timeline = TimelineView::new(db_path.clone(), session_paths.sqlite_path.clone());
        // Best-effort, same reasoning as `rule_paths` above: a bad
        // hand-edited `display_timezone` just means starting at UTC (the
        // default it would already be at), not a crash on startup —
        // `Settings::display_timezone_spec`'s own doc comment covers why a
        // *save* from the Settings dialog is stricter than this.
        if let Ok(display_tz) = settings.display_timezone_spec() {
            timeline.set_display_timezone(display_tz);
        }
        let default_source_timezone_input =
            settings.default_source_timezone.clone().unwrap_or_default();

        Self {
            db_path: db_path.clone(),
            timeline,
            visited_sessions: vec![session_paths.sqlite_path.clone()],
            session_paths,
            // A session `new_session_id()` just minted has no
            // `session_state` row yet — nothing to load.
            session_display_name: None,
            loaded_sources: Vec::new(),
            source_kind,
            source_path,
            parser_config_path: None,
            skip_bad_records: false,
            // Every `*.toml` already sitting in the configured rules
            // directory applies from the start, same as the built-in packs
            // — a rule created via "Tag all matching (advanced)..." in a
            // previous session doesn't need manually re-picking every time
            // Peach starts. Best-effort: an unreadable/nonexistent rules
            // directory (e.g. a stale configured override that was since
            // deleted) just means starting with no extra rules selected,
            // same as before this existed — still visible in the "N rule
            // file(s) selected" label either way, so not a silent failure.
            rule_paths: settings
                .rules_dir()
                .and_then(|dir| rule_file::scan_rules_dir(&dir))
                .unwrap_or_default(),
            // `active_builtin_rules` is tier 2 (a currently-applied
            // downloaded rule pack) wholesale-replacing tier 1 (the
            // embedded baseline) when present — see
            // `docs/design/rule-pack-updates.md` §3. `.ok()` on the
            // directory lookup: same best-effort tolerance as `rule_paths`
            // above, since nothing writes into that directory yet (the
            // still-unbuilt UI, step 7) so it's normal for the lookup to
            // find nothing.
            enabled_builtin_rules: crate::tagging::builtin::active_builtin_rules(
                rule_file::default_applied_pack_dir().ok().as_deref(),
            )
            .iter()
            .map(|rule| rule.rule.name.clone())
            .collect(),
            file_pick_rx: None,
            load_state: LoadState::Idle,
            load_rx: None,
            load_cancel: None,
            retag_state: RetagState::Idle,
            retag_rx: None,
            export_state: ExportState::Idle,
            export_rx: None,
            portable_case_export_state: PortableCaseExportState::Idle,
            portable_case_export_rx: None,
            portable_case_import_state: PortableCaseImportState::Idle,
            portable_case_import_rx: None,
            filter_bar: FilterBar::new(),
            available_levels: Vec::new(),
            available_tags: Vec::new(),
            level_counts: HashMap::new(),
            tag_counts: HashMap::new(),
            source_counts: HashMap::new(),
            pending_cli_sources,
            cleanup_dirs,
            ephemeral_session_dir,
            tag_dialog: TagDialog::Closed,
            note_dialog: NoteDialog::Closed,
            format_dialog: FormatDialog::Closed,
            raw_fields_dialog: RawFieldsDialog::Closed,
            session_dialog: SessionManagerDialog::Closed,
            settings,
            settings_dialog: SettingsDialog::Closed,
            about_dialog: AboutDialog::Closed,
            activity_log_dialog: ActivityLogDialog::Closed,
            case_summary_dialog: CaseSummaryDialog::Closed,
            builtin_rules_dialog: BuiltinRulesDialog::Closed,
            rules_reference_dialog: RulesReferenceDialog::Closed,
            rule_pack_dialog: RulePackDialog::Closed,
            rainbow_start: None,
            tag_preview_rx: None,
            tag_preview_key: None,
            tag_preview: None,
            default_source_timezone_input,
            display_timezone_dialog: DisplayTimezoneDialog::Closed,
        }
    }

    /// Starts a brand-new, empty session — same shape as the one `new()`
    /// creates at startup (fresh `new_session_id()`, no `.duckdb` until
    /// data is loaded into it), but reachable mid-run from the File menu
    /// instead of only via a restart. Doesn't touch the session being left
    /// behind: if it's still empty, the next `sweep_empty_sessions` (at the
    /// next startup) or `on_exit` cleans it up same as any other abandoned
    /// empty session.
    fn new_session(&mut self) {
        let sessions_dir = match &self.ephemeral_session_dir {
            Some(dir) => dir.clone(),
            None => self
                .settings
                .sessions_dir()
                .unwrap_or_else(|_| std::env::temp_dir()),
        };
        let session_paths = SessionPaths::new_in(&sessions_dir, persist::new_session_id());
        // Best-effort, same reasoning as `new()`: a failure here just means
        // this session doesn't persist, not a crash.
        let _ = session_paths.ensure_dir();
        let _ = persist::open_session_db(&session_paths.sqlite_path);

        self.db_path = session_paths.duckdb_path.clone();
        self.timeline = TimelineView::new(self.db_path.clone(), session_paths.sqlite_path.clone());
        if let Ok(display_tz) = self.settings.display_timezone_spec() {
            self.timeline.set_display_timezone(display_tz);
        }
        if !self.visited_sessions.contains(&session_paths.sqlite_path) {
            self.visited_sessions
                .push(session_paths.sqlite_path.clone());
        }
        self.session_paths = session_paths;
        // A session `new_session_id()` just minted has no `session_state`
        // row yet — nothing to load, same as `new()`.
        self.session_display_name = None;
        self.loaded_sources = Vec::new();
        self.available_levels = Vec::new();
        self.available_tags = Vec::new();
        self.level_counts = HashMap::new();
        self.tag_counts = HashMap::new();
        self.source_counts = HashMap::new();
        self.filter_bar = FilterBar::new();
        self.timeline.set_query(Query::default());
    }

    /// Switches to a previously saved session — points at its `.duckdb`
    /// (already-parsed, no re-parsing) and restores the loaded-source list
    /// and search query from its `.sqlite` `session_state`.
    fn load_session(&mut self, sqlite_path: PathBuf) -> anyhow::Result<()> {
        let session_paths = SessionPaths::from_sqlite_path(&sqlite_path)?;
        let conn = persist::open_session_db(&session_paths.sqlite_path)?;
        let loaded_sources = persist::load_loaded_sources(&conn)?;
        let search_query = persist::load_search_query(&conn)?.unwrap_or_default();
        let display_name = persist::load_display_name(&conn)?;

        self.db_path = session_paths.duckdb_path.clone();
        self.timeline = TimelineView::new(self.db_path.clone(), session_paths.sqlite_path.clone());
        if let Ok(display_tz) = self.settings.display_timezone_spec() {
            self.timeline.set_display_timezone(display_tz);
        }
        if !self.visited_sessions.contains(&session_paths.sqlite_path) {
            self.visited_sessions
                .push(session_paths.sqlite_path.clone());
        }
        self.session_paths = session_paths;
        self.session_display_name = display_name;
        self.loaded_sources = loaded_sources;
        self.timeline.refresh();
        self.available_levels = self.timeline.distinct_levels();
        self.available_tags = self.timeline.distinct_tags();
        self.level_counts = self.timeline.level_counts();
        self.tag_counts = self.timeline.tag_counts();
        self.source_counts = self.timeline.source_counts();
        self.filter_bar.set_text(search_query.clone());
        self.timeline.set_query(Query::parse(&search_query));

        Ok(())
    }

    fn start_retag(&mut self) {
        if self.rule_paths.is_empty() && self.enabled_builtin_rules.is_empty() {
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
        let enabled_builtin_rules = self.enabled_builtin_rules.clone();
        let session_sqlite_path = self.session_paths.sqlite_path.clone();

        std::thread::spawn(move || {
            let started_at = chrono::Utc::now().timestamp();
            let retag_result = run_retag(&rule_paths, &enabled_builtin_rules, conn);
            record_retag_activity_entry(
                &session_sqlite_path,
                started_at,
                chrono::Utc::now().timestamp(),
                &retag_result,
                RuleSelection {
                    paths: &rule_paths,
                    enabled_builtin_rules: &enabled_builtin_rules,
                },
            );
            let result = retag_result.map_err(|err| format!("{err:#}"));
            let _ = tx.send(RetagOutcome::Done(result));
        });
    }

    /// Kicks off a background export of the timeline's *current* filter
    /// (see `export`'s module doc comment) to `out_path` — same
    /// spawn-a-thread-and-poll shape as `start_load`/`start_retag`.
    /// `ExportFormat::from_path` decides CSV vs. JSON from `out_path`'s
    /// extension, which the save dialog's filters already steer toward.
    fn start_export(&mut self, out_path: PathBuf) {
        let Some(conn) = self.timeline.try_clone_conn() else {
            self.export_state =
                ExportState::Failed("failed to open a database connection for export".into());
            return;
        };
        // Same precedence a typo'd `assume_offset` gets — a bad
        // `display_timezone` surfaces as a failed export rather than
        // silently exporting in the wrong (or UTC) timezone.
        let display_tz = match self.settings.display_timezone_spec() {
            Ok(spec) => spec,
            Err(err) => {
                self.export_state = ExportState::Failed(format!("{err:#}"));
                return;
            }
        };
        let (tx, rx) = mpsc::channel();
        self.export_rx = Some(rx);
        self.export_state = ExportState::Running {
            rows_written: 0,
            path: out_path.clone(),
        };

        let session_sqlite_path = self.session_paths.sqlite_path.clone();
        let query = self.timeline.query().clone();
        let format = export::ExportFormat::from_path(&out_path);

        std::thread::spawn(move || {
            let result = export::export_to_file(
                &conn,
                &session_sqlite_path,
                &query,
                &display_tz,
                format,
                &out_path,
                &tx,
            )
            .map_err(|err| format!("{err:#}"));
            let _ = tx.send(ExportOutcome::Done(result));
        });
    }

    /// Kicks off a background "Export portable case..." — a full-fidelity,
    /// `raw`/`fields`/tags/notes-preserving bundle, unlike `start_export`'s
    /// lossy CSV/JSON — filtered by the timeline's *current* search query,
    /// same as `start_export` (an empty query bundles the whole session).
    /// Same spawn-a-thread-and-poll shape as `start_load`/`start_export`.
    fn start_portable_case_export(&mut self, out_path: PathBuf) {
        let Some(conn) = self.timeline.try_clone_conn() else {
            self.portable_case_export_state = PortableCaseExportState::Failed(
                "failed to open a database connection for export".into(),
            );
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.portable_case_export_rx = Some(rx);
        self.portable_case_export_state = PortableCaseExportState::Running {
            stage: PortableCaseExportStage::CopyingTimeline,
            path: out_path.clone(),
        };

        let session_sqlite_path = self.session_paths.sqlite_path.clone();
        let original_session_id = self.session_paths.id.clone();
        let display_name = self.session_display_name.clone();
        let filter_query_text = self.filter_bar.text().to_string();
        let staging_base = self
            .settings
            .staging_dir()
            .unwrap_or_else(|_| std::env::temp_dir());

        std::thread::spawn(move || {
            let result = portable_case::export_portable_case(
                &conn,
                &session_sqlite_path,
                &original_session_id,
                display_name.as_deref(),
                &filter_query_text,
                &out_path,
                &staging_base,
                &tx,
            )
            .map_err(|err| format!("{err:#}"));
            let _ = tx.send(PortableCaseExportOutcome::Done(result));
        });
    }

    /// Kicks off a background "Import portable case..." — extracts,
    /// verifies, and registers `zip_path` as a brand-new session (never
    /// reusing the bundle's original session id, see
    /// `persist::new_session_dir_for_import`), then switches into it on
    /// success (`PortableCaseImportOutcome::Done` handling in `ui()`).
    fn start_portable_case_import(&mut self, zip_path: PathBuf) {
        let sessions_dir = match &self.ephemeral_session_dir {
            Some(dir) => dir.clone(),
            None => self
                .settings
                .sessions_dir()
                .unwrap_or_else(|_| std::env::temp_dir()),
        };
        let staging_base = self
            .settings
            .staging_dir()
            .unwrap_or_else(|_| std::env::temp_dir());
        let (tx, rx) = mpsc::channel();
        self.portable_case_import_rx = Some(rx);
        self.portable_case_import_state =
            PortableCaseImportState::Running(PortableCaseImportStage::Extracting);

        std::thread::spawn(move || {
            let result =
                portable_case::import_portable_case(&zip_path, &sessions_dir, &staging_base, &tx)
                    .map_err(|err| format!("{err:#}"));
            let _ = tx.send(PortableCaseImportOutcome::Done(result));
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
            total_entries: None,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.load_cancel = Some(Arc::clone(&cancel));

        let source_kind = self.source_kind;
        let parser_config_path = self.parser_config_path.clone();
        let rule_paths = self.rule_paths.clone();
        let enabled_builtin_rules = self.enabled_builtin_rules.clone();
        let load_threads = self.settings.effective_load_threads();
        let default_source_timezone = self.settings.default_source_timezone.clone();
        let session_sqlite_path = self.session_paths.sqlite_path.clone();
        let skip_bad_records = self.skip_bad_records;

        std::thread::spawn(move || {
            let progress_tx = tx.clone();
            let started_at = chrono::Utc::now().timestamp();
            let start = std::time::Instant::now();
            let load_result = run_load(
                source_kind,
                &source_path,
                parser_config_path.as_deref(),
                RuleSelection {
                    paths: &rule_paths,
                    enabled_builtin_rules: &enabled_builtin_rules,
                },
                conn,
                LoadSettings {
                    thread_count: load_threads,
                    default_source_timezone,
                    skip_bad_records,
                },
                LoadControl {
                    progress_tx: &progress_tx,
                    cancel,
                },
            );
            record_load_activity_entry(
                &session_sqlite_path,
                &source_path,
                started_at,
                chrono::Utc::now().timestamp(),
                &load_result,
                skip_bad_records,
                RuleSelection {
                    paths: &rule_paths,
                    enabled_builtin_rules: &enabled_builtin_rules,
                },
            );
            let result = load_result
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
                self.tag_preview_key = None;
            }
            RowAction::TagAllMatching {
                event_id,
                message,
                sourcetype,
                fields,
            } => {
                let existing = self.combined_tag_vocabulary();
                self.tag_dialog =
                    TagDialog::open_advanced(event_id, message, sourcetype, fields, existing);
                self.tag_preview = None;
                self.tag_preview_key = None;
            }
            RowAction::ShowContext { query_text } => {
                self.filter_bar.set_text(query_text.clone());
                self.timeline.set_query(Query::parse(&query_text));
                if let Ok(conn) = persist::open_session_db(&self.session_paths.sqlite_path) {
                    let _ = persist::save_search_query(&conn, &query_text);
                }
            }
            RowAction::FilterByColumn { field, value } => {
                self.filter_bar.set_column_filter(field, &value);
                self.timeline
                    .set_query(Query::parse(self.filter_bar.text()));
                if let Ok(conn) = persist::open_session_db(&self.session_paths.sqlite_path) {
                    let _ = persist::save_search_query(&conn, self.filter_bar.text());
                }
            }
            RowAction::ManageNotes { event_id } => {
                let notes = persist::open_session_db(&self.session_paths.sqlite_path)
                    .and_then(|conn| persist::notes_for_event(&conn, event_id))
                    .unwrap_or_default();
                self.note_dialog = NoteDialog::open(event_id, notes);
            }
            RowAction::ViewRawFields { entry } => {
                self.raw_fields_dialog = RawFieldsDialog::open(entry);
            }
        }
    }

    /// Same overall pattern as `handle_tag_dialog`, but every outcome here
    /// re-fetches this one event's notes and feeds them back into the
    /// dialog (`set_notes`) instead of the dialog just closing — an
    /// add/edit/delete should be visible immediately in the still-open
    /// "Notes" window, not only after reopening it.
    fn handle_note_dialog(&mut self, ctx: &egui::Context) {
        if !self.note_dialog.is_open() {
            return;
        }
        let Some(outcome) = self.note_dialog.ui(ctx) else {
            return;
        };
        let Ok(conn) = persist::open_session_db(&self.session_paths.sqlite_path) else {
            return;
        };
        let event_id = match outcome {
            NoteDialogOutcome::Add { event_id, text } => {
                let _ = persist::insert_event_note(&conn, event_id, &text);
                Some(event_id)
            }
            NoteDialogOutcome::Update { note_id, text } => {
                let _ = persist::update_event_note(&conn, note_id, &text);
                self.note_dialog_event_id()
            }
            NoteDialogOutcome::Delete { note_id } => {
                let _ = persist::delete_event_note(&conn, note_id);
                self.note_dialog_event_id()
            }
        };
        if let Some(event_id) = event_id
            && let Ok(notes) = persist::notes_for_event(&conn, event_id)
        {
            self.note_dialog.set_notes(notes);
        }
        self.timeline.refresh_window();
    }

    /// The event a still-open `NoteDialog` is showing, if any — needed by
    /// `Update`/`Delete` outcomes, which only carry a `note_id`, not the
    /// `event_id` it belongs to (unlike `Add`, which does).
    fn note_dialog_event_id(&self) -> Option<EventId> {
        match &self.note_dialog {
            NoteDialog::Open { event_id, .. } => Some(*event_id),
            NoteDialog::Closed => None,
        }
    }

    /// Opens the "Define format..." dialog against `self.source_path` (the
    /// button that triggers this is disabled while that's `None`, so
    /// bailing out silently here is unreachable in practice, not a
    /// swallowed error). Seeds the draft from the currently-selected
    /// parser config, if any, so refining an existing config is the same
    /// flow as starting a new one rather than a separate "edit" entry
    /// point — falls back to a blank draft if none is selected yet, or if
    /// the selected one fails to parse (e.g. hand-edited into something
    /// this dialog's fields can't represent).
    fn open_format_dialog(&mut self) {
        let Some(source_path) = self.source_path.clone() else {
            return;
        };
        let preview_lines = read_preview_lines(&source_path, FORMAT_PREVIEW_LINES);
        let draft = self
            .parser_config_path
            .as_deref()
            .and_then(|path| TextFormatDraft::from_file(path).ok())
            .unwrap_or_default();
        let saved = text_config_file::default_user_parsers_dir()
            .map(|dir| text_config_file::list_saved_configs(&dir))
            .unwrap_or_default();
        self.format_dialog = FormatDialog::open(
            preview_lines,
            draft,
            saved,
            self.settings.default_source_timezone.clone(),
        );
    }

    /// Same overall pattern as `handle_settings_dialog`: `app.rs` owns the
    /// `parsers/` directory, the dialog only reports what the analyst
    /// clicked. Unlike Settings, a failure here (disk error, or a chosen
    /// saved file that no longer parses) is reported back into the still-
    /// open dialog via `set_error` rather than just logged to stderr —
    /// this dialog's whole point is to catch problems before a real load,
    /// so a save/load failure needs to be as visible as the preview
    /// itself, not buried in a terminal the analyst may not be watching.
    fn handle_format_dialog(&mut self, ctx: &egui::Context) {
        if !self.format_dialog.is_open() {
            return;
        }
        let Some(outcome) = self.format_dialog.ui(ctx) else {
            return;
        };
        let Ok(dir) = text_config_file::default_user_parsers_dir() else {
            self.format_dialog
                .set_error("could not determine the per-user parsers directory".to_string());
            return;
        };
        match outcome {
            FormatDialogOutcome::Save(draft) => match text_config_file::save(&dir, &draft) {
                Ok(_) => {
                    self.format_dialog
                        .set_saved(text_config_file::list_saved_configs(&dir));
                }
                Err(err) => self.format_dialog.set_error(format!("{err:#}")),
            },
            FormatDialogOutcome::SaveAndUse(draft) => match text_config_file::save(&dir, &draft) {
                Ok(path) => {
                    self.parser_config_path = Some(path);
                    self.format_dialog = FormatDialog::Closed;
                }
                Err(err) => self.format_dialog.set_error(format!("{err:#}")),
            },
            FormatDialogOutcome::Load(path) => match TextFormatDraft::from_file(&path) {
                Ok(draft) => self.format_dialog.set_draft(draft),
                Err(err) => self.format_dialog.set_error(format!("{err:#}")),
            },
            FormatDialogOutcome::LoadBuiltin(toml) => match TextFormatDraft::from_toml_str(toml) {
                Ok(draft) => self.format_dialog.set_draft(draft),
                Err(err) => self.format_dialog.set_error(format!("{err:#}")),
            },
        }
    }

    /// Kicks off a background match count for the Advanced dialog's
    /// current condition if it changed since the last one — same "don't
    /// freeze the UI on every keystroke" reasoning as
    /// `TimelineView::recount`, since this is the same kind of scan over a
    /// multi-million-row table.
    fn update_tag_preview_request(&mut self) {
        let Some(target) = self.tag_dialog.current_preview_target() else {
            return;
        };
        let key: (Option<&'static str>, String) = match &target {
            PreviewTarget::MessageContains(pattern) => (None, pattern.to_string()),
            PreviewTarget::FieldEquals { field, value } => (Some(*field), value.to_string()),
        };
        if self.tag_preview_key.as_ref() == Some(&key) || self.tag_preview_rx.is_some() {
            return;
        }
        self.tag_preview_key = Some(key.clone());
        self.tag_preview = None;
        let (key_field, key_value) = key;
        if key_value.trim().is_empty() {
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.tag_preview_rx = Some(rx);
        let conn = self.timeline.try_clone_conn();
        std::thread::spawn(move || {
            let count = conn
                .and_then(|conn| match key_field {
                    None => timeline_queries::count_message_contains(&conn, &key_value).ok(),
                    Some(field) => {
                        let query = Query {
                            terms: vec![Term {
                                connector: Connector::And,
                                negate: false,
                                kind: TermKind::Field {
                                    field: Field::parse(field)?,
                                    value: key_value,
                                    is_regex: false,
                                },
                            }],
                        };
                        timeline_queries::count_matching(&conn, &query).ok()
                    }
                })
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
        let current_key = self
            .tag_dialog
            .current_preview_target()
            .map(|target| match target {
                PreviewTarget::MessageContains(pattern) => (None, pattern.to_string()),
                PreviewTarget::FieldEquals { field, value } => (Some(field), value.to_string()),
            });
        let preview = current_key
            .filter(|key| Some(key) == self.tag_preview_key.as_ref())
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
                self.timeline.refresh_window();
            }
            TagDialogOutcome::CreateRule {
                rule_name,
                sourcetype,
                condition,
                tag_value,
            } => {
                if let Ok(dir) = self.settings.rules_dir() {
                    let path = dir.join(format!("{}.toml", rule_file::slugify(&rule_name)));
                    if rule_file::create_rule(
                        &path,
                        &rule_name,
                        &sourcetype,
                        &condition,
                        &tag_value,
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

    /// Opens the "Manage sessions" dialog — the *only* way to switch
    /// sessions now (there used to also be a "Load session..." native file
    /// picker, removed once sessions could have a display name: that
    /// picker showed raw `session-YYYYMMDD-HHMMSS.sqlite` filenames with no
    /// way to show the friendly name instead, which defeated the point of
    /// renaming for exactly the moment it mattered most — finding the
    /// right session again later). Called from both the File menu and a
    /// button next to the session label in the controls panel, so this
    /// isn't duplicated between them.
    fn open_session_manager_dialog(&mut self) {
        let Ok(dir) = self.settings.sessions_dir() else {
            return;
        };
        // Only clone a connection if the current session's `.duckdb`
        // already exists — `try_clone_conn` lazily *creates* it on first
        // call, and this dialog otherwise has no reason to touch a session
        // nothing has been loaded into yet. Doing that unconditionally here
        // used to leave behind an empty-but-no-longer-"empty" `.duckdb`
        // (data schema, zero rows) just from opening this dialog, which
        // then defeated the on-exit empty-session cleanup
        // (`delete_if_empty`) since it only checks file *existence*, not
        // row count.
        let current_conn = if self.db_path.exists() {
            self.timeline.try_clone_conn()
        } else {
            None
        };
        self.session_dialog =
            SessionManagerDialog::open(&dir, &self.session_paths.id, current_conn);
    }

    /// Opens the "Activity Log" dialog, populated with a fresh read of every
    /// load/re-tag this session has recorded so far — same synchronous
    /// `persist::open_session_db` + query pattern as `ManageNotes`
    /// (`RowAction::ManageNotes`), not backgrounded: `activity_log` stays small
    /// (one row per operation, never per timeline entry), so there's no UI
    /// freeze risk to guard against here the way `SessionManagerDialog`'s
    /// per-session row counts need to be.
    fn open_activity_log_dialog(&mut self) {
        let entries = persist::open_session_db(&self.session_paths.sqlite_path)
            .and_then(|conn| persist::all_activity_log_entries(&conn))
            .unwrap_or_default();
        self.activity_log_dialog = ActivityLogDialog::open(entries);
    }

    /// Effective display timezone, falling back to UTC on a bad/unparseable
    /// `Settings::display_timezone` — used for cosmetic label formatting
    /// (`CaseSummaryDialog`'s earliest/latest range) where a config typo
    /// should degrade to a readable UTC label, not abort the whole view the
    /// way `start_export`'s stricter data-affecting check does.
    fn display_timezone_or_utc(&self) -> TimezoneSpec {
        self.settings
            .display_timezone_spec()
            .unwrap_or_else(|_| TimezoneSpec::parse("UTC").expect("\"UTC\" always parses"))
    }

    /// Opens the whole-session "Case Summary" dialog — used by both the
    /// View menu (`title` is a fixed label) and the portable-case import
    /// success handler (`title` names the just-imported case), which is why
    /// `title` is a parameter rather than hardcoded here.
    fn open_case_summary_dialog(&mut self, title: String) {
        let Some(conn) = self.timeline.try_clone_conn() else {
            return;
        };
        let Ok(summary) = timeline_queries::case_summary(&conn, &Query::default()) else {
            return;
        };
        let skipped_files = persist::open_session_db(&self.session_paths.sqlite_path)
            .and_then(|conn| persist::all_activity_log_entries(&conn))
            .map(|entries| entries.iter().map(|entry| entry.skipped.len()).sum())
            .ok();
        let display_tz = self.display_timezone_or_utc();
        self.case_summary_dialog =
            CaseSummaryDialog::open_info(title, summary, skipped_files, &display_tz);
    }

    /// Computes a `CaseSummary` scoped to the timeline's *current* search
    /// filter and opens it as an export-confirmation preview — "Export
    /// portable case..."'s menu click calls this instead of opening the
    /// save-file dialog directly, so the analyst sees exactly what's about
    /// to be bundled before picking a destination. The save dialog itself
    /// only opens once the preview reports
    /// `CaseSummaryDialogOutcome::ExportConfirmed` (see `ui()`'s handling of
    /// `case_summary_dialog`), via
    /// [`Self::open_portable_case_export_save_dialog`].
    fn open_portable_case_export_preview(&mut self) {
        let Some(conn) = self.timeline.try_clone_conn() else {
            self.portable_case_export_state = PortableCaseExportState::Failed(
                "failed to open a database connection for export".into(),
            );
            return;
        };
        let summary = match timeline_queries::case_summary(&conn, self.timeline.query()) {
            Ok(summary) => summary,
            Err(err) => {
                self.portable_case_export_state =
                    PortableCaseExportState::Failed(format!("{err:#}"));
                return;
            }
        };
        let display_tz = self.display_timezone_or_utc();
        self.case_summary_dialog = CaseSummaryDialog::open_export_confirm(summary, &display_tz);
    }

    /// Opens the save-file dialog for "Export portable case..." — factored
    /// out so both the (now preview-gated) menu click path and the preview
    /// dialog's `ExportConfirmed` outcome reach it without duplicating the
    /// `rfd::AsyncFileDialog` setup.
    fn open_portable_case_export_save_dialog(&mut self) {
        let default_name = self
            .session_display_name
            .clone()
            .unwrap_or_else(|| self.session_paths.id.clone());
        let task = rfd::AsyncFileDialog::new()
            .add_filter("Peach Case", &["peachcase"])
            .set_file_name(format!("{default_name}.peachcase"))
            .save_file();
        self.file_pick_rx = Some(spawn_dialog_pick(task, |picked| {
            FilePickOutcome::PortableCaseExportTarget(
                picked.map(|h: rfd::FileHandle| h.path().to_path_buf()),
            )
        }));
    }

    /// Re-reads `activity_log` and pushes it into the dialog if it's currently
    /// open — called right after a load or re-tag finishes (both the
    /// success and failure paths already wrote an entry by this point, from
    /// inside the background thread, before the outcome even reached this
    /// UI-thread handler). Without this, a dialog left open across a load
    /// would keep showing whatever it had at open time until manually
    /// closed and reopened — the whole point of leaving it open while
    /// working is to watch it update.
    fn refresh_activity_log_dialog_if_open(&mut self) {
        if !self.activity_log_dialog.is_open() {
            return;
        }
        let entries = persist::open_session_db(&self.session_paths.sqlite_path)
            .and_then(|conn| persist::all_activity_log_entries(&conn))
            .unwrap_or_default();
        self.activity_log_dialog.set_entries(entries);
    }

    /// Renders the "Manage sessions" dialog if open and switches to
    /// whichever session the analyst picked via its Open button — deletion
    /// and renaming are both handled entirely inside the dialog itself (it
    /// only ever touches session files on disk, not `PeachApp`'s own
    /// state), so the only state this side needs to keep in sync is its
    /// own displayed name when the session just renamed happens to be the
    /// one currently open.
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
            SessionManagerOutcome::Renamed { id } => {
                if id == self.session_paths.id {
                    self.session_display_name = self.load_current_session_display_name();
                }
            }
        }
    }

    /// Starts a re-tag when the "Rule packs..." dialog's own Apply flow
    /// asks for one — everything else about that dialog (checking for
    /// updates, verifying a dropped bundle, previewing the diff, applying
    /// it) is entirely self-contained; re-tagging the current session is
    /// the one piece that belongs to `app.rs`'s existing machinery
    /// (`start_retag`), same division of labor as `handle_session_dialog`.
    fn handle_rule_pack_dialog(&mut self, ctx: &egui::Context) {
        if !self.rule_pack_dialog.is_open() {
            return;
        }
        match self.rule_pack_dialog.ui(ctx, self.file_pick_rx.is_some()) {
            Some(RulePackDialogOutcome::RetagRequested) => self.start_retag(),
            Some(RulePackDialogOutcome::BrowseRequested) => {
                let task = rfd::AsyncFileDialog::new()
                    .add_filter("Peach Rule Pack", &["zip"])
                    .pick_file();
                self.file_pick_rx = Some(spawn_dialog_pick(
                    task,
                    |picked: Option<rfd::FileHandle>| {
                        FilePickOutcome::RulePackBundle(picked.map(|h| h.path().to_path_buf()))
                    },
                ));
            }
            None => {}
        }
    }

    /// Reads the current session's `display_name` (see
    /// `session::persist::load_display_name`) fresh from its `.sqlite`
    /// file — `None` on any failure or if none was ever set, same
    /// best-effort reasoning as everything else that reads session state
    /// for display purposes only.
    fn load_current_session_display_name(&self) -> Option<String> {
        persist::open_session_db(&self.session_paths.sqlite_path)
            .ok()
            .and_then(|conn| persist::load_display_name(&conn).ok())
            .flatten()
    }

    /// Renders the "Settings" dialog if open and persists a confirmed
    /// change — best-effort, same as the rest of this app's local-file
    /// housekeeping (`cleanup_temp_dir`, the empty-session cleanup in
    /// `on_exit`): a failure to *write* `config.toml` shouldn't undo the
    /// analyst's choice for the rest of this run, just mean it doesn't
    /// survive a restart.
    /// `CaseSummaryDialogOutcome::ExportConfirmed` is the only outcome this
    /// dialog ever reports — a plain "Close"/dismiss (Info mode, or Cancel
    /// in ExportConfirm mode) is handled entirely inside `CaseSummaryDialog`
    /// itself (it just closes), never reaches here.
    fn handle_case_summary_dialog(&mut self, ctx: &egui::Context) {
        if !self.case_summary_dialog.is_open() {
            return;
        }
        let Some(CaseSummaryDialogOutcome::ExportConfirmed) = self.case_summary_dialog.ui(ctx)
        else {
            return;
        };
        self.open_portable_case_export_save_dialog();
    }

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
                // Re-scan and replace the current rule selection if the
                // rules directory actually changed — otherwise saving
                // Settings for an unrelated reason (e.g. Theme) would
                // silently wipe out whatever's currently selected, rule
                // files picked from elsewhere via "Choose tagging rules..."
                // included. Same replace-the-whole-selection semantics that
                // button already has, just triggered from here instead —
                // not a merge, since there's no way to tell "still wanted"
                // apart from "leftover from the old directory" otherwise.
                let old_dir = self.settings.rules_dir().ok();
                let new_dir = new_settings.rules_dir().ok();
                if old_dir != new_dir
                    && let Some(dir) = &new_dir
                    && let Ok(paths) = rule_file::scan_rules_dir(dir)
                {
                    self.rule_paths = paths;
                }
                // Same best-effort reasoning as startup: the Settings
                // dialog validates the field before allowing Save (see
                // `SettingsDialog`), so a parse failure here would only
                // mean a config file hand-edited to something invalid
                // between opening the dialog and clicking Save — keep
                // whatever display timezone was already in effect rather
                // than silently reverting to UTC.
                if let Ok(display_tz) = new_settings.display_timezone_spec() {
                    self.timeline.set_display_timezone(display_tz);
                }
                // Keep the load-controls quick-access copy of this field in
                // sync — otherwise saving a change via Settings would leave
                // it showing a stale value until the app restarts. Display
                // timezone has no such copy to keep in sync: it's only
                // editable from View > Display timezone now, not Settings
                // (see that dialog's doc comment for why one field ended up
                // with two editable locations and the other doesn't).
                self.default_source_timezone_input = new_settings
                    .default_source_timezone
                    .clone()
                    .unwrap_or_default();
                self.settings = new_settings;
            }
        }
    }

    /// Applies a validated `Display Timezone` edit the moment it lands —
    /// same immediate-apply/immediate-save shape as `View > Theme` and the
    /// load-controls' own `default_source_timezone` field, just routed
    /// through a real window instead of directly in the View menu (see
    /// `DisplayTimezoneDialog`'s doc comment for why).
    fn handle_display_timezone_dialog(&mut self, ctx: &egui::Context) {
        if !self.display_timezone_dialog.is_open() {
            return;
        }
        let Some(value) = self.display_timezone_dialog.ui(ctx) else {
            return;
        };
        if value == self.settings.display_timezone {
            return;
        }
        self.settings.display_timezone = value;
        if let Ok(display_tz) = self.settings.display_timezone_spec() {
            self.timeline.set_display_timezone(display_tz);
        }
        if let Err(err) = config::save(&self.settings) {
            eprintln!("peach: failed to save display timezone: {err:#}");
        }
    }
}

/// Lines shown in the "Define format..." dialog's live preview — a small,
/// fixed sample, not a scan of the whole file: enough to judge whether a
/// pattern is right, without reading a multi-hundred-MB text source just to
/// open a dialog.
const FORMAT_PREVIEW_LINES: usize = 20;

/// Reads up to `max_lines` lines from `path` without reading past what's
/// needed — a `BufRead` line iterator stops pulling from disk once `take`
/// is satisfied, unlike `std::fs::read_to_string` followed by `.lines()`,
/// which would materialize the entire file first regardless of how many
/// lines are actually wanted. Returns whatever was read on any I/O error
/// partway through (e.g. non-UTF-8 bytes past the first few lines) rather
/// than discarding a preview that was otherwise working.
fn read_preview_lines(path: &Path, max_lines: usize) -> Vec<String> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    std::io::BufRead::lines(std::io::BufReader::new(file))
        .take(max_lines)
        .map_while(Result::ok)
        .collect()
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

/// User-facing label for a [`PortableCaseExportStage`] — stage-based, not
/// row-count-based like `ExportState`'s progress display, since a single
/// `INSERT ... SELECT` doesn't expose incremental row progress the way
/// `export.rs`'s chunked CSV/JSON export does.
fn portable_case_export_stage_label(stage: PortableCaseExportStage) -> &'static str {
    match stage {
        PortableCaseExportStage::CopyingTimeline => "copying timeline",
        PortableCaseExportStage::CopyingSessionData => "copying tags and notes",
        PortableCaseExportStage::CollectingParserConfigs => "collecting parser configs",
        PortableCaseExportStage::Hashing => "verifying integrity",
        PortableCaseExportStage::Packaging => "packaging",
    }
}

fn portable_case_import_stage_label(stage: PortableCaseImportStage) -> &'static str {
    match stage {
        PortableCaseImportStage::Extracting => "extracting",
        PortableCaseImportStage::VerifyingFormat => "verifying format",
        PortableCaseImportStage::VerifyingIntegrity => "verifying integrity",
        PortableCaseImportStage::RegisteringSession => "registering session",
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
        // `--ephemeral-session`: remove the whole staging directory
        // unconditionally, unlike the `delete_if_empty` sweep above — a
        // session that has data (the normal case for one actually used
        // this run) is exactly what must not survive here. Removed
        // directly rather than via `cleanup_temp_dir`: that function's
        // "must be under the OS temp directory" safety net exists for
        // `cleanup_dirs` below (an externally supplied path from crush, see
        // its own doc comment), but `ephemeral_session_dir` is a path Peach
        // minted itself via `persist::new_ephemeral_sessions_dir` — safe to
        // remove regardless of whether `Settings::staging_dir` points it
        // somewhere other than OS temp.
        if let Some(dir) = &self.ephemeral_session_dir
            && let Err(err) = std::fs::remove_dir_all(dir)
        {
            eprintln!(
                "peach: failed to clean up ephemeral session directory {}: {err}",
                dir.display()
            );
        }
        for dir in &self.cleanup_dirs {
            cleanup_temp_dir(dir);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        theme::tick(ui.ctx(), self.settings.theme, &mut self.rainbow_start);

        if let Some(rx) = &self.file_pick_rx {
            match rx.try_recv() {
                Ok(outcome) => {
                    match outcome {
                        FilePickOutcome::SourcePaths(Some(picked)) => {
                            if let Some((first, rest)) = source_path_and_queue_from_pick(picked) {
                                self.source_path = Some(first);
                                // Same "next queued source becomes the new
                                // `source_path` once the current load
                                // finishes" flow `--add-source` already
                                // drives (see the
                                // `pending_cli_sources.pop_front()` handler
                                // in this same match, below) — a multi-file
                                // pick just seeds that queue directly
                                // instead of via the CLI. Pushed to the
                                // *front*, in order, so these take priority
                                // over anything already queued rather than
                                // landing after it.
                                for path in rest.into_iter().rev() {
                                    self.pending_cli_sources.push_front(path);
                                }
                            }
                        }
                        FilePickOutcome::ParserConfigFile(Some(picked)) => {
                            self.parser_config_path = Some(picked);
                        }
                        FilePickOutcome::RuleFiles(Some(picked)) => {
                            self.rule_paths = picked;
                        }
                        FilePickOutcome::ExportTarget(Some(picked)) => {
                            self.start_export(picked);
                        }
                        FilePickOutcome::PortableCaseExportTarget(Some(picked)) => {
                            self.start_portable_case_export(picked);
                        }
                        FilePickOutcome::PortableCaseImportSource(Some(picked)) => {
                            self.start_portable_case_import(picked);
                        }
                        FilePickOutcome::RulePackBundle(Some(picked)) => {
                            self.rule_pack_dialog.begin_verify_file(picked);
                        }
                        // The analyst cancelled the dialog — nothing to update.
                        FilePickOutcome::SourcePaths(None)
                        | FilePickOutcome::ParserConfigFile(None)
                        | FilePickOutcome::RuleFiles(None)
                        | FilePickOutcome::ExportTarget(None)
                        | FilePickOutcome::PortableCaseExportTarget(None)
                        | FilePickOutcome::PortableCaseImportSource(None)
                        | FilePickOutcome::RulePackBundle(None) => {}
                    }
                    self.file_pick_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ui.ctx().request_repaint();
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.file_pick_rx = None;
                }
            }
        }

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
                        total_entries,
                    }) => {
                        self.load_state = LoadState::Loading {
                            inserted_so_far: inserted,
                            bytes_done,
                            bytes_total,
                            total_entries,
                        };
                    }
                    Ok(LoadOutcome::Done(result)) => {
                        match result {
                            Ok((summary, elapsed)) => {
                                let cancelled = summary.cancelled;
                                self.load_state = LoadState::Done {
                                    inserted: summary.inserted,
                                    tags_applied: summary.tags_applied,
                                    elapsed,
                                    skipped: summary.skipped,
                                    records_skipped: summary.records_skipped,
                                    cancelled,
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
                                self.level_counts = self.timeline.level_counts();
                                self.tag_counts = self.timeline.tag_counts();
                                self.source_counts = self.timeline.source_counts();
                                self.loaded_sources.extend(summary.loaded_sources);
                                if let Ok(conn) =
                                    persist::open_session_db(&self.session_paths.sqlite_path)
                                {
                                    let _ =
                                        persist::save_loaded_sources(&conn, &self.loaded_sources);
                                }
                                // An aborted load shouldn't silently barrel on
                                // into the next `--add-source`-queued file —
                                // the analyst cancelled *because* this was
                                // taking too long/too much, so auto-starting
                                // another load right away would defeat that.
                                if !cancelled
                                    && let Some(next) = self.pending_cli_sources.pop_front()
                                {
                                    self.source_kind = source_kind_for_path(&next);
                                    self.source_path = Some(next);
                                    self.parser_config_path = None;
                                }
                            }
                            Err(err) => self.load_state = LoadState::Failed(err),
                        }
                        self.refresh_activity_log_dialog_if_open();
                        self.load_rx = None;
                        self.load_cancel = None;
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
                        self.load_cancel = None;
                        break;
                    }
                }
            }
        }

        if let Some(rx) = &self.retag_rx {
            match rx.try_recv() {
                Ok(RetagOutcome::Done(result)) => {
                    match result {
                        Ok(summary) => {
                            self.retag_state = RetagState::Done {
                                applied: summary.applied,
                                tags_by_rule: summary.tags_by_rule,
                            };
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
                            self.tag_counts = self.timeline.tag_counts();
                        }
                        Err(err) => self.retag_state = RetagState::Failed(err),
                    }
                    self.refresh_activity_log_dialog_if_open();
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

        if let Some(rx) = &self.export_rx {
            // Drain everything queued this frame, same reasoning as
            // `load_rx`: a large export can flush several `Progress`
            // updates between frames.
            loop {
                match rx.try_recv() {
                    Ok(ExportOutcome::Progress { rows_written }) => {
                        if let ExportState::Running { path, .. } = &self.export_state {
                            self.export_state = ExportState::Running {
                                rows_written,
                                path: path.clone(),
                            };
                        }
                    }
                    Ok(ExportOutcome::Done(result)) => {
                        match result {
                            Ok(rows_written) => {
                                let path = match &self.export_state {
                                    ExportState::Running { path, .. } => path.clone(),
                                    _ => PathBuf::new(),
                                };
                                self.export_state = ExportState::Done { rows_written, path };
                            }
                            Err(err) => self.export_state = ExportState::Failed(err),
                        }
                        self.export_rx = None;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        ui.ctx().request_repaint();
                        break;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.export_state = ExportState::Failed(
                            "export worker disconnected unexpectedly".to_string(),
                        );
                        self.export_rx = None;
                        break;
                    }
                }
            }
        }

        if let Some(rx) = &self.portable_case_export_rx {
            // Drain everything queued this frame, same reasoning as
            // `load_rx`/`export_rx`: several stage transitions can fire
            // between two frames.
            loop {
                match rx.try_recv() {
                    Ok(PortableCaseExportOutcome::Progress(stage)) => {
                        if let PortableCaseExportState::Running { path, .. } =
                            &self.portable_case_export_state
                        {
                            self.portable_case_export_state = PortableCaseExportState::Running {
                                stage,
                                path: path.clone(),
                            };
                        }
                    }
                    Ok(PortableCaseExportOutcome::Done(result)) => {
                        match result {
                            Ok(summary) => {
                                let path = match &self.portable_case_export_state {
                                    PortableCaseExportState::Running { path, .. } => path.clone(),
                                    _ => PathBuf::new(),
                                };
                                self.portable_case_export_state =
                                    PortableCaseExportState::Done { summary, path };
                            }
                            Err(err) => {
                                self.portable_case_export_state =
                                    PortableCaseExportState::Failed(err);
                            }
                        }
                        self.portable_case_export_rx = None;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        ui.ctx().request_repaint();
                        break;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.portable_case_export_state = PortableCaseExportState::Failed(
                            "portable case export worker disconnected unexpectedly".to_string(),
                        );
                        self.portable_case_export_rx = None;
                        break;
                    }
                }
            }
        }

        if let Some(rx) = &self.portable_case_import_rx {
            loop {
                match rx.try_recv() {
                    Ok(PortableCaseImportOutcome::Progress(stage)) => {
                        self.portable_case_import_state = PortableCaseImportState::Running(stage);
                    }
                    Ok(PortableCaseImportOutcome::Done(result)) => {
                        match result {
                            Ok(session_paths) => {
                                match self.load_session(session_paths.sqlite_path) {
                                    Ok(()) => {
                                        self.portable_case_import_state =
                                            PortableCaseImportState::Done {
                                                display_name: self.session_display_name.clone(),
                                            };
                                        let title = format!(
                                            "Imported: {}",
                                            self.session_display_name
                                                .clone()
                                                .unwrap_or_else(|| self.session_paths.id.clone())
                                        );
                                        self.open_case_summary_dialog(title);
                                    }
                                    Err(err) => {
                                        self.portable_case_import_state =
                                            PortableCaseImportState::Failed(format!(
                                                "imported, but failed to switch into the new \
                                                 session: {err:#}"
                                            ));
                                    }
                                }
                            }
                            Err(err) => {
                                self.portable_case_import_state =
                                    PortableCaseImportState::Failed(err);
                            }
                        }
                        self.portable_case_import_rx = None;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        ui.ctx().request_repaint();
                        break;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.portable_case_import_state = PortableCaseImportState::Failed(
                            "portable case import worker disconnected unexpectedly".to_string(),
                        );
                        self.portable_case_import_rx = None;
                        break;
                    }
                }
            }
        }

        let can_switch_session = !matches!(self.load_state, LoadState::Loading { .. })
            && !matches!(self.retag_state, RetagState::Running)
            && !matches!(
                self.portable_case_export_state,
                PortableCaseExportState::Running { .. }
            )
            && !matches!(
                self.portable_case_import_state,
                PortableCaseImportState::Running(_)
            );

        egui::Panel::top("menu_bar").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui
                        .add_enabled(can_switch_session, egui::Button::new("New session"))
                        .on_hover_text(
                            "Starts a fresh, empty session — the one you're leaving stays on \
                             disk (via Manage sessions...) as long as it has data loaded into \
                             it.",
                        )
                        .clicked()
                    {
                        ui.close();
                        self.new_session();
                    }
                    if ui
                        .add_enabled(can_switch_session, egui::Button::new("Manage sessions..."))
                        .clicked()
                    {
                        ui.close();
                        self.open_session_manager_dialog();
                    }
                    ui.separator();
                    let can_export = self.timeline.total_rows() > 0
                        && self.file_pick_rx.is_none()
                        && !matches!(self.export_state, ExportState::Running { .. })
                        && !matches!(
                            self.portable_case_export_state,
                            PortableCaseExportState::Running { .. }
                        )
                        && !matches!(
                            self.portable_case_import_state,
                            PortableCaseImportState::Running(_)
                        );
                    if ui
                        .add_enabled(can_export, egui::Button::new("Export (current filter)..."))
                        .on_hover_text(
                            "Exports exactly what the timeline is showing right now — clear \
                             the search box first to export everything.",
                        )
                        .clicked()
                    {
                        ui.close();
                        let task = rfd::AsyncFileDialog::new()
                            .add_filter("CSV", &["csv"])
                            .add_filter("JSON", &["json"])
                            .set_file_name("peach_export.csv")
                            .save_file();
                        self.file_pick_rx = Some(spawn_dialog_pick(task, |picked| {
                            FilePickOutcome::ExportTarget(
                                picked.map(|h: rfd::FileHandle| h.path().to_path_buf()),
                            )
                        }));
                    }
                    let can_export_portable_case = can_switch_session
                        && self.timeline.total_rows() > 0
                        && self.file_pick_rx.is_none()
                        && !matches!(self.export_state, ExportState::Running { .. });
                    if ui
                        .add_enabled(
                            can_export_portable_case,
                            egui::Button::new("Export portable case..."),
                        )
                        .on_hover_text(
                            "Bundles this session (or, with an active search, just the \
                             matching subset) into a single file another analyst's Peach can \
                             import — unlike the row export above, raw data, tags, and notes \
                             all travel intact.",
                        )
                        .clicked()
                    {
                        ui.close();
                        self.open_portable_case_export_preview();
                    }
                    let can_import_portable_case = can_switch_session
                        && self.file_pick_rx.is_none()
                        && !matches!(self.export_state, ExportState::Running { .. });
                    if ui
                        .add_enabled(
                            can_import_portable_case,
                            egui::Button::new("Import portable case..."),
                        )
                        .on_hover_text(
                            "Opens a .peachcase bundle as a brand-new session — the session \
                             you're in now is left untouched.",
                        )
                        .clicked()
                    {
                        ui.close();
                        let task = rfd::AsyncFileDialog::new()
                            .add_filter("Peach Case", &["peachcase"])
                            .pick_file();
                        self.file_pick_rx = Some(spawn_dialog_pick(
                            task,
                            |picked: Option<rfd::FileHandle>| {
                                FilePickOutcome::PortableCaseImportSource(
                                    picked.map(|h| h.path().to_path_buf()),
                                )
                            },
                        ));
                    }
                    ui.separator();
                    if ui.button("Rule packs...").clicked() {
                        self.rule_pack_dialog = RulePackDialog::open();
                        ui.close();
                    }
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
                    ui.separator();
                    if ui.button("Display timezone...").clicked() {
                        self.display_timezone_dialog =
                            DisplayTimezoneDialog::open(self.settings.display_timezone.as_deref());
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Activity Log...").clicked() {
                        self.open_activity_log_dialog();
                        ui.close();
                    }
                    if ui
                        .add_enabled(
                            self.timeline.total_rows() > 0,
                            egui::Button::new("Case Summary..."),
                        )
                        .on_hover_text(
                            "Entries per source/sourcetype/level, tag coverage, and the \
                             covered time range for the whole session.",
                        )
                        .clicked()
                    {
                        self.open_case_summary_dialog("Case Summary".to_string());
                        ui.close();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About Peach...").clicked() {
                        self.about_dialog = AboutDialog::open();
                        ui.close();
                    }
                    if ui.button("Rules reference...").clicked() {
                        self.rules_reference_dialog = RulesReferenceDialog::open();
                        ui.close();
                    }
                });
            });
        });

        egui::Panel::top("controls").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Session: {}",
                    self.session_display_name
                        .as_deref()
                        // An empty string means the analyst cleared a
                        // previously-set name (see `session_dialog`'s
                        // "Rename..." Save handler) — same fallback to the
                        // raw id as `SessionEntry::label()` uses.
                        .filter(|name| !name.is_empty())
                        .unwrap_or(&self.session_paths.id)
                ));
                if ui
                    .add_enabled(can_switch_session, egui::Button::new("Manage sessions..."))
                    .clicked()
                {
                    self.open_session_manager_dialog();
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
                ui.selectable_value(
                    &mut self.source_kind,
                    SourceKind::IntrusionLog,
                    "Android Intrusion Log",
                );
                if !self.pending_cli_sources.is_empty() {
                    ui.label(format!(
                        "({} more source(s) queued from --add-source)",
                        self.pending_cli_sources.len()
                    ));
                }
            });

            ui.horizontal(|ui| {
                if matches!(self.source_kind, SourceKind::Aul | SourceKind::IntrusionLog) {
                    let folder_label = match self.source_kind {
                        SourceKind::Aul => "Choose .logarchive folder...",
                        SourceKind::IntrusionLog => "Choose intrusion-logs folder...",
                        _ => unreachable!("handled by the outer matches! above"),
                    };
                    if ui
                        .add_enabled(self.file_pick_rx.is_none(), egui::Button::new(folder_label))
                        .clicked()
                    {
                        let task = rfd::AsyncFileDialog::new().pick_folder();
                        self.file_pick_rx = Some(spawn_dialog_pick(task, |picked| {
                            FilePickOutcome::SourcePaths(
                                picked.map(|h: rfd::FileHandle| vec![h.path().to_path_buf()]),
                            )
                        }));
                    }
                } else {
                    let (file_label, extension_filter) = match self.source_kind {
                        SourceKind::Evtx => ("Choose .evtx file(s)...", Some(("EVTX", "evtx"))),
                        SourceKind::Journald => {
                            ("Choose .journal file(s)...", Some(("journald", "journal")))
                        }
                        SourceKind::Text => ("Choose log file(s)...", None),
                        SourceKind::Aul | SourceKind::IntrusionLog => {
                            unreachable!("handled above")
                        }
                    };
                    if ui
                        .add_enabled(self.file_pick_rx.is_none(), egui::Button::new(file_label))
                        .on_hover_text(
                            "Select several to queue them as separate sources, loaded one \
                             after another — each still needs its own \"Load\" click, same as \
                             a single file",
                        )
                        .clicked()
                    {
                        let mut dialog = rfd::AsyncFileDialog::new();
                        if let Some((name, ext)) = extension_filter {
                            dialog = dialog.add_filter(name, &[ext]);
                        }
                        let task = dialog.pick_files();
                        self.file_pick_rx = Some(spawn_dialog_pick(task, |picked| {
                            FilePickOutcome::SourcePaths(picked.map(
                                |handles: Vec<rfd::FileHandle>| {
                                    handles.iter().map(|h| h.path().to_path_buf()).collect()
                                },
                            ))
                        }));
                    }
                    if ui
                        .add_enabled(
                            self.file_pick_rx.is_none(),
                            egui::Button::new("Choose folder..."),
                        )
                        .on_hover_text(
                            "Recursively loads every matching file found in the folder \
                             (and its subfolders) as separate sources",
                        )
                        .clicked()
                    {
                        let task = rfd::AsyncFileDialog::new().pick_folder();
                        self.file_pick_rx = Some(spawn_dialog_pick(task, |picked| {
                            FilePickOutcome::SourcePaths(
                                picked.map(|h: rfd::FileHandle| vec![h.path().to_path_buf()]),
                            )
                        }));
                    }
                }
                if let Some(source_path) = &self.source_path {
                    ui.label(source_path.display().to_string());
                }
            });

            if self.source_kind == SourceKind::Text {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.file_pick_rx.is_none(),
                            egui::Button::new("Choose parser config (TOML)..."),
                        )
                        .clicked()
                    {
                        let task = rfd::AsyncFileDialog::new()
                            .add_filter("TOML", &["toml"])
                            .pick_file();
                        self.file_pick_rx = Some(spawn_dialog_pick(task, |picked| {
                            FilePickOutcome::ParserConfigFile(
                                picked.map(|h: rfd::FileHandle| h.path().to_path_buf()),
                            )
                        }));
                    }
                    if let Some(config_path) = &self.parser_config_path {
                        ui.label(config_path.display().to_string());
                    }
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.source_path.is_some(),
                            egui::Button::new("Define format..."),
                        )
                        .on_hover_text(
                            "Build a parser config with a live preview against this source's \
                             own lines, instead of hand-editing TOML.",
                        )
                        .clicked()
                    {
                        self.open_format_dialog();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Assume timezone for logs with no timezone of their own:");
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.default_source_timezone_input)
                            .desired_width(160.0)
                            .hint_text("+0100, +02:00, UTC, or Europe/Berlin"),
                    );
                    match settings_dialog::parse_timezone_field(&self.default_source_timezone_input)
                    {
                        Ok(value) => {
                            // Only on an actual edit, not every frame — a
                            // `config::save` per frame regardless of change
                            // would be pure waste, and this field is valid
                            // (or blank) far more of the time than the
                            // display-timezone field below, since it's only
                            // ever a fallback rather than something typed
                            // character-by-character toward a specific goal.
                            if response.changed() && value != self.settings.default_source_timezone
                            {
                                self.settings.default_source_timezone = value;
                                if let Err(err) = config::save(&self.settings) {
                                    eprintln!(
                                        "peach: failed to save default source timezone: {err:#}"
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            ui.colored_label(ui.visuals().error_fg_color, err);
                        }
                    }
                })
                .response
                .on_hover_text(
                    "Fallback when a text source's own \"Assume offset\" isn't set. \
                     Applies immediately.",
                );
            }

            ui.horizontal(|ui| {
                if builtin_rules_button_is_relevant(self.source_kind, &self.loaded_sources)
                    && ui
                        .button("Built-in rules...")
                        .on_hover_text(
                            "Choose exactly which built-in AUL/EVTX rules apply on every load \
                             and re-tag, regardless of which rule files are also selected \
                             below. Every built-in rule is enabled by default.",
                        )
                        .clicked()
                {
                    self.builtin_rules_dialog = BuiltinRulesDialog::open();
                }

                if ui
                    .add_enabled(
                        self.file_pick_rx.is_none(),
                        egui::Button::new("Choose tagging rules (TOML, optional)..."),
                    )
                    .clicked()
                {
                    let mut dialog = rfd::AsyncFileDialog::new().add_filter("TOML", &["toml"]);
                    // Opens where rule files actually live by default — the
                    // configured rules directory (same one auto-loaded at
                    // startup, see `PeachApp::new`) — rather than wherever
                    // the OS picker last happened to be.
                    if let Ok(dir) = self.settings.rules_dir() {
                        dialog = dialog.set_directory(dir);
                    }
                    let task = dialog.pick_files();
                    self.file_pick_rx = Some(spawn_dialog_pick(task, |picked| {
                        FilePickOutcome::RuleFiles(picked.map(|handles: Vec<rfd::FileHandle>| {
                            handles.iter().map(|h| h.path().to_path_buf()).collect()
                        }))
                    }));
                }
                if self.rule_paths.is_empty() {
                    ui.label("(no extra rule files selected)");
                } else {
                    ui.label(format!("{} rule file(s) selected", self.rule_paths.len()));
                }

                let can_retag = !matches!(self.load_state, LoadState::Loading { .. })
                    && !matches!(self.retag_state, RetagState::Running)
                    && !matches!(
                        self.portable_case_export_state,
                        PortableCaseExportState::Running { .. }
                    )
                    && !matches!(
                        self.portable_case_import_state,
                        PortableCaseImportState::Running(_)
                    )
                    && (!self.rule_paths.is_empty() || !self.enabled_builtin_rules.is_empty())
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
                    RetagState::Done {
                        applied,
                        tags_by_rule,
                    } => {
                        let response = ui.label(format!("Re-tag applied {applied} tags"));
                        if !tags_by_rule.is_empty() {
                            response.on_hover_ui(|ui| {
                                let mut rules: Vec<(&String, &usize)> =
                                    tags_by_rule.iter().collect();
                                rules.sort_by(|a, b| a.0.cmp(b.0));
                                for (rule_name, count) in rules {
                                    ui.label(format!("{rule_name}: {count}"));
                                }
                            });
                        }
                    }
                    RetagState::Failed(err) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {err}"));
                    }
                }
            });

            match &self.export_state {
                ExportState::Idle => {}
                ExportState::Running { rows_written, .. } => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!("Exporting... {rows_written} rows so far"));
                    });
                }
                ExportState::Done { rows_written, path } => {
                    ui.label(format!(
                        "Export complete: {rows_written} rows to {}",
                        path.display()
                    ));
                }
                ExportState::Failed(err) => {
                    ui.colored_label(egui::Color32::RED, format!("Export failed: {err}"));
                }
            }

            match &self.portable_case_export_state {
                PortableCaseExportState::Idle => {}
                PortableCaseExportState::Running { stage, .. } => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!(
                            "Exporting portable case... {}",
                            portable_case_export_stage_label(*stage)
                        ));
                    });
                }
                PortableCaseExportState::Done { summary, path } => {
                    ui.label(format!(
                        "Portable case complete: {} entries, {} tags, to {}",
                        summary.entries_written,
                        summary.tags_written,
                        path.display()
                    ));
                }
                PortableCaseExportState::Failed(err) => {
                    ui.colored_label(
                        egui::Color32::RED,
                        format!("Portable case export failed: {err}"),
                    );
                }
            }

            match &self.portable_case_import_state {
                PortableCaseImportState::Idle => {}
                PortableCaseImportState::Running(stage) => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!(
                            "Importing portable case... {}",
                            portable_case_import_stage_label(*stage)
                        ));
                    });
                }
                PortableCaseImportState::Done { display_name } => {
                    ui.label(format!(
                        "Portable case imported and opened: {}",
                        display_name.as_deref().unwrap_or(&self.session_paths.id)
                    ));
                }
                PortableCaseImportState::Failed(err) => {
                    ui.colored_label(
                        egui::Color32::RED,
                        format!("Portable case import failed: {err}"),
                    );
                }
            }

            let can_load = !matches!(self.load_state, LoadState::Loading { .. })
                && !matches!(self.retag_state, RetagState::Running)
                && !matches!(
                    self.portable_case_export_state,
                    PortableCaseExportState::Running { .. }
                )
                && !matches!(
                    self.portable_case_import_state,
                    PortableCaseImportState::Running(_)
                )
                && self.source_path.is_some()
                && (self.source_kind != SourceKind::Text || self.parser_config_path.is_some());

            ui.add_enabled(
                !matches!(self.load_state, LoadState::Loading { .. }),
                egui::Checkbox::new(
                    &mut self.skip_bad_records,
                    "Skip bad records instead of failing",
                ),
            )
            .on_hover_text(
                "If a line/record can't be parsed, skip it and keep going instead of aborting \
                 the whole file. Off by default — a bad record normally stops the file's load \
                 entirely, so nothing is ever silently incomplete. When on, how many records \
                 were skipped (and why) is recorded in the Activity Log, per file.",
            );

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(can_load, egui::Button::new("Load"))
                    .clicked()
                {
                    self.start_load();
                }
                if matches!(self.load_state, LoadState::Loading { .. })
                    && ui
                        .button("Abort")
                        .on_hover_text(
                            "Stops after the file currently being parsed finishes (or, for a \
                             large single file, at the next internal checkpoint) — whatever's \
                             already inserted stays; nothing gets rolled back.",
                        )
                        .clicked()
                    && let Some(cancel) = &self.load_cancel
                {
                    cancel.store(true, Ordering::Relaxed);
                }
                match &self.load_state {
                    LoadState::Idle => {}
                    LoadState::Loading {
                        inserted_so_far,
                        bytes_done,
                        bytes_total,
                        total_entries,
                    } => {
                        ui.spinner();
                        // Data-based progress — file-level granularity (jumps
                        // per completed file, not smooth within one large
                        // file; see `run_load`'s doc comment for why entry
                        // count can't drive a real fraction here either) —
                        // except for AUL, where `on_bytes_progress` advances
                        // per `.tracev3` file within the one `.logarchive`.
                        if *bytes_total > 0 {
                            let fraction = *bytes_done as f32 / *bytes_total as f32;
                            ui.add(egui::ProgressBar::new(fraction).desired_width(200.0).text(
                                format!(
                                    "Parsing: {:.1} / {:.1} MB",
                                    *bytes_done as f64 / 1_000_000.0,
                                    *bytes_total as f64 / 1_000_000.0
                                ),
                            ));
                        }
                        // Once AUL's parsing phase ends, `bytes_done` is
                        // already pinned at `bytes_total` (100%) while the
                        // DB insert + tagging phase — often the larger share
                        // of total load time — is still running; without
                        // this second bar that phase would show only a raw
                        // climbing count with no sense of how much is left.
                        // `total_entries` stays `None` for every other
                        // sourcetype (see `LoadOutcome::Progress`'s doc
                        // comment), so this just falls through to the same
                        // plain count they've always shown.
                        match total_entries {
                            Some(total) if *total > 0 => {
                                let fraction = *inserted_so_far as f32 / *total as f32;
                                ui.add(
                                    egui::ProgressBar::new(fraction).desired_width(200.0).text(
                                        format!("Writing: {inserted_so_far} / {total} entries"),
                                    ),
                                );
                            }
                            _ if *inserted_so_far > 0 => {
                                ui.label(format!("Loading... {inserted_so_far} entries so far"));
                            }
                            _ => {
                                ui.label("Loading...");
                            }
                        }
                    }
                    LoadState::Done {
                        inserted,
                        tags_applied,
                        elapsed,
                        skipped,
                        records_skipped,
                        cancelled,
                    } => {
                        ui.label(format!(
                            "Loaded {inserted} entries, applied {tags_applied} tags in {:.1}s",
                            elapsed.as_secs_f64()
                        ));
                        if *cancelled {
                            ui.colored_label(egui::Color32::from_rgb(230, 160, 0), "Aborted");
                        }
                        if *records_skipped > 0 {
                            ui.colored_label(
                                egui::Color32::from_rgb(230, 160, 0),
                                format!(
                                    "{records_skipped} record(s) skipped (skip bad records was on)"
                                ),
                            )
                            .on_hover_text(
                                "See Activity Log for the per-file breakdown and reasons.",
                            );
                        }
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
            // Built fresh each frame, not cached like `available_levels`/
            // `available_tags`: unlike those (a background DuckDB query),
            // this is a plain map over the handful of already-in-memory
            // `loaded_sources` — no query to avoid re-running. Sources
            // loaded before this field existed (`source_file_id` empty,
            // see `LoadedSource`'s doc comment) are left out rather than
            // shown as an unclickable/always-empty chip.
            let available_sources: Vec<(String, String)> = self
                .loaded_sources
                .iter()
                .filter(|s| !s.source_file_id.is_empty())
                .map(|s| {
                    (
                        s.source_file_id.clone(),
                        source_display_label(&s.path, &s.sourcetype).to_string(),
                    )
                })
                .collect();
            if let Some(query) = self.filter_bar.ui(
                ui,
                &self.available_levels,
                &self.available_tags,
                &available_sources,
                &self.level_counts,
                &self.tag_counts,
                &self.source_counts,
            ) {
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
        self.handle_note_dialog(ui.ctx());
        self.handle_format_dialog(ui.ctx());
        self.raw_fields_dialog.ui(ui.ctx());
        self.handle_session_dialog(ui.ctx());
        self.handle_settings_dialog(ui.ctx());
        self.handle_display_timezone_dialog(ui.ctx());
        self.about_dialog.ui(ui.ctx());
        self.activity_log_dialog.ui(ui.ctx());
        self.handle_case_summary_dialog(ui.ctx());
        self.builtin_rules_dialog
            .ui(ui.ctx(), &mut self.enabled_builtin_rules);
        self.rules_reference_dialog.ui(ui.ctx());
        self.handle_rule_pack_dialog(ui.ctx());
    }
}

/// Rows held in memory at once between flushes to DuckDB. Bounds peak RSS
/// to O(batch), not O(source size) — see the module doc on `run_load` for
/// why that distinction actually matters here.
const LOAD_BATCH_SIZE: usize = 10_000;

/// Resolves `source_path` to the concrete list of files [`run_load`] will
/// parse, one file = one independent parse run = one `source_file_id`/
/// `sources` row (see [`load_one_file`]). AUL's `.logarchive` and an
/// intrusion-log export are always one atomic source each (never split up)
/// regardless of `source_path` being a directory — both parsers walk their
/// own directory internally (see [`crate::parsers::aul::AulParser`],
/// [`crate::parsers::intrusion_log::IntrusionLogParser`]) — and a plain
/// file pick for any sourcetype is always exactly itself; all three
/// short-circuit before ever touching the filesystem beyond `source_path`
/// itself.
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
    if matches!(source_kind, SourceKind::Aul | SourceKind::IntrusionLog) || source_path.is_file() {
        return vec![source_path.to_path_buf()];
    }
    let extension_filter: Option<&str> = match source_kind {
        SourceKind::Evtx => Some("evtx"),
        SourceKind::Journald => Some("journal"),
        SourceKind::Text | SourceKind::Aul | SourceKind::IntrusionLog => None,
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
/// directory (AUL's `.logarchive` or an intrusion-log export — the only two
/// sourcetypes [`collect_source_files`] ever hands a directory to this
/// function, since every other sourcetype's folder pick resolves to
/// individual files first), the sum of just the files that sourcetype's
/// parser actually reads (`.tracev3` for AUL, `.txt` for intrusion_log).
/// `path.metadata().len()` on a directory returns a small, meaningless
/// number (just the directory entry itself, not its contents), so that
/// shortcut can't be used for either. AUL's restriction to `.tracev3`
/// specifically (not every file under the directory — `dsc`/`uuidtext`/
/// `timesync` too) matters for a reason intrusion_log doesn't share: it
/// must match exactly what [`AulParser`]'s own `on_bytes_progress`
/// reporting sums to (see its doc comment), or the progress bar would stall
/// short of 100% instead of reaching it cleanly — `IntrusionLogParser` has
/// no such per-file progress reporting (the default `parse_streaming`
/// wrapper), so its own `.txt`-only restriction is just "don't count files
/// this parser doesn't read" rather than a progress-matching requirement.
fn path_byte_size(sourcetype: &str, path: &Path) -> u64 {
    if path.is_dir() {
        let extension: &str = if sourcetype == "intrusion_log" {
            "txt"
        } else {
            "tracev3"
        };
        walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
            })
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
/// which built-in rules (by name, from either
/// `tagging::builtin::aul_pattern_of_life_rules` or
/// `evtx_security_auditing_rules`) are also merged in. A struct rather than
/// two more `run_load` parameters, same reasoning as [`LoadContext`]
/// bundling its own fields.
struct RuleSelection<'a> {
    paths: &'a [PathBuf],
    enabled_builtin_rules: &'a std::collections::BTreeSet<String>,
}

/// How the caller watches/steers an in-flight load — where to report
/// progress, and how it notices "Abort" was clicked. Bundled together
/// rather than two more `run_load` parameters, same reasoning as
/// [`RuleSelection`]/[`LoadContext`] (and keeps `run_load` under clippy's
/// `too_many_arguments` threshold).
struct LoadControl<'a> {
    progress_tx: &'a mpsc::Sender<LoadOutcome>,
    cancel: Arc<AtomicBool>,
}

/// Settings-derived values `run_load` needs but that don't belong on
/// [`RuleSelection`]/[`LoadControl`] — bundled for the same
/// clippy-argument-count reason as those two, not because these two
/// particularly belong together.
struct LoadSettings {
    thread_count: usize,
    /// `Settings::default_source_timezone` — only used for
    /// `SourceKind::Text` (`TextConfigParser::default_assume_offset`); every
    /// other sourcetype's own timestamps are already absolute, see
    /// `parsers::text_config`'s own doc comment on why only text sources
    /// ever need this at all.
    default_source_timezone: Option<String>,
    /// "Skip bad records instead of failing" — the analyst's per-load,
    /// off-by-default choice (see `PeachApp::skip_bad_records`). `false`
    /// preserves every parser's original behavior exactly: the first bad
    /// record still aborts the whole file.
    skip_bad_records: bool,
}

fn run_load(
    source_kind: SourceKind,
    source_path: &Path,
    parser_config_path: Option<&Path>,
    rules: RuleSelection,
    conn: duckdb::Connection,
    settings: LoadSettings,
    control: LoadControl,
) -> anyhow::Result<LoadSummary> {
    setup_timeline_schema(&conn)?;

    // Constructed unconditionally, not just inside the `SourceKind::Text`
    // match arm below: `&dyn LogParser` needs something to borrow from for
    // the rest of this function, and only the arm that's actually taken
    // ever gets referenced — the other unit structs cost nothing to
    // instantiate. `text_parser` is the only one that isn't a plain unit
    // struct (it carries `default_source_timezone`), which is exactly why
    // this had to move out of the match arm: a value constructed *inside*
    // an arm doesn't live long enough to be borrowed as `&dyn LogParser`
    // past the match.
    let aul_parser = AulParser;
    let evtx_parser = EvtxFileParser;
    let journald_parser = JournaldFileParser;
    let intrusion_log_parser = IntrusionLogParser;
    let text_parser = TextConfigParser {
        default_assume_offset: settings.default_source_timezone,
    };

    let (parser, config): (&dyn LogParser, ParserConfig) = match source_kind {
        SourceKind::Aul => (
            &aul_parser,
            ParserConfig::from_toml_str("[parser]\nname = \"aul\"\nsourcetype = \"aul\"\n")?,
        ),
        SourceKind::IntrusionLog => (
            &intrusion_log_parser,
            ParserConfig::from_toml_str(
                "[parser]\nname = \"intrusion_log\"\nsourcetype = \"intrusion_log\"\n",
            )?,
        ),
        SourceKind::Evtx => (
            &evtx_parser,
            ParserConfig::from_toml_str("[parser]\nname = \"evtx\"\nsourcetype = \"evtx\"\n")?,
        ),
        SourceKind::Journald => (
            &journald_parser,
            ParserConfig::from_toml_str(
                "[parser]\nname = \"journald\"\nsourcetype = \"journald\"\n",
            )?,
        ),
        SourceKind::Text => {
            let config_path = parser_config_path
                .ok_or_else(|| anyhow::anyhow!("no parser config selected for a text source"))?;
            let config_text = std::fs::read_to_string(config_path)?;
            (&text_parser, ParserConfig::from_toml_str(&config_text)?)
        }
    };
    // The config's sourcetype is authoritative, not `parser.sourcetype()`:
    // TextConfigParser serves many different sourcetypes (nginx, syslog,
    // ...) depending on which config is loaded, so its own sourcetype() is
    // just a generic marker (see parsers/mod.rs doc comment).
    let sourcetype = config.parser.sourcetype.clone();
    let rules = load_rules(rules.paths, rules.enabled_builtin_rules)?;

    let files = collect_source_files(source_kind, source_path);
    if files.is_empty() {
        anyhow::bail!("no matching files found under {}", source_path.display());
    }
    let bytes_total: u64 = files
        .iter()
        .map(|path| path_byte_size(&sourcetype, path))
        .sum();

    let load_ctx = LoadContext {
        parser,
        config: &config,
        sourcetype: &sourcetype,
        rules: &rules,
        parser_config_path,
        cancel: Arc::clone(&control.cancel),
        skip_bad_records: settings.skip_bad_records,
    };

    let mut summary = if files.len() <= 1 {
        run_sequential(&load_ctx, files, &conn, bytes_total, control.progress_tx)?
    } else {
        run_parallel(
            &load_ctx,
            files,
            &conn,
            bytes_total,
            settings.thread_count,
            control.progress_tx,
        )?
    };
    summary.cancelled = control.cancel.load(Ordering::Relaxed);

    // One follow-up query against `import_tags` (already has `rule_name`
    // per row) rather than threading a per-rule breakdown through
    // `run_sequential`/`run_parallel`'s per-file tagging calls — scoped to
    // just this load's own `source_file_id`s so a re-tag-driven or earlier
    // load's tags in the same session don't leak into this load's numbers.
    let source_file_ids: Vec<String> = summary
        .loaded_sources
        .iter()
        .map(|source| source.source_file_id.clone())
        .collect();
    summary.tags_by_rule = timeline_queries::rule_counts_for_sources(&conn, &source_file_ids)?;

    Ok(summary)
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
    /// Set by the "Abort" button (`PeachApp::load_cancel`) to stop an
    /// in-flight load early — checked between files in
    /// `run_sequential`/`run_parallel`'s loops and inside the per-batch
    /// streaming sink in `load_one_file`/`parse_file_for_worker`. An `Arc`
    /// (not a plain `bool`) because it has to be visible from both this
    /// background load thread and the UI thread's click handler at once.
    cancel: Arc<AtomicBool>,
    /// See [`LoadSettings::skip_bad_records`].
    skip_bad_records: bool,
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
        per_file_inserted: std::collections::BTreeMap::new(),
        per_file_records_skipped: std::collections::BTreeMap::new(),
        records_skipped: 0,
        tags_by_rule: HashMap::new(),
        cancelled: false,
    };
    let mut total_inserted = 0usize;
    let mut bytes_done = 0u64;

    for file_path in files {
        // Already cancelled before this file even started (e.g. "Abort"
        // clicked while between-files, or before the load began at all) —
        // don't start parsing something that's just going to be discarded.
        if ctx.cancel.load(Ordering::Relaxed) {
            break;
        }
        let file_bytes = path_byte_size(ctx.sourcetype, &file_path);
        match load_one_file(
            ctx,
            &file_path,
            conn,
            &mut total_inserted,
            bytes_done,
            bytes_total,
            progress_tx,
        ) {
            Ok(Some((
                tags_applied,
                loaded_source,
                inserted_this_file,
                records_skipped_this_file,
            ))) => {
                summary.tags_applied += tags_applied;
                summary.records_skipped += records_skipped_this_file;
                summary
                    .per_file_inserted
                    .insert(loaded_source.path.clone(), inserted_this_file);
                if records_skipped_this_file > 0 {
                    summary
                        .per_file_records_skipped
                        .insert(loaded_source.path.clone(), records_skipped_this_file);
                }
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
            // The file this send reports on just finished entirely (insert
            // + tagging included), so whatever `total_entries` it may have
            // reported mid-file is moot now — and the next file (if any)
            // starts its own count from scratch.
            total_entries: None,
        });
        // Checked here (between files) in addition to inside
        // `load_one_file`'s own per-batch check: a file that finished (or
        // was itself cancelled) right as "Abort" was clicked must not be
        // followed by starting another one.
        if ctx.cancel.load(Ordering::Relaxed) {
            break;
        }
    }
    summary.inserted = total_inserted;

    Ok(summary)
}

/// Parses one file and, if it produced anything, appends it to
/// `log_entries`/`sources`. `total_inserted` is threaded through by `&mut`
/// rather than returned fresh, so [`LoadOutcome::Progress`] keeps
/// reporting one running total, not a per-file count that resets and
/// confuses "how far along is this." `bytes_done_before`/`bytes_total`
/// seed the running byte count for this file's parsing — for most
/// sourcetypes (a single real file) that count only advances once this
/// whole call returns (see [`run_sequential`]/[`run_parallel`]), so it
/// stays flat while this one is in flight and only `inserted` climbs
/// live. AUL is the exception: its parser reports incremental progress
/// per `.tracev3` file via `on_bytes_progress`, so for an AUL source
/// `bytes_done` also climbs during the call, not just at the end.
///
/// `Ok(None)` — not an error — when the file parsed cleanly but matched
/// zero entries: still worth a note in the skip report ([`run_load`]), but
/// not a parse failure, so it's kept distinct from `Err`. On `Ok(Some(...))`,
/// the third element is this file's own insert count (not the running
/// `total_inserted`) — [`LoadSummary::per_file_inserted`]'s source — and the
/// fourth is how many records `ctx.skip_bad_records` let it skip instead of
/// aborting — [`LoadSummary::per_file_records_skipped`]'s source.
///
/// A mid-file [`LoadCancelled`] (the "Abort" button, `ctx.cancel`) also
/// surfaces here as `Ok(Some(...))`/`Ok(None)` rather than `Err` — whatever
/// was flushed before the cancel is a perfectly valid, if smaller than
/// usual, result; the caller ([`run_sequential`]/[`run_parallel`]) learns
/// the load was cancelled by checking `ctx.cancel` itself, not from this
/// return value.
fn load_one_file(
    ctx: &LoadContext,
    file_path: &Path,
    conn: &duckdb::Connection,
    total_inserted: &mut usize,
    bytes_done_before: u64,
    bytes_total: u64,
    progress_tx: &mpsc::Sender<LoadOutcome>,
) -> anyhow::Result<Option<(usize, LoadedSource, usize, usize)>> {
    let mut batch: Vec<LogEntry> = Vec::with_capacity(LOAD_BATCH_SIZE);
    let mut inserted_this_file = 0usize;
    let mut tags_applied = 0usize;
    // Interior mutability, not `&mut total_inserted` directly: the
    // progress-reporting closures below need to read the running insert
    // count for their own progress sends, and the entry-sink closure needs
    // to mutate it — two separate `FnMut` closures can't both hold a
    // `&mut` (or a `&mut` and a `&`) to the same location, but both can
    // hold a `&Cell` and stay within Rust's aliasing rules. Written back to
    // `*total_inserted` once `parse_source_streaming` returns.
    let inserted_cell = std::cell::Cell::new(*total_inserted);
    let bytes_done_cell = std::cell::Cell::new(bytes_done_before);
    let total_entries_cell: std::cell::Cell<Option<usize>> = std::cell::Cell::new(None);
    // Every entry carries the same `source_file_id` (assigned once per file
    // by `parse_source_streaming`, before the first one reaches this sink),
    // so capturing it off the first entry gives `load_one_file` its own copy
    // even if streaming is cut short by [`LoadCancelled`] below —
    // `parse_source_streaming`'s `Err` path doesn't return the id at all.
    let captured_source_file_id: std::cell::Cell<Option<SourceFileId>> = std::cell::Cell::new(None);
    let send_progress = |inserted: usize, bytes_done: u64, total_entries: Option<usize>| {
        // Best-effort: if the UI thread has already dropped its receiver
        // (e.g. app shutting down mid-load), there's nobody to tell and the
        // load itself must still proceed.
        let _ = progress_tx.send(LoadOutcome::Progress {
            inserted,
            bytes_done,
            bytes_total,
            total_entries,
        });
    };

    let stream_result = parse_source_streaming(
        ctx.parser,
        file_path,
        ctx.config,
        |entry| {
            if captured_source_file_id.get().is_none() {
                captured_source_file_id.set(Some(entry.event_id.source_file_id));
            }
            inserted_this_file += 1;
            inserted_cell.set(inserted_cell.get() + 1);
            batch.push(entry);
            if batch.len() >= LOAD_BATCH_SIZE {
                tags_applied += flush_batch(conn, &mut batch, ctx.rules, ctx.sourcetype)?;
                send_progress(
                    inserted_cell.get(),
                    bytes_done_cell.get(),
                    total_entries_cell.get(),
                );
                if ctx.cancel.load(Ordering::Relaxed) {
                    anyhow::bail!(LoadCancelled);
                }
            }
            Ok(())
        },
        &mut StreamingProgress {
            on_bytes: &mut |delta| {
                bytes_done_cell.set(bytes_done_cell.get() + delta);
                send_progress(
                    inserted_cell.get(),
                    bytes_done_cell.get(),
                    total_entries_cell.get(),
                );
            },
            on_total_known: &mut |total| {
                total_entries_cell.set(Some(total));
                send_progress(inserted_cell.get(), bytes_done_cell.get(), Some(total));
            },
        },
        ctx.skip_bad_records,
    );
    *total_inserted = inserted_cell.get();

    // A batch already flushed above (right before the cancel check that
    // fired) leaves nothing in `batch` — this only ever has something to do
    // for a normal end-of-file remainder under `LOAD_BATCH_SIZE`.
    // A cancelled stream reports no `SkippedRecord`s of its own (the `Err`
    // path carries none) — an aborted load's skip accounting just stays at
    // 0, a minor gap next to the much bigger fact that the file itself was
    // cut short.
    let (source_file_id, records_skipped) = match stream_result {
        Ok((id, skipped)) => (id, skipped.len()),
        Err(err) if err.is::<LoadCancelled>() => match captured_source_file_id.get() {
            Some(id) if inserted_this_file > 0 => (id, 0),
            _ => return Ok(None),
        },
        Err(err) => return Err(err),
    };
    tags_applied += flush_batch(conn, &mut batch, ctx.rules, ctx.sourcetype)?;

    if inserted_this_file == 0 {
        return Ok(None);
    }
    insert_source_record(conn, source_file_id, file_path, ctx.sourcetype)?;

    let loaded_source = LoadedSource {
        path: file_path.display().to_string(),
        sourcetype: ctx.sourcetype.to_string(),
        parser_config_path: ctx.parser_config_path.map(|p| p.display().to_string()),
        source_file_id: source_file_id.to_string(),
    };
    Ok(Some((
        tags_applied,
        loaded_source,
        inserted_this_file,
        records_skipped,
    )))
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
        /// See `load_one_file`'s doc comment on its own fourth return
        /// value — same "0 when `source_file_id` is `None`" scope.
        records_skipped: usize,
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
        per_file_inserted: std::collections::BTreeMap::new(),
        per_file_records_skipped: std::collections::BTreeMap::new(),
        records_skipped: 0,
        tags_by_rule: HashMap::new(),
        cancelled: false,
    };
    let mut total_inserted = 0usize;
    let mut bytes_done = 0u64;
    let mut write_error = None;
    // Batches from different files arrive interleaved (multiple workers in
    // flight at once), so per-file counts can't just be a running total the
    // way `total_inserted` is — tallied by `source_file_id` here as batches
    // arrive (every `LogEntry` already carries its own, see `ParseEvent::Batch`'s
    // doc comment) and looked up by path once `FileDone` reports which path
    // that id belongs to.
    let mut inserted_by_source_id: HashMap<SourceFileId, usize> = HashMap::new();

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
                    for entry in &entries {
                        *inserted_by_source_id
                            .entry(entry.event_id.source_file_id)
                            .or_insert(0) += 1;
                    }
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
                    records_skipped,
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
                            summary.per_file_inserted.insert(
                                file_path.display().to_string(),
                                inserted_by_source_id.get(&id).copied().unwrap_or(0),
                            );
                            summary.records_skipped += records_skipped;
                            if records_skipped > 0 {
                                summary
                                    .per_file_records_skipped
                                    .insert(file_path.display().to_string(), records_skipped);
                            }
                            summary.loaded_sources.push(LoadedSource {
                                path: file_path.display().to_string(),
                                sourcetype: ctx.sourcetype.to_string(),
                                parser_config_path: ctx
                                    .parser_config_path
                                    .map(|p| p.display().to_string()),
                                source_file_id: id.to_string(),
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
                // `run_parallel` never handles AUL (see `parse_file_for_worker`'s
                // doc comment) — the only sourcetype that can ever populate this.
                total_entries: None,
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
    // Already cancelled before this worker even got to this file (rayon
    // dispatches every file up front, regardless) — don't start parsing
    // something that's just going to be thrown away.
    if ctx.cancel.load(Ordering::Relaxed) {
        return;
    }

    let bytes = path_byte_size(ctx.sourcetype, file_path);
    let mut batch: Vec<LogEntry> = Vec::with_capacity(LOAD_BATCH_SIZE);
    let mut inserted = 0usize;
    // Same reasoning as `load_one_file`'s own capture: `parse_source_streaming`
    // only returns the id on `Ok`, but a [`LoadCancelled`] `Err` still needs
    // it to report a `FileDone` for whatever was already sent.
    let captured_source_file_id: std::cell::Cell<Option<SourceFileId>> = std::cell::Cell::new(None);

    // `on_bytes_progress` is a no-op here: `run_parallel` (this function's
    // only caller) never runs for AUL — it's always exactly one atomic
    // parse unit, so a multi-file folder load can only mean EVTX/journald/
    // Text, none of which override `parse_streaming`'s progress reporting.
    let result = parse_source_streaming(
        ctx.parser,
        file_path,
        ctx.config,
        |entry| {
            if captured_source_file_id.get().is_none() {
                captured_source_file_id.set(Some(entry.event_id.source_file_id));
            }
            inserted += 1;
            batch.push(entry);
            if batch.len() >= LOAD_BATCH_SIZE {
                let full_batch = std::mem::replace(&mut batch, Vec::with_capacity(LOAD_BATCH_SIZE));
                let _ = tx.send(ParseEvent::Batch {
                    entries: full_batch,
                });
                if ctx.cancel.load(Ordering::Relaxed) {
                    anyhow::bail!(LoadCancelled);
                }
            }
            Ok(())
        },
        &mut StreamingProgress {
            on_bytes: &mut |_| {},
            on_total_known: &mut |_| {},
        },
        ctx.skip_bad_records,
    );

    // A cancelled stream reports no `SkippedRecord`s of its own, same
    // scope decision as `load_one_file`.
    let (source_file_id, records_skipped) = match result {
        Ok((id, skipped)) => (Some(id), skipped.len()),
        Err(err) if err.is::<LoadCancelled>() => (captured_source_file_id.get(), 0),
        Err(err) => {
            let _ = tx.send(ParseEvent::FileFailed {
                file_path: file_path.to_path_buf(),
                bytes,
                reason: format!("{err:#}"),
            });
            return;
        }
    };

    if !batch.is_empty() {
        let _ = tx.send(ParseEvent::Batch { entries: batch });
    }
    let source_file_id = source_file_id.filter(|_| inserted > 0);
    // A file that produced zero entries reports no records-skipped count
    // either, even under skip mode — it already surfaces via the existing
    // "no matching entries" `SkippedFile` reason instead (see
    // `run_parallel`'s `ParseEvent::FileDone` handling); a sub-count on top
    // of that would need `load_one_file`'s zero-entry path reworked too,
    // which isn't worth it for what both cases already boil down to
    // "nothing usable came out of this file."
    let records_skipped = if source_file_id.is_some() {
        records_skipped
    } else {
        0
    };
    let _ = tx.send(ParseEvent::FileDone {
        file_path: file_path.to_path_buf(),
        bytes,
        source_file_id,
        records_skipped,
    });
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
    enabled_builtin_rules: &std::collections::BTreeSet<String>,
    conn: duckdb::Connection,
) -> anyhow::Result<RetagSummary> {
    let rules = load_rules(rule_paths, enabled_builtin_rules)?;
    re_tag(&conn, &rules)
}

/// Writes one `activity_log` row for a completed or failed load — best-effort:
/// a failure to record the entry itself is logged to stderr and otherwise
/// swallowed, same as `config::save`'s error handling elsewhere. The load
/// already succeeded or failed on its own terms by the time this runs; the
/// activity log is a record of what happened, not something a load should
/// itself fail over just because writing the record failed.
fn record_load_activity_entry(
    sqlite_path: &Path,
    source_path: &Path,
    started_at: i64,
    finished_at: i64,
    result: &anyhow::Result<LoadSummary>,
    skip_bad_records_enabled: bool,
    rules: RuleSelection,
) {
    let Ok(conn) = persist::open_session_db(sqlite_path) else {
        eprintln!("peach: failed to open session DB to record activity log entry");
        return;
    };
    let rule_versions = rule_version_lookup(rules);
    let entry = match result {
        Ok(summary) => persist::NewActivityLogEntry {
            operation: "load".to_string(),
            started_at,
            finished_at,
            source_path: Some(source_path.display().to_string()),
            sourcetype: summary
                .loaded_sources
                .first()
                .map(|source| source.sourcetype.clone()),
            status: if summary.cancelled {
                "cancelled".to_string()
            } else {
                "ok".to_string()
            },
            error: None,
            entries_inserted: Some(summary.inserted as i64),
            tags_applied: Some(summary.tags_applied as i64),
            skipped: summary
                .skipped
                .iter()
                .map(|file| persist::ActivitySkippedFile {
                    path: file.path.display().to_string(),
                    reason: file.reason.clone(),
                })
                .collect(),
            per_file: summary
                .per_file_inserted
                .iter()
                .map(|(path, inserted)| persist::ActivityFileCount {
                    path: path.clone(),
                    inserted: *inserted,
                    records_skipped: summary
                        .per_file_records_skipped
                        .get(path)
                        .copied()
                        .unwrap_or(0),
                })
                .collect(),
            tags_by_rule: rule_counts_to_activity_counts(&summary.tags_by_rule, &rule_versions),
            skip_bad_records_enabled,
        },
        Err(err) => persist::NewActivityLogEntry {
            operation: "load".to_string(),
            started_at,
            finished_at,
            source_path: Some(source_path.display().to_string()),
            sourcetype: None,
            status: "failed".to_string(),
            error: Some(format!("{err:#}")),
            entries_inserted: None,
            tags_applied: None,
            skipped: Vec::new(),
            per_file: Vec::new(),
            tags_by_rule: Vec::new(),
            skip_bad_records_enabled,
        },
    };
    if let Err(err) = persist::insert_activity_log_entry(&conn, entry) {
        eprintln!("peach: failed to record activity log entry: {err:#}");
    }
}

/// Sorted by rule name for determinism — a `HashMap`'s iteration order
/// isn't stable, and the forensic principle of "same inputs, same result"
/// (see CLAUDE.md) applies just as much to what lands in the Activity Log
/// as to anything else recorded about a load. `rule_versions` is looked up
/// by [`rule_version_lookup`] from whatever rule set actually ran — a rule
/// absent from it (shouldn't happen, since `tags_by_rule` only ever
/// contains names of rules that just matched something) gets `None`
/// rather than panicking, since a stale/mismatched lookup is not worth
/// failing an Activity Log write over.
fn rule_counts_to_activity_counts(
    tags_by_rule: &HashMap<String, usize>,
    rule_versions: &HashMap<String, Option<String>>,
) -> Vec<persist::ActivityRuleCount> {
    let mut counts: Vec<persist::ActivityRuleCount> = tags_by_rule
        .iter()
        .map(|(rule_name, count)| persist::ActivityRuleCount {
            rule_name: rule_name.clone(),
            count: *count,
            version: rule_versions.get(rule_name).cloned().flatten(),
        })
        .collect();
    counts.sort_by(|a, b| a.rule_name.cmp(&b.rule_name));
    counts
}

/// The `name → version` of every rule in the set `rule_paths`/
/// `enabled_builtin_rules` currently resolve to (see `load_rules`) — what
/// [`rule_counts_to_activity_counts`] stamps onto the Activity Log's
/// per-rule breakdown, so a load/re-tag entry answers "which rule
/// *version* produced this tag count" (`docs/design/rule-pack-updates.md`
/// §5), not just which rule. Best-effort: an unreadable rule file here
/// means a missing/`None` version for that one entry, not a failure to
/// record the Activity Log entry at all — same tolerance `load_rules`
/// itself extends elsewhere.
fn rule_version_lookup(rules: RuleSelection) -> HashMap<String, Option<String>> {
    load_rules(rules.paths, rules.enabled_builtin_rules)
        .unwrap_or_default()
        .into_iter()
        .map(|rule| (rule.rule.name, rule.rule.version))
        .collect()
}

/// Same reasoning as [`record_load_activity_entry`], for a re-tag — no
/// `source_path`/`sourcetype`/`skipped` (a re-tag applies across whatever's
/// already loaded, not to one file) or `entries_inserted` (nothing new gets
/// inserted, only `import_tags` recomputed).
fn record_retag_activity_entry(
    sqlite_path: &Path,
    started_at: i64,
    finished_at: i64,
    result: &anyhow::Result<RetagSummary>,
    rules: RuleSelection,
) {
    let Ok(conn) = persist::open_session_db(sqlite_path) else {
        eprintln!("peach: failed to open session DB to record activity log entry");
        return;
    };
    let rule_versions = rule_version_lookup(rules);
    let entry = match result {
        Ok(summary) => persist::NewActivityLogEntry {
            operation: "retag".to_string(),
            started_at,
            finished_at,
            source_path: None,
            sourcetype: None,
            status: "ok".to_string(),
            error: None,
            entries_inserted: None,
            tags_applied: Some(summary.applied as i64),
            skipped: Vec::new(),
            per_file: Vec::new(),
            tags_by_rule: rule_counts_to_activity_counts(&summary.tags_by_rule, &rule_versions),
            skip_bad_records_enabled: false,
        },
        Err(err) => persist::NewActivityLogEntry {
            operation: "retag".to_string(),
            started_at,
            finished_at,
            source_path: None,
            sourcetype: None,
            status: "failed".to_string(),
            error: Some(format!("{err:#}")),
            entries_inserted: None,
            tags_applied: None,
            skipped: Vec::new(),
            per_file: Vec::new(),
            tags_by_rule: Vec::new(),
            skip_bad_records_enabled: false,
        },
    };
    if let Err(err) = persist::insert_activity_log_entry(&conn, entry) {
        eprintln!("peach: failed to record activity log entry: {err:#}");
    }
}

/// `enabled_builtin_rules` (rule *names*, from either
/// `tagging::builtin::aul_pattern_of_life_rules` or
/// `evtx_security_auditing_rules`) appends whichever built-in rules are
/// currently enabled after the user-selected file-based rules — order
/// doesn't affect tagging (every matching rule applies independently, see
/// `tagging::engine`), it's just where they land in `import_tags`. Every
/// built-in rule already scopes itself to its own sourcetype
/// (`"aul"`/`"evtx"`), so filtering by name rather than by pack is safe the
/// same way the old per-pack toggle was — a rule not in `enabled_builtin_rules`
/// simply isn't included, and an included one still only ever matches rows
/// from its own source, including during a retag of a session that also has
/// other sourcetypes loaded alongside.
fn load_rules(
    rule_paths: &[PathBuf],
    enabled_builtin_rules: &std::collections::BTreeSet<String>,
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
    // Tier 2 (a currently-applied downloaded rule pack) wholesale-replaces
    // tier 1 (the embedded baseline) when present, same as the
    // `enabled_builtin_rules` seed in `PeachApp::new` — see
    // `docs/design/rule-pack-updates.md` §3.
    let applied_pack_dir = rule_file::default_applied_pack_dir().ok();
    rules.extend(
        crate::tagging::builtin::active_builtin_rules(applied_pack_dir.as_deref())
            .into_iter()
            .filter(|rule| enabled_builtin_rules.contains(&rule.rule.name)),
    );
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

/// Used only for `--cleanup-dir` paths (crush's own extraction temp dir,
/// externally supplied): `dir` is only ever deleted verbatim and only if it
/// resolves (after following symlinks) to somewhere under the OS temp
/// directory — a safety net against a mistaken or malicious path, not a
/// guess about what "temporary" means. Peach's own self-created scratch
/// directories (`ephemeral_session_dir`, `portable_case::ScratchDir`) are
/// removed directly instead, without this check: they may legitimately live
/// under a configured `Settings::staging_dir` override rather than OS temp,
/// and Peach already knows it minted that exact path itself.
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

/// Pre-rasterized window/taskbar icon — raw RGBA, straight (not
/// premultiplied) alpha, exactly matching [`egui::IconData`]'s own
/// requirement. Generated once from `resources/icons/peach_icon_128.svg`
/// via `rsvg-convert -w 256 -h 256 ... | magick ... RGBA:...` rather than
/// decoded from a compressed image format at startup — avoids adding an
/// image-decoding dependency (`image`, `png`, ...) for a single asset that
/// never changes at runtime. Regenerate with that same two-step conversion
/// if the icon design ever changes.
const APP_ICON_RGBA: &[u8] = include_bytes!("../resources/icons/peach_icon_256.rgba");
const APP_ICON_SIZE: u32 = 256;

pub fn run(
    add_sources: Vec<PathBuf>,
    cleanup_dirs: Vec<PathBuf>,
    ephemeral_session: bool,
) -> anyhow::Result<()> {
    let window_title = format!("Peach {}", about_dialog::display_version());
    let icon = egui::IconData {
        rgba: APP_ICON_RGBA.to_vec(),
        width: APP_ICON_SIZE,
        height: APP_ICON_SIZE,
    };
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(&window_title)
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        &window_title,
        native_options,
        Box::new(move |cc| {
            let app = PeachApp::new(add_sources, cleanup_dirs, ephemeral_session);
            theme::apply(&cc.egui_ctx, app.settings.theme);
            Ok(Box::new(app))
        }),
    )
    .map_err(|err| anyhow::anyhow!("failed to run peach GUI: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::log_entry::ParsedRecord;
    use crate::parsers::SkippedRecord;
    use chrono::Utc;

    /// Catches exactly the failure mode the embedded icon asset is prone
    /// to: `APP_ICON_SIZE` and the actual pixel data in
    /// `peach_icon_256.rgba` silently drifting apart (e.g. regenerating the
    /// asset at a different resolution without updating the constant) —
    /// `egui::IconData` has no way to detect that itself, it would just
    /// misinterpret the byte buffer as whatever dimensions it's told.
    #[test]
    fn app_icon_rgba_byte_length_matches_its_declared_dimensions() {
        assert_eq!(
            APP_ICON_RGBA.len(),
            (APP_ICON_SIZE * APP_ICON_SIZE * 4) as usize
        );
    }

    fn loaded_source(sourcetype: &str) -> LoadedSource {
        LoadedSource {
            path: "/evidence/test".to_string(),
            sourcetype: sourcetype.to_string(),
            parser_config_path: None,
            source_file_id: String::new(),
        }
    }

    #[test]
    fn builtin_rules_button_is_relevant_when_source_kind_is_aul() {
        assert!(builtin_rules_button_is_relevant(SourceKind::Aul, &[]));
    }

    #[test]
    fn builtin_rules_button_is_relevant_when_source_kind_is_evtx() {
        assert!(builtin_rules_button_is_relevant(SourceKind::Evtx, &[]));
    }

    #[test]
    fn builtin_rules_button_is_relevant_when_source_kind_is_journald() {
        assert!(builtin_rules_button_is_relevant(SourceKind::Journald, &[]));
    }

    #[test]
    fn builtin_rules_button_is_relevant_when_an_aul_source_is_already_loaded() {
        let loaded = [loaded_source("text_config"), loaded_source("aul")];
        assert!(builtin_rules_button_is_relevant(SourceKind::Text, &loaded));
    }

    #[test]
    fn builtin_rules_button_is_relevant_when_an_evtx_source_is_already_loaded() {
        let loaded = [loaded_source("text_config"), loaded_source("evtx")];
        assert!(builtin_rules_button_is_relevant(SourceKind::Text, &loaded));
    }

    #[test]
    fn builtin_rules_button_is_relevant_when_a_journald_source_is_already_loaded() {
        let loaded = [loaded_source("text_config"), loaded_source("journald")];
        assert!(builtin_rules_button_is_relevant(SourceKind::Text, &loaded));
    }

    #[test]
    fn builtin_rules_button_is_relevant_when_source_kind_is_intrusion_log() {
        assert!(builtin_rules_button_is_relevant(
            SourceKind::IntrusionLog,
            &[]
        ));
    }

    #[test]
    fn builtin_rules_button_is_relevant_when_an_intrusion_log_source_is_already_loaded() {
        let loaded = [loaded_source("text_config"), loaded_source("intrusion_log")];
        assert!(builtin_rules_button_is_relevant(SourceKind::Text, &loaded));
    }

    #[test]
    fn builtin_rules_button_is_not_relevant_with_none_of_the_four_sourcetypes_involved() {
        let loaded = [loaded_source("text_config")];
        assert!(!builtin_rules_button_is_relevant(SourceKind::Text, &loaded));
        assert!(!builtin_rules_button_is_relevant(SourceKind::Text, &[]));
    }

    fn no_builtin_rules() -> std::collections::BTreeSet<String> {
        std::collections::BTreeSet::new()
    }

    fn no_cancel() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    fn all_builtin_rule_names() -> std::collections::BTreeSet<String> {
        crate::tagging::builtin::all_builtin_rules()
            .iter()
            .map(|r| r.rule.name.clone())
            .collect()
    }

    fn builtin_rule_names(tag_values: &[&str]) -> std::collections::BTreeSet<String> {
        crate::tagging::builtin::all_builtin_rules()
            .into_iter()
            .filter(|r| tag_values.contains(&r.rule.tag.value.as_str()))
            .map(|r| r.rule.name)
            .collect()
    }

    #[test]
    fn load_rules_with_no_files_and_no_builtin_pack_is_empty() {
        let rules = load_rules(&[], &no_builtin_rules()).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn load_rules_merges_the_builtin_aul_pack_with_no_files_selected() {
        let rules = load_rules(&[], &all_builtin_rule_names()).unwrap();
        assert!(rules.len() >= 33);
        assert!(rules.iter().any(|r| r.rule.tag.value == "wifi_status"));
    }

    #[test]
    fn load_rules_merges_the_builtin_evtx_pack_with_no_files_selected() {
        let rules = load_rules(&[], &all_builtin_rule_names()).unwrap();
        assert!(rules.len() >= 15);
        assert!(rules.iter().any(|r| r.rule.tag.value == "logon_success"));
    }

    #[test]
    fn load_rules_merges_both_builtin_packs_together() {
        let rules = load_rules(&[], &all_builtin_rule_names()).unwrap();
        assert!(rules.iter().any(|r| r.rule.tag.value == "wifi_status"));
        assert!(rules.iter().any(|r| r.rule.tag.value == "logon_success"));
    }

    #[test]
    fn load_rules_only_includes_explicitly_enabled_builtin_rules() {
        // Point 3's whole reason to exist: a subset of one pack, not just
        // "the pack" as a unit.
        let enabled = builtin_rule_names(&["wifi_status"]);
        let rules = load_rules(&[], &enabled).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule.tag.value, "wifi_status");
    }

    #[test]
    fn read_preview_lines_caps_at_max_lines() {
        let dir = temp_test_dir("preview-cap");
        let path = dir.join("source.log");
        std::fs::write(&path, "one\ntwo\nthree\nfour\nfive\n").unwrap();

        let lines = read_preview_lines(&path, 3);

        assert_eq!(lines, vec!["one", "two", "three"]);
    }

    #[test]
    fn read_preview_lines_returns_every_line_when_the_file_has_fewer_than_the_cap() {
        let dir = temp_test_dir("preview-short");
        let path = dir.join("source.log");
        std::fs::write(&path, "only one line\n").unwrap();

        let lines = read_preview_lines(&path, 20);

        assert_eq!(lines, vec!["only one line"]);
    }

    #[test]
    fn read_preview_lines_is_empty_for_a_missing_file() {
        let missing = temp_test_dir("preview-missing").join("does-not-exist.log");

        assert!(read_preview_lines(&missing, 20).is_empty());
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

        let rules =
            load_rules(std::slice::from_ref(&rule_path), &all_builtin_rule_names()).unwrap();

        assert!(rules.iter().any(|r| r.rule.tag.value == "custom_tag"));
        assert!(rules.iter().any(|r| r.rule.tag.value == "wifi_status"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rule_version_lookup_reads_each_rules_version_field() {
        let dir = temp_test_dir("rule-version-lookup");
        let versioned_path = dir.join("versioned.toml");
        std::fs::write(
            &versioned_path,
            "[rule]\nname = \"versioned\"\nversion = \"7\"\n[rule.match]\nmessage_contains = \"x\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let unversioned_path = dir.join("unversioned.toml");
        std::fs::write(
            &unversioned_path,
            "[rule]\nname = \"unversioned\"\n[rule.match]\nmessage_contains = \"y\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let lookup = rule_version_lookup(RuleSelection {
            paths: &[versioned_path, unversioned_path],
            enabled_builtin_rules: &no_builtin_rules(),
        });

        assert_eq!(lookup.get("versioned"), Some(&Some("7".to_string())));
        assert_eq!(lookup.get("unversioned"), Some(&None));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rule_counts_to_activity_counts_stamps_each_rules_version_and_sorts_by_name() {
        let tags_by_rule = HashMap::from([
            ("versioned".to_string(), 3usize),
            ("unversioned".to_string(), 1usize),
            ("not_in_lookup".to_string(), 2usize),
        ]);
        let rule_versions = HashMap::from([
            ("versioned".to_string(), Some("5".to_string())),
            ("unversioned".to_string(), None),
            // "not_in_lookup" deliberately absent — a rule name present in
            // `tags_by_rule` but missing from `rule_versions` shouldn't
            // happen in practice, but must fall back to `None` rather than
            // panicking (see the doc comment).
        ]);

        let counts = rule_counts_to_activity_counts(&tags_by_rule, &rule_versions);

        assert_eq!(
            counts,
            vec![
                persist::ActivityRuleCount {
                    rule_name: "not_in_lookup".to_string(),
                    count: 2,
                    version: None,
                },
                persist::ActivityRuleCount {
                    rule_name: "unversioned".to_string(),
                    count: 1,
                    version: None,
                },
                persist::ActivityRuleCount {
                    rule_name: "versioned".to_string(),
                    count: 3,
                    version: Some("5".to_string()),
                },
            ]
        );
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

    /// Regression test for the index-out-of-bounds panic an empty pick used
    /// to cause: closing the native multi-file picker via the window's own
    /// X button (rather than an explicit Cancel) has been observed on Linux
    /// to resolve `pick_files()` to `Some(vec![])` instead of `None` — see
    /// `FilePickOutcome::SourcePaths`'s doc comment.
    #[test]
    fn source_path_and_queue_from_pick_treats_an_empty_pick_as_none() {
        assert_eq!(source_path_and_queue_from_pick(vec![]), None);
    }

    #[test]
    fn source_path_and_queue_from_pick_splits_first_from_rest() {
        let picked = vec![
            PathBuf::from("/evidence/a.evtx"),
            PathBuf::from("/evidence/b.evtx"),
            PathBuf::from("/evidence/c.evtx"),
        ];

        let (first, rest) = source_path_and_queue_from_pick(picked).unwrap();

        assert_eq!(first, PathBuf::from("/evidence/a.evtx"));
        assert_eq!(
            rest,
            vec![
                PathBuf::from("/evidence/b.evtx"),
                PathBuf::from("/evidence/c.evtx"),
            ]
        );
    }

    #[test]
    fn source_path_and_queue_from_pick_with_one_file_has_an_empty_rest() {
        let picked = vec![PathBuf::from("/evidence/only.evtx")];

        let (first, rest) = source_path_and_queue_from_pick(picked).unwrap();

        assert_eq!(first, PathBuf::from("/evidence/only.evtx"));
        assert!(rest.is_empty());
    }

    /// Exercises the whole `crush` handoff mechanics end to end at the
    /// `PeachApp` level, without needing a real window: `--add-source` /
    /// `--cleanup-dir` / `--ephemeral-session` as `crush` would pass them
    /// for a temp-extracted or decrypted source, from pre-fill at startup
    /// (`PeachApp::new`) through cleanup on shutdown (`on_exit`). Was never
    /// verified this way before the first release that `crush` is meant to
    /// depend on instead of the nightly build.
    #[test]
    fn ephemeral_crush_handoff_prefills_source_and_cleans_up_everything_on_exit() {
        let unique = uuid::Uuid::new_v4();
        let source_path =
            std::env::temp_dir().join(format!("peach-test-crush-source-{unique}.log"));
        std::fs::write(&source_path, b"2026-08-14 hello\n").unwrap();
        let cleanup_dir = std::env::temp_dir().join(format!("peach-test-crush-cleanup-{unique}"));
        std::fs::create_dir_all(&cleanup_dir).unwrap();
        std::fs::write(cleanup_dir.join("source.log"), b"evidence").unwrap();

        let mut app = PeachApp::new(vec![source_path.clone()], vec![cleanup_dir.clone()], true);

        // Pre-fill, same as a manual "Load" would need it.
        assert_eq!(app.source_path, Some(source_path));
        assert_eq!(app.source_kind, SourceKind::Text);
        // The session lives under a one-off temp dir, not the persistent
        // sessions directory, and its `.sqlite` already exists (`new` opens
        // it eagerly to set up the schema).
        let ephemeral_dir = app
            .ephemeral_session_dir
            .clone()
            .expect("--ephemeral-session must set ephemeral_session_dir");
        assert!(ephemeral_dir.starts_with(std::env::temp_dir()));
        assert!(app.session_paths.sqlite_path.starts_with(&ephemeral_dir));
        assert!(app.session_paths.sqlite_path.exists());
        // Nothing gets touched before shutdown.
        assert!(cleanup_dir.exists());
        assert!(ephemeral_dir.exists());

        eframe::App::on_exit(&mut app);

        assert!(
            !cleanup_dir.exists(),
            "crush's --cleanup-dir must be removed on exit"
        );
        assert!(
            !ephemeral_dir.exists(),
            "--ephemeral-session must leave no session copy behind on exit"
        );
    }

    /// "New session" (File menu) must produce a genuinely fresh session —
    /// a different id/files on disk from the one it replaces — and reset
    /// every piece of per-session UI state (loaded sources, filter text,
    /// level counts, ...) rather than leaving stale state from the session
    /// it left behind visible against an empty timeline.
    #[test]
    fn new_session_starts_a_fresh_session_and_resets_ui_state() {
        let mut app = PeachApp::new(Vec::new(), Vec::new(), true);
        let old_session_id = app.session_paths.id.clone();
        let old_sqlite_path = app.session_paths.sqlite_path.clone();

        app.loaded_sources.push(loaded_source("evtx"));
        app.session_display_name = Some("Suspect laptop".to_string());
        app.filter_bar.set_text("level=ERROR".to_string());
        app.available_levels
            .push(("ERROR".to_string(), "ERROR".to_string()));
        app.level_counts.insert("ERROR".to_string(), 1);

        // `new_session_id()` has one-second resolution — without this, a
        // test run fast enough to call it twice within the same wall-clock
        // second would get the *same* id back, defeating the whole point
        // of this assertion.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        app.new_session();

        assert_ne!(app.session_paths.id, old_session_id);
        assert!(app.session_paths.sqlite_path.exists());
        assert!(app.visited_sessions.contains(&old_sqlite_path));
        assert!(
            app.visited_sessions
                .contains(&app.session_paths.sqlite_path)
        );
        assert!(app.loaded_sources.is_empty());
        assert_eq!(app.session_display_name, None);
        assert_eq!(app.filter_bar.text(), "");
        assert!(app.available_levels.is_empty());
        assert!(app.level_counts.is_empty());
        assert_eq!(app.timeline.query(), &Query::default());
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
    fn collect_source_files_returns_the_folder_itself_for_intrusion_log_even_though_its_a_directory()
     {
        let dir = temp_test_dir("intrusion-log-folder");
        std::fs::write(dir.join("intrusion-logs-0.txt"), b"x").unwrap();

        let files = collect_source_files(SourceKind::IntrusionLog, &dir);

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
                enabled_builtin_rules: &no_builtin_rules(),
            },
            conn,
            LoadSettings {
                thread_count: 2, // 3 files > 1, so this exercises run_parallel
                default_source_timezone: None,
                skip_bad_records: false,
            },
            LoadControl {
                progress_tx: &tx,
                cancel: no_cancel(),
            },
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
        // Per-file breakdown must attribute each file's own count, not the
        // running total — this is exactly what the interleaved-batch
        // tallying in `run_parallel`'s `ParseEvent::Batch` handler exists
        // to get right.
        assert_eq!(summary.per_file_inserted.len(), 2);
        let a_log_path = logs_dir.join("a.log").display().to_string();
        let b_log_path = logs_dir.join("b.log").display().to_string();
        assert_eq!(summary.per_file_inserted.get(&a_log_path), Some(&1));
        assert_eq!(summary.per_file_inserted.get(&b_log_path), Some(&2));

        std::fs::remove_dir_all(base).unwrap();
    }

    /// End-to-end regression test for "skip bad records" through the real
    /// multi-file (`run_parallel`) path: a file with one bad line among
    /// good ones must keep its good entries and land in
    /// `records_skipped`/`per_file_records_skipped` instead of `skipped`
    /// (which stays empty — no *whole file* failed).
    #[test]
    fn run_load_with_skip_bad_records_keeps_good_lines_and_tallies_skipped_records() {
        let base = temp_test_dir("run-load-skip-bad-records");
        let logs_dir = base.join("logs");
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::write(
            logs_dir.join("a.log"),
            "2026-07-28T12:00:00+0200 ERROR first\n\
             this line matches nothing\n\
             2026-07-28T12:00:02+0200 ERROR second\n",
        )
        .unwrap();
        std::fs::write(
            logs_dir.join("b.log"),
            "2026-07-28T12:05:00+0200 INFO all fine\n",
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
                enabled_builtin_rules: &no_builtin_rules(),
            },
            conn,
            LoadSettings {
                thread_count: 2, // 2 files > 1, so this exercises run_parallel
                default_source_timezone: None,
                skip_bad_records: true,
            },
            LoadControl {
                progress_tx: &tx,
                cancel: no_cancel(),
            },
        )
        .unwrap();

        assert_eq!(summary.inserted, 3); // 2 good from a.log + 1 from b.log
        assert!(
            summary.skipped.is_empty(),
            "no whole file should be marked skipped — a.log still loaded most of itself"
        );
        assert_eq!(summary.records_skipped, 1);
        let a_log_path = logs_dir.join("a.log").display().to_string();
        assert_eq!(summary.per_file_records_skipped.get(&a_log_path), Some(&1));

        std::fs::remove_dir_all(base).unwrap();
    }

    /// `record_load_activity_entry` must persist both the per-file skip
    /// counts and whether skip mode was even on for this load — the
    /// analyst's choice to tolerate corruption is itself forensically
    /// relevant, not just the resulting numbers.
    #[test]
    fn record_load_activity_entry_persists_skip_bad_records_details() {
        let sqlite_path = temp_test_dir("record-load-activity-skip").join("session.sqlite");
        let summary = LoadSummary {
            inserted: 5,
            tags_applied: 0,
            loaded_sources: Vec::new(),
            skipped: Vec::new(),
            per_file_inserted: std::collections::BTreeMap::from([("a.log".to_string(), 5)]),
            per_file_records_skipped: std::collections::BTreeMap::from([("a.log".to_string(), 2)]),
            records_skipped: 2,
            tags_by_rule: HashMap::new(),
            cancelled: false,
        };

        record_load_activity_entry(
            &sqlite_path,
            Path::new("/evidence/a.log"),
            1_753_704_000,
            1_753_704_010,
            &Ok(summary),
            true,
            RuleSelection {
                paths: &[],
                enabled_builtin_rules: &std::collections::BTreeSet::new(),
            },
        );

        let conn = persist::open_session_db(&sqlite_path).unwrap();
        let entries = persist::all_activity_log_entries(&conn).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].skip_bad_records_enabled);
        assert_eq!(entries[0].per_file.len(), 1);
        assert_eq!(entries[0].per_file[0].records_skipped, 2);

        // Windows keeps the sqlite file locked open while `conn` is alive —
        // drop it before cleanup, same as `session_schema.rs`'s own tests.
        drop(conn);
        std::fs::remove_dir_all(sqlite_path.parent().unwrap()).unwrap();
    }

    /// `LoadSummary::tags_by_rule` is computed by `run_load` itself (a
    /// follow-up query, not threaded through `run_sequential`/`run_parallel`)
    /// — this exercises that end to end with two rules matching different
    /// subsets of one file's entries.
    #[test]
    fn run_load_breaks_down_tags_applied_by_rule_name() {
        let base = temp_test_dir("run-load-tags-by-rule");
        let log_path = base.join("mixed.log");
        std::fs::write(
            &log_path,
            "2026-07-28T12:00:00+0200 ERROR something broke\n\
             2026-07-28T12:01:00+0200 INFO all fine\n",
        )
        .unwrap();
        let config_path = base.join("config.toml");
        std::fs::write(&config_path, text_parser_config()).unwrap();
        let rule_path = base.join("rule.toml");
        std::fs::write(
            &rule_path,
            "[rule]\nname = \"errors_only\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"error\"\n",
        )
        .unwrap();

        let db_path = base.join("test.duckdb");
        let conn = duckdb::Connection::open(&db_path).unwrap();
        let (tx, _rx) = mpsc::channel();

        let summary = run_load(
            SourceKind::Text,
            &log_path,
            Some(&config_path),
            RuleSelection {
                paths: &[rule_path],
                enabled_builtin_rules: &no_builtin_rules(),
            },
            conn,
            LoadSettings {
                thread_count: 1,
                default_source_timezone: None,
                skip_bad_records: false,
            },
            LoadControl {
                progress_tx: &tx,
                cancel: no_cancel(),
            },
        )
        .unwrap();

        assert_eq!(summary.tags_applied, 1);
        assert_eq!(summary.tags_by_rule.get("errors_only"), Some(&1));
        assert_eq!(summary.tags_by_rule.len(), 1);
        // Single file, sequential path — `load_one_file`'s own
        // `inserted_this_file` is the source here, not `run_parallel`'s
        // batch-tallying.
        assert_eq!(
            summary
                .per_file_inserted
                .get(&log_path.display().to_string()),
            Some(&2)
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
                enabled_builtin_rules: &no_builtin_rules(),
            },
            conn,
            LoadSettings {
                thread_count: 4, // irrelevant with a single file — must still behave correctly
                default_source_timezone: None,
                skip_bad_records: false,
            },
            LoadControl {
                progress_tx: &tx,
                cancel: no_cancel(),
            },
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

    #[test]
    fn run_load_already_cancelled_before_starting_loads_nothing_sequential() {
        let base = temp_test_dir("run-load-cancel-before-sequential");
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
                enabled_builtin_rules: &no_builtin_rules(),
            },
            conn,
            LoadSettings {
                thread_count: 1,
                default_source_timezone: None,
                skip_bad_records: false,
            },
            LoadControl {
                progress_tx: &tx,
                cancel: Arc::new(AtomicBool::new(true)), // already cancelled
            },
        )
        .unwrap();

        assert!(summary.cancelled);
        assert_eq!(summary.inserted, 0);
        assert!(summary.loaded_sources.is_empty());

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn run_load_already_cancelled_before_starting_loads_nothing_parallel() {
        let base = temp_test_dir("run-load-cancel-before-parallel");
        let logs_dir = base.join("logs");
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::write(logs_dir.join("a.log"), "2026-07-28T12:00:00+0200 ERROR a\n").unwrap();
        std::fs::write(logs_dir.join("b.log"), "2026-07-28T12:00:00+0200 ERROR b\n").unwrap();
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
                enabled_builtin_rules: &no_builtin_rules(),
            },
            conn,
            LoadSettings {
                thread_count: 2, // 2 files > 1, exercises run_parallel
                default_source_timezone: None,
                skip_bad_records: false,
            },
            LoadControl {
                progress_tx: &tx,
                cancel: Arc::new(AtomicBool::new(true)), // already cancelled
            },
        )
        .unwrap();

        assert!(summary.cancelled);
        assert_eq!(summary.inserted, 0);
        assert!(summary.loaded_sources.is_empty());

        std::fs::remove_dir_all(base).unwrap();
    }

    /// Cancellation mid-*file* (not just between files) only has a
    /// checkpoint to fire at every `LOAD_BATCH_SIZE` (10,000) entries — so
    /// this needs a file that large to exercise it at all. A background
    /// thread flips `cancel` as soon as it sees the first `Progress` update
    /// (sent right after the first full batch flushes), so the load stops
    /// partway through instead of consuming the whole file — proving
    /// `load_one_file` salvages what was already flushed (a real `sources`
    /// row, real `log_entries` rows) rather than losing or orphaning it.
    #[test]
    fn run_load_cancelled_mid_file_keeps_the_entries_already_flushed() {
        let base = temp_test_dir("run-load-cancel-mid-file");
        let log_path = base.join("big.log");
        let mut contents = String::new();
        for i in 0..(LOAD_BATCH_SIZE * 2 + 500) {
            contents.push_str(&format!("2026-07-28T12:00:00+0200 INFO line {i}\n"));
        }
        std::fs::write(&log_path, contents).unwrap();
        let config_path = base.join("config.toml");
        std::fs::write(&config_path, text_parser_config()).unwrap();
        let db_path = base.join("test.duckdb");
        let conn = duckdb::Connection::open(&db_path).unwrap();
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_for_watcher = Arc::clone(&cancel);

        let watcher = std::thread::spawn(move || {
            for outcome in rx {
                if let LoadOutcome::Progress { .. } = outcome {
                    cancel_for_watcher.store(true, Ordering::Relaxed);
                }
            }
        });

        let summary = run_load(
            SourceKind::Text,
            &log_path,
            Some(&config_path),
            RuleSelection {
                paths: &[],
                enabled_builtin_rules: &no_builtin_rules(),
            },
            conn,
            LoadSettings {
                thread_count: 1,
                default_source_timezone: None,
                skip_bad_records: false,
            },
            LoadControl {
                progress_tx: &tx,
                cancel,
            },
        )
        .unwrap();
        drop(tx);
        watcher.join().unwrap();

        assert!(summary.cancelled);
        assert!(
            summary.inserted > 0 && summary.inserted < LOAD_BATCH_SIZE * 2 + 500,
            "expected a partial insert count, got {}",
            summary.inserted
        );
        // The salvaged partial file must still be a properly registered
        // source, not orphaned `log_entries` rows with no matching `sources`
        // entry — this is exactly the bug the capture-the-id-off-the-first-
        // entry approach in `load_one_file` exists to avoid.
        assert_eq!(summary.loaded_sources.len(), 1);
        assert_eq!(summary.per_file_inserted.len(), 1);

        std::fs::remove_dir_all(base).unwrap();
    }

    struct TotalKnownParser;

    impl LogParser for TotalKnownParser {
        fn sourcetype(&self) -> &str {
            "test-total-known"
        }

        fn parse(
            &self,
            _path: &Path,
            _config: &ParserConfig,
            _skip_bad_records: bool,
        ) -> anyhow::Result<(Vec<ParsedRecord>, Vec<SkippedRecord>)> {
            Ok((Vec::new(), Vec::new()))
        }

        fn parse_streaming(
            &self,
            _path: &Path,
            _config: &ParserConfig,
            sink: &mut dyn FnMut(ParsedRecord) -> anyhow::Result<()>,
            progress: &mut StreamingProgress,
            _skip_bad_records: bool,
        ) -> anyhow::Result<Vec<SkippedRecord>> {
            (progress.on_total_known)(2);
            for message in ["first", "second"] {
                sink(ParsedRecord {
                    timestamp_utc: Utc::now(),
                    level: None,
                    message: Some(message.to_string()),
                    raw: message.to_string(),
                    fields: serde_json::Value::Null,
                })?;
            }
            Ok(Vec::new())
        }
    }

    /// `load_one_file` (below `run_load`'s `SourceKind` dispatch, so this
    /// injects a test-double parser directly via `LoadContext` — no real
    /// AUL fixture needed) must surface `total_entries` in a `Progress`
    /// send as soon as the parser reports it, not just once a full
    /// `LOAD_BATCH_SIZE` batch flushes — otherwise a small/test-sized
    /// source would never show it at all.
    #[test]
    fn load_one_file_surfaces_total_entries_as_soon_as_the_parser_reports_it() {
        let base = temp_test_dir("load-one-file-total-entries");
        let db_path = base.join("test.duckdb");
        let conn = duckdb::Connection::open(&db_path).unwrap();
        setup_timeline_schema(&conn).unwrap();
        let config = ParserConfig::from_toml_str(
            "[parser]\nname = \"test\"\nsourcetype = \"test-total-known\"\n",
        )
        .unwrap();
        let ctx = LoadContext {
            parser: &TotalKnownParser,
            config: &config,
            sourcetype: "test-total-known",
            rules: &[],
            parser_config_path: None,
            cancel: no_cancel(),
            skip_bad_records: false,
        };
        let file_path = base.join("fake-source");
        std::fs::write(&file_path, b"unused").unwrap();
        let (tx, rx) = mpsc::channel();
        let mut total_inserted = 0usize;

        let result = load_one_file(&ctx, &file_path, &conn, &mut total_inserted, 0, 100, &tx)
            .unwrap()
            .unwrap();

        assert_eq!(result.0, 0, "no rules selected, so no tags applied");
        assert_eq!(total_inserted, 2);
        let total_entries_seen: Vec<Option<usize>> = rx
            .try_iter()
            .map(|msg| match msg {
                LoadOutcome::Progress { total_entries, .. } => total_entries,
                LoadOutcome::Done(_) => None,
            })
            .collect();
        assert!(
            total_entries_seen.contains(&Some(2)),
            "expected a Progress message with total_entries = Some(2), got {total_entries_seen:?}"
        );

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
                    enabled_builtin_rules: &no_builtin_rules(),
                },
                conn,
                LoadSettings {
                    thread_count,
                    default_source_timezone: None,
                    skip_bad_records: false,
                },
                LoadControl {
                    progress_tx: &tx,
                    cancel: no_cancel(),
                },
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
    fn path_byte_size_sums_a_directorys_tracev3_files_recursively() {
        let dir = temp_test_dir("byte-size-dir");
        std::fs::write(dir.join("a.tracev3"), vec![0u8; 100]).unwrap();
        let nested = dir.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("b.tracev3"), vec![0u8; 50]).unwrap();

        assert_eq!(path_byte_size("aul", &dir), 150);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn path_byte_size_of_a_directory_ignores_non_tracev3_files() {
        // dsc/uuidtext/timesync data lives alongside the .tracev3 files in
        // both AUL layouts — excluded so this total matches what
        // AulParser's own on_bytes_progress reporting sums to.
        let dir = temp_test_dir("byte-size-dir-mixed");
        std::fs::write(dir.join("a.tracev3"), vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("some_uuidtext_file"), vec![0u8; 999]).unwrap();

        assert_eq!(path_byte_size("aul", &dir), 100);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn path_byte_size_of_an_intrusion_log_directory_sums_txt_files_not_tracev3() {
        let dir = temp_test_dir("byte-size-dir-intrusion-log");
        std::fs::write(dir.join("intrusion-logs-0.txt"), vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("manifest.tracev3"), vec![0u8; 999]).unwrap();

        assert_eq!(path_byte_size("intrusion_log", &dir), 100);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn path_byte_size_of_a_plain_file_is_its_own_size() {
        let dir = temp_test_dir("byte-size-file");
        let file = dir.join("only.log");
        std::fs::write(&file, vec![0u8; 42]).unwrap();

        assert_eq!(path_byte_size("evtx", &file), 42);

        std::fs::remove_dir_all(dir).unwrap();
    }
}
