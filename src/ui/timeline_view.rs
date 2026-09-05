use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::mpsc;

use duckdb::Connection;
use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::db::timeline_queries::{self, DisplayRow, Query};
use crate::model::event_id::EventId;
use crate::model::timezone_spec::TimezoneSpec;
use crate::session::persist;
use crate::ui::colors::categorical_color;

/// An action requested via a row's right-click context menu — handled by
/// the caller (`PeachApp`), which owns the session/rule-file/search state
/// these need (`TimelineView` only knows the DuckDB timeline itself).
pub enum RowAction {
    /// "Tag this event..." — a single manual, analyst-driven tag.
    TagSingle { event_id: EventId },
    /// "Tag all matching (advanced)..." — the clicked row's message seeds
    /// the pattern for a `message_contains` rule; `fields` (the same
    /// populated-on-this-row set `FilterByColumn`'s "Filter by..." submenu
    /// offers — Sourcetype/Host/Process/Event ID/Subsystem/Category) lets
    /// the dialog offer an exact-match rule on one of those instead.
    TagAllMatching {
        event_id: EventId,
        message: String,
        sourcetype: String,
        fields: Vec<(&'static str, &'static str, String)>,
    },
    /// "Notes..." — view/add/edit/delete free-text notes on this event,
    /// independent of any tag (see `session::persist`'s `*_event_note`
    /// functions).
    ManageNotes { event_id: EventId },
    /// "Show context around this event" — replaces the search query with
    /// an `after=.../before=...` window centered on the clicked row.
    /// Computed here (not in `app.rs`) since it needs the row's own
    /// timestamp, which `DisplayRow` already carries as a formatted
    /// string.
    ShowContext { query_text: String },
    /// "View raw/fields..." — the complete `raw`/`fields` data for this one
    /// event, already fetched (same synchronous single-row lookup "Copy
    /// whole event as text" already does with `conn`, available right
    /// here) so `app.rs` only has to open the dialog with it, not fetch it
    /// again.
    ViewRawFields { entry: timeline_queries::FullEntry },
    /// "Filter by..." submenu — add (or replace) an exact-match filter for
    /// one of the clicked row's own field values
    /// (`timeline_queries::COLUMN_FILTER_FIELDS`: Sourcetype/Host/Process/
    /// Event ID/Subsystem/Category). Row-level, not cell-level, like every
    /// other row action here — the submenu lists whichever of the row's
    /// fields are actually populated, not just the one under the pointer.
    FilterByColumn { field: &'static str, value: String },
}

/// How many rows to fetch per DuckDB query when the visible scroll window
/// moves. Keeps memory bounded (never holds the full result set — section
/// "nicht im RAM halten") while avoiding a query per visible row.
const WINDOW_SIZE: usize = 200;

struct RowCache {
    offset: usize,
    rows: Vec<DisplayRow>,
}

/// Every column the timeline table can show, in one place — drives the
/// table's `.column()` calls, headers, and body cells all from the same
/// data instead of three separately-maintained parallel sequences (the
/// pre-drag-reorder code's actual bug-prone shape: adding a column meant
/// touching four different spots that all had to agree on order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ColumnKind {
    Timestamp,
    Level,
    Source,
    Sourcetype,
    Host,
    Process,
    EventCode,
    Subsystem,
    Category,
    Tags,
    Notes,
    Message,
}

impl ColumnKind {
    fn label(self) -> &'static str {
        match self {
            // Not "Timestamp (UTC)" — the column can now show any
            // configured display timezone, not always UTC. Each cell is
            // self-describing on its own instead (`d.timestamp_display`
            // always carries its own `%:z` offset via
            // `TimezoneSpec::format_utc`), so the header doesn't need to
            // name a specific zone.
            Self::Timestamp => "Timestamp",
            Self::Level => "Level",
            Self::Source => "Source",
            Self::Sourcetype => "Sourcetype",
            Self::Host => "Host",
            Self::Process => "Process",
            Self::EventCode => "Event ID",
            Self::Subsystem => "Subsystem",
            Self::Category => "Category",
            Self::Tags => "Tags",
            Self::Notes => "Notes",
            Self::Message => "Message",
        }
    }

    fn min_width(self) -> f32 {
        match self {
            Self::Timestamp => 170.0,
            Self::Level => 80.0,
            Self::Source => 140.0,
            Self::Sourcetype => 90.0,
            Self::Host => 110.0,
            Self::Process => 110.0,
            Self::EventCode => 70.0,
            Self::Subsystem => 140.0,
            Self::Category => 110.0,
            Self::Tags => 140.0,
            Self::Notes => 160.0,
            Self::Message => 200.0,
        }
    }
}

/// The table's column order before any drag-and-drop reordering — also the
/// full set of `ColumnKind`s that exist, so [`TimelineView::visible_columns`]
/// has something to filter.
const DEFAULT_COLUMN_ORDER: [ColumnKind; 12] = [
    ColumnKind::Timestamp,
    ColumnKind::Level,
    ColumnKind::Source,
    ColumnKind::Sourcetype,
    ColumnKind::Host,
    ColumnKind::Process,
    ColumnKind::EventCode,
    ColumnKind::Subsystem,
    ColumnKind::Category,
    ColumnKind::Tags,
    ColumnKind::Notes,
    ColumnKind::Message,
];

/// Moves `dragged` to just before `target`'s current position in `order` —
/// the effect of dropping a dragged column header onto another one.
/// Falls back to the end if `target` isn't found (shouldn't happen — every
/// `ColumnKind` a drop can name is already in `order`, since `order` always
/// holds the complete fixed set — but appending rather than panicking keeps
/// a dropped drag harmless even if that invariant is ever violated). A
/// no-op if `dragged == target`, or if `dragged` itself isn't found for the
/// same reason.
fn reorder_columns(order: &mut Vec<ColumnKind>, dragged: ColumnKind, target: ColumnKind) {
    if dragged == target {
        return;
    }
    let Some(from) = order.iter().position(|kind| *kind == dragged) else {
        return;
    };
    order.remove(from);
    let to = order
        .iter()
        .position(|kind| *kind == target)
        .unwrap_or(order.len());
    order.insert(to, dragged);
}

/// The human-readable severity name for a sourcetype's raw numeric level
/// digit (e.g. journald's `"6"` -> `"info"`, EVTX's `"2"` -> `"Error"`),
/// if this sourcetype/level combination has a confirmed mapping. Shared by
/// [`format_level`] (the table's Level column) and
/// `ui::filter_bar`'s quick Level-filter row (via
/// [`TimelineView::distinct_levels`]), so both surfaces agree on the same
/// name rather than each maintaining their own copy of this table.
pub(crate) fn level_display_name(level: &str, sourcetype: &str) -> Option<&'static str> {
    match sourcetype {
        "journald" => Some(match level {
            "0" => "emerg",
            "1" => "alert",
            "2" => "crit",
            "3" => "err",
            "4" => "warning",
            "5" => "notice",
            "6" => "info",
            "7" => "debug",
            _ => return None,
        }),
        // Standard Windows Event Level values (`winmeta.xml`'s
        // `WINEVENT_LEVEL_*` constants) — defined once at the OS/schema
        // level and used consistently by every provider, unlike EventData
        // which varies per provider. 6-255 are provider-defined/reserved,
        // not part of this fixed set, so they pass through unmapped.
        "evtx" => Some(match level {
            "0" => "LogAlways",
            "1" => "Critical",
            "2" => "Error",
            "3" => "Warning",
            "4" => "Informational",
            "5" => "Verbose",
            _ => return None,
        }),
        _ => None,
    }
}

/// Display-only formatting of the Level column — appends
/// [`level_display_name`]'s human-readable severity name to a sourcetype's
/// raw numeric level digit (e.g. `"6"` -> `"6 (info)"`). The stored `level`
/// value itself stays exactly what the parser read (see
/// `parsers::journald`'s and `parsers::evtx`'s doc comments on why it's
/// deliberately not remapped there) — this only touches what's rendered in
/// the table, same forensic "raw stays raw" principle applied to the UI
/// layer instead of the data layer. Any sourcetype/level combination without
/// a mapping passes through unchanged.
fn format_level(level: &str, sourcetype: &str) -> String {
    match level_display_name(level, sourcetype) {
        Some(name) => format!("{level} ({name})"),
        None => level.to_string(),
    }
}

/// Display-only shortening of the Source column: the last path component for
/// most sourcetypes (a real filename, e.g. `security.evtx`), but the full
/// path for AUL. AUL's "file" is actually the directory the analyst picked —
/// a raw extraction's parent folder, or a `.logarchive` bundle — and its last
/// path component is frequently a generic name (`"db"`, `"extraction"`) that
/// doesn't distinguish one AUL source from another the way a real filename
/// does. The full path is always available via hover regardless of which
/// form is shown here.
///
/// `pub(crate)` — also used by `app.rs` to label the per-source visibility
/// chips (`ui::filter_bar`) with the same short name this column already
/// shows, rather than a second, separately-maintained shortening rule.
pub(crate) fn source_display_label<'a>(source_path: &'a str, sourcetype: &str) -> &'a str {
    if sourcetype == "aul" {
        return source_path;
    }
    std::path::Path::new(source_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(source_path)
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
    /// Lazily-opened base connection to `db_path`, kept alive for the rest
    /// of this view's lifetime — see [`Self::try_clone_conn`] for why every
    /// background thread and foreground query gets a `try_clone()` of this
    /// instead of independently re-opening the file.
    conn: RefCell<Option<Connection>>,
    /// Whether the optional Sourcetype/Host/Process/Event ID/Subsystem/
    /// Category columns are shown, toggled via the "Columns" picker above
    /// the table. The Source (file) column is always shown — these default
    /// to hidden since they're either derivable from the file name
    /// (Sourcetype) or only populated for sourcetypes with a confirmed
    /// field mapping (see `timeline_queries::extracted_field_sql`), so
    /// showing them unconditionally would mean an empty column for most
    /// sessions.
    show_sourcetype_column: bool,
    show_host_column: bool,
    show_process_column: bool,
    show_event_code_column: bool,
    show_subsystem_column: bool,
    show_category_column: bool,
    /// Whether the Notes column is shown — same opt-in-via-picker reasoning
    /// as the columns above, defaulting to hidden since most rows have no
    /// notes at all.
    show_notes_column: bool,
    /// Display order for every column (visible or not) — starts as
    /// [`DEFAULT_COLUMN_ORDER`], rearranged by dragging a header onto
    /// another one (see [`reorder_columns`]). Not persisted across
    /// restarts, same as the `show_*_column` visibility flags above.
    column_order: Vec<ColumnKind>,
    /// Whether the timeline is shown newest-first (`true`) instead of the
    /// default oldest-first (`false`). Toggled via the button next to
    /// "Columns"; affects both `fetch_window`'s ordering and, symmetrically,
    /// its tie-breaker on `(event_id_source, event_id_seq)` — see
    /// `timeline_queries::fetch_window_keys`'s doc comment on why the whole
    /// tuple flips together rather than only `timestamp_utc`. Not persisted
    /// across restarts, same as the `show_*_column` flags above. Export
    /// (`export.rs`) deliberately ignores this and always writes
    /// chronological order.
    sort_descending: bool,
    /// `Settings::display_timezone`, resolved to a `TimezoneSpec` — what
    /// every window/full-entry fetch formats `timestamp_display` in.
    /// Defaults to UTC (same as every display before this setting
    /// existed); `app.rs` calls [`Self::set_display_timezone`] on startup
    /// and again whenever Settings are saved, the same refresh-on-save
    /// pattern `rules_dir` already uses.
    display_tz: TimezoneSpec,
}

impl TimelineView {
    /// `session_sqlite_path` is the session's `.sqlite` file — used to
    /// merge `analyst_tags` (manual, per-entry tags) into the Tags column
    /// alongside `import_tags` (rule-produced, lives in `db_path`'s
    /// DuckDB file instead). Two separate database files by design —
    /// merging them is this view's job, not either engine's.
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
            conn: RefCell::new(None),
            show_sourcetype_column: false,
            show_host_column: false,
            show_process_column: false,
            show_event_code_column: false,
            show_subsystem_column: false,
            show_category_column: false,
            show_notes_column: false,
            column_order: DEFAULT_COLUMN_ORDER.to_vec(),
            sort_descending: false,
            display_tz: TimezoneSpec::Fixed(chrono::FixedOffset::east_opt(0).unwrap()),
        }
    }

    /// Sets the timezone future window/full-entry fetches format
    /// `timestamp_display` in — called by `app.rs` on startup (from
    /// `Settings::display_timezone`) and again whenever Settings are saved.
    /// Does not retroactively reformat the current cache; the next
    /// `ensure_window`/`fetch_full_entry` call picks it up, same as every
    /// other "changed setting only affects fetches from now on" case in
    /// this view.
    pub fn set_display_timezone(&mut self, display_tz: TimezoneSpec) {
        self.display_tz = display_tz;
    }

    /// Flips newest-first/oldest-first and drops the window cache — the
    /// filtered row count (`total_rows`) doesn't change, only the order
    /// `LIMIT`/`OFFSET` walks it in, so this only needs `refresh_window`,
    /// not a full `recount`.
    fn toggle_sort_direction(&mut self) {
        self.sort_descending = !self.sort_descending;
        self.refresh_window();
    }

    /// `column_order`, filtered down to whichever columns are actually
    /// enabled right now — the always-shown ones (Timestamp/Level/Source/
    /// Tags/Message) plus whichever optional ones the `show_*_column`
    /// flags currently allow. Order is preserved from `column_order`, so a
    /// drag-and-drop rearrangement still applies even while a column is
    /// toggled off and back on.
    fn visible_columns(&self) -> Vec<ColumnKind> {
        self.column_order
            .iter()
            .copied()
            .filter(|kind| match kind {
                ColumnKind::Timestamp
                | ColumnKind::Level
                | ColumnKind::Source
                | ColumnKind::Tags
                | ColumnKind::Message => true,
                ColumnKind::Sourcetype => self.show_sourcetype_column,
                ColumnKind::Host => self.show_host_column,
                ColumnKind::Process => self.show_process_column,
                ColumnKind::EventCode => self.show_event_code_column,
                ColumnKind::Subsystem => self.show_subsystem_column,
                ColumnKind::Category => self.show_category_column,
                ColumnKind::Notes => self.show_notes_column,
            })
            .collect()
    }

    /// Hands out a connection to the same open database instance as every
    /// other clone from this view — and, via `PeachApp`'s own use of this
    /// method, the same instance `run_load`/`run_retag`/the tag-preview
    /// count write and read through too. `try_clone()` reconnects to the
    /// already-open file (no new OS-level file lock); it does not
    /// independently re-open `db_path` from disk.
    ///
    /// This isn't just an optimization: DuckDB only reliably tolerates one
    /// independent `Connection::open` of a given file at a time within a
    /// process. A second, unrelated `open` while the first is still alive
    /// can fail — reliably on Windows (file locks are scoped per handle,
    /// not per process, so a second handle from the same process still
    /// conflicts), while POSIX's per-*process* advisory locks mostly hide
    /// the same hazard, which is why this only ever surfaced as CI
    /// failures on `windows-latest`.
    ///
    /// Opens `db_path` lazily, on the first call — not in `new` — so a
    /// session nothing has been loaded into yet still has no `.duckdb` file
    /// on disk. `session_dialog`'s empty-session cleanup keys off exactly
    /// that file's absence.
    pub fn try_clone_conn(&self) -> Option<Connection> {
        if let Some(conn) = self.conn.borrow().as_ref() {
            return conn.try_clone().ok();
        }
        let conn = Connection::open(&self.db_path).ok()?;
        let clone = conn.try_clone().ok();
        *self.conn.borrow_mut() = Some(conn);
        clone
    }

    /// Drops the base connection [`Self::try_clone_conn`] keeps alive,
    /// without touching `db_path` itself — the next call to
    /// `try_clone_conn` transparently reopens it fresh. Call after a large
    /// bulk load or re-tag finishes.
    ///
    /// This isn't just housekeeping: measured directly against a real
    /// multi-million-row load, DuckDB's Appender-based bulk-insert path
    /// leaves several GB attached to the database instance that stays
    /// resident for as long as *any* connection or clone to it remains
    /// open — but is fully released once every one of them is dropped,
    /// including this base connection, not just the clone that did the
    /// actual inserting (that one alone already goes out of scope when
    /// `run_load`/`run_retag` return). Since every other consumer only
    /// ever holds a short-lived clone, this base connection — kept alive
    /// for this view's entire lifetime otherwise — is the one thing still
    /// pinning that memory once a load/re-tag's own clone is gone.
    pub fn reopen_connection(&self) {
        *self.conn.borrow_mut() = None;
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

    /// Drops the window cache and any in-flight window fetch, without
    /// touching the row counts — unlike `refresh`, doesn't run a DuckDB
    /// recount or show "Filtering…". Call after a change that's confined to
    /// the SQLite session DB (an analyst note or tag edited/added/removed):
    /// `analyst_tags`/`event_notes` are merged into a window's rows in
    /// `spawn_window_fetch`, not counted by `count_matching` at all (that
    /// only ever queries DuckDB's `import_tags`/`log_entries`), so a note or
    /// manual tag edit can never change `total_rows`/`total_unfiltered_rows`
    /// — only the next window fetch needs to pick up the new merge.
    pub fn refresh_window(&mut self) {
        self.cache = None;
        self.window_rx = None;
        self.pending_window_offset = None;
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

    /// The currently active filter — what "Export..." exports (see
    /// `export`'s module doc comment on why there's no separate "export
    /// everything" path).
    pub fn query(&self) -> &Query {
        &self.query
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
        let conn = self.try_clone_conn();
        let (tx, rx) = mpsc::channel();
        self.count_rx = Some(rx);
        std::thread::spawn(move || {
            let total = conn
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
    /// thread — same reasoning as `recount`, its own connection (via
    /// [`Self::try_clone_conn`]) since `Connection` can't be moved into an
    /// already-running thread.
    fn recount_total(&mut self) {
        let conn = self.try_clone_conn();
        let (tx, rx) = mpsc::channel();
        self.total_rx = Some(rx);
        std::thread::spawn(move || {
            let total = conn
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

    /// Gets a fresh connection handle per call (via [`Self::try_clone_conn`])
    /// rather than reusing one — same reasoning as `recount`/`fetch_window`:
    /// a load or re-tag writes `import_tags`/`log_entries` from its own,
    /// separate connection on a background thread, and a long-lived
    /// connection kept around on this side isn't guaranteed to see those
    /// writes on its next query. That bug was real, not hypothetical:
    /// without this, the Tag filter row's vocabulary could stay stuck at
    /// whatever `import_tags` looked like the *first* time this was called,
    /// even after later tagging added rows — see
    /// `distinct_tags_sees_tags_written_by_a_different_connection_afterward`.
    /// `(value, display-label)` pairs for the quick Level-filter row — one
    /// entry per distinct `level` value across every loaded source, labeled
    /// via [`level_display_name`] when every sourcetype using that value
    /// agrees on what it means. A value used by two loaded sourcetypes with
    /// genuinely different meanings for the same digit (e.g. journald's
    /// `"2"` is `crit`, EVTX's `"2"` is `Error`) shows both names rather
    /// than silently picking one — same "don't misrepresent a value" call
    /// as `timeline_queries::extracted_field_sql`'s doc comment. Falls back
    /// to the bare value when no loaded sourcetype has a confirmed mapping
    /// for it (AUL's `LogType` names, a text log's ERROR/WARN/INFO, ...).
    pub fn distinct_levels(&self) -> Vec<(String, String)> {
        let Some(conn) = self.try_clone_conn() else {
            return Vec::new();
        };
        let Ok(pairs) = timeline_queries::distinct_levels_by_sourcetype(&conn) else {
            return Vec::new();
        };

        let mut names_by_level: Vec<(String, Vec<&'static str>)> = Vec::new();
        for (level, sourcetype) in &pairs {
            let entry = match names_by_level.iter_mut().find(|(v, _)| v == level) {
                Some(entry) => entry,
                None => {
                    names_by_level.push((level.clone(), Vec::new()));
                    names_by_level.last_mut().unwrap()
                }
            };
            if let Some(name) = level_display_name(level, sourcetype)
                && !entry.1.contains(&name)
            {
                entry.1.push(name);
            }
        }

        names_by_level
            .into_iter()
            .map(|(level, names)| {
                let label = if names.is_empty() {
                    level.clone()
                } else {
                    format!("{level} ({})", names.join("/"))
                };
                (level, label)
            })
            .collect()
    }

    pub fn distinct_tags(&self) -> Vec<String> {
        self.try_clone_conn()
            .and_then(|conn| timeline_queries::distinct_tags(&conn).ok())
            .unwrap_or_default()
    }

    /// Whole-loaded-timeline per-value event counts for `ui::filter_bar`'s
    /// Level/Tag/Sources dropdowns — see `timeline_queries::tag_counts`'s
    /// doc comment for why these are a snapshot (refreshed the same
    /// `distinct_tags`/`distinct_levels` call sites already refresh on) and
    /// not a live, filter-relative number.
    pub fn tag_counts(&self) -> std::collections::HashMap<String, usize> {
        self.try_clone_conn()
            .and_then(|conn| timeline_queries::tag_counts(&conn).ok())
            .unwrap_or_default()
    }

    /// See [`Self::tag_counts`].
    pub fn level_counts(&self) -> std::collections::HashMap<String, usize> {
        self.try_clone_conn()
            .and_then(|conn| timeline_queries::level_counts(&conn).ok())
            .unwrap_or_default()
    }

    /// See [`Self::tag_counts`].
    pub fn source_counts(&self) -> std::collections::HashMap<String, usize> {
        self.try_clone_conn()
            .and_then(|conn| timeline_queries::source_counts(&conn).ok())
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
    /// (a `try_clone_conn()` for the timeline, a fresh `rusqlite::Connection`
    /// for the small per-session SQLite file — `Connection` can't be moved
    /// into an already-running thread) and merges in `analyst_tags` and
    /// `event_notes` there too — same reasoning as [`Self::recount`].
    fn spawn_window_fetch(&mut self, offset: usize) {
        self.pending_window_offset = Some(offset);
        let query = self.query.clone();
        let conn = self.try_clone_conn();
        let session_sqlite_path = self.session_sqlite_path.clone();
        let display_tz = self.display_tz;
        let sort_descending = self.sort_descending;
        let (tx, rx) = mpsc::channel();
        self.window_rx = Some(rx);
        std::thread::spawn(move || {
            let Some(conn) = conn else {
                return;
            };
            let Ok(mut rows) = timeline_queries::fetch_window(
                &conn,
                &query,
                offset,
                WINDOW_SIZE,
                &display_tz,
                sort_descending,
            ) else {
                return;
            };

            // Merge in analyst_tags/event_notes (SQLite, a different
            // database file than the DuckDB timeline) — the former so the
            // Tags column reflects both rule-produced and manually-set
            // tags, the latter (independent of tags entirely) for the Tags
            // column's hover text. Best-effort: a failure here just means
            // neither shows up for this window, not that the fetch fails.
            if let Ok(session_conn) = rusqlite::Connection::open(&session_sqlite_path) {
                if let Ok(analyst_tags) = persist::all_analyst_tags(&session_conn) {
                    for row in &mut rows {
                        if let Some(extra) = analyst_tags.get(&row.event_id) {
                            row.tags.extend(extra.iter().cloned());
                            row.tags.sort();
                            row.tags.dedup();
                        }
                    }
                }
                if let Ok(notes) = persist::all_event_notes(&session_conn) {
                    for row in &mut rows {
                        if let Some(extra) = notes.get(&row.event_id) {
                            row.notes.extend(extra.iter().cloned());
                        }
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

        ui.horizontal(|ui| {
            ui.menu_button("Columns", |ui| {
                ui.checkbox(&mut self.show_sourcetype_column, "Sourcetype");
                ui.checkbox(&mut self.show_host_column, "Host");
                ui.checkbox(&mut self.show_process_column, "Process");
                ui.checkbox(&mut self.show_event_code_column, "Event ID");
                ui.checkbox(&mut self.show_subsystem_column, "Subsystem");
                ui.checkbox(&mut self.show_category_column, "Category");
                ui.checkbox(&mut self.show_notes_column, "Notes");
                ui.separator();
                ui.weak("Drag a column header to reorder it.");
            });

            let sort_label = if self.sort_descending {
                "Timestamp ▼ (newest first)"
            } else {
                "Timestamp ▲ (oldest first)"
            };
            if ui
                .button(sort_label)
                .on_hover_text("Toggle sort direction")
                .clicked()
            {
                self.toggle_sort_direction();
            }
        });

        let mut requested = None;
        let total_rows = self.total_rows;
        let visible = self.visible_columns();
        let mut table = TableBuilder::new(ui)
            .striped(true)
            // Rows only sense hover by default — a right-click context
            // menu needs click sensing on the row's `response()`, or
            // `.context_menu()` never fires no matter what's inside it.
            .sense(egui::Sense::click());
        for (i, kind) in visible.iter().enumerate() {
            // Whichever column ends up last (order can change via drag-and-
            // drop) gets the remaining width — same as `Message` always did
            // back when it was hardcoded last; every other column is a
            // fixed minimum width that grows to fit its content.
            let column = if i + 1 == visible.len() {
                Column::remainder()
            } else {
                Column::auto().at_least(kind.min_width())
            };
            table = table.column(column);
        }

        let mut pending_reorder: Option<(ColumnKind, ColumnKind)> = None;
        table
            .header(20.0, |mut header| {
                for kind in &visible {
                    header.col(|ui| {
                        // A drag source *and* a drop target at once: every
                        // header cell can both be picked up and be dropped
                        // onto. `dnd_drag_source` paints a floating copy at
                        // the cursor while dragging; `dnd_release_payload`
                        // on the same response fires once, the frame the
                        // drag is released over this cell.
                        //
                        // Explicit `Id`, not `ui.id().with(...)`: the id
                        // this closure's `ui` carries is table-internal
                        // (egui_extras salts it from `(row_index,
                        // col_index)`), not something worth depending on
                        // for a drag/drop identity that has to stay stable
                        // across frames regardless of column position.
                        //
                        // `with_main_justify(true)`: without it, the
                        // draggable/droppable area is only as big as the
                        // label text itself (`dnd_drag_source` derives its
                        // interact rect from whatever `add_contents`
                        // painted), which for a header cell can be far
                        // smaller than the column's actual width — dropping
                        // anywhere in the rest of the cell wouldn't
                        // register at all. This makes the content fill the
                        // whole cell instead, so the entire header is both
                        // grabbable and a drop target.
                        let id = egui::Id::new("timeline_column_header").with(*kind);
                        let response = ui
                            .dnd_drag_source(id, *kind, |ui| {
                                ui.with_layout(
                                    egui::Layout::left_to_right(egui::Align::Center)
                                        .with_main_justify(true),
                                    |ui| {
                                        ui.strong(kind.label());
                                    },
                                );
                            })
                            .response;
                        if let Some(dragged) = response.dnd_release_payload::<ColumnKind>() {
                            pending_reorder = Some((*dragged, *kind));
                        }
                    });
                }
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

                    let mut full_row_rect: Option<egui::Rect> = None;
                    for (i, kind) in visible.iter().enumerate() {
                        let is_last = i + 1 == visible.len();
                        let (rect, _) = row.col(|ui| {
                            let Some(d) = display else { return };
                            match kind {
                                ColumnKind::Timestamp => {
                                    ui.label(d.timestamp_display.as_str());
                                }
                                ColumnKind::Level => {
                                    if !d.level.is_empty() {
                                        let color =
                                            categorical_color(&d.level, ui.visuals().dark_mode);
                                        ui.colored_label(
                                            color,
                                            format_level(&d.level, &d.sourcetype),
                                        );
                                    }
                                }
                                ColumnKind::Source => {
                                    if !d.source_path.is_empty() {
                                        let label =
                                            source_display_label(&d.source_path, &d.sourcetype);
                                        ui.label(label).on_hover_text(&d.source_path);
                                    }
                                }
                                ColumnKind::Sourcetype => {
                                    ui.label(d.sourcetype.as_str());
                                }
                                ColumnKind::Host => {
                                    ui.label(d.host.as_str());
                                }
                                ColumnKind::Process => {
                                    ui.label(d.process.as_str());
                                }
                                ColumnKind::EventCode => {
                                    ui.label(d.event_code.as_str());
                                }
                                ColumnKind::Subsystem => {
                                    ui.label(d.subsystem.as_str());
                                }
                                ColumnKind::Category => {
                                    ui.label(d.category.as_str());
                                }
                                ColumnKind::Tags => {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.spacing_mut().item_spacing.x = 6.0;
                                        for tag in &d.tags {
                                            let color =
                                                categorical_color(tag, ui.visuals().dark_mode);
                                            ui.colored_label(color, tag);
                                        }
                                        // A visible marker even when
                                        // `d.tags` is empty: notes don't
                                        // require a tag to exist (see
                                        // `session::persist::insert_event_note`),
                                        // so an untagged row can still have
                                        // one. The note text itself isn't
                                        // attached as hover text here — see
                                        // the row-spanning interact widget
                                        // below, where it actually has a
                                        // chance of registering as hovered.
                                        if !d.notes.is_empty() {
                                            ui.label("📝");
                                        }
                                    });
                                }
                                ColumnKind::Notes => {
                                    if !d.notes.is_empty() {
                                        // Multiple notes on one event joined
                                        // with " | " for a single-line cell.
                                        ui.label(d.notes.join(" | "));
                                    }
                                }
                                ColumnKind::Message => {
                                    ui.label(d.message.as_str());
                                }
                            }

                            // Whichever column is last owns the row's
                            // right-click context menu — not tied to
                            // `Message` specifically now that drag-and-drop
                            // can put any column last, and it doesn't
                            // matter which cell's closure runs this: the
                            // interact rect below spans the whole row
                            // regardless. Not `row.response().context_menu(...)`:
                            // that response is a union of each cell's own
                            // interact state, and empirically only some
                            // cells ever registered hover or a right-click,
                            // for reasons not fully pinned down in
                            // egui_extras' per-cell layout internals.
                            // Explicitly interacting over the whole row's
                            // rect (every earlier cell's rect, unioned as
                            // they were returned, plus this cell's own via
                            // `ui.max_rect()`) sidesteps that entirely.
                            if is_last {
                                let event_id = d.event_id;
                                let message = d.message.clone();
                                let conn = self.try_clone_conn();
                                let timestamp = chrono::NaiveDateTime::parse_from_str(
                                    &d.timestamp_utc,
                                    "%Y-%m-%d %H:%M:%S%.f",
                                )
                                .ok();

                                let full_row_rect = full_row_rect
                                    .map_or(ui.max_rect(), |acc| acc.union(ui.max_rect()));
                                let mut row_response = ui.interact(
                                    full_row_rect,
                                    ui.id().with(("row_context_menu", row_index)),
                                    egui::Sense::click(),
                                );

                                if !d.notes.is_empty() {
                                    // Attached here, not on the Tags/Notes
                                    // cells' own widgets: this row-spanning
                                    // interact widget is created after every
                                    // per-cell one, and egui only reports the
                                    // topmost click-sensing widget under the
                                    // pointer as hovered — an underlying
                                    // widget's own `.on_hover_text()` never
                                    // fires once this one exists over it, so
                                    // this is the only widget in the row a
                                    // tooltip can actually attach to.
                                    row_response = row_response.on_hover_text(d.notes.join("\n"));
                                }

                                row_response.context_menu(|ui| {
                                    if ui.button("Copy message").clicked() {
                                        ui.ctx().copy_text(message.clone());
                                        ui.close();
                                    }
                                    if ui.button("Copy whole event as text").clicked() {
                                        // `.as_ref()`, not consuming `conn`
                                        // by value: "View raw/fields..."
                                        // below needs it too, and both
                                        // buttons' bodies exist in the same
                                        // frame's closure regardless of
                                        // which one is actually clicked.
                                        if let Some(text) = conn
                                            .as_ref()
                                            .and_then(|conn| {
                                                timeline_queries::fetch_full_entry(
                                                    conn,
                                                    event_id,
                                                    &self.display_tz,
                                                )
                                                .ok()
                                            })
                                            .flatten()
                                            .map(|entry| entry.to_text())
                                        {
                                            ui.ctx().copy_text(text);
                                        }
                                        ui.close();
                                    }
                                    if ui.button("View raw/fields...").clicked() {
                                        if let Some(entry) = conn
                                            .as_ref()
                                            .and_then(|conn| {
                                                timeline_queries::fetch_full_entry(
                                                    conn,
                                                    event_id,
                                                    &self.display_tz,
                                                )
                                                .ok()
                                            })
                                            .flatten()
                                        {
                                            requested = Some(RowAction::ViewRawFields { entry });
                                        }
                                        ui.close();
                                    }
                                    let filterable: Vec<(&'static str, &'static str, &str)> =
                                        timeline_queries::COLUMN_FILTER_FIELDS
                                            .iter()
                                            .filter_map(|&(field, label)| {
                                                let value: &str = match field {
                                                    "sourcetype" => d.sourcetype.as_str(),
                                                    "host" => d.host.as_str(),
                                                    "process" => d.process.as_str(),
                                                    "event_id" => d.event_code.as_str(),
                                                    "subsystem" => d.subsystem.as_str(),
                                                    "category" => d.category.as_str(),
                                                    _ => unreachable!(
                                                        "COLUMN_FILTER_FIELDS and this match must \
                                                         list exactly the same fields"
                                                    ),
                                                };
                                                (!value.is_empty()).then_some((field, label, value))
                                            })
                                            .collect();
                                    if !filterable.is_empty() {
                                        ui.menu_button("Filter by...", |ui| {
                                            for (field, label, value) in &filterable {
                                                if ui.button(format!("{label} = {value}")).clicked()
                                                {
                                                    requested = Some(RowAction::FilterByColumn {
                                                        field,
                                                        value: value.to_string(),
                                                    });
                                                    ui.close();
                                                }
                                            }
                                        });
                                    }
                                    ui.separator();
                                    if let Some(timestamp) = timestamp {
                                        ui.menu_button("Show context around this event", |ui| {
                                            for minutes in [1, 5, 15, 60] {
                                                if ui.button(format!("± {minutes} min")).clicked()
                                                {
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
                                        requested = Some(RowAction::TagAllMatching {
                                            event_id,
                                            message,
                                            sourcetype: d.sourcetype.clone(),
                                            fields: filterable
                                                .iter()
                                                .map(|&(field, label, value)| {
                                                    (field, label, value.to_string())
                                                })
                                                .collect(),
                                        });
                                        ui.close();
                                    }
                                    if ui.button("Notes...").clicked() {
                                        requested = Some(RowAction::ManageNotes { event_id });
                                        ui.close();
                                    }
                                });
                            }
                        });
                        full_row_rect = Some(full_row_rect.map_or(rect, |acc| acc.union(rect)));
                    }
                });
            });
        if let Some((dragged, target)) = pending_reorder {
            reorder_columns(&mut self.column_order, dragged, target);
        }
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
    fn format_level_appends_the_syslog_severity_name_for_journald() {
        assert_eq!(format_level("6", "journald"), "6 (info)");
        assert_eq!(format_level("0", "journald"), "0 (emerg)");
        assert_eq!(format_level("7", "journald"), "7 (debug)");
    }

    #[test]
    fn format_level_leaves_unmapped_sourcetypes_untouched() {
        assert_eq!(format_level("ERROR", "text_config"), "ERROR");
        assert_eq!(format_level("Info", "aul"), "Info");
    }

    #[test]
    fn format_level_passes_through_an_unrecognized_journald_digit() {
        assert_eq!(format_level("9", "journald"), "9");
    }

    #[test]
    fn format_level_appends_the_windows_event_level_name_for_evtx() {
        assert_eq!(format_level("2", "evtx"), "2 (Error)");
        assert_eq!(format_level("3", "evtx"), "3 (Warning)");
        assert_eq!(format_level("4", "evtx"), "4 (Informational)");
    }

    #[test]
    fn source_display_label_shows_the_full_path_for_aul() {
        // AUL's "file" is a directory the analyst picked — its last path
        // component (e.g. "db") isn't distinctive the way a real filename
        // is, so the full path is shown instead of being truncated.
        assert_eq!(
            source_display_label("/home/kalinko/Documents/temp/db", "aul"),
            "/home/kalinko/Documents/temp/db"
        );
    }

    #[test]
    fn source_display_label_shows_only_the_filename_for_other_sourcetypes() {
        assert_eq!(
            source_display_label("/var/log/security.evtx", "evtx"),
            "security.evtx"
        );
        assert_eq!(
            source_display_label("/var/log/syslog", "journald"),
            "syslog"
        );
    }

    #[test]
    fn reorder_columns_moves_dragged_before_target() {
        let mut order = vec![
            ColumnKind::Timestamp,
            ColumnKind::Level,
            ColumnKind::Source,
            ColumnKind::Message,
        ];

        // Drag Source onto Timestamp: Source should land right before it.
        reorder_columns(&mut order, ColumnKind::Source, ColumnKind::Timestamp);

        assert_eq!(
            order,
            vec![
                ColumnKind::Source,
                ColumnKind::Timestamp,
                ColumnKind::Level,
                ColumnKind::Message,
            ]
        );
    }

    #[test]
    fn reorder_columns_dropping_onto_itself_is_a_no_op() {
        let mut order = vec![ColumnKind::Timestamp, ColumnKind::Level];

        reorder_columns(&mut order, ColumnKind::Level, ColumnKind::Level);

        assert_eq!(order, vec![ColumnKind::Timestamp, ColumnKind::Level]);
    }

    #[test]
    fn reorder_columns_dropping_onto_the_immediate_successor_is_a_no_op() {
        // Moving `Level` to "just before `Source`" when it's already
        // immediately before `Source` must leave the order unchanged, not
        // remove-then-reinsert-at-the-same-spot in a way that looks like a
        // change.
        let mut order = vec![ColumnKind::Timestamp, ColumnKind::Level, ColumnKind::Source];

        reorder_columns(&mut order, ColumnKind::Level, ColumnKind::Source);

        assert_eq!(
            order,
            vec![ColumnKind::Timestamp, ColumnKind::Level, ColumnKind::Source]
        );
    }

    #[test]
    fn visible_columns_preserves_column_order_and_respects_visibility_flags() {
        let db_path = temp_db_path("visible-columns");
        let mut view = TimelineView::new(db_path, temp_sqlite_path("session"));
        view.show_host_column = true;
        view.show_category_column = true;
        // Move Host ahead of Timestamp, so order is provably not just
        // "always DEFAULT_COLUMN_ORDER filtered" — it must reflect the
        // rearrangement too.
        reorder_columns(
            &mut view.column_order,
            ColumnKind::Host,
            ColumnKind::Timestamp,
        );

        let visible = view.visible_columns();

        assert_eq!(
            visible,
            vec![
                ColumnKind::Host,
                ColumnKind::Timestamp,
                ColumnKind::Level,
                ColumnKind::Source,
                ColumnKind::Category,
                ColumnKind::Tags,
                ColumnKind::Message,
            ]
        );
    }

    #[test]
    fn format_level_passes_through_an_unrecognized_evtx_level() {
        // 6-255 are provider-defined/reserved, not part of the fixed
        // standard set — must not be mapped to a guessed name.
        assert_eq!(format_level("16", "evtx"), "16");
    }

    #[test]
    fn reopen_connection_still_works_afterward() {
        let db_path = temp_db_path("reopen");
        let view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        let first = view.try_clone_conn().unwrap();
        first.execute("CREATE TABLE t (x INTEGER)", []).unwrap();
        drop(first);

        view.reopen_connection();

        let second = view.try_clone_conn().unwrap();
        let count: i64 = second
            .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        std::fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn reopen_connection_before_the_file_ever_existed_is_a_no_op() {
        let db_path = temp_db_path("reopen-empty");
        let view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));

        // No try_clone_conn() call yet — self.conn is already None, and
        // reopen_connection() must tolerate that instead of panicking.
        view.reopen_connection();

        assert!(!db_path.exists());
    }

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
    /// from a different `Connection` — a `try_clone_conn()` sibling, its own
    /// background thread, exactly like `run_load`/`run_retag` — and then
    /// calls `distinct_tags()` again. That second call must see the new tag
    /// — not whatever `import_tags` looked like when the first call
    /// happened to run.
    #[test]
    fn distinct_tags_sees_tags_written_by_a_different_connection_afterward() {
        let db_path = temp_db_path("distinct-tags-fresh-read");
        seed_db(&db_path, &["hello"]);

        let view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        assert_eq!(view.distinct_tags(), Vec::<String>::new());

        {
            // Not an independent `Connection::open` of the same file: `view`
            // already holds `db_path` open (lazily, since the assertion
            // above), and a second, unrelated `open` while that's alive is
            // exactly the Windows lock conflict `try_clone_conn` exists to
            // avoid. `try_clone_conn()` still hands back a genuinely
            // different `Connection` object, which is what this test needs
            // to exercise.
            let conn = view.try_clone_conn().unwrap();
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

    /// Regression test for the note/manual-tag "Filtering…" flash: adding a
    /// note or an analyst tag only changes the SQLite session DB, which
    /// `count_matching` never queries, so `refresh_window` must drop the
    /// window cache (so the next fetch picks up the new note/tag merge)
    /// without kicking off a recount or flipping `counting` — unlike
    /// `refresh`, which does both.
    #[test]
    fn refresh_window_drops_the_cache_without_recounting() {
        let db_path = temp_db_path("refresh-window");
        seed_db(&db_path, &["one", "two", "three"]);
        let ctx = egui::Context::default();

        let mut view = TimelineView::new(db_path.clone(), temp_sqlite_path("session"));
        view.refresh();
        wait_for_count(&mut view, &ctx);
        wait_for_total(&mut view, &ctx);
        view.ensure_window(0);
        wait_for_window(&mut view, &ctx);
        assert!(view.cache.is_some());

        view.refresh_window();

        assert!(view.cache.is_none());
        assert!(view.window_rx.is_none());
        assert!(view.pending_window_offset.is_none());
        // Row counts survive untouched, and no new background count was
        // spawned — the whole point of `refresh_window` over `refresh`.
        assert!(!view.counting);
        assert!(view.count_rx.is_none());
        assert_eq!(view.total_rows(), 3);
        assert_eq!(view.total_unfiltered_rows(), 3);
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

    /// A manual analyst tag and an independent event note, written to the
    /// session SQLite file by a different connection (same setup as
    /// `distinct_tags_sees_tags_written_by_a_different_connection_afterward`,
    /// but exercising the `analyst_tags`/`event_notes` merge paths instead
    /// of `import_tags`), must show up on the matching rows' `tags`/`notes`
    /// once the window fetch picks them up — on *different* rows here,
    /// specifically to pin down that a note needs no tag to exist: the
    /// note-only row must still surface its note with `tags` empty.
    #[test]
    fn ensure_window_merges_analyst_tags_and_notes() {
        let db_path = temp_db_path("window-analyst-notes");
        let sqlite_path = temp_sqlite_path("window-analyst-notes");
        let source_file_id = SourceFileId::new_random();
        let mut counter = SequenceCounter::new();
        let tagged_event = EventId {
            source_file_id,
            sequence_number: counter.next_sequence_number(),
        };
        let noted_event = EventId {
            source_file_id,
            sequence_number: counter.next_sequence_number(),
        };
        {
            let conn = Connection::open(&db_path).unwrap();
            setup_timeline_schema(&conn).unwrap();
            for (event_id, message) in [(tagged_event, "hello"), (noted_event, "world")] {
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
        {
            let session_conn = rusqlite::Connection::open(&sqlite_path).unwrap();
            crate::db::session_schema::setup_session_schema(&session_conn).unwrap();
            persist::insert_analyst_tag(&session_conn, tagged_event, "reviewed").unwrap();
            persist::insert_event_note(&session_conn, noted_event, "check this").unwrap();
        }

        let ctx = egui::Context::default();
        let mut view = TimelineView::new(db_path.clone(), sqlite_path);
        view.set_query(Query::default());
        wait_for_count(&mut view, &ctx);
        view.ensure_window(0);
        wait_for_window(&mut view, &ctx);

        let cache = view
            .cache
            .as_ref()
            .expect("window fetch should have landed");
        let tagged_row = cache
            .rows
            .iter()
            .find(|row| row.event_id == tagged_event)
            .unwrap();
        let noted_row = cache
            .rows
            .iter()
            .find(|row| row.event_id == noted_event)
            .unwrap();
        assert_eq!(tagged_row.tags, vec!["reviewed".to_string()]);
        assert!(tagged_row.notes.is_empty());
        assert!(noted_row.tags.is_empty(), "a note must not require a tag");
        assert_eq!(noted_row.notes, vec!["check this".to_string()]);
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
