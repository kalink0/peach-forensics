use std::collections::HashMap;

use duckdb::{Connection, types::Value};

use crate::model::event_id::EventId;
use crate::model::timezone_spec::TimezoneSpec;

/// The format `timestamp_display` is always rendered in, before
/// [`TimezoneSpec::format_utc`] appends its self-describing `%:z` offset —
/// same precision `timestamp_utc` itself always used, just no longer
/// hardcoded to UTC.
const DISPLAY_TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f";

/// A Splunk-inspired v1 search grammar — whitespace-separated terms,
/// implicit `AND`, explicit `OR`, `NOT`/`-` negation, `field=value` /
/// `field:value` for exact filters, `field!=value` for negated exact
/// filters (sugar for `NOT field=value` — see [`parse_term_kind`]),
/// `field~value` for regex, quoted phrases, bare words as free text against
/// `message` and `raw`.
/// Left-associative, no parentheses, no operator precedence — deliberately
/// deferred, not an oversight (see [`crate::ui::filter_bar`]'s doc comment
/// for why the multi-select filter buttons work around this with a single
/// anchored regex alternation instead of composing several terms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Level,
    /// `sourcetype=` — the format (`aul`/`evtx`/`journald`/...), matched
    /// against `sources.sourcetype`. Exact match, like `Level`.
    Sourcetype,
    /// `source=` — the actual evidence file, matched against `sources.path`.
    /// Substring match by default (like `Message`/`Raw`), since a full path
    /// is rarely worth typing out — `source~` for a regex still works the
    /// same as any other field.
    SourceFile,
    /// `source_id=` — the internal `source_file_id` (a random UUID assigned
    /// per load, see [`crate::model::event_id::SourceFileId`]), matched
    /// exactly against `sources.source_file_id`. Not something an analyst
    /// would type by hand — this exists for `ui::filter_bar`'s per-source
    /// visibility chips ("hide this loaded source without unloading it"),
    /// which need to target one *specific load* rather than a path
    /// substring: two independent loads of the same file (the same path
    /// string, loaded twice — not deduplicated by design, see
    /// `SourceFileId`'s own doc comment) must stay independently
    /// hideable, and a path can contain spaces a plain
    /// `source="<path>"` term would need quoting for. A UUID has neither
    /// problem.
    SourceId,
    Tag,
    Message,
    Raw,
    /// `event_id=` — EVTX's `Event.System.EventID` (e.g. `4625`), the same
    /// value the "Event ID" column shows (see `extracted_field_sql`'s doc
    /// comment). Exact match by default, like `Level`/`Sourcetype` — an
    /// event ID is a whole number, not free text to substring-search.
    /// `NULL`/no match for every sourcetype other than `evtx`, same as the
    /// column itself.
    EventId,
    /// `host=` — the "Host" column's value (journald's `_HOSTNAME`, EVTX's
    /// `Event.System.Computer`; empty/no match for AUL/`text_config`). Exact
    /// match, same reasoning as `EventId` — a hostname is a discrete value
    /// to match exactly, not free text; use `host~` for partial matches.
    Host,
    /// `process=` — the "Process" column's value (journald's
    /// `SYSLOG_IDENTIFIER`/`_COMM`, AUL's `process`; empty/no match for
    /// EVTX/`text_config`). Exact match, same reasoning as `Host`.
    Process,
    /// `subsystem=` — the "Subsystem" column's value (AUL's `subsystem`,
    /// EVTX's `Event.System.Provider_attributes.Name`; empty/no match for
    /// journald/`text_config`). Exact match, same reasoning as `Host`.
    Subsystem,
    /// `category=` — the "Category" column's value (AUL's `category`;
    /// empty/no match for every other sourcetype — see
    /// `extracted_field_sql`'s doc comment on why EVTX's superficially
    /// similar `Channel` deliberately isn't mapped here). Exact match, same
    /// reasoning as `Host`.
    Category,
    /// `timestamp_utc >= value`. `value` is parsed at compile time (not
    /// here) since a malformed timestamp still needs to produce a valid,
    /// always-false query rather than a parse error — see
    /// `parse_query_timestamp`.
    After,
    /// `timestamp_utc <= value`.
    Before,
}

impl Field {
    /// `pub(crate)`, not private: `app.rs`'s Advanced tagging preview count
    /// also needs to turn one of `COLUMN_FILTER_FIELDS`'s keyword strings
    /// back into a `Field` to build a `Query` directly (see
    /// `TagDialogOutcome::CreateRule`'s `RuleCondition::FieldEquals`
    /// handling) — those keyword strings are defined to be exactly what
    /// this function accepts, so there's no real parsing risk in exposing
    /// it, just reuse.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "level" => Some(Self::Level),
            "sourcetype" => Some(Self::Sourcetype),
            "source" => Some(Self::SourceFile),
            "source_id" => Some(Self::SourceId),
            "tag" => Some(Self::Tag),
            "message" => Some(Self::Message),
            "raw" => Some(Self::Raw),
            "event_id" => Some(Self::EventId),
            "host" => Some(Self::Host),
            "process" => Some(Self::Process),
            "subsystem" => Some(Self::Subsystem),
            "category" => Some(Self::Category),
            "after" => Some(Self::After),
            "before" => Some(Self::Before),
            _ => None,
        }
    }
}

/// `(grammar keyword, display label)` pairs for every exact-match field
/// that doesn't already have its own dedicated quick-filter UI
/// (`ui::filter_bar`'s Level/Tag/Sources dropdowns) — Sourcetype, Host,
/// Process, `event_id`, Subsystem, Category. Shared by two call sites that
/// would otherwise drift apart: `ui::timeline_view`'s row context menu
/// ("Filter by..." submenu, built from a clicked row's own field values)
/// and `ui::filter_bar`'s "Active filters" chip row (scans the current
/// query text for which of these are currently set). One list, so adding
/// a seventh column-filterable field later only means editing this array.
pub(crate) const COLUMN_FILTER_FIELDS: [(&str, &str); 6] = [
    ("sourcetype", "Sourcetype"),
    ("host", "Host"),
    ("process", "Process"),
    ("event_id", "Event ID"),
    ("subsystem", "Subsystem"),
    ("category", "Category"),
];

#[derive(Debug, Clone, PartialEq)]
pub enum TermKind {
    /// Bare word or quoted phrase without a recognized `field=`/`field:`/
    /// `field~` prefix — substring match against `message` OR `raw`. Also
    /// the fallback when a `word=...` prefix doesn't match a known field
    /// name, so a typo degrades to "search for this literally" rather than
    /// a hard parse error.
    FreeText(String),
    Field {
        field: Field,
        value: String,
        is_regex: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Term {
    /// Connector joining this term to the accumulated result of every term
    /// before it. Ignored for the first term.
    pub connector: Connector,
    pub negate: bool,
    pub kind: TermKind,
}

/// A parsed query: a flat, left-associative sequence of [`Term`]s.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Query {
    pub terms: Vec<Term>,
}

impl Query {
    pub fn parse(input: &str) -> Self {
        let mut terms = Vec::new();
        let mut connector = Connector::And;
        let mut negate = false;

        for token in tokenize(input) {
            match token.to_ascii_uppercase().as_str() {
                "OR" => {
                    connector = Connector::Or;
                    continue;
                }
                "AND" => {
                    connector = Connector::And;
                    continue;
                }
                "NOT" => {
                    negate = true;
                    continue;
                }
                _ => {}
            }

            let (negate_prefix, raw) = match token.strip_prefix('-') {
                Some(rest) if !rest.is_empty() => (true, rest),
                _ => (false, token.as_str()),
            };

            let (kind, negate_operator) = parse_term_kind(raw);
            terms.push(Term {
                connector,
                // Three independent ways to negate a term (`NOT`, a `-`
                // prefix, `field!=value`'s own built-in negation) combine
                // via OR, not XOR — `-field!=value` still just means "not",
                // same as any one of them alone. Consistent with how `NOT`
                // and `-` already combined before `!=` existed; a
                // double-negation-cancels reading would be surprising for
                // something this rarely stacked, not more correct.
                negate: negate || negate_prefix || negate_operator,
                kind,
            });
            connector = Connector::And;
            negate = false;
        }

        Self { terms }
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }
}

/// Splits `input` on whitespace, treating `"..."` as one token (quotes
/// dropped, spaces inside preserved) — so `field="a b"` and `"a b"` each
/// become a single raw token.
///
/// `pub(crate)` — also used by `ui::filter_bar`'s per-column right-click
/// filters (Host/Process/Subsystem/Category/`event_id`/Sourcetype), whose
/// values routinely contain whitespace (a process name, a hostname) where
/// every *other* term `filter_bar` writes (Level/Tag values, `source_id`
/// UUIDs, ISO dates) never does — those keep using plain
/// `str::split_whitespace` since they never need quote-awareness.
pub(crate) fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in input.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Also returns whether the term parsed with its own built-in negation
/// (currently only `field!=value`) — the caller ORs this into the term's
/// `NOT`/`-`-prefix negation rather than this function returning a
/// `TermKind` that somehow carries negation itself, since negation is a
/// `Term`-level concept (see `Term::negate`), not a `TermKind` one.
fn parse_term_kind(raw: &str) -> (TermKind, bool) {
    // Checked before the single-char separator scan below: that scan's
    // `char_indices` search for `=`/`:`/`~` would otherwise land on the
    // `=` inside `!=` first, treating the `!` as part of the field name
    // (so `level!=ERROR` would look for a field literally called
    // `"level!"`, fail to find one, and silently fall through to
    // free-text) — checking the two-char operator first is what makes
    // `!=` actually reachable at all.
    if let Some(idx) = raw.find("!=") {
        let field_str = &raw[..idx];
        let value = &raw[idx + 2..];
        if let Some(field) = Field::parse(field_str) {
            return (
                TermKind::Field {
                    field,
                    value: value.to_string(),
                    is_regex: false,
                },
                true,
            );
        }
    }

    if let Some((idx, sep)) = raw
        .char_indices()
        .find(|(_, c)| matches!(c, '=' | ':' | '~'))
    {
        let field_str = &raw[..idx];
        let value = &raw[idx + sep.len_utf8()..];
        if let Some(field) = Field::parse(field_str) {
            return (
                TermKind::Field {
                    field,
                    value: value.to_string(),
                    is_regex: sep == '~',
                },
                false,
            );
        }
    }
    (TermKind::FreeText(raw.to_string()), false)
}

fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

struct CompiledQuery {
    from: String,
    where_clause: Option<String>,
    params: Vec<Value>,
}

impl Query {
    fn compile(&self) -> CompiledQuery {
        // Always joined, not just when a `sourcetype=`/`source=` term is
        // present: `fetch_window` needs `s.path`/`s.sourcetype` for every
        // row regardless of the active filter. `LEFT JOIN`, not `JOIN` —
        // `sources` only gains its row for a file once that whole file has
        // finished parsing (`insert_source_record` runs after the last
        // batch, see `app.rs::load_one_file`), so a row already flushed to
        // `log_entries` mid-load can briefly have no matching `sources` row
        // yet. An inner join would make those rows vanish from the live
        // view until their file completes — `LEFT JOIN` keeps them visible
        // with an empty source column instead, consistent with how the
        // live entry count already behaves during a load.
        let from = "log_entries AS le \
             LEFT JOIN sources AS s ON le.event_id_source = s.source_file_id"
            .to_string();

        let mut params = Vec::new();
        let mut where_clause: Option<String> = None;
        for term in &self.terms {
            let (mut fragment, term_params) = compile_term_kind(&term.kind);
            if term.negate {
                fragment = format!("NOT ({fragment})");
            }
            where_clause = Some(match where_clause {
                None => fragment,
                Some(prev) => {
                    let op = match term.connector {
                        Connector::And => "AND",
                        Connector::Or => "OR",
                    };
                    format!("({prev}) {op} ({fragment})")
                }
            });
            params.extend(term_params);
        }

        CompiledQuery {
            from,
            where_clause,
            params,
        }
    }
}

/// `EXISTS` subquery rather than a `JOIN import_tags`: one entry can have
/// several tags, and a join would fan out into duplicate rows per matching
/// tag. `sources` is safe to `JOIN` instead since `source_file_id` is its
/// primary key — at most one match per entry, no fan-out possible.
fn compile_term_kind(kind: &TermKind) -> (String, Vec<Value>) {
    match kind {
        TermKind::FreeText(text) => {
            let pattern = Value::Text(format!("%{}%", escape_like(text)));
            (
                "(le.message LIKE ? ESCAPE '\\' OR le.raw LIKE ? ESCAPE '\\')".to_string(),
                vec![pattern.clone(), pattern],
            )
        }
        TermKind::Field {
            field: Field::Tag,
            value,
            is_regex,
        } if !*is_regex && value == "*" => (
            // `tag=*` means "has at least one tag, whichever" — combined
            // with the existing `NOT` prefix this is how "untagged" is
            // expressed (`NOT tag=*`), without a dedicated grammar keyword.
            "EXISTS (SELECT 1 FROM import_tags AS it \
             WHERE it.event_id_source = le.event_id_source \
             AND it.event_id_seq = le.event_id_seq)"
                .to_string(),
            Vec::new(),
        ),
        TermKind::Field {
            field: Field::Tag,
            value,
            is_regex,
        } => {
            let predicate = if *is_regex {
                "regexp_matches(it.tag_value, ?)"
            } else {
                "it.tag_value = ?"
            };
            (
                format!(
                    "EXISTS (SELECT 1 FROM import_tags AS it \
                     WHERE it.event_id_source = le.event_id_source \
                     AND it.event_id_seq = le.event_id_seq AND {predicate})"
                ),
                vec![Value::Text(value.clone())],
            )
        }
        TermKind::Field {
            field: Field::After,
            value,
            ..
        } => compile_time_bound(value, ">="),
        TermKind::Field {
            field: Field::Before,
            value,
            ..
        } => compile_time_bound(value, "<="),
        TermKind::Field {
            field,
            value,
            is_regex,
        } => {
            let column = match field {
                Field::Level => "le.level".to_string(),
                Field::Sourcetype => "s.sourcetype".to_string(),
                Field::SourceFile => "s.path".to_string(),
                Field::SourceId => "s.source_file_id".to_string(),
                Field::Message => "le.message".to_string(),
                Field::Raw => "le.raw".to_string(),
                Field::EventId => event_code_case_sql("le.fields", "s.sourcetype"),
                Field::Host => host_case_sql("le.fields", "s.sourcetype"),
                Field::Process => process_case_sql("le.fields", "s.sourcetype"),
                Field::Subsystem => subsystem_case_sql("le.fields", "s.sourcetype"),
                Field::Category => category_case_sql("le.fields", "s.sourcetype"),
                Field::Tag | Field::After | Field::Before => unreachable!("handled above"),
            };
            if *is_regex {
                (
                    format!("regexp_matches({column}, ?)"),
                    vec![Value::Text(value.clone())],
                )
            } else {
                match field {
                    Field::Level
                    | Field::Sourcetype
                    | Field::SourceId
                    | Field::EventId
                    | Field::Host
                    | Field::Process
                    | Field::Subsystem
                    | Field::Category => {
                        (format!("{column} = ?"), vec![Value::Text(value.clone())])
                    }
                    Field::SourceFile | Field::Message | Field::Raw => (
                        format!("{column} LIKE ? ESCAPE '\\'"),
                        vec![Value::Text(format!("%{}%", escape_like(value)))],
                    ),
                    Field::Tag | Field::After | Field::Before => unreachable!("handled above"),
                }
            }
        }
    }
}

/// Parses an `after=`/`before=` value into a bound on `timestamp_utc`. A
/// value that doesn't parse as a timestamp compiles to `FALSE` rather than
/// an error — consistent with how a malformed regex elsewhere in this
/// grammar surfaces as "matches nothing" (a DuckDB error from the
/// `regexp_matches` call) rather than a parse-time failure: this search box
/// has no error-reporting channel of its own, so "no results" is the
/// existing convention for "something in this query didn't make sense",
/// not a new one invented here.
fn compile_time_bound(value: &str, operator: &str) -> (String, Vec<Value>) {
    match parse_query_timestamp(value) {
        Some(ts) => (
            format!("le.timestamp_utc {operator} CAST(? AS TIMESTAMP)"),
            vec![Value::Text(ts.format("%Y-%m-%d %H:%M:%S%.6f").to_string())],
        ),
        None => ("FALSE".to_string(), Vec::new()),
    }
}

/// Accepts `after=`/`before=` values in a few reasonable shapes so a
/// hand-typed date doesn't have to hit one exact format: ISO-ish
/// `T`-separated (what the "show context around this event" context-menu
/// action writes, since it needs a single whitespace-free token) or
/// space-separated (only usable hand-typed and quoted, since the query
/// tokenizer otherwise splits on the space), with or without seconds or
/// fractional seconds, or a bare date (midnight UTC).
fn parse_query_timestamp(value: &str) -> Option<chrono::NaiveDateTime> {
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(ts) = chrono::NaiveDateTime::parse_from_str(value, format) {
            return Some(ts);
        }
    }
    chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()
        .and_then(|date| date.and_hms_opt(0, 0, 0))
}

/// One row as shown in the timeline table.
pub struct DisplayRow {
    pub event_id: EventId,
    /// Always literal UTC (`%Y-%m-%d %H:%M:%S%.3f`, no offset suffix) —
    /// internal logic (the context-window re-parse in `timeline_view`'s row
    /// context menu, sorting) depends on this being UTC regardless of the
    /// configured display timezone, so it's never repurposed for rendering.
    /// See [`Self::timestamp_display`] for what the table actually shows.
    pub timestamp_utc: String,
    /// `timestamp_utc` formatted in `Settings::display_timezone` (UTC if
    /// unset) via [`TimezoneSpec::format_utc`] — always carries its own
    /// `%:z` offset, so it's self-describing on its own. This is what the
    /// Timestamp column renders; `timestamp_utc` stays internal.
    pub timestamp_display: String,
    pub level: String,
    pub message: String,
    pub tags: Vec<String>,
    /// The evidence file this entry came from (`sources.path`). Empty for
    /// the brief window where a row has been flushed to `log_entries` but
    /// its file hasn't finished parsing yet — see `compile`'s `LEFT JOIN`
    /// comment.
    pub source_path: String,
    /// `sources.sourcetype` (`aul`/`evtx`/`journald`/...) for this entry's
    /// source file. Same brief-empty-window caveat as `source_path`.
    pub sourcetype: String,
    /// Originating host, extracted from `fields` where the sourcetype has
    /// one — journald's `_HOSTNAME` or EVTX's `Event.System.Computer`. AUL
    /// is a single-device archive (no host concept), so it's empty there —
    /// see [`extracted_field_sql`] for the exact mapping per sourcetype.
    pub host: String,
    /// Originating process, extracted from `fields` where the sourcetype
    /// has a *name* (not just a numeric PID) for it — journald's
    /// `SYSLOG_IDENTIFIER` (falling back to `_COMM` when a process didn't
    /// set its own identifier) or AUL's `process`. Empty for EVTX: its only
    /// generically available field is a bare PID, not a name — see
    /// [`extracted_field_sql`].
    pub process: String,
    /// EVTX's `Event.System.EventID` (e.g. `4625`) — the single most
    /// important field for triaging Windows events, so it's surfaced as its
    /// own column rather than left inside `fields`/`raw`. Empty for every
    /// other sourcetype (none has an equivalent numeric event-type code).
    pub event_code: String,
    /// The logging component: AUL's `subsystem` or EVTX's
    /// `Event.System.Provider` name. Empty for journald and any sourcetype
    /// without a confirmed mapping.
    pub subsystem: String,
    /// The event's classification within its subsystem/component: AUL's
    /// `category` only — EVTX's closest-sounding field, `Channel`, is a
    /// different kind of thing (which top-level Windows Event Log the
    /// entry was routed to, e.g. `"Security"`, not a developer-set
    /// classification) and deliberately isn't mapped here, same reasoning
    /// as why EVTX has no `process`. Empty for every other sourcetype.
    pub category: String,
    /// Free-text notes on this event (`event_notes`, SQLite session DB —
    /// independent of tags entirely, not this DuckDB query) — always empty
    /// straight out of [`fetch_window`], filled in afterward by
    /// `timeline_view`'s notes-merge step, the same way `tags` itself picks
    /// up manually-set tags from a separate merge step. Shown as hover text
    /// on the Tags column rather than its own column: a note is the
    /// exception, not something worth a column that's blank for almost
    /// every row.
    pub notes: Vec<String>,
}

/// Distinct, non-null `(level, sourcetype)` pairs currently in
/// `log_entries` — used to populate the quick level-filter buttons with
/// whatever this particular loaded source actually uses (AUL's `LogType`
/// names vs. a text log's ERROR/WARN/INFO have nothing in common).
/// `sourcetype` rides along (rather than just distinct `level`s) so the
/// caller can attach a human-readable name to sourcetypes with numeric
/// levels (journald, EVTX) without guessing which sourcetype a bare digit
/// like `"2"` came from when several are loaded at once — see
/// `ui::timeline_view::level_display_name`.
pub fn distinct_levels_by_sourcetype(conn: &Connection) -> anyhow::Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT le.level, s.sourcetype
         FROM log_entries AS le
         LEFT JOIN sources AS s ON le.event_id_source = s.source_file_id
         WHERE le.level IS NOT NULL
         ORDER BY le.level",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?.unwrap_or_default(),
        ))
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Distinct `tag_value`s currently in `import_tags` — same idea as
/// [`distinct_levels_by_sourcetype`], populating the quick tag-filter buttons from
/// whatever tagging rules actually produced on this data, rather than a
/// fixed list.
pub fn distinct_tags(conn: &Connection) -> anyhow::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT DISTINCT tag_value FROM import_tags ORDER BY tag_value")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Per-value event counts for `ui::filter_bar`'s Level/Tag/Sources
/// dropdowns — how many rows *in the whole loaded timeline* carry each
/// value, not how many currently match the active search query. A
/// deliberate snapshot, not a live number: recomputing this on every query
/// change would need the same background-thread treatment as
/// `count_matching` (whose cost scales with the filtered result, not the
/// whole table), for a number whose actual purpose here is "how big is
/// this tag/level/source overall", which only changes on a load or re-tag
/// — same refresh cadence [`distinct_tags`]/[`distinct_levels_by_sourcetype`]
/// already use, and called the same synchronous way (no `mpsc` channel):
/// each of these three is one `GROUP BY` over a single narrow column
/// (`tag_value`/`level`/`event_id_source`), never `fields`/`raw` — the
/// wide-column combination that actually caused the real OOM these other
/// two avoid.
///
/// Three near-identical query shapes below rather than one generic
/// function: the source table differs (`import_tags` vs `log_entries`),
/// and unlike `distinct_levels_by_sourcetype`, [`Field::Level`]'s own
/// filter semantics are sourcetype-*agnostic* (`level=X` matches `X`
/// regardless of which sourcetype logged it), so grouping level counts by
/// sourcetype too would produce numbers that don't match what the
/// checkbox next to them actually filters by.
pub fn tag_counts(conn: &Connection) -> anyhow::Result<HashMap<String, usize>> {
    let mut stmt =
        conn.prepare("SELECT tag_value, COUNT(*) FROM import_tags GROUP BY tag_value")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
    })?;
    rows.collect::<Result<HashMap<_, _>, _>>()
        .map_err(Into::into)
}

/// See [`tag_counts`]'s doc comment. Keyed by the bare `level` value, same
/// as [`Field::Level`]'s own filter — not scoped by sourcetype.
pub fn level_counts(conn: &Connection) -> anyhow::Result<HashMap<String, usize>> {
    let mut stmt = conn.prepare(
        "SELECT level, COUNT(*) FROM log_entries WHERE level IS NOT NULL GROUP BY level",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
    })?;
    rows.collect::<Result<HashMap<_, _>, _>>()
        .map_err(Into::into)
}

/// See [`tag_counts`]'s doc comment. Keyed by `source_file_id`, matching
/// [`Field::SourceId`]'s own filter.
pub fn source_counts(conn: &Connection) -> anyhow::Result<HashMap<String, usize>> {
    let mut stmt =
        conn.prepare("SELECT event_id_source, COUNT(*) FROM log_entries GROUP BY event_id_source")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
    })?;
    rows.collect::<Result<HashMap<_, _>, _>>()
        .map_err(Into::into)
}

/// `import_tags` counts grouped by `rule_name`, restricted to
/// `source_file_ids` — the Activity Log's "how many did rule X tag" for one
/// specific load, not the whole session the way [`tag_counts`] is (which is
/// also grouped by `tag_value`, not `rule_name` — several rules can
/// deliberately share a tag value, so that wouldn't answer "which rule"
/// either). Empty input yields an empty map without querying — an empty
/// `IN ()` is invalid SQL, and a load where every file was skipped
/// legitimately has no source file ids to scope by.
pub fn rule_counts_for_sources(
    conn: &Connection,
    source_file_ids: &[String],
) -> anyhow::Result<HashMap<String, usize>> {
    if source_file_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; source_file_ids.len()].join(", ");
    let sql = format!(
        "SELECT rule_name, COUNT(*) FROM import_tags \
         WHERE event_id_source IN ({placeholders}) GROUP BY rule_name"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(duckdb::params_from_iter(source_file_ids), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
    })?;
    rows.collect::<Result<HashMap<_, _>, _>>()
        .map_err(Into::into)
}

/// Exposes `query`'s compiled `FROM ... [WHERE ...]` fragment and its bound
/// parameters to callers outside this module that need to filter
/// `log_entries` directly in SQL rather than through [`fetch_window`]/
/// [`count_matching`] — currently only `session::portable_case`'s filtered
/// export, which runs `INSERT INTO ... SELECT le.* FROM <this>` against a
/// freshly attached database rather than pulling rows into Rust first.
pub(crate) fn compile_from_where(query: &Query) -> (String, Vec<Value>) {
    let compiled = query.compile();
    let sql = match compiled.where_clause {
        Some(w) => format!("{} WHERE {w}", compiled.from),
        None => compiled.from,
    };
    (sql, compiled.params)
}

/// One row of [`CaseSummary::sources`] — one loaded source and how many of
/// `query`'s matching entries came from it.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseSummarySource {
    pub source_file_id: String,
    pub path: String,
    pub sourcetype: String,
    pub entry_count: usize,
}

/// Widest span [`case_summary`] will build a dense per-day
/// [`CaseSummary::daily_histogram`] for (~10 years) — a guard against a
/// single garbage/out-of-range timestamp (a known real hazard in log
/// evidence) turning "earliest to latest" into an unbounded allocation. The
/// plain `earliest_utc`/`latest_utc` range is still reported either way;
/// only the day-by-day breakdown is skipped.
const MAX_HISTOGRAM_DAYS: i64 = 3660;

/// Coarse per-source/sourcetype/level/tag/time breakdown of everything
/// `query` matches — the data behind `ui::case_summary_dialog`'s View-menu
/// "whole session" view and the Portable Case export's filtered preview
/// (same struct either way; only the `Query` passed to [`case_summary`]
/// differs).
#[derive(Debug, Clone, PartialEq)]
pub struct CaseSummary {
    pub total_entries: usize,
    pub tagged_entries: usize,
    /// Descending by `entry_count` — every source with at least one
    /// matching entry, complete (a dialog rendering this may choose to
    /// truncate the display, but the data here never does).
    pub sources: Vec<CaseSummarySource>,
    /// Summed from `sources` (not a separate query) — descending by count.
    pub sourcetype_counts: Vec<(String, usize)>,
    /// Descending by count. Entries with no `level` at all are excluded
    /// (same convention as [`level_counts`]).
    pub level_counts: Vec<(String, usize)>,
    pub earliest_utc: Option<chrono::DateTime<chrono::Utc>>,
    pub latest_utc: Option<chrono::DateTime<chrono::Utc>>,
    /// Dense, gap-preserving per-UTC-day counts from `earliest_utc`'s day to
    /// `latest_utc`'s day inclusive — a day with zero matching events still
    /// gets an entry, since a real gap in coverage is itself a forensically
    /// meaningful thing to show, not something to compress away. `None`
    /// when nothing matched, or the span exceeds [`MAX_HISTOGRAM_DAYS`].
    /// Bucketed in UTC regardless of display timezone — a documented
    /// simplification, not a silent one (see `ui::case_summary_dialog`).
    pub daily_histogram: Option<Vec<(chrono::NaiveDate, usize)>>,
}

/// Builds a [`CaseSummary`] for everything `query` matches — an empty/
/// default `Query` naturally selects the whole session (via
/// [`compile_from_where`]'s "no `WHERE` clause at all" degradation), so this
/// one function serves both the plain whole-session summary and a filtered
/// preview without a separate code path to keep in sync.
///
/// Every query below stays on narrow columns only
/// (`event_id_source`/`event_id_seq`/`timestamp_utc`/`level`, plus
/// `sources`' own small table) — never `message`/`raw`/`fields`, the wide
/// columns `duckdb_memory_limit_investigation` traced the project's one
/// real freeze/OOM incident to. Like [`tag_counts`]/[`level_counts`]/
/// [`source_counts`], this is cheap enough to run synchronously on the
/// calling thread — no background-thread treatment needed the way
/// [`fetch_window`]/[`count_matching`] (whose cost scales with the filtered
/// result across every column) do.
///
/// Four separate queries share one `WITH filtered AS (...)` CTE text (a CTE
/// can't be shared across separate top-level statements, so each restates
/// it) rather than one combined query — plainer SQL, and still four cheap
/// narrow-column scans rather than one expensive wide one.
pub fn case_summary(conn: &Connection, query: &Query) -> anyhow::Result<CaseSummary> {
    let (from_where, params) = compile_from_where(query);
    let cte = format!(
        "WITH filtered AS (
            SELECT le.event_id_source, le.event_id_seq, le.timestamp_utc, le.level,
                   s.source_file_id AS src_id, s.path AS src_path, s.sourcetype AS src_sourcetype
            FROM {from_where}
        )"
    );

    let sources_sql = format!(
        "{cte} SELECT src_id, src_path, src_sourcetype, COUNT(*) \
         FROM filtered GROUP BY src_id, src_path, src_sourcetype ORDER BY 4 DESC"
    );
    let mut stmt = conn.prepare(&sources_sql)?;
    let rows = stmt.query_map(duckdb::params_from_iter(&params), |row| {
        Ok(CaseSummarySource {
            source_file_id: row.get(0)?,
            path: row.get(1)?,
            sourcetype: row.get(2)?,
            entry_count: row.get::<_, i64>(3)? as usize,
        })
    })?;
    let sources: Vec<CaseSummarySource> = rows.collect::<Result<_, _>>()?;

    let mut sourcetype_totals: HashMap<String, usize> = HashMap::new();
    for source in &sources {
        *sourcetype_totals
            .entry(source.sourcetype.clone())
            .or_default() += source.entry_count;
    }
    let mut sourcetype_counts: Vec<(String, usize)> = sourcetype_totals.into_iter().collect();
    sourcetype_counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    let level_sql = format!(
        "{cte} SELECT level, COUNT(*) FROM filtered WHERE level IS NOT NULL \
         GROUP BY level ORDER BY 2 DESC"
    );
    let mut stmt = conn.prepare(&level_sql)?;
    let rows = stmt.query_map(duckdb::params_from_iter(&params), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
    })?;
    let level_counts: Vec<(String, usize)> = rows.collect::<Result<_, _>>()?;

    let totals_sql = format!(
        "{cte} SELECT COUNT(*), \
             COUNT(*) FILTER (WHERE EXISTS ( \
                 SELECT 1 FROM import_tags it \
                 WHERE it.event_id_source = filtered.event_id_source \
                   AND it.event_id_seq = filtered.event_id_seq)), \
             MIN(timestamp_utc), MAX(timestamp_utc) \
         FROM filtered"
    );
    let (total_entries, tagged_entries, earliest_utc, latest_utc): (
        i64,
        i64,
        Option<chrono::NaiveDateTime>,
        Option<chrono::NaiveDateTime>,
    ) = conn.query_row(&totals_sql, duckdb::params_from_iter(&params), |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    let earliest_utc = earliest_utc.map(|dt| dt.and_utc());
    let latest_utc = latest_utc.map(|dt| dt.and_utc());

    let daily_histogram = match (earliest_utc, latest_utc) {
        (Some(earliest), Some(latest)) => {
            let earliest_day = earliest.date_naive();
            let latest_day = latest.date_naive();
            let span_days = (latest_day - earliest_day).num_days();
            if span_days > MAX_HISTOGRAM_DAYS {
                None
            } else {
                let histogram_sql = format!(
                    "{cte} SELECT date_trunc('day', timestamp_utc), COUNT(*) \
                     FROM filtered GROUP BY 1 ORDER BY 1"
                );
                let mut stmt = conn.prepare(&histogram_sql)?;
                let rows = stmt.query_map(duckdb::params_from_iter(&params), |row| {
                    let day: chrono::NaiveDateTime = row.get(0)?;
                    Ok((day.date(), row.get::<_, i64>(1)? as usize))
                })?;
                let sparse: HashMap<chrono::NaiveDate, usize> = rows.collect::<Result<_, _>>()?;

                let mut dense = Vec::with_capacity((span_days + 1) as usize);
                let mut day = earliest_day;
                loop {
                    dense.push((day, sparse.get(&day).copied().unwrap_or(0)));
                    if day == latest_day {
                        break;
                    }
                    day = day + chrono::Days::new(1);
                }
                Some(dense)
            }
        }
        _ => None,
    };

    Ok(CaseSummary {
        total_entries: total_entries as usize,
        tagged_entries: tagged_entries as usize,
        sources,
        sourcetype_counts,
        level_counts,
        earliest_utc,
        latest_utc,
        daily_histogram,
    })
}

pub fn count_matching(conn: &Connection, query: &Query) -> anyhow::Result<usize> {
    let compiled = query.compile();
    let sql = match &compiled.where_clause {
        Some(w) => format!("SELECT COUNT(*) FROM {} WHERE {w}", compiled.from),
        None => format!("SELECT COUNT(*) FROM {}", compiled.from),
    };
    let count: i64 = conn.query_row(&sql, duckdb::params_from_iter(&compiled.params), |row| {
        row.get(0)
    })?;
    Ok(count as usize)
}

/// How many entries a `message_contains` pattern would tag — the advanced
/// tagging dialog's live preview, backgrounded the same way as
/// [`count_matching`] for the same reason (a leading-wildcard `LIKE` scan
/// over a multi-million-row table must not run on every keystroke).
/// Deliberately matches `message` only, not `raw` (unlike free-text search)
/// — this is a preview of what the resulting `message_contains` rule will
/// actually match, and that rule only ever looks at `message`.
pub fn count_message_contains(conn: &Connection, pattern: &str) -> anyhow::Result<usize> {
    let like_pattern = format!("%{}%", escape_like(pattern));
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM log_entries WHERE message LIKE ? ESCAPE '\\'",
        duckdb::params![like_pattern],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

/// One entry's complete data — unlike [`DisplayRow`], includes `raw` (the
/// full original record/line), for the "Copy whole event" context-menu
/// action. Deliberately not part of `DisplayRow`/`fetch_window`: `raw` can
/// be a whole JSON-serialized record for binary sources (AUL/EVTX/
/// journald), and fetching it for every row in a 200-row scroll window
/// (most of which never get copied) would reintroduce the kind of
/// needless-copy memory bloat the AUL streaming-load fix was written to
/// avoid. A single-event lookup by primary key is cheap enough to run
/// synchronously, unlike the window/count queries.
pub struct FullEntry {
    /// Always literal UTC, same reasoning as `DisplayRow::timestamp_utc`.
    pub timestamp_utc: String,
    /// Same as `DisplayRow::timestamp_display` — what "Copy whole event as
    /// text" and the "View raw/fields" dialog actually show, since both are
    /// analyst-facing rather than internal.
    pub timestamp_display: String,
    pub level: String,
    pub message: String,
    pub raw: String,
    /// The source-specific `fields` JSON — same column `extracted_field_sql`
    /// pulls Host/Process/Subsystem/etc. out of, but here in full rather
    /// than just the handful of confirmed-mapped keys. For AUL/EVTX/
    /// journald this largely overlaps `raw` (both are the complete decoded
    /// record); kept as its own field anyway rather than folded into `raw`
    /// since for a `text_config` source they're genuinely different things
    /// (`raw` is the literal original line, `fields` is what the regex
    /// captured out of it) — collapsing them would lose that distinction.
    pub fields: serde_json::Value,
    pub tags: Vec<String>,
}

impl FullEntry {
    /// Plain-text rendering for the clipboard — not a serialization
    /// format, just something readable to paste into a note or ticket.
    pub fn to_text(&self) -> String {
        format!(
            "Timestamp: {}\nLevel: {}\nTags: {}\nMessage: {}\nRaw: {}\nFields: {}",
            self.timestamp_display,
            self.level,
            self.tags.join(", "),
            self.message,
            self.raw,
            self.fields,
        )
    }
}

/// Looks up one entry by its primary key (`event_id_source`,
/// `event_id_seq`) — see [`FullEntry`] for why this is separate from
/// [`fetch_window`].
pub fn fetch_full_entry(
    conn: &Connection,
    event_id: EventId,
    display_tz: &TimezoneSpec,
) -> anyhow::Result<Option<FullEntry>> {
    let mut stmt = conn.prepare(
        "SELECT le.timestamp_utc, le.level, le.message, le.raw, le.fields,
                (SELECT string_agg(it.tag_value, ',') FROM import_tags AS it
                 WHERE it.event_id_source = le.event_id_source
                 AND it.event_id_seq = le.event_id_seq) AS tags
         FROM log_entries AS le
         WHERE le.event_id_source = ? AND le.event_id_seq = ?",
    )?;
    let mut rows = stmt.query(duckdb::params![
        event_id.source_file_id.to_string(),
        event_id.sequence_number.value() as i64
    ])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let timestamp_utc: chrono::NaiveDateTime = row.get(0)?;
    let level: Option<String> = row.get(1)?;
    let message: Option<String> = row.get(2)?;
    let raw: String = row.get(3)?;
    let fields: serde_json::Value = row.get(4)?;
    let tags: Option<String> = row.get(5)?;
    let mut tags: Vec<String> = tags
        .map(|joined| joined.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    tags.sort();

    Ok(Some(FullEntry {
        timestamp_utc: timestamp_utc.format(DISPLAY_TIMESTAMP_FORMAT).to_string(),
        timestamp_display: display_tz.format_utc(timestamp_utc.and_utc(), DISPLAY_TIMESTAMP_FORMAT),
        level: level.unwrap_or_default(),
        message: message.unwrap_or_default(),
        raw,
        fields,
        tags,
    }))
}

/// SQL for the `host`/`process`/`event_code`/`subsystem`/`category`
/// columns — a `CASE` on `s.sourcetype` since each sourcetype's `fields`
/// JSON uses entirely different keys (or has no such concept at all) for
/// these. Only sourcetypes with a *confirmed* field name are mapped;
/// anything else falls through to `NULL` rather than guessing at a JSON
/// path that might silently extract the wrong thing. See
/// `docs/field-extraction.md` for the authoritative, per-sourcetype list
/// this implements.
///
/// EVTX's `Event.System.Computer`, `Event.System.EventID`, and
/// `Event.System.Provider_attributes.Name` are all confirmed against the
/// `evtx` crate's own test snapshots
/// (`tests/snapshots/test_record_samples__event_json_sample_with_separate_json_attributes.snap`
/// — `parsers::evtx` parses with `separate_json_attributes(true)`, see its
/// doc comment for why: without it, an `EventID` with a `Qualifiers`
/// attribute — common on older/manifest-free providers like MsiInstaller,
/// frequent in `Application.evtx` — serializes as a nested
/// `{"#text": ..., "#attributes": {...}}` object instead of a plain value,
/// and `json_extract_string` on that returns the whole object stringified
/// instead of the ID). `Event.System.Execution_attributes.ProcessID` is
/// confirmed too, but it's a bare numeric PID, not a process name/path
/// like journald's `SYSLOG_IDENTIFIER` or AUL's `process` — mixing "the
/// process's name" and "some process's PID" under one "Process" column
/// would misrepresent one of them, so EVTX deliberately has no `process`
/// mapping here. `Event.System.Channel` (e.g. `"Security"`,
/// `"Application"`) is confirmed present too, but deliberately has no
/// `category` mapping for the same reason: it's which top-level Windows
/// Event Log the entry was routed to, not a fine-grained developer-set
/// classification the way AUL's `category` is — same "don't misrepresent
/// a different concept as if it were the same one" call as `process`.
///
/// AUL's `subsystem`/`category` are confirmed directly against a real
/// loaded session's `fields` JSON (both plain top-level string values,
/// matching `macos-unifiedlogs`' own `LogData` field names).
///
/// `fields_ref`/`sourcetype_ref` are the column references to use for
/// `fields`/`sourcetype` in the caller's query — parameterized because
/// [`fetch_window`]'s windowed lookup joins back through `le`/`s`, not the
/// aliases a caller evaluating this against some other query shape might
/// use.
fn extracted_field_sql(fields_ref: &str, sourcetype_ref: &str) -> String {
    let host_case = host_case_sql(fields_ref, sourcetype_ref);
    let process_case = process_case_sql(fields_ref, sourcetype_ref);
    let event_code_case = event_code_case_sql(fields_ref, sourcetype_ref);
    let subsystem_case = subsystem_case_sql(fields_ref, sourcetype_ref);
    let category_case = category_case_sql(fields_ref, sourcetype_ref);
    format!(
        "{host_case} AS host,
         {process_case} AS process,
         {event_code_case} AS event_code,
         {subsystem_case} AS subsystem,
         {category_case} AS category"
    )
}

/// Every `*_case_sql` function below returns a bare `CASE ... END`
/// expression (no `AS` alias) — factored out of [`extracted_field_sql`] so
/// each can also back `compile_term_kind`'s matching `host=`/`process=`/
/// `event_id=`/`subsystem=`/`category=` filter (with their usual
/// `!=`/`~` variants too). One shared expression per field, not two
/// independently-maintained copies of the same mapping (one for the
/// display column, one for the filter), means a column and its filter can
/// never quietly drift apart on what the field even means.
fn host_case_sql(fields_ref: &str, sourcetype_ref: &str) -> String {
    format!(
        "CASE {sourcetype_ref}
            WHEN 'journald' THEN json_extract_string({fields_ref}, '$._HOSTNAME')
            WHEN 'evtx' THEN json_extract_string({fields_ref}, '$.Event.System.Computer')
            ELSE NULL
         END"
    )
}

fn process_case_sql(fields_ref: &str, sourcetype_ref: &str) -> String {
    format!(
        "CASE {sourcetype_ref}
            WHEN 'journald' THEN COALESCE(
                json_extract_string({fields_ref}, '$.SYSLOG_IDENTIFIER'),
                json_extract_string({fields_ref}, '$._COMM')
            )
            WHEN 'aul' THEN json_extract_string({fields_ref}, '$.process')
            ELSE NULL
         END"
    )
}

fn event_code_case_sql(fields_ref: &str, sourcetype_ref: &str) -> String {
    format!(
        "CASE {sourcetype_ref}
            WHEN 'evtx' THEN json_extract_string({fields_ref}, '$.Event.System.EventID')
            ELSE NULL
         END"
    )
}

fn subsystem_case_sql(fields_ref: &str, sourcetype_ref: &str) -> String {
    format!(
        "CASE {sourcetype_ref}
            WHEN 'aul' THEN json_extract_string({fields_ref}, '$.subsystem')
            WHEN 'evtx' THEN json_extract_string({fields_ref}, '$.Event.System.Provider_attributes.Name')
            ELSE NULL
         END"
    )
}

fn category_case_sql(fields_ref: &str, sourcetype_ref: &str) -> String {
    format!(
        "CASE {sourcetype_ref}
            WHEN 'aul' THEN json_extract_string({fields_ref}, '$.category')
            ELSE NULL
         END"
    )
}

/// Two fully separate statements, not one query (not even a `MATERIALIZED`
/// CTE): whenever the wide `fields`/`message` columns are selected in the
/// same statement as the `tag=`/`tag~` filter's correlated `EXISTS`/
/// `regexp_matches` condition, DuckDB reads `fields` for roughly the whole
/// scanned range rather than only the rows that survive the filter,
/// regardless of how the `SELECT`/CTE/temp-table boundaries are drawn —
/// only fully separating "find the matching keys" (narrow columns, the
/// filter) from "look up those exact keys" (wide columns, a plain
/// equality lookup, no filter) keeps both stages proportional to the
/// window size rather than the table size.
///
/// `sort_descending` flips the whole tuple, tie-breaker included, rather
/// than just `timestamp_utc` — descending is the exact reverse of
/// ascending, so ties still resolve the same deterministic way instead of
/// falling back to whatever order DuckDB happens to produce for equal
/// timestamps.
fn fetch_window_keys(
    conn: &Connection,
    compiled: &CompiledQuery,
    where_sql: &str,
    offset: usize,
    limit: usize,
    sort_descending: bool,
) -> anyhow::Result<Vec<(String, i64)>> {
    let direction = if sort_descending { "DESC" } else { "ASC" };
    let sql = format!(
        "SELECT le.event_id_source, le.event_id_seq
         FROM {}
         {where_sql}
         ORDER BY le.timestamp_utc {direction}, le.event_id_source {direction}, le.event_id_seq {direction}
         LIMIT ? OFFSET ?",
        compiled.from
    );
    let mut params = compiled.params.clone();
    params.push(Value::BigInt(limit as i64));
    params.push(Value::BigInt(offset as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(duckdb::params_from_iter(&params), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn fetch_window(
    conn: &Connection,
    query: &Query,
    offset: usize,
    limit: usize,
    display_tz: &TimezoneSpec,
    sort_descending: bool,
) -> anyhow::Result<Vec<DisplayRow>> {
    let compiled = query.compile();
    let where_sql = compiled
        .where_clause
        .as_deref()
        .map(|w| format!("WHERE {w}"))
        .unwrap_or_default();

    let keys = fetch_window_keys(conn, &compiled, &where_sql, offset, limit, sort_descending)?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }

    // Tags via a correlated scalar subquery rather than a JOIN, same
    // reasoning as the `tag=`/`tag~` filter above: one entry can have
    // several tags, and a join would fan out into duplicate rows. Sorted
    // in Rust after splitting rather than inside `string_agg` — simpler
    // than depending on DuckDB's ordered-aggregate syntax, and the tag
    // count per entry is always small.
    //
    // A `JOIN` against a `VALUES` list, not `WHERE (a, b) IN ((?, ?), ...)`
    // — measured directly, the `IN`-list form still read `fields` broadly
    // rather than doing a per-key primary-key lookup (a 200-key window
    // stayed multiple GB), while the `JOIN` form (small list, driving into
    // `log_entries`' primary key) cost under 200MB for the same 200 keys.
    let extracted_field_sql = extracted_field_sql("le.fields", "s.sourcetype");
    let values = keys.iter().map(|_| "(?, ?)").collect::<Vec<_>>().join(", ");
    let direction = if sort_descending { "DESC" } else { "ASC" };
    let sql = format!(
        "SELECT le.event_id_source, le.event_id_seq, le.timestamp_utc, le.level, le.message,
                (SELECT string_agg(it.tag_value, ',') FROM import_tags AS it
                 WHERE it.event_id_source = le.event_id_source
                 AND it.event_id_seq = le.event_id_seq) AS tags,
                s.path, s.sourcetype, {extracted_field_sql}
         FROM (VALUES {values}) AS k(source_id, seq)
         JOIN log_entries AS le
             ON le.event_id_source = k.source_id AND le.event_id_seq = k.seq
         LEFT JOIN sources AS s ON le.event_id_source = s.source_file_id
         ORDER BY le.timestamp_utc {direction}, le.event_id_source {direction}, le.event_id_seq {direction}"
    );

    let mut params: Vec<Value> = Vec::with_capacity(keys.len() * 2);
    for (source_id, seq) in &keys {
        params.push(Value::Text(source_id.clone()));
        params.push(Value::BigInt(*seq));
    }

    // Raw rows first, `EventId` parsing after — `query_map`'s closure can
    // only fail with `duckdb::Error`, and a malformed `source_file_id`
    // would rather surface as a clear anyhow error than get shoehorned
    // into that type (same approach as `tagging::engine::for_each_taggable_row`).
    let mut stmt = conn.prepare(&sql)?;
    let raw_rows = stmt.query_map(duckdb::params_from_iter(&params), |row| {
        let source_file_id: String = row.get(0)?;
        let sequence_number: i64 = row.get(1)?;
        let timestamp_utc: chrono::NaiveDateTime = row.get(2)?;
        let level: Option<String> = row.get(3)?;
        let message: Option<String> = row.get(4)?;
        let tags: Option<String> = row.get(5)?;
        let source_path: Option<String> = row.get(6)?;
        let sourcetype: Option<String> = row.get(7)?;
        let host: Option<String> = row.get(8)?;
        let process: Option<String> = row.get(9)?;
        let event_code: Option<String> = row.get(10)?;
        let subsystem: Option<String> = row.get(11)?;
        let category: Option<String> = row.get(12)?;
        Ok((
            source_file_id,
            sequence_number,
            timestamp_utc,
            level,
            message,
            tags,
            source_path,
            sourcetype,
            host,
            process,
            event_code,
            subsystem,
            category,
        ))
    })?;

    let mut display_rows = Vec::new();
    for row in raw_rows {
        let (
            source_file_id,
            sequence_number,
            timestamp_utc,
            level,
            message,
            tags,
            source_path,
            sourcetype,
            host,
            process,
            event_code,
            subsystem,
            category,
        ) = row?;
        let event_id = EventId {
            source_file_id: source_file_id
                .parse()
                .map_err(|err| anyhow::anyhow!("invalid source_file_id in database: {err}"))?,
            sequence_number: crate::model::event_id::SequenceNumber::from_raw(
                sequence_number as u64,
            ),
        };
        let mut tags: Vec<String> = tags
            .map(|joined| joined.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        tags.sort();
        display_rows.push(DisplayRow {
            event_id,
            timestamp_utc: timestamp_utc.format(DISPLAY_TIMESTAMP_FORMAT).to_string(),
            timestamp_display: display_tz
                .format_utc(timestamp_utc.and_utc(), DISPLAY_TIMESTAMP_FORMAT),
            level: level.unwrap_or_default(),
            message: message.unwrap_or_default(),
            tags,
            source_path: source_path.unwrap_or_default(),
            sourcetype: sourcetype.unwrap_or_default(),
            host: host.unwrap_or_default(),
            process: process.unwrap_or_default(),
            event_code: event_code.unwrap_or_default(),
            subsystem: subsystem.unwrap_or_default(),
            category: category.unwrap_or_default(),
            notes: Vec::new(),
        });
    }
    Ok(display_rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `fetch_window`/`fetch_full_entry` test cares about `raw`
    /// UTC-based behavior, not display-timezone conversion (that's
    /// `timezone_spec`'s own test module's job) — a fixed UTC spec keeps
    /// every existing assertion against `timestamp_utc`-shaped values
    /// meaningful without each test needing its own timezone concern.
    fn utc() -> TimezoneSpec {
        TimezoneSpec::Fixed(chrono::FixedOffset::east_opt(0).unwrap())
    }

    #[test]
    fn after_and_before_parse_as_fields_not_free_text() {
        let query = Query::parse("after=2026-07-29T10:00:00 before=2026-07-29T11:00:00");
        assert_eq!(
            query.terms,
            vec![
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::Field {
                        field: Field::After,
                        value: "2026-07-29T10:00:00".to_string(),
                        is_regex: false,
                    }
                },
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::Field {
                        field: Field::Before,
                        value: "2026-07-29T11:00:00".to_string(),
                        is_regex: false,
                    }
                },
            ]
        );
    }

    #[test]
    fn parse_query_timestamp_accepts_the_shapes_it_documents() {
        let expected = chrono::NaiveDate::from_ymd_opt(2026, 7, 29)
            .unwrap()
            .and_hms_opt(10, 30, 0)
            .unwrap();
        assert_eq!(parse_query_timestamp("2026-07-29T10:30:00"), Some(expected));
        assert_eq!(parse_query_timestamp("2026-07-29 10:30:00"), Some(expected));
        assert_eq!(parse_query_timestamp("2026-07-29T10:30"), Some(expected));
        assert_eq!(
            parse_query_timestamp("2026-07-29"),
            Some(
                chrono::NaiveDate::from_ymd_opt(2026, 7, 29)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
            )
        );
        assert_eq!(parse_query_timestamp("not a date"), None);
    }

    #[test]
    fn bare_words_are_free_text_anded_together() {
        let query = Query::parse("hello world");
        assert_eq!(
            query.terms,
            vec![
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::FreeText("hello".to_string())
                },
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::FreeText("world".to_string())
                },
            ]
        );
    }

    #[test]
    fn quoted_phrase_is_one_free_text_term() {
        let query = Query::parse(r#"sourcetype=evtx "failed login""#);
        assert_eq!(
            query.terms,
            vec![
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::Field {
                        field: Field::Sourcetype,
                        value: "evtx".to_string(),
                        is_regex: false
                    }
                },
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::FreeText("failed login".to_string())
                },
            ]
        );
    }

    #[test]
    fn source_and_sourcetype_are_distinct_fields() {
        assert_eq!(
            Query::parse("sourcetype=evtx").terms[0].kind,
            TermKind::Field {
                field: Field::Sourcetype,
                value: "evtx".to_string(),
                is_regex: false
            }
        );
        assert_eq!(
            Query::parse("source=journal").terms[0].kind,
            TermKind::Field {
                field: Field::SourceFile,
                value: "journal".to_string(),
                is_regex: false
            }
        );
    }

    #[test]
    fn event_id_is_recognized_as_an_exact_match_field() {
        assert_eq!(
            Query::parse("event_id=4625").terms[0].kind,
            TermKind::Field {
                field: Field::EventId,
                value: "4625".to_string(),
                is_regex: false
            }
        );
    }

    #[test]
    fn host_process_subsystem_and_category_are_all_recognized_exact_match_fields() {
        assert_eq!(
            Query::parse("host=WORKSTATION1").terms[0].kind,
            TermKind::Field {
                field: Field::Host,
                value: "WORKSTATION1".to_string(),
                is_regex: false
            }
        );
        assert_eq!(
            Query::parse("process=systemd").terms[0].kind,
            TermKind::Field {
                field: Field::Process,
                value: "systemd".to_string(),
                is_regex: false
            }
        );
        assert_eq!(
            Query::parse("subsystem=com.apple.mDNSResponder").terms[0].kind,
            TermKind::Field {
                field: Field::Subsystem,
                value: "com.apple.mDNSResponder".to_string(),
                is_regex: false
            }
        );
        assert_eq!(
            Query::parse("category=mDNS").terms[0].kind,
            TermKind::Field {
                field: Field::Category,
                value: "mDNS".to_string(),
                is_regex: false
            }
        );
    }

    #[test]
    fn field_filters_recognize_equals_and_colon() {
        assert_eq!(
            Query::parse("level=ERROR").terms[0].kind,
            TermKind::Field {
                field: Field::Level,
                value: "ERROR".to_string(),
                is_regex: false
            }
        );
        assert_eq!(
            Query::parse("level:ERROR").terms[0].kind,
            TermKind::Field {
                field: Field::Level,
                value: "ERROR".to_string(),
                is_regex: false
            }
        );
    }

    #[test]
    fn tilde_means_regex() {
        assert_eq!(
            Query::parse("message~^ERROR.*").terms[0].kind,
            TermKind::Field {
                field: Field::Message,
                value: "^ERROR.*".to_string(),
                is_regex: true
            }
        );
    }

    #[test]
    fn unrecognized_field_name_falls_back_to_free_text() {
        assert_eq!(
            Query::parse("bogus=foo").terms[0].kind,
            TermKind::FreeText("bogus=foo".to_string())
        );
    }

    #[test]
    fn dash_prefix_and_not_keyword_both_negate() {
        let query = Query::parse("-level=INFO NOT tag=noise");
        assert!(query.terms[0].negate);
        assert!(query.terms[1].negate);
    }

    #[test]
    fn not_equal_operator_negates_and_parses_as_an_exact_field_match() {
        let query = Query::parse("level!=ERROR");
        assert_eq!(query.terms.len(), 1);
        assert!(query.terms[0].negate);
        assert_eq!(
            query.terms[0].kind,
            TermKind::Field {
                field: Field::Level,
                value: "ERROR".to_string(),
                is_regex: false
            }
        );
    }

    #[test]
    fn not_equal_operator_compiles_the_same_as_not_field_equals() {
        // `!=` is sugar, not a separate code path in `compile_term_kind` —
        // this pins that the two really do produce identical SQL/params,
        // not just "both happen to set `negate`".
        let via_operator = Query::parse("level!=ERROR").compile();
        let via_not_keyword = Query::parse("NOT level=ERROR").compile();
        assert_eq!(via_operator.where_clause, via_not_keyword.where_clause);
        assert_eq!(via_operator.params, via_not_keyword.params);
    }

    #[test]
    fn not_equal_operator_combines_with_a_dash_prefix_without_double_negating() {
        // See `Query::parse`'s doc comment on `negate_operator`: every
        // negation source ORs together, so stacking `-` on top of `!=`
        // still just means "not," not "not not."
        let query = Query::parse("-level!=ERROR");
        assert!(query.terms[0].negate);
    }

    #[test]
    fn not_equal_on_an_unrecognized_field_falls_back_to_free_text() {
        assert_eq!(
            Query::parse("bogus!=foo").terms[0].kind,
            TermKind::FreeText("bogus!=foo".to_string())
        );
    }

    #[test]
    fn tag_not_equal_wildcard_means_untagged_same_as_not_tag_equals_wildcard() {
        let via_operator = Query::parse("tag!=*").compile();
        let via_not_keyword = Query::parse("NOT tag=*").compile();
        assert_eq!(via_operator.where_clause, via_not_keyword.where_clause);
    }

    #[test]
    fn or_keyword_sets_the_next_terms_connector() {
        let query = Query::parse("level=ERROR OR level=FATAL");
        assert_eq!(query.terms[0].connector, Connector::And);
        assert_eq!(query.terms[1].connector, Connector::Or);
    }

    #[test]
    fn empty_query_has_no_terms() {
        assert!(Query::parse("   ").is_empty());
    }

    #[test]
    fn compiling_escapes_like_wildcards_in_free_text() {
        let compiled = Query::parse("50%").compile();
        assert!(compiled.where_clause.unwrap().contains("ESCAPE"));
        assert_eq!(compiled.params[0], Value::Text("%50\\%%".to_string()));
    }

    #[test]
    fn tag_filter_compiles_to_an_exists_subquery_not_a_join() {
        let compiled = Query::parse("tag=auth_failure").compile();
        assert!(!compiled.from.contains("import_tags"));
        assert!(compiled.where_clause.unwrap().contains("EXISTS"));
    }

    #[test]
    fn sources_are_always_joined_regardless_of_filter() {
        // `DisplayRow` needs `s.path`/`s.sourcetype` for every row, not
        // just when a sourcetype=/source= filter is active — see
        // `compile`'s doc comment on why this is a LEFT, not inner, join.
        let compiled = Query::parse("level=ERROR").compile();
        assert!(compiled.from.contains("LEFT JOIN sources"));
    }

    #[test]
    fn left_associative_and_or_is_explicitly_parenthesized() {
        let compiled = Query::parse("level=ERROR level=WARN OR level=INFO").compile();
        let where_sql = compiled.where_clause.unwrap();
        // (a) AND (b), then wrapped again for the OR: ((a) AND (b)) OR (c)
        assert!(where_sql.starts_with('('));
        assert!(where_sql.contains(") OR ("));
    }

    mod against_real_data {
        use super::*;
        use crate::db::timeline_schema::setup_timeline_schema;
        use crate::model::event_id::{EventId, SequenceCounter, SourceFileId};
        use chrono::Utc;

        fn open_test_db() -> Connection {
            let conn = Connection::open_in_memory().unwrap();
            setup_timeline_schema(&conn).unwrap();
            conn
        }

        fn insert_source(conn: &Connection, source_file_id: SourceFileId, sourcetype: &str) {
            conn.execute(
                "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
                 VALUES (?, '/evidence/test.log', ?, NULL, NULL)",
                duckdb::params![source_file_id.to_string(), sourcetype],
            )
            .unwrap();
        }

        fn insert_entry(
            conn: &Connection,
            event_id: EventId,
            level: &str,
            message: &str,
            raw: &str,
        ) {
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, ?, ?, ?, '{}')",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    Utc::now().naive_utc(),
                    level,
                    message,
                    raw,
                ],
            )
            .unwrap();
        }

        fn insert_entry_at(
            conn: &Connection,
            event_id: EventId,
            timestamp_utc: chrono::NaiveDateTime,
            message: &str,
        ) {
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, NULL, ?, ?, '{}')",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    timestamp_utc,
                    message,
                    message,
                ],
            )
            .unwrap();
        }

        fn insert_tag(conn: &Connection, event_id: EventId, tag_value: &str) {
            conn.execute(
                "INSERT INTO import_tags (event_id_source, event_id_seq, rule_name, tag_value, applied_at)
                 VALUES (?, ?, 'rule', ?, ?)",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    tag_value,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();
        }

        #[test]
        fn free_text_matches_message_or_raw() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERROR",
                "connection refused",
                "raw line one",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "all good",
                "raw line two",
            );

            let query = Query::parse("refused");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
            let rows = fetch_window(&conn, &query, 0, 10, &utc(), false).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(count_message_contains(&conn, "refused").unwrap(), 1);
            assert_eq!(count_message_contains(&conn, "raw line").unwrap(), 0);
            assert_eq!(rows[0].message, "connection refused");
        }

        #[test]
        fn source_id_field_targets_exactly_one_loaded_source() {
            // Regression coverage for `ui::filter_bar`'s per-source
            // visibility chips: `NOT source_id=<id>` must hide only that
            // one loaded source's rows, leaving every other loaded
            // source's rows untouched — even though both entries here
            // otherwise look identical (same level/message shape from two
            // different sources).
            let conn = open_test_db();
            let source_a = SourceFileId::new_random();
            let source_b = SourceFileId::new_random();
            insert_source(&conn, source_a, "evtx");
            insert_source(&conn, source_b, "evtx");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id: source_a,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "from source a",
                "raw a",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id: source_b,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "from source b",
                "raw b",
            );

            let hide_a = Query::parse(&format!("NOT source_id={source_a}"));
            let rows = fetch_window(&conn, &hide_a, 0, 10, &utc(), false).unwrap();
            assert_eq!(count_matching(&conn, &hide_a).unwrap(), 1);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].message, "from source b");

            let only_a = Query::parse(&format!("source_id={source_a}"));
            let rows = fetch_window(&conn, &only_a, 0, 10, &utc(), false).unwrap();
            assert_eq!(count_matching(&conn, &only_a).unwrap(), 1);
            assert_eq!(rows[0].message, "from source a");
        }

        #[test]
        fn hiding_two_sources_at_once_leaves_only_the_third() {
            let conn = open_test_db();
            let source_a = SourceFileId::new_random();
            let source_b = SourceFileId::new_random();
            let source_c = SourceFileId::new_random();
            insert_source(&conn, source_a, "evtx");
            insert_source(&conn, source_b, "evtx");
            insert_source(&conn, source_c, "evtx");
            let mut counter = SequenceCounter::new();
            for (source, message) in [
                (source_a, "from a"),
                (source_b, "from b"),
                (source_c, "from c"),
            ] {
                insert_entry(
                    &conn,
                    EventId {
                        source_file_id: source,
                        sequence_number: counter.next_sequence_number(),
                    },
                    "INFO",
                    message,
                    message,
                );
            }

            // Same shape `FilterBar::toggle_source_hidden_term` produces
            // for two independently-hidden sources: two plain `NOT` terms,
            // ANDed by the grammar's default connector.
            let query = Query::parse(&format!(
                "NOT source_id={source_a} NOT source_id={source_b}"
            ));
            let rows = fetch_window(&conn, &query, 0, 10, &utc(), false).unwrap();
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
            assert_eq!(rows[0].message, "from c");
        }

        #[test]
        fn fetch_window_includes_sorted_tags_per_entry() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut counter = SequenceCounter::new();
            let tagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let untagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry(&conn, tagged, "Info", "a", "a");
            insert_entry(&conn, untagged, "Info", "b", "b");
            insert_tag(&conn, tagged, "wifi_status");
            insert_tag(&conn, tagged, "app_launch");

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].tags, vec!["app_launch", "wifi_status"]);
            assert!(rows[1].tags.is_empty());
        }

        /// `timestamp_utc` must stay literal UTC regardless of the
        /// configured display timezone — `timeline_view`'s context-window
        /// re-parse depends on that — while `timestamp_display` reflects
        /// the requested zone and carries its own offset.
        #[test]
        fn fetch_window_keeps_timestamp_utc_literal_while_timestamp_display_follows_the_configured_zone()
         {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            let event_id = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry_at(
                &conn,
                event_id,
                chrono::NaiveDate::from_ymd_opt(2026, 7, 28)
                    .unwrap()
                    .and_hms_opt(12, 0, 0)
                    .unwrap(),
                "noon in utc",
            );

            let rows = fetch_window(
                &conn,
                &Query::parse(""),
                0,
                10,
                &TimezoneSpec::parse("+02:00").unwrap(),
                false,
            )
            .unwrap();

            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].timestamp_utc, "2026-07-28 12:00:00.000");
            assert_eq!(rows[0].timestamp_display, "2026-07-28 14:00:00.000 +02:00");
        }

        #[test]
        fn fetch_window_sort_descending_reverses_timestamp_order() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            let day = |d: u32| {
                chrono::NaiveDate::from_ymd_opt(2026, 7, d)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
            };
            insert_entry_at(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                day(1),
                "first",
            );
            insert_entry_at(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                day(2),
                "second",
            );
            insert_entry_at(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                day(3),
                "third",
            );

            let ascending = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();
            assert_eq!(
                ascending
                    .iter()
                    .map(|r| r.message.as_str())
                    .collect::<Vec<_>>(),
                vec!["first", "second", "third"]
            );

            let descending = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), true).unwrap();
            assert_eq!(
                descending
                    .iter()
                    .map(|r| r.message.as_str())
                    .collect::<Vec<_>>(),
                vec!["third", "second", "first"]
            );
        }

        #[test]
        fn level_filter_is_exact_match() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERROR",
                "a",
                "a",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERRORISH",
                "b",
                "b",
            );

            let query = Query::parse("level=ERROR");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn sourcetype_filter_matches_via_join() {
            let conn = open_test_db();
            let aul_source = SourceFileId::new_random();
            let evtx_source = SourceFileId::new_random();
            insert_source(&conn, aul_source, "aul");
            insert_source(&conn, evtx_source, "evtx");
            insert_entry(
                &conn,
                EventId {
                    source_file_id: aul_source,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "INFO",
                "a",
                "a",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id: evtx_source,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "INFO",
                "b",
                "b",
            );

            let query = Query::parse("sourcetype=evtx");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn source_file_filter_matches_a_substring_of_the_path() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            conn.execute(
                "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
                 VALUES (?, '/evidence/case1/system.journal', 'journald', NULL, NULL)",
                duckdb::params![source_file_id.to_string()],
            )
            .unwrap();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "6",
                "a",
                "a",
            );

            assert_eq!(
                count_matching(&conn, &Query::parse("source=system.journal")).unwrap(),
                1
            );
            assert_eq!(
                count_matching(&conn, &Query::parse("source=nomatch")).unwrap(),
                0
            );
        }

        #[test]
        fn fetch_window_includes_source_path_and_sourcetype() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "journald");
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "6",
                "a",
                "a",
            );

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].source_path, "/evidence/test.log");
            assert_eq!(rows[0].sourcetype, "journald");
        }

        #[test]
        fn fetch_window_extracts_journald_host_and_process() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "journald");
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, '6', 'a', 'a',
                         '{\"_HOSTNAME\": \"workstation1\", \"SYSLOG_IDENTIFIER\": \"sshd\"}')",
                duckdb::params![
                    source_file_id.to_string(),
                    SequenceCounter::new().next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].host, "workstation1");
            assert_eq!(rows[0].process, "sshd");
        }

        #[test]
        fn fetch_window_falls_back_to_comm_when_syslog_identifier_is_absent() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "journald");
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, '6', 'a', 'a', '{\"_COMM\": \"systemd\"}')",
                duckdb::params![
                    source_file_id.to_string(),
                    SequenceCounter::new().next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].process, "systemd");
        }

        #[test]
        fn fetch_window_extracts_aul_process_but_not_host() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, 'Info', 'a', 'a', '{\"process\": \"/usr/bin/example\"}')",
                duckdb::params![
                    source_file_id.to_string(),
                    SequenceCounter::new().next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].process, "/usr/bin/example");
            assert_eq!(
                rows[0].host, "",
                "AUL has no host concept — must stay empty"
            );
        }

        #[test]
        fn fetch_window_extracts_evtx_host_event_code_and_subsystem_but_not_process_or_category() {
            // `fields` shape matches the real `evtx` crate's own
            // `separate_json_attributes(true)` output (what this parser
            // actually configures, see `parsers::evtx`'s doc comment) —
            // verified against
            // `evtx-0.12.2/tests/snapshots/test_record_samples__event_json_sample_with_separate_json_attributes.snap`,
            // not guessed.
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "evtx");
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, '4', 'a', 'a',
                         '{\"Event\": {\"System\": {\"Computer\": \"WORKSTATION1\", \
                         \"EventID\": 4625, \
                         \"Provider_attributes\": {\"Name\": \"Microsoft-Windows-Security-Auditing\"}, \
                         \"Channel\": \"Security\", \
                         \"Execution_attributes\": {\"ProcessID\": 456}}}}')",
                duckdb::params![
                    source_file_id.to_string(),
                    SequenceCounter::new().next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].host, "WORKSTATION1");
            assert_eq!(rows[0].event_code, "4625");
            assert_eq!(rows[0].subsystem, "Microsoft-Windows-Security-Auditing");
            assert_eq!(
                rows[0].category, "",
                "EVTX's Channel is which log the entry was routed to, not a \
                 developer-set classification like AUL's category — must stay empty"
            );
            assert_eq!(
                rows[0].process, "",
                "EVTX only has a numeric PID generically, not a process name — must stay empty"
            );
        }

        #[test]
        fn fetch_window_extracts_evtx_event_code_as_a_bare_number_despite_a_qualifiers_attribute() {
            // Without `separate_json_attributes(true)`, an `EventID` that
            // carries a `Qualifiers` attribute (common on older/
            // manifest-free providers — MsiInstaller, the Service Control
            // Manager — frequent in `Application.evtx`) would serialize as
            // `{"#text": 4111, "#attributes": {"Qualifiers": 16384}}`, and
            // `json_extract_string` on that would return the whole object
            // stringified instead of `4111`. With it (what `parsers::evtx`
            // actually configures), the attribute moves to a sibling
            // `EventID_attributes` key and `EventID` stays a plain number —
            // shape verified against
            // `evtx-0.12.2/tests/snapshots/test_record_samples__event_json_sample_with_separate_json_attributes.snap`.
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "evtx");
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, '4', 'a', 'a',
                         '{\"Event\": {\"System\": {\
                         \"EventID_attributes\": {\"Qualifiers\": 16384}, \
                         \"EventID\": 4111}}}')",
                duckdb::params![
                    source_file_id.to_string(),
                    SequenceCounter::new().next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].event_code, "4111");
        }

        #[test]
        fn event_id_filter_matches_exactly_and_only_evtx_entries() {
            // Three rows: an EVTX 4625 (must match), an EVTX 4624 (must
            // not — exact match, not a prefix/substring match), and an AUL
            // entry whose `fields` happens to contain the string "4625"
            // somewhere irrelevant (must not match either — `event_id=`
            // only ever looks at EVTX's `Event.System.EventID`, same as
            // the "Event ID" column itself).
            let conn = open_test_db();

            let evtx_source = SourceFileId::new_random();
            insert_source(&conn, evtx_source, "evtx");
            let mut evtx_seq = SequenceCounter::new();
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, '0', 'a', 'a', '{\"Event\": {\"System\": {\"EventID\": 4625}}}')",
                duckdb::params![
                    evtx_source.to_string(),
                    evtx_seq.next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, '0', 'b', 'b', '{\"Event\": {\"System\": {\"EventID\": 4624}}}')",
                duckdb::params![
                    evtx_source.to_string(),
                    evtx_seq.next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let aul_source = SourceFileId::new_random();
            insert_source(&conn, aul_source, "aul");
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, 'Default', 'contains 4625 in the message', 'c', '{}')",
                duckdb::params![
                    aul_source.to_string(),
                    SequenceCounter::new().next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let rows =
                fetch_window(&conn, &Query::parse("event_id=4625"), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].message, "a");
        }

        #[test]
        fn fetch_window_extracts_aul_subsystem_and_category() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, 'Default', 'a', 'a',
                         '{\"subsystem\": \"com.apple.mDNSResponder\", \"category\": \"mDNS\"}')",
                duckdb::params![
                    source_file_id.to_string(),
                    SequenceCounter::new().next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].subsystem, "com.apple.mDNSResponder");
            assert_eq!(rows[0].category, "mDNS");
        }

        #[test]
        fn subsystem_and_category_filters_match_exactly_against_aul_entries() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut seq = SequenceCounter::new();
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, 'Default', 'a', 'a',
                         '{\"subsystem\": \"com.apple.mDNSResponder\", \"category\": \"mDNS\"}')",
                duckdb::params![
                    source_file_id.to_string(),
                    seq.next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, 'Default', 'b', 'b',
                         '{\"subsystem\": \"com.apple.wifi\", \"category\": \"WiFi\"}')",
                duckdb::params![
                    source_file_id.to_string(),
                    seq.next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let by_subsystem = fetch_window(
                &conn,
                &Query::parse("subsystem=com.apple.mDNSResponder"),
                0,
                10,
                &utc(),
                false,
            )
            .unwrap();
            assert_eq!(by_subsystem.len(), 1);
            assert_eq!(by_subsystem[0].message, "a");

            let by_category =
                fetch_window(&conn, &Query::parse("category=WiFi"), 0, 10, &utc(), false).unwrap();
            assert_eq!(by_category.len(), 1);
            assert_eq!(by_category[0].message, "b");
        }

        #[test]
        fn host_and_process_filters_match_exactly_against_journald_entries() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "journald");
            let mut seq = SequenceCounter::new();
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, '6', 'a', 'a',
                         '{\"_HOSTNAME\": \"host-a\", \"SYSLOG_IDENTIFIER\": \"sshd\"}')",
                duckdb::params![
                    source_file_id.to_string(),
                    seq.next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, '6', 'b', 'b',
                         '{\"_HOSTNAME\": \"host-b\", \"SYSLOG_IDENTIFIER\": \"cron\"}')",
                duckdb::params![
                    source_file_id.to_string(),
                    seq.next_sequence_number().value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let by_host =
                fetch_window(&conn, &Query::parse("host=host-a"), 0, 10, &utc(), false).unwrap();
            assert_eq!(by_host.len(), 1);
            assert_eq!(by_host[0].message, "a");

            let by_process =
                fetch_window(&conn, &Query::parse("process=cron"), 0, 10, &utc(), false).unwrap();
            assert_eq!(by_process.len(), 1);
            assert_eq!(by_process[0].message, "b");
        }

        #[test]
        fn fetch_window_leaves_subsystem_and_category_empty_for_journald() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "journald");
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "6",
                "a",
                "a",
            );

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].subsystem, "");
            assert_eq!(rows[0].category, "");
        }

        #[test]
        fn fetch_window_leaves_event_code_empty_for_non_evtx_sourcetypes() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "journald");
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "6",
                "a",
                "a",
            );

            let rows = fetch_window(&conn, &Query::parse(""), 0, 10, &utc(), false).unwrap();

            assert_eq!(rows[0].event_code, "");
        }

        #[test]
        fn tag_filter_matches_and_does_not_duplicate_multi_tagged_entries() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let event_id = EventId {
                source_file_id,
                sequence_number: SequenceCounter::new().next_sequence_number(),
            };
            insert_entry(&conn, event_id, "ERROR", "a", "a");
            insert_tag(&conn, event_id, "auth_failure");
            insert_tag(&conn, event_id, "reviewed");

            let query = Query::parse("tag=auth_failure");
            assert_eq!(
                count_matching(&conn, &query).unwrap(),
                1,
                "multiple tags on one entry must not duplicate it"
            );
        }

        #[test]
        fn tag_wildcard_matches_any_tagged_entry_regardless_of_value() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut counter = SequenceCounter::new();
            let tagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let untagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry(&conn, tagged, "Info", "a", "a");
            insert_entry(&conn, untagged, "Info", "b", "b");
            insert_tag(&conn, tagged, "wifi_status");

            let query = Query::parse("tag=*");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn not_tag_wildcard_matches_untagged_entries_only() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut counter = SequenceCounter::new();
            let tagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let untagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry(&conn, tagged, "Info", "a", "a");
            insert_entry(&conn, untagged, "Info", "b", "b");
            insert_tag(&conn, tagged, "wifi_status");

            let query = Query::parse("NOT tag=*");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn tag_regex_alternation_matches_any_selected_value() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut counter = SequenceCounter::new();
            let a = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let b = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let c = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry(&conn, a, "Info", "a", "a");
            insert_entry(&conn, b, "Info", "b", "b");
            insert_entry(&conn, c, "Info", "c", "c");
            insert_tag(&conn, a, "wifi_status");
            insert_tag(&conn, b, "screen_lock_state");
            insert_tag(&conn, c, "flashlight");

            // What the Tag quick-filter buttons generate when two tags are
            // selected at once — must be OR, not AND (see filter_bar tests).
            let query = Query::parse(r"tag~^(?:wifi_status|screen_lock_state)$");
            assert_eq!(count_matching(&conn, &query).unwrap(), 2);
        }

        #[test]
        fn after_and_before_bound_the_timestamp_range() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut counter = SequenceCounter::new();
            let base = chrono::NaiveDate::from_ymd_opt(2026, 7, 29)
                .unwrap()
                .and_hms_opt(10, 0, 0)
                .unwrap();
            for offset_minutes in [-10, -1, 0, 1, 10] {
                insert_entry_at(
                    &conn,
                    EventId {
                        source_file_id,
                        sequence_number: counter.next_sequence_number(),
                    },
                    base + chrono::Duration::minutes(offset_minutes),
                    &format!("event at offset {offset_minutes}"),
                );
            }

            // What "Show context around this event" (±5 min) generates
            // for an event at `base`.
            let query = Query::parse("after=2026-07-29T09:55:00 before=2026-07-29T10:05:00");
            assert_eq!(
                count_matching(&conn, &query).unwrap(),
                3,
                "only the entries within ±5 minutes of base should match"
            );
        }

        #[test]
        fn an_unparseable_after_value_matches_nothing_rather_than_erroring() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "INFO",
                "a",
                "a",
            );

            let query = Query::parse("after=not-a-date");
            assert_eq!(count_matching(&conn, &query).unwrap(), 0);
        }

        #[test]
        fn tag_and_untagged_combined_with_or_shows_both_alongside_a_level_filter() {
            // Regression test for the exact bug report: selecting a tag
            // (e.g. "airplane_mode") *and* Untagged together must show
            // both the tagged entries and the untagged ones around them
            // — not silently AND into a contradiction ("has this tag AND
            // has no tag") that always returns zero rows. Also proves the
            // FilterBar fix's front-positioning actually works when a
            // Level filter is also active — the exact combination that
            // breaks without it (see `set_tag_block`'s doc comment).
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut counter = SequenceCounter::new();
            let tagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let untagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let neither = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry(&conn, tagged, "Info", "a", "a");
            insert_entry(&conn, untagged, "Info", "b", "b");
            insert_entry(&conn, neither, "Error", "c", "c");
            insert_tag(&conn, tagged, "airplane_mode");

            // Exactly what FilterBar now produces for tag=airplane_mode +
            // Untagged + level=Info (tag block kept at the front).
            let query = Query::parse("tag~^(?:airplane_mode)$ OR NOT tag=* level~^(?:Info)$");
            assert_eq!(
                count_matching(&conn, &query).unwrap(),
                2,
                "must match both the tagged and the untagged Info entry, not neither"
            );
        }

        #[test]
        fn not_excludes_matching_entries() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERROR",
                "a",
                "a",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "b",
                "b",
            );

            let query = Query::parse("NOT level=ERROR");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn empty_query_matches_everything() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "INFO",
                "a",
                "a",
            );

            let query = Query::parse("");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn regex_field_filter_matches() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "user42 logged in",
                "raw",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "no digits here",
                "raw",
            );

            let query = Query::parse(r"message~user\d+");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn distinct_tags_returns_sorted_unique_values() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut counter = SequenceCounter::new();
            let a = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let b = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry(&conn, a, "Info", "m", "r");
            insert_entry(&conn, b, "Info", "m", "r");
            insert_tag(&conn, a, "wifi_status");
            insert_tag(&conn, b, "screen_lock_state");
            insert_tag(&conn, b, "wifi_status");

            assert_eq!(
                distinct_tags(&conn).unwrap(),
                vec!["screen_lock_state".to_string(), "wifi_status".to_string()]
            );
        }

        #[test]
        fn distinct_tags_is_empty_when_no_tags_applied() {
            let conn = open_test_db();
            assert_eq!(distinct_tags(&conn).unwrap(), Vec::<String>::new());
        }

        #[test]
        fn tag_counts_counts_events_per_tag_value_not_per_tag_row() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let mut counter = SequenceCounter::new();
            let a = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let b = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry(&conn, a, "Info", "m", "r");
            insert_entry(&conn, b, "Info", "m", "r");
            insert_tag(&conn, a, "wifi_status");
            insert_tag(&conn, b, "screen_lock_state");
            insert_tag(&conn, b, "wifi_status");

            let counts = tag_counts(&conn).unwrap();

            assert_eq!(counts.get("wifi_status"), Some(&2));
            assert_eq!(counts.get("screen_lock_state"), Some(&1));
        }

        #[test]
        fn tag_counts_is_empty_when_no_tags_applied() {
            let conn = open_test_db();
            assert!(tag_counts(&conn).unwrap().is_empty());
        }

        #[test]
        fn level_counts_counts_events_per_level_regardless_of_sourcetype() {
            // `level=` itself isn't scoped by sourcetype (see `Field::Level`),
            // so counts for the same level string from two different
            // sourcetypes must be summed together, not kept separate.
            let conn = open_test_db();
            let evtx_source = SourceFileId::new_random();
            let journald_source = SourceFileId::new_random();
            insert_source(&conn, evtx_source, "evtx");
            insert_source(&conn, journald_source, "journald");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id: evtx_source,
                    sequence_number: counter.next_sequence_number(),
                },
                "2",
                "evtx error",
                "raw",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id: journald_source,
                    sequence_number: counter.next_sequence_number(),
                },
                "2",
                "journald crit",
                "raw",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id: evtx_source,
                    sequence_number: counter.next_sequence_number(),
                },
                "4",
                "evtx info",
                "raw",
            );

            let counts = level_counts(&conn).unwrap();

            assert_eq!(counts.get("2"), Some(&2));
            assert_eq!(counts.get("4"), Some(&1));
        }

        #[test]
        fn source_counts_counts_events_per_loaded_source() {
            let conn = open_test_db();
            let source_a = SourceFileId::new_random();
            let source_b = SourceFileId::new_random();
            insert_source(&conn, source_a, "evtx");
            insert_source(&conn, source_b, "evtx");
            let mut counter = SequenceCounter::new();
            for _ in 0..3 {
                insert_entry(
                    &conn,
                    EventId {
                        source_file_id: source_a,
                        sequence_number: counter.next_sequence_number(),
                    },
                    "INFO",
                    "m",
                    "r",
                );
            }
            insert_entry(
                &conn,
                EventId {
                    source_file_id: source_b,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "m",
                "r",
            );

            let counts = source_counts(&conn).unwrap();

            assert_eq!(counts.get(&source_a.to_string()), Some(&3));
            assert_eq!(counts.get(&source_b.to_string()), Some(&1));
        }

        fn insert_import_tag(
            conn: &Connection,
            event_id: EventId,
            rule_name: &str,
            tag_value: &str,
        ) {
            conn.execute(
                "INSERT INTO import_tags (event_id_source, event_id_seq, rule_name, tag_value, applied_at)
                 VALUES (?, ?, ?, ?, ?)",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    rule_name,
                    tag_value,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();
        }

        #[test]
        fn rule_counts_for_sources_groups_by_rule_name_within_scope() {
            let conn = open_test_db();
            let in_scope = SourceFileId::new_random();
            let out_of_scope = SourceFileId::new_random();
            insert_source(&conn, in_scope, "evtx");
            insert_source(&conn, out_of_scope, "evtx");
            let mut counter = SequenceCounter::new();
            let a = EventId {
                source_file_id: in_scope,
                sequence_number: counter.next_sequence_number(),
            };
            let b = EventId {
                source_file_id: in_scope,
                sequence_number: counter.next_sequence_number(),
            };
            let c = EventId {
                source_file_id: out_of_scope,
                sequence_number: counter.next_sequence_number(),
            };
            insert_import_tag(&conn, a, "evtx_logon_success", "logon_success");
            insert_import_tag(&conn, b, "evtx_process_creation", "process_creation");
            // A tag on a source outside the requested scope must not leak in.
            insert_import_tag(&conn, c, "evtx_logon_success", "logon_success");

            let counts = rule_counts_for_sources(&conn, &[in_scope.to_string()]).unwrap();

            assert_eq!(counts.get("evtx_logon_success"), Some(&1));
            assert_eq!(counts.get("evtx_process_creation"), Some(&1));
            assert_eq!(counts.len(), 2);
        }

        #[test]
        fn rule_counts_for_sources_is_empty_for_no_source_ids() {
            let conn = open_test_db();
            assert!(rule_counts_for_sources(&conn, &[]).unwrap().is_empty());
        }

        #[test]
        fn fetch_full_entry_includes_raw_and_sorted_tags() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let event_id = EventId {
                source_file_id,
                sequence_number: SequenceCounter::new().next_sequence_number(),
            };
            insert_entry(&conn, event_id, "Info", "the message", "the raw record");
            insert_tag(&conn, event_id, "wifi_status");
            insert_tag(&conn, event_id, "app_launch");

            let entry = fetch_full_entry(&conn, event_id, &utc()).unwrap().unwrap();

            assert_eq!(entry.level, "Info");
            assert_eq!(entry.message, "the message");
            assert_eq!(entry.raw, "the raw record");
            assert_eq!(entry.fields, serde_json::json!({}));
            assert_eq!(entry.tags, vec!["app_launch", "wifi_status"]);
            assert!(entry.to_text().contains("the raw record"));
        }

        #[test]
        fn fetch_full_entry_keeps_timestamp_utc_literal_while_timestamp_display_follows_the_configured_zone()
         {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let event_id = EventId {
                source_file_id,
                sequence_number: SequenceCounter::new().next_sequence_number(),
            };
            insert_entry_at(
                &conn,
                event_id,
                chrono::NaiveDate::from_ymd_opt(2026, 7, 28)
                    .unwrap()
                    .and_hms_opt(12, 0, 0)
                    .unwrap(),
                "noon in utc",
            );

            let entry = fetch_full_entry(&conn, event_id, &TimezoneSpec::parse("+02:00").unwrap())
                .unwrap()
                .unwrap();

            assert_eq!(entry.timestamp_utc, "2026-07-28 12:00:00.000");
            assert_eq!(entry.timestamp_display, "2026-07-28 14:00:00.000 +02:00");
            assert!(entry.to_text().contains("2026-07-28 14:00:00.000 +02:00"));
            assert!(!entry.to_text().contains("12:00:00.000\n"));
        }

        #[test]
        fn fetch_full_entry_includes_the_fields_json_distinct_from_raw() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let event_id = EventId {
                source_file_id,
                sequence_number: SequenceCounter::new().next_sequence_number(),
            };
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, 'INFO', 'the message', 'the literal original line',
                         '{\"ip\": \"10.0.0.1\"}')",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();

            let entry = fetch_full_entry(&conn, event_id, &utc()).unwrap().unwrap();

            assert_eq!(entry.raw, "the literal original line");
            assert_eq!(entry.fields, serde_json::json!({"ip": "10.0.0.1"}));
            let text = entry.to_text();
            assert!(text.contains("Raw: the literal original line"));
            assert!(text.contains("Fields: {\"ip\":\"10.0.0.1\"}"));
        }

        #[test]
        fn fetch_full_entry_is_none_for_an_unknown_event_id() {
            let conn = open_test_db();
            let event_id = EventId {
                source_file_id: SourceFileId::new_random(),
                sequence_number: SequenceCounter::new().next_sequence_number(),
            };

            assert!(fetch_full_entry(&conn, event_id, &utc()).unwrap().is_none());
        }

        #[test]
        fn case_summary_of_an_empty_timeline_is_all_zero_or_none() {
            let conn = open_test_db();

            let summary = case_summary(&conn, &Query::default()).unwrap();

            assert_eq!(summary.total_entries, 0);
            assert_eq!(summary.tagged_entries, 0);
            assert!(summary.sources.is_empty());
            assert!(summary.sourcetype_counts.is_empty());
            assert!(summary.level_counts.is_empty());
            assert_eq!(summary.earliest_utc, None);
            assert_eq!(summary.latest_utc, None);
            assert_eq!(summary.daily_histogram, None);
        }

        #[test]
        fn case_summary_counts_entries_per_source_and_sourcetype() {
            let conn = open_test_db();
            let evtx_source = SourceFileId::new_random();
            let text_source = SourceFileId::new_random();
            insert_source(&conn, evtx_source, "evtx");
            insert_source(&conn, text_source, "text_config");
            let mut counter = SequenceCounter::new();
            for _ in 0..3 {
                insert_entry(
                    &conn,
                    EventId {
                        source_file_id: evtx_source,
                        sequence_number: counter.next_sequence_number(),
                    },
                    "INFO",
                    "evtx entry",
                    "raw",
                );
            }
            insert_entry(
                &conn,
                EventId {
                    source_file_id: text_source,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "text entry",
                "raw",
            );

            let summary = case_summary(&conn, &Query::default()).unwrap();

            assert_eq!(summary.total_entries, 4);
            assert_eq!(summary.sources.len(), 2);
            // Descending by entry_count: the 3-entry evtx source comes first.
            assert_eq!(summary.sources[0].source_file_id, evtx_source.to_string());
            assert_eq!(summary.sources[0].entry_count, 3);
            assert_eq!(summary.sources[1].entry_count, 1);
            assert_eq!(
                summary.sourcetype_counts,
                vec![("evtx".to_string(), 3), ("text_config".to_string(), 1)]
            );
        }

        #[test]
        fn case_summary_reports_tag_coverage() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            let tagged = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let untagged_a = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            let untagged_b = EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            };
            insert_entry(&conn, tagged, "INFO", "a", "raw");
            insert_entry(&conn, untagged_a, "INFO", "b", "raw");
            insert_entry(&conn, untagged_b, "INFO", "c", "raw");
            insert_tag(&conn, tagged, "reviewed");

            let summary = case_summary(&conn, &Query::default()).unwrap();

            assert_eq!(summary.total_entries, 3);
            assert_eq!(summary.tagged_entries, 1);
        }

        #[test]
        fn case_summary_level_counts_exclude_entries_with_no_level() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERROR",
                "a",
                "raw",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERROR",
                "b",
                "raw",
            );
            // No level at all — via `insert_entry_at`, which always inserts
            // a NULL level.
            insert_entry_at(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                Utc::now().naive_utc(),
                "c",
            );

            let summary = case_summary(&conn, &Query::default()).unwrap();

            assert_eq!(
                summary.total_entries, 3,
                "the level-less entry still counts"
            );
            assert_eq!(summary.level_counts, vec![("ERROR".to_string(), 2)]);
        }

        #[test]
        fn case_summary_respects_the_query_filter() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "hello world",
                "raw",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "goodbye world",
                "raw",
            );

            let summary = case_summary(&conn, &Query::parse("hello")).unwrap();

            assert_eq!(summary.total_entries, 1);
            assert_eq!(summary.sources[0].entry_count, 1);
        }

        #[test]
        fn case_summary_daily_histogram_preserves_a_gap_day() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            let day1 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap();
            // 2026-01-02 deliberately has no entries at all.
            let day3 = chrono::NaiveDate::from_ymd_opt(2026, 1, 3)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap();
            insert_entry_at(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                day1,
                "first day",
            );
            insert_entry_at(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                day3,
                "third day",
            );

            let summary = case_summary(&conn, &Query::default()).unwrap();

            let histogram = summary.daily_histogram.unwrap();
            assert_eq!(histogram.len(), 3, "day 1, the empty gap day, and day 3");
            assert_eq!(histogram[0].1, 1);
            assert_eq!(
                histogram[1].1, 0,
                "the gap day must be present, not skipped"
            );
            assert_eq!(histogram[2].1, 1);
        }

        #[test]
        fn case_summary_histogram_is_none_when_the_span_exceeds_the_cap() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            let far_past = chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            let far_future = chrono::NaiveDate::from_ymd_opt(2011, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            insert_entry_at(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                far_past,
                "old",
            );
            insert_entry_at(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                far_future,
                "new",
            );

            let summary = case_summary(&conn, &Query::default()).unwrap();

            assert!(summary.earliest_utc.is_some());
            assert!(summary.latest_utc.is_some());
            assert_eq!(
                summary.daily_histogram, None,
                "an 11-year span must not build a multi-thousand-entry dense vector"
            );
        }
    }
}
