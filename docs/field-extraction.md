# Field Extraction Per Sourcetype

Every entry, regardless of sourcetype, gets normalized into the same core
columns (`timestamp_utc`, `level`, `message`, `raw`, `fields`) — see
[supported-sources.md](supported-sources.md) for what each parser puts in
those. Beyond that core set, the timeline view surfaces a handful of
*extra* columns pulled out of `fields` (a source-specific JSON blob) for
sourcetypes where the underlying field is confirmed to exist and mean what
the column name says. This is the authoritative list of that extraction —
update it alongside any change to
[`db::timeline_queries::extracted_field_sql`](../src/db/timeline_queries.rs),
the same file that implements it.

Every extra column below (Host, Process, Event ID, Subsystem, Category) is
also a search-grammar field — `host=`, `process=`, `event_id=`,
`subsystem=`, `category=` (see [user-guide.md](user-guide.md#search) for the
full grammar, `!=`/`~` included). Each filter shares its exact `CASE`
expression with the matching column (a `*_case_sql` function in
`timeline_queries.rs`, e.g. `host_case_sql`), so a row that's empty in a
column is exactly a row that never matches that column's filter either —
one mapping, not two that could quietly drift apart.

A row here is either:
- **Confirmed** — verified against a real fixture (a crate's own test
  snapshot, or output from actually parsing a real file), not guessed.
- **Not mapped** — deliberately left as `NULL`/empty rather than guessing at
  a JSON path. Better an empty column than one that silently shows the
  wrong thing.

## Source (file) / Sourcetype

Not from `fields` — from the `sources` table (`path`/`sourcetype`),
joined by `source_file_id`. Present for every sourcetype, always. Source is
always shown in the timeline table; Sourcetype is opt-in via the "Columns"
picker (usually redundant with the file's own name/extension).

## Level (display-only name mapping)

Not extracted from `fields`, and not a `db::timeline_queries` concern —
`timeline_view::level_display_name` (used by both `format_level`, the
table's Level column, and `TimelineView::distinct_levels`, the quick
Level-filter row's button labels in `ui::filter_bar`) appends a
human-readable severity name to a sourcetype's raw numeric `level` for
*display* only. The *stored* `level` value, and the actual query term a
filter button writes, are never touched (forensic "raw stays raw", same
principle as the extracted-field table below, just applied to formatting
instead of a JOIN). When several loaded sourcetypes disagree on what a
shared digit means (e.g. journald's `"2"` is `crit`, EVTX's `"2"` is
`Error`), the filter button shows both names rather than silently picking
one:

| Sourcetype | Status | Mapping |
|---|---|---|
| journald | Confirmed | Standard syslog `PRIORITY` digits `0`-`7` (`systemd.journal-fields(7)`) -> `emerg`/`alert`/`crit`/`err`/`warning`/`notice`/`info`/`debug` |
| evtx | Confirmed | Standard Windows Event Level digits `0`-`5` (`winmeta.xml`'s `WINEVENT_LEVEL_*` constants, fixed at the OS/schema level, not per-provider) -> `LogAlways`/`Critical`/`Error`/`Warning`/`Informational`/`Verbose`. `6`-`255` are provider-defined/reserved and deliberately left unmapped |
| aul / text_config / other | Not mapped | AUL's `LogType` and text-log levels are already human-readable strings, nothing to translate |

## Host

| Sourcetype | Status | Field |
|---|---|---|
| journald | Confirmed | `_HOSTNAME` (documented systemd field, `systemd.journal-fields(7)`) |
| evtx | Confirmed | `Event.System.Computer` — verified against the `evtx` crate's own test snapshot (`evtx-0.12.2/tests/snapshots/test_record_samples__event_json_sample_with_separate_json_attributes.snap`), the `separate_json_attributes(true)` shape `parsers::evtx` actually parses with (see its doc comment for why) |
| aul | Not mapped | AUL is a single-device archive — no host concept |
| text_config / other | Not mapped | No universal field across arbitrary TOML-configured text formats |

## Process

| Sourcetype | Status | Field |
|---|---|---|
| journald | Confirmed | `SYSLOG_IDENTIFIER`, falling back to `_COMM` when a process didn't set its own identifier (both documented systemd fields) |
| aul | Confirmed | `process` (verified against `parsers::aul`'s own test fixtures) |
| evtx | Not mapped | The only generically available field is `Event.System.Execution_attributes.ProcessID` — a bare numeric PID, not a process name/path. Mixing "a name" and "a PID" under one "Process" column would misrepresent one of them, so this is deliberately left unmapped rather than shown as a misleading number |
| text_config / other | Not mapped | No universal field |

## Message (parser-level, not `db::timeline_queries`)

Unlike every other row in this document, this mapping happens in the
parser itself (`parsers::evtx::to_parsed_record`), not in
`extracted_field_sql` — `message` is a core column (see the intro above),
so populating it is normalization, not an extra display column. Listed
here anyway since it's still "a field extracted from a sourcetype-specific
JSON shape," the same category of decision as everything else on this page.

| Sourcetype | Status | Field |
|---|---|---|
| evtx | Confirmed, conditional | `Event.RenderingInfo.Message` — an *optional* part of the Windows Event schema (`RenderingInfoType`, `minOccurs="0"` in Microsoft's own MS-EVEN6 schema, bundled with the `evtx` crate). Present only when the file was produced by something that rendered the event first (e.g. Windows Event Forwarding's collector side); a plain live `winevt\Logs\*.evtx` read directly won't have it, since real rendering needs message-resource DLLs/templates this crate doesn't ship |
| evtx (fallback) | Confirmed, conditional | When `RenderingInfo.Message` is absent, `parsers::evtx_templates::render_for_event` looks up a built-in template for this record's `(Event.System.Provider_attributes.Name, Event.System.EventID)` — see [Message templates](#message-templates-evtx) below. A record matching no built-in template still leaves `message` empty; nothing is ever fabricated without a curated template backing it |

### Message templates (evtx)

`message_templates/examples/evtx_*.toml`, embedded at compile time
(`build.rs`, same mechanism as the AUL rule pack — see
`parsers::evtx_templates`'s module doc comment). Each entry maps one
`(provider, event_id)` to a template string; `{FieldName}` placeholders are
resolved against this record's `Event.EventData` object (the `evtx`
crate's flattened form for named `<Data Name="...">` elements — confirmed
against `evtx-0.12.2/tests/snapshots/test_record_samples__event_json_sample_with_event_data.snap`).
An unresolved placeholder (field genuinely absent, or `EventData` isn't a
named-field object at all — e.g. a legacy provider using the positional
`%1`/`%2` scheme) is left as literal `{FieldName}` text rather than dropped
or blanked, so a bad or mismatched template shows itself immediately
instead of rendering something plausible-looking but wrong.

**This is Peach's own reconstruction, not source-provided text** —
qualitatively different provenance from a real `RenderingInfo.Message`, so
every template-rendered message is prefixed with
`parsers::evtx_templates::RENDERED_PREFIX` (`"[Peach] "`). A real
`RenderingInfo.Message`, when present, always wins; the template fallback
only ever fires in its absence.

Current coverage (Security-auditing-first, the events an IR analyst reaches
for before anything else): logon/logoff (4624/4625/4634/4648/4672),
process creation (4688), service install (4697, and Service Control
Manager's 7045), account/group management (4720/4724/4728/4732/4738/4740/4756),
credential validation (4776), audit log clearing (1102), and PowerShell
ScriptBlock logging (4104). Field names come from Microsoft's published
Security-Auditing event reference, not guesswork; anything outside this set
falls through to empty, same as before this feature existed.

## Event ID

Windows Event Log's numeric event-type code (e.g. `4625` = failed logon) —
the single most load-bearing field for triaging EVTX, so it gets its own
column rather than staying buried in `fields`/`raw`, and its own search
grammar field: `event_id=4625` (exact match; `event_id~`/`event_id!=` work
too, same as any other field — see [user-guide.md](user-guide.md#search)).
The filter and the column are backed by the exact same `CASE` expression
(`db::timeline_queries::event_code_case_sql`, factored out specifically so
the two can't drift apart on what "Event ID" means).

| Sourcetype | Status | Field |
|---|---|---|
| evtx | Confirmed | `Event.System.EventID` — same snapshot fixture as Host above. Some elements (most commonly `EventID` on older/manifest-free providers like MsiInstaller or the Service Control Manager) carry a `Qualifiers` XML attribute alongside their value; without `separate_json_attributes(true)` this would serialize as a nested `{"#text": ..., "#attributes": {...}}` object instead of a plain number, which is exactly why `parsers::evtx` parses with that setting on |
| journald / aul / text_config / other | Not mapped | No equivalent concept |

## Subsystem

The logging component: which piece of software emitted the entry.

| Sourcetype | Status | Field |
|---|---|---|
| aul | Confirmed | `subsystem` (e.g. `"com.apple.mDNSResponder"`) — verified directly against a real loaded session's `fields` JSON, matching `macos-unifiedlogs`' own `LogData` field name |
| evtx | Confirmed | `Event.System.Provider_attributes.Name` (e.g. `"Microsoft-Windows-Security-Auditing"`) — same snapshot fixture as Host above; conceptually the closest EVTX equivalent to AUL's subsystem (both identify "which component logged this") |
| journald / text_config / other | Not mapped | No equivalent concept |

## Category

A further sub-classification *within* a subsystem/component, set by
whoever wrote the logging code.

| Sourcetype | Status | Field |
|---|---|---|
| aul | Confirmed | `category` (e.g. `"mDNS"`) — same verification as `subsystem` above |
| evtx | **Deliberately not mapped** | `Event.System.Channel` (e.g. `"Security"`, `"Application"`) looks similar but is a different kind of thing: which top-level Windows Event Log the entry was routed to, not a developer-set classification the way AUL's `category` is. Mapping it here would misrepresent it as something more fine-grained than it actually is — same reasoning as EVTX's `process` staying unmapped (a PID isn't a process name) |
| journald / text_config / other | Not mapped | No equivalent concept |

## Adding a new extracted field

1. Confirm the JSON path against a real fixture first — a crate's own test
   snapshot, a real sample file, or (for AUL/text) the parser's own test
   data. Never guess a path from documentation alone if a real fixture is
   available to check it against.
2. Write a `fn foo_case_sql(fields_ref: &str, sourcetype_ref: &str) -> String`
   in `src/db/timeline_queries.rs` returning the bare `CASE {sourcetype_ref}
   WHEN '...' THEN json_extract_string({fields_ref}, '$....') ... END`
   expression (see `host_case_sql`/`subsystem_case_sql`/etc. for the
   pattern) — a function, not an inline `CASE` in `extracted_field_sql`
   only, so the same expression can also back a search-grammar filter (next
   step) without a second, separately-maintained copy.
3. Wire it into `extracted_field_sql`'s `format!` (`{foo_case} AS foo,`).
4. Add the field to `DisplayRow`, `fetch_window`'s row-parsing tuple, and
   the `DisplayRow` construction at the end of `fetch_window`.
5. Add a column toggle + rendering in `timeline_view.rs` (`show_*_column`
   field, `Columns` picker checkbox, header/body cells, and the
   `full_row_rect` union so right-click still covers the new cell).
6. If it should be search-filterable too (usually yes — see the note at the
   top of this document): add a `Field::Foo` variant + `"foo"` keyword in
   `Field::parse`, then a `Field::Foo => foo_case_sql(...)` arm in
   `compile_term_kind`'s `column` match (plus the exact-match-vs-`LIKE`
   match right below it — most extracted fields want exact match, a
   discrete value rather than free text; see `Field::EventId`'s doc comment
   for the reasoning).
7. Add a test with the field's real JSON shape (not a synthetic
   simplification) confirming extraction, a test confirming it stays empty
   for sourcetypes without a mapping, and (if filterable) a test that the
   `field=` filter actually matches/excludes the right rows.
8. Update this document.
