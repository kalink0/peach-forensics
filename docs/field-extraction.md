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
`timeline_view::format_level` appends a human-readable severity name to a
sourcetype's raw numeric `level` for the Level column's display text only.
The *stored* `level` value is never touched (forensic "raw stays raw",
same principle as the extracted-field table below, just applied to
formatting instead of a JOIN):

| Sourcetype | Status | Mapping |
|---|---|---|
| journald | Confirmed | Standard syslog `PRIORITY` digits `0`-`7` (`systemd.journal-fields(7)`) -> `emerg`/`alert`/`crit`/`err`/`warning`/`notice`/`info`/`debug` |
| evtx | Confirmed | Standard Windows Event Level digits `0`-`5` (`winmeta.xml`'s `WINEVENT_LEVEL_*` constants, fixed at the OS/schema level, not per-provider) -> `LogAlways`/`Critical`/`Error`/`Warning`/`Informational`/`Verbose`. `6`-`255` are provider-defined/reserved and deliberately left unmapped |
| aul / text_config / other | Not mapped | AUL's `LogType` and text-log levels are already human-readable strings, nothing to translate |

## Host

| Sourcetype | Status | Field |
|---|---|---|
| journald | Confirmed | `_HOSTNAME` (documented systemd field, `systemd.journal-fields(7)`) |
| evtx | Confirmed | `Event.System.Computer` — verified against the `evtx` crate's own test snapshot (`evtx-0.12.2/tests/snapshots/test_record_samples__event_json_sample.snap`), the default non-`separate_json_attributes` shape this parser uses |
| aul | Not mapped | AUL is a single-device archive — no host concept |
| text_config / other | Not mapped | No universal field across arbitrary TOML-configured text formats |

## Process

| Sourcetype | Status | Field |
|---|---|---|
| journald | Confirmed | `SYSLOG_IDENTIFIER`, falling back to `_COMM` when a process didn't set its own identifier (both documented systemd fields) |
| aul | Confirmed | `process` (verified against `parsers::aul`'s own test fixtures) |
| evtx | Not mapped | The only generically available field is `Event.System.Execution.#attributes.ProcessID` — a bare numeric PID, not a process name/path. Mixing "a name" and "a PID" under one "Process" column would misrepresent one of them, so this is deliberately left unmapped rather than shown as a misleading number |
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
| evtx | Confirmed, conditional | `Event.RenderingInfo.Message` — an *optional* part of the Windows Event schema (`RenderingInfoType`, `minOccurs="0"` in Microsoft's own MS-EVEN6 schema, bundled with the `evtx` crate). Present only when the file was produced by something that rendered the event first (e.g. Windows Event Forwarding's collector side); a plain live `winevt\Logs\*.evtx` read directly won't have it, since rendering needs message-resource DLLs/templates this crate doesn't ship. `message` stays empty when absent — never fabricated from `EventData` or anything else |

## Event ID

Windows Event Log's numeric event-type code (e.g. `4625` = failed logon) —
the single most load-bearing field for triaging EVTX, so it gets its own
column rather than staying buried in `fields`/`raw`.

| Sourcetype | Status | Field |
|---|---|---|
| evtx | Confirmed | `Event.System.EventID` — same snapshot fixture as Host above |
| journald / aul / text_config / other | Not mapped | No equivalent concept |

## Subsystem

The logging component: which piece of software emitted the entry.

| Sourcetype | Status | Field |
|---|---|---|
| aul | Confirmed | `subsystem` (e.g. `"com.apple.mDNSResponder"`) — verified directly against a real loaded session's `fields` JSON, matching `macos-unifiedlogs`' own `LogData` field name |
| evtx | Confirmed | `Event.System.Provider.#attributes.Name` (e.g. `"Microsoft-Windows-Security-Auditing"`) — same snapshot fixture as Host above; conceptually the closest EVTX equivalent to AUL's subsystem (both identify "which component logged this") |
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
2. Add a `CASE s.sourcetype WHEN '...' THEN json_extract_string(le.fields, '$....')`
   branch in `extracted_field_sql` (`src/db/timeline_queries.rs`).
3. Add the field to `DisplayRow`, `fetch_window`'s row-parsing tuple, and
   the `DisplayRow` construction at the end of `fetch_window`.
4. Add a column toggle + rendering in `timeline_view.rs` (`show_*_column`
   field, `Columns` picker checkbox, header/body cells, and the
   `full_row_rect` union so right-click still covers the new cell).
5. Add a test with the field's real JSON shape (not a synthetic
   simplification) confirming extraction, and a test confirming it stays
   empty for sourcetypes without a mapping.
6. Update this document.
