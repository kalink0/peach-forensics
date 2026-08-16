# Peach User Guide

This covers how to operate Peach today. For what source types are actually
supported, see [supported-sources.md](supported-sources.md) — this guide assumes
you already know which sourcetype you're loading.

Every dialog (About, Settings, Notes, Tag this event/Advanced tagging,
View raw/fields, Define format, Manage sessions, Time range) opens as its
own real, independent window — draggable anywhere on the desktop,
including off the main window entirely or onto a second monitor, not
confined to staying inside the main window the way a typical in-app popup
would be. Closing one works the normal way for a window on your OS (the
title bar's close button) as well as via any in-dialog Cancel/Close
button.

## Loading a source

1. Pick a **Sourcetype**: `AUL (.logarchive)`, `EVTX`, `journald`, or
   `Text (config-based)`.
2. Click the picker button:
   - AUL expects a folder — the `.logarchive` bundle itself (it contains
     `Persist`/`Special`/`Signpost`/`HighVolume` subfolders plus `dsc`/`uuidtext`/
     `timesync` reference data). One `.logarchive` becomes one source.
   - EVTX/journald/Text's **"Choose ... file(s)..."** button supports
     selecting several files at once (e.g. `Application.evtx` +
     `Security.evtx` + `System.evtx` together) — the first one becomes the
     current source, the rest queue up ("N more source(s) queued", same as
     `--add-source`) and become the current source in turn as each load
     finishes. Each still needs its own **Load** click; a multi-select
     doesn't load itself automatically, since different queued files can
     need different settings (sourcetype, parser config) before loading.
   - Any of them also has a **"Choose folder..."** button, which recursively
     loads every matching file under that folder (and subfolders) as
     separate sources in one go — no per-file **Load** click needed, but
     also no per-file control over settings first. Text expects a
     **parser config** (TOML) either way — see below.
3. Optionally choose one or more **tagging rules** (TOML, multi-select) — see
   [Tagging](#tagging).
4. Click **Load**. Loading runs in the background so the UI stays responsive; a
   large AUL source can take a while and insert millions of rows.

**Abort** appears next to **Load** while a load is running. It stops after the
file currently being parsed finishes (or, for one very large file, at the next
internal checkpoint — every 10,000 entries) — whatever's already been inserted
stays, nothing gets rolled back. The result shows **"Aborted"**, with the real
(partial) counts alongside it, and a `--add-source`/multi-select queue does
**not** auto-continue into its next file after an abort.

Peach never auto-detects a format — you always confirm the sourcetype yourself.

A file that `--add-source`, a multi-select pick, or **"Choose folder..."**
finds but that produces zero timeline entries (a real parse error, or a
file that parsed cleanly but matched nothing — e.g. an EVTX channel that's
never logged anything) shows up as **"N file(s) skipped"** next to the load
result, rather than silently vanishing from the count. Hover it for the
exact path and reason per file.

### Text parser configs

A text source needs a TOML file describing how to parse it: a regex with named
capture groups, a timestamp format, and a mapping from capture groups to Peach's
normalized `level`/`message` fields. Example:

```toml
[parser]
name = "nginx_access"
sourcetype = "nginx"

[parser.pattern]
regex = '^(?P<timestamp>\S+) (?P<level_raw>\w+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%dT%H:%M:%S%z"
# multiline_start_pattern = '^\d{4}-\d{2}-\d{2}'   # optional, for multi-line events
# assume_offset = "+02:00"                          # only if timestamp_format has no timezone

[parser.field_mapping]
level = "level_raw"
message = "msg"
```

- `timestamp_format` **must** resolve to an absolute time. If it doesn't carry its
  own timezone (no `%z`), set `assume_offset` explicitly (`"+02:00"`, `"UTC"`, …) —
  Peach refuses to guess a timezone.
- `multiline_start_pattern` groups continuation lines (e.g. stack traces) into the
  event whose first line matched the pattern; without it, every line is its own
  event.
- Every named capture group ends up in the entry's `fields`, not just the ones
  used in `field_mapping` — useful for tagging rules and search (`fieldname=...`).
- A line that doesn't match `pattern.regex` aborts the whole parse with a clear
  error (including the line number) rather than being silently skipped.

Hand-editing that TOML isn't the only way to get there: with `Text (config-based)`
selected and a source file picked, **"Define format..."** opens a builder for it
instead — the same fields as above, plus a live preview against the first 20
lines of the actual picked file. Each preview line shows its named capture
groups colour-highlighted, and underneath, the exact level/message/timestamp
a real load would produce for that line (or its exact error, if it wouldn't
parse) — the preview calls the same parsing code a real **Load** does, so it
can't show something a real load would then contradict. **Save** writes the
config to a per-user library (without touching whatever's currently selected
for the pending load); **Save & Use** does the same and also makes it the
active parser config, closing the dialog. **Load** next to the saved-configs
dropdown pulls an existing config's fields back in for editing/reuse.

## Tagging

Tagging rules are TOML files matching entries against normalized fields
(`sourcetype`, `level`, `message`) or source-specific fields inside `fields`:

```toml
[rule]
name = "failed_logon"
description = "Windows failed logon"

[rule.match]
sourcetype = "evtx"
event_id = 4625

[rule.tag]
value = "auth_failure"
```

`message_contains` is a substring variant of `message`: a string or array of
strings, matching if the entry's message contains *any* of them. This is the
main mechanism for pattern-of-life categorization, where messages carry
variable data around a recognizable fixed substring:

```toml
[rule.match]
sourcetype = "aul"
message_contains = ["Screen did lock", "screen is unlocked"]
```

`rules/examples/aul_*.toml` is a pattern-of-life rule pack for AUL (33 rule
files covering human presence/handling, communication and input, application
activity, connectivity, device state and power, media/audio/camera, motion
and vehicle, and emergency SOS) — the predicates are sourced from "Apple
Unified Log Predicates in iLEAPP: The Reference" (Alexis Brignoni),
leapps.org/blog-post?post=2026-08-01-unified-log-predicate-reference, rather
than re-derived from scratch. SMS/message *content* is still out of scope —
that lives in a separate SQLite database Peach doesn't parse — but call
tracking itself (`aul_call_events.toml`) is covered directly from Unified Log
predicates.

`rules/examples/evtx_*.toml` is the tagging companion to the built-in EVTX
message templates (see [field-extraction.md](field-extraction.md#message-templates-evtx)):
15 rule files covering the same Security-Auditing event IDs those templates
render — logon/logoff (4624/4625/4634/4648/4672), process creation (4688),
service install (4697), account/group management (4720/4724/4728/4732/4738/4740/4756),
and credential validation (4776) — cross-checked against Microsoft's official
Security Auditing event reference for each event ID (see each rule file's
header comment for its specific citation). `event_id`/`provider` are
normalized match keys resolved against EVTX's actual nested
`Event.System.*` JSON shape, not a flat top-level lookup — see
`tagging::rule::normalized_field`'s doc comment if writing a custom rule
against these fields yourself.

Unlike other rule files (which load either automatically from the
configured [rules directory](#settings) or by explicit selection via
"Choose tagging rules..."), both of these packs ship **embedded in the
binary itself** (`build.rs` bundles every `rules/examples/aul_*.toml` and
`rules/examples/evtx_*.toml` file at compile time — see
`src/tagging/builtin.rs`) and every rule in them is applied automatically on
every load and re-tag by default — no file to locate or select, works the
same in a release build with no repo nearby. Every rule matches its own
`sourcetype` on its own, so an enabled AUL rule never tags an EVTX row or
vice versa.

**Built-in rules...** (next to "Choose tagging rules...", only shown when
relevant to the current source) opens a picker listing every built-in rule
from both packs — AUL and EVTX in their own sections, each rule a checkbox
(hover one for its full match condition, tag, and description), plus
**Select all**/**Select none** per section. This is exact, per-rule control,
not just a whole-pack on/off switch: enable only the three or four AUL rules
you actually care about for this case, say. See
[rules-reference.md](rules-reference.md) for the same information as a
static, browsable table (generated from the same `rules/examples/*.toml`
files this picker reads).

Beyond the built-in packs, every `*.toml` file directly in the configured
[rules directory](#settings) — your own personal rule collection, see
Settings — loads automatically, no selection needed. **Choose tagging rules
(TOML, optional)...** additionally lets you pick specific files from
anywhere else (it opens in the rules directory by default); doing so
replaces the current selection rather than adding to it, so it's "pick your
whole set" rather than "add one more". Either way, the count next to the
button ("N rule file(s) selected") reflects what's actually active,
auto-loaded and manually picked alike.

Three modes:

- **Import-time**: rules selected before clicking **Load** are applied
  automatically as entries are inserted.
- **Re-tag**: click **Re-tag now** to re-evaluate the currently selected rules
  against *everything* already loaded. This **replaces** all import-time tags —
  it's a full recompute, not an incremental patch, so a changed or removed rule
  never leaves a stale tag behind.
- **Ad-hoc / analyst tags**: query-time evaluation exists at the engine level
  with no dedicated UI yet. Manual, per-entry tags (`analyst_tags`) do have a
  UI — see below.

**Right-click a row** in the timeline for these actions:

- **Copy message** — copies just the `message` field to the clipboard.
- **Copy whole event as text** — copies timestamp, level, tags, message, and
  `raw` (the full original record/line) as a plain-text block.
- **View raw/fields...** — same data as "Copy whole event as text", shown in
  a read-only, scrollable, selectable window instead of only going to the
  clipboard: `raw` (the full original record/line) and `fields` (the
  source-specific JSON — for AUL/EVTX/journald this largely overlaps `raw`,
  but for a `text_config` source it's genuinely different: `raw` is the
  literal original line, `fields` is what the regex captured out of it).
- **Filter by...** — a submenu listing whichever of the clicked row's
  Sourcetype/Host/Process/Event ID/Subsystem/Category are actually
  populated for that row (empty ones don't show up); picking one adds (or
  replaces) an exact-match filter for that value, shown as a removable
  chip in the **Active filters** row under the search box. This is
  row-level, not cell-level — the submenu offers every populated field on
  the row you right-clicked, not only whichever column happened to be
  under the pointer.
- **Show context around this event** (± 1 / 5 / 15 / 60 min) — replaces the
  search box with an `after=.../before=...` window centered on the clicked
  row, so you see everything around it rather than only whatever the
  previous filter matched.
- **Tag this event...** — a manual tag on just that one entry, stored in the
  session's `analyst_tags` (SQLite), separate from rule-produced tags because
  it isn't rule-based. Pick an already-used tag from the dropdown or choose
  "New tag...".
- **Tag all matching (advanced)...** — tags every entry that matches a
  condition, with a live preview of how many entries currently match before
  you commit. Choose what to match on via the radio buttons at the top:
  **Message contains** (a substring, prefilled from the clicked row,
  editable) or an exact match on one of the row's own populated fields —
  Sourcetype/Host/Process/Event ID/Subsystem/Category, the same set "Filter
  by..." offers. Switching the radio button reloads the text field with that
  field's own value. Choosing an existing tag that's produced by exactly one
  currently-loaded rule file offers to extend that rule's pattern list
  instead of creating a new one — but only for a **Message contains**
  condition; a field condition always creates a fresh rule file, since the
  tagging engine has no OR-list support for exact-match fields the way
  `message_contains` has. A brand-new tag (or one with no single unambiguous
  owning rule) creates a new rule file under the [rules
  directory](#settings) and asks you to name it. Applying either path
  re-tags immediately, same as clicking **Re-tag now**.

Both the Tags column and the tag picker in these dialogs combine tags from
both `import_tags` and `analyst_tags` — one vocabulary regardless of which
table a tag happened to come from.

The timeline table has a **Tags** column listing every tag on that entry, and
the **Level** column is colored — both from the same 8-color categorical
palette. The color is a deterministic hash of the value, not
assignment-order-based: the same level/tag string always gets the same color,
in this session and every future one, rather than shifting depending on what
order things were loaded in.

### Notes

**Notes...** (also in the row context menu) opens a dialog listing every note
on that event, with Edit/Delete per note and a field to add another —
independent of tags entirely: a note needs no tag to exist, and a tag needs no
note. Stored in the session's `event_notes` table (SQLite), separate from
`analyst_tags`' own unused `note` column for the same reason.

Any row with at least one note shows a 📝 marker in the Tags column (hover for
the full text) regardless of whether the **Notes** column itself is enabled —
that column is opt-in via the **Columns** picker, same as
Sourcetype/Host/Process/Event ID/Subsystem/Category, and shows every note on
each row directly in the table (joined with " | "; hover for one-per-line).

## Search

The **Columns** picker (above the timeline table) toggles Sourcetype, Host,
Process, Event ID, Subsystem, Category, and Notes on or off — Timestamp,
Level, Source, Tags, and Message are always shown. Drag a column header to
reorder it.

The search box (top of the timeline) uses a small, Splunk-inspired query
language. Filters apply live as you type — there's no separate "search" button.

- Bare words / `"quoted phrases"` — substring match against `message` OR `raw`.
- `field=value` / `field:value` — exact match, except `source`/`message`/`raw`
  (substring, like bare-word search — a full path is rarely worth typing out
  in full). Recognized fields: `level`, `sourcetype` (the format —
  `aul`/`evtx`/`journald`/...), `source` (the evidence file's path), `tag`
  (from tagging rules), `message`, `raw`, and every column the **Columns**
  picker can show — `event_id`, `host`, `process`, `subsystem`, `category`.
  Each of those is empty/no-match for whichever sourcetypes don't populate
  that column in the first place (e.g. `event_id=` only ever matches EVTX) —
  see [field-extraction.md](field-extraction.md) for exactly which
  sourcetype populates which. A value with spaces (a process name, a
  hostname) needs quoting right after the `=`, e.g. `process="Windows
  Explorer"` — otherwise the space splits it into two tokens. The row
  context menu's **Filter by...** entry always quotes correctly for you.
- `field!=value` — negated exact match; shorthand for `NOT field=value`
  (identical result, just without the extra word).
- `field~value` — regex match on that field instead of exact/substring.
- `tag=*` — has at least one tag, whichever. Combined with negation,
  `NOT tag=*` means "untagged" — there's no separate keyword for it.
- `source_id=<id>` — exact match against one specific loaded source (not its
  path — the internal id assigned to that one load). Not meant for hand-typing
  (see the **Sources** row below); documented here because it's a real,
  functioning grammar field like any other, not UI-only magic.
- `after=<timestamp>` / `before=<timestamp>` — bounds on `timestamp_utc`
  (UTC, always). Accepts `2026-07-29T10:00:00`, `2026-07-29 10:00:00` (quote
  it — the space would otherwise split into two tokens), with or without
  seconds or fractional seconds, or a bare date (`2026-07-29`, meaning
  midnight). A timestamp that doesn't parse in any of these shapes matches
  nothing, rather than erroring.
- `NOT term` or `-term` — negation.
- Terms are implicitly ANDed; use `OR` explicitly. There's no parentheses or
  operator precedence yet — everything evaluates strictly left to right, in the
  order you typed it. This means several terms joined by bare `OR` only group
  correctly if nothing else in the query is `AND`-ing against them — see the
  next paragraph for how the buttons avoid this trap.

Example: `sourcetype=evtx tag=auth_failure NOT level=INFO "login"`

The **Level**, **Tag**, and **Sources** dropdowns under the search box are a
shortcut: each is a button (e.g. `Level`, or `Level (2)` once something's
selected) that opens a scrollable checklist instead of always showing every
value as its own button — with a rule pack's worth of tags (AUL's built-in
pack alone is 33) or many loaded sources, a permanently-visible row would
otherwise push the timeline further down the screen with every new value.
Each value's checkbox is followed by a count in parentheses, e.g.
`wifi_status (1234)` — a note at the top of every dropdown makes clear
these are for the *whole loaded timeline*, not how many currently match
your search: they're computed once (after a load or **Re-tag now**), not
recomputed on every keystroke, so they'd otherwise be easy to misread as a
live, filter-relative number. "Untagged" doesn't get a count next to it —
nothing computes that one yet.

Every dropdown offers the same two actions, consistently: a small **only**
button next to each value — narrows to just that one value, deselecting
everything else in that field (for Tag, Untagged too) — and a **Show all**
button, pinned below the scrollable list rather than as its last entry, so
it stays reachable without scrolling all the way down first. For Level/Tag,
"Show all" clears the whole selection back to no filter on that field at
all; for Sources, see below.

Checking a box toggles that value in and out of the search box; the list
itself is populated from whatever level/tag values are actually present in
the loaded data (AUL's level names and a text log's ERROR/WARN/INFO have
nothing in common, and which tags exist depends entirely on which rules were
run, so neither list is ever hardcoded). The Tag dropdown only appears once
at least one tagging rule has produced a tag — either from import-time
tagging during Load, or after clicking **Re-tag now**.

Checking several boxes in Level/Tag means "match any of these", not "match
all of these" — but since the grammar above has no parentheses, that can't be
expressed as several `field=value` terms joined by `OR` once anything else in
the query is `AND`-ing against them. Instead, checking boxes writes a single
regex-alternation term, e.g. selecting two tags produces
`tag~^(?:wifi_status|screen_lock_state)$` — one term, so it always combines
correctly with the rest of the query regardless of order. An **Untagged**
checkbox at the bottom of the Tag dropdown toggles `NOT tag=*` for the same
reason it isn't just another value: "no tag" isn't a value that could appear
in the alternation.

**Sources** appears once at least one source is loaded, and works the
opposite way on purpose: it's an *exclusion* list, not an inclusion one.
Every source starts checked (visible, no filter applied at all), and
unchecking one hides that source's rows — the source stays loaded, nothing
is unloaded or re-parsed, it just adds a `NOT source_id=<id>` term. Each
source's label is colour-coded the same way as the Level/Tags columns.
Hiding several sources at once needs no special-casing the way Tag/Untagged
did: each hidden source is its own independent `NOT` term, and plain
`AND`-ing those together already means exactly "not any of these",
regardless of where in the query they end up. Each row also has an **only**
button — hides every *other* loaded source in one click, for isolating a
single source's timeline instead of unchecking everything else by hand —
and **Show all** clears every hidden-source term at once.

A **Time range** button opens a small window offering `after=`/`before=`
via a calendar and a clock instead of typing an ISO timestamp by hand —
check **After** and/or **Before** (either alone is fine), pick a date,
adjust the hour/minute/second spinners next to it if needed (click-drag or
click-to-type, like any other numeric field), then **Apply** (which also
closes the window; so does **Clear**). Defaults to midnight for After and
the last second of the day for Before — "the whole day" is the common
case — freely adjustable from there. A separate window, not a dropdown
like Level/Tag/Sources: the calendar itself opens its own floating popup,
and nesting that inside a dropdown's popup made the outer one close the
instant you tried to click a date — clicking the calendar read as "clicked
outside the dropdown" to the dropdown itself. Both bounds always write the
explicit `<date>T<hour>:<minute>:<second>` form, never a bare date — a
bare date means literal midnight, which as a *before* bound with the time
left untouched would otherwise silently exclude the rest of that day.
**Clear** resets both bounds — there's no **only**/**Show all** pair here
the way the checkbox-list dropdowns have one, since a date range isn't a
list of discrete values to narrow to one of or reset to "every value".

An **Active filters** row appears under the search box once at least one
Sourcetype/Host/Process/Event ID/Subsystem/Category filter is set — see the
row context menu's **Filter by...** entry below for how they get set.
Each shows as a removable chip (`Host = DESKTOP-1 ✕`); click one to remove
just that filter, or **Clear all** to remove every one at once (shown once
there's more than one). Unlike Level/Tag/Sources, there's no dedicated
dropdown for these six fields — they're set from the row you're looking
at, not picked from a list of every possible value up front.

## Settings

**File > Settings...** covers where Peach writes things, and how a folder
load parallelizes:

- **Sessions directory** — where new sessions' `.duckdb`/`.sqlite` files are
  created (see [Sessions](#sessions) below). Defaults to the OS-standard
  per-user data directory; only affects sessions created from now on.
- **Rules directory** — where **Tag all matching (advanced)...** (see
  [Tagging](#tagging) above) writes new rule files, and where Peach looks
  for rules to load automatically. Defaults to the OS-standard per-user data
  directory too, but this one is meant to be pointed elsewhere: at a folder
  you keep under your own git repo, for example, to build up a personal
  rule collection over time, kept separate from `rules/examples/` in the
  Peach repo itself (a read-only reference library, not a place to write
  into). Every `*.toml` file directly in this folder (not subfolders) loads
  automatically on startup and shows up in the "N rule file(s) selected"
  count, the same way the built-in AUL/EVTX packs always apply — a rule
  created in a previous session doesn't need re-selecting by hand every
  time. Changing this and clicking **Save** re-scans the new folder
  immediately, replacing whatever rule files are currently selected
  (including any picked from elsewhere via **Choose tagging rules...**,
  which itself opens in this folder by default).
- **Parse threads for folder loads** — worker threads for parsing a
  multi-file folder load (EVTX/journald/Text) in parallel; automatic by
  default. Irrelevant for AUL or a single-file load — both are always
  exactly one parse unit, nothing to spread across threads.

Both directory settings always show the effective path — prefixed with
"(default)" when no override is set — plus **Choose...** to pick a folder,
**Reset to default** to clear an override, and **Open folder** to reveal it
in the OS file manager (creating it first if it doesn't exist yet).

## Sessions

A session is a pair of files (`<id>.duckdb` for the parsed timeline, `<id>.sqlite`
for tags and search state) created automatically when Peach starts — nothing to
set up. Every successful load and every search-box change is saved into the
current session immediately; there's no separate "save" action.

Peach does **not** reopen your last session automatically. Click **Manage
sessions...** (File menu, or next to the "Session: ..." label in the controls
panel — same dialog either way) and **Open** one to switch to it — this reads
the already-parsed `.duckdb` directly, so it works even if the original
evidence file is no longer reachable, and nothing gets re-parsed.

Session files live in the OS-standard per-user data directory (not yet
user-configurable): `~/.local/share/peach/sessions/` on Linux, similar
platform-appropriate locations on macOS/Windows.

**Manage sessions...** lists every session found there, each with Open/
Rename/Delete. **Rename...** sets a display name shown instead of the raw
`session-YYYYMMDD-HHMMSS` id everywhere a session is listed (including the
"Session: ..." label once it's the one open) — the underlying `.duckdb`/
`.sqlite` files and the id itself never change, only that label, so renaming
never risks breaking anything path-based. Works on the currently-open
session too, unlike Delete.

There's deliberately no separate "Load session..." file picker anymore: a
native file dialog can only show real filenames, and once a session has a
display name that stopped being a useful way to find one again — "Manage
sessions..." is the only path now, so the friendly name is always what you
see.

## Activity Log

**View → Activity Log...** shows every load and re-tag this session has run —
what was loaded, when it started/finished, how many entries were inserted
and tags applied, and which files (if any) were skipped and why. Recorded on
both success *and* failure: a failed load shows up here with its error, not
just as a transient message that's gone once you dismiss it. Persisted in
the session's `.sqlite` (same file as tags/notes), so it survives closing
and reopening Peach — the point is a durable record of what actually
happened to the evidence, not a live status readout.

## Export

**File > Export (current filter)...** exports exactly what the timeline is
showing right now — clear the search box first to export everything
loaded. Pick a `.csv` or `.json` destination (either extension works;
anything else defaults to CSV). Streamed in 5,000-row chunks with a
progress readout, so an export of millions of rows doesn't need to hold
the whole result in memory first.

Each exported row has the same normalized columns the timeline table shows
— timestamp, level, source path, sourcetype, host, process, event ID,
subsystem, category, message — plus tags and notes joined into single
fields (`;`- and ` | `-separated respectively, since neither CSV nor a flat
JSON row has a native list type). **`raw` (the original record/line) is
not included** — export is a filtered, normalized view for sharing or
reporting, not a substitute for the original evidence file, which stays
wherever it was loaded from.

## View menu

**View > Theme** switches the window chrome: System default (follows the
OS light/dark setting), Light, Dark, Geek (a phosphor-green terminal look),
or Rainbow (continuously hue-cycling, animated). Persisted across restarts.
**View > Activity Log...** is covered above.

## Command line

```sh
peach --add-source <path> [--add-source <path> ...] [--cleanup-dir <path> ...] [--ephemeral-session]
```

`--add-source` pre-fills the source picker (sourcetype guessed only as
directory-implies-AUL, never a text-format guess) — you still confirm and click
**Load** yourself. Multiple `--add-source` flags queue up; after each load
completes, the next one pre-fills automatically. `--cleanup-dir` deletes a
directory when Peach closes, but only if it's actually under the OS temp
directory — a safety net, not something to rely on for arbitrary paths.

`--ephemeral-session` skips session persistence for the run entirely: instead of
the usual persistent sessions directory, the session's `.duckdb`/`.sqlite` live in
a one-off temp directory that's removed on close no matter what it holds — use
this when the source itself came from a temp extraction or a decrypted copy, so
Peach doesn't leave a second, unencrypted copy of that data sitting around after
you're done. The session won't show up in "Manage sessions..." either, since it
never lived in the persistent sessions directory to begin with.
