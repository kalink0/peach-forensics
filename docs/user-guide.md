# Peach User Guide

This covers how to operate Peach today. For what source types are actually
supported, see [supported-sources.md](supported-sources.md) — this guide assumes
you already know which sourcetype you're loading.

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

Unlike other rule files (which the analyst selects explicitly via "Choose
tagging rules..."), this pack ships **embedded in the binary itself**
(`build.rs` bundles every `rules/examples/aul_*.toml` file at compile time —
see `src/tagging/builtin.rs`) and is applied automatically on every AUL
load and re-tag by default — no file to locate or select, works the same in
a release build with no repo nearby. The "Built-in AUL pattern-of-life
rules" checkbox next to "Choose tagging rules..." turns this off if you want
to import/re-tag without it; every rule in the pack matches
`sourcetype = "aul"` on its own, so leaving it on never tags non-AUL rows.

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
- **Show context around this event** (± 1 / 5 / 15 / 60 min) — replaces the
  search box with an `after=.../before=...` window centered on the clicked
  row, so you see everything around it rather than only whatever the
  previous filter matched.
- **Tag this event...** — a manual tag on just that one entry, stored in the
  session's `analyst_tags` (SQLite), separate from rule-produced tags because
  it isn't rule-based. Pick an already-used tag from the dropdown or choose
  "New tag...".
- **Tag all matching (advanced)...** — tags every entry whose message
  contains a pattern (prefilled from the clicked row, editable), with a live
  preview of how many entries currently match before you commit. Choosing an
  existing tag that's produced by exactly one currently-loaded rule file
  offers to extend that rule's pattern list instead of creating a new one; a
  brand-new tag (or one with no single unambiguous owning rule) creates a new
  rule file under the per-user rules directory and asks you to name it.
  Applying either path re-tags immediately, same as clicking **Re-tag now**.

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

The search box (top of the timeline) uses a small, Splunk-inspired query
language. Filters apply live as you type — there's no separate "search" button.

- Bare words / `"quoted phrases"` — substring match against `message` OR `raw`.
- `field=value` / `field:value` — exact match. Recognized fields: `level`,
  `source` (sourcetype), `tag` (from tagging rules), `message`, `raw`,
  and every column the **Columns** picker can show — `event_id`, `host`,
  `process`, `subsystem`, `category`. Each of those is empty/no-match for
  whichever sourcetypes don't populate that column in the first place (e.g.
  `event_id=` only ever matches EVTX) — see
  [field-extraction.md](field-extraction.md) for exactly which sourcetype
  populates which.
- `field!=value` — negated exact match; shorthand for `NOT field=value`
  (identical result, just without the extra word).
- `field~value` — regex match on that field instead of exact/substring.
- `tag=*` — has at least one tag, whichever. Combined with negation,
  `NOT tag=*` means "untagged" — there's no separate keyword for it.
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

Example: `source=evtx tag=auth_failure NOT level=INFO "login"`

The **Level** and **Tag** button rows under the search box are a shortcut:
clicking one toggles that value in and out of the search box, populated from
whatever level/tag values are actually present in the loaded data (AUL's
level names and a text log's ERROR/WARN/INFO have nothing in common, and
which tags exist depends entirely on which rules were run, so neither list
is ever hardcoded). The Tag row only appears once at least one tagging rule
has produced a tag — either from import-time tagging during Load, or after
clicking **Re-tag now**.

Selecting several buttons in the same row means "match any of these", not
"match all of these" — but since the grammar above has no parentheses, that
can't be expressed as several `field=value` terms joined by `OR` once
anything else in the query is `AND`-ing against them. Instead, the buttons
write a single regex-alternation term, e.g. selecting two tags produces
`tag~^(?:wifi_status|screen_lock_state)$` — one term, so it always combines
correctly with the rest of the query regardless of order. The **Untagged**
button next to the Tag row toggles `NOT tag=*` for the same reason it isn't
just another value button: "no tag" isn't a value that could appear in the
alternation.

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

## Command line

```sh
peach --add-source <path> [--add-source <path> ...] [--cleanup-dir <path> ...]
```

`--add-source` pre-fills the source picker (sourcetype guessed only as
directory-implies-AUL, never a text-format guess) — you still confirm and click
**Load** yourself. Multiple `--add-source` flags queue up; after each load
completes, the next one pre-fills automatically. `--cleanup-dir` deletes a
directory when Peach closes, but only if it's actually under the OS temp
directory — a safety net, not something to rely on for arbitrary paths.
