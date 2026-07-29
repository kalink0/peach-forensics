# Peach User Guide

This covers how to operate Peach today. For what source types are actually
supported, see [supported-sources.md](supported-sources.md) — this guide assumes
you already know which sourcetype you're loading.

## Loading a source

1. Pick a **Sourcetype**: `AUL (.logarchive)` or `Text (config-based)`.
2. Click the picker button:
   - AUL expects a folder — the `.logarchive` bundle itself (it contains
     `Persist`/`Special`/`Signpost`/`HighVolume` subfolders plus `dsc`/`uuidtext`/
     `timesync` reference data). One `.logarchive` becomes one source.
   - Text expects a single file, plus a **parser config** (TOML) — see below.
3. Optionally choose one or more **tagging rules** (TOML, multi-select) — see
   [Tagging](#tagging).
4. Click **Load**. Loading runs in the background so the UI stays responsive; a
   large AUL source can take a while and insert millions of rows.

Peach never auto-detects a format — you always confirm the sourcetype yourself.

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

Three modes:

- **Import-time**: rules selected before clicking **Load** are applied
  automatically as entries are inserted.
- **Re-tag**: click **Re-tag now** to re-evaluate the currently selected rules
  against *everything* already loaded. This **replaces** all import-time tags —
  it's a full recompute, not an incremental patch, so a changed or removed rule
  never leaves a stale tag behind.
- **Ad-hoc / analyst tags**: query-time evaluation and manually-set per-entry tags
  exist at the engine/database level but have no dedicated UI yet.

## Search

The search box (top of the timeline) uses a small, Splunk-inspired query
language. Filters apply live as you type — there's no separate "search" button.

- Bare words / `"quoted phrases"` — substring match against `message` OR `raw`.
- `field=value` / `field:value` — exact match. Recognized fields: `level`,
  `source` (sourcetype), `tag` (from tagging rules), `message`, `raw`.
- `field~value` — regex match on that field instead of exact/substring.
- `NOT term` or `-term` — negation.
- Terms are implicitly ANDed; use `OR` explicitly. There's no parentheses or
  operator precedence yet — everything evaluates strictly left to right, in the
  order you typed it.

Example: `source=evtx tag=auth_failure NOT level=INFO "login"`

The **Level** buttons under the search box are a shortcut: clicking one just
toggles a `level=X` term in the search box, populated from whatever level values
are actually present in the loaded data (AUL's level names and a text log's
ERROR/WARN/INFO have nothing in common, so this list is never hardcoded).

## Sessions

A session is a pair of files (`<id>.duckdb` for the parsed timeline, `<id>.sqlite`
for tags and search state) created automatically when Peach starts — nothing to
set up. Every successful load and every search-box change is saved into the
current session immediately; there's no separate "save" action.

Peach does **not** reopen your last session automatically. Click **Load
session...** and pick a `.sqlite` file to switch to it — this reads the
already-parsed `.duckdb` directly, so it works even if the original evidence file
is no longer reachable, and nothing gets re-parsed.

Session files live in the OS-standard per-user data directory (not yet
user-configurable): `~/.local/share/peach/sessions/` on Linux, similar
platform-appropriate locations on macOS/Windows.

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
