# Supported Source Types

Kept intentionally short and current — update this alongside any parser change
so it never drifts from what's actually implemented.

## Implemented

### AUL (Apple Unified Log, `.logarchive`)

Whole `.logarchive` directory as produced by `log collect` or extracted from a
device. Wraps the `macos-unifiedlogs` crate.

- `level` is the raw `LogType` variant name (`Error`, `Info`,
  `ProcessSignpostStart`, …) — not remapped into an INFO/WARN/ERROR scheme.
- `raw` and `fields` both hold the complete extracted record as JSON — there's no
  single "original line" for a binary source, so the full structured extraction
  is the most faithful equivalent.
- **Known limitation:** entries whose format string lives in a *different*
  `.tracev3` file's oversize data than the entry itself get only a single-pass
  resolution attempt (no cross-file second pass yet). Unresolved ones still show
  up, with an explicit "Failed to get string message..." message rather than
  being dropped.
- No config-driven field-mapping — the mapping above is fixed, not
  TOML-configurable like the text parser.

### Text (TOML-configured)

Any line-oriented text log describable with a regex + timestamp format — syslog,
Apache/nginx access logs, logcat, etc. One TOML config = one sourcetype. See
[user-guide.md](user-guide.md#text-parser-configs) for the config format.

### EVTX (Windows Event Log, `.evtx`)

Single `.evtx` file. Wraps the `evtx` crate.

- `level` is the raw `Event.System.Level` JSON value verbatim (usually a small
  integer per the Windows Event Schema, e.g. 2=Error, 3=Warning,
  4=Informational) — not remapped, same reasoning as AUL's `LogType`.
- `message` is always empty: the crate doesn't render human-readable event text
  (that needs the OS's message-resource DLLs/templates, which it deliberately
  doesn't ship). `EventData` is preserved in full in `raw`/`fields` instead.
- No config-driven field-mapping, like AUL.
- A single unparseable record aborts the whole parse (the crate's per-record
  error carries no partial data — not even a timestamp — so there's nothing to
  show as a visible-but-broken entry the way AUL's oversize failures work).

## Planned, not yet implemented

- **journald** (systemd Journal, binary format) — not started.

## Explicitly out of scope

USN Journal, FSEvents, encrypted containers, and automatic format detection as a
requirement — the analyst always chooses the sourcetype.
