# Supported Source Types

Kept intentionally short and current — update this alongside any parser change
so it never drifts from what's actually implemented.

## Implemented

### AUL (Apple Unified Log)

Wraps the `macos-unifiedlogs` crate. Two source layouts are recognized —
selecting either just works, no manual restructuring needed:

- A flattened `.logarchive` directory as produced by `log collect`
  (`Persist`/`Special`/`Signpost`/`HighVolume`/`dsc`/uuidtext hex directories
  all directly under one folder).
- A raw filesystem extraction (the common case for mobile acquisitions), where
  the tracev3 data (`diagnostics/`) and the uuidtext/dsc string-resolution data
  (`uuidtext/`) sit as two separate directory trees, mirroring their layout on
  the live device. Select either the `diagnostics` folder itself (with
  `uuidtext` next to it as a sibling) or their common parent folder — both are
  detected automatically. Selecting `diagnostics` alone, with no `uuidtext`
  anywhere nearby, fails fast with an explicit error rather than silently
  producing a timeline where almost every message is an unresolved
  placeholder (which is what happened before this detection existed — a
  219 MB real-device export came back ~98% unresolved, because
  `LogarchiveProvider`'s string-lookup paths assume the flattened bundle
  layout and silently look in the wrong place for a raw extraction's split
  layout).
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
- **Known limitation:** if the device's `uuidtext`/`dsc` reference data has
  moved on since a log entry was written (app updated/removed, OS's shared
  cache regenerated), that entry's format string is gone for good — no
  extraction can recover it. Expect a meaningful fraction of unresolved
  messages on any real device history, independent of the layout-detection
  above.
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

### journald (systemd Journal, `.journal`)

Single `.journal` file. Hand-rolled binary reader — see
[src/parsers/journald.rs](../src/parsers/journald.rs) for why no external crate
is used (the only pure-Rust cross-platform option is GPL-3.0-or-later, which
would pull peach's Apache-2.0 binary under GPL copyleft on static linking; the
alternative binds against `libsystemd`, Linux-only).

- `level` is the raw `PRIORITY` field verbatim (syslog priority digit
  `"0"`-`"7"`) — not remapped, same convention as EVTX/AUL.
- `message` is the `MESSAGE` field — unlike EVTX, journald stores literal
  message text, so this is populated directly.
- `raw`/`fields` hold every field on the entry, including the synthesized
  `__REALTIME_TIMESTAMP`/`__MONOTONIC_TIMESTAMP`/`__SEQNUM` fields (same
  naming as real sd-journal, which also derives these from the entry header
  rather than storing them).
- Entries are found by scanning the file's object arena sequentially rather
  than following the hash-table/entry-array chains real `libsystemd` uses for
  keyed lookups — simpler, and more robust against a journal whose index
  structures are partially corrupted.
- **Known limitations:**
  - The "compact" entry format (systemd 254+) is not implemented; such files
    fail to parse with an explicit error rather than being misread.
  - Only LZ4-compressed field values are decompressed (journald's default).
    XZ/ZSTD-compressed fields stay visible with a placeholder value noting the
    unsupported algorithm, rather than being silently dropped.
  - Only little-endian journal files are supported (universal on modern
    Linux).
  - A single corrupt/truncated object aborts the whole parse, same as EVTX.
- No config-driven field-mapping, like AUL/EVTX.

## Explicitly out of scope

USN Journal, FSEvents, encrypted containers, and automatic format detection as a
requirement — the analyst always chooses the sourcetype.
