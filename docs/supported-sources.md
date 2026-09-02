# Supported Source Types

Kept intentionally short and current — update this alongside any parser change
so it never drifts from what's actually implemented. For the extra
Host/Process/Event ID/Subsystem/Category columns the timeline view pulls out
of `fields` on top of the core mapping described here, see
[field-extraction.md](field-extraction.md).

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
  4=Informational) — not remapped, same reasoning as AUL's `LogType`. The
  timeline view's Level column appends the standard name for display
  (`"2 (Error)"`) without touching the stored value — see
  [field-extraction.md](field-extraction.md).
- `message` is `Event.RenderingInfo.Message` when the file has it.
  `RenderingInfo` is an *optional* part of the Windows Event schema
  (`RenderingInfoType`, `minOccurs="0"`) — present when the file was
  produced by something that rendered the event before writing it out (e.g.
  Windows Event Forwarding's collector side), absent for a plain live
  `winevt\Logs\*.evtx` read directly, since real rendering needs the source
  machine's message-resource DLLs/templates, which this crate deliberately
  doesn't ship or emulate.
  - When `RenderingInfo.Message` is absent, Peach falls back to a built-in
    message template for a curated set of common Security-auditing events
    (logons, process creation, service installs, account/group management,
    audit log clearing, PowerShell ScriptBlock logging — see
    [field-extraction.md](field-extraction.md#message-templates-evtx) for
    the exact list and how placeholders resolve). A template-rendered
    message is Peach's own reconstruction from `EventData`, not text the
    source embedded, so it's always prefixed `[Peach] ` — never mistake it
    for something Windows itself wrote. Anything outside that curated set
    still leaves `message` empty, same as before this existed.
  - `EventData` is preserved in full in `raw`/`fields` regardless, so
    nothing is ever lost when `message` is empty or template-derived.
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
- Both the "regular" and "compact" (`HEADER_INCOMPATIBLE_COMPACT`, systemd
  254+ — the default on every current distro) entry formats are implemented.
- **Known limitations:**
  - Only LZ4-compressed field values are decompressed (journald's default).
    XZ/ZSTD-compressed fields stay visible with a placeholder value noting the
    unsupported algorithm, rather than being silently dropped.
  - Only little-endian journal files are supported (universal on modern
    Linux).
  - A single corrupt/truncated object aborts the whole parse, same as EVTX.
- No config-driven field-mapping, like AUL/EVTX.

### Android Intrusion Log (Advanced Protection Mode)

A directory (AndroidQF's own `intrusion-logs/` output layout — searched
recursively for `.txt` files), same "one directory = one source" shape as
AUL. Reads Android's **Intrusion Logging** feature (Android 16+, Advanced
Protection Mode, built by Google with [Amnesty International's Security
Lab](https://securitylab.amnesty.org/latest/2026/05/android-intrusion-logging-as-a-new-source-of-data-for-consensual-forensic-analysis/)
specifically for spyware/"consensual" forensic analysis) — newline-delimited
JSON, one event per line, verified directly against the [Mobile
Verification Toolkit](https://github.com/mvt-project/mvt)'s own
`intrusion_logs` module rather than guessed from documentation.

- **Out of scope, deliberately:** the logs themselves are collected once
  daily on-device, end-to-end encrypted, and stored in the user's Google
  account. Decrypting and exporting them is a cloud/account-credential
  operation, not a local read-only file, so it's handled entirely by
  [AndroidQF](https://github.com/mvt-project/androidqf) or MVT during
  acquisition, before Peach ever sees anything. This parser starts from an
  already-extracted local `intrusion-logs/` directory.
- Three event types, each wrapped under its own top-level JSON key per
  line: `dns_event`, `connect_event`, `security_event` (the last nesting
  one level deeper — a tag naming the specific event, e.g.
  `keyguard_dismiss_auth_attempt`, alongside that event's own detail
  object — see [rules-reference.md](rules-reference.md#android-intrusion-log-rules)
  for the full tag catalogue, one row per tag).
- `event_time` is Unix epoch, but the **unit differs by event type** —
  milliseconds for `dns_event`/`connect_event`, nanoseconds for
  `security_event` — confirmed against MVT's own conversion code, not
  assumed consistent across the three.
- `level` is always empty — Android's own schema carries no severity for
  any of these three event types.
- `message` is a reconstructed, human-readable one-line summary (not
  present verbatim in the source JSON) — always prefixed `[Peach] `, same
  convention as EVTX's message templates, to mark it as derived rather
  than source text.
- `fields` preserves the original JSON structure exactly as found (nothing
  flattened away), plus two derived, flat lookup keys: `event_type` (the
  outer key) and, for `security_event` specifically, `security_event_tag`
  (the inner key) — so a tagging rule can match
  `security_event_tag = "..."` directly.
- An event whose one-and-only top-level key isn't one of the three known
  types is not silently dropped or guessed at (Android's own docs describe
  this feature as one still being expanded) — it's treated as an
  unparseable record, same as any other malformed line
  (`skip_bad_records` applies here too).
- No config-driven field-mapping, like AUL/EVTX/journald.

## Explicitly out of scope

USN Journal, FSEvents, encrypted containers, and automatic format detection as a
requirement — the analyst always chooses the sourcetype.
