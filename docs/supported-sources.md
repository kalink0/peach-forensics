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
    message template for a curated set of common events (Security-auditing
    logons, process creation, service installs, account/group management,
    audit log clearing, PowerShell ScriptBlock logging, Remote Desktop /
    Terminal Services sessions, kernel boot/shutdown — see
    [field-extraction.md](field-extraction.md#message-templates-evtx) for
    the exact list and how placeholders resolve). A template-rendered
    message is Peach's own reconstruction from the record's `EventData` or
    `UserData`, not text the
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
JSON, one event per line, verified directly against Amnesty's own [Mobile
Verification Toolkit](https://github.com/mvt-project/mvt) `intrusion_logs`
module rather than guessed from documentation.

- **Out of scope, deliberately:** the logs themselves are collected once
  daily on-device, end-to-end encrypted, and stored in the user's Google
  account. Decrypting and exporting them is a cloud/account-credential
  operation, not a local read-only file, so it's handled entirely by
  [AndroidQF](https://github.com/mvt-project/androidqf), MVT, or
  [ALEX](https://github.com/prosch88/ALEX) (a dedicated Android
  acquisition tool) during acquisition, before Peach ever sees anything.
  This parser starts from an already-extracted local `intrusion-logs/`
  directory.
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

### Biome (SEGB)

A `.../biome/streams` directory — Apple's pattern-of-life logging system
(`private/var/db/biome/streams` on macOS; the per-app `Library/Biome/streams`
location on iOS is deliberately out of scope, see
[docs/design/biome-rule-pack-research.md](design/biome-rule-pack-research.md)).
Unlike AUL/Android Intrusion Log, the whole `streams/` folder is **not**
one atomic source — each individual SEGB file (under a
`<StreamName>/local` or `/remote` directory) becomes its own independent
source, the same "one file = one source" model EVTX/journald use. There's
no cross-file resolution need for Biome the way AUL's `dsc`/`uuidtext`
lookups have, so nothing is lost by keeping every file independent, and a
lot is gained: one bad or unsupported file only takes down that one
source, the Source column shows each record's actual originating file
directly, and a multi-file load runs in parallel. The whole `streams/`
folder is still handed to Peach as one folder pick (including when
handed off from crush's "Send Biome Streams to Peach…" action, or picked
directly via **Choose biome/streams folder...**) and walked recursively
to discover every candidate file — no manual restructuring needed.

- Each stream lives under `<visibility>/<StreamName>/local|remote/<file>` —
  the stream name is derived purely from this path shape (the directory
  named after the stream, one level above a `local`/`remote` leaf), never
  from file content, so it works identically for streams whose semantics
  aren't documented anywhere. Every stream directory also carries `lock`/
  `metadata` housekeeping files directly under `<StreamName>/` (normal
  Biome runtime bookkeeping, never log data) — these are excluded
  structurally (no `local`/`remote` parent) before ever being opened,
  never even counted as a skipped source.
- Each file is a **SEGB** envelope (Segmented Biome) wrapping one or more
  records. **Only SEGB v2 is currently implemented** — the format variant
  that has an actively-maintained upstream reference implementation
  ([`cclgroupltd/ccl-segb`](https://github.com/cclgroupltd/ccl-segb), MIT)
  with a hardened, tested v2 reader; SEGB v1 predates that hardening pass
  and has no equivalent fixture/test to verify a Rust port against. A v1
  file is detected by its signature (so it's never silently misread as v2
  or silently skipped) and surfaces a clear "SEGB v1 not yet supported"
  error per file instead. See
  [docs/design/biome-rule-pack-research.md](design/biome-rule-pack-research.md)
  for the full rationale and what would need to change to add v1 support
  later.
- Each record's protobuf payload is decoded schema-less (no `.proto`
  definitions exist for these streams) — the output is a JSON object keyed
  by field number (`"1"`, `"2"`, …), with a length-delimited field's bytes
  exposed as UTF-8 (`utf8`), a best-effort recursive nested-message
  reinterpretation (`nested`, only when that reparse cleanly consumes every
  byte), and raw hex (`hex`) side by side — nothing is ever discarded in
  favor of one interpretation. A growing set of well-known streams have
  documented field semantics (sourced from iLEAPP's `biome*.py` artifact
  modules) exposed as normalized tagging keys: `ScreenTime.AppUsage`,
  `Keyboard.TokenFrequency`, `App.Intent`, `ProactiveHarvesting.Mail`/
  `.Messages` (`bundle_id`, `token_text`, `app_id`, `mail_subject`,
  `harvested_message_content`, …); eight structurally identical
  binary-state streams (`Device.ScreenLocked`, `Device.KeybagLocked`,
  `CarPlay.Connected`, `Device.Wireless.AirplaneMode`/
  `.CellularDataEnabled`/`.WiFi`, `Device.Power.LowPowerMode`/
  `.PluggedIn`) share one `state_raw` key (a plain 0/1, not a JSON bool —
  the schema-less decoder never guesses varint semantics) resolving to
  whichever field number that stream actually uses; and a handful of
  streams with arbitrary per-record values (`Device.Wireless.WiFi`'s
  `wifi_ssid`, `Device.TimeZone`'s `timezone_name`,
  `Safari.Navigations`'s `safari_host`/`safari_url`,
  `Device.Wireless.Bluetooth`'s `bluetooth_mac`/`bluetooth_name`,
  `Messages.Read`'s `message_id`) are reachable as normalized keys for
  ad-hoc/advanced rules even though no specific value is worth a built-in
  rule. See [rules-reference.md](rules-reference.md#apple-biome-rules)
  for the full, generated list.
- `fields` also carries `entry_state` (`"written"`/`"deleted"`) and
  `crc_valid` (bool) per record. **Deleted-but-still-readable records are
  surfaced, not dropped** — they retain real forensic recovery value. A CRC
  mismatch is likewise surfaced as plain data (`crc_valid = false`,
  filterable via an ad-hoc/advanced rule) rather than treated as a parse
  failure, since the payload is still structurally intact and readable —
  matching the reference implementation's own behavior (it exposes the
  check for inspection, never raises on a mismatch). Note that in a real
  export almost every `deleted` record also fails this check (deletion
  zeroes the payload, which no longer matches the CRC computed over its
  original content) — a mismatch on its own says nothing beyond
  `entry_state`; only a mismatch on a *written* record is actually
  unusual. No built-in rule promotes this to its own tag, since neither
  iLEAPP nor crush treats a CRC mismatch as a notable category.
- `raw` holds the same serialized structure as `fields` (no separate
  independent byte dump) — the original payload bytes stay fully
  recoverable via `fields.payload_hex`/`fields.payload.<N>.hex` either way,
  same convention as every other binary parser (AUL/EVTX).
- `level` is always empty — SEGB carries no severity concept.
- `message` renders actual decoded content, not just the stream name: a
  named human summary for every stream with documented field semantics
  (`"[Peach] Device.Power.PluggedIn: Plugged In"`,
  `"[Peach] Device.TimeZone: US/Pacific"`), and for every other stream a
  compact, crush-style rendering of every decoded field
  (`"[Peach] Device.Metadata: 2: \"21D61\"  |  3: 2  |  4: \"21D61\""`) —
  so something readable always shows even for streams nobody has named a
  field on, matching crush's own SEGB viewer's single "Payload" column.
  Falls back to just the stream name only when the payload decoded to
  nothing at all.
- No config-driven field-mapping, like AUL/EVTX/journald/Android Intrusion
  Log.

## Explicitly out of scope

USN Journal, FSEvents, encrypted containers, and automatic format detection as a
requirement — the analyst always chooses the sourcetype.
