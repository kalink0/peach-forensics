# Changelog

All notable changes to Peach will be documented in this file.

## Unreleased

### New Features

- EVTX rule pack grown from 35 to 41 rules: system time changes (4616, an anti-forensic/timestomping indicator), Kerberos replay attacks (4649), object access attempts (4663), network share connections (5140, complementing the existing 5145), service start type changes (7040, a classic defense-evasion indicator), and PowerShell Module Logging (4103, alongside the existing 4104 Script Block Logging). journald rule pack grown from 15 to 18 rules: generic login-session open/close via `systemd-logind` (console, graphical, or su/sudo — not just SSH), and a generic PAM authentication-failure catch-all for services without a dedicated rule. All sourced from Microsoft's own documentation, the JPCERT/CC lateral-movement report already cited elsewhere in this pack, and systemd's own docs.

### Bug Fixes

- **Built-in rules...** had the same staleness problem v0.4.1's "Rules reference..." fix addressed, just less visibly: the checkbox list always showed the built-in baseline while the enabled/disabled state underneath was already tracking whatever's actually active — so a newly-added baseline rule could appear unchecked (or a rule from an older downloaded pack not appear at all) whenever a downloaded pack was active. Now reads the same live active rule set as Rules reference, and shows which tier is active the same way.

## v0.4.1 - 2026-08-31

### Bug Fixes

- **Rules reference...** no longer shows a fixed, build-time snapshot of the built-in rules — it now reads whatever's actually active, so applying a downloaded rule pack (**File → Rule packs...**) updates it immediately instead of requiring a new Peach release. Also shows which tier is currently active (built-in baseline vs. a downloaded pack's version), and disables "Open on GitHub..." while a downloaded pack is active, since that link only ever matches the baseline.

## v0.4.0 - 2026-08-31

### New Features

- **Rule pack updates** (**File → Rule packs...**) — get a curated update to the built-in AUL/EVTX/journald tagging rules into a running Peach without waiting for the next app release. Three ways in: **Check for updates...** (the app's only network request, and only when you click it) against a new, dedicated [kalink0/peach-rules](https://github.com/kalink0/peach-rules) repo; **Browse...** via the native file dialog; or dragging a bundle onto the window (not supported on Linux/Wayland — a `winit` windowing-library limitation, not something Peach can work around; use Browse there). Every bundle is a complete, SHA-256-verified snapshot of every rule — never a partial update — previewed as a new/modified/removed diff (derived from each rule's own version number, not a hand-written changelog) before anything is applied, with an offer to immediately re-tag the current session afterward. Every rule now carries its own version, and the Activity Log records which rule version tagged each load/re-tag.
- AUL rule pack grown from 37 to 39 rules, sourced from Tim Korver's Thesis Friday research — USB active-charging state, AssistiveTouch-triggered sysdiagnose generation, on-screen-keyboard raw touch events, Emergency SOS's watch-side handshake, and macOS Touch-ID-vs-password unlock disambiguation.

### Improvements

- **Help → Rules reference...** now renders as an actual formatted table with clickable links, instead of a raw markdown text dump.

### Documentation

- Peach is now described as a "DFIR log workbench" rather than a "forensic log viewer" — it's grown well past viewing (README, in-app About, CLI help).
- Removed the winget install instructions from the README; the winget-forensics submission is still pending upstream approval.

## v0.3.0 - 2026-08-28

### New Features

- **Portable Case export/import** — **File > Export portable case...** bundles a whole session (or, with an active search filter, just the matching subset) into a single `.peachcase` file another analyst's Peach can open via **File > Import portable case...** as a brand-new, independent session. Unlike the existing row-level **Export (current filter)...** (CSV/JSON, no `raw`), a portable case is full-fidelity: `raw`, `fields`, analyst tags, notes, and the activity log all travel intact, and referenced text-parser TOML configs are bundled as reference copies. A filtered export still carries every analyst tag/note from the whole session, not just the filtered subset, so an annotation never silently disappears because of the filter used at export time. Integrity-checked (SHA-256, verified on import) and format-versioned, so a corrupted, tampered, or too-new bundle is refused with a clear error instead of imported anyway.
- **Case Summary** (**View > Case Summary...**) — an at-a-glance breakdown of the loaded case: total entries, entries per source and per sourcetype, level breakdown, tag coverage (tagged vs. untagged), the covered time range, and a daily-activity histogram (with real gap days shown as zero, not silently skipped), each count-based section as a small bar chart. The same view now also appears as a preview before **Export portable case...** actually runs (scoped to the active filter, so it shows exactly what's about to be bundled, with Cancel/Export... buttons) and automatically after a successful **Import portable case...**, so the result is visible without an extra click.
- **"Skip bad records instead of failing"** — an opt-in checkbox next to **Load**, off by default. Every parser (Text, EVTX, AUL, journald) used to abort a file's entire load the moment it hit one unparseable line/record, even if the rest of the file was fine. With this on, a bad record is skipped and counted instead, and the rest of the file still loads — visible afterward both in the load summary and, per file, in the Activity Log, along with whether skip mode was even used for that load. journald's one truly unrecoverable case (a corrupted object header, where there's no safe way to find the next record without guessing) still keeps everything parsed up to that point as a normal result rather than discarding it, with a note explaining where and why it stopped.

## v0.2.1 - 2026-08-24

### Documentation

- macOS release/nightly builds are now a single universal (arm64+x86_64) binary via `lipo`, instead of two separate architecture-specific downloads — each architecture still builds natively (no cross-compiling the bundled DuckDB/SQLite), only the final packaging step changed.

## v0.2.0 - 2026-08-24

### New Features

- **"Define format..." dialog** for building a text-log parser config interactively (regex, timestamp format, multiline pattern, level/message field mapping) instead of hand-editing TOML — a live preview against the picked file's first 20 lines shows exactly what a real load would parse, or the exact error, per line. Configs save to a per-user library (`Save`/`Save & Use`/`Load`).
- **Built-in text-log format library** — starter configs for Generic timestamp, Syslog (RFC 3164), Android Logcat, Pacman log, and, new this release, **Apache Common/Combined** and **Nginx access log** (HTTP status → `level`, request line → `message`). Selectable from a **Built-in formats** dropdown in "Define format...".
- **`assume_year`** config field for text-log sources whose timestamp format carries no year at all (classic syslog, logcat) — same explicit, never-guessed approach as the existing `assume_offset`.
- **Timezone settings** — a session-wide fallback timezone for sources with none of their own, and a separate **Display timezone** controlling how the timeline/exports render timestamps. Internal UTC storage, sorting, and filtering are unaffected either way; every rendered/exported timestamp always carries its own explicit offset.
- **Level/Tag/Sources filters as dropdowns** with per-value event counts (e.g. `wifi_status (1234)`, a whole-timeline snapshot, not a live filtered count) instead of ever-growing button rows. **Sources** is new — unchecking one hides that source's rows without unloading it (backed by a new `source_id=` search field). Every dropdown has a per-row **only** and a **Show all**.
- **Time range picker** — a calendar-and-clock way to set `after=`/`before=` instead of typing an ISO timestamp by hand.
- **Per-column filter chips** — the row context menu's **Filter by...** (Sourcetype/Host/Process/Event ID/Subsystem/Category) adds a removable chip under the search box.
- **"Tag all matching (advanced)..."** can now match on any populated field on the clicked row (Sourcetype/Host/Process/Event ID/Subsystem/Category), not just a message substring.
- **Configurable rules directory** (Settings) — `.toml` rule files placed there load automatically on startup, same as the built-in packs, for building a personal rule collection over time.
- **AUL rule pack** grown from 33 to 37 rules (dialed-number recovery, device orientation, Watch Crown button, CarPlay connection, plus two extended predicates), sourced from Tim Korver's Thesis Friday research.
- **EVTX rule pack** grown from 15 to 35 rules, and a **new journald rule pack** (0 → 15 rules) — SSH/sudo/su, account/group lifecycle, PowerShell Script Block Logging, process exit, Kerberos ticket requests, SMB share access, service install, reboot/shutdown, cron execution, kernel boot markers, sourced from Microsoft's own docs and JPCERT/CC's lateral-movement research. Along the way, fixed a bug where `event_id`/`provider` rule conditions never actually matched real EVTX data.
- **Per-rule built-in rule picker** — enable/disable each built-in AUL/EVTX/journald rule individually instead of only the whole pack; doubles as an in-app reference.
- **Help > Rules reference...** — the full built-in rule table (match condition, tag, description), embedded in the binary so it works fully offline.
- **Activity Log** (View menu) — every load/re-tag this session has run (status, counts, per-file and per-rule breakdown), persisted across restarts.
- **Abort button** for a running load — partial results already inserted are kept, not rolled back.
- **File > New session** — starts a fresh, empty session without restarting Peach.
- **App icon** — Peach now has its own icon (window icon on Linux/macOS, embedded `.exe` icon on Windows; Wayland `.desktop`/macOS `.app` packaging still pending).
- Settings dialog: long explanatory text now collapses behind a **?** button per setting, decluttering the dialog.

### Bug Fixes

- **Every dialog could hang the app on Wayland** — opening any dialog (reproduced down to About, the simplest one) sent CPU usage into a continuous climb, and the window's own close (X) button would sometimes stop responding until the main window was refocused first. Root cause: dialogs briefly became independent OS windows via egui's multi-viewport support, which has a documented, still-open Wayland repaint-scheduling cost. Reverted to the previous, always-reliable embedded-window approach — the tradeoff (dialogs can no longer be dragged onto a second monitor) is worth a forensic tool that doesn't hang.
- Adding/editing a note or manual tag no longer briefly re-filters the whole timeline.
- Notes now actually show on hover (previously silently never fired).
- Fixed a crash closing the file picker via the window's X button (instead of Cancel) on Linux.
- Fixed the Activity Log and "Define format..." dialogs' buttons rendering below the visible window area on tall content.

### Documentation

- README: project banner, Download section (Homebrew/Winget/Scoop, nightly builds), badge row, and an expanded Acknowledgements section.
- About dialog's Acknowledgements tab updated to cite every rule-pack source (Microsoft's Security Auditing reference, OpenSSH/sudo/shadow-utils, Thesis Friday, iLEAPP).
- `docs/user-guide.md`: documented Export, View > Theme, and the Columns picker.
- Removed "Finding-Nemo ecosystem" wording (trademark).

## v0.1.0 - 2026-08-14

First release — beta quality. Rudimentary AUL support (with a built-in
pattern-of-life tagging rule pack), plus EVTX, journald, and
TOML-configurable text log parsing, all on top of a Splunk-inspired
search/filter, three-mode tagging engine, session persistence, CSV/JSON
export, and CLI handoff from crush
(`--add-source`/`--cleanup-dir`/`--ephemeral-session`). See
[docs/supported-sources.md](docs/supported-sources.md) for exactly what each
sourcetype does and doesn't cover today.
