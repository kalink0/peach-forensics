# Changelog

All notable changes to Peach will be documented in this file.

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
