# Changelog

All notable changes to Peach will be documented in this file.

## Unreleased

### Bug Fixes

- **Adding/editing a note or a manual analyst tag briefly re-filtered the whole timeline** — both went through the same path as a load/re-tag finishing (a full DuckDB recount, showing "Filtering…"), even though notes and analyst tags live entirely in the separate SQLite session DB and never change what a filter matches. A new `TimelineView::refresh_window()` now only drops the cached window (so the edit shows up immediately) without recounting.
- **Notes never showed on hover — only the 📝 marker in the Tags column was visible** — the row's right-click-context-menu widget is created after every per-cell widget in that row, and egui only reports the topmost click-sensing widget under the pointer as hovered, so the Tags/Notes cells' own `.on_hover_text()` silently never fired. The notes tooltip is now attached to the row-spanning widget itself, the only one in the row actually eligible to register hover.

### Documentation

- README: added a Download section (prebuilt binaries/nightly) and an Acknowledgements section (crate credits, AUL rule pack research attribution, thanks to [@dugeonlady](https://github.com/dugeonlady) for the Rainbow theme).
- Removed the "Finding-Nemo ecosystem" wording from the README and About dialog — avoids invoking Disney/Pixar's trademark for a name that was never itself published anywhere.

## v0.1.0 - 2026-08-14

First release — beta quality. Rudimentary AUL support (with a built-in
pattern-of-life tagging rule pack), plus EVTX, journald, and
TOML-configurable text log parsing, all on top of a Splunk-inspired
search/filter, three-mode tagging engine, session persistence, CSV/JSON
export, and CLI handoff from crush
(`--add-source`/`--cleanup-dir`/`--ephemeral-session`). See
[docs/supported-sources.md](docs/supported-sources.md) for exactly what each
sourcetype does and doesn't cover today.