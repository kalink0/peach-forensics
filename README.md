# peach-forensics

![peach](.github/peach_readme_banner.svg)

A lean, local-first forensic log viewer for DFIR work. Parses log sources into a
normalized, taggable timeline stored in DuckDB, with a Splunk-inspired search syntax
and a SQLite session layer for analyst tags. Rust + egui, no server, no cloud.

Runs standalone, or can be started and handed evidence paths by
[crush](https://github.com/kalink0/crush-forensics), then continues completely
independently (no IPC).

## Status

Currently implemented: AUL (`.logarchive`), EVTX, journald, and TOML-configurable
text log parsing, import-time and re-tag tagging, session persistence, and CLI
source handoff. See [docs/supported-sources.md](docs/supported-sources.md) for the
authoritative, up-to-date list of what actually works today.

## Download

Prebuilt binaries for Linux, Windows, macOS (Apple Silicon and Intel) are attached to
every [GitHub release](https://github.com/kalink0/peach-forensics/releases) — no Rust
toolchain or build step needed. A [nightly build](https://github.com/kalink0/peach-forensics/releases/tag/nightly)
tracks `main` and is rebuilt automatically whenever new commits land.

### Package managers

**macOS (Homebrew)**
```bash
brew tap kalink0/forensics
brew install peach-forensics
```

**Windows (winget)**
```powershell
winget install kalink0.Peach
```

**Windows (Scoop)**
```powershell
scoop bucket add forensics https://github.com/kalink0/scoop-forensics
scoop install forensics/peach-forensics
```

No native package for Linux yet — grab the binary from
[Releases](https://github.com/kalink0/peach-forensics/releases).

## Building and running

Building from source is only needed to modify peach yourself — see
[Download](#download) above for ready-to-run binaries.

Requires a Rust toolchain (stable) and a C/C++ compiler + CMake (DuckDB is compiled
from source on first build).

```sh
cargo build          # first build compiles bundled DuckDB — several minutes
cargo run             # build + launch the GUI
```

Local checks (mirrors CI):

```sh
just check            # cargo fmt --check + clippy -D warnings + test
just fmt               # auto-format
```

## CLI

```sh
peach --add-source <path> [--add-source <path> ...] [--cleanup-dir <path> ...] [--ephemeral-session]
```

`--add-source` pre-fills a source to load in the GUI (sourcetype is still confirmed
manually — peach never auto-detects a format). `--cleanup-dir` marks a directory
(e.g. a temp extraction dir `crush` created) to be deleted when peach closes; it's
only ever deleted if it resolves to somewhere under the OS temp directory.
`--ephemeral-session` disables session persistence for the run: the session's
`.duckdb`/`.sqlite` are written to a one-off temp directory instead of the
persistent sessions directory and removed on exit regardless of whether they hold
data — for evidence handed off from a temp extraction or a decrypted source, where
no durable unencrypted session copy should be left behind.

## Documentation

- [docs/user-guide.md](docs/user-guide.md) — how to use peach: loading sources,
  tagging rules, search syntax, sessions
- [docs/supported-sources.md](docs/supported-sources.md) — supported/planned source
  types
- [docs/rules-reference.md](docs/rules-reference.md) — every built-in tagging rule
  (AUL/EVTX/journald), generated from the actual shipped rule files; also
  available fully offline in-app via **Help → Rules reference...**
- [CHANGELOG.md](CHANGELOG.md) — what changed in each release

## Acknowledgements

Peach builds on the open-source and DFIR community. AUL (`.logarchive`) parsing
uses [macos-unifiedlogs](https://github.com/mandiant/macos-UnifiedLogs) by
[Mandiant](https://github.com/mandiant) (Apache-2.0); EVTX parsing uses
[evtx](https://github.com/omerbenamram/evtx) by
[@omerbenamram](https://github.com/omerbenamram) (MIT/Apache-2.0). The GUI is
built on [egui/eframe](https://egui.rs); the bulk timeline on
[DuckDB](https://duckdb.org) via `duckdb-rs`; the session layer on SQLite via
`rusqlite`. See the in-app **Help → About → Acknowledgements** tab for the
full dependency list with licenses.

The built-in tagging rule packs (`rules/examples/*.toml`) are built on
published research and primary sources, not re-derived from scratch:

- **AUL** — most predicates sourced from ["Apple Unified Log Predicates in
  iLEAPP: The
  Reference"](https://leapps.org/blog-post?post=2026-08-01-unified-log-predicate-reference)
  by Alexis Brignoni, with a handful of newer ones (dialed-number recovery,
  device orientation, Apple Watch Crown/button, CarPlay handshake) from Tim
  Korver's [Thesis Friday](https://thesisfriday.com/) series.
- **EVTX** — cross-checked against [Microsoft's official Security Auditing
  event
  reference](https://learn.microsoft.com/windows/security/threat-protection/auditing/)
  for each event ID, with a handful from JPCERT/CC's ["Detecting Lateral
  Movement through Tracking Event
  Logs"](https://www.jpcert.or.jp/english/pub/sr/DetectingLateralMovementThroughTrackingEventLogs_version2.pdf)
  report and PowerShell's own logging docs.
- **journald** — message text sourced directly from OpenSSH, sudo,
  shadow-utils, and systemd's own logging code.

See each rule file's own header comment for its specific citation, and
[docs/rules-reference.md](docs/rules-reference.md) for the full, generated
rule-by-rule breakdown.

Special thanks to [@dugeonlady](https://github.com/dugeonlady) for suggesting
the Rainbow theme in crush — Peach's Rainbow theme (*View → Theme → Rainbow*)
carries over the same cycle and colors. Forensics tools don't have to be grey.

Parts of this software were developed with assistance from
[Claude AI / Claude Code](https://claude.ai) by Anthropic.

## Bugs and feature requests

Use [GitHub Issues](https://github.com/kalink0/peach-forensics/issues). Please
include the Peach version (shown in **Help → About**), your OS, and steps to
reproduce.
