# peach-forensics

A lean, local-first forensic log viewer for DFIR work. Parses log sources into a
normalized, taggable timeline stored in DuckDB, with a Splunk-inspired search syntax
and a SQLite session layer for analyst tags. Rust + egui, no server, no cloud.

Part of the Finding-Nemo ecosystem: can be started standalone or handed evidence paths
by `crush`, then runs completely independently (no IPC).

## Status

Currently implemented: AUL (`.logarchive`) and TOML-configurable text log parsing,
import-time and re-tag tagging, session persistence, and CLI source handoff. EVTX and
journald parsers are planned but not yet built — see
[docs/supported-sources.md](docs/supported-sources.md) for the authoritative,
up-to-date list of what actually works today.

## Building and running

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
peach --add-source <path> [--add-source <path> ...] [--cleanup-dir <path> ...]
```

`--add-source` pre-fills a source to load in the GUI (sourcetype is still confirmed
manually — peach never auto-detects a format). `--cleanup-dir` marks a directory
(e.g. a temp extraction dir `crush` created) to be deleted when peach closes; it's
only ever deleted if it resolves to somewhere under the OS temp directory.

## Documentation

- [docs/user-guide.md](docs/user-guide.md) — how to use peach: loading sources,
  tagging rules, search syntax, sessions
- [docs/supported-sources.md](docs/supported-sources.md) — supported/planned source
  types
