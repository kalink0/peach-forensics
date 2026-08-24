# Contributing to Peach

Thanks for your interest in contributing. This document covers how to set up a development environment, run the checks CI runs, and submit changes.

## Development setup

```bash
git clone https://github.com/kalink0/peach-forensics.git
cd peach-forensics
cargo build          # first build compiles bundled DuckDB and SQLite from source — several minutes
cargo run             # build + launch the GUI
```

Requires a Rust toolchain (stable) and a C/C++ compiler + CMake — DuckDB and SQLite are both compiled from source via their `bundled` Cargo features, not linked against system libraries. See the [README](README.md#building-and-running) for details.

## Running the checks

```bash
just check            # cargo fmt --check + clippy -D warnings + test, same as CI
just fmt               # auto-format
```

Or individually: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`. CI runs all three on every push to `main` and every pull request — a pull request should pass all three before review.

## Builds

**Stable releases** are cut by publishing a GitHub Release (with a version tag); `release.yml` then builds and attaches binaries for Linux, Windows, and macOS (Apple Silicon and Intel).

**Nightly builds** run automatically at 02:00 UTC via `nightly.yml`, tracking `main`, and produce pre-release artifacts for the same three platforms — see the [`nightly` tag](https://github.com/kalink0/peach-forensics/releases/tag/nightly).

## Adding a source type or parser

`LogParser` (`src/parsers/mod.rs`) is the extension point for a new sourcetype — see the existing wrappers (`src/parsers/evtx.rs`, `aul.rs`, `journald.rs`, `text_config.rs`) for the pattern each one follows. If your change adds a new column extracted from a sourcetype's `fields` JSON (the way Host/Process/Event ID/Subsystem/Category already work), [docs/field-extraction.md](docs/field-extraction.md#adding-a-new-extracted-field) has a step-by-step checklist for that specific case.

## Submitting changes

- Open an issue first for significant changes so we can agree on the approach before you write code.
- Keep pull requests focused — one feature or fix per PR.
- Add or update tests for any changed parser, tagging rule, or core query logic. Peach is forensic software: test coverage isn't a nice-to-have here, it's part of what makes its output verifiable — see [docs/supported-sources.md](docs/supported-sources.md) for the standard every parser is already held to.
- Follow the existing code style (`cargo fmt`-enforced, nothing to configure by hand).

## Forensic data

Do **not** include real device acquisitions, case data, or personal information in tests, examples, or issue reports. Use synthetic or purpose-built test fixtures only (see `tests/fixtures/`).

## Reporting bugs

Use [GitHub Issues](https://github.com/kalink0/peach-forensics/issues). Include the Peach version (shown in **Help → About**), your OS, and steps to reproduce. For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.
