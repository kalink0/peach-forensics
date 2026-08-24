# Security Policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report security issues privately via [GitHub's private vulnerability reporting](https://github.com/kalink0/peach-forensics/security/advisories/new), or by emailing **peach@be-binary.de**.

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected version(s)

## Scope

Peach is a **read-only** forensic analysis tool. It parses evidence files into a local timeline but never writes to the source. Relevant security concerns include:

- Maliciously crafted evidence files (`.evtx`, AUL `.logarchive`/raw `tracev3` extractions, `.journal`, arbitrary text logs) that trigger crashes or arbitrary code execution in a parser or the crates it wraps (`evtx`, `macos-unifiedlogs`)
- Regular-expression denial of service (catastrophic backtracking) via a text-log parser config's `pattern.regex`/`multiline_start_pattern` — these are analyst-authored TOML, but a config shared or copied from an untrusted source could still carry a hostile pattern
- Path traversal or directory escape when loading a source, saving a tagging rule file, or exporting CSV/JSON
- Unexpected network access (Peach is designed to be fully offline — no cloud sync, no telemetry, no update checks)
