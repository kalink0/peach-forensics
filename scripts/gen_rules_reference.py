#!/usr/bin/env python3
"""Generates docs/rules-reference.md from rules/examples/*.toml — reads the
actual TOML files (not a hand-transcribed summary), so it can't drift from
what's actually shipped. Run after adding/editing a rule file, from
anywhere: `python3 scripts/gen_rules_reference.py`."""

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "examples"
OUT_PATH = REPO_ROOT / "docs" / "rules-reference.md"


def load_rule(path: Path) -> dict:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return data["rule"]


def format_match(match: dict) -> str:
    parts = []
    for key, value in match.items():
        if key == "sourcetype":
            continue
        if key == "message_contains":
            if isinstance(value, list):
                items = "<br>".join(f"&bull; `{v}`" for v in value)
                parts.append(f"message contains any of:<br>{items}")
            else:
                parts.append(f"message contains `{value}`")
        elif isinstance(value, bool):
            parts.append(f"`{key}` = `{str(value).lower()}`")
        else:
            parts.append(f"`{key}` = `{value}`")
    return "<br>".join(parts) if parts else "(sourcetype only)"


def build_table(rows: list[dict]) -> str:
    lines = [
        "| Rule name | Match | Tag | Description |",
        "|---|---|---|---|",
    ]
    for r in rows:
        name = r["name"]
        desc = r.get("description", "")
        tag = r["tag"]["value"]
        match = format_match(r["match"])
        lines.append(f"| `{name}` | {match} | `{tag}` | {desc} |")
    return "\n".join(lines)


def main():
    aul_files = sorted(RULES_DIR.glob("aul_*.toml"))
    evtx_files = sorted(RULES_DIR.glob("evtx_*.toml"))
    journald_files = sorted(RULES_DIR.glob("journald_*.toml"))

    aul_rules = [load_rule(p) for p in aul_files]
    evtx_rules = [load_rule(p) for p in evtx_files]
    journald_rules = [load_rule(p) for p in journald_files]

    aul_rules.sort(key=lambda r: r["name"])
    evtx_rules.sort(key=lambda r: r["match"].get("event_id", 0))
    journald_rules.sort(key=lambda r: r["name"])

    out = []
    out.append("# Tagging Rule Reference")
    out.append("")
    out.append(
        "Generated from `rules/examples/*.toml` — the actual shipped rule "
        "files, not a hand-transcribed summary that can drift from them. "
        "Regenerate (`python3 scripts/gen_rules_reference.py`) after "
        "adding/editing a rule file rather than hand-editing this doc "
        "directly."
    )
    out.append("")
    out.append(
        "All three packs below ship **embedded in the binary itself** "
        "(`build.rs` + `src/tagging/builtin.rs`) and every rule in them is "
        "enabled by default — see [user-guide.md](user-guide.md#tagging) "
        "for the \"Built-in rules...\" picker that lets you enable/disable "
        "individual rules rather than only a whole pack at once."
    )
    out.append("")
    out.append(f"## AUL pattern-of-life rules ({len(aul_rules)})")
    out.append("")
    out.append(
        "Most predicates sourced from [\"Apple Unified Log Predicates in "
        "iLEAPP: The Reference\"](https://leapps.org/blog-post?post=2026-08-01-unified-log-predicate-reference) "
        "(Alexis Brignoni), with a handful of newer, higher-precision ones "
        "from Tim Korver's [Thesis Friday](https://thesisfriday.com/) "
        "series instead — see each rule file's header comment for the "
        "specific citation either way. Every rule matches "
        "`sourcetype = \"aul\"`."
    )
    out.append("")
    out.append(build_table(aul_rules))
    out.append("")
    out.append(f"## EVTX Security-Auditing rules ({len(evtx_rules)})")
    out.append("")
    out.append(
        "Cross-checked against [Microsoft's official Security Auditing "
        "event reference](https://learn.microsoft.com/windows/security/threat-protection/auditing/) "
        "for each event ID — see each rule file's header comment for the "
        "specific citation. Every rule matches `sourcetype = \"evtx\"`; "
        "companion to the built-in EVTX message templates (see "
        "[field-extraction.md](field-extraction.md#message-templates-evtx))."
    )
    out.append("")
    out.append(build_table(evtx_rules))
    out.append("")
    out.append(f"## journald rules ({len(journald_rules)})")
    out.append("")
    out.append(
        "Message text sourced directly from the logging daemons' own "
        "source (OpenSSH, sudo, shadow-utils) rather than re-derived from "
        "memory — see each rule file's header comment for the specific "
        "citation. Every rule matches `sourcetype = \"journald\"` and scopes "
        "itself to a specific `process` (journald's `SYSLOG_IDENTIFIER`), "
        "since message text alone is the only signal journald offers — "
        "unlike EVTX's structured `event_id`."
    )
    out.append("")
    out.append(build_table(journald_rules))
    out.append("")

    OUT_PATH.write_text("\n".join(out))
    print(
        f"wrote {OUT_PATH} ({len(aul_rules)} AUL + {len(evtx_rules)} EVTX + "
        f"{len(journald_rules)} journald rules)"
    )


if __name__ == "__main__":
    main()
