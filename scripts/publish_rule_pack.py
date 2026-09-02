#!/usr/bin/env python3
"""Builds peach-rules-v{N}.zip — the downloadable rule-pack bundle described
in docs/design/rule-pack-updates.md — from the current rules/examples/*.toml
files (AUL + EVTX + journald + intrusion_log together; every bundle is a
full snapshot of all four families, never a delta).

Published from a separate repo, kalink0/peach-rules — not this one — so a
rule-pack release never gets mixed into peach-forensics' own app-release
list (tag `v{N}` there means "rule pack N", unambiguously; no
`peach-rules-`  prefix needed the way it would be sharing a tag namespace
with app releases like `v0.3.0`). This script itself is unaffected by
which repo publishes it — it only ever reads from and writes into its own
checkout (`rules/examples/`, `Cargo.toml`, `dist/`) — the peach-rules CI
workflow runs it against a checkout of *this* repo's source, then creates
the release on the *other* one.

N defaults to the highest existing "peach-rules-vN" git tag *in this repo's
own checkout* plus one — a read-only `git tag --list` lookup, meaningful
only for a local dry run here (this repo's tags are app releases, not rule
packs, so this is not where real version numbers come from once
peach-rules exists). Always pass --version explicitly for a real release —
the peach-rules CI workflow does.

Output goes to dist/peach-rules-v{N}.zip (gitignored — a build artifact,
not something to commit) plus dist/peach-rules-v{N}/manifest.toml and the
included rule files, unzipped, for inspection before publishing, and
dist/peach-rules-v{N}-notes.md — a rule-name-to-version table meant to be
passed straight to `gh release create --notes-file`, so the release page
itself answers "which version is rule X at in this pack?" without anyone
downloading and unzipping the bundle first.

Run: python3 scripts/publish_rule_pack.py [--version N] [--min-peach-version X.Y.Z]
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "examples"
DIST_DIR = REPO_ROOT / "dist"

FAMILY_PREFIXES = ("aul_", "evtx_", "journald_", "intrusion_log_")
TAG_PATTERN = re.compile(r"^peach-rules-v(\d+)$")


def rule_files() -> list[Path]:
    """Every AUL/EVTX/journald/intrusion_log rule file — sorted for a
    deterministic zip (same inputs, same bundle, every time), matching the
    same principle build.rs already applies to the embedded packs."""
    files = [
        path
        for path in RULES_DIR.glob("*.toml")
        if path.name.startswith(FAMILY_PREFIXES)
    ]
    files.sort(key=lambda p: p.name)
    if not files:
        raise SystemExit(f"no rule files found under {RULES_DIR}")
    return files


def load_rule_name_and_version(path: Path) -> tuple[str, str]:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    rule = data.get("rule", {})
    name = rule.get("name")
    version = rule.get("version")
    if not name:
        raise SystemExit(f"{path}: [rule] has no name")
    if not version:
        raise SystemExit(
            f"{path}: [rule] has no version — every shipped rule must be "
            "versioned before it can go into a rule pack bundle (see "
            "docs/design/rule-pack-updates.md §5)"
        )
    return name, version


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def next_pack_version() -> int:
    """Highest existing peach-rules-vN git tag, plus one — 1 if there is
    none yet. Read-only: lists tags, never creates one."""
    result = subprocess.run(
        ["git", "tag", "--list", "peach-rules-v*"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    versions = [
        int(m.group(1))
        for line in result.stdout.splitlines()
        if (m := TAG_PATTERN.match(line.strip()))
    ]
    return max(versions, default=0) + 1


def current_peach_version() -> str:
    cargo_toml = (REPO_ROOT / "Cargo.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', cargo_toml, re.MULTILINE)
    if not match:
        raise SystemExit("could not find [package].version in Cargo.toml")
    return match.group(1)


def source_commit() -> str:
    """Short SHA of the peach-forensics checkout this script is running
    from — more precise than a human-typed branch/tag name for "what was
    this bundle built from", and correct regardless of who's asking
    (a local dry run, or peach-rules' publish workflow after checking out
    a specific `ref`): whatever's actually on disk right now is the
    answer, not a name that could point somewhere else by the time anyone
    reads the release notes later."""
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def write_release_notes(dest: Path, entries: list[dict]) -> None:
    """A per-rule name-to-version table, written as the GitHub release's
    own notes body — visible directly on the release page, no download or
    unzip needed to answer "which version is rule X at in this pack?".
    Sorted by rule name, not file order, for easy scanning/diffing between
    releases."""
    lines = [
        f"Built from kalink0/peach-forensics@{source_commit()}. See that "
        "repo's rules/examples/ for the individual rule sources and "
        "citations.",
        "",
        "## Rule versions in this pack",
        "",
        "| Rule | Version |",
        "|---|---|",
    ]
    for entry in sorted(entries, key=lambda e: e["rule_name"]):
        lines.append(f'| `{entry["rule_name"]}` | {entry["rule_version"]} |')
    dest.write_text("\n".join(lines) + "\n")


def write_manifest(dest: Path, pack_version: int, min_peach_version: str, entries: list[dict]) -> None:
    lines = [
        "[pack]",
        f"pack_version = {pack_version}",
        f'released_at = "{date.today().isoformat()}"',
        f'min_peach_version = "{min_peach_version}"',
        "",
    ]
    for entry in entries:
        lines.append("[[files]]")
        lines.append(f'name = "{entry["name"]}"')
        lines.append(f'sha256 = "{entry["sha256"]}"')
        lines.append(f'rule_name = "{entry["rule_name"]}"')
        lines.append(f'rule_version = "{entry["rule_version"]}"')
        lines.append("")
    dest.write_text("\n".join(lines).rstrip() + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        type=int,
        default=None,
        help="pack_version to build (default: highest existing peach-rules-vN tag + 1)",
    )
    parser.add_argument(
        "--min-peach-version",
        default=None,
        help="min_peach_version to write into the manifest (default: current Cargo.toml version)",
    )
    args = parser.parse_args()

    pack_version = args.version if args.version is not None else next_pack_version()
    min_peach_version = args.min_peach_version or current_peach_version()

    files = rule_files()
    entries = []
    for path in files:
        rule_name, rule_version = load_rule_name_and_version(path)
        entries.append(
            {
                "path": path,
                "name": path.name,
                "sha256": sha256_of(path),
                "rule_name": rule_name,
                "rule_version": rule_version,
            }
        )

    bundle_name = f"peach-rules-v{pack_version}"
    staging_dir = DIST_DIR / bundle_name
    zip_path = DIST_DIR / f"{bundle_name}.zip"

    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True)

    manifest_path = staging_dir / "manifest.toml"
    write_manifest(manifest_path, pack_version, min_peach_version, entries)

    for entry in entries:
        shutil.copy2(entry["path"], staging_dir / entry["name"])

    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(manifest_path, manifest_path.name)
        for entry in entries:
            zf.write(staging_dir / entry["name"], entry["name"])

    notes_path = DIST_DIR / f"{bundle_name}-notes.md"
    write_release_notes(notes_path, entries)

    print(f"built {zip_path} ({len(entries)} rule files, pack_version={pack_version})")
    print(f"unzipped copy for inspection: {staging_dir}")
    print(f"release notes (rule name -> version table): {notes_path}")
    print()
    print("to publish: push this bundle to a release in kalink0/peach-rules (tag")
    print(f'v{pack_version}), not this repo — e.g. from a checkout of peach-rules:')
    print(
        f'  gh release create v{pack_version} '
        f'/path/to/peach-forensics/{zip_path.relative_to(REPO_ROOT)} '
        f'--repo kalink0/peach-rules --title "Rule pack v{pack_version}" '
        f'--notes-file /path/to/peach-forensics/{notes_path.relative_to(REPO_ROOT)}'
    )


if __name__ == "__main__":
    main()
