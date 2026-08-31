# Concept: Decoupling Rule-Pack Updates from App Releases

Status: **Draft, not built.** Branch `feature/rule-pack-updates`. This document is the
discussion basis before implementation — points marked **Open question** still need a
decision; points marked **Resolved** were decided in review. §11 is the implementation
plan, for review before any code gets written.

## 1. Problem

The built-in rule packs (`rules/examples/aul_*.toml` etc.) are embedded into the binary at
compile time via `build.rs` (`include_str!`). A recent Thesis Friday review added six new
AUL rules that had to wait for the next app release, even though they're pure data, not
code. An analyst who needs a new rule *today* either waits for a release or manually drops
the TOML file into the already-existing configurable rules directory (Settings) — that
works, but is completely undiscoverable for anyone who doesn't read the rules reference.

Goal: an in-app way to get up-to-date curated rule packs **without** rebuilding/releasing
the whole app — for two user groups:
- **offline/air-gapped:** download a bundle elsewhere, drag it into Peach
- **online:** a "Check for updates" / "Download" button right in the app

## 2. Principles this feature must respect

From CLAUDE.md section 0.1, applied concretely to this feature:

- **Local-only stays the default.** Peach today makes zero network calls of its own. This
  feature would be the first — it must be strictly user-initiated (a button click), never
  automatic/background/on-startup. No auto-update check at launch, not even opt-out —
  otherwise "local-only" becomes a default instead of a guarantee.
- **Determinism.** "Same file + same parser config → always the same result" applies to
  rule packs too. If a pack changes under the hood, it must be traceable *which* rule
  version produced *which* tags at *what* time — otherwise a reopened case is no longer
  reproducible. (See §5 — this ended up being the load-bearing design point.)
- **Traceability over convenience.** An update must never happen silently in the
  background. Preview before applying (which rules are new/changed/removed), explicit
  confirmation, an Activity Log entry.
- **Make errors visible.** A failed download, a corrupt/tampered bundle file, a version
  mismatch — all surfaced clearly, never silently ignored or guessed at.

## 3. Three-tier model for rule provenance

Today there are two tiers (built-in + settings directory). Proposal: a third tier in
between:

1. **Built-in** (`build.rs`/`include_str!`) — the offline baseline as of release time.
   Stays as-is, never changes at runtime. Works if *nothing* about this feature is used —
   Peach remains exactly as usable as today without a single click on "Update".
2. **Downloaded/updated** (new) — one versioned bundle applied via drag-and-drop or the
   download button, covering **all three families at once** (see §4 — there is no
   per-family download). Lands in its own directory (not mixed with the existing "custom
   rules" directory, see below).
3. **Custom rules** (existing, Settings → configurable rules directory) — unchanged, stays
   purely local/personal, no update logic.

**Resolved:** tier 2 wins wholesale over tier 1 when present — not a rule-by-rule merge,
and (per §4's revision) not even a per-family question anymore: either Peach is running
purely on the embedded baseline, or it's running on downloaded pack vN for AUL *and* EVTX
*and* journald together, since every bundle always contains all three. One number (`vN`)
fully describes which rule state is active.

## 4. Bundle format

No new rule format needed — the TOML structure (`[rule]`/`[rule.match]`/`[rule.tag]`) stays
exactly as it is today, aside from the added `version` field described in §5. What's new is
the wrapper around it, modeled on the already-established `.peachcase` pattern (SHA-256
integrity check, format versioning, a clear error on a too-new/corrupt bundle):

```
peach-rules-v1.zip
├── manifest.toml      # pack_version, released_at, min_peach_version,
│                       # one [[files]] entry per included rule file:
│                       # name, sha256, rule_name, rule_version
├── aul_*.toml          # today's rule format + a per-rule `version` field
├── evtx_*.toml
├── journald_*.toml
```

**Resolved (revised):** there is no per-family download and no per-family tag. **One
combined bundle, one tag, one version number, covering AUL + EVTX + journald together —
`peach-rules-v1`, `peach-rules-v2`, ...** Simpler than the earlier per-family draft: one
release process, one version number to reason about, no risk of the three families drifting
out of sync with each other. ZIP for both delivery paths (drag-and-drop accepts a ZIP too,
not a loose folder) stays as previously decided. Accepted trade-off, also as before: a
pack update is all-or-nothing for the whole rule set — no cherry-picking one family or one
rule out of a release.

**Explicitly: every bundle is a full snapshot, never a delta.** `peach-rules-v5.zip`
contains all 89 rule files exactly as they should be at v5, including the ones that haven't
changed since v1 — not just what changed since v4. This falls directly out of §3's
wholesale-replacement precedence: applying a pack means tier 2 fully replaces tier 1, so
Peach always needs the complete state, never a diff to merge onto a previous one. It also
means a client can jump straight from v1 to v5 without installing v2–v4 first. The
per-rule `version` field (§5) has nothing to do with the bundle format itself — it exists
purely so the *preview* can tell the analyst which of the 89 files actually changed,
without which every update would look like "all 89 rules replaced," changed or not.

## 5. Rule-level versioning (drives both traceability and the diff/changelog)

Each rule gets its own `version` field in its TOML, alongside `name`/`description`:

```toml
[rule]
name = "aul_airplane_mode"
description = "..."
version = "3"
```

Bumped by whoever curates the rule whenever its `match`/`tag` semantics change — not tied
to the bundle's own `pack_version` in `manifest.toml`, which just marks a release of the
*whole set*. Applies to all three tiers, not just downloaded packs: a rule in the user's
own custom rules directory can carry a version too, for the same reason. Every one of the
89 currently-shipped rules starts at `version = "1"` — nothing has been versioned before
this, so today's shipped state *is* version 1 for all of them.

**Two things this one field feeds, not just one:**

1. **Traceability (resolves the original open question 4).** Don't log "pack was updated"
   as its own event — that's not tied to any case/file. Instead: **every processing run**
   (an import-time load, or a re-tag pass) **records, in its existing Activity Log entry,
   the name+version of every rule that was active for that run** — not just which rules
   matched (already tracked per the existing per-rule breakdown, CHANGELOG v0.2.0), but
   their versions too. A re-tag run naturally produces a *new* Activity Log entry with
   whatever versions were current at that moment, so re-tagging a source under a newer
   rule pack doesn't lose the history of what the original load used — both entries stay
   in the log.
2. **The new/modified/removed diff for the preview step (§7).** This is **derived, not
   manually authored** — `manifest.toml` does *not* carry a hand-maintained changelog list.
   Instead, comparing the candidate bundle's rule set against whatever is currently active
   (by rule `name`) gives the full picture with no extra bookkeeping to get wrong:
   - name present in the bundle, absent locally → **new**
   - name present in both, but `version` differs → **modified**
   - name present in both, same `version` → unchanged, not shown
   - name present locally, **absent from the bundle** → **removed** — and this one matters
     enough to call out on its own: a rule an analyst has been relying on can simply stop
     existing in a newer pack (retired, merged into another rule, etc.), and unlike a
     version bump this doesn't error or warn on its own — it just silently stops tagging
     anything from here on. The removed-list in the preview is the only place this becomes
     visible before it's applied.

   Human-readable *why* (e.g. "sourced from Thesis Friday #27") stays exactly where it
   already lives — the rule file's own header comment, and the GitHub release's free-text
   body for anyone browsing there. Nothing machine-readable needs to duplicate that prose;
   the diff is computed from data (presence + version number) that can't drift from what's
   actually in the bundle, which prose easily can.

## 6. Distribution source for the download path

**Resolved, then revised again — separate repo.** The first pass shared this repo's own
Releases list with app releases, disambiguated by a `peach-rules-` tag prefix
(`peach-rules-v{N}`). Building the actual publish workflow surfaced a real problem with
that: GitHub auto-flags the most-recently-published non-prerelease release as "Latest",
so a rule-pack release could displace the real newest app version there — avoidable only
via `--prerelease` (borrows a flag that really means "unstable/beta", not "different kind
of artifact") or the more surgical `make_latest: false` (correct, but still a workaround
bolted onto a release model that assumes one release *kind* per repo).

**A dedicated repo, `kalink0/peach-rules`, sidesteps this outright** — parallel to
`winget-forensics` already being a separate repo for winget packaging (see
[[winget_peach_paused]]), same reasoning: a distinct distribution concern gets its own
repo rather than being shoehorned into this one. Every release there *is* a rule pack, so:
- tag is a plain `v{N}` (no `peach-rules-` prefix needed — nothing to disambiguate from)
- asset stays `peach-rules-v{N}.zip` (kept descriptive since the filename travels outside
  repo context, e.g. once downloaded to disk)
- "Latest" there always means "latest rule pack", automatically, no flag juggling

"Check for updates" calls `GET /repos/kalink0/peach-rules/releases` (GitHub REST API,
unauthenticated — 60 requests/hour/IP is fine for a manual button click, not a background
poll), filters tags matching `^v(\d+)$`, takes the highest N with a matching
`peach-rules-v{N}.zip` asset, compares against the locally active `pack_version`, and if
newer, downloads that release's asset via its `browser_download_url`.

**Publishing:** `scripts/publish_rule_pack.py` lives in *this* repo (parallel to the
existing `gen_rules_reference.py`) since it only ever reads `rules/examples/*.toml` and
`Cargo.toml` from wherever it's checked out — which repo ends up publishing the result
doesn't change what the script itself does. It scans
`rules/examples/{aul,evtx,journald}_*.toml`, computes each file's SHA-256, reads each
rule's `name`/`version` out of its TOML, writes `manifest.toml`, zips everything as
`peach-rules-v{N}.zip`. Its own `git tag`-based version auto-detect (highest existing
local tag + 1) is only meaningful for a manual dry run inside *this* repo's checkout —
this repo's tags are app releases (`v0.3.0`-style), not rule-pack numbers, so it's not
where a real release's version number comes from once `peach-rules` exists; the actual
publish path always passes `--version` explicitly instead (see below).

**CI, living in `peach-rules`, `workflow_dispatch`-triggered (manual, not automatic):** a
`.github/workflows/publish.yml` in `peach-rules` itself — required `version` input (no
auto-detect in CI at all, to avoid the cross-repo git-tag confusion above; the maintainer
glances at the existing releases list before triggering, this isn't a frequent operation),
optional `ref` input (which `peach-forensics` commit/branch/tag to build from, default
`main`). Steps: check out `peach-forensics` at `ref` into a subdirectory (read-only, no
push access needed — public repo), run `publish_rule_pack.py --version N` against that
checkout, `gh release create v{N} ... --repo kalink0/peach-rules` with the resulting zip.
Still fully human-initiated (a click in the Actions tab, or `gh workflow run`) — moving
"run a script + gh release create" from the maintainer's terminal into a repeatable,
auditable CI job doesn't change that this is manual, deliberate publishing, never
triggered by a push/schedule/webhook.

## 7. UI sketch

A new window, e.g. **Settings → Rule packs...** or its own menu entry next to
"Rules reference...":

- Header: active pack version (or "built-in baseline" if tier 2 was never applied),
  applied-at date, source. A table underneath, broken out by family purely for display
  (AUL/EVTX/journald · rule count) — the version number itself is the same for all three,
  since a bundle is always the complete set.
- Drop zone: "Drag a bundle here" — accepts a ZIP.
- "Check for updates" button (clearly labeled as a network request — the only one in the
  whole program, and that must be visible, never hidden behavior).
- After selection/download: **preview** before applying — the derived new/modified/removed
  list from §5, applied only after explicit confirmation. Same pattern as the
  "Define format..." live preview.
- After applying: offer to immediately run a re-tag pass on the current session (existing
  tagging-engine mode, see [[peach_tagging_message_contains]]) — otherwise new rules only
  apply to files loaded from now on. The resulting Activity Log entry records the new
  versions per §5.

## 8. Integrity & trust

- SHA-256 check like `.peachcase`, download over HTTPS only.
- No auto-apply — preview is mandatory, not optional.
- TOML rules are data/config, not executable code — lower risk than a binary update, but
  they directly influence forensic conclusions, so they deserve the same seriousness as a
  software update.
- Format versioning in the manifest (`min_peach_version`), so a too-new bundle is rejected
  with a clear error instead of silently loaded wrong — parallel to `.peachcase`'s own
  behavior.

## 9. Scope for v1

Since every bundle now always covers all three families together (§4), there's no more
"AUL first" staging question for the *distribution* mechanism itself — it ships for all
three families at once, by construction. The per-rule `version` field (§5) needs to land
on all 89 currently-shipped rule files as part of the same work, all starting at
`version = "1"` (see §11 step 1).

## 10. Open questions — none remaining

All four original questions are resolved (§3, §4/§6, §5). §4/§6 were revised in review from
independent per-family tags to a single combined bundle/tag, and §5 was extended to also
drive the new/modified/removed diff, at the user's request, rather than a manually
maintained changelog list.

## 11. Implementation plan (for review before coding starts)

Proposed order — each step is independently testable, later steps depend on earlier ones:

1. **Rule-level `version` field — done.** `version = "1"` added to all 89 existing rule
   TOMLs (39 AUL + 35 EVTX + 15 journald); `RuleBody.version: Option<String>` added to
   `tagging::rule` (`None` for older/hand-written rules outside the shipped packs, e.g.
   from "Tag all matching (advanced)..."); `every_shipped_rule_file_parses_and_is_versioned`
   guards every shipped file has a non-empty version going forward.
2. **Diff computation — done.** `tagging::pack_diff::diff` — pure function,
   `BTreeMap<String, String>` (name → version, chosen over `HashMap` specifically for
   deterministic iteration/output order) in, `RulePackDiff { new, modified, removed }` out.
   No I/O, no UI, no dependency on steps 3+.
3. **`scripts/publish_rule_pack.py` — done.** Builds `dist/peach-rules-v{N}.zip` (+ an
   unzipped `dist/peach-rules-v{N}/` copy for inspection) from `rules/examples/*.toml` per
   §6. `N` defaults to the highest existing `peach-rules-v\d+` git tag plus one (read-only
   `git tag --list` lookup, never creates a tag itself); `--version`/`--min-peach-version`
   override the defaults. Fails loudly (non-zero exit, clear message) on a rule file with
   no `version`, rather than silently shipping an unversioned entry. `dist/` gitignored —
   build artifact, not committed. Publishing itself stays manual (the script prints the
   `gh release create` command, doesn't run it).
4. **Bundle loading & integrity check — done.** `tagging::pack_bundle::load_pack_bundle` —
   extracts the zip, parses `manifest.toml`, rejects a bundle whose `min_peach_version` is
   newer than the running Peach, verifies every listed file's SHA-256, and (the one thing
   `.peachcase` doesn't need to check) rejects an unaccounted-for extra file smuggled into
   the zip that the manifest never mentioned. Mirrors `.peachcase`'s `ScratchDir`/
   `extract_zip`/SHA-256 shape but doesn't share code with it — those helpers are private
   to `session::portable_case`, so this module has its own small copies rather than
   restructuring visibility across two unrelated domains for it. 11 unit tests plus a
   manual end-to-end check against a real `publish_rule_pack.py`-built bundle (89 files,
   loads and verifies correctly).
5. **Tier-2 storage & wholesale replacement — done.**
   `tagging::rule_file::default_applied_pack_dir` (a sibling of `default_user_rules_dir`,
   same `ProjectDirs` layout, own `rule_pack` subdirectory — nothing writes into it yet,
   that's step 7's UI). `tagging::builtin::active_builtin_rules(applied_pack_dir)` reads
   it: empty/missing/unreadable → falls back to the embedded baseline unchanged; present
   and every file parses → wholesale replaces the baseline (not merged); even one file
   failing to parse → falls back to the *whole* embedded baseline rather than a partial
   tier-2 set, matching §4's "always a full snapshot" invariant. `manifest.toml` (which
   `scan_rules_dir` would otherwise also pick up as a `.toml` file) is explicitly skipped,
   not treated as a broken rule. Wired into both places `app.rs` previously called
   `all_builtin_rules()` directly (the `enabled_builtin_rules` seed in `PeachApp::new`, and
   `load_rules`). Tier 3 (the existing user rules directory) is untouched by any of this —
   still scanned and merged in exactly as before.
6. **Activity Log: per-rule version stamps — done.** `persist::ActivityRuleCount` gained a
   `version: Option<String>` field (`#[serde(default)]` — `tags_by_rule` is a JSON blob
   column, so this needed no SQL migration, just a new optional key an old row's JSON
   simply doesn't have). `app::rule_version_lookup` resolves the same rule set a load/re-tag
   actually used (`load_rules`) into a `name → version` map; `rule_counts_to_activity_counts`
   stamps it onto each `ActivityRuleCount` when building the log entry. Both
   `record_load_activity_entry`/`record_retag_activity_entry` now take the existing
   `RuleSelection` struct (reused, not a new one — kept the argument count under clippy's
   `too_many_arguments`) instead of computing counts alone. `ui::activity_log_dialog` shows
   `rule_name (vN): count tags` when a version is present, falling back to the old
   unversioned line otherwise. Tests: version stamping + sort order, an unknown-to-the-
   lookup rule name falling back to `None` rather than panicking, and old-format JSON
   (no `version` key at all) still deserializing.
7. **UI: "Rule packs..." window.** Split into three parts:
   - **7b, the "apply" logic — done.** `tagging::pack_bundle::apply_bundle(bundle, dest_dir)`
     — empties `dest_dir` (tier 2, `default_applied_pack_dir()`) and moves every verified
     file from the bundle's extracted directory into it, wholesale per §3/§4. Reuses
     `.peachcase`'s `rename`-falling-back-to-copy+delete pattern for cross-filesystem moves
     (own small copy, same non-sharing rationale as the rest of this module). Cleans up
     the scratch extraction directory afterward regardless of success/failure. 3 new tests
     (empty dest, wholesale-replaces a stale previous pack including its old manifest.toml,
     creates dest_dir if missing).
   - **7a, the update check — done.** New module `tagging::pack_update` — **the app's first
     and only network call**, ureq (chosen over reqwest specifically to stay synchronous,
     matching the existing `std::thread::spawn`+`mpsc` background-work pattern instead of
     pulling in an async runtime). `check_for_update(current_pack_version)` hits GitHub's
     Releases API, `pick_latest_update` (pure, unit-tested without network — 9 tests: tag
     parsing, picks-highest, ignores app-release tags/tag-without-matching-asset, respects
     `current_pack_version`) picks the newest `peach-rules-v{N}` release with a matching
     `.zip` asset. `download_update` fetches the bytes only — verification stays
     `pack_bundle::load_pack_bundle`'s job. Manually verified against the real repo's
     GitHub API (correctly returns `Ok(None)`, since no `peach-rules-v*` release exists
     yet) via a throwaway example, cleaned up after.
   - **7c, the actual dialog — built, pending the user's own visual test.**
     `ui::rule_pack_dialog` (self-contained, mirrors `ui::session_dialog`'s own-background-
     thread shape rather than routing through `app.rs`'s shared file-pick machinery — no
     native OS dialog is involved here, only drag-and-drop, so nothing to share). Header
     shows active pack version (or "built-in baseline"); "Check for updates" and a native
     `egui` drop zone both land on the same verify → diff-preview → Apply flow; Apply moves
     the bundle into `default_applied_pack_dir()` via `pack_bundle::apply_bundle`, then
     offers an immediate re-tag (routed to `app.rs`'s existing `start_retag` via a small
     `RulePackDialogOutcome`, same division of labor as `SessionManagerOutcome::Open`).
     Menu entry: File → "Rule packs...", next to "Settings..." — moved there from an
     initial Help placement (next to "Rules reference...") after the user flagged Help as
     the wrong home: Help is read-only reference/about content, and this dialog actually
     changes application state, same category as "Settings..." and "Manage sessions...".

     **Update, found via the user's own live test: drag-and-drop doesn't work on
     Wayland.** Checked directly in winit 0.30.13's source — `WindowEvent::DroppedFile` is
     only implemented for the macOS/X11/Windows backends; the Linux Wayland backend has no
     drag-and-drop code at all, and 0.30.13 is the latest release, so there's no newer
     version to pick up support from. Not a bug in this dialog, and not fixable here — same
     class of upstream Wayland gap as the earlier dialog-hang bug (see
     [[peach_format_dialog_hang_2026-08-17]]). Added a **"Browse..." button** as the
     actual answer for Wayland, not just a nice-to-have: routes through `app.rs`'s shared
     `FilePickOutcome`/`file_pick_rx` (the same native-dialog machinery every other picker
     in this app already uses — `rfd`, which goes through `xdg-desktop-portal` and works
     regardless of X11/Wayland), landing on the same `pack_bundle::load_pack_bundle` verify
     path as a drop via a new shared `start_verify_file` helper and a public
     `RulePackDialog::begin_verify_file` entry point. Drag-and-drop itself was kept in the
     code (works on X11/Windows/macOS, and free if winit ever adds Wayland support) — the
     module doc and the drop-zone's own label both now say plainly that Browse is the
     reliable path, not just an alternative.

     Also fixed same-day: the header showed no version at all for the built-in-baseline
     case (embedded rules have no `pack_version`, only a downloaded bundle's manifest
     does) — now shows the running Peach version instead, since the embedded baseline is
     versioned in the sense that matters (one fixed snapshot per Peach release).

     15 tests total for the dialog's own logic (`poll()`'s state machine +
     `begin_verify_file`'s no-op/reject/in-flight-guard cases) — rendering and drag-and-drop
     itself still aren't unit-testable (same live-desktop-only limit as
     `rules_reference_dialog`'s window-sizing bugs). A `dist/peach-rules-v99.zip` test
     bundle (deliberately an out-of-sequence version, obviously not a real release) sits in
     the repo root (gitignored) for the user's own testing.
8. **Docs.** `docs/user-guide.md` gets the new window documented; `CONTRIBUTING.md` gets a
   short note on how to cut a rule-pack release (`publish_rule_pack.py` + `gh release
   create`), same spirit as its existing build/release section.

Steps 1–4 have no UI dependency and could land as their own reviewable slice before step 5
onward touches how Peach actually loads rules at startup.
