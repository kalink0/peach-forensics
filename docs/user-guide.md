# Peach User Guide

This covers how to operate Peach today. For what source types are actually
supported, see [supported-sources.md](supported-sources.md) — this guide assumes
you already know which sourcetype you're loading.

Every dialog (About, Settings, Notes, Tag this event/Advanced tagging,
View raw/fields, Define format, Manage sessions, Time range) opens as a
window confined to the main Peach window — draggable within it, but not
off it or onto a second monitor. (An earlier version of this behavior used
egui's multi-viewport support to make dialogs fully independent OS
windows; that was reverted before v0.2.0 after it turned out to hang the
whole app on at least one real Wayland desktop, opening even the simplest
dialog. See the v0.2.0 changelog entry for details.) Close a dialog via its
own Cancel/Close/OK button, or the small **✕** in its title bar.

## Loading a source

1. Pick a **Sourcetype**: `AUL (.logarchive)`, `EVTX`, `journald`,
   `Text (config-based)`, or `Android Intrusion Log`.
2. Click the picker button:
   - AUL expects a folder — the `.logarchive` bundle itself (it contains
     `Persist`/`Special`/`Signpost`/`HighVolume` subfolders plus `dsc`/`uuidtext`/
     `timesync` reference data). One `.logarchive` becomes one source.
   - Android Intrusion Log also expects a folder — the `intrusion-logs/`
     directory an [AndroidQF](https://github.com/mvt-project/androidqf) or
     [ALEX](https://github.com/prosch88/ALEX) acquisition produces
     (searched recursively for `.txt` files). One folder becomes one
     source, same as AUL. See
     [supported-sources.md](supported-sources.md) for what this sourcetype
     covers and, importantly, what it doesn't (acquisition/decryption is
     outside Peach's scope).
   - EVTX/journald/Text's **"Choose ... file(s)..."** button supports
     selecting several files at once (e.g. `Application.evtx` +
     `Security.evtx` + `System.evtx` together) — the first one becomes the
     current source, the rest queue up ("N more source(s) queued", same as
     `--add-source`) and become the current source in turn as each load
     finishes. Each still needs its own **Load** click; a multi-select
     doesn't load itself automatically, since different queued files can
     need different settings (sourcetype, parser config) before loading.
   - Any of them also has a **"Choose folder..."** button, which recursively
     loads every matching file under that folder (and subfolders) as
     separate sources in one go — no per-file **Load** click needed, but
     also no per-file control over settings first. Text expects a
     **parser config** (TOML) either way — see below.
3. Optionally choose one or more **tagging rules** (TOML, multi-select) — see
   [Tagging](#tagging).
4. Click **Load**. Loading runs in the background so the UI stays responsive; a
   large AUL source can take a while and insert millions of rows.

**Abort** appears next to **Load** while a load is running. It stops after the
file currently being parsed finishes (or, for one very large file, at the next
internal checkpoint — every 10,000 entries) — whatever's already been inserted
stays, nothing gets rolled back. The result shows **"Aborted"**, with the real
(partial) counts alongside it, and a `--add-source`/multi-select queue does
**not** auto-continue into its next file after an abort.

Peach never auto-detects a format — you always confirm the sourcetype yourself.

A file that `--add-source`, a multi-select pick, or **"Choose folder..."**
finds but that produces zero timeline entries (a real parse error, or a
file that parsed cleanly but matched nothing — e.g. an EVTX channel that's
never logged anything) shows up as **"N file(s) skipped"** next to the load
result, rather than silently vanishing from the count. Hover it for the
exact path and reason per file.

**Skip bad records instead of failing** (checkbox next to **Load**, off by
default) changes what happens when a *single* line/record inside an
otherwise-good file can't be parsed. Normally that aborts the whole file —
nothing from it loads, and it shows up in the skipped-files list above.
With this checked, the bad record is skipped and counted instead, and the
rest of the file still loads normally. How many records were skipped (and
why) shows up both in the load result and, per file, in the
[Activity Log](#activity-log) — along with whether skip mode was even used
for that load, since tolerating corruption is itself worth knowing about
later. For journald specifically, a corrupted individual entry is always
skippable this way, but a corrupted *structural* header (rare) isn't — there's
no safe way to find the next record without guessing at the file's layout,
so parsing stops there; everything read up to that point still loads
normally, with a note explaining where and why it stopped.

### Text parser configs

A text source needs a TOML file describing how to parse it: a regex with named
capture groups, a timestamp format, and a mapping from capture groups to Peach's
normalized `level`/`message` fields. Example:

```toml
[parser]
name = "nginx_access"
sourcetype = "nginx"

[parser.pattern]
regex = '^(?P<timestamp>\S+) (?P<level_raw>\w+) (?P<msg>.*)$'
timestamp_format = "%Y-%m-%dT%H:%M:%S%z"
# multiline_start_pattern = '^\d{4}-\d{2}-\d{2}'   # optional, for multi-line events
# assume_offset = "+02:00"                          # only if timestamp_format has no timezone
# assume_year = 2026                                # only if timestamp_format has no year

[parser.field_mapping]
level = "level_raw"
message = "msg"
```

- `timestamp_format` **must** resolve to an absolute time. If it doesn't carry its
  own timezone (no `%z`), set `assume_offset` explicitly (`"+02:00"`, `"UTC"`, …) —
  Peach refuses to guess a timezone. Some very common formats (classic BSD
  syslog, Android logcat) don't carry a year either; set `assume_year` the
  same way for those — Peach refuses to guess that too (silently assuming
  "this year" would be flatly wrong for the historical log files forensic
  work usually deals with). If a source's own config leaves `assume_offset`
  unset, Peach falls back to **"Assume timezone for logs with no timezone
  of their own"** — visible and directly editable right in the load
  controls once **Text (config-based)** is selected (also in [Settings](#settings),
  same field either way).
- `multiline_start_pattern` groups continuation lines (e.g. stack traces) into the
  event whose first line matched the pattern; without it, every line is its own
  event.
- Every named capture group ends up in the entry's `fields`, not just the ones
  used in `field_mapping` — useful for tagging rules and search (`fieldname=...`).
- A line that doesn't match `pattern.regex` aborts the whole parse with a clear
  error (including the line number) rather than being silently skipped.

Hand-editing that TOML isn't the only way to get there: with `Text (config-based)`
selected and a source file picked, **"Define format..."** opens a builder for it
instead — the same fields as above, plus a live preview against the first 20
lines of the actual picked file. Each preview line shows its named capture
groups colour-highlighted, and underneath, the exact level/message/timestamp
a real load would produce for that line (or its exact error, if it wouldn't
parse) — the preview calls the same parsing code a real **Load** does, so it
can't show something a real load would then contradict. **Save** writes the
config to a per-user library (without touching whatever's currently selected
for the pending load); **Save & Use** does the same and also makes it the
active parser config, closing the dialog. **Load** next to the saved-configs
dropdown pulls an existing config's fields back in for editing/reuse.

**Built-in formats** (next to the saved-configs dropdown) has the same
**Load** flow, but for a small built-in starter library instead of your own
saved configs — Generic timestamp (`YYYY-MM-DD HH:MM:SS`, the shape most
hand-rolled application logs use), Syslog (RFC 3164), Android Logcat (brief
format), Pacman log (`/var/log/pacman.log` on Arch/Manjaro/
EndeavourOS — package install/upgrade/removal history, forensically
relevant for a supply-chain or "what got installed and when" timeline),
Apache Common/Combined Log Format, and Nginx Access Log (combined) — the
three web-server formats all map the HTTP status code to `level` (so
`level=404`/`level~^5` filters work) and the full request line to
`message`, with `ip`/`user`/`referer`/`user-agent`/`bytes` still visible per
event via "View raw/fields" even though the search grammar has no dedicated
term for them yet.
These are starting points, not an auto-detector: loading one fills in the
fields for you to check against the live preview, not something that
applies itself blindly — a real log's exact shape varies too much for
that, and two of the four (syslog, logcat) genuinely have no year or
timezone in them at all, so `assume_offset`/`assume_year` almost always
need filling in afterward for those two specifically (pacman's own
timestamp already carries both, so neither is needed there). See
[parsers/examples/](../parsers/examples/) for the actual shipped files.

## Tagging

Tagging rules are TOML files matching entries against normalized fields
(`sourcetype`, `level`, `message`) or source-specific fields inside `fields`:

```toml
[rule]
name = "failed_logon"
description = "Windows failed logon"

[rule.match]
sourcetype = "evtx"
event_id = 4625

[rule.tag]
value = "auth_failure"
```

`message_contains` is a substring variant of `message`: a string or array of
strings, matching if the entry's message contains *any* of them. This is the
main mechanism for pattern-of-life categorization, where messages carry
variable data around a recognizable fixed substring:

```toml
[rule.match]
sourcetype = "aul"
message_contains = ["Screen did lock", "screen is unlocked"]
```

`rules/examples/aul_*.toml` is a pattern-of-life rule pack for AUL (39 rule
files covering human presence/handling, communication and input, application
activity, connectivity, device state and power, media/audio/camera, motion
and vehicle, and emergency SOS) — most predicates are sourced from "Apple
Unified Log Predicates in iLEAPP: The Reference" (Alexis Brignoni),
leapps.org/blog-post?post=2026-08-01-unified-log-predicate-reference, with a
handful of newer, higher-precision ones (dialed-number recovery via
CommCenter, device orientation, Apple Watch Crown/button, CarPlay
handshake) from Tim Korver's [Thesis Friday](https://thesisfriday.com/)
series instead — see each rule file's own header comment for its specific
citation either way, rather than re-deriving predicates from scratch.
SMS/message *content* is still out of scope — that lives in a separate
SQLite database Peach doesn't parse — but call tracking itself
(`aul_call_events.toml`, and the more direct `aul_dialed_number_recovery.toml`)
is covered directly from Unified Log predicates.

`rules/examples/evtx_*.toml` is the tagging companion to the built-in EVTX
message templates (see [field-extraction.md](field-extraction.md#message-templates-evtx)):
41 rule files covering Security-Auditing event IDs those templates render or
otherwise high forensic value — logon/logoff (4624/4625/4634/4648/4672),
process creation and exit (4688/4689), service install (4697, and 7045 from
the System log, not gated behind a special audit subcategory the way 4697
is), service start type changed (7040, defense-evasion indicator), account
lifecycle
(created/enabled/disabled/deleted/locked/unlocked: 4720/4722/4725/4726/4740/4767),
self vs. admin password changes (4723/4724), group management
(4728/4732/4756), credential validation (4776), Kerberos TGT/service ticket
requests and replay attacks (4768/4769/4649 — domain-controller-only, base
signal for Kerberoasting/Golden Ticket detection), SMB share connections and
access checks (5140/5145), object access attempts (4663, requires a SACL),
scheduled task creation/deletion (4698/4699), RDP session reconnect/
disconnect (4778/4779), PowerShell Script Block Logging and Module Logging
(4104/4103, a different channel/provider than the rest of this pack — see
those rule files' header comments), system time changes (4616, an
anti-forensic/timestomping indicator, always logged regardless of audit
policy), boot/shutdown (6005/6008/41/1074), and the audit log being cleared
(1102) — cross-checked against Microsoft's official Security Auditing event
reference (or, for 4104/4103/7045/boot-shutdown, other primary sources — see
each rule file's header comment for its specific citation).
`event_id`/`provider` are normalized match keys resolved against EVTX's
actual nested `Event.System.*` JSON shape, not a flat top-level lookup —
see `tagging::rule::normalized_field`'s doc comment if writing a custom
rule against these fields yourself.

`rules/examples/journald_*.toml` is journald's rule pack: 18 rules covering
SSH logon success/failure/logoff, sudo command usage/denial, privilege
escalation via `su`, generic login-session open/close via `systemd-logind`
(console, graphical, or su/sudo — not just SSH), a generic PAM
authentication-failure catch-all for services without a dedicated rule,
password changes, account lifecycle/group membership changes via
`useradd`/`userdel`/`usermod`, cron job execution, and a kernel boot marker.
Message text sourced directly from OpenSSH, sudo, shadow-utils', and
systemd's own logging code (see each rule file's header comment for its
specific citation) — journald has no structured `event_id` the way EVTX
does, so most rules scope themselves to a specific `process` (journald's
`SYSLOG_IDENTIFIER`) or trusted field (`_TRANSPORT`, for the kernel boot
marker) as well as matching on message text, to avoid two unrelated daemons
coincidentally sharing a substring — the generic PAM failure rule is the one
deliberate exception, scoped to message text alone.

`rules/examples/intrusion_log_*.toml` is the Android Intrusion Log rule
pack: 48 rules — one per Android SecurityLog tag (~46 of them, e.g.
`keyguard_dismiss_auth_attempt` for a failed unlock attempt,
`cert_authority_installed` for a root certificate install — a classic
MITM/spyware indicator, `adb_shell_cmd`, `wipe_failure`,
`package_installed`/`updated`/`uninstalled`) plus `dns_event` and
`connect_event`. Tag IDs and descriptions sourced from Android's own AOSP
`SecurityLogTags.logtags`/`SecurityLog.java`; the JSON format and each
event's tag key cross-confirmed against two independent tools that parse
real device exports of the same format — Amnesty's own [Mobile
Verification Toolkit](https://github.com/mvt-project/mvt) and
[ALEAPP](https://github.com/abrignoni/ALEAPP) (see each rule file's header
comment for the specific citation). Every rule
matches `sourcetype = "intrusion_log"` plus `event_type`/
`security_event_tag`, two fields
`parsers::intrusion_log::IntrusionLogParser` derives onto each entry
rather than fields Android's own JSON carries directly — see
[supported-sources.md](supported-sources.md) for that derivation.

Unlike other rule files (which load either automatically from the
configured [rules directory](#settings) or by explicit selection via
"Choose tagging rules..."), all four packs ship **embedded in the binary
itself** (`build.rs` bundles every `rules/examples/aul_*.toml`,
`rules/examples/evtx_*.toml`, `rules/examples/journald_*.toml`, and
`rules/examples/intrusion_log_*.toml` file at compile time — see
`src/tagging/builtin.rs`) and every rule in them is applied automatically
on every load and re-tag by default — no file to locate or select, works
the same in a release build with no repo nearby. Every rule matches its
own `sourcetype` on its own, so an enabled AUL rule never tags an EVTX,
journald, or intrusion_log row, or vice versa.

**Built-in rules...** (next to "Choose tagging rules...", only shown when
relevant to the current source) opens a picker listing every rule from
whichever tier is currently active — AUL, EVTX, journald, and Android
Intrusion Log in their own sections, each rule a checkbox (hover one for
its full match condition, tag, and description), plus **Select
all**/**Select none** per section. Like
[Rules reference...](#tagging), this reflects a downloaded pack (see
"Updating the built-in rule packs" below) if one is currently applied,
not just the version embedded in this build. This is exact, per-rule
control, not just a whole-pack on/off switch: enable only the three or four
AUL rules you actually care about for this case, say. See
[rules-reference.md](rules-reference.md) for the same information as a
static, browsable table generated from the packs embedded at build time
(so it won't reflect a downloaded pack the way this picker and the in-app
**Help → Rules reference...** dialog do).

### Updating the built-in rule packs

**File → Rule packs...** gets a curated update to the built-in
AUL/EVTX/journald/intrusion_log packs into a running Peach without waiting
for the next app release — bundles are published separately, at
[kalink0/peach-rules](https://github.com/kalink0/peach-rules).
The window shows what's currently active (either the packs embedded in this build, or a
previously-applied downloaded pack's version) and three ways to get a new one:

- **Check for updates...** — the only network request anywhere in Peach, and only ever
  runs when you click this. Offers the newest published pack, if it's newer than what's
  currently active.
- **Browse...** — pick a `peach-rules-vN.zip` bundle (downloaded from a
  [release](https://github.com/kalink0/peach-rules/releases) yourself, say) via the
  normal native file dialog.
- **Drag a bundle onto the window** — same effect as Browse, if your desktop environment
  supports drag-and-drop onto Peach. It doesn't everywhere: Linux/Wayland currently
  doesn't (a `winit`/windowing-library limitation, not something Peach can work around) —
  use Browse there instead.

Either path leads to the same preview before anything changes: which rules are new,
modified, or removed relative to what's currently active, computed from each rule's own
version rather than a hand-written changelog. Nothing is applied until you click
**Apply**. A pack is always a complete, self-contained snapshot of every
AUL/EVTX/journald/intrusion_log rule (never a partial update), verified
(SHA-256 per file, checked against the bundle's
own manifest) before it's ever trusted — a corrupted or tampered download is refused, not
applied best-effort. After applying, Peach offers to **re-tag** the current session
immediately; skipping that just means the new rules only apply to sources loaded from now
on, same as changing any other rule selection.

Beyond the built-in packs, every `*.toml` file directly in the configured
[rules directory](#settings) — your own personal rule collection, see
Settings — loads automatically, no selection needed. **Choose tagging rules
(TOML, optional)...** additionally lets you pick specific files from
anywhere else (it opens in the rules directory by default); doing so
replaces the current selection rather than adding to it, so it's "pick your
whole set" rather than "add one more". Either way, the count next to the
button ("N rule file(s) selected") reflects what's actually active,
auto-loaded and manually picked alike.

Three modes:

- **Import-time**: rules selected before clicking **Load** are applied
  automatically as entries are inserted.
- **Re-tag**: click **Re-tag now** to re-evaluate the currently selected rules
  against *everything* already loaded. This **replaces** all import-time tags —
  it's a full recompute, not an incremental patch, so a changed or removed rule
  never leaves a stale tag behind.
- **Ad-hoc / analyst tags**: query-time evaluation exists at the engine level
  with no dedicated UI yet. Manual, per-entry tags (`analyst_tags`) do have a
  UI — see below.

**Right-click a row** in the timeline for these actions:

- **Copy message** — copies just the `message` field to the clipboard.
- **Copy whole event as text** — copies timestamp, level, tags, message, and
  `raw` (the full original record/line) as a plain-text block.
- **View raw/fields...** — same data as "Copy whole event as text", shown in
  a read-only, scrollable, selectable window instead of only going to the
  clipboard: `raw` (the full original record/line) and `fields` (the
  source-specific JSON — for AUL/EVTX/journald/intrusion_log this largely
  overlaps `raw`, but for a `text_config` source it's genuinely different: `raw` is the
  literal original line, `fields` is what the regex captured out of it).
- **Filter by...** — a submenu listing whichever of the clicked row's
  Sourcetype/Host/Process/Event ID/Subsystem/Category are actually
  populated for that row (empty ones don't show up); picking one adds (or
  replaces) an exact-match filter for that value, shown as a removable
  chip in the **Active filters** row under the search box. This is
  row-level, not cell-level — the submenu offers every populated field on
  the row you right-clicked, not only whichever column happened to be
  under the pointer.
- **Show context around this event** (± 1 / 5 / 15 / 60 min) — replaces the
  search box with an `after=.../before=...` window centered on the clicked
  row, so you see everything around it rather than only whatever the
  previous filter matched.
- **Tag this event...** — a manual tag on just that one entry, stored in the
  session's `analyst_tags` (SQLite), separate from rule-produced tags because
  it isn't rule-based. Pick an already-used tag from the dropdown or choose
  "New tag...".
- **Tag all matching (advanced)...** — tags every entry that matches a
  condition, with a live preview of how many entries currently match before
  you commit. Choose what to match on via the radio buttons at the top:
  **Message contains** (a substring, prefilled from the clicked row,
  editable) or an exact match on one of the row's own populated fields —
  Sourcetype/Host/Process/Event ID/Subsystem/Category, the same set "Filter
  by..." offers. Switching the radio button reloads the text field with that
  field's own value. Choosing an existing tag that's produced by exactly one
  currently-loaded rule file offers to extend that rule's pattern list
  instead of creating a new one — but only for a **Message contains**
  condition; a field condition always creates a fresh rule file, since the
  tagging engine has no OR-list support for exact-match fields the way
  `message_contains` has. A brand-new tag (or one with no single unambiguous
  owning rule) creates a new rule file under the [rules
  directory](#settings) and asks you to name it. Applying either path
  re-tags immediately, same as clicking **Re-tag now**.

Both the Tags column and the tag picker in these dialogs combine tags from
both `import_tags` and `analyst_tags` — one vocabulary regardless of which
table a tag happened to come from.

The timeline table has a **Tags** column listing every tag on that entry, and
the **Level** column is colored — both from the same 8-color categorical
palette. The color is a deterministic hash of the value, not
assignment-order-based: the same level/tag string always gets the same color,
in this session and every future one, rather than shifting depending on what
order things were loaded in.

### Notes

**Notes...** (also in the row context menu) opens a dialog listing every note
on that event, with Edit/Delete per note and a field to add another —
independent of tags entirely: a note needs no tag to exist, and a tag needs no
note. Stored in the session's `event_notes` table (SQLite), separate from
`analyst_tags`' own unused `note` column for the same reason.

Any row with at least one note shows a 📝 marker in the Tags column (hover for
the full text) regardless of whether the **Notes** column itself is enabled —
that column is opt-in via the **Columns** picker, same as
Sourcetype/Host/Process/Event ID/Subsystem/Category, and shows every note on
each row directly in the table (joined with " | "; hover for one-per-line).

## Search

The **Columns** picker (above the timeline table) toggles Sourcetype, Host,
Process, Event ID, Subsystem, Category, and Notes on or off — Timestamp,
Level, Source, Tags, and Message are always shown. Drag a column header to
reorder it.

The search box (top of the timeline) uses a small, Splunk-inspired query
language. Filters apply live as you type — there's no separate "search" button.

- Bare words / `"quoted phrases"` — substring match against `message` OR `raw`.
- `field=value` / `field:value` — exact match, except `source`/`message`/`raw`
  (substring, like bare-word search — a full path is rarely worth typing out
  in full). Recognized fields: `level`, `sourcetype` (the format —
  `aul`/`evtx`/`journald`/...), `source` (the evidence file's path), `tag`
  (from tagging rules), `message`, `raw`, and every column the **Columns**
  picker can show — `event_id`, `host`, `process`, `subsystem`, `category`.
  Each of those is empty/no-match for whichever sourcetypes don't populate
  that column in the first place (e.g. `event_id=` only ever matches EVTX) —
  see [field-extraction.md](field-extraction.md) for exactly which
  sourcetype populates which. A value with spaces (a process name, a
  hostname) needs quoting right after the `=`, e.g. `process="Windows
  Explorer"` — otherwise the space splits it into two tokens. The row
  context menu's **Filter by...** entry always quotes correctly for you.
- `field!=value` — negated exact match; shorthand for `NOT field=value`
  (identical result, just without the extra word).
- `field~value` — regex match on that field instead of exact/substring.
- `tag=*` — has at least one tag, whichever. Combined with negation,
  `NOT tag=*` means "untagged" — there's no separate keyword for it.
- `source_id=<id>` — exact match against one specific loaded source (not its
  path — the internal id assigned to that one load). Not meant for hand-typing
  (see the **Sources** row below); documented here because it's a real,
  functioning grammar field like any other, not UI-only magic.
- `after=<timestamp>` / `before=<timestamp>` — bounds on `timestamp_utc`
  (UTC, always). Accepts `2026-07-29T10:00:00`, `2026-07-29 10:00:00` (quote
  it — the space would otherwise split into two tokens), with or without
  seconds or fractional seconds, or a bare date (`2026-07-29`, meaning
  midnight). A timestamp that doesn't parse in any of these shapes matches
  nothing, rather than erroring.
- `NOT term` or `-term` — negation.
- Terms are implicitly ANDed; use `OR` explicitly. There's no parentheses or
  operator precedence yet — everything evaluates strictly left to right, in the
  order you typed it. This means several terms joined by bare `OR` only group
  correctly if nothing else in the query is `AND`-ing against them — see the
  next paragraph for how the buttons avoid this trap.

Example: `sourcetype=evtx tag=auth_failure NOT level=INFO "login"`

The **Level**, **Tag**, and **Sources** dropdowns under the search box are a
shortcut: each is a button (e.g. `Level`, or `Level (2)` once something's
selected) that opens a scrollable checklist instead of always showing every
value as its own button — with a rule pack's worth of tags (AUL's built-in
pack alone is 33) or many loaded sources, a permanently-visible row would
otherwise push the timeline further down the screen with every new value.
Each value's checkbox is followed by a count in parentheses, e.g.
`wifi_status (1234)` — a note at the top of every dropdown makes clear
these are for the *whole loaded timeline*, not how many currently match
your search: they're computed once (after a load or **Re-tag now**), not
recomputed on every keystroke, so they'd otherwise be easy to misread as a
live, filter-relative number. "Untagged" doesn't get a count next to it —
nothing computes that one yet.

Every dropdown offers the same two actions, consistently: a small **only**
button next to each value — narrows to just that one value, deselecting
everything else in that field (for Tag, Untagged too) — and a **Show all**
button, pinned below the scrollable list rather than as its last entry, so
it stays reachable without scrolling all the way down first. For Level/Tag,
"Show all" clears the whole selection back to no filter on that field at
all; for Sources, see below.

Checking a box toggles that value in and out of the search box; the list
itself is populated from whatever level/tag values are actually present in
the loaded data (AUL's level names and a text log's ERROR/WARN/INFO have
nothing in common, and which tags exist depends entirely on which rules were
run, so neither list is ever hardcoded). The Tag dropdown only appears once
at least one tagging rule has produced a tag — either from import-time
tagging during Load, or after clicking **Re-tag now**.

Checking several boxes in Level/Tag means "match any of these", not "match
all of these" — but since the grammar above has no parentheses, that can't be
expressed as several `field=value` terms joined by `OR` once anything else in
the query is `AND`-ing against them. Instead, checking boxes writes a single
regex-alternation term, e.g. selecting two tags produces
`tag~^(?:wifi_status|screen_lock_state)$` — one term, so it always combines
correctly with the rest of the query regardless of order. An **Untagged**
checkbox at the bottom of the Tag dropdown toggles `NOT tag=*` for the same
reason it isn't just another value: "no tag" isn't a value that could appear
in the alternation.

**Sources** appears once at least one source is loaded, and works the
opposite way on purpose: it's an *exclusion* list, not an inclusion one.
Every source starts checked (visible, no filter applied at all), and
unchecking one hides that source's rows — the source stays loaded, nothing
is unloaded or re-parsed, it just adds a `NOT source_id=<id>` term. Each
source's label is colour-coded the same way as the Level/Tags columns.
Hiding several sources at once needs no special-casing the way Tag/Untagged
did: each hidden source is its own independent `NOT` term, and plain
`AND`-ing those together already means exactly "not any of these",
regardless of where in the query they end up. Each row also has an **only**
button — hides every *other* loaded source in one click, for isolating a
single source's timeline instead of unchecking everything else by hand —
and **Show all** clears every hidden-source term at once.

A **Time range** button opens a small window offering `after=`/`before=`
via a calendar and a clock instead of typing an ISO timestamp by hand —
check **After** and/or **Before** (either alone is fine), pick a date,
adjust the hour/minute/second spinners next to it if needed (click-drag or
click-to-type, like any other numeric field), then **Apply** (which also
closes the window; so does **Clear**). Defaults to midnight for After and
the last second of the day for Before — "the whole day" is the common
case — freely adjustable from there. A separate window, not a dropdown
like Level/Tag/Sources: the calendar itself opens its own floating popup,
and nesting that inside a dropdown's popup made the outer one close the
instant you tried to click a date — clicking the calendar read as "clicked
outside the dropdown" to the dropdown itself. Both bounds always write the
explicit `<date>T<hour>:<minute>:<second>` form, never a bare date — a
bare date means literal midnight, which as a *before* bound with the time
left untouched would otherwise silently exclude the rest of that day.
**Clear** resets both bounds — there's no **only**/**Show all** pair here
the way the checkbox-list dropdowns have one, since a date range isn't a
list of discrete values to narrow to one of or reset to "every value".

An **Active filters** row appears under the search box once at least one
Sourcetype/Host/Process/Event ID/Subsystem/Category filter is set — see the
row context menu's **Filter by...** entry below for how they get set.
Each shows as a removable chip (`Host = DESKTOP-1 ✕`); click one to remove
just that filter, or **Clear all** to remove every one at once (shown once
there's more than one). Unlike Level/Tag/Sources, there's no dedicated
dropdown for these six fields — they're set from the row you're looking
at, not picked from a list of every possible value up front.

## Settings

**File > Settings...** covers where Peach writes things, and how a folder
load parallelizes:

- **Sessions directory** — where new sessions' `.duckdb`/`.sqlite` files are
  created (see [Sessions](#sessions) below). Defaults to the OS-standard
  per-user data directory; only affects sessions created from now on.
- **Rules directory** — where **Tag all matching (advanced)...** (see
  [Tagging](#tagging) above) writes new rule files, and where Peach looks
  for rules to load automatically. Defaults to the OS-standard per-user data
  directory too, but this one is meant to be pointed elsewhere: at a folder
  you keep under your own git repo, for example, to build up a personal
  rule collection over time, kept separate from `rules/examples/` in the
  Peach repo itself (a read-only reference library, not a place to write
  into). Every `*.toml` file directly in this folder (not subfolders) loads
  automatically on startup and shows up in the "N rule file(s) selected"
  count, the same way the built-in AUL/EVTX packs always apply — a rule
  created in a previous session doesn't need re-selecting by hand every
  time. Changing this and clicking **Save** re-scans the new folder
  immediately, replacing whatever rule files are currently selected
  (including any picked from elsewhere via **Choose tagging rules...**,
  which itself opens in this folder by default).
- **Staging directory** — working space for `--ephemeral-session` and
  Portable Case export/import (see [Portable Case](#portable-case) below);
  can briefly hold a full copy of the bulk timeline. Defaults to the OS temp
  directory.
- **Parse threads for folder loads** — worker threads for parsing a
  multi-file folder load (EVTX/journald/Text) in parallel; automatic by
  default. Irrelevant for AUL, Android Intrusion Log, or a single-file
  load — all three are always exactly one parse unit, nothing to spread
  across threads.
- **Assume timezone for logs with no timezone of their own** — a session-wide
  fallback for a text source's own `assume_offset` (see
  [Text parser configs](#text-parser-configs) above), used whenever that
  source's own config doesn't set one. Accepts a fixed offset (`+0100`,
  `+02:00`, `UTC` — colon optional) or a real IANA zone name
  (`Europe/Berlin`) — a named zone resolves DST correctly across the whole
  timeline, unlike a fixed offset, which would silently apply the wrong
  number to half a case that spans a DST transition. Blank (the default)
  means every text source still needs its own `assume_offset`; never
  applies to AUL/EVTX/journald/intrusion_log, whose own timestamps are
  already absolute.
  A source's own `assume_offset` always wins if it sets one. Also directly
  editable in the load controls once **Text (config-based)** is selected
  (same field, applies and saves immediately either place) — kept in
  Settings too, unlike Display timezone below, since the load-controls
  copy is only visible while Text is the selected sourcetype.

**Display timezone** — what the timeline table and CSV/JSON export render
timestamps in — isn't in this dialog: it's set from **View > Display
timezone...** instead (see [View and Help menus](#view-and-help-menus)),
since that's reachable regardless of what's currently loaded or selected,
so there was no reason to also duplicate it here.

The timezone field above is validated as you type — an invalid value shows
an error underneath and (in Settings specifically) disables **Save** until
it's fixed or cleared.

Every setting's label has a small **?** button next to it — click to
show/hide the full explanation as its own line underneath (also shows on
hover), instead of it always taking up space as its own paragraph.

Both directory settings always show the effective path — prefixed with
"(default)" when no override is set — plus **Choose...** to pick a folder,
**Reset to default** to clear an override, and **Open folder** to reveal it
in the OS file manager (creating it first if it doesn't exist yet).

## Sessions

A session is a pair of files (`<id>.duckdb` for the parsed timeline, `<id>.sqlite`
for tags and search state) created automatically when Peach starts — nothing to
set up. Every successful load and every search-box change is saved into the
current session immediately; there's no separate "save" action.

Peach does **not** reopen your last session automatically. Click **Manage
sessions...** (File menu, or next to the "Session: ..." label in the controls
panel — same dialog either way) and **Open** one to switch to it — this reads
the already-parsed `.duckdb` directly, so it works even if the original
evidence file is no longer reachable, and nothing gets re-parsed.

**File → New session** starts a fresh, empty session without restarting
Peach — same as what happens automatically at startup, but reachable
mid-run. Loaded sources, search/filter state, and the timeline itself all
reset to empty; the session you were on isn't deleted, and stays listed in
**Manage sessions...** as long as it has data in it (an empty one left
behind gets swept up automatically, same as one abandoned by switching
sessions or just closing Peach without loading anything).

Session files live in the OS-standard per-user data directory (not yet
user-configurable): `~/.local/share/peach/sessions/` on Linux, similar
platform-appropriate locations on macOS/Windows.

**Manage sessions...** lists every session found there, each with Open/
Rename/Delete. **Rename...** sets a display name shown instead of the raw
`session-YYYYMMDD-HHMMSS` id everywhere a session is listed (including the
"Session: ..." label once it's the one open) — the underlying `.duckdb`/
`.sqlite` files and the id itself never change, only that label, so renaming
never risks breaking anything path-based. Works on the currently-open
session too, unlike Delete.

There's deliberately no separate "Load session..." file picker anymore: a
native file dialog can only show real filenames, and once a session has a
display name that stopped being a useful way to find one again — "Manage
sessions..." is the only path now, so the friendly name is always what you
see.

A session that arrived via **File → Import portable case...** (see
[Portable Case](#portable-case) below) shows up in **Manage sessions...**
like any other — it's a real, independent session, not a special mode.
Its Activity Log carries an "Import" entry recording which session it came
from, when, and under what filter, so that provenance is never just
implicit.

## Activity Log

**View → Activity Log...** shows every load and re-tag this session has run —
what was loaded, when it started/finished, how many entries were inserted
and tags applied, and which files (if any) were skipped and why. Recorded on
both success *and* failure: a failed load shows up here with its error, not
just as a transient message that's gone once you dismiss it. Persisted in
the session's `.sqlite` (same file as tags/notes), so it survives closing
and reopening Peach — the point is a durable record of what actually
happened to the evidence, not a live status readout. A load run with
**Skip bad records instead of failing** on is marked as such, and shows,
per file, how many records were skipped alongside how many entries were
inserted.

## Export

**File > Export (current filter)...** exports exactly what the timeline is
showing right now — clear the search box first to export everything
loaded. Pick a `.csv` or `.json` destination (either extension works;
anything else defaults to CSV). Streamed in 5,000-row chunks with a
progress readout, so an export of millions of rows doesn't need to hold
the whole result in memory first.

Each exported row has the same normalized columns the timeline table shows
— timestamp, level, source path, sourcetype, host, process, event ID,
subsystem, category, message — plus tags and notes joined into single
fields (`;`- and ` | `-separated respectively, since neither CSV nor a flat
JSON row has a native list type). **`raw` (the original record/line) is
not included** — export is a filtered, normalized view for sharing or
reporting, not a substitute for the original evidence file, which stays
wherever it was loaded from.

The exported `timestamp` column follows the
[Display timezone](#view-and-help-menus) setting, same as the timeline
table — not necessarily UTC. It always
carries its own offset (e.g. `2026-07-28 14:00:00.000 +02:00`), so the
exported value stays unambiguous on its own even without knowing what
Peach was configured to at export time.

## Case Summary

**View > Case Summary...** shows an at-a-glance breakdown of the whole
loaded session: total entries, how many sources and sourcetypes, entries
per source and per sourcetype, a level breakdown, tag coverage (tagged vs.
untagged), the covered time range, and a daily-activity histogram — each
count-based section shown as a small bar chart, colored the same way the
timeline's Level/Tags columns already are. A real gap day (no events at
all) still shows up as a zero-height bar rather than being silently
skipped — a gap in coverage can be as meaningful as the events themselves.
Per-source counts beyond the top 15 are collapsed into a "+N more" line for
readability; nothing is actually left out of the underlying numbers.

This same view also appears in two other places: as a preview before
[Export portable case...](#portable-case) actually runs (scoped to the
active search filter, so it shows exactly what's about to be bundled, with
Cancel/Export... buttons instead of Close), and automatically right after a
successful [Import portable case...](#portable-case), so you see the
result immediately without an extra click.

## Portable Case

**File > Export portable case...** and **File > Import portable case...**
hand a whole session (or a filtered subset of one) to another analyst as a
single `.peachcase` file — a different tool from **Export (current
filter)...** above, not a replacement for it:

| | Export (current filter)... | Export portable case... |
|---|---|---|
| Format | CSV or JSON | `.peachcase` (a ZIP bundle) |
| Contains `raw`/`fields` | No | Yes |
| Contains tags and notes | Joined into text columns | Full analyst tags, notes, and activity log |
| Opens as | A spreadsheet/text file | A brand-new Peach session |
| Use it for | Sharing/reporting a view | Handing off a case for full review in Peach |

Clicking **Export portable case...** first shows a [Case Summary](#case-summary)
preview of exactly what will be bundled — confirm with **Export...** to
pick a destination, or **Cancel** to back out without writing anything.

Exporting bundles exactly what the timeline is currently showing — same
rule as the row export: clear the search box first to bundle the whole
session, or leave a filter active to bundle just the matching subset. A
filtered export still includes every analyst tag and note from the *whole*
session, even ones on entries the filter hides — an annotation you wrote
never silently disappears just because of the filter used at export time.
Referenced text-parser configs (for `text_config` sources like syslog or
Apache/Nginx) are bundled as reference copies too, so the recipient can see
exactly how a source was parsed.

**`raw` never leaves the bundle** — every entry's original record/line
travels byte-for-byte, unlike the row export.

Importing always opens the bundle as a **new, independent session** — it
never touches or merges into the session you're currently in. Evidence file
paths recorded in the bundle are shown for reference only; Peach never
tries to re-locate the original evidence on the importing machine (loading
more evidence into an imported session works exactly like any other
session — point Peach at the files again if you have access to them). A
[Case Summary](#case-summary) of the freshly-imported session opens
automatically so you immediately see what you received.

A `.peachcase` file carries an integrity check (computed at export, verified
at import) — a bundle that was corrupted or modified in transit is refused
with a clear error rather than imported anyway. A bundle exported by a
newer version of Peach than the one importing it is refused the same way,
rather than risking a partial or wrong import.

## View and Help menus

**View > Theme** switches the window chrome: System default (follows the
OS light/dark setting), Light, Dark, Geek (a phosphor-green terminal look),
or Rainbow (continuously hue-cycling, animated). Persisted across restarts.
**View > Display timezone...** opens a small window with a single field —
what the timeline table and CSV/JSON export render timestamps in. Accepts
a fixed offset (`+0100`, `+02:00`, `UTC`) or a real IANA zone name
(`Europe/Berlin`); blank means UTC. Applies and saves immediately as you
type, no separate **Save** click. Display-only: what's stored on disk
stays UTC regardless, and every rendered/exported value always carries its
own offset (e.g. `2026-07-28 14:00:00.000 +02:00`), so it stays
unambiguous even if this setting changes later. **View > Activity Log...**
is covered above.

**Help > Rules reference...** opens the same rule table as **Built-in
rules...** (described under [Tagging](#tagging) above) in its own window,
formatted for reading rather than for enabling/disabling — reflects
whichever tier is currently active (built-in baseline or a downloaded
pack, see "Updating the built-in rule packs" under Tagging), works fully
offline either way (no browser, no network, nothing extra to carry to an
airgapped analysis machine). Has its own filter field for jumping to a
rule/tag by name instead of scrolling, plus an **Open on GitHub...**
button for the same table rendered on GitHub — only enabled while the
built-in baseline is active, since a downloaded pack has no single
matching page there.
**Help > About Peach...** covers version info, licenses, and the research
sources behind the built-in rule packs.

## Command line

```sh
peach --add-source <path> [--add-source <path> ...] [--cleanup-dir <path> ...] [--ephemeral-session]
```

`--add-source` pre-fills the source picker (sourcetype guessed only as
directory-implies-AUL, never a text-format guess) — you still confirm and click
**Load** yourself. Multiple `--add-source` flags queue up; after each load
completes, the next one pre-fills automatically. `--cleanup-dir` deletes a
directory when Peach closes, but only if it's actually under the OS temp
directory — a safety net, not something to rely on for arbitrary paths.

`--ephemeral-session` skips session persistence for the run entirely: instead of
the usual persistent sessions directory, the session's `.duckdb`/`.sqlite` live in
a one-off temp directory that's removed on close no matter what it holds — use
this when the source itself came from a temp extraction or a decrypted copy, so
Peach doesn't leave a second, unencrypted copy of that data sitting around after
you're done. The session won't show up in "Manage sessions..." either, since it
never lived in the persistent sessions directory to begin with.

Exporting a [Portable Case](#portable-case) still works normally from an
ephemeral session — it's the sanctioned way to hand review results to
another analyst from this kind of run: the exported bundle holds only
Peach's derived data (parsed entries, tags, notes), never the original
evidence, so it doesn't recreate the unencrypted-copy problem
`--ephemeral-session` exists to avoid.
