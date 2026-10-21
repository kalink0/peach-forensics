### Peach UI text, English — the reference every translation is checked against.
###
### Translators: copy this file to i18n/<language-code>/peach.ftl and
### translate the text right of each "=". See i18n/README.md for the rules
### (what must stay as-is, how placeholders work, how CI checks your file).

# Name of this language, written in the language itself (e.g. "Deutsch",
# "Français"). Shown in the Settings language list.
language-name = English


## Shared buttons and labels, reused across dialogs.

common-save = Save
common-cancel = Cancel
# Button that opens a folder picker.
common-choose = Choose...
common-reset-to-default = Reset to default
# Button that opens the folder in the system file manager.
common-open-folder = Open folder
common-close = Close
common-edit = Edit
common-delete = Delete
common-add = Add
# A directory setting that is not overridden. $path is the full directory
# path, keep it in the text.
common-default-path = (default) { $path }


## Settings dialog (menu: File > Settings).

settings-title = Settings

settings-language = Language:
settings-language-help = Translations are maintained by the community and can be incomplete — anything not translated yet is shown in English. Log data, tags, rules, the search syntax and exports are never translated.
# One entry in the language list. $name is the language's own name
# (language-name above), $code its code such as "de", $percent how much of
# it is translated (0–100).
settings-language-entry = { $name } ({ $code }) — { $percent }% translated
# Same, for a language whose file doesn't set language-name yet.
settings-language-entry-unnamed = { $code } — { $percent }% translated
# A language whose file is broken and therefore can't be selected.
settings-language-entry-broken = { $code } — file has errors, see i18n/README.md
# Shown below the list when the configured language can't be used. $code is
# the language code from the config file.
settings-language-unavailable = Language "{ $code }" is not available or its file has errors — showing English.

settings-sessions-dir = Sessions directory:
settings-sessions-dir-help = New sessions only — the current session stays put.
# The same setting's name without the colon, used when other texts point
# to it (e.g. "Settings → Sessions directory").
settings-sessions-dir-name = Sessions directory

settings-rules-dir = Rules directory:
settings-rules-dir-help = Where new rules get saved, and auto-loaded from on startup.

settings-staging-dir = Staging directory:
# "--ephemeral-session" is a command-line flag: keep it exactly as written.
# "Portable Case" is the name of a Peach feature.
settings-staging-dir-help = Working space for --ephemeral-session and Portable Case export/import — can hold a full copy of the bulk timeline.

settings-load-threads = Parse threads for folder loads:
# EVTX, journald and Text are log format names: keep them as written.
settings-load-threads-help = Only matters for multi-file EVTX/journald/Text loads.
settings-load-threads-automatic = Automatic
# $count is the number of threads picked automatically.
settings-load-threads-on-this-machine = ({ $count } on this machine)

settings-memory-limit = Database memory limit (MB):
settings-memory-limit-help = RAM the timeline database may use. Beyond it, data spills to a temp folder next to the session file. Raising it rarely speeds up loading.
settings-memory-limit-default = Default
# $mb is the default limit in megabytes.
settings-memory-limit-default-value = ({ $mb } MB)

settings-source-timezone = Assume timezone for logs with no timezone of their own:
# "Assume offset" is the label of a field in the load controls; use the same
# wording as that field's translation.
settings-source-timezone-help = Fallback when a text source's own "Assume offset" isn't set.
# Input hint. The examples (+0100, +02:00, UTC, Europe/Berlin) are values
# Peach accepts: keep them exactly as written.
settings-source-timezone-hint = +0100, +02:00, UTC, or Europe/Berlin — blank to disable


## About dialog (menu: Help > About).

about-title = About Peach
about-tab-about = About
about-tab-acknowledgements = Acknowledgements
# Subtitle next to the copyright line. "DFIR" is a fixed abbreviation.
about-tagline = DFIR Log Workbench
# AUL, EVTX, journald and TOML are format names: keep them as written.
about-description = A lean, local-first DFIR log workbench. Parses log sources — AUL, EVTX, journald, and TOML-configurable text logs — into a normalized, taggable timeline, with a Splunk-inspired search syntax and semantic tagging.
# "crush" is the name of another tool (lowercase): keep it as written.
about-crush = Runs standalone, or can be started and handed evidence paths by crush, then continues completely independently (no IPC).
about-dedication = Thank you to someone special — for every word of encouragement, for believing in me, for motivating me, and for the inspiration.
about-license = Licensed under the Apache License 2.0
about-report-bug = Report a bug or request a feature

acknowledgements-intro = Peach is built on the shoulders of the open-source and DFIR community.
acknowledgements-dependencies = Rust crate dependencies
# Role column of the dependency table. Product names (DuckDB, SQLite, AUL,
# EVTX) and "Public Domain" (a license) stay as written.
acknowledgements-role-gui = GUI framework
acknowledgements-role-duckdb = Bulk timeline storage (bundles DuckDB itself)
acknowledgements-role-rusqlite = Session DB (bundles SQLite, Public Domain)
acknowledgements-role-aul = AUL (.logarchive) parsing
acknowledgements-role-evtx = Windows EVTX parsing
acknowledgements-role-rfd = Native file dialogs
acknowledgements-research = Research
# The research paragraphs below credit sources. $files are file paths, $url
# a web address, $title a publication title: Peach fills them in. Keep
# people's and project names as written.
acknowledgements-research-aul = The built-in AUL rule pack ({ $files }) is built on predicates from "{ $title }" by Alexis Brignoni, rather than re-derived from scratch — { $url }.
acknowledgements-research-evtx = The built-in EVTX message templates and tagging rule pack ({ $files }) are cross-checked against Microsoft's official Security Auditing event reference for each event ID — { $url }.
acknowledgements-research-thesis-friday = A handful of newer AUL predicates (dialed-number recovery, device orientation, Apple Watch Crown/button, CarPlay handshake, unlock endpoint, hardware buttons, USB host) are from Tim Korver's Thesis Friday series and his search term and process cheatsheet, rather than re-derived from scratch — { $url }.
acknowledgements-research-journald = The built-in journald tagging rule pack ({ $files }) is sourced directly from OpenSSH, sudo, and shadow-utils' own logging code, not re-derived from memory — see each rule file's header comment for its specific citation.
# SecurityLogTags.logtags and SecurityLog.java are file names.
acknowledgements-research-intrusion-log = The built-in Android Intrusion Log tagging rule pack ({ $files }) sources tag IDs and descriptions from Android's own AOSP SecurityLogTags.logtags / SecurityLog.java, cross-confirmed against two independent tools that parse the same real-world export format: the Mobile Verification Toolkit (Amnesty International's Security Lab) and ALEAPP.
# biome*.py is a file name pattern; ccl_segb a project name.
acknowledgements-research-biome = The built-in Apple Biome (SEGB) tagging rule pack ({ $files }) sources stream names and field semantics from iLEAPP's biome*.py artifact modules (Apache-2.0). The SEGB v1/v2 envelope format is a Rust port of CCL Forensics' ccl_segb project (MIT) — { $url }.
acknowledgements-special-thanks = Special thanks
# $menu_path is the menu location of the theme, e.g. "View → Theme → Rainbow".
acknowledgements-rainbow = @dugeonlady — for suggesting the Rainbow theme in crush. Peach's Rainbow theme ({ $menu_path }) carries over the same cycle and colors.
acknowledgements-development-tools = Development tools
acknowledgements-claude = Claude / Claude Code — AI assistant used during development (Anthropic)


## Notes dialog (timeline row right-click > Notes).

notes-title = Notes
notes-empty = No notes on this event yet.
notes-new = New note:


## Raw / Fields dialog (timeline row right-click > View raw/fields).
## "raw" and "fields" are names of timeline columns and are not translated.

raw-fields-title = Raw / Fields
# Shown instead of the event's message when it has none.
raw-fields-no-message = (no message)


## Display timezone dialog (menu: View > Display timezone).

display-timezone-title = Display Timezone
display-timezone-prompt = How the timeline and export show timestamps:
# Input hint. The examples (+0100, +02:00, UTC, Europe/Berlin) are values
# Peach accepts: keep them exactly as written.
display-timezone-hint = +0100, +02:00, UTC, or Europe/Berlin — blank means UTC


## Tagging dialogs (timeline row right-click > Tag this event / Tag all matching).

tag-single-title = Tag this event
tag-advanced-title = Advanced tagging
common-apply = Apply
# Label of the tag drop-down.
tag-picker-label = Tag
# First entry of the tag drop-down; picking it reveals a name field.
tag-picker-new = New tag...
tag-picker-new-name = New tag name:
tag-match-on = Match on:
tag-match-message-contains = Message contains
tag-message-contains-prompt = Tag every entry whose message contains:
# $sourcetype is a source type such as "evtx" or "aul" (not translated),
# $field the name of a column such as "Host" or "Event ID".
tag-field-equals-prompt = Tag every { $sourcetype } entry whose { $field } is exactly:
# $count is how many timeline entries the condition matches right now.
tag-preview-count = Preview: { $count ->
    [one] { $count } entry currently matches
   *[other] { $count } entries currently match
}
tag-preview-counting = Preview: counting...
# $path is the rule file that will be changed.
tag-extend-existing = Will extend existing rule: { $path }
tag-no-single-rule = No single loaded rule produces this tag — a new rule will be created.
tag-new-rule-name = New rule name:


## Case Summary dialog (menu: View > Case Summary, and before/after Portable Case export/import).

case-summary-export-title = Export portable case
case-summary-export-button = Export...
# $entries total entries, $sources number of source files, $sourcetypes
# number of different source types.
case-summary-totals = { $entries ->
    [one] { $entries } entry
   *[other] { $entries } entries
} across { $sources ->
    [one] { $sources } source
   *[other] { $sources } sources
}, { $sourcetypes ->
    [one] { $sourcetypes } sourcetype
   *[other] { $sourcetypes } sourcetypes
}
# $percent is already formatted with one decimal, e.g. "12.5".
case-summary-tagged = { $tagged } tagged ({ $percent }%), { $untagged } untagged
# "Activity Log" is the name of a Peach window (menu: View > Activity Log).
case-summary-skipped-files = { $count ->
    [one] { $count } file skipped during loading (see Activity Log for why)
   *[other] { $count } files skipped during loading (see Activity Log for why)
}
# $earliest and $latest are timestamps; keep the arrow or use your
# language's usual range notation.
case-summary-time-range = Time range: { $earliest } → { $latest }
case-summary-no-timestamps = No timestamped entries.
case-summary-per-sourcetype = Entries per sourcetype
case-summary-per-source = Entries per source
case-summary-none = (none)
# Shown when the source list is cut off. $count sources not shown,
# $entries their combined entries.
case-summary-more-sources = +{ $count ->
    [one] { $count } more source
   *[other] { $count } more sources
} ({ $entries } entries, not shown above)
case-summary-levels = Level breakdown
case-summary-no-levels = No leveled entries.
# "UTC" stays as written.
case-summary-daily = Daily activity (UTC days)


## Activity Log dialog (menu: View > Activity Log).
## Operation and status names are stored in the session in English; only
## their display here is translated.

activity-log-title = Activity Log
activity-log-empty = No load or re-tag operations recorded yet in this session.
activity-log-operation-load = Load
activity-log-operation-retag = Re-tag
activity-log-operation-import = Import
activity-log-status-ok = OK
activity-log-status-aborted = Aborted
activity-log-status-aborted-help = Stopped early by the analyst — counts below are real, just less than a full run would have produced.
activity-log-status-failed = Failed
# $start and $end are timestamps; keep the arrow or use your language's
# usual range notation.
activity-log-time-range = { $start } → { $end }
# "skip bad records" is a checkbox in the load controls; use that
# checkbox's wording.
activity-log-skip-bad-records-on = (skip bad records was on)
# $session is the id of the session the portable case was exported from.
activity-log-imported-from = Imported from { $session }
activity-log-load-summary = Loaded { $entries ->
    [one] { $entries } entry
   *[other] { $entries } entries
}, applied { $tags ->
    [one] { $tags } tag
   *[other] { $tags } tags
}
activity-log-retag-summary = Applied { $tags ->
    [one] { $tags } tag
   *[other] { $tags } tags
}
activity-log-files-skipped = { $count ->
    [one] { $count } file skipped
   *[other] { $count } files skipped
}
activity-log-records-skipped = { $count ->
    [one] { $count } record skipped instead of failing its file
   *[other] { $count } records skipped instead of failing their file
}
activity-log-per-file = Per file:
# One line per file; $path is the file path.
activity-log-file-entries = { $path }: { $entries ->
    [one] { $entries } entry
   *[other] { $entries } entries
}
activity-log-file-entries-skipped = { $path }: { $entries ->
    [one] { $entries } entry
   *[other] { $entries } entries
}, { $skipped } skipped
activity-log-per-rule = Per rule:
# One line per tagging rule; $rule is the rule name, $version its version.
activity-log-rule-tags = { $rule }: { $count ->
    [one] { $count } tag
   *[other] { $count } tags
}
activity-log-rule-tags-versioned = { $rule } (v{ $version }): { $count ->
    [one] { $count } tag
   *[other] { $count } tags
}


## Shared by the Built-in Rules and Rules Reference dialogs.

# Column headers of the rule table.
rule-list-column-source = Source
rule-list-column-rule = Rule
rule-list-column-tag = Tag
rule-list-column-match = Match
rule-list-column-description = Description
rule-list-sort-help = Click to sort, click again to reverse
rule-list-search = Search:
rule-list-search-hint = name, tag, description or match text
rule-list-reset-filters = Reset filters
rule-list-reset-filters-help = Clear the search and show every source and state again
# The Source drop-down. $hidden is how many sources are hidden.
rule-list-source-filter = Source
rule-list-source-filter-hidden = Source ({ $hidden } hidden)
rule-list-source-counts-help = Counts are all rules of that source, ignoring the other filters.
# Small button next to one source: show only that source.
rule-list-source-only = only
rule-list-source-only-help = Show only this source, hide every other one
rule-list-show-all = Show all
# Source of a rule that belongs to none of the known log formats.
rule-list-source-other = Other
rule-list-no-match = No rules match the current filters.
# Tooltip of a rule. $description is the rule's description, $condition its
# match condition, $tag its tag (all three not translated).
rule-list-hover = { $description }

    Match: { $condition }
    Tag: { $tag }
rule-list-no-description = (no description)
# A rule that matches on its log format only. "sourcetype" is a rule
# field name: keep it as written.
rule-list-sourcetype-only = (sourcetype only)
# Introduces a list of phrases, one per line. "message" is the name of a
# timeline column.
rule-list-message-contains-any = message contains any of:
# $value is the phrase, in quotes.
rule-list-message-contains = message contains { $value }
# A shortened list. $count is how many items are left out.
rule-list-more = (+{ $count } more)


## Built-in Rules dialog ("Built-in rules..." button in the load controls).

builtin-rules-title = Built-in Rules
# $version is the rule pack's version number, $menu_path the menu location
# where packs are downloaded (e.g. "File → Rule packs...").
builtin-rules-pack-active = Rule pack version { $version } (downloaded via { $menu_path }). Checked rules apply on every load and re-tag.
builtin-rules-baseline = Built-in baseline. Checked rules apply on every load and re-tag.
builtin-rules-show = Show:
builtin-rules-show-all = All
builtin-rules-show-enabled = Enabled
builtin-rules-show-disabled = Disabled
# $count is the number of rules the table currently lists.
builtin-rules-enable-shown = Enable shown ({ $count })
builtin-rules-enable-shown-help = Enable every rule the table currently lists
builtin-rules-disable-shown = Disable shown ({ $count })
builtin-rules-disable-shown-help = Disable every rule the table currently lists
builtin-rules-shown-count = { $shown } of { $total } rules shown · { $enabled } enabled


## Rules Reference dialog (menu: Help > Rules reference).

rules-reference-title = Rules Reference
# $menu_path is the menu location where packs are downloaded
# (e.g. "File → Rule packs...").
rules-reference-live-note = Built from the rules actually active in this session right now, not a fixed snapshot — this updates whenever a different rule pack is applied. See { $menu_path } to check for updates.
# "GitHub" is a website name.
rules-reference-open-github = Open on GitHub...
rules-reference-open-github-disabled = A downloaded rule pack is active — the GitHub copy only matches the built-in baseline, not this pack.
rules-reference-shown-count = { $shown } of { $total } rules shown
# $menu_path: see rules-reference-live-note.
rules-reference-pack-active = Showing rule pack version { $version } (applied via { $menu_path }).
# $version is Peach's version number, $date its build date.
rules-reference-baseline = Showing the built-in baseline — Peach { $version }, built { $date }.
rules-reference-detail-hint = Click a rule to see its full match condition and description here.
# Shown between the rule's source and its tag in the detail panel, e.g.
# "AUL · tag wifi_status".
rules-reference-detail-tag = tag


## Define Text Format dialog ("Define format..." in the load controls,
## for the Text source type).

format-title = Define Text Format
# Saves the format and uses it for the file about to be loaded.
format-save-and-use = Save & Use
format-saved-configs = Saved configs:
# Placeholder of a drop-down with nothing picked yet.
format-select = — select —
# Loads the picked format into the fields below (not a log file).
format-load = Load
format-builtin-formats = Built-in formats:
# "syslog" and "logcat" are log format names: keep them as written.
format-builtin-formats-help = Starting points for common text-log shapes (generic timestamp, syslog, logcat) — a real log's exact format varies too much to apply one of these blindly, so this loads it into the fields below for you to check against the live preview and adjust (timezone/year in particular almost always need filling in) before saving.
format-name = Name:
format-sourcetype = Sourcetype:
format-pattern-regex = Pattern regex:
format-timestamp-format = Timestamp format:
format-multiline-start = Multiline start pattern:
format-optional = optional
# The Settings dialog refers to this field by name; keep both translations
# the same.
format-assume-offset = Assume offset:
# "+02:00" is an example value: keep it as written.
format-assume-offset-hint = e.g. +02:00 — only if the format has no timezone
format-assume-year = Assume year:
format-assume-year-hint = e.g. 2026 — only if the format has no year
format-level-group = Level capture group:
format-message-group = Message capture group:
# "Level" and "Message" refer to the two fields above.
format-capture-groups-help = Every named capture group becomes a searchable field regardless — Level/Message above only control which two get promoted to Peach's normalized columns.
# $count is the number of lines shown below.
format-preview-heading = Live preview — first { $count ->
    [one] line
   *[other] { $count } lines
} of the source file:
format-preview-empty = (source file has no lines to preview)
# Error frames: the technical detail after the colon stays in English.
format-invalid-regex = Invalid regex: { $error }
format-invalid-assume-offset = Invalid assume offset: { $error }
format-invalid-assume-year = Invalid assume year: { $error }
format-no-parsers-dir = Could not determine the per-user parsers directory.


## Manage sessions dialog (menu: File > Manage sessions).

sessions-title = Manage sessions
sessions-none = No saved sessions found.
# One row per session. $name is the session's name, $size its size on
# disk with unit (e.g. "1.2 GB", units are not translated).
sessions-row-counted = { $name } — { $count ->
    [one] { $count } event
   *[other] { $count } events
}, { $size }
sessions-row-counting = { $name } (counting…), { $size }
# A session nothing has been loaded into yet.
sessions-row-empty = { $name } (empty)
# Marks the session open in this window.
sessions-current = (current)
sessions-open = Open
sessions-rename = Rename...
# ".sqlite" and ".duckdb" are file extensions: keep them as written.
sessions-open-folder-help = Show this session's .sqlite/.duckdb files in the file manager — handy for copying the session elsewhere
sessions-really-delete = Really delete?
sessions-delete = Delete...
sessions-delete-current-help = Cannot delete the session currently open in this window


## Rule Packs dialog (menu: File > Rule packs).

rule-packs-title = Rule Packs
rule-packs-active-downloaded = Active rule pack: downloaded, version { $version }
# $version is Peach's version number, $date its build date.
rule-packs-active-baseline = Active rule pack: built-in baseline — Peach { $version }, built { $date }. No pack version number to compare; check the build date above against a rule pack's release date to see which is more current.
rule-packs-rule-count = { $count ->
    [one] { $count } rule currently active.
   *[other] { $count } rules currently active.
}
# "peach-rules-vN.zip" is a file name pattern: keep it as written.
rule-packs-drop-hint = Drag a peach-rules-vN.zip bundle here (or use Browse — drag-and-drop isn't supported on every Linux desktop)
rule-packs-drop-unavailable = Drag-and-drop unavailable: couldn't determine the rule pack directory
rule-packs-browse = Browse...
# $file is the file name. ".zip" is a file extension.
rule-packs-not-a-zip = { $file } isn't a .zip file — expected a rule pack bundle
rule-packs-check = Check for updates...
# "GitHub" is a website name.
rule-packs-check-help = Network request to GitHub — only runs when you click this.
rule-packs-checking = Checking GitHub for a newer rule pack...
rule-packs-no-update = No newer rule pack available.
rule-packs-check-again = Check again
# $tag is the release name on GitHub, e.g. "peach-rules-v3".
rule-packs-update-available = Rule pack version { $version } is available ({ $tag }).
rule-packs-download = Download and verify
rule-packs-downloading = Downloading and verifying version { $version }...
# $file is the file name.
rule-packs-verifying = Verifying { $file }...
rule-packs-applying = Applying rule pack...
rule-packs-applied = Applied rule pack version { $version }.
rule-packs-applied-help = Already-loaded sources keep whatever tags they have until re-tagged — new rules apply automatically to anything loaded from now on.
rule-packs-retag-now = Re-tag now
rule-packs-not-now = Not now
# Where the reviewed pack came from. $file is a file name, $tag a release
# name such as "peach-rules-v3".
rule-packs-source-dropped = dropped file: { $file }
rule-packs-source-browsed = browsed file: { $file }
rule-packs-source-downloaded = downloaded update: { $tag }
# $source is one of the three lines above.
rule-packs-reviewing = Reviewing: { $source } (pack version { $version })
rule-packs-no-changes = No changes relative to what's currently active.
# Headings of the change list, $count rules each.
rule-packs-diff-new = New ({ $count })
rule-packs-diff-modified = Modified ({ $count })
rule-packs-diff-removed = Removed ({ $count })


## Timeline column names. Also used wherever Peach names one of these
## fields: the "Filter by..." menu, active-filter chips, the tagging
## dialog. The search syntax uses its own fixed lowercase keywords
## (sourcetype=, event_id=, ...), which are not translated.

column-timestamp = Timestamp
column-level = Level
column-source = Source
column-sourcetype = Sourcetype
column-host = Host
column-process = Process
column-event-id = Event ID
column-subsystem = Subsystem
column-category = Category
column-tags = Tags
column-notes = Notes
column-message = Message


## Search and filter bar (above the timeline).

filter-search = Search:
# Example query in the search syntax: keep it exactly as written.
filter-search-hint = e.g. sourcetype=evtx tag=auth_failure NOT level=INFO "login"
filter-clear = Clear
filter-counts-whole-timeline = Counts are for the whole loaded timeline, not the current filter.
# Small button next to one value: keep only that value selected.
filter-only = only
filter-show-all = Show all
# Drop-down button with $count values selected, e.g. "Level (2)".
filter-dropdown-selected = { $label } ({ $count })
filter-level-only-help = Select only this value, deselecting every other one
filter-tag = Tag
filter-tag-selected = Tag ({ $selected })
filter-tag-excluded = Tag ({ $excluded } excluded)
filter-tag-selected-excluded = Tag ({ $selected }, { $excluded } excluded)
filter-tag-only-help = Select only this tag, deselecting every other tag and Untagged
# Short for "exclude": toggles hiding entries with this tag.
filter-tag-exclude = excl.
# "NOT tag=<value>" is search syntax: keep it as written.
filter-tag-exclude-help = Hide entries that have this tag, even alongside others (NOT tag=<value>) — independent of the checkbox above
filter-untagged = Untagged
# "NOT tag=*" is search syntax: keep it as written.
filter-untagged-help = Entries with no tag at all (NOT tag=*)
filter-sources = Sources
filter-sources-hidden = Sources ({ $hidden } hidden)
filter-source-only-help = Show only this source, hide every other one
filter-time-range = Time range
# $count is how many of the two bounds (after/before) are set.
filter-time-range-active = Time range ({ $count })
# Checkboxes for the start and end of the time range.
filter-time-after = After
filter-time-before = Before
filter-active-filters = Active filters:
# Tooltip of an active-filter chip. $term is the search term it stands for,
# e.g. "host=DESKTOP-1" (search syntax, not translated).
filter-chip-remove-help = Remove this filter ({ $term })
filter-clear-all = Clear all


## Timeline table.

timeline-events-loaded = { $count ->
    [one] { $count } event loaded
   *[other] { $count } events loaded
}
timeline-events-matching = { $matching } of { $total ->
    [one] { $total } event loaded matches the filter
   *[other] { $total } events loaded match the filter
}
timeline-filtering = Filtering…
timeline-no-match = No entries match.
# Menu for showing/hiding table columns.
timeline-columns = Columns
timeline-columns-reorder-hint = Drag a column header to reorder it.
timeline-sort-newest-first = Timestamp ▼ (newest first)
timeline-sort-oldest-first = Timestamp ▲ (oldest first)
timeline-sort-help = Toggle sort direction

## Timeline row right-click menu.

row-menu-copy-message = Copy message
# The copied text itself is not translated (like an export).
row-menu-copy-event = Copy whole event as text
# "raw" and "fields" are column names: keep them as written.
row-menu-view-raw-fields = View raw/fields...
row-menu-filter-by = Filter by...
row-menu-show-context = Show context around this event
# $minutes is 1, 5, 15 or 60.
row-menu-context-minutes = ± { $minutes } min
row-menu-tag-event = Tag this event...
row-menu-tag-all-matching = Tag all matching (advanced)...
row-menu-notes = Notes...


## Menu bar. Other texts refer to menu entries by these names (e.g. "File →
## Rule packs..."), built from the translations here.

menu-file = File
menu-new-session = New session
menu-new-session-help = Starts a fresh, empty session — the one you're leaving stays on disk (via Manage sessions...) as long as it has data loaded into it.
menu-manage-sessions = Manage sessions...
menu-export = Export (current filter)...
menu-export-help = Exports exactly what the timeline is showing right now — clear the search box first to export everything.
menu-export-portable-case = Export portable case...
menu-export-portable-case-help = Bundles this session (or, with an active search, just the matching subset) into a single file another analyst's Peach can import — unlike the row export above, raw data, tags, and notes all travel intact.
menu-import-portable-case = Import portable case...
# ".peachcase" is a file extension: keep it as written.
menu-import-portable-case-help = Opens a .peachcase bundle as a brand-new session — the session you're in now is left untouched.
menu-rule-packs = Rule packs...
menu-settings = Settings...
menu-quit = Quit
menu-view = View
menu-theme = Theme
theme-system = System default
theme-light = Light
theme-dark = Dark
theme-geek = Geek
theme-rainbow = Rainbow
menu-display-timezone = Display timezone...
menu-activity-log = Activity Log...
menu-case-summary = Case Summary...
menu-case-summary-help = Entries per source/sourcetype/level, tag coverage, and the covered time range for the whole session.
menu-help = Help
menu-about = About Peach...
menu-rules-reference = Rules reference...

# Window title of the Case Summary dialog opened from the View menu.
case-summary-title = Case Summary
# Window title of the Case Summary shown after importing a portable case.
# $name is the imported session's name.
case-summary-imported-title = Imported: { $name }


## Load controls (top of the main window).

# $name is the session's name or id.
load-session = Session: { $name }
load-sourcetype = Sourcetype:
# Source type for text logs parsed with a configurable format.
load-source-text = Text (config-based)
# "--add-source" is a command-line flag: keep it as written.
load-queued-sources = { $count ->
    [one] ({ $count } more source queued from --add-source)
   *[other] ({ $count } more sources queued from --add-source)
}
# ".logarchive" is a folder type: keep it as written.
load-choose-logarchive = Choose .logarchive folder...
# "intrusion-logs" is a folder name: keep it as written.
load-choose-intrusion-logs = Choose intrusion-logs folder...
# "biome/streams" is a folder path: keep it as written.
load-choose-biome = Choose biome/streams folder...
load-choose-evtx = Choose .evtx file(s)...
load-choose-journal = Choose .journal file(s)...
load-choose-log-files = Choose log file(s)...
# "Load" is the name of the button that starts loading.
load-choose-files-help = Select several to queue them as separate sources, loaded one after another — each still needs its own "Load" click, same as a single file
load-choose-folder = Choose folder...
load-choose-folder-help = Recursively loads every matching file found in the folder (and its subfolders) as separate sources
load-choose-parser-config = Choose parser config (TOML)...
load-define-format = Define format...
load-define-format-help = Build a parser config with a live preview against this source's own lines, instead of hand-editing TOML.
# Input hint. The examples are values Peach accepts: keep them as written.
load-source-timezone-hint = +0100, +02:00, UTC, or Europe/Berlin
# "Assume offset" is the label of a field in the Define Text Format dialog;
# use the same wording as that field's translation.
load-source-timezone-help = Fallback when a text source's own "Assume offset" isn't set. Applies immediately.
load-builtin-rules = Built-in rules...
load-builtin-rules-help = Choose exactly which built-in AUL/EVTX rules apply on every load and re-tag, regardless of which rule files are also selected below. Every built-in rule is enabled by default.
load-choose-rules = Choose tagging rules (TOML, optional)...
load-no-rule-files = (no extra rule files selected)
load-rule-files = { $count ->
    [one] { $count } rule file selected
   *[other] { $count } rule files selected
}
load-retag = Re-tag now
# "import_tags" is a database table name: keep it as written.
load-retag-help = Re-evaluate the selected rules against everything already loaded, replacing import_tags
load-retagging = Re-tagging...
load-retag-done = Re-tag applied { $count ->
    [one] { $count } tag
   *[other] { $count } tags
}
# Error frame: $error is the technical detail and stays in English.
load-error = Error: { $error }
load-exporting = Exporting... { $rows ->
    [one] { $rows } row so far
   *[other] { $rows } rows so far
}
load-export-done = Export complete: { $rows ->
    [one] { $rows } row
   *[other] { $rows } rows
} to { $path }
load-export-failed = Export failed: { $error }
# $stage is one of the portable-case-stage-* texts below.
load-portable-case-exporting = Exporting portable case... { $stage }
load-portable-case-export-done = Portable case complete: { $entries ->
    [one] { $entries } entry
   *[other] { $entries } entries
}, { $tags ->
    [one] { $tags } tag
   *[other] { $tags } tags
}, to { $path }
load-portable-case-export-failed = Portable case export failed: { $error }
load-portable-case-importing = Importing portable case... { $stage }
load-portable-case-import-done = Portable case imported and opened: { $name }
load-portable-case-import-failed = Portable case import failed: { $error }
load-portable-case-switch-failed = imported, but failed to switch into the new session: { $error }
portable-case-stage-copying-timeline = copying timeline
portable-case-stage-copying-session-data = copying tags and notes
portable-case-stage-collecting-parser-configs = collecting parser configs
portable-case-stage-verifying-integrity = verifying integrity
portable-case-stage-packaging = packaging
portable-case-stage-extracting = extracting
portable-case-stage-verifying-format = verifying format
portable-case-stage-registering-session = registering session
load-dismiss = Dismiss
# $legacy and $new are folder paths. $settings_path is where the setting
# lives, e.g. "Settings → Sessions directory". A list of the items and
# reasons follows on the next lines.
load-session-migration-warning = { $count ->
    [one] { $count } item could not be moved from the old sessions folder { $legacy } to { $new }. It was left unchanged. To open it, close Peach and move it yourself, or point { $settings_path } at the old folder:
   *[other] { $count } items could not be moved from the old sessions folder { $legacy } to { $new }. They were left unchanged. To open them, close Peach and move them yourself, or point { $settings_path } at the old folder:
}
load-skip-bad-records = Skip bad records instead of failing
load-skip-bad-records-help = If a line/record can't be parsed, skip it and keep going instead of aborting the whole file. Off by default — a bad record normally stops the file's load entirely, so nothing is ever silently incomplete. When on, how many records were skipped (and why) is recorded in the Activity Log, per file.
load-load = Load
load-abort = Abort
load-abort-help = Stops after the file currently being parsed finishes (or, for a large single file, at the next internal checkpoint) — whatever's already inserted stays; nothing gets rolled back.
# Progress bar text. $done and $total are already formatted with one
# decimal, e.g. "12.5".
load-parsing-progress = Parsing: { $done } / { $total } MB
load-loading = Loading...
load-loading-entries = Loading... { $count ->
    [one] { $count } entry so far
   *[other] { $count } entries so far
}
# $seconds is already formatted with one decimal, e.g. "3.2".
load-done = Loaded { $entries ->
    [one] { $entries } entry
   *[other] { $entries } entries
}, applied { $tags ->
    [one] { $tags } tag
   *[other] { $tags } tags
} in { $seconds }s
load-aborted = Aborted
load-records-skipped = { $count ->
    [one] { $count } record skipped (skip bad records was on)
   *[other] { $count } records skipped (skip bad records was on)
}
# "Activity Log" is the name of a Peach window.
load-records-skipped-help = See Activity Log for the per-file breakdown and reasons.
load-files-skipped = { $count ->
    [one] { $count } file skipped
   *[other] { $count } files skipped
}
