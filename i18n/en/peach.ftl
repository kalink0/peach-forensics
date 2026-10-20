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
