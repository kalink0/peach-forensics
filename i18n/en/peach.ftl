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
