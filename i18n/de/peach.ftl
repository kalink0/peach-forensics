### Peach UI text, German (Deutsch).
###
### Section headers follow i18n/en/peach.ftl, which also carries the
### comments on where each text appears and what to keep as-is.

language-name = Deutsch


## Shared buttons and labels, reused across dialogs.

common-save = Speichern
common-cancel = Abbrechen
common-choose = Auswählen...
common-reset-to-default = Zurücksetzen auf Standard
common-open-folder = Ordner öffnen
common-close = Schließen
common-edit = Ändern
common-delete = Löschen
common-add = Hinzufügen
common-default-path = (Standard) { $path }


## Settings dialog (menu: File > Settings).

settings-title = Einstellungen

settings-language = Sprache:
settings-language-help = Übersetzungen werden von der Community gepflegt und können unvollständig sein — alles, was noch nicht übersetzt ist, wird auf Englisch angezeigt. Log-Daten, Tags, Regeln, die Suchsyntax und Exporte werden nie übersetzt.
settings-language-entry = { $name } ({ $code }) — { $percent }% übersetzt
settings-language-entry-unnamed = { $code } — { $percent }% übersetzt
settings-language-entry-broken = { $code } — Datei enthält Fehler, schau in i18n/README.md
settings-language-unavailable = Sprache "{ $code }" ist nicht verfügbar oder ihre Datei enthält Fehler — Englisch wird angezeigt.

settings-sessions-dir = Sessions-Ordner:
settings-sessions-dir-help = Nur für neue Sessions — die aktuelle Session bleibt, wo sie ist.
settings-sessions-dir-name = Sessions-Ordner

settings-rules-dir = Regel-Ordner:
settings-rules-dir-help = Hier werden neue Regeln gespeichert und beim Start automatisch geladen.

settings-staging-dir = Staging-Ordner:
settings-staging-dir-help = Arbeitsbereich für --ephemeral-session und Portable-Case-Export/-Import — kann eine vollständige Kopie der Bulk-Timeline aufnehmen.

settings-load-threads = Parse-Threads beim Laden von Ordnern:
settings-load-threads-help = Nur relevant, wenn mehrere EVTX-/journald-/Text-Dateien geladen werden.
settings-load-threads-automatic = Automatisch
settings-load-threads-on-this-machine = ({ $count } auf diesem Rechner)

settings-memory-limit = Speicherlimit der Datenbank (MB):
settings-memory-limit-help = RAM, den die Timeline-Datenbank nutzen darf. Darüber hinaus lagert sie Daten in einen temporären Ordner neben der Session-Datei aus. Ein höherer Wert beschleunigt das Laden nur selten.
settings-memory-limit-default = Standard
settings-memory-limit-default-value = ({ $mb } MB)

settings-source-timezone = Zeitzone für Logs ohne eigene Zeitzone annehmen:
settings-source-timezone-help = Fallback, wenn bei einer Textquelle kein eigenes „Offset annehmen“ gesetzt ist.
settings-source-timezone-hint = +0100, +02:00, UTC oder Europe/Berlin — leer lassen zum Deaktivieren


## About dialog (menu: Help > About).

about-title = Über Peach
about-tab-about = Über
about-tab-acknowledgements = Danksagungen
about-tagline = DFIR Log Workbench
about-description = Eine schlanke, lokal arbeitende DFIR-Log-Workbench. Liest Log-Quellen — AUL, EVTX, journald und per TOML konfigurierbare Text-Logs — in eine normalisierte, taggbare Timeline ein, mit einer an Splunk angelehnten Suchsyntax und semantischem Tagging.
about-crush = Läuft eigenständig oder kann von crush gestartet und mit Pfaden zu Beweismitteln versorgt werden und arbeitet danach völlig unabhängig weiter (kein IPC).
about-dedication = Danke an einen besonderen Menschen — für jedes ermutigende Wort, dafür, dass du an mich geglaubt hast, für die Motivation und für die Inspiration.
about-license = Lizenziert unter der Apache License 2.0
about-report-bug = Fehler melden oder Funktion vorschlagen

acknowledgements-intro = Peach steht auf den Schultern der Open-Source- und DFIR-Community.
acknowledgements-dependencies = Rust-Crate-Abhängigkeiten
acknowledgements-role-gui = GUI-Framework
acknowledgements-role-duckdb = Speicher für die Bulk-Timeline (bringt DuckDB selbst mit)
acknowledgements-role-rusqlite = Session-DB (bringt SQLite mit, Public Domain)
acknowledgements-role-aul = Parsen von AUL (.logarchive)
acknowledgements-role-evtx = Parsen von Windows-EVTX
acknowledgements-role-rfd = Native Dateidialoge
acknowledgements-research = Recherche
acknowledgements-research-aul = Das integrierte AUL-Regelpaket ({ $files }) baut auf Prädikaten aus „{ $title }“ von Alexis Brignoni auf, statt sie von Grund auf neu herzuleiten — { $url }.
acknowledgements-research-evtx = Die integrierten EVTX-Nachrichtenvorlagen und das Tagging-Regelpaket ({ $files }) sind für jede Event-ID mit Microsofts offizieller Security-Auditing-Referenz abgeglichen — { $url }.
acknowledgements-research-thesis-friday = Einige neuere AUL-Prädikate (Wiederherstellung gewählter Nummern, Geräteausrichtung, Krone/Taste der Apple Watch, CarPlay-Handshake, Entsperr-Endpunkt, Hardwaretasten, USB-Host) stammen aus Tim Korvers Reihe Thesis Friday und seinem Cheatsheet zu Suchbegriffen und Prozessen, statt von Grund auf neu hergeleitet zu werden — { $url }.
acknowledgements-research-journald = Das integrierte journald-Tagging-Regelpaket ({ $files }) stammt direkt aus dem Logging-Code von OpenSSH, sudo und shadow-utils, nicht aus dem Gedächtnis rekonstruiert — die genaue Quelle steht jeweils im Kopfkommentar der Regeldatei.
acknowledgements-research-intrusion-log = Das integrierte Tagging-Regelpaket für das Android Intrusion Log ({ $files }) übernimmt Tag-IDs und Beschreibungen aus Androids eigenem AOSP-Code SecurityLogTags.logtags / SecurityLog.java, gegengeprüft mit zwei unabhängigen Tools, die dasselbe reale Exportformat parsen: dem Mobile Verification Toolkit (Security Lab von Amnesty International) und ALEAPP.
acknowledgements-research-biome = Das integrierte Tagging-Regelpaket für Apple Biome (SEGB) ({ $files }) übernimmt Stream-Namen und Feldbedeutungen aus iLEAPPs Artefaktmodulen biome*.py (Apache-2.0). Das SEGB-v1/v2-Containerformat ist eine Rust-Portierung des Projekts ccl_segb von CCL Forensics (MIT) — { $url }.
acknowledgements-special-thanks = Besonderer Dank
acknowledgements-rainbow = @dugeonlady — für den Vorschlag des Rainbow-Designs in crush. Peachs Rainbow-Design ({ $menu_path }) übernimmt denselben Farbzyklus und dieselben Farben.
acknowledgements-development-tools = Entwicklungswerkzeuge
acknowledgements-claude = Claude / Claude Code — KI-Assistent, bei der Entwicklung eingesetzt (Anthropic)


## Notes dialog (timeline row right-click > Notes).

notes-title = Notizen
notes-empty = Zu diesem Ereignis gibt es noch keine Notizen.
notes-new = Neue Notiz:


## Raw / Fields dialog (timeline row right-click > View raw/fields).
## "raw" and "fields" are names of timeline columns and are not translated.

raw-fields-title = Raw / Fields
raw-fields-no-message = (keine Nachricht)


## Display timezone dialog (menu: View > Display timezone).

display-timezone-title = Anzeige-Zeitzone
display-timezone-prompt = Wie Timeline und Export Zeitstempel anzeigen:
display-timezone-hint = +0100, +02:00, UTC oder Europe/Berlin — leer bedeutet UTC


## Tagging dialogs (timeline row right-click > Tag this event / Tag all matching).

tag-single-title = Dieses Ereignis taggen
tag-advanced-title = Erweitertes Tagging
common-apply = Anwenden
tag-picker-label = Tag
tag-picker-new = Neuer Tag...
tag-picker-new-name = Name des neuen Tags:
tag-match-on = Abgleichen über:
tag-match-message-contains = Nachricht enthält
tag-message-contains-prompt = Jeden Eintrag taggen, dessen Nachricht Folgendes enthält:
tag-field-equals-prompt = Jeden { $sourcetype }-Eintrag taggen, dessen { $field } genau lautet:
tag-preview-count = Vorschau: { $count ->
    [one] { $count } Eintrag passt derzeit
   *[other] { $count } Einträge passen derzeit
}
tag-preview-counting = Vorschau: wird gezählt...
tag-extend-existing = Erweitert die vorhandene Regel: { $path }
tag-no-single-rule = Keine einzelne geladene Regel erzeugt diesen Tag — es wird eine neue Regel angelegt.
tag-new-rule-name = Name der neuen Regel:


## Case Summary dialog (menu: View > Case Summary, and before/after Portable Case export/import).

case-summary-export-title = Portable Case exportieren
case-summary-export-button = Exportieren...
case-summary-totals = { $entries ->
    [one] { $entries } Eintrag
   *[other] { $entries } Einträge
} aus { $sources ->
    [one] { $sources } Quelle
   *[other] { $sources } Quellen
}, { $sourcetypes ->
    [one] { $sourcetypes } Quelltyp
   *[other] { $sourcetypes } Quelltypen
}
case-summary-tagged = { $tagged } getaggt ({ $percent }%), { $untagged } ohne Tag
case-summary-skipped-files = { $count ->
    [one] { $count } Datei beim Laden übersprungen (Gründe im Aktivitätsprotokoll)
   *[other] { $count } Dateien beim Laden übersprungen (Gründe im Aktivitätsprotokoll)
}
case-summary-time-range = Zeitraum: { $earliest } → { $latest }
case-summary-no-timestamps = Keine Einträge mit Zeitstempel.
case-summary-per-sourcetype = Einträge pro Quelltyp
case-summary-per-source = Einträge pro Quelle
case-summary-none = (keine)
case-summary-more-sources = +{ $count ->
    [one] { $count } weitere Quelle
   *[other] { $count } weitere Quellen
} ({ $entries } Einträge, oben nicht aufgeführt)
case-summary-levels = Verteilung nach Level
case-summary-no-levels = Keine Einträge mit Level.
case-summary-daily = Aktivität pro Tag (UTC-Tage)


## Activity Log dialog (menu: View > Activity Log).
## Operation and status names are stored in the session in English; only
## their display here is translated.

activity-log-title = Aktivitätsprotokoll
activity-log-empty = In dieser Session wurde noch kein Laden oder Neu-Tagging aufgezeichnet.
activity-log-operation-load = Laden
activity-log-operation-retag = Neu-Tagging
activity-log-operation-import = Import
activity-log-status-ok = OK
activity-log-status-aborted = Abgebrochen
activity-log-status-aborted-help = Vom Analysten vorzeitig gestoppt — die Zahlen unten sind echt, nur kleiner, als ein vollständiger Durchlauf ergeben hätte.
activity-log-status-failed = Fehlgeschlagen
activity-log-time-range = { $start } → { $end }
activity-log-skip-bad-records-on = („Fehlerhafte Datensätze überspringen“ war aktiv)
activity-log-imported-from = Importiert aus { $session }
activity-log-load-summary = { $entries ->
    [one] { $entries } Eintrag
   *[other] { $entries } Einträge
} geladen, { $tags ->
    [one] { $tags } Tag
   *[other] { $tags } Tags
} vergeben
activity-log-retag-summary = { $tags ->
    [one] { $tags } Tag
   *[other] { $tags } Tags
} vergeben
activity-log-files-skipped = { $count ->
    [one] { $count } Datei übersprungen
   *[other] { $count } Dateien übersprungen
}
activity-log-records-skipped = { $count ->
    [one] { $count } Datensatz übersprungen, statt seine Datei abzubrechen
   *[other] { $count } Datensätze übersprungen, statt ihre Datei abzubrechen
}
activity-log-per-file = Pro Datei:
activity-log-file-entries = { $path }: { $entries ->
    [one] { $entries } Eintrag
   *[other] { $entries } Einträge
}
activity-log-file-entries-skipped = { $path }: { $entries ->
    [one] { $entries } Eintrag
   *[other] { $entries } Einträge
}, { $skipped } übersprungen
activity-log-per-rule = Pro Regel:
activity-log-rule-tags = { $rule }: { $count ->
    [one] { $count } Tag
   *[other] { $count } Tags
}
activity-log-rule-tags-versioned = { $rule } (v{ $version }): { $count ->
    [one] { $count } Tag
   *[other] { $count } Tags
}


## Shared by the Built-in Rules and Rules Reference dialogs.

rule-list-column-source = Quelle
rule-list-column-rule = Regel
rule-list-column-tag = Tag
rule-list-column-match = Bedingung
rule-list-column-description = Beschreibung
rule-list-sort-help = Klicken zum Sortieren, erneut klicken zum Umkehren
rule-list-search = Suche:
rule-list-search-hint = Name, Tag, Beschreibung oder Bedingungstext
rule-list-reset-filters = Filter zurücksetzen
rule-list-reset-filters-help = Suche leeren und wieder alle Quellen und Zustände anzeigen
rule-list-source-filter = Quelle
rule-list-source-filter-hidden = Quelle ({ $hidden } ausgeblendet)
rule-list-source-counts-help = Die Zahlen umfassen alle Regeln dieser Quelle, unabhängig von den anderen Filtern.
rule-list-source-only = nur
rule-list-source-only-help = Nur diese Quelle anzeigen, alle anderen ausblenden
rule-list-show-all = Alle anzeigen
rule-list-source-other = Sonstige
rule-list-no-match = Keine Regel passt zu den aktuellen Filtern.
rule-list-hover = { $description }

    Bedingung: { $condition }
    Tag: { $tag }
rule-list-no-description = (keine Beschreibung)
rule-list-sourcetype-only = (nur sourcetype)
rule-list-message-contains-any = message enthält eines von:
rule-list-message-contains = message enthält { $value }
rule-list-more = (+{ $count } weitere)


## Built-in Rules dialog ("Built-in rules..." button in the load controls).

builtin-rules-title = Integrierte Regeln
builtin-rules-pack-active = Regelpaket Version { $version } (heruntergeladen über { $menu_path }). Angehakte Regeln gelten bei jedem Laden und Neu-Tagging.
builtin-rules-baseline = Integrierte Basis. Angehakte Regeln gelten bei jedem Laden und Neu-Tagging.
builtin-rules-show = Anzeigen:
builtin-rules-show-all = Alle
builtin-rules-show-enabled = Aktiviert
builtin-rules-show-disabled = Deaktiviert
builtin-rules-enable-shown = Angezeigte aktivieren ({ $count })
builtin-rules-enable-shown-help = Alle Regeln aktivieren, die die Tabelle gerade anzeigt
builtin-rules-disable-shown = Angezeigte deaktivieren ({ $count })
builtin-rules-disable-shown-help = Alle Regeln deaktivieren, die die Tabelle gerade anzeigt
builtin-rules-shown-count = { $shown } von { $total } Regeln angezeigt · { $enabled } aktiviert


## Rules Reference dialog (menu: Help > Rules reference).

rules-reference-title = Regelreferenz
rules-reference-live-note = Erstellt aus den Regeln, die in dieser Session gerade tatsächlich aktiv sind, kein fester Stand — wird aktualisiert, sobald ein anderes Regelpaket angewendet wird. Unter { $menu_path } kannst du nach Updates suchen.
rules-reference-open-github = Auf GitHub öffnen...
rules-reference-open-github-disabled = Ein heruntergeladenes Regelpaket ist aktiv — die Fassung auf GitHub entspricht nur der integrierten Basis, nicht diesem Paket.
rules-reference-shown-count = { $shown } von { $total } Regeln angezeigt
rules-reference-pack-active = Angezeigt wird Regelpaket Version { $version } (angewendet über { $menu_path }).
rules-reference-baseline = Angezeigt wird die integrierte Basis — Peach { $version }, erstellt am { $date }.
rules-reference-detail-hint = Klick auf eine Regel, um hier ihre vollständige Bedingung und Beschreibung zu sehen.
rules-reference-detail-tag = Tag


## Define Text Format dialog ("Define format..." in the load controls,
## for the Text source type).

format-title = Textformat definieren
format-save-and-use = Speichern & verwenden
format-saved-configs = Gespeicherte Konfigurationen:
format-select = — auswählen —
format-load = Laden
format-builtin-formats = Integrierte Formate:
format-builtin-formats-help = Ausgangspunkte für gängige Text-Log-Formen (generischer Zeitstempel, syslog, logcat) — das genaue Format eines echten Logs schwankt zu stark, um eines davon blind anzuwenden. Deshalb wird es in die Felder unten geladen, damit du es vor dem Speichern mit der Live-Vorschau abgleichen und anpassen kannst (Zeitzone und Jahr müssen fast immer ergänzt werden).
format-name = Name:
format-sourcetype = Quelltyp:
format-pattern-regex = Muster (Regex):
format-timestamp-format = Zeitstempelformat:
format-multiline-start = Startmuster für mehrzeilige Einträge:
format-optional = optional
format-assume-offset = Offset annehmen:
format-assume-offset-hint = z. B. +02:00 — nur wenn das Format keine Zeitzone enthält
format-assume-year = Jahr annehmen:
format-assume-year-hint = z. B. 2026 — nur wenn das Format kein Jahr enthält
format-level-group = Capture-Gruppe für Level:
format-message-group = Capture-Gruppe für Nachricht:
format-capture-groups-help = Jede benannte Capture-Gruppe wird ohnehin zu einem durchsuchbaren Feld — Level/Nachricht oben legen nur fest, welche zwei in Peachs normalisierte Spalten übernommen werden.
format-preview-heading = Live-Vorschau — { $count ->
    [one] erste Zeile
   *[other] erste { $count } Zeilen
} der Quelldatei:
format-preview-empty = (die Quelldatei enthält keine Zeilen für die Vorschau)
format-invalid-regex = Ungültiger Regex: { $error }
format-invalid-assume-offset = Ungültiger angenommener Offset: { $error }
format-invalid-assume-year = Ungültiges angenommenes Jahr: { $error }
format-no-parsers-dir = Der benutzerspezifische Parser-Ordner konnte nicht ermittelt werden.


## Manage sessions dialog (menu: File > Manage sessions).

sessions-title = Sessions verwalten
sessions-none = Keine gespeicherten Sessions gefunden.
sessions-row-counted = { $name } — { $count ->
    [one] { $count } Ereignis
   *[other] { $count } Ereignisse
}, { $size }
sessions-row-counting = { $name } (wird gezählt…), { $size }
sessions-row-empty = { $name } (leer)
sessions-current = (aktuell)
sessions-open = Öffnen
sessions-rename = Umbenennen...
sessions-open-folder-help = Die .sqlite-/.duckdb-Dateien dieser Session im Dateimanager zeigen — praktisch, um die Session woandershin zu kopieren
sessions-really-delete = Wirklich löschen?
sessions-delete = Löschen...
sessions-delete-current-help = Die in diesem Fenster geöffnete Session kann nicht gelöscht werden


## Rule Packs dialog (menu: File > Rule packs).

rule-packs-title = Regelpakete
rule-packs-active-downloaded = Aktives Regelpaket: heruntergeladen, Version { $version }
rule-packs-active-baseline = Aktives Regelpaket: integrierte Basis — Peach { $version }, erstellt am { $date }. Es gibt keine Paketversion zum Vergleichen; vergleiche das Erstelldatum oben mit dem Veröffentlichungsdatum eines Regelpakets, um zu sehen, welches aktueller ist.
rule-packs-rule-count = { $count ->
    [one] { $count } Regel derzeit aktiv.
   *[other] { $count } Regeln derzeit aktiv.
}
rule-packs-drop-hint = Ein peach-rules-vN.zip-Paket hierher ziehen (oder „Durchsuchen“ verwenden — Drag-and-drop wird nicht auf jedem Linux-Desktop unterstützt)
rule-packs-drop-unavailable = Drag-and-drop nicht verfügbar: Der Regelpaket-Ordner konnte nicht ermittelt werden
rule-packs-browse = Durchsuchen...
rule-packs-not-a-zip = { $file } ist keine .zip-Datei — erwartet wird ein Regelpaket
rule-packs-check = Nach Updates suchen...
rule-packs-check-help = Netzwerkanfrage an GitHub — läuft nur, wenn du hier klickst.
rule-packs-checking = Suche auf GitHub nach einem neueren Regelpaket...
rule-packs-no-update = Kein neueres Regelpaket verfügbar.
rule-packs-check-again = Erneut prüfen
rule-packs-update-available = Regelpaket Version { $version } ist verfügbar ({ $tag }).
rule-packs-download = Herunterladen und prüfen
rule-packs-downloading = Version { $version } wird heruntergeladen und geprüft...
rule-packs-verifying = { $file } wird geprüft...
rule-packs-applying = Regelpaket wird angewendet...
rule-packs-applied = Regelpaket Version { $version } angewendet.
rule-packs-applied-help = Bereits geladene Quellen behalten ihre bisherigen Tags, bis sie neu getaggt werden — neue Regeln gelten automatisch für alles, was ab jetzt geladen wird.
rule-packs-retag-now = Jetzt neu taggen
rule-packs-not-now = Nicht jetzt
rule-packs-source-dropped = abgelegte Datei: { $file }
rule-packs-source-browsed = ausgewählte Datei: { $file }
rule-packs-source-downloaded = heruntergeladenes Update: { $tag }
rule-packs-reviewing = Prüfung: { $source } (Paketversion { $version })
rule-packs-no-changes = Keine Änderungen gegenüber dem derzeit aktiven Stand.
rule-packs-diff-new = Neu ({ $count })
rule-packs-diff-modified = Geändert ({ $count })
rule-packs-diff-removed = Entfernt ({ $count })


## Timeline column names.

column-timestamp = Zeitstempel
column-level = Level
column-source = Quelle
column-sourcetype = Quelltyp
column-host = Host
column-process = Prozess
column-event-id = Event-ID
column-subsystem = Subsystem
column-category = Kategorie
column-tags = Tags
column-notes = Notizen
column-message = Nachricht


## Search and filter bar (above the timeline).

filter-search = Suche:
filter-search-hint = z. B. sourcetype=evtx tag=auth_failure NOT level=INFO "login"
filter-clear = Leeren
filter-counts-whole-timeline = Die Zahlen gelten für die gesamte geladene Timeline, nicht für den aktuellen Filter.
filter-only = nur
filter-show-all = Alle anzeigen
filter-dropdown-selected = { $label } ({ $count })
filter-level-only-help = Nur diesen Wert auswählen, alle anderen abwählen
filter-tag = Tag
filter-tag-selected = Tag ({ $selected })
filter-tag-excluded = Tag ({ $excluded } ausgeschlossen)
filter-tag-selected-excluded = Tag ({ $selected }, { $excluded } ausgeschlossen)
filter-tag-only-help = Nur diesen Tag auswählen, alle anderen Tags und „Ohne Tag“ abwählen
filter-tag-exclude = ausschl.
filter-tag-exclude-help = Einträge mit diesem Tag ausblenden, auch wenn sie weitere Tags haben (NOT tag=<value>) — unabhängig von der Checkbox oben
filter-untagged = Ohne Tag
filter-untagged-help = Einträge ganz ohne Tag (NOT tag=*)
filter-sources = Quellen
filter-sources-hidden = Quellen ({ $hidden } ausgeblendet)
filter-source-only-help = Nur diese Quelle anzeigen, alle anderen ausblenden
filter-time-range = Zeitraum
filter-time-range-active = Zeitraum ({ $count })
filter-time-after = Nach
filter-time-before = Vor
filter-active-filters = Aktive Filter:
filter-chip-remove-help = Diesen Filter entfernen ({ $term })
filter-clear-all = Alle entfernen


## Timeline table.

timeline-events-loaded = { $count ->
    [one] { $count } Ereignis geladen
   *[other] { $count } Ereignisse geladen
}
timeline-events-matching = Treffer: { $matching } von { $total ->
    [one] { $total } geladenen Ereignis
   *[other] { $total } geladenen Ereignissen
}
timeline-filtering = Filtern…
timeline-no-match = Keine passenden Einträge.
timeline-columns = Spalten
timeline-columns-reorder-hint = Zieh einen Spaltenkopf, um die Reihenfolge zu ändern.
timeline-sort-newest-first = Zeitstempel ▼ (neueste zuerst)
timeline-sort-oldest-first = Zeitstempel ▲ (älteste zuerst)
timeline-sort-help = Sortierrichtung umschalten

## Timeline row right-click menu.

row-menu-copy-message = Nachricht kopieren
row-menu-copy-event = Ganzes Ereignis als Text kopieren
row-menu-view-raw-fields = raw/fields anzeigen...
row-menu-filter-by = Filtern nach...
row-menu-show-context = Kontext um dieses Ereignis anzeigen
row-menu-context-minutes = ± { $minutes } min
row-menu-tag-event = Dieses Ereignis taggen...
row-menu-tag-all-matching = Alle passenden taggen (erweitert)...
row-menu-notes = Notizen...


## Menu bar. Other texts refer to menu entries by these names (e.g. "File →
## Rule packs..."), built from the translations here.

menu-file = Datei
menu-new-session = Neue Session
menu-new-session-help = Startet eine neue, leere Session — die bisherige bleibt auf der Festplatte erhalten (über „Sessions verwalten...“), sofern Daten in sie geladen wurden.
menu-manage-sessions = Sessions verwalten...
menu-export = Exportieren (aktueller Filter)...
menu-export-help = Exportiert genau das, was die Timeline gerade anzeigt — für einen vollständigen Export zuerst das Suchfeld leeren.
menu-export-portable-case = Portable Case exportieren...
menu-export-portable-case-help = Packt diese Session (oder bei aktiver Suche nur die passende Teilmenge) in eine einzige Datei, die Peach bei einem anderen Analysten importieren kann — anders als beim Zeilenexport oben bleiben Rohdaten, Tags und Notizen vollständig erhalten.
menu-import-portable-case = Portable Case importieren...
menu-import-portable-case-help = Öffnet ein .peachcase-Paket als ganz neue Session — die aktuelle Session bleibt unverändert.
menu-rule-packs = Regelpakete...
menu-settings = Einstellungen...
menu-quit = Beenden
menu-view = Ansicht
menu-theme = Design
theme-system = Systemstandard
theme-light = Hell
theme-dark = Dunkel
theme-geek = Geek
theme-rainbow = Rainbow
menu-display-timezone = Anzeige-Zeitzone...
menu-activity-log = Aktivitätsprotokoll...
menu-case-summary = Fallübersicht...
menu-case-summary-help = Einträge pro Quelle/Quelltyp/Level, Tag-Abdeckung und abgedeckter Zeitraum für die gesamte Session.
menu-help = Hilfe
menu-about = Über Peach...
menu-rules-reference = Regelreferenz...

case-summary-title = Fallübersicht
case-summary-imported-title = Importiert: { $name }


## Load controls (top of the main window).

load-session = Session: { $name }
load-sourcetype = Quelltyp:
load-source-text = Text (konfigurationsbasiert)
load-queued-sources = { $count ->
    [one] ({ $count } weitere Quelle aus --add-source in der Warteschlange)
   *[other] ({ $count } weitere Quellen aus --add-source in der Warteschlange)
}
load-choose-logarchive = .logarchive-Ordner auswählen...
load-choose-intrusion-logs = intrusion-logs-Ordner auswählen...
load-choose-biome = biome/streams-Ordner auswählen...
load-choose-evtx = .evtx-Datei(en) auswählen...
load-choose-journal = .journal-Datei(en) auswählen...
load-choose-log-files = Log-Datei(en) auswählen...
load-choose-files-help = Wähle mehrere aus, um sie als einzelne Quellen nacheinander in die Warteschlange zu stellen — jede braucht trotzdem ihren eigenen Klick auf „Laden“, wie eine einzelne Datei
load-choose-folder = Ordner auswählen...
load-choose-folder-help = Lädt rekursiv jede passende Datei im Ordner (und in seinen Unterordnern) als eigene Quelle
load-choose-parser-config = Parser-Konfiguration (TOML) auswählen...
load-define-format = Format definieren...
load-define-format-help = Erstellt eine Parser-Konfiguration mit Live-Vorschau auf die Zeilen dieser Quelle, statt TOML von Hand zu bearbeiten.
load-source-timezone-hint = +0100, +02:00, UTC oder Europe/Berlin
load-source-timezone-help = Fallback, wenn bei einer Textquelle kein eigenes „Offset annehmen“ gesetzt ist. Gilt sofort.
load-builtin-rules = Integrierte Regeln...
load-builtin-rules-help = Lege genau fest, welche integrierten AUL-/EVTX-Regeln bei jedem Laden und Neu-Tagging gelten, unabhängig davon, welche Regeldateien unten zusätzlich ausgewählt sind. Alle integrierten Regeln sind standardmäßig aktiviert.
load-choose-rules = Tagging-Regeln auswählen (TOML, optional)...
load-no-rule-files = (keine zusätzlichen Regeldateien ausgewählt)
load-rule-files = { $count ->
    [one] { $count } Regeldatei ausgewählt
   *[other] { $count } Regeldateien ausgewählt
}
load-retag = Jetzt neu taggen
load-retag-help = Die ausgewählten Regeln erneut auf alles bereits Geladene anwenden und dabei import_tags ersetzen
load-retagging = Neu-Tagging läuft...
load-retag-done = Neu-Tagging hat { $count ->
    [one] { $count } Tag
   *[other] { $count } Tags
} vergeben
load-error = Fehler: { $error }
load-exporting = Exportieren... { $rows ->
    [one] bisher { $rows } Zeile
   *[other] bisher { $rows } Zeilen
}
load-export-done = Export abgeschlossen: { $rows ->
    [one] { $rows } Zeile
   *[other] { $rows } Zeilen
} nach { $path }
load-export-failed = Export fehlgeschlagen: { $error }
load-portable-case-exporting = Portable Case wird exportiert... { $stage }
load-portable-case-export-done = Portable Case fertig: { $entries ->
    [one] { $entries } Eintrag
   *[other] { $entries } Einträge
}, { $tags ->
    [one] { $tags } Tag
   *[other] { $tags } Tags
}, nach { $path }
load-portable-case-export-failed = Export des Portable Case fehlgeschlagen: { $error }
load-portable-case-importing = Portable Case wird importiert... { $stage }
load-portable-case-import-done = Portable Case importiert und geöffnet: { $name }
load-portable-case-import-failed = Import des Portable Case fehlgeschlagen: { $error }
load-portable-case-switch-failed = importiert, aber der Wechsel in die neue Session ist fehlgeschlagen: { $error }
portable-case-stage-copying-timeline = Timeline wird kopiert
portable-case-stage-copying-session-data = Tags und Notizen werden kopiert
portable-case-stage-collecting-parser-configs = Parser-Konfigurationen werden gesammelt
portable-case-stage-verifying-integrity = Integrität wird geprüft
portable-case-stage-packaging = wird gepackt
portable-case-stage-extracting = wird entpackt
portable-case-stage-verifying-format = Format wird geprüft
portable-case-stage-registering-session = Session wird registriert
load-dismiss = Ausblenden
load-session-migration-warning = { $count ->
    [one] { $count } Element konnte nicht aus dem alten Sessions-Ordner { $legacy } nach { $new } verschoben werden. Es wurde unverändert gelassen. Um es zu öffnen, schließ Peach und verschieb es selbst, oder setze { $settings_path } auf den alten Ordner:
   *[other] { $count } Elemente konnten nicht aus dem alten Sessions-Ordner { $legacy } nach { $new } verschoben werden. Sie wurden unverändert gelassen. Um sie zu öffnen, schließ Peach und verschieb sie selbst, oder setze { $settings_path } auf den alten Ordner:
}
load-skip-bad-records = Fehlerhafte Datensätze überspringen statt abzubrechen
load-skip-bad-records-help = Wenn eine Zeile oder ein Datensatz nicht geparst werden kann, wird sie bzw. er übersprungen und es geht weiter, statt die ganze Datei abzubrechen. Standardmäßig aus — ein fehlerhafter Datensatz stoppt normalerweise das Laden der ganzen Datei, damit nie etwas unbemerkt unvollständig ist. Wenn aktiv, hält das Aktivitätsprotokoll pro Datei fest, wie viele Datensätze übersprungen wurden (und warum).
load-load = Laden
load-abort = Abbrechen
load-abort-help = Stoppt, sobald die gerade geparste Datei fertig ist (bei einer großen einzelnen Datei am nächsten internen Kontrollpunkt) — bereits Eingefügtes bleibt erhalten, nichts wird zurückgerollt.
load-parsing-progress = Parsen: { $done } / { $total } MB
load-loading = Laden...
load-loading-entries = Laden... { $count ->
    [one] bisher { $count } Eintrag
   *[other] bisher { $count } Einträge
}
load-done = { $entries ->
    [one] { $entries } Eintrag
   *[other] { $entries } Einträge
} geladen und { $tags ->
    [one] { $tags } Tag
   *[other] { $tags } Tags
} vergeben in { $seconds } s
load-aborted = Abgebrochen
load-records-skipped = { $count ->
    [one] { $count } Datensatz übersprungen („Fehlerhafte Datensätze überspringen“ war aktiv)
   *[other] { $count } Datensätze übersprungen („Fehlerhafte Datensätze überspringen“ war aktiv)
}
load-records-skipped-help = Aufschlüsselung pro Datei und Gründe im Aktivitätsprotokoll.
load-files-skipped = { $count ->
    [one] { $count } Datei übersprungen
   *[other] { $count } Dateien übersprungen
}
