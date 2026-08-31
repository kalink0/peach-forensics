//! "Activity Log" dialog — read-only review of every load/re-tag operation
//! this session has run, persisted in the session DB's `activity_log` table
//! (see `db::session_schema::setup_session_schema`'s doc comment on why:
//! logged on both success and failure, so a problem never quietly
//! disappears). Opened from the "View" menu; `app.rs` owns the session DB
//! and hands this dialog a freshly-read `Vec<ActivityLogEntry>` each time it
//! (re)opens — same division of labor as `note_dialog`/`tag_dialog`, but
//! read-only, so there's no outcome type to report back.

use eframe::egui;

use crate::session::persist::ActivityLogEntry;
use crate::ui::dialog_window::show_dialog_window;

pub enum ActivityLogDialog {
    Closed,
    Open { entries: Vec<ActivityLogEntry> },
}

impl ActivityLogDialog {
    pub fn open(entries: Vec<ActivityLogEntry>) -> Self {
        Self::Open { entries }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Replaces the entry list with a freshly-fetched one — called by
    /// `app.rs` right after a load/re-tag finishes, so a still-open dialog
    /// reflects the new entry immediately instead of only after being
    /// closed and reopened (same shape as `NoteDialog::set_notes`). A
    /// no-op if the dialog isn't open.
    pub fn set_entries(&mut self, entries: Vec<ActivityLogEntry>) {
        if let Self::Open { entries: current } = self {
            *current = entries;
        }
    }

    /// Renders the dialog if open (a no-op otherwise).
    pub fn ui(&mut self, ctx: &egui::Context) {
        let mut close = false;

        if let Self::Open { entries } = self {
            close = show_dialog_window(
                ctx,
                "peach_activity_log_dialog",
                "Activity Log",
                [640.0, 480.0],
                true,
                |ui, close| {
                    // Pinned to the bottom *before* the scroll area below —
                    // an unbounded `ScrollArea` claims all remaining space
                    // in its parent `Ui` first, which would push a trailing
                    // "Close" button below the window's visible area for
                    // any entry list tall enough to need scrolling.
                    // `Panel::bottom` reserves its own space up front
                    // regardless of source order, so the button stays
                    // visible and the scroll area gets exactly what's left.
                    egui::Panel::bottom("peach_activity_log_dialog_bottom_bar").show(ui, |ui| {
                        ui.add_space(4.0);
                        if ui.button("Close").clicked() {
                            *close = true;
                        }
                        ui.add_space(4.0);
                    });

                    if entries.is_empty() {
                        ui.weak("No load or re-tag operations recorded yet in this session.");
                    }
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for entry in entries.iter() {
                            render_entry(ui, entry);
                            ui.separator();
                        }
                    });
                },
            );
        }

        if close {
            *self = Self::Closed;
        }
    }
}

/// Formats a Unix-epoch-seconds timestamp as a UTC string — same UTC-first
/// convention as the timeline itself. Falls back to the raw number on the
/// (never expected in practice) case that `secs` isn't representable,
/// rather than panicking on a display-only path.
fn format_utc(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| secs.to_string())
}

fn render_entry(ui: &mut egui::Ui, entry: &ActivityLogEntry) {
    ui.horizontal(|ui| {
        let operation_label = match entry.operation.as_str() {
            "load" => "Load",
            "retag" => "Re-tag",
            "import" => "Import",
            other => other,
        };
        ui.strong(operation_label);
        match entry.status.as_str() {
            "ok" => {
                ui.colored_label(egui::Color32::from_rgb(0, 160, 0), "OK");
            }
            "cancelled" => {
                ui.colored_label(egui::Color32::from_rgb(230, 160, 0), "Aborted")
                    .on_hover_text(
                        "Stopped early by the analyst — counts below are real, just less \
                         than a full run would have produced.",
                    );
            }
            _ => {
                ui.colored_label(egui::Color32::RED, "Failed");
            }
        }
        ui.label(format!(
            "{} \u{2192} {}",
            format_utc(entry.started_at),
            format_utc(entry.finished_at)
        ));
        if entry.skip_bad_records_enabled {
            ui.weak("(skip bad records was on)");
        }
    });

    if let Some(source_path) = &entry.source_path {
        if entry.operation == "import" {
            // `source_path` holds the portable case's `original_session_id`
            // for an import entry, not an evidence file path — see
            // `session::portable_case::import_portable_case`.
            ui.label(format!("Imported from {source_path}"));
        } else {
            let sourcetype = entry.sourcetype.as_deref().unwrap_or("?");
            ui.label(format!("{source_path} ({sourcetype})"));
        }
    }

    if let Some(err) = &entry.error {
        // A failed entry has no `entries_inserted`/`tags_applied` to speak
        // of — showing the error takes the place of the summary line below,
        // rather than both rendering side by side (which would otherwise
        // read as "loaded 0 entries", a misleading way to describe "never
        // got that far").
        ui.colored_label(egui::Color32::RED, err);
    } else {
        let summary = match entry.operation.as_str() {
            "load" => format!(
                "Loaded {} entries, applied {} tags",
                entry.entries_inserted.unwrap_or(0),
                entry.tags_applied.unwrap_or(0),
            ),
            "retag" => format!("Applied {} tags", entry.tags_applied.unwrap_or(0)),
            _ => String::new(),
        };
        if !summary.is_empty() {
            ui.label(summary);
        }
    }

    if !entry.skipped.is_empty() {
        ui.colored_label(
            egui::Color32::from_rgb(230, 160, 0),
            format!("{} file(s) skipped", entry.skipped.len()),
        );
        for file in &entry.skipped {
            ui.label(format!("  {}: {}", file.path, file.reason));
        }
    }

    let total_records_skipped: usize = entry.per_file.iter().map(|f| f.records_skipped).sum();
    if total_records_skipped > 0 {
        ui.colored_label(
            egui::Color32::from_rgb(230, 160, 0),
            format!("{total_records_skipped} record(s) skipped instead of failing their file"),
        );
    }

    // Only worth a separate breakdown for a multi-file load — a single
    // file's count already duplicates the summary line above and the
    // source path line, so showing it again here would be noise. A skipped-
    // records count is the exception: worth showing even for one file,
    // since it's not duplicated anywhere else.
    if entry.per_file.len() > 1 || total_records_skipped > 0 {
        ui.label("Per file:");
        for file in &entry.per_file {
            if file.records_skipped > 0 {
                ui.label(format!(
                    "  {}: {} entries, {} skipped",
                    file.path, file.inserted, file.records_skipped
                ));
            } else {
                ui.label(format!("  {}: {} entries", file.path, file.inserted));
            }
        }
    }

    if !entry.tags_by_rule.is_empty() {
        ui.label("Per rule:");
        for rule in &entry.tags_by_rule {
            match &rule.version {
                Some(version) => ui.label(format!(
                    "  {} (v{version}): {} tags",
                    rule.rule_name, rule.count
                )),
                None => ui.label(format!("  {}: {} tags", rule.rule_name, rule.count)),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::persist::{ActivityFileCount, ActivityRuleCount, ActivitySkippedFile};

    fn sample_entry() -> ActivityLogEntry {
        ActivityLogEntry {
            id: 1,
            operation: "load".to_string(),
            started_at: 1_753_704_000,
            finished_at: 1_753_704_010,
            source_path: Some("/evidence/system.evtx".to_string()),
            sourcetype: Some("evtx".to_string()),
            status: "ok".to_string(),
            error: None,
            entries_inserted: Some(1000),
            tags_applied: Some(12),
            skipped: vec![ActivitySkippedFile {
                path: "/evidence/bad.evtx".to_string(),
                reason: "not a valid EVTX file".to_string(),
            }],
            per_file: vec![ActivityFileCount {
                path: "/evidence/system.evtx".to_string(),
                inserted: 1000,
                records_skipped: 0,
            }],
            tags_by_rule: vec![ActivityRuleCount {
                rule_name: "evtx_logon_success".to_string(),
                count: 12,
                version: Some("2".to_string()),
            }],
            skip_bad_records_enabled: false,
        }
    }

    #[test]
    fn open_starts_with_the_given_entries() {
        let dialog = ActivityLogDialog::open(vec![sample_entry()]);
        assert!(dialog.is_open());
        assert!(matches!(
            &dialog,
            ActivityLogDialog::Open { entries } if entries.len() == 1
        ));
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!ActivityLogDialog::Closed.is_open());
    }

    #[test]
    fn open_with_no_entries_is_still_open() {
        let dialog = ActivityLogDialog::open(Vec::new());
        assert!(dialog.is_open());
    }

    #[test]
    fn set_entries_replaces_the_list_while_open() {
        let mut dialog = ActivityLogDialog::open(vec![sample_entry()]);
        let mut second_entry = sample_entry();
        second_entry.id = 2;

        dialog.set_entries(vec![second_entry.clone(), sample_entry()]);

        assert!(matches!(
            &dialog,
            ActivityLogDialog::Open { entries } if entries.len() == 2 && entries[0].id == 2
        ));
    }

    #[test]
    fn set_entries_is_a_no_op_when_closed() {
        let mut dialog = ActivityLogDialog::Closed;

        dialog.set_entries(vec![sample_entry()]);

        assert!(!dialog.is_open());
    }

    #[test]
    fn format_utc_renders_a_known_timestamp() {
        // 2025-07-28 12:00:00 UTC
        assert_eq!(format_utc(1_753_704_000), "2025-07-28 12:00:00 UTC");
    }
}
