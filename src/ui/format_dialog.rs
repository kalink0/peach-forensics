//! "Define format..." dialog — a regex-based text-log parser config
//! builder with a live preview against real lines from the source file
//! being loaded, and a saved/loadable config library. Opened from the
//! source picker when `Text (config-based)` is selected (see `app.rs`),
//! not from the timeline's row context menu like most other dialogs here.
//!
//! Same division of labor as every other dialog in this module: this only
//! renders widgets and reports what the analyst did
//! ([`FormatDialogOutcome`]) — `app.rs` owns the `parsers/` directory via
//! [`crate::parsers::text_config_file`] and calls [`FormatDialog::set_saved`]
//! / [`FormatDialog::set_draft`] afterward so the dialog reflects the
//! change without closing and reopening it.
//!
//! The preview reuses [`crate::parsers::text_config::parse_block`] and
//! [`crate::parsers::text_config::parse_fixed_offset`] directly — the same
//! functions a real load calls — so what's shown here can never drift from
//! what actually happens on **Load**. Each preview line is treated as its
//! own single-line block; `multiline_start_pattern` isn't exercised by the
//! preview, since grouping only matters across the file as a whole, not
//! within an arbitrary N-line sample.

use std::collections::HashMap;
use std::path::PathBuf;

use eframe::egui;
use regex::Regex;

use crate::parsers::text_config::{parse_block, parse_fixed_offset};
use crate::parsers::text_config_file::{SavedConfig, TextFormatDraft};
use crate::ui::colors::categorical_color;
use crate::ui::dialog_window::show_dialog_window;

/// What the analyst did — `app.rs` executes it against the `parsers/`
/// directory.
pub enum FormatDialogOutcome {
    /// "Save": persist under the draft's name, keep the dialog open.
    Save(TextFormatDraft),
    /// "Save & Use": persist, then make it the active parser config for
    /// the source about to be loaded.
    SaveAndUse(TextFormatDraft),
    /// "Load": replace the draft with the config at this path.
    Load(PathBuf),
}

pub enum FormatDialog {
    Closed,
    // Boxed: `Closed` carries nothing, so an unboxed `OpenFormatDialog` here
    // (it holds a `TextFormatDraft` and a `Vec<String>` preview) would make
    // every `FormatDialog` value, including the near-always-current
    // `Closed` one, as large as the biggest variant — same reasoning as
    // `RawFieldsDialog`.
    Open(Box<OpenFormatDialog>),
}

pub struct OpenFormatDialog {
    /// Up to a few dozen lines read directly from the picked source file —
    /// see `app.rs`'s open call for the exact cap. Fixed for the dialog's
    /// lifetime; re-picking a different source closes and reopens this
    /// dialog rather than swapping the preview under the analyst mid-edit.
    preview_lines: Vec<String>,
    draft: TextFormatDraft,
    saved: Vec<SavedConfig>,
    selected_saved: Option<PathBuf>,
    /// Set after a failed Save/Load (a disk error, or a chosen saved file
    /// that no longer parses) — cleared on the next successful action.
    error: Option<String>,
}

impl FormatDialog {
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    pub fn open(
        preview_lines: Vec<String>,
        draft: TextFormatDraft,
        saved: Vec<SavedConfig>,
    ) -> Self {
        Self::Open(Box::new(OpenFormatDialog {
            preview_lines,
            draft,
            saved,
            selected_saved: None,
            error: None,
        }))
    }

    /// Refreshes the saved-configs list — called by `app.rs` after a
    /// successful Save, so a just-saved config shows up in the picker
    /// immediately. A no-op if the dialog isn't open (closed via "Save &
    /// Use" before the write finished, or "Cancel").
    pub fn set_saved(&mut self, new_saved: Vec<SavedConfig>) {
        if let Self::Open(state) = self {
            state.saved = new_saved;
        }
    }

    /// Replaces the draft with a freshly-loaded one — called by `app.rs`
    /// after [`FormatDialogOutcome::Load`] succeeds.
    pub fn set_draft(&mut self, new_draft: TextFormatDraft) {
        if let Self::Open(state) = self {
            state.draft = new_draft;
            state.error = None;
        }
    }

    /// Records a failed Save/Load so the dialog can show it — called by
    /// `app.rs` instead of `set_saved`/`set_draft` when the corresponding
    /// operation failed.
    pub fn set_error(&mut self, message: String) {
        if let Self::Open(state) = self {
            state.error = Some(message);
        }
    }

    pub fn ui(&mut self, ctx: &egui::Context) -> Option<FormatDialogOutcome> {
        let mut outcome = None;
        let mut close = false;

        if let Self::Open(state) = self {
            let OpenFormatDialog {
                preview_lines,
                draft,
                saved,
                selected_saved,
                error,
            } = state.as_mut();
            close = show_dialog_window(
                ctx,
                "peach_format_dialog",
                "Define Text Format",
                [760.0, 620.0],
                true,
                |ui, close| {
                    ui.horizontal(|ui| {
                        ui.label("Saved configs:");
                        let selected_name = selected_saved
                            .as_ref()
                            .and_then(|path| saved.iter().find(|s| &s.path == path))
                            .map(|s| s.name.clone())
                            .unwrap_or_else(|| "— select —".to_string());
                        egui::ComboBox::from_id_salt("format_dialog_saved_configs")
                            .selected_text(selected_name)
                            .show_ui(ui, |ui| {
                                for s in saved.iter() {
                                    ui.selectable_value(
                                        selected_saved,
                                        Some(s.path.clone()),
                                        format!("{} ({})", s.name, s.sourcetype),
                                    );
                                }
                            });
                        if ui
                            .add_enabled(selected_saved.is_some(), egui::Button::new("Load"))
                            .clicked()
                            && let Some(path) = selected_saved.clone()
                        {
                            outcome = Some(FormatDialogOutcome::Load(path));
                        }
                    });

                    ui.separator();

                    egui::Grid::new("format_dialog_fields")
                        .num_columns(2)
                        .spacing([8.0, 6.0])
                        .show(ui, |ui| {
                            ui.label("Name:");
                            ui.text_edit_singleline(&mut draft.name);
                            ui.end_row();

                            ui.label("Sourcetype:");
                            ui.text_edit_singleline(&mut draft.sourcetype);
                            ui.end_row();

                            ui.label("Pattern regex:");
                            ui.add(
                                egui::TextEdit::singleline(&mut draft.regex)
                                    .font(egui::TextStyle::Monospace),
                            );
                            ui.end_row();

                            ui.label("Timestamp format:");
                            ui.add(
                                egui::TextEdit::singleline(&mut draft.timestamp_format)
                                    .font(egui::TextStyle::Monospace),
                            );
                            ui.end_row();

                            ui.label("Multiline start pattern:");
                            ui.add(
                                egui::TextEdit::singleline(&mut draft.multiline_start_pattern)
                                    .font(egui::TextStyle::Monospace)
                                    .hint_text("optional"),
                            );
                            ui.end_row();

                            ui.label("Assume offset:");
                            ui.add(
                                egui::TextEdit::singleline(&mut draft.assume_offset)
                                    .hint_text("e.g. +02:00 — only if the format has no timezone"),
                            );
                            ui.end_row();

                            ui.label("Level capture group:");
                            ui.text_edit_singleline(&mut draft.level_group);
                            ui.end_row();

                            ui.label("Message capture group:");
                            ui.text_edit_singleline(&mut draft.message_group);
                            ui.end_row();
                        });

                    ui.weak(
                        "Every named capture group becomes a searchable field regardless — \
                         Level/Message above only control which two get promoted to Peach's \
                         normalized columns.",
                    );

                    ui.separator();
                    ui.label(format!(
                        "Live preview — first {} line(s) of the source file:",
                        preview_lines.len()
                    ));
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .show(ui, |ui| {
                            render_preview(ui, preview_lines, draft);
                        });

                    if let Some(message) = error {
                        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), message.as_str());
                    }

                    ui.separator();
                    ui.horizontal(|ui| {
                        let saveable = draft.is_saveable();
                        if ui
                            .add_enabled(saveable, egui::Button::new("Save"))
                            .clicked()
                        {
                            outcome = Some(FormatDialogOutcome::Save(draft.clone()));
                        }
                        // Deliberately doesn't set `close` here, unlike
                        // every other dialog's single-shot action button —
                        // if the save fails, `app.rs` reports it via
                        // `set_error` instead of closing, so the failure
                        // stays visible rather than the dialog just
                        // vanishing. `app.rs` closes this explicitly once
                        // the write actually succeeds.
                        if ui
                            .add_enabled(saveable, egui::Button::new("Save & Use"))
                            .clicked()
                        {
                            outcome = Some(FormatDialogOutcome::SaveAndUse(draft.clone()));
                        }
                        if ui.button("Cancel").clicked() {
                            *close = true;
                        }
                    });
                },
            );
        }

        if close {
            *self = Self::Closed;
        }
        outcome
    }
}

/// One row per preview line: line number, match/no-match marker, the line
/// itself with named capture groups colour-highlighted, and — since a
/// highlighted match doesn't guarantee the *timestamp* parses — the same
/// per-line result [`parse_block`] would actually produce on a real load
/// (resolved level/message/timestamp, or its exact error message).
fn render_preview(ui: &mut egui::Ui, preview_lines: &[String], draft: &TextFormatDraft) {
    if preview_lines.is_empty() {
        ui.weak("(source file has no lines to preview)");
        return;
    }

    let regex = match Regex::new(draft.regex.trim()) {
        Ok(regex) => regex,
        Err(err) => {
            ui.colored_label(
                egui::Color32::from_rgb(220, 80, 80),
                format!("Invalid regex: {err}"),
            );
            return;
        }
    };

    let assume_offset = if draft.assume_offset.trim().is_empty() {
        None
    } else {
        match parse_fixed_offset(&draft.assume_offset) {
            Ok(offset) => Some(offset),
            Err(err) => {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 80, 80),
                    format!("Invalid assume offset: {err:#}"),
                );
                return;
            }
        }
    };

    let mut field_mapping = HashMap::new();
    if !draft.level_group.trim().is_empty() {
        field_mapping.insert("level".to_string(), draft.level_group.trim().to_string());
    }
    if !draft.message_group.trim().is_empty() {
        field_mapping.insert(
            "message".to_string(),
            draft.message_group.trim().to_string(),
        );
    }

    let dark_mode = ui.visuals().dark_mode;
    for (i, line) in preview_lines.iter().enumerate() {
        let line_no = i + 1;
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(format!("{line_no:>4}"))
                    .weak()
                    .monospace(),
            );
            ui.label(highlighted_line(line, &regex, dark_mode));
        });

        match parse_block(
            line_no,
            &[line.as_str()],
            &regex,
            draft.timestamp_format.trim(),
            assume_offset,
            &field_mapping,
        ) {
            Ok(record) => {
                ui.indent(("format_preview_ok", i), |ui| {
                    ui.weak(format!(
                        "→ {}  level={:?}  message={:?}",
                        record.timestamp_utc, record.level, record.message
                    ));
                });
            }
            Err(err) => {
                ui.indent(("format_preview_err", i), |ui| {
                    ui.colored_label(egui::Color32::from_rgb(220, 80, 80), format!("→ {err:#}"));
                });
            }
        }
    }
}

/// Renders `line` as an [`egui::text::LayoutJob`] with every named capture
/// group of `regex` highlighted in a colour hashed from its own name (via
/// [`categorical_color`], the same function the Level/Tags timeline
/// columns use) — the same group always gets the same colour across
/// preview refreshes and across sessions, not reassigned by scan order.
fn highlighted_line(line: &str, regex: &Regex, dark_mode: bool) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let font_id = egui::FontId::monospace(12.0);
    let default_color = egui::Color32::GRAY;

    let Some(captures) = regex.captures(line) else {
        job.append(line, 0.0, egui::TextFormat::simple(font_id, default_color));
        return job;
    };

    let mut spans: Vec<(usize, usize, egui::Color32)> = regex
        .capture_names()
        .flatten()
        .filter_map(|name| {
            let m = captures.name(name)?;
            Some((m.start(), m.end(), categorical_color(name, dark_mode)))
        })
        .collect();
    spans.sort_by_key(|(start, ..)| *start);

    let mut pos = 0;
    for (start, end, color) in spans {
        if start < pos {
            continue; // overlapping named groups — keep the first, same as crush's preview
        }
        if pos < start {
            job.append(
                &line[pos..start],
                0.0,
                egui::TextFormat::simple(font_id.clone(), default_color),
            );
        }
        job.append(
            &line[start..end],
            0.0,
            egui::TextFormat::simple(font_id.clone(), color),
        );
        pos = end;
    }
    if pos < line.len() {
        job.append(
            &line[pos..],
            0.0,
            egui::TextFormat::simple(font_id, default_color),
        );
    }
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_draft() -> TextFormatDraft {
        TextFormatDraft {
            name: "Nginx".to_string(),
            ..Default::default()
        }
    }

    fn sample_saved() -> Vec<SavedConfig> {
        vec![SavedConfig {
            path: PathBuf::from("/tmp/nginx.toml"),
            name: "Nginx".to_string(),
            sourcetype: "nginx".to_string(),
        }]
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!FormatDialog::Closed.is_open());
    }

    #[test]
    fn open_starts_with_the_given_preview_draft_and_saved_list() {
        let dialog =
            FormatDialog::open(vec!["line one".to_string()], sample_draft(), sample_saved());
        assert!(dialog.is_open());
        let FormatDialog::Open(state) = &dialog else {
            panic!("expected Open");
        };
        assert_eq!(state.preview_lines, vec!["line one".to_string()]);
        assert_eq!(state.draft, sample_draft());
        assert_eq!(state.saved, sample_saved());
        assert!(state.selected_saved.is_none());
        assert!(state.error.is_none());
    }

    #[test]
    fn set_saved_replaces_the_list_while_open() {
        let mut dialog = FormatDialog::open(Vec::new(), sample_draft(), Vec::new());
        dialog.set_saved(sample_saved());
        let FormatDialog::Open(state) = &dialog else {
            panic!("expected Open");
        };
        assert_eq!(state.saved, sample_saved());
    }

    #[test]
    fn set_saved_is_a_no_op_when_closed() {
        let mut dialog = FormatDialog::Closed;
        dialog.set_saved(sample_saved());
        assert!(!dialog.is_open());
    }

    #[test]
    fn set_draft_replaces_the_draft_and_clears_any_error() {
        let mut dialog = FormatDialog::open(Vec::new(), TextFormatDraft::default(), Vec::new());
        dialog.set_error("boom".to_string());
        dialog.set_draft(sample_draft());
        let FormatDialog::Open(state) = &dialog else {
            panic!("expected Open");
        };
        assert_eq!(state.draft, sample_draft());
        assert!(state.error.is_none());
    }

    #[test]
    fn set_error_is_visible_until_the_next_set_draft() {
        let mut dialog = FormatDialog::open(Vec::new(), sample_draft(), Vec::new());
        dialog.set_error("disk full".to_string());
        let FormatDialog::Open(state) = &dialog else {
            panic!("expected Open");
        };
        assert_eq!(state.error.as_deref(), Some("disk full"));
    }
}
