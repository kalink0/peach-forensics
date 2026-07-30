//! The two dialogs opened from the timeline's row context menu (see
//! [`crate::ui::timeline_view::RowAction`]): a single manual tag, and
//! "advanced tagging" (create or extend a `message_contains` rule with a
//! live match-count preview).
//!
//! This module only renders widgets and reports what the analyst decided —
//! it doesn't touch the session DB or rule files itself. `app.rs` owns that
//! (session path, `rule_paths`), so it executes the returned
//! [`TagDialogOutcome`].

use std::path::PathBuf;

use eframe::egui;

use crate::model::event_id::EventId;

/// What the analyst confirmed — `app.rs` executes it.
pub enum TagDialogOutcome {
    /// "Tag this event..." confirmed: a manual `analyst_tags` entry.
    TagSingleEvent {
        event_id: EventId,
        tag_value: String,
    },
    /// "Tag all matching..." confirmed with a brand-new tag/rule.
    CreateRule {
        rule_name: String,
        pattern: String,
        tag_value: String,
    },
    /// "Tag all matching..." confirmed, reusing an existing tag by
    /// extending the one loaded rule file that already produces it.
    ExtendRule { path: PathBuf, pattern: String },
}

/// Combo box of already-used tag values, plus a "New tag..." entry that
/// reveals a text field — shared by both dialogs so a typo-prone free-text
/// field isn't the only way to pick a tag that already exists.
pub struct TagPicker {
    existing: Vec<String>,
    selected: Option<String>,
    new_name: String,
}

impl TagPicker {
    fn new(existing: Vec<String>) -> Self {
        Self {
            existing,
            selected: None,
            new_name: String::new(),
        }
    }

    /// `None` while "New tag..." is selected but no name has been typed yet
    /// — callers use this to gray out Apply rather than accept a blank tag.
    fn tag_value(&self) -> Option<String> {
        match &self.selected {
            Some(value) => Some(value.clone()),
            None => {
                let trimmed = self.new_name.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
        }
    }

    fn is_new(&self) -> bool {
        self.selected.is_none()
    }

    fn ui(&mut self, ui: &mut egui::Ui) {
        egui::ComboBox::from_label("Tag")
            .selected_text(
                self.selected
                    .clone()
                    .unwrap_or_else(|| "New tag...".to_string()),
            )
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.selected, None, "New tag...");
                for tag in self.existing.clone() {
                    let label = tag.clone();
                    ui.selectable_value(&mut self.selected, Some(tag), label);
                }
            });
        if self.is_new() {
            ui.horizontal(|ui| {
                ui.label("New tag name:");
                ui.text_edit_singleline(&mut self.new_name);
            });
        }
    }
}

pub enum TagDialog {
    Closed,
    Single {
        event_id: EventId,
        picker: TagPicker,
    },
    Advanced {
        event_id: EventId,
        pattern: String,
        picker: TagPicker,
        rule_name: String,
        extend_path: Option<PathBuf>,
    },
}

impl TagDialog {
    pub fn open_single(event_id: EventId, existing_tags: Vec<String>) -> Self {
        Self::Single {
            event_id,
            picker: TagPicker::new(existing_tags),
        }
    }

    pub fn open_advanced(event_id: EventId, message: String, existing_tags: Vec<String>) -> Self {
        Self::Advanced {
            event_id,
            pattern: message,
            picker: TagPicker::new(existing_tags),
            rule_name: String::new(),
            extend_path: None,
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// The Advanced dialog's current pattern text, if that's the one open —
    /// `app.rs` uses this to know what to run the (backgrounded, like the
    /// timeline's own search count) live match-count preview against.
    pub fn current_pattern(&self) -> Option<&str> {
        match self {
            Self::Advanced { pattern, .. } => Some(pattern.as_str()),
            _ => None,
        }
    }

    /// Renders whichever dialog is currently open (a no-op otherwise).
    /// `find_rule_for_tag` looks up the one currently-loaded rule file (if
    /// exactly one, `None` if zero or several — ambiguous) that already
    /// produces a given tag value; owned by the caller since it needs
    /// `rule_paths`, which this dialog doesn't hold. `preview` is the
    /// match count for the *current* pattern text, if the caller has one
    /// ready yet (`None` while a background count is still in flight, or
    /// briefly right after the pattern changed and a new one hasn't been
    /// kicked off yet).
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        find_rule_for_tag: impl Fn(&str) -> Option<PathBuf>,
        preview: Option<usize>,
    ) -> Option<TagDialogOutcome> {
        let mut outcome = None;
        let mut close = false;

        match self {
            Self::Closed => {}
            Self::Single { event_id, picker } => {
                egui::Window::new("Tag this event")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        picker.ui(ui);
                        ui.horizontal(|ui| {
                            let tag_value = picker.tag_value();
                            if ui
                                .add_enabled(tag_value.is_some(), egui::Button::new("Apply"))
                                .clicked()
                            {
                                outcome = Some(TagDialogOutcome::TagSingleEvent {
                                    event_id: *event_id,
                                    tag_value: tag_value.expect("Apply is disabled otherwise"),
                                });
                                close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            Self::Advanced {
                pattern,
                picker,
                rule_name,
                extend_path,
                ..
            } => {
                egui::Window::new("Advanced tagging")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label("Tag every entry whose message contains:");
                        ui.text_edit_singleline(pattern);
                        match preview {
                            Some(count) => {
                                ui.label(format!("Preview: {count} entries currently match"));
                            }
                            None if !pattern.trim().is_empty() => {
                                ui.label("Preview: counting...");
                            }
                            None => {}
                        }
                        picker.ui(ui);

                        let tag_value = picker.tag_value();
                        *extend_path = tag_value
                            .as_deref()
                            .filter(|_| !picker.is_new())
                            .and_then(&find_rule_for_tag);

                        let needs_rule_name = extend_path.is_none();
                        if !picker.is_new() {
                            match extend_path {
                                Some(path) => {
                                    ui.label(format!("Will extend existing rule: {}", path.display()));
                                }
                                None => {
                                    ui.label(
                                        "No single loaded rule produces this tag — a new rule will be created.",
                                    );
                                }
                            }
                        }
                        if needs_rule_name {
                            ui.horizontal(|ui| {
                                ui.label("New rule name:");
                                ui.text_edit_singleline(rule_name);
                            });
                        }

                        ui.horizontal(|ui| {
                            let can_apply = tag_value.is_some()
                                && !pattern.trim().is_empty()
                                && (!needs_rule_name || !rule_name.trim().is_empty());
                            if ui
                                .add_enabled(can_apply, egui::Button::new("Apply"))
                                .clicked()
                            {
                                outcome = Some(match extend_path {
                                    Some(path) => TagDialogOutcome::ExtendRule {
                                        path: path.clone(),
                                        pattern: pattern.clone(),
                                    },
                                    None => TagDialogOutcome::CreateRule {
                                        rule_name: rule_name.trim().to_string(),
                                        pattern: pattern.clone(),
                                        tag_value: tag_value.expect("Apply is disabled otherwise"),
                                    },
                                });
                                close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
        }

        if close {
            *self = Self::Closed;
        }
        outcome
    }
}
