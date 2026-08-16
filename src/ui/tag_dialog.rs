//! The two dialogs opened from the timeline's row context menu (see
//! [`crate::ui::timeline_view::RowAction`]): a single manual tag, and
//! "advanced tagging" (create or extend a tagging rule — either a
//! `message_contains` substring match or an exact match on one of the
//! clicked row's other extracted fields — with a live match-count preview).
//!
//! This module only renders widgets and reports what the analyst decided —
//! it doesn't touch the session DB or rule files itself. `app.rs` owns that
//! (session path, `rule_paths`), so it executes the returned
//! [`TagDialogOutcome`].

use std::path::PathBuf;

use eframe::egui;

use crate::model::event_id::EventId;
use crate::tagging::rule_file::RuleCondition;
use crate::ui::dialog_window::show_dialog_window;

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
        sourcetype: String,
        condition: RuleCondition,
        tag_value: String,
    },
    /// "Tag all matching..." confirmed, reusing an existing tag by
    /// extending the one loaded rule file that already produces it. Only
    /// reachable for a `message_contains` condition — see
    /// [`RuleCondition::FieldEquals`]'s doc comment on why field conditions
    /// never offer an extend path.
    ExtendRule { path: PathBuf, pattern: String },
}

/// What the Advanced dialog's currently-configured condition should be
/// previewed against — `app.rs` uses this to decide which kind of live
/// match-count query to run (see `update_tag_preview_request`).
pub enum PreviewTarget<'a> {
    MessageContains(&'a str),
    FieldEquals { field: &'static str, value: &'a str },
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

/// Which condition the Advanced dialog is currently configured to match on.
/// `MessageContains` is always available (every entry has a message, even
/// if empty); `Field` is one of the clicked row's own populated
/// `COLUMN_FILTER_FIELDS` values (Sourcetype/Host/Process/Event ID/
/// Subsystem/Category) — same set "Filter by..." offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    MessageContains,
    Field {
        field: &'static str,
        label: &'static str,
    },
}

pub enum TagDialog {
    Closed,
    Single {
        event_id: EventId,
        picker: TagPicker,
    },
    Advanced {
        event_id: EventId,
        sourcetype: String,
        /// The clicked row's original message — restored into `pattern`
        /// when switching `match_kind` back to `MessageContains`.
        message: String,
        /// The clicked row's other populated fields, `(field, label,
        /// value)` — restored into `pattern` when switching `match_kind` to
        /// that field.
        available_fields: Vec<(&'static str, &'static str, String)>,
        match_kind: MatchKind,
        /// Current condition value: a substring (`MessageContains`) or an
        /// exact value (`Field`) — meaning depends on `match_kind`.
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

    pub fn open_advanced(
        event_id: EventId,
        message: String,
        sourcetype: String,
        available_fields: Vec<(&'static str, &'static str, String)>,
        existing_tags: Vec<String>,
    ) -> Self {
        Self::Advanced {
            event_id,
            sourcetype,
            pattern: message.clone(),
            message,
            available_fields,
            match_kind: MatchKind::MessageContains,
            picker: TagPicker::new(existing_tags),
            rule_name: String::new(),
            extend_path: None,
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// What `app.rs`'s live match-count preview should run against, if the
    /// Advanced dialog is the one open — `None` otherwise (nothing to
    /// preview for the Single dialog).
    pub fn current_preview_target(&self) -> Option<PreviewTarget<'_>> {
        match self {
            Self::Advanced {
                match_kind,
                pattern,
                ..
            } => Some(match match_kind {
                MatchKind::MessageContains => PreviewTarget::MessageContains(pattern),
                MatchKind::Field { field, .. } => PreviewTarget::FieldEquals {
                    field,
                    value: pattern,
                },
            }),
            _ => None,
        }
    }

    /// Renders whichever dialog is currently open (a no-op otherwise).
    /// `find_rule_for_tag` looks up the one currently-loaded rule file (if
    /// exactly one, `None` if zero or several — ambiguous) that already
    /// produces a given tag value; owned by the caller since it needs
    /// `rule_paths`, which this dialog doesn't hold. `preview` is the
    /// match count for the *current* condition, if the caller has one ready
    /// yet (`None` while a background count is still in flight, or briefly
    /// right after the condition changed and a new one hasn't been kicked
    /// off yet).
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
                close = show_dialog_window(
                    ctx,
                    "peach_tag_single_dialog",
                    "Tag this event",
                    [360.0, 160.0],
                    true,
                    |ui, close| {
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
                                *close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                *close = true;
                            }
                        });
                    },
                );
            }
            Self::Advanced {
                sourcetype,
                message,
                available_fields,
                match_kind,
                pattern,
                picker,
                rule_name,
                extend_path,
                ..
            } => {
                close = show_dialog_window(
                    ctx,
                    "peach_tag_advanced_dialog",
                    "Advanced tagging",
                    [460.0, 360.0],
                    true,
                    |ui, close| {
                        ui.label("Match on:");
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .radio(
                                    *match_kind == MatchKind::MessageContains,
                                    "Message contains",
                                )
                                .clicked()
                                && *match_kind != MatchKind::MessageContains
                            {
                                *match_kind = MatchKind::MessageContains;
                                *pattern = message.clone();
                            }
                            for (field, label, value) in available_fields.iter() {
                                let this_kind = MatchKind::Field { field, label };
                                if ui.radio(*match_kind == this_kind, *label).clicked()
                                    && *match_kind != this_kind
                                {
                                    *match_kind = this_kind;
                                    *pattern = value.clone();
                                }
                            }
                        });

                        match match_kind {
                            MatchKind::MessageContains => {
                                ui.label("Tag every entry whose message contains:");
                                ui.text_edit_singleline(pattern);
                            }
                            MatchKind::Field { label, .. } => {
                                ui.label(format!(
                                    "Tag every {sourcetype} entry whose {label} is exactly:"
                                ));
                                ui.text_edit_singleline(pattern);
                            }
                        }
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
                        // No extend path for a field condition: the tagging
                        // engine has no OR-list support for arbitrary/
                        // normalized fields the way `message_contains` has
                        // (see `RuleCondition::FieldEquals`'s doc comment),
                        // so there's nothing to append a second value to —
                        // picking an existing tag while matching on a field
                        // always creates a fresh rule file.
                        *extend_path = match match_kind {
                            MatchKind::MessageContains => tag_value
                                .as_deref()
                                .filter(|_| !picker.is_new())
                                .and_then(&find_rule_for_tag),
                            MatchKind::Field { .. } => None,
                        };

                        let needs_rule_name = extend_path.is_none();
                        if !picker.is_new() {
                            match extend_path {
                                Some(path) => {
                                    ui.label(format!(
                                        "Will extend existing rule: {}",
                                        path.display()
                                    ));
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
                                        sourcetype: sourcetype.clone(),
                                        condition: match match_kind {
                                            MatchKind::MessageContains => {
                                                RuleCondition::MessageContains(pattern.clone())
                                            }
                                            MatchKind::Field { field, .. } => {
                                                RuleCondition::FieldEquals {
                                                    field,
                                                    value: pattern.clone(),
                                                }
                                            }
                                        },
                                        tag_value: tag_value.expect("Apply is disabled otherwise"),
                                    },
                                });
                                *close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                *close = true;
                            }
                        });
                    },
                );
            }
        }

        if close {
            *self = Self::Closed;
        }
        outcome
    }
}
