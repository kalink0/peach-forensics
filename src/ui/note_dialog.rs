//! "Notes" dialog, opened from the timeline's row context menu (see
//! [`crate::ui::timeline_view::RowAction::ManageNotes`]) — lists every
//! existing note on one event with edit/delete controls, plus a field to
//! add a new one. Free-text notes are independent of tags entirely (no tag
//! picker here at all, unlike [`crate::ui::tag_dialog::TagDialog`]).
//!
//! Same division of labor as `tag_dialog`: this module only renders the
//! widget and reports what the analyst did — `app.rs` owns the session DB,
//! calling `session::persist::{insert_event_note, update_event_note,
//! delete_event_note}` and re-fetching via `notes_for_event` so the dialog
//! reflects the change immediately, without closing and reopening it.

use eframe::egui;

use crate::model::event_id::EventId;

/// What the analyst did — `app.rs` executes it against the session DB, then
/// calls [`NoteDialog::set_notes`] with a fresh `notes_for_event` read so
/// the list on screen reflects the change right away.
pub enum NoteDialogOutcome {
    Add { event_id: EventId, text: String },
    Update { note_id: i64, text: String },
    Delete { note_id: i64 },
}

pub enum NoteDialog {
    Closed,
    Open {
        event_id: EventId,
        /// `(note_id, text)` pairs, oldest first — mirrors
        /// `session::persist::notes_for_event`'s return shape directly, so
        /// `app.rs` can hand its result straight to [`Self::set_notes`].
        notes: Vec<(i64, String)>,
        /// The note currently being edited, if any: `(note_id, draft
        /// text)`. Only one at a time — editing a second note while the
        /// first edit is unsaved would need its own draft slot for no real
        /// benefit, so opening a new edit discards an unsaved one.
        editing: Option<(i64, String)>,
        new_text: String,
    },
}

impl NoteDialog {
    pub fn open(event_id: EventId, notes: Vec<(i64, String)>) -> Self {
        Self::Open {
            event_id,
            notes,
            editing: None,
            new_text: String::new(),
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Replaces the note list with a freshly-fetched one — called by
    /// `app.rs` right after executing an [`NoteDialogOutcome`], so an
    /// add/edit/delete shows up immediately instead of only after the
    /// dialog is closed and reopened. A no-op if the dialog isn't open
    /// (e.g. the analyst closed it before the DB round-trip finished).
    pub fn set_notes(&mut self, notes: Vec<(i64, String)>) {
        if let Self::Open { notes: current, .. } = self {
            *current = notes;
        }
    }

    /// Renders the dialog if open (a no-op otherwise).
    pub fn ui(&mut self, ctx: &egui::Context) -> Option<NoteDialogOutcome> {
        let mut outcome = None;
        let mut close = false;

        if let Self::Open {
            event_id,
            notes,
            editing,
            new_text,
        } = self
        {
            egui::Window::new("Notes")
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    if notes.is_empty() {
                        ui.weak("No notes on this event yet.");
                    }
                    for (note_id, text) in notes.iter() {
                        ui.separator();
                        let is_editing = editing.as_ref().is_some_and(|(id, _)| id == note_id);
                        if is_editing {
                            // A local copy, not a direct `&mut` borrow into
                            // `editing`: egui's closure below would need a
                            // second mutable borrow of `editing` (to clear
                            // it on Save/Cancel) while the first was still
                            // alive. Written back into `*editing` at the
                            // end so keystrokes still persist across frames
                            // when neither button was clicked this one.
                            let mut draft = editing
                                .as_ref()
                                .map(|(_, text)| text.clone())
                                .unwrap_or_default();
                            ui.text_edit_multiline(&mut draft);
                            let mut save_clicked = false;
                            let mut cancel_clicked = false;
                            ui.horizontal(|ui| {
                                save_clicked = ui.button("Save").clicked();
                                cancel_clicked = ui.button("Cancel").clicked();
                            });
                            if save_clicked {
                                let trimmed = draft.trim();
                                if !trimmed.is_empty() {
                                    outcome = Some(NoteDialogOutcome::Update {
                                        note_id: *note_id,
                                        text: trimmed.to_string(),
                                    });
                                }
                                *editing = None;
                            } else if cancel_clicked {
                                *editing = None;
                            } else {
                                *editing = Some((*note_id, draft));
                            }
                        } else {
                            ui.label(text);
                            ui.horizontal(|ui| {
                                if ui.button("Edit").clicked() {
                                    *editing = Some((*note_id, text.clone()));
                                }
                                if ui.button("Delete").clicked() {
                                    outcome = Some(NoteDialogOutcome::Delete { note_id: *note_id });
                                }
                            });
                        }
                    }

                    ui.separator();
                    ui.label("New note:");
                    ui.text_edit_multiline(new_text);
                    ui.horizontal(|ui| {
                        let trimmed = new_text.trim();
                        if ui
                            .add_enabled(!trimmed.is_empty(), egui::Button::new("Add"))
                            .clicked()
                        {
                            outcome = Some(NoteDialogOutcome::Add {
                                event_id: *event_id,
                                text: trimmed.to_string(),
                            });
                            new_text.clear();
                        }
                        if ui.button("Close").clicked() {
                            close = true;
                        }
                    });
                });
        }

        if close {
            *self = Self::Closed;
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::event_id::{SequenceCounter, SourceFileId};

    fn sample_event_id() -> EventId {
        EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceCounter::new().next_sequence_number(),
        }
    }

    #[test]
    fn open_starts_with_the_given_notes_and_no_draft() {
        let dialog = NoteDialog::open(sample_event_id(), vec![(1, "existing".to_string())]);
        assert!(dialog.is_open());
        assert!(matches!(
            &dialog,
            NoteDialog::Open { notes, editing, new_text, .. }
            if notes == &vec![(1, "existing".to_string())]
                && editing.is_none()
                && new_text.is_empty()
        ));
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!NoteDialog::Closed.is_open());
    }

    #[test]
    fn set_notes_replaces_the_list_while_open() {
        let mut dialog = NoteDialog::open(sample_event_id(), vec![(1, "old".to_string())]);

        dialog.set_notes(vec![(1, "old".to_string()), (2, "new".to_string())]);

        assert!(matches!(
            &dialog,
            NoteDialog::Open { notes, .. }
            if notes == &vec![(1, "old".to_string()), (2, "new".to_string())]
        ));
    }

    #[test]
    fn set_notes_is_a_no_op_when_closed() {
        let mut dialog = NoteDialog::Closed;

        dialog.set_notes(vec![(1, "irrelevant".to_string())]);

        assert!(!dialog.is_open());
    }
}
