//! "View raw/fields" dialog, opened from the timeline's row context menu
//! (see [`crate::ui::timeline_view::RowAction::ViewRawFields`]) — a
//! read-only view of one event's complete `raw`/`fields` data, the same
//! [`crate::db::timeline_queries::FullEntry`] "Copy whole event as text"
//! already fetches, just shown on screen instead of only going to the
//! clipboard.
//!
//! Pure display: unlike every other dialog in `ui`, there's nothing to
//! decide here, so no outcome type and nothing for `app.rs` to execute —
//! `ui()` takes no arguments beyond the context and returns nothing.

use eframe::egui;

use crate::db::timeline_queries::FullEntry;
use crate::ui::dialog_window::show_dialog_window;

pub enum RawFieldsDialog {
    Closed,
    // Boxed: `Closed` carries nothing, so an unboxed `FullEntry` here would
    // make every `RawFieldsDialog` value (including the near-always-current
    // `Closed` one) as large as the biggest variant.
    Open(Box<OpenRawFieldsDialog>),
}

pub struct OpenRawFieldsDialog {
    entry: FullEntry,
    /// `fields`, pretty-printed once at open time rather than on every
    /// frame — reformatting a potentially-large JSON tree 60 times a
    /// second while the window is open would be wasted work for text
    /// that never changes after it's fetched.
    fields_pretty: String,
}

impl RawFieldsDialog {
    pub fn open(entry: FullEntry) -> Self {
        let fields_pretty = serde_json::to_string_pretty(&entry.fields)
            .unwrap_or_else(|_| entry.fields.to_string());
        Self::Open(Box::new(OpenRawFieldsDialog {
            entry,
            fields_pretty,
        }))
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// A real, separate OS window rather than an in-app floating panel —
    /// `raw`/`fields` can run long enough (AUL entries especially) that
    /// being able to resize freely and drag it out from under the main
    /// window (a second monitor, side-by-side with the timeline) is worth
    /// more here than for the app's smaller, quicker dialogs. This was
    /// this dialog's own bespoke reason for it before every dialog in this
    /// module got the same treatment — see
    /// [`crate::ui::dialog_window::show_dialog_window`]'s doc comment for
    /// why it's now the shared, not the exceptional, case.
    pub fn ui(&mut self, ctx: &egui::Context) {
        let Self::Open(state) = self else {
            return;
        };
        let OpenRawFieldsDialog {
            entry,
            fields_pretty,
        } = state.as_ref();

        let close = show_dialog_window(
            ctx,
            "peach_raw_fields_dialog",
            "Raw / Fields",
            [500.0, 500.0],
            true,
            |ui, close| {
                ui.label(format!(
                    "{} — {}",
                    entry.timestamp_display,
                    if entry.message.is_empty() {
                        "(no message)"
                    } else {
                        &entry.message
                    }
                ));
                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.strong("raw");
                    ui.add(
                        egui::Label::new(egui::RichText::new(&entry.raw).monospace())
                            .selectable(true)
                            .wrap(),
                    );
                    ui.add_space(8.0);
                    ui.strong("fields");
                    ui.add(
                        egui::Label::new(egui::RichText::new(fields_pretty.as_str()).monospace())
                            .selectable(true)
                            .wrap(),
                    );
                });

                ui.separator();
                if ui.button("Close").clicked() {
                    *close = true;
                }
            },
        );

        if close {
            *self = Self::Closed;
        }
    }
}
