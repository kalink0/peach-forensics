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
    /// more here than for the app's smaller, quicker dialogs. See
    /// `egui::Context::show_viewport_immediate`'s doc comment: the
    /// callback gets `&mut Ui` directly (not a `Window` to `.show()`), and
    /// the OS-level close button (as opposed to the in-UI "Close" button
    /// below) surfaces as `close_requested()` on that viewport's input —
    /// both are treated the same way here.
    pub fn ui(&mut self, ctx: &egui::Context) {
        let Self::Open(state) = self else {
            return;
        };
        let OpenRawFieldsDialog {
            entry,
            fields_pretty,
        } = state.as_ref();
        let mut close = false;

        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("peach_raw_fields_dialog"),
            egui::ViewportBuilder::default()
                .with_title("Raw / Fields")
                .with_inner_size([500.0, 500.0])
                .with_resizable(true),
            |ui, _class| {
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.label(format!(
                        "{} — {}",
                        entry.timestamp_utc,
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
                            egui::Label::new(
                                egui::RichText::new(fields_pretty.as_str()).monospace(),
                            )
                            .selectable(true)
                            .wrap(),
                        );
                    });

                    ui.separator();
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
                if ui.ctx().input(|i| i.viewport().close_requested()) {
                    close = true;
                }
            },
        );

        if close {
            *self = Self::Closed;
        }
    }
}
