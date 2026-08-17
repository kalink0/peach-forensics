//! "Display timezone" — a small, focused window opened from View menu.
//!
//! Originally this lived directly inside the View menu as a nested
//! `menu_button` popup (the same shape `View > Theme` already used), with
//! a live `egui::TextEdit` right there. In practice, typing into a text
//! field inside a transient popup menu was unreliable — egui's menu popups
//! are built to close on pointer-away/outside-click, and that logic can
//! fight with a text field that wants to keep keyboard focus while the
//! pointer isn't necessarily still over the button that opened it. Every
//! other text field in this app lives in a real window (`show_dialog_window`)
//! and none of those have this problem, so this one now does too instead of
//! trying to make text input reliable inside a popup.
//!
//! Same division of labor as every other dialog here: this only renders
//! the field and reports a validated value — `app.rs` owns applying it to
//! `Settings`/`TimelineView` and persisting it.

use eframe::egui;

use crate::ui::dialog_window::show_dialog_window;
use crate::ui::settings_dialog::parse_timezone_field;

pub enum DisplayTimezoneDialog {
    Closed,
    Open { input: String },
}

impl DisplayTimezoneDialog {
    /// `current` is `Settings::display_timezone` — `None`/blank means UTC.
    pub fn open(current: Option<&str>) -> Self {
        Self::Open {
            input: current.unwrap_or_default().to_string(),
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Renders the dialog if open (a no-op otherwise). Returns `Some(value)`
    /// exactly on the frame the text changes to something that parses
    /// (`Ok`) — blank included, which parses to `Ok(None)` — so `app.rs`
    /// can apply it immediately, the same "no separate Save click" shape
    /// `View > Theme` already has. An in-progress invalid value shows its
    /// own error inline and simply doesn't produce an outcome that frame,
    /// rather than applying anything.
    pub fn ui(&mut self, ctx: &egui::Context) -> Option<Option<String>> {
        let mut outcome = None;
        let mut close = false;

        if let Self::Open { input } = self {
            close = show_dialog_window(
                ctx,
                "peach_display_timezone_dialog",
                "Display Timezone",
                [380.0, 150.0],
                true,
                |ui, close| {
                    ui.label("How the timeline and export show timestamps:");
                    let response = ui.add(
                        egui::TextEdit::singleline(input)
                            .hint_text("+0100, +02:00, UTC, or Europe/Berlin — blank means UTC"),
                    );
                    match parse_timezone_field(input) {
                        Ok(value) => {
                            if response.changed() {
                                outcome = Some(value);
                            }
                        }
                        Err(err) => {
                            ui.colored_label(ui.visuals().error_fg_color, err);
                        }
                    }
                    ui.separator();
                    if ui.button("Close").clicked() {
                        *close = true;
                    }
                },
            );
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

    #[test]
    fn open_seeds_the_input_from_the_current_value() {
        let dialog = DisplayTimezoneDialog::open(Some("Europe/Berlin"));
        assert!(matches!(
            &dialog,
            DisplayTimezoneDialog::Open { input } if input == "Europe/Berlin"
        ));
    }

    #[test]
    fn open_seeds_an_empty_input_when_none_is_set() {
        let dialog = DisplayTimezoneDialog::open(None);
        assert!(matches!(
            &dialog,
            DisplayTimezoneDialog::Open { input } if input.is_empty()
        ));
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!DisplayTimezoneDialog::Closed.is_open());
    }

    #[test]
    fn open_is_open() {
        assert!(DisplayTimezoneDialog::open(None).is_open());
    }
}
