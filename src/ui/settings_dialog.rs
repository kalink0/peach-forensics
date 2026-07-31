//! "Settings" dialog — currently just the sessions-directory override (see
//! [`crate::config::Settings`]). Same Closed/open-state-enum +
//! `ui() -> Option<Outcome>` pattern as `TagDialog`/`SessionManagerDialog`:
//! this module only renders widgets and reports what the analyst
//! confirmed, `app.rs` owns actually persisting it to disk.

use eframe::egui;

use crate::config::Settings;

pub enum SettingsOutcome {
    Save(Settings),
}

pub enum SettingsDialog {
    Closed,
    Open {
        /// Editable copy — discarded on Cancel, only becomes the real
        /// settings on Save.
        draft: Settings,
    },
}

impl SettingsDialog {
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    pub fn open(current: Settings) -> Self {
        Self::Open { draft: current }
    }

    pub fn ui(&mut self, ctx: &egui::Context) -> Option<SettingsOutcome> {
        let mut outcome = None;
        let mut close = false;

        if let Self::Open { draft } = self {
            egui::Window::new("Settings")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Sessions directory:");
                    ui.horizontal(|ui| {
                        let current = draft
                            .sessions_dir
                            .as_ref()
                            .map(|dir| dir.display().to_string())
                            .unwrap_or_else(|| "(default)".to_string());
                        ui.label(current);
                        if ui.button("Choose...").clicked()
                            && let Some(picked) = rfd::FileDialog::new().pick_folder()
                        {
                            draft.sessions_dir = Some(picked);
                        }
                        if draft.sessions_dir.is_some() && ui.button("Reset to default").clicked() {
                            draft.sessions_dir = None;
                        }
                    });
                    ui.label(
                        "Applies to new sessions from now on — the session currently open, \
                         and sessions already saved elsewhere, stay where they are.",
                    );

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            outcome = Some(SettingsOutcome::Save(draft.clone()));
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
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
