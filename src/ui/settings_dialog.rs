//! "Settings" dialog — currently just the sessions-directory override (see
//! [`crate::config::Settings`]). Same Closed/open-state-enum +
//! `ui() -> Option<Outcome>` pattern as `TagDialog`/`SessionManagerDialog`:
//! this module only renders widgets and reports what the analyst
//! confirmed, `app.rs` owns actually persisting it to disk.

use eframe::egui;

use crate::config::{self, Settings};

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
                    ui.label("Parse threads for folder loads:");
                    ui.horizontal(|ui| {
                        let mut automatic = draft.load_threads.is_none();
                        if ui.checkbox(&mut automatic, "Automatic").changed() {
                            draft.load_threads = (!automatic).then(config::default_load_threads);
                        }
                        if let Some(mut value) = draft.load_threads {
                            if ui
                                .add(egui::DragValue::new(&mut value).range(1..=64))
                                .changed()
                            {
                                draft.load_threads = Some(value);
                            }
                        } else {
                            ui.weak(format!(
                                "({} on this machine)",
                                config::default_load_threads()
                            ));
                        }
                    });
                    ui.label(
                        "Only used when a folder load resolves to more than one file \
                         (EVTX/journald/Text). AUL and single-file loads always run on \
                         one thread — there's nothing to parallelize.",
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
