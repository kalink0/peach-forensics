//! "Settings" dialog — currently just the sessions-directory override (see
//! [`crate::config::Settings`]). Same Closed/open-state-enum +
//! `ui() -> Option<Outcome>` pattern as `TagDialog`/`SessionManagerDialog`:
//! this module only renders widgets and reports what the analyst
//! confirmed, `app.rs` owns actually persisting it to disk.

use std::path::{Path, PathBuf};

use eframe::egui;

use crate::config::{self, Settings};
use crate::session::persist;
use crate::tagging::rule_file;
use crate::ui::dialog_window::show_dialog_window;
use crate::ui::reveal;

pub enum SettingsOutcome {
    Save(Settings),
}

pub enum SettingsDialog {
    Closed,
    Open {
        /// Editable copy — discarded on Cancel, only becomes the real
        /// settings on Save.
        draft: Settings,
        /// What `sessions_dir`/`rules_dir` resolve to when left unset —
        /// resolved once when the dialog opens (not every frame: it can't
        /// change while the dialog is open, and resolving it creates the
        /// directory as a side effect via `default_sessions_dir`/
        /// `default_user_rules_dir`, not something worth repeating 60
        /// times a second). Empty on the rare platform where `ProjectDirs`
        /// can't determine a per-user data directory at all — the same
        /// failure `Settings::sessions_dir`/`rules_dir` would themselves
        /// hit, surfaced here as a blank path rather than a dialog that
        /// can't open.
        default_sessions_dir: PathBuf,
        default_rules_dir: PathBuf,
    },
}

impl SettingsDialog {
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    pub fn open(current: Settings) -> Self {
        Self::Open {
            draft: current,
            default_sessions_dir: persist::default_sessions_dir().unwrap_or_default(),
            default_rules_dir: rule_file::default_user_rules_dir().unwrap_or_default(),
        }
    }

    pub fn ui(&mut self, ctx: &egui::Context) -> Option<SettingsOutcome> {
        let mut outcome = None;
        let mut close = false;

        if let Self::Open {
            draft,
            default_sessions_dir,
            default_rules_dir,
        } = self
        {
            close = show_dialog_window(
                ctx,
                "peach_settings_dialog",
                "Settings",
                [520.0, 420.0],
                true,
                |ui, close| {
                    ui.label("Sessions directory:");
                    directory_row(ui, &mut draft.sessions_dir, default_sessions_dir);
                    ui.label(
                        "Applies to new sessions from now on — the session currently open, \
                         and sessions already saved elsewhere, stay where they are.",
                    );

                    ui.separator();
                    ui.label("Rules directory:");
                    directory_row(ui, &mut draft.rules_dir, default_rules_dir);
                    ui.label(
                        "Where \"Tag all matching (advanced)...\" saves new rules — point this \
                         at your own folder (e.g. one you keep under your own git repo) to build \
                         up a personal rule collection outside Peach's built-in packs. Every \
                         *.toml file directly in this folder loads automatically on startup, \
                         same as the built-in rule packs — saving here takes effect immediately, \
                         replacing whatever's currently selected via \"Choose tagging rules...\".",
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
                            *close = true;
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

/// One directory-override row (Sessions/Rules): the effective path — the
/// override if set, `default_dir` otherwise, always shown in full rather
/// than hidden behind a bare "(default)" — plus Choose/Reset/Open folder.
/// Shared between the two settings so they can't drift into showing the
/// path differently.
fn directory_row(ui: &mut egui::Ui, override_dir: &mut Option<PathBuf>, default_dir: &Path) {
    ui.horizontal(|ui| {
        let label = match override_dir {
            Some(dir) => dir.display().to_string(),
            None => format!("(default) {}", default_dir.display()),
        };
        ui.label(label);
        if ui.button("Choose...").clicked()
            && let Some(picked) = rfd::FileDialog::new().pick_folder()
        {
            *override_dir = Some(picked);
        }
        if override_dir.is_some() && ui.button("Reset to default").clicked() {
            *override_dir = None;
        }
        if ui.button("Open folder").clicked() {
            // Owned, computed fresh here rather than held across the
            // buttons above: `override_dir` needs a mutable borrow for
            // Choose/Reset, which a live reference derived from it earlier
            // in this closure would conflict with.
            let effective = override_dir
                .clone()
                .unwrap_or_else(|| default_dir.to_path_buf());
            // Best-effort: creates `effective` if it doesn't exist yet (a
            // never-used default, or an override chosen but not yet saved)
            // so there's always something for the file manager to actually
            // open, same reasoning `Settings::sessions_dir`/`rules_dir`
            // already apply when resolving these directories for real use.
            let _ = std::fs::create_dir_all(&effective);
            let _ = reveal::open_folder(&effective);
        }
    });
}
