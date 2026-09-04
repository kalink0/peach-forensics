//! "Settings" dialog — currently just the sessions-directory override (see
//! [`crate::config::Settings`]). Same Closed/open-state-enum +
//! `ui() -> Option<Outcome>` pattern as `TagDialog`/`SessionManagerDialog`:
//! this module only renders widgets and reports what the analyst
//! confirmed, `app.rs` owns actually persisting it to disk.

use std::path::{Path, PathBuf};

use eframe::egui;

use crate::config::{self, Settings};
use crate::model::timezone_spec::TimezoneSpec;
use crate::session::persist;
use crate::tagging::rule_file;
use crate::ui::dialog_window::show_dialog_window;
use crate::ui::reveal;

pub enum SettingsOutcome {
    Save(Settings),
}

pub enum SettingsDialog {
    Closed,
    // Boxed: `Closed` carries nothing, so an unboxed `OpenSettingsDialog`
    // here would make every `SettingsDialog` value, including the
    // near-always-current `Closed` one, as large as the biggest variant —
    // same reasoning as `RawFieldsDialog`/`FormatDialog`.
    Open(Box<OpenSettingsDialog>),
}

pub struct OpenSettingsDialog {
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
    /// What `staging_dir` resolves to when left unset — the OS temp
    /// directory. Unlike `default_sessions_dir`/`default_rules_dir` this
    /// always exists already, so resolving it here doesn't create anything
    /// as a side effect (see `Settings::staging_dir`'s doc comment).
    default_staging_dir: PathBuf,
    /// Free-typed text for `draft.default_source_timezone` — kept as a
    /// separate edit buffer rather than binding `egui::TextEdit`
    /// straight to the `Option<String>` field, since a `String` widget
    /// needs a `&mut String` to type into, and `Option<String>` can't
    /// tell "not set" apart from "currently empty while typing"; only
    /// converted back to `Option<String>` (empty means `None`) on Save,
    /// after [`parse_timezone_field`] confirms it's either blank or a
    /// valid `TimezoneSpec`. `display_timezone` has no equivalent field
    /// here — it's only editable from View > Display timezone now, not
    /// Settings (see `ui::display_timezone_dialog`'s doc comment for why
    /// that one field ended up single-location while this one didn't: the
    /// load controls' own copy of this field is only visible while `Text
    /// (config-based)` is the selected sourcetype, so Settings stays as
    /// the one place it's reachable regardless of what's currently
    /// selected — View is always reachable, so Display timezone doesn't
    /// need that same second door).
    default_source_timezone_input: String,
}

impl SettingsDialog {
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    pub fn open(current: Settings) -> Self {
        let default_source_timezone_input =
            current.default_source_timezone.clone().unwrap_or_default();
        Self::Open(Box::new(OpenSettingsDialog {
            draft: current,
            default_sessions_dir: persist::default_sessions_dir().unwrap_or_default(),
            default_rules_dir: rule_file::default_user_rules_dir().unwrap_or_default(),
            default_staging_dir: std::env::temp_dir(),
            default_source_timezone_input,
        }))
    }

    pub fn ui(&mut self, ctx: &egui::Context) -> Option<SettingsOutcome> {
        let mut outcome = None;
        let mut close = false;

        if let Self::Open(state) = self {
            let OpenSettingsDialog {
                draft,
                default_sessions_dir,
                default_rules_dir,
                default_staging_dir,
                default_source_timezone_input,
            } = state.as_mut();
            close = show_dialog_window(
                ctx,
                "peach_settings_dialog",
                "Settings",
                [520.0, 420.0],
                true,
                |ui, close| {
                    help_row(
                        ui,
                        "Sessions directory:",
                        "New sessions only — the current session stays put.",
                    );
                    directory_row(ui, &mut draft.sessions_dir, default_sessions_dir);

                    ui.separator();
                    help_row(
                        ui,
                        "Rules directory:",
                        "Where new rules get saved, and auto-loaded from on startup.",
                    );
                    directory_row(ui, &mut draft.rules_dir, default_rules_dir);

                    ui.separator();
                    help_row(
                        ui,
                        "Staging directory:",
                        "Working space for --ephemeral-session and Portable Case export/\
                         import — can hold a full copy of the bulk timeline.",
                    );
                    directory_row(ui, &mut draft.staging_dir, default_staging_dir);

                    ui.separator();
                    help_row(
                        ui,
                        "Parse threads for folder loads:",
                        "Only matters for multi-file EVTX/journald/Text loads.",
                    );
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

                    ui.separator();
                    help_row(
                        ui,
                        "Assume timezone for logs with no timezone of their own:",
                        "Fallback when a text source's own \"Assume offset\" isn't set.",
                    );
                    ui.add(
                        egui::TextEdit::singleline(default_source_timezone_input)
                            .hint_text("+0100, +02:00, UTC, or Europe/Berlin — blank to disable"),
                    );
                    let default_source_timezone_error =
                        parse_timezone_field(default_source_timezone_input).err();
                    if let Some(err) = &default_source_timezone_error {
                        ui.colored_label(ui.visuals().error_fg_color, err);
                    }

                    ui.separator();
                    let can_save = default_source_timezone_error.is_none();
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(can_save, egui::Button::new("Save"))
                            .clicked()
                        {
                            draft.default_source_timezone =
                                parse_timezone_field(default_source_timezone_input)
                                    .unwrap_or_default();
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

/// Validates one of the two timezone text fields — blank (after trimming)
/// means "no override" (`Ok(None)`), anything else must parse as a
/// [`TimezoneSpec`] or the field shows an error and Save is disabled.
/// Pure/no `egui` dependency so it's directly unit-testable, same reasoning
/// `filter_bar`'s parsing helpers are kept pure. `pub(crate)` — `app.rs`
/// reuses this for the same two fields' quick-access copies in the load
/// controls (`default_source_timezone`) and View menu (`display_timezone`),
/// so both places validate identically rather than each growing a
/// slightly-different copy.
pub(crate) fn parse_timezone_field(input: &str) -> Result<Option<String>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    TimezoneSpec::parse(trimmed)
        .map(|_| Some(trimmed.to_string()))
        .map_err(|err| format!("{err:#}"))
}

/// A setting's label plus a small "?" button that reveals `text` — either
/// on hover (a tooltip, for anyone who discovers that) or, more reliably,
/// by clicking it: click toggles a persistent expanded/collapsed state
/// (`egui::Context::data`, keyed off `label` so each row remembers its own
/// state independently) and the full explanation renders as its own line
/// right below when expanded. Click, not just hover, because a fleeting
/// tooltip on a tiny single-character button is easy to miss entirely —
/// requires holding the pointer still and waiting out egui's tooltip
/// delay, over a small target; a click is unambiguous and the result stays
/// on screen until clicked again, not just for as long as the pointer
/// happens to stay put.
fn help_row(ui: &mut egui::Ui, label: &str, text: &str) {
    let id = ui.make_persistent_id(("peach_settings_help_expanded", label));
    let mut expanded = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    ui.horizontal(|ui| {
        ui.label(label);
        if ui.small_button("?").on_hover_text(text).clicked() {
            expanded = !expanded;
            ui.data_mut(|d| d.insert_temp(id, expanded));
        }
    });
    if expanded {
        ui.weak(text);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timezone_field_blank_or_whitespace_only_means_no_override() {
        assert_eq!(parse_timezone_field(""), Ok(None));
        assert_eq!(parse_timezone_field("   "), Ok(None));
    }

    #[test]
    fn parse_timezone_field_accepts_a_fixed_offset_and_trims_it() {
        assert_eq!(
            parse_timezone_field("  +02:00  "),
            Ok(Some("+02:00".to_string()))
        );
    }

    #[test]
    fn parse_timezone_field_accepts_an_iana_zone_name() {
        assert_eq!(
            parse_timezone_field("Europe/Berlin"),
            Ok(Some("Europe/Berlin".to_string()))
        );
    }

    #[test]
    fn parse_timezone_field_rejects_garbage_with_an_error_not_a_panic() {
        assert!(parse_timezone_field("not a timezone").is_err());
    }

    #[test]
    fn open_seeds_the_input_buffer_from_the_current_settings() {
        let settings = Settings {
            default_source_timezone: Some("Europe/Berlin".to_string()),
            ..Settings::default()
        };
        let dialog = SettingsDialog::open(settings);
        let SettingsDialog::Open(state) = &dialog else {
            panic!("expected Open");
        };
        assert_eq!(state.default_source_timezone_input, "Europe/Berlin");
    }

    #[test]
    fn open_seeds_an_empty_input_buffer_when_no_override_is_set() {
        let dialog = SettingsDialog::open(Settings::default());
        let SettingsDialog::Open(state) = &dialog else {
            panic!("expected Open");
        };
        assert_eq!(state.default_source_timezone_input, "");
    }
}
