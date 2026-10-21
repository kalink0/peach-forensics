//! "Rule packs..." — check for, preview, and apply an updated AUL/EVTX/
//! journald rule pack without a full Peach release, per
//! `docs/design/rule-pack-updates.md`. Three ways in, all user-initiated:
//! drag a `peach-rules-vN.zip` bundle onto this window, click "Browse..."
//! to pick one via a native file dialog, or click "Check for updates"
//! (§6 — **the only network call in the whole app**, never automatic).
//! All three land on the same verify-then-preview-then-apply flow:
//! [`tagging::pack_bundle::load_pack_bundle`] extracts and SHA-256-checks
//! the bundle, [`tagging::pack_diff::diff`] compares it against whatever's
//! currently active (§5's derived new/modified/removed, not a
//! hand-maintained changelog), and only an explicit "Apply" click calls
//! [`tagging::pack_bundle::apply_bundle`] to actually replace tier 2.
//!
//! **Drag-and-drop doesn't work on Wayland** — winit 0.30's Wayland
//! backend has no `WindowEvent::DroppedFile` support at all (only
//! X11/Windows/macOS do; checked directly in winit's own source, not
//! assumed). Not something fixable in this dialog; `Browse...` is the
//! actual answer for anyone on Wayland, not just a nice-to-have alternate
//! path.
//!
//! Mostly self-contained, same shape as `ui::session_dialog`: owns its own
//! background-thread channel for network/disk verification work. The one
//! exception is `Browse...` itself — every native OS file dialog in this
//! app shares `app.rs`'s single `PeachApp::file_pick_rx` (only one makes
//! sense open at a time), so that one path necessarily goes through
//! `app.rs`: [`RulePackDialogOutcome::BrowseRequested`] out,
//! [`RulePackDialog::begin_verify_file`] back in once a path comes back.

use std::path::PathBuf;
use std::sync::mpsc;

use eframe::egui;

use crate::tagging::pack_bundle::{self, LoadedPackBundle};
use crate::tagging::pack_diff::{self, RulePackDiff};
use crate::tagging::pack_update::{self, AvailableUpdate};
use crate::tagging::{builtin, rule_file};
use crate::ui::dialog_window::show_dialog_window;

/// What `app.rs` needs to react to after this dialog's `ui()` call —
/// same division of labor as `ui::session_dialog::SessionManagerOutcome`:
/// the dialog does its own work directly (applying a pack is entirely
/// self-contained), but re-tagging the current session is `app.rs`'s
/// machinery (`start_retag`), not this dialog's.
pub enum RulePackDialogOutcome {
    RetagRequested,
    /// "Browse..." was clicked. Unlike everything else in this dialog,
    /// picking a local file needs a native OS dialog — and every native
    /// dialog in this app shares one `PeachApp::file_pick_rx` (see that
    /// field's doc comment: only one can sensibly be open at a time), so
    /// this is the one thing the dialog can't just do itself. `app.rs`
    /// spawns the picker and, once a path comes back, calls
    /// [`RulePackDialog::begin_verify_file`] with it — the same entry
    /// point drag-and-drop uses.
    BrowseRequested,
}

/// What's currently active, read fresh every time the dialog opens.
pub struct AppliedInfo {
    /// `None` — running on the embedded baseline, tier 2 has never been
    /// applied (or was cleared). `Some` — the applied pack's own
    /// `pack_version`, read from its `manifest.toml` (best-effort, see
    /// `pack_bundle::read_applied_manifest`).
    pack_version: Option<u32>,
    /// `name → version` for whatever's actually active right now
    /// (`tagging::builtin::active_rule_versions`) — the "active" side of
    /// every diff this dialog computes, kept in sync after a successful
    /// apply so a second check/drop in the same session diffs against the
    /// new state, not the stale one from when the dialog opened.
    rule_versions: pack_diff::RuleVersions,
}

/// Where a candidate bundle came from — shown in the preview header so it's
/// clear what is being reviewed. Kept as data rather than a finished
/// sentence: the download path builds it on a worker thread, and the text
/// is only put together in the UI language when it's shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateSource {
    Dropped { file_name: String },
    Browsed { file_name: String },
    Downloaded { tag_name: String },
}

impl CandidateSource {
    fn dropped(file_name: String) -> Self {
        Self::Dropped { file_name }
    }

    fn browsed(file_name: String) -> Self {
        Self::Browsed { file_name }
    }

    fn label(&self) -> String {
        match self {
            Self::Dropped { file_name } => {
                crate::fl!("rule-packs-source-dropped", file = file_name.clone())
            }
            Self::Browsed { file_name } => {
                crate::fl!("rule-packs-source-browsed", file = file_name.clone())
            }
            Self::Downloaded { tag_name } => {
                crate::fl!("rule-packs-source-downloaded", tag = tag_name.clone())
            }
        }
    }
}

/// A verified candidate bundle staged for review, not yet applied.
pub struct Candidate {
    bundle: LoadedPackBundle,
    diff: RulePackDiff,
    source: CandidateSource,
}

pub enum Stage {
    Idle,
    CheckingForUpdate,
    /// Reachable, nothing newer than what's applied.
    NoUpdateAvailable,
    UpdateAvailable(AvailableUpdate),
    DownloadingAndVerifying(AvailableUpdate),
    VerifyingFile(String),
    Ready(Candidate),
    Applying,
    Applied {
        pack_version: u32,
    },
}

pub enum WorkOutcome {
    CheckedForUpdate(Result<Option<AvailableUpdate>, String>),
    Verified {
        result: Result<LoadedPackBundle, String>,
        source: CandidateSource,
    },
    Applied(Result<u32, String>),
}

pub enum RulePackDialog {
    Closed,
    Open {
        applied_pack_dir: Option<PathBuf>,
        applied: AppliedInfo,
        /// Boxed: `Stage::Ready`/`UpdateAvailable`/etc. carry a
        /// `Candidate`/`AvailableUpdate` that's much larger than the
        /// tiny `Closed` variant, and clippy's `large_enum_variant`
        /// flags the resulting size gap on `RulePackDialog` itself.
        stage: Box<Stage>,
        rx: Option<mpsc::Receiver<WorkOutcome>>,
        error: Option<String>,
    },
}

impl RulePackDialog {
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Resolves `tagging::rule_file::default_applied_pack_dir` itself
    /// (best-effort — `None` on failure just means "Check for updates"/
    /// drag-and-drop have nowhere to apply to, and the dialog says so,
    /// same tolerance every other consumer of that path already has) and
    /// reads what's currently active, so the header shows real state
    /// immediately without a background round-trip.
    pub fn open() -> Self {
        let applied_pack_dir = rule_file::default_applied_pack_dir().ok();
        let pack_version = applied_pack_dir
            .as_deref()
            .and_then(pack_bundle::read_applied_manifest)
            .map(|manifest| manifest.pack.pack_version);
        let rule_versions = builtin::active_rule_versions(applied_pack_dir.as_deref());
        Self::Open {
            applied_pack_dir,
            applied: AppliedInfo {
                pack_version,
                rule_versions,
            },
            stage: Box::new(Stage::Idle),
            rx: None,
            error: None,
        }
    }

    /// Renders the dialog if open; returns `Some` the one frame the
    /// analyst asks to re-tag after applying, or asks to browse for a
    /// local bundle (see [`RulePackDialogOutcome::BrowseRequested`]).
    /// `file_pick_in_flight` — `app.rs`'s `PeachApp::file_pick_rx.is_some()`
    /// — disables the "Browse..." button while some *other* native dialog
    /// is already open, same rule every other picker button in this app
    /// already follows. A no-op (returning `None`) when closed.
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        file_pick_in_flight: bool,
    ) -> Option<RulePackDialogOutcome> {
        self.poll();

        let mut close = false;
        let mut outcome = None;

        if let Self::Open {
            applied_pack_dir,
            applied,
            stage,
            rx,
            error,
        } = self
        {
            close = show_dialog_window(
                ctx,
                "peach_rule_pack_dialog",
                &crate::fl!("rule-packs-title"),
                [640.0, 520.0],
                true,
                |ui, close| {
                    egui::Panel::bottom("peach_rule_pack_dialog_bottom_bar").show(ui, |ui| {
                        ui.add_space(4.0);
                        if ui.button(crate::fl!("common-close")).clicked() {
                            *close = true;
                        }
                        ui.add_space(4.0);
                    });

                    render_header(ui, applied);
                    ui.separator();

                    if let Some(err) = error {
                        ui.colored_label(egui::Color32::RED, err.as_str());
                        ui.separator();
                    }

                    render_drop_zone(
                        ui,
                        stage,
                        applied_pack_dir.is_some(),
                        file_pick_in_flight,
                        &mut outcome,
                    );
                    ui.separator();

                    render_stage(ui, stage, applied, applied_pack_dir, rx, &mut outcome);
                },
            );

            handle_drop(ctx, applied_pack_dir, stage, rx, error);
        }

        if close {
            *self = Self::Closed;
        }
        outcome
    }

    /// Starts verifying a bundle file picked via `app.rs`'s shared native
    /// file dialog (in response to
    /// [`RulePackDialogOutcome::BrowseRequested`]) — the browse-button
    /// counterpart to what `handle_drop` does for a dropped file, and the
    /// reason this method needs to be `pub` at all rather than purely
    /// internal like the rest of this dialog's background-work triggers.
    /// A no-op if the dialog isn't open (it was closed while the picker
    /// was up) or another verify/apply is already in flight.
    pub fn begin_verify_file(&mut self, path: PathBuf) {
        let Self::Open {
            stage, rx, error, ..
        } = self
        else {
            return;
        };
        if rx.is_some() {
            return;
        }
        start_verify_file(path, CandidateSource::browsed, stage, rx, error);
    }

    /// Drains whatever background work has finished since the last frame
    /// — separated from `ui()` so it can be exercised in tests without an
    /// active egui frame, same reasoning as
    /// `ui::session_dialog::poll_counts`.
    fn poll(&mut self) {
        let Self::Open {
            applied,
            stage,
            rx,
            error,
            ..
        } = self
        else {
            return;
        };
        let Some(receiver) = rx else { return };
        match receiver.try_recv() {
            Ok(WorkOutcome::CheckedForUpdate(Ok(Some(update)))) => {
                **stage = Stage::UpdateAvailable(update);
                *rx = None;
            }
            Ok(WorkOutcome::CheckedForUpdate(Ok(None))) => {
                **stage = Stage::NoUpdateAvailable;
                *rx = None;
            }
            Ok(WorkOutcome::CheckedForUpdate(Err(err))) => {
                **stage = Stage::Idle;
                *error = Some(err);
                *rx = None;
            }
            Ok(WorkOutcome::Verified {
                result: Ok(bundle),
                source,
            }) => {
                let diff =
                    pack_diff::diff(&applied.rule_versions, &bundle.manifest.rule_versions());
                **stage = Stage::Ready(Candidate {
                    bundle,
                    diff,
                    source,
                });
                *rx = None;
            }
            Ok(WorkOutcome::Verified {
                result: Err(err), ..
            }) => {
                **stage = Stage::Idle;
                *error = Some(err);
                *rx = None;
            }
            Ok(WorkOutcome::Applied(Ok(pack_version))) => {
                **stage = Stage::Applied { pack_version };
                applied.pack_version = Some(pack_version);
                *rx = None;
            }
            Ok(WorkOutcome::Applied(Err(err))) => {
                **stage = Stage::Idle;
                *error = Some(err);
                *rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => *rx = None,
        }
    }
}

fn render_header(ui: &mut egui::Ui, applied: &AppliedInfo) {
    match applied.pack_version {
        Some(version) => {
            ui.label(crate::fl!(
                "rule-packs-active-downloaded",
                version = version
            ));
        }
        None => {
            // No downloaded pack has ever been applied — there's no
            // `pack_version` for that case (only a downloaded bundle's
            // `manifest.toml` has one), so it can't be compared numerically
            // against a `v{N}` rule pack the way two downloaded packs can
            // be compared against each other. `PEACH_BUILD_DATE`
            // (build.rs's `stamp_build_date`, every build, not just
            // nightly) is offered instead — directly comparable to a
            // downloaded pack's own `released_at` date, unlike a bare
            // Peach version number on its own.
            ui.label(crate::fl!(
                "rule-packs-active-baseline",
                version = env!("CARGO_PKG_VERSION"),
                date = env!("PEACH_BUILD_DATE")
            ));
        }
    }
    ui.label(crate::fl!(
        "rule-packs-rule-count",
        count = applied.rule_versions.len()
    ));
}

fn render_drop_zone(
    ui: &mut egui::Ui,
    stage: &mut Stage,
    can_apply: bool,
    file_pick_in_flight: bool,
    outcome: &mut Option<RulePackDialogOutcome>,
) {
    let busy = matches!(
        stage,
        Stage::CheckingForUpdate
            | Stage::DownloadingAndVerifying(_)
            | Stage::VerifyingFile(_)
            | Stage::Applying
    );
    ui.add_enabled_ui(!busy, |ui| {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_height(60.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(if can_apply {
                        // Drag-and-drop of files isn't implemented by
                        // winit's Wayland backend as of winit 0.30 (only
                        // X11/Windows/macOS) — real for anyone on
                        // Wayland, not this dialog's bug to fix, which is
                        // exactly why "Browse..." exists as a
                        // works-everywhere alternative right next to it.
                        crate::fl!("rule-packs-drop-hint")
                    } else {
                        crate::fl!("rule-packs-drop-unavailable")
                    });
                });
                if can_apply
                    && ui
                        .add_enabled(
                            !file_pick_in_flight,
                            egui::Button::new(crate::fl!("rule-packs-browse")),
                        )
                        .clicked()
                {
                    *outcome = Some(RulePackDialogOutcome::BrowseRequested);
                }
            });
        });
    });
}

fn handle_drop(
    ctx: &egui::Context,
    applied_pack_dir: &Option<PathBuf>,
    stage: &mut Stage,
    rx: &mut Option<mpsc::Receiver<WorkOutcome>>,
    error: &mut Option<String>,
) {
    if rx.is_some() || applied_pack_dir.is_none() {
        return;
    }
    let dropped = ctx.input(|i| i.raw.dropped_files.clone());
    let Some(path) = dropped.into_iter().find_map(|f| f.path) else {
        return;
    };
    start_verify_file(path, CandidateSource::dropped, stage, rx, error);
}

/// Shared by both ways a local bundle file reaches this dialog — dropped
/// (`handle_drop`, winit `WindowEvent::DroppedFile`, unsupported on
/// Wayland as of winit 0.30 — see the module doc) and browsed
/// (`RulePackDialog::begin_verify_file`, via `app.rs`'s shared native file
/// dialog, which works everywhere `rfd`/`xdg-desktop-portal` does). Same
/// verification path either way — only the [`CandidateSource`] differs.
fn start_verify_file(
    path: PathBuf,
    source_kind: fn(String) -> CandidateSource,
    stage: &mut Stage,
    rx: &mut Option<mpsc::Receiver<WorkOutcome>>,
    error: &mut Option<String>,
) {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    if path.extension().and_then(|e| e.to_str()) != Some("zip") {
        *error = Some(crate::fl!("rule-packs-not-a-zip", file = file_name));
        return;
    }

    let (tx, receiver) = mpsc::channel();
    *rx = Some(receiver);
    *stage = Stage::VerifyingFile(file_name.clone());
    *error = None;
    let source = source_kind(file_name);
    std::thread::spawn(move || {
        let result = pack_bundle::load_pack_bundle(&path).map_err(|err| format!("{err:#}"));
        let _ = tx.send(WorkOutcome::Verified { result, source });
    });
}

fn render_stage(
    ui: &mut egui::Ui,
    stage: &mut Stage,
    applied: &AppliedInfo,
    applied_pack_dir: &Option<PathBuf>,
    rx: &mut Option<mpsc::Receiver<WorkOutcome>>,
    outcome: &mut Option<RulePackDialogOutcome>,
) {
    match stage {
        Stage::Idle => {
            ui.horizontal(|ui| {
                if ui.button(crate::fl!("rule-packs-check")).clicked() {
                    start_check(applied, stage, rx);
                }
                ui.weak(crate::fl!("rule-packs-check-help"));
            });
        }
        Stage::CheckingForUpdate => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(crate::fl!("rule-packs-checking"));
            });
        }
        Stage::NoUpdateAvailable => {
            ui.label(crate::fl!("rule-packs-no-update"));
            if ui.button(crate::fl!("rule-packs-check-again")).clicked() {
                start_check(applied, stage, rx);
            }
        }
        Stage::UpdateAvailable(update) => {
            ui.label(crate::fl!(
                "rule-packs-update-available",
                version = update.pack_version,
                tag = update.tag_name.clone()
            ));
            if ui.button(crate::fl!("rule-packs-download")).clicked() {
                start_download(update.clone(), stage, rx);
            }
        }
        Stage::DownloadingAndVerifying(update) => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(crate::fl!(
                    "rule-packs-downloading",
                    version = update.pack_version
                ));
            });
        }
        Stage::VerifyingFile(name) => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(crate::fl!("rule-packs-verifying", file = name.clone()));
            });
        }
        Stage::Ready(candidate) => {
            render_preview(ui, candidate);
            ui.separator();
            if ui.button(crate::fl!("common-apply")).clicked() {
                start_apply(stage, applied_pack_dir.clone(), rx);
            }
        }
        Stage::Applying => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(crate::fl!("rule-packs-applying"));
            });
        }
        Stage::Applied { pack_version } => {
            let version: u32 = *pack_version;
            ui.label(crate::fl!("rule-packs-applied", version = version));
            ui.label(crate::fl!("rule-packs-applied-help"));
            ui.horizontal(|ui| {
                if ui.button(crate::fl!("rule-packs-retag-now")).clicked() {
                    *outcome = Some(RulePackDialogOutcome::RetagRequested);
                }
                if ui.button(crate::fl!("rule-packs-not-now")).clicked() {
                    *stage = Stage::Idle;
                }
            });
        }
    }
}

fn render_preview(ui: &mut egui::Ui, candidate: &Candidate) {
    ui.label(crate::fl!(
        "rule-packs-reviewing",
        source = candidate.source.label(),
        version = candidate.bundle.manifest.pack.pack_version
    ));
    if candidate.diff.is_empty() {
        ui.label(crate::fl!("rule-packs-no-changes"));
        return;
    }
    egui::ScrollArea::vertical()
        .max_height(240.0)
        .show(ui, |ui| {
            if !candidate.diff.new.is_empty() {
                ui.strong(crate::fl!(
                    "rule-packs-diff-new",
                    count = candidate.diff.new.len()
                ));
                for name in &candidate.diff.new {
                    ui.label(format!("  + {name}"));
                }
            }
            if !candidate.diff.modified.is_empty() {
                ui.strong(crate::fl!(
                    "rule-packs-diff-modified",
                    count = candidate.diff.modified.len()
                ));
                for name in &candidate.diff.modified {
                    ui.label(format!("  ~ {name}"));
                }
            }
            if !candidate.diff.removed.is_empty() {
                ui.strong(crate::fl!(
                    "rule-packs-diff-removed",
                    count = candidate.diff.removed.len()
                ));
                for name in &candidate.diff.removed {
                    ui.colored_label(egui::Color32::from_rgb(200, 120, 0), format!("  - {name}"));
                }
            }
        });
}

fn start_check(
    applied: &AppliedInfo,
    stage: &mut Stage,
    rx: &mut Option<mpsc::Receiver<WorkOutcome>>,
) {
    let (tx, receiver) = mpsc::channel();
    *rx = Some(receiver);
    *stage = Stage::CheckingForUpdate;
    let current_pack_version = applied.pack_version;
    std::thread::spawn(move || {
        let result =
            pack_update::check_for_update(current_pack_version).map_err(|err| format!("{err:#}"));
        let _ = tx.send(WorkOutcome::CheckedForUpdate(result));
    });
}

fn start_download(
    update: AvailableUpdate,
    stage: &mut Stage,
    rx: &mut Option<mpsc::Receiver<WorkOutcome>>,
) {
    let (tx, receiver) = mpsc::channel();
    *rx = Some(receiver);
    *stage = Stage::DownloadingAndVerifying(update.clone());
    std::thread::spawn(move || {
        let result = download_and_verify(&update);
        let _ = tx.send(WorkOutcome::Verified {
            result,
            source: CandidateSource::Downloaded {
                tag_name: update.tag_name.clone(),
            },
        });
    });
}

fn download_and_verify(update: &AvailableUpdate) -> Result<LoadedPackBundle, String> {
    let zip_path = std::env::temp_dir().join(format!(
        "peach-rule-pack-download-{}-{}.zip",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    pack_update::download_update(update, &zip_path).map_err(|err| format!("{err:#}"))?;
    let result = pack_bundle::load_pack_bundle(&zip_path).map_err(|err| format!("{err:#}"));
    let _ = std::fs::remove_file(&zip_path);
    result
}

fn start_apply(
    stage: &mut Stage,
    applied_pack_dir: Option<PathBuf>,
    rx: &mut Option<mpsc::Receiver<WorkOutcome>>,
) {
    let Some(dest_dir) = applied_pack_dir else {
        return;
    };
    // Take the bundle out of `Ready` by value — `apply_bundle` consumes
    // it (it needs to remove the scratch extraction directory
    // afterward), so it can't be borrowed from `stage` while also
    // replacing `stage` itself.
    let previous = std::mem::replace(stage, Stage::Applying);
    let Stage::Ready(candidate) = previous else {
        *stage = previous;
        return;
    };
    let (tx, receiver) = mpsc::channel();
    *rx = Some(receiver);
    std::thread::spawn(move || {
        let pack_version = candidate.bundle.manifest.pack.pack_version;
        let result = pack_bundle::apply_bundle(candidate.bundle, &dest_dir)
            .map(|()| pack_version)
            .map_err(|err| format!("{err:#}"));
        let _ = tx.send(WorkOutcome::Applied(result));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagging::pack_bundle::{PackFileEntry, PackInfo, PackManifest};

    fn sample_manifest(pack_version: u32) -> PackManifest {
        PackManifest {
            pack: PackInfo {
                pack_version,
                released_at: "2026-09-01".to_string(),
                min_peach_version: "0.0.1".to_string(),
            },
            files: vec![PackFileEntry {
                name: "aul_a.toml".to_string(),
                sha256: "x".to_string(),
                rule_name: "aul_a".to_string(),
                rule_version: "1".to_string(),
            }],
        }
    }

    fn open_dialog_for_test() -> RulePackDialog {
        RulePackDialog::Open {
            applied_pack_dir: Some(PathBuf::from("/tmp/peach-rule-pack-dialog-test")),
            applied: AppliedInfo {
                pack_version: None,
                rule_versions: pack_diff::RuleVersions::new(),
            },
            stage: Box::new(Stage::Idle),
            rx: None,
            error: None,
        }
    }

    fn stage_of(dialog: &RulePackDialog) -> &Stage {
        let RulePackDialog::Open { stage, .. } = dialog else {
            panic!("expected an open dialog");
        };
        stage
    }

    #[test]
    fn poll_is_a_no_op_when_closed() {
        let mut dialog = RulePackDialog::Closed;
        dialog.poll();
        assert!(matches!(dialog, RulePackDialog::Closed));
    }

    #[test]
    fn poll_is_a_no_op_with_no_receiver() {
        let mut dialog = open_dialog_for_test();
        dialog.poll();
        assert!(matches!(stage_of(&dialog), Stage::Idle));
    }

    #[test]
    fn poll_moves_to_update_available_when_an_update_is_found() {
        let mut dialog = open_dialog_for_test();
        let (tx, rx) = mpsc::channel();
        let RulePackDialog::Open { rx: slot, .. } = &mut dialog else {
            unreachable!()
        };
        *slot = Some(rx);
        tx.send(WorkOutcome::CheckedForUpdate(Ok(Some(AvailableUpdate {
            pack_version: 3,
            tag_name: "peach-rules-v3".to_string(),
            download_url: "https://example.com/peach-rules-v3.zip".to_string(),
        }))))
        .unwrap();

        dialog.poll();

        assert!(matches!(
            stage_of(&dialog),
            Stage::UpdateAvailable(update) if update.pack_version == 3
        ));
    }

    #[test]
    fn poll_moves_to_no_update_available_when_none_is_found() {
        let mut dialog = open_dialog_for_test();
        let (tx, rx) = mpsc::channel();
        let RulePackDialog::Open { rx: slot, .. } = &mut dialog else {
            unreachable!()
        };
        *slot = Some(rx);
        tx.send(WorkOutcome::CheckedForUpdate(Ok(None))).unwrap();

        dialog.poll();

        assert!(matches!(stage_of(&dialog), Stage::NoUpdateAvailable));
    }

    #[test]
    fn poll_records_an_error_and_returns_to_idle_on_check_failure() {
        let mut dialog = open_dialog_for_test();
        let (tx, rx) = mpsc::channel();
        let RulePackDialog::Open { rx: slot, .. } = &mut dialog else {
            unreachable!()
        };
        *slot = Some(rx);
        tx.send(WorkOutcome::CheckedForUpdate(Err(
            "network down".to_string()
        )))
        .unwrap();

        dialog.poll();

        assert!(matches!(stage_of(&dialog), Stage::Idle));
        let RulePackDialog::Open { error, .. } = &dialog else {
            unreachable!()
        };
        assert_eq!(error.as_deref(), Some("network down"));
    }

    #[test]
    fn poll_computes_a_diff_against_the_active_versions_when_verified() {
        let mut dialog = open_dialog_for_test();
        // Seed "active" with one rule at version 1 (matches the candidate,
        // so it should show as unchanged) and a second rule the candidate
        // doesn't have at all (so it should show as removed).
        let RulePackDialog::Open {
            applied, rx: slot, ..
        } = &mut dialog
        else {
            unreachable!()
        };
        applied.rule_versions = pack_diff::RuleVersions::from([
            ("aul_a".to_string(), "1".to_string()),
            ("aul_gone".to_string(), "1".to_string()),
        ]);
        let (tx, rx) = mpsc::channel();
        *slot = Some(rx);

        let bundle = LoadedPackBundle {
            manifest: sample_manifest(5),
            extracted_dir: PathBuf::from("/tmp/peach-rule-pack-dialog-test-extracted"),
        };
        tx.send(WorkOutcome::Verified {
            result: Ok(bundle),
            source: CandidateSource::dropped("peach-rules-v5.zip".to_string()),
        })
        .unwrap();

        dialog.poll();

        let RulePackDialog::Open { stage, .. } = &dialog else {
            unreachable!()
        };
        let Stage::Ready(candidate) = stage.as_ref() else {
            panic!("expected Ready, got a different stage");
        };
        assert!(candidate.diff.new.is_empty());
        assert!(candidate.diff.modified.is_empty());
        assert_eq!(candidate.diff.removed, vec!["aul_gone".to_string()]);
    }

    #[test]
    fn poll_records_an_error_and_returns_to_idle_on_verify_failure() {
        let mut dialog = open_dialog_for_test();
        let (tx, rx) = mpsc::channel();
        let RulePackDialog::Open { rx: slot, .. } = &mut dialog else {
            unreachable!()
        };
        *slot = Some(rx);
        tx.send(WorkOutcome::Verified {
            result: Err("integrity check failed".to_string()),
            source: CandidateSource::dropped("bad.zip".to_string()),
        })
        .unwrap();

        dialog.poll();

        assert!(matches!(stage_of(&dialog), Stage::Idle));
    }

    #[test]
    fn poll_moves_to_applied_and_updates_the_active_pack_version_on_success() {
        let mut dialog = open_dialog_for_test();
        let (tx, rx) = mpsc::channel();
        let RulePackDialog::Open { rx: slot, .. } = &mut dialog else {
            unreachable!()
        };
        *slot = Some(rx);
        tx.send(WorkOutcome::Applied(Ok(7))).unwrap();

        dialog.poll();

        assert!(matches!(
            stage_of(&dialog),
            Stage::Applied { pack_version: 7 }
        ));
        let RulePackDialog::Open { applied, .. } = &dialog else {
            unreachable!()
        };
        assert_eq!(applied.pack_version, Some(7));
    }

    #[test]
    fn poll_records_an_error_and_returns_to_idle_on_apply_failure() {
        let mut dialog = open_dialog_for_test();
        let (tx, rx) = mpsc::channel();
        let RulePackDialog::Open { rx: slot, .. } = &mut dialog else {
            unreachable!()
        };
        *slot = Some(rx);
        tx.send(WorkOutcome::Applied(Err("disk full".to_string())))
            .unwrap();

        dialog.poll();

        assert!(matches!(stage_of(&dialog), Stage::Idle));
    }

    #[test]
    fn poll_clears_the_receiver_once_drained() {
        let mut dialog = open_dialog_for_test();
        let (tx, rx) = mpsc::channel();
        let RulePackDialog::Open { rx: slot, .. } = &mut dialog else {
            unreachable!()
        };
        *slot = Some(rx);
        tx.send(WorkOutcome::CheckedForUpdate(Ok(None))).unwrap();

        dialog.poll();

        let RulePackDialog::Open { rx, .. } = &dialog else {
            unreachable!()
        };
        assert!(rx.is_none());
    }

    #[test]
    fn the_candidate_source_is_named_with_its_file_or_release() {
        assert_eq!(
            CandidateSource::browsed("peach-rules-v5.zip".to_string()).label(),
            "browsed file: peach-rules-v5.zip"
        );
        assert_eq!(
            CandidateSource::Downloaded {
                tag_name: "peach-rules-v5".to_string()
            }
            .label(),
            "downloaded update: peach-rules-v5"
        );
    }

    #[test]
    fn is_open_reflects_open_vs_closed() {
        assert!(!RulePackDialog::Closed.is_open());
        assert!(open_dialog_for_test().is_open());
    }

    #[test]
    fn begin_verify_file_is_a_no_op_when_closed() {
        let mut dialog = RulePackDialog::Closed;
        dialog.begin_verify_file(PathBuf::from("/tmp/does-not-matter.zip"));
        assert!(matches!(dialog, RulePackDialog::Closed));
    }

    #[test]
    fn begin_verify_file_starts_verification_and_sets_the_stage() {
        let mut dialog = open_dialog_for_test();

        dialog.begin_verify_file(PathBuf::from("/tmp/peach-rules-v5.zip"));

        assert!(
            matches!(stage_of(&dialog), Stage::VerifyingFile(name) if name == "peach-rules-v5.zip")
        );
        let RulePackDialog::Open { rx, .. } = &dialog else {
            unreachable!()
        };
        assert!(rx.is_some());
    }

    #[test]
    fn begin_verify_file_rejects_a_non_zip_file_with_an_error() {
        let mut dialog = open_dialog_for_test();

        dialog.begin_verify_file(PathBuf::from("/tmp/not-a-bundle.txt"));

        assert!(matches!(stage_of(&dialog), Stage::Idle));
        let RulePackDialog::Open { error, rx, .. } = &dialog else {
            unreachable!()
        };
        assert!(
            error
                .as_deref()
                .is_some_and(|e| e.contains("not-a-bundle.txt"))
        );
        assert!(rx.is_none());
    }

    #[test]
    fn begin_verify_file_is_a_no_op_while_another_operation_is_in_flight() {
        let mut dialog = open_dialog_for_test();
        let (_tx, rx) = mpsc::channel();
        let RulePackDialog::Open { rx: slot, .. } = &mut dialog else {
            unreachable!()
        };
        *slot = Some(rx);

        dialog.begin_verify_file(PathBuf::from("/tmp/peach-rules-v5.zip"));

        // Still whatever it was before — not overwritten mid-flight.
        assert!(matches!(stage_of(&dialog), Stage::Idle));
    }
}
