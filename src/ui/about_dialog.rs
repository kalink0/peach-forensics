//! "About" dialog — read-only, so unlike [`crate::ui::settings_dialog`] it
//! has no draft state beyond which tab is showing.

use eframe::egui;

use crate::ui::dialog_window::show_dialog_window;

const REPO_URL: &str = "https://github.com/kalink0/peach-forensics";
const ISSUES_URL: &str = "https://github.com/kalink0/peach-forensics/issues";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AboutTab {
    About,
    Acknowledgements,
}

pub enum AboutDialog {
    Closed,
    Open { tab: AboutTab },
}

impl AboutDialog {
    pub fn open() -> Self {
        Self::Open {
            tab: AboutTab::About,
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        let mut close = false;

        if let Self::Open { tab } = self {
            close = show_dialog_window(
                ctx,
                "peach_about_dialog",
                &crate::fl!("about-title"),
                [480.0, 420.0],
                true,
                |ui, close| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(tab, AboutTab::About, crate::fl!("about-tab-about"));
                        ui.selectable_value(
                            tab,
                            AboutTab::Acknowledgements,
                            crate::fl!("about-tab-acknowledgements"),
                        );
                    });
                    ui.separator();

                    match tab {
                        AboutTab::About => about_tab(ui),
                        AboutTab::Acknowledgements => acknowledgements_tab(ui),
                    }

                    ui.separator();
                    if ui.button(crate::fl!("common-close")).clicked() {
                        *close = true;
                    }
                },
            );
        }

        if close {
            *self = Self::Closed;
        }
    }
}

fn about_tab(ui: &mut egui::Ui) {
    ui.heading(format!("Peach {}", display_version()));
    ui.label(format!(
        "{}  ·  © 2026 Marco Neumann (kalink0)",
        crate::fl!("about-tagline")
    ));
    ui.add_space(6.0);
    ui.label(crate::fl!("about-description"));
    ui.label(crate::fl!("about-crush"));
    ui.add_space(6.0);
    ui.label(
        egui::RichText::new(crate::fl!("about-dedication"))
            .small()
            .italics(),
    );
    ui.add_space(6.0);
    ui.label(crate::fl!("about-license"));
    ui.hyperlink(REPO_URL);
    ui.hyperlink_to(crate::fl!("about-report-bug"), ISSUES_URL);
}

fn acknowledgements_tab(ui: &mut egui::Ui) {
    ui.label(crate::fl!("acknowledgements-intro"));
    ui.add_space(8.0);

    ui.strong(crate::fl!("acknowledgements-dependencies"));
    egui::Grid::new("about_dependencies")
        .num_columns(4)
        .striped(true)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            // Crate names, licenses and sources are identifiers, only the
            // role column is UI text.
            let rows: [(&str, String, &str, &str); 6] = [
                (
                    "egui / eframe / egui_extras",
                    crate::fl!("acknowledgements-role-gui"),
                    "MIT OR Apache-2.0",
                    "egui.rs",
                ),
                (
                    "duckdb",
                    crate::fl!("acknowledgements-role-duckdb"),
                    "MIT",
                    "duckdb.org",
                ),
                (
                    "rusqlite",
                    crate::fl!("acknowledgements-role-rusqlite"),
                    "MIT",
                    "github.com/rusqlite/rusqlite",
                ),
                (
                    "macos-unifiedlogs",
                    crate::fl!("acknowledgements-role-aul"),
                    "Apache-2.0",
                    "github.com/mandiant/macos-UnifiedLogs",
                ),
                (
                    "evtx",
                    crate::fl!("acknowledgements-role-evtx"),
                    "MIT/Apache-2.0",
                    "github.com/omerbenamram/evtx",
                ),
                (
                    "rfd",
                    crate::fl!("acknowledgements-role-rfd"),
                    "MIT",
                    "github.com/PolyMeilex/rfd",
                ),
            ];
            for (name, role, license, source) in rows {
                ui.strong(name);
                ui.label(role);
                ui.weak(license);
                ui.label(source);
                ui.end_row();
            }
        });

    ui.add_space(10.0);
    // Paths, URLs and the publication title are placeholders, not part of
    // the translatable text: citations have to stay exact in every language.
    ui.strong(crate::fl!("acknowledgements-research"));
    ui.label(crate::fl!(
        "acknowledgements-research-aul",
        files = "rules/examples/aul_*.toml",
        title = "Apple Unified Log Predicates in iLEAPP: The Reference",
        url = "leapps.org/blog-post?post=2026-08-01-unified-log-predicate-reference"
    ));
    ui.add_space(4.0);
    ui.label(crate::fl!(
        "acknowledgements-research-evtx",
        files = "message_templates/examples/evtx_*.toml, rules/examples/evtx_*.toml",
        url = "learn.microsoft.com/windows/security/threat-protection/auditing/"
    ));
    ui.add_space(4.0);
    ui.label(crate::fl!(
        "acknowledgements-research-thesis-friday",
        url = "thesisfriday.com"
    ));
    ui.add_space(4.0);
    ui.label(crate::fl!(
        "acknowledgements-research-journald",
        files = "rules/examples/journald_*.toml"
    ));
    ui.add_space(4.0);
    ui.label(crate::fl!(
        "acknowledgements-research-intrusion-log",
        files = "rules/examples/intrusion_log_*.toml"
    ));
    ui.add_space(4.0);
    ui.label(crate::fl!(
        "acknowledgements-research-biome",
        files = "rules/examples/biome_*.toml",
        url = "github.com/cclgroupltd/ccl-segb"
    ));

    ui.add_space(10.0);
    ui.strong(crate::fl!("acknowledgements-special-thanks"));
    ui.label(crate::fl!(
        "acknowledgements-rainbow",
        menu_path = "View \u{2192} Theme \u{2192} Rainbow"
    ));

    ui.add_space(10.0);
    ui.strong(crate::fl!("acknowledgements-development-tools"));
    ui.label(crate::fl!("acknowledgements-claude"));
}

/// Version string for UI display — the plain crate version normally, with a
/// `PEACH_BUILD_TAG` suffix when one was baked in at compile time (set by
/// the nightly workflow, e.g. `20260801-nightly-abc1234`; unset for a
/// normal dev build or a tagged release build). `pub(crate)`, not private:
/// also used for the window title (`app.rs::run`), not just this dialog.
pub(crate) fn display_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    match option_env!("PEACH_BUILD_TAG") {
        Some(tag) if !tag.is_empty() => format!("{version} ({tag})"),
        _ => version.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_version_falls_back_to_the_plain_crate_version() {
        // This test binary is never built with `PEACH_BUILD_TAG` set (only
        // the nightly CI workflow sets it), so `display_version` must
        // return exactly `CARGO_PKG_VERSION` with no suffix.
        assert_eq!(display_version(), env!("CARGO_PKG_VERSION"));
    }
}
