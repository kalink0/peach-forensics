//! "About" dialog — read-only, so unlike [`crate::ui::settings_dialog`] it
//! has no draft state beyond which tab is showing.

use eframe::egui;

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
            egui::Window::new("About Peach")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(tab, AboutTab::About, "About");
                        ui.selectable_value(tab, AboutTab::Acknowledgements, "Acknowledgements");
                    });
                    ui.separator();

                    match tab {
                        AboutTab::About => about_tab(ui),
                        AboutTab::Acknowledgements => acknowledgements_tab(ui),
                    }

                    ui.separator();
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
        }

        if close {
            *self = Self::Closed;
        }
    }
}

fn about_tab(ui: &mut egui::Ui) {
    ui.heading(format!("Peach {}", display_version()));
    ui.label("Forensic Multi-Log Viewer  ·  © 2026 Marco Neumann (kalink0)");
    ui.add_space(6.0);
    ui.label(
        "A lean, local-first forensic log viewer for DFIR work. Parses log \
         sources — AUL, EVTX, journald, and TOML-configurable text logs — \
         into a normalized, taggable timeline, with a Splunk-inspired \
         search syntax and semantic tagging.",
    );
    ui.label(
        "Runs standalone, or can be started and handed evidence paths by \
         crush, then continues completely independently (no IPC).",
    );
    ui.add_space(6.0);
    ui.label("Licensed under the Apache License 2.0");
    ui.hyperlink(REPO_URL);
    ui.hyperlink_to("Report a bug or request a feature", ISSUES_URL);
}

fn acknowledgements_tab(ui: &mut egui::Ui) {
    ui.label("Peach is built on the shoulders of the open-source and DFIR community.");
    ui.add_space(8.0);

    ui.strong("Rust crate dependencies");
    egui::Grid::new("about_dependencies")
        .num_columns(4)
        .striped(true)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            let rows: [(&str, &str, &str, &str); 6] = [
                (
                    "egui / eframe / egui_extras",
                    "GUI framework",
                    "MIT OR Apache-2.0",
                    "egui.rs",
                ),
                (
                    "duckdb",
                    "Bulk timeline storage (bundles DuckDB itself)",
                    "MIT",
                    "duckdb.org",
                ),
                (
                    "rusqlite",
                    "Session DB (bundles SQLite, Public Domain)",
                    "MIT",
                    "github.com/rusqlite/rusqlite",
                ),
                (
                    "macos-unifiedlogs",
                    "AUL (.logarchive) parsing",
                    "Apache-2.0",
                    "github.com/mandiant/macos-UnifiedLogs",
                ),
                (
                    "evtx",
                    "Windows EVTX parsing",
                    "MIT/Apache-2.0",
                    "github.com/omerbenamram/evtx",
                ),
                (
                    "rfd",
                    "Native file dialogs",
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
    ui.strong("Research");
    ui.label(
        "The built-in AUL pattern-of-life rule pack (rules/examples/aul_*.toml) \
         is built on predicates from \"Apple Unified Log Predicates in \
         iLEAPP: The Reference\" by Alexis Brignoni, rather than re-derived \
         from scratch \u{2014} leapps.org/blog-post?post=2026-08-01-unified-log-predicate-reference.",
    );

    ui.add_space(10.0);
    ui.strong("Special thanks");
    ui.label(
        "@dugeonlady — for suggesting the Rainbow theme in crush. Peach's \
         Rainbow theme (View \u{2192} Theme \u{2192} Rainbow) carries over \
         the same cycle and colors.",
    );

    ui.add_space(10.0);
    ui.strong("Development tools");
    ui.label("Claude / Claude Code — AI assistant used during development (Anthropic)");
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
