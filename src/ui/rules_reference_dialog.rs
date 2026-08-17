//! "Rules reference" — the full [docs/rules-reference.md](../../docs/rules-reference.md)
//! table (every built-in AUL/EVTX/journald rule's match condition, tag, and
//! description), embedded into the binary (`include_str!`, resolved at
//! compile time from the repo checkout that built it) and shown in-app.
//!
//! Originally this menu item just opened the same file on GitHub in the
//! system browser — cheap to build, but useless for the airgapped/offline
//! analysis machines a lot of DFIR work actually happens on, and Peach is
//! explicitly a local-only tool in the first place (no cloud sync, no
//! server) — requiring internet access just to read documentation about a
//! feature that itself works entirely offline was the odd one out. This
//! dialog is the exact same content instead, readable with zero network
//! access; a button still offers the GitHub copy for whoever has
//! connectivity and wants the nicely-rendered table instead of raw
//! markdown source.
//!
//! [`format_rules_reference`] is a light readability pass, not a markdown
//! renderer: `<br>`/`&bull;` (used in the source so GitHub renders bullet
//! lists inside table cells) become a real newline/bullet, since egui has
//! no HTML support and showing the literal tags would be worse than
//! leaving them out. Everything else (table pipes, `**bold**`, markdown
//! links) stays as plain text — still fully readable monospace source,
//! just not prettified further; a full markdown renderer would be a new
//! dependency for what's ultimately a reference table, not a rich document.

use eframe::egui;

use crate::ui::dialog_window::show_dialog_window;

const RULES_REFERENCE_MD: &str = include_str!("../../docs/rules-reference.md");

/// The GitHub copy of the same file — offered as a secondary "prettier, if
/// you have internet" option, not the primary path anymore.
const RULES_REFERENCE_URL: &str =
    "https://github.com/kalink0/peach-forensics/blob/main/docs/rules-reference.md";

pub enum RulesReferenceDialog {
    Closed,
    Open {
        /// Formatted once at open time, not every frame — reformatting a
        /// multi-hundred-line string 60 times a second for text that never
        /// changes after it's embedded would be wasted work, same
        /// reasoning `RawFieldsDialog` pretty-prints `fields` once.
        formatted: String,
        /// Case-insensitive substring filter over `formatted`'s lines —
        /// the full table is long enough (three packs, 80+ rules combined)
        /// that jumping straight to a known rule/tag name by typing beats
        /// scrolling through everything.
        filter: String,
    },
}

impl RulesReferenceDialog {
    pub fn open() -> Self {
        Self::Open {
            formatted: format_rules_reference(RULES_REFERENCE_MD),
            filter: String::new(),
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        let mut close = false;

        if let Self::Open { formatted, filter } = self {
            close = show_dialog_window(
                ctx,
                "peach_rules_reference_dialog",
                "Rules Reference",
                [760.0, 620.0],
                true,
                |ui, close| {
                    ui.horizontal(|ui| {
                        ui.label("Filter:");
                        ui.text_edit_singleline(filter);
                        if ui.button("Open on GitHub...").clicked() {
                            ui.ctx()
                                .open_url(egui::OpenUrl::same_tab(RULES_REFERENCE_URL));
                        }
                    });
                    ui.separator();

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        let filter_lower = filter.trim().to_lowercase();
                        let visible: String = formatted
                            .lines()
                            .filter(|line| {
                                filter_lower.is_empty()
                                    || line.to_lowercase().contains(&filter_lower)
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        ui.add(
                            egui::Label::new(egui::RichText::new(&visible).monospace())
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
        }

        if close {
            *self = Self::Closed;
        }
    }
}

/// Replaces the two HTML bits `docs/rules-reference.md` uses so GitHub
/// renders bullet lists inside table cells (`<br>` between items,
/// `&bull;` before each one) with plain-text equivalents a monospace
/// label can actually show — everything else in the source passes through
/// unchanged. Pure/no `egui` dependency so it's directly unit-testable.
fn format_rules_reference(markdown: &str) -> String {
    markdown.replace("<br>", "\n    ").replace("&bull;", "•")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_rules_reference_turns_br_into_an_indented_newline() {
        let formatted = format_rules_reference("a<br>b");
        assert_eq!(formatted, "a\n    b");
    }

    #[test]
    fn format_rules_reference_turns_bullet_entity_into_a_real_bullet() {
        let formatted = format_rules_reference("&bull; item");
        assert_eq!(formatted, "• item");
    }

    #[test]
    fn format_rules_reference_leaves_everything_else_untouched() {
        let formatted = format_rules_reference("| `rule_name` | plain | text |");
        assert_eq!(formatted, "| `rule_name` | plain | text |");
    }

    /// Regression coverage for the actual embedded file, not just the pure
    /// formatter in isolation — confirms `include_str!` resolved a real,
    /// non-empty file and that it's the file this dialog claims to be.
    #[test]
    fn the_embedded_rules_reference_is_non_empty_and_looks_right() {
        assert!(RULES_REFERENCE_MD.contains("AUL pattern-of-life rules"));
        assert!(RULES_REFERENCE_MD.contains("EVTX Security-Auditing rules"));
        assert!(RULES_REFERENCE_MD.contains("journald rules"));
    }

    #[test]
    fn open_starts_closed_dialog_open_with_no_filter() {
        let dialog = RulesReferenceDialog::open();
        assert!(dialog.is_open());
        assert!(matches!(&dialog, RulesReferenceDialog::Open { filter, .. } if filter.is_empty()));
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!RulesReferenceDialog::Closed.is_open());
    }
}
