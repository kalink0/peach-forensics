use eframe::egui;

use crate::db::timeline_queries::Query;

/// Search box + quick level-filter buttons. The buttons are a low-effort
/// entry point into the same query language the text box edits (toggling
/// `level=X` in and out of the query text) rather than a second, separate
/// filter mechanism that would need reconciling with it.
pub struct FilterBar {
    text: String,
}

impl FilterBar {
    pub fn new() -> Self {
        Self {
            text: String::new(),
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// Restores a query string (e.g. from a loaded session) without
    /// triggering the "did it change" logic in [`Self::ui`] — the caller
    /// re-runs the count/window queries itself when restoring a session.
    pub fn set_text(&mut self, text: String) {
        self.text = text;
    }

    /// `available_levels` should be the distinct `level` values currently in
    /// the loaded data (queried fresh after each load — AUL's `LogType`
    /// names and a text log's ERROR/WARN/INFO have nothing in common, so a
    /// fixed button set wouldn't fit either well).
    ///
    /// Returns the freshly parsed [`Query`] only on the frame something
    /// changed, so the caller re-runs the count/window queries only when
    /// there's an actual reason to.
    pub fn ui(&mut self, ui: &mut egui::Ui, available_levels: &[String]) -> Option<Query> {
        let mut changed = false;

        ui.horizontal(|ui| {
            ui.label("Search:");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.text)
                    .hint_text(r#"e.g. source=evtx tag=auth_failure NOT level=INFO "login""#)
                    .desired_width(400.0),
            );
            changed |= response.changed();
            if ui.button("Clear").clicked() && !self.text.is_empty() {
                self.text.clear();
                changed = true;
            }
        });

        if !available_levels.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label("Level:");
                for level in available_levels {
                    let active = self.has_level_term(level);
                    if ui.selectable_label(active, level).clicked() {
                        self.toggle_level_term(level);
                        changed = true;
                    }
                }
            });
        }

        changed.then(|| Query::parse(&self.text))
    }

    fn has_level_term(&self, level: &str) -> bool {
        let term = format!("level={level}");
        self.text
            .split_whitespace()
            .any(|t| t.eq_ignore_ascii_case(&term))
    }

    fn toggle_level_term(&mut self, level: &str) {
        let term = format!("level={level}");
        if self.has_level_term(level) {
            self.text = self
                .text
                .split_whitespace()
                .filter(|t| !t.eq_ignore_ascii_case(&term))
                .collect::<Vec<_>>()
                .join(" ");
        } else {
            if !self.text.is_empty() && !self.text.ends_with(' ') {
                self.text.push(' ');
            }
            self.text.push_str(&term);
        }
    }
}

impl Default for FilterBar {
    fn default() -> Self {
        Self::new()
    }
}
