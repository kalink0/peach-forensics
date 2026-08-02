use eframe::egui;

use crate::db::timeline_queries::Query;

/// Search box + quick level/tag-filter buttons. The buttons are a low-effort
/// entry point into the same query language the text box edits, rather than
/// a second, separate filter mechanism that would need reconciling with it.
///
/// Selecting several values in the same row is meant as "match any of
/// these" — but the search grammar has no operator precedence or
/// parentheses, so appending several bare `field=value` terms joined by
/// `OR` would silently mean
/// something else entirely as soon as any other `AND`-ed term is also
/// present (`level=ERROR tag=a OR tag=b` parses left-to-right as
/// `(level=ERROR AND tag=a) OR tag=b`, not `level=ERROR AND (tag=a OR
/// tag=b)`). Representing the whole selection as a single anchored regex
/// alternation (`field~^(?:a|b)$`) sidesteps that entirely: it's always
/// exactly one term, so it composes correctly with everything else no
/// matter what else is in the query.
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

    /// `available_levels` should be the distinct `level` values and
    /// `available_tags` the distinct `import_tags.tag_value`s currently in
    /// the loaded data (both queried fresh after each load/re-tag — AUL's
    /// `LogType` names and a text log's ERROR/WARN/INFO have nothing in
    /// common, and which tags exist depends entirely on which rules were
    /// selected, so a fixed button set wouldn't fit either).
    ///
    /// Returns the freshly parsed [`Query`] only on the frame something
    /// changed, so the caller re-runs the count/window queries only when
    /// there's an actual reason to.
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        available_levels: &[String],
        available_tags: &[String],
    ) -> Option<Query> {
        let mut changed = false;

        ui.horizontal(|ui| {
            ui.label("Search:");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.text)
                    .hint_text(r#"e.g. sourcetype=evtx tag=auth_failure NOT level=INFO "login""#)
                    .desired_width(400.0),
            );
            changed |= response.changed();
            if ui.button("Clear").clicked() && !self.text.is_empty() {
                self.text.clear();
                changed = true;
            }
        });

        changed |= self.quick_filter_row(ui, "Level", "level", available_levels);
        changed |= self.tag_filter_row(ui, available_tags);

        changed.then(|| Query::parse(&self.text))
    }

    /// One row of toggleable `field=value` buttons, all selected values of
    /// the same field combined via a single `field~^(?:...)$` term (see the
    /// struct docs for why not several `field=value OR ...` terms).
    fn quick_filter_row(
        &mut self,
        ui: &mut egui::Ui,
        label: &str,
        field: &str,
        values: &[String],
    ) -> bool {
        if values.is_empty() {
            return false;
        }
        let mut changed = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("{label}:"));
            for value in values {
                let active = self.has_term(field, value);
                if ui.selectable_label(active, value).clicked() {
                    self.toggle_term(field, value);
                    changed = true;
                }
            }
        });
        changed
    }

    /// Same as [`Self::quick_filter_row`] for `tag`, plus an "Untagged"
    /// toggle for `NOT tag=*` — entries with no tag at all, which the
    /// per-value buttons can't express since they only ever add positive
    /// `tag=...`/`tag~...` conditions.
    fn tag_filter_row(&mut self, ui: &mut egui::Ui, available_tags: &[String]) -> bool {
        if available_tags.is_empty() {
            return false;
        }
        let mut changed = false;
        ui.horizontal_wrapped(|ui| {
            ui.label("Tag:");
            for value in available_tags {
                let active = self.has_term("tag", value);
                if ui.selectable_label(active, value).clicked() {
                    self.toggle_term("tag", value);
                    changed = true;
                }
            }
            let untagged_active = self.has_untagged_term();
            if ui
                .selectable_label(untagged_active, "Untagged")
                .on_hover_text("Entries with no tag at all (NOT tag=*)")
                .clicked()
            {
                self.toggle_untagged_term();
                changed = true;
            }
        });
        changed
    }

    /// Whether `value` is one of the alternatives in this field's
    /// `field~^(?:...)$` term, if that term is present at all.
    fn has_term(&self, field: &str, value: &str) -> bool {
        self.term_values(field).iter().any(|v| v == value)
    }

    /// Adds or removes `value` from this field's selection, rewriting the
    /// single `field~^(?:...)$` term in place (or adding/removing it
    /// entirely once the selection becomes non-empty/empty). `tag` is
    /// special-cased through [`Self::set_tag_block`] instead, since its
    /// selection can also include "Untagged" (see there for why).
    fn toggle_term(&mut self, field: &str, value: &str) {
        let mut values = self.term_values(field);
        match values.iter().position(|v| v == value) {
            Some(pos) => {
                values.remove(pos);
            }
            None => values.push(value.to_string()),
        }
        if field == "tag" {
            let untagged = self.has_untagged_term();
            self.set_tag_block(&values, untagged);
        } else {
            self.set_term_values(field, &values);
        }
    }

    /// Parses the currently-selected values back out of this field's
    /// `field~^(?:a|b)$` token, if present — the query text is the only
    /// state `FilterBar` keeps (it must survive a session save/reload as
    /// plain text), so button state has to be recovered from it rather than
    /// tracked separately.
    fn term_values(&self, field: &str) -> Vec<String> {
        let prefix = format!("{field}~^(?:");
        self.text
            .split_whitespace()
            .find(|t| t.starts_with(&prefix) && t.ends_with(")$"))
            .map(|t| {
                t[prefix.len()..t.len() - 2]
                    .split('|')
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Replaces (or removes, if `values` is empty) this field's
    /// `field~^(?:...)$` token in place, leaving every other token
    /// untouched.
    fn set_term_values(&mut self, field: &str, values: &[String]) {
        let prefix = format!("{field}~^(?:");
        let tokens: Vec<&str> = self.text.split_whitespace().collect();
        let existing_idx = tokens
            .iter()
            .position(|t| t.starts_with(&prefix) && t.ends_with(")$"));

        let new_token = (!values.is_empty()).then(|| format!("{field}~^(?:{})$", values.join("|")));

        let mut rebuilt: Vec<String> = tokens
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != existing_idx)
            .map(|(_, t)| t.to_string())
            .collect();

        match (existing_idx, new_token) {
            (Some(idx), Some(token)) => rebuilt.insert(idx.min(rebuilt.len()), token),
            (None, Some(token)) => rebuilt.push(token),
            _ => {}
        }

        self.text = rebuilt.join(" ");
    }

    const UNTAGGED_TERM: [&'static str; 2] = ["NOT", "tag=*"];

    fn has_untagged_term(&self) -> bool {
        let tokens: Vec<&str> = self.text.split_whitespace().collect();
        tokens.windows(2).any(|w| {
            w[0].eq_ignore_ascii_case(Self::UNTAGGED_TERM[0]) && w[1] == Self::UNTAGGED_TERM[1]
        })
    }

    /// Toggles "Untagged" (`NOT tag=*`) alongside whatever tag values are
    /// currently selected — see [`Self::set_tag_block`] for why this can't
    /// just independently append/remove its own term.
    fn toggle_untagged_term(&mut self) {
        let untagged = !self.has_untagged_term();
        let values = self.term_values("tag");
        self.set_tag_block(&values, untagged);
    }

    /// Finds the Tag row's own block, whatever shape it's currently
    /// written in — the only three shapes [`Self::set_tag_block`] ever
    /// produces: just `tag~^(?:...)$`, just `NOT tag=*`, or both joined by
    /// `OR` in that order. Returns the token index range to replace.
    fn find_tag_block_range(tokens: &[&str]) -> Option<(usize, usize)> {
        for (i, token) in tokens.iter().enumerate() {
            let is_values = token.starts_with("tag~^(?:") && token.ends_with(")$");
            let is_untagged = token.eq_ignore_ascii_case(Self::UNTAGGED_TERM[0])
                && tokens.get(i + 1) == Some(&Self::UNTAGGED_TERM[1]);
            if is_values {
                let is_combined = tokens
                    .get(i + 1)
                    .is_some_and(|t| t.eq_ignore_ascii_case("OR"))
                    && tokens
                        .get(i + 2)
                        .is_some_and(|t| t.eq_ignore_ascii_case("NOT"))
                    && tokens.get(i + 3) == Some(&Self::UNTAGGED_TERM[1]);
                return Some(if is_combined { (i, i + 3) } else { (i, i) });
            }
            if is_untagged {
                return Some((i, i + 1));
            }
        }
        None
    }

    /// Tag values and "Untagged" both belong to the same logical
    /// selection — "show entries with any of these tags, or with none at
    /// all" — so they're written as one contiguous block, joined by an
    /// explicit `OR`, always moved to the very front of the query text
    /// whenever it changes.
    ///
    /// The front-position is load-bearing, not cosmetic: the grammar has
    /// no parentheses (see the struct docs), so `(values OR untagged) AND
    /// rest-of-query` only comes out correctly under the existing
    /// left-to-right fold if the OR'd pair is evaluated *first* — anywhere
    /// else, a trailing `AND` term would silently apply only to the last
    /// half of the pair (`(level=ERROR AND tag~(...)) OR NOT tag=*`)
    /// instead of the whole group, which is exactly the bug this was
    /// written to fix: selecting a tag *and* Untagged together used to
    /// mean "has this tag AND has no tag" — always zero rows — instead of
    /// "has this tag, or is untagged".
    fn set_tag_block(&mut self, values: &[String], untagged: bool) {
        let tokens: Vec<&str> = self.text.split_whitespace().collect();
        let existing_range = Self::find_tag_block_range(&tokens);

        let mut block: Vec<String> = Vec::new();
        if !values.is_empty() {
            block.push(format!("tag~^(?:{})$", values.join("|")));
        }
        if untagged {
            if !block.is_empty() {
                block.push("OR".to_string());
            }
            block.push(Self::UNTAGGED_TERM[0].to_string());
            block.push(Self::UNTAGGED_TERM[1].to_string());
        }

        let mut rest: Vec<String> = tokens.iter().map(|t| t.to_string()).collect();
        if let Some((start, end)) = existing_range {
            rest.splice(start..=end, std::iter::empty());
        }

        block.extend(rest);
        self.text = block.join(" ");
    }
}

impl Default for FilterBar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggling_one_value_writes_a_single_element_alternation() {
        let mut bar = FilterBar::new();
        bar.toggle_term("tag", "wifi_status");
        assert_eq!(bar.text(), "tag~^(?:wifi_status)$");
        assert!(bar.has_term("tag", "wifi_status"));
    }

    #[test]
    fn toggling_a_second_value_extends_the_same_alternation() {
        let mut bar = FilterBar::new();
        bar.toggle_term("tag", "wifi_status");
        bar.toggle_term("tag", "screen_lock_state");

        assert_eq!(bar.text(), "tag~^(?:wifi_status|screen_lock_state)$");
        assert!(bar.has_term("tag", "wifi_status"));
        assert!(bar.has_term("tag", "screen_lock_state"));
    }

    #[test]
    fn toggling_off_one_of_several_leaves_the_rest() {
        let mut bar = FilterBar::new();
        bar.toggle_term("tag", "a");
        bar.toggle_term("tag", "b");
        bar.toggle_term("tag", "c");

        bar.toggle_term("tag", "b");

        assert_eq!(bar.text(), "tag~^(?:a|c)$");
        assert!(!bar.has_term("tag", "b"));
    }

    #[test]
    fn toggling_off_the_last_value_removes_the_term_entirely() {
        let mut bar = FilterBar::new();
        bar.toggle_term("tag", "wifi_status");
        bar.toggle_term("tag", "wifi_status");

        assert_eq!(bar.text(), "");
    }

    #[test]
    fn level_and_tag_selections_stay_independent() {
        let mut bar = FilterBar::new();
        bar.toggle_term("level", "ERROR");
        bar.toggle_term("tag", "wifi_status");
        bar.toggle_term("tag", "screen_lock_state");

        assert!(bar.has_term("level", "ERROR"));
        assert!(bar.has_term("tag", "wifi_status"));
        assert!(bar.has_term("tag", "screen_lock_state"));
        // Both fields' terms present and independently toggleable, whatever
        // the exact textual layout.
        assert!(bar.text().contains("level~^(?:ERROR)$"));
        assert!(
            bar.text()
                .contains("tag~^(?:wifi_status|screen_lock_state)$")
        );
    }

    #[test]
    fn hand_typed_free_text_survives_a_button_toggle() {
        let mut bar = FilterBar::new();
        bar.set_text("connection_refused".to_string());

        bar.toggle_term("tag", "wifi_status");

        assert!(bar.text().contains("connection_refused"));
        assert!(bar.has_term("tag", "wifi_status"));
    }

    #[test]
    fn untagged_toggle_adds_and_removes_not_tag_wildcard() {
        let mut bar = FilterBar::new();
        assert!(!bar.has_untagged_term());

        bar.toggle_untagged_term();
        assert!(bar.has_untagged_term());
        assert_eq!(bar.text(), "NOT tag=*");

        bar.toggle_untagged_term();
        assert!(!bar.has_untagged_term());
        assert_eq!(bar.text(), "");
    }

    #[test]
    fn untagged_toggle_does_not_disturb_other_terms() {
        let mut bar = FilterBar::new();
        bar.toggle_term("level", "ERROR");

        bar.toggle_untagged_term();
        assert!(bar.text().contains("level~^(?:ERROR)$"));
        assert!(bar.text().contains("NOT tag=*"));

        bar.toggle_untagged_term();
        assert!(!bar.text().contains("NOT tag=*"));
        assert!(bar.text().contains("level~^(?:ERROR)$"));
    }

    #[test]
    fn selecting_a_tag_and_untagged_together_combines_with_or() {
        let mut bar = FilterBar::new();
        bar.toggle_term("tag", "airplane_mode");
        bar.toggle_untagged_term();

        assert_eq!(bar.text(), "tag~^(?:airplane_mode)$ OR NOT tag=*");
        assert!(bar.has_term("tag", "airplane_mode"));
        assert!(bar.has_untagged_term());
    }

    #[test]
    fn tag_and_untagged_block_moves_to_the_front_ahead_of_other_terms() {
        // Load-bearing, not cosmetic: the grammar has no parentheses, so
        // `(tag~... OR NOT tag=*) AND level=ERROR` only comes out correct
        // under the left-to-right fold if the OR'd pair is evaluated
        // first — see `set_tag_block`'s doc comment.
        let mut bar = FilterBar::new();
        bar.toggle_term("level", "ERROR");
        bar.toggle_term("tag", "airplane_mode");
        bar.toggle_untagged_term();

        assert_eq!(
            bar.text(),
            "tag~^(?:airplane_mode)$ OR NOT tag=* level~^(?:ERROR)$"
        );
    }

    #[test]
    fn removing_the_tag_value_leaves_untagged_alone_and_vice_versa() {
        let mut bar = FilterBar::new();
        bar.toggle_term("tag", "airplane_mode");
        bar.toggle_untagged_term();

        bar.toggle_term("tag", "airplane_mode"); // remove the value again
        assert_eq!(bar.text(), "NOT tag=*");
        assert!(!bar.has_term("tag", "airplane_mode"));
        assert!(bar.has_untagged_term());

        bar.toggle_term("tag", "airplane_mode"); // add it back
        bar.toggle_untagged_term(); // remove untagged again
        assert_eq!(bar.text(), "tag~^(?:airplane_mode)$");
    }
}
