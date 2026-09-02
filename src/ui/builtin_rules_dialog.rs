//! "Built-in Rules" picker — lets the analyst see every currently active
//! AUL/EVTX/journald tagging rule (match condition, tag, description) and
//! choose exactly which ones are enabled, rather than only an all-or-nothing
//! pack switch. Doubles as the in-app rule reference — the same
//! information [docs/rules-reference.md](../../docs/rules-reference.md)
//! documents, generated from the same `rules/examples/*.toml` files.
//!
//! Holds no rule data itself — `PeachApp::enabled_builtin_rules` (a
//! `BTreeSet` of rule names) is the single source of truth for which rules
//! are active, mutated directly through the `&mut` this dialog is handed;
//! [`crate::tagging::builtin::active_builtin_rules`] is re-resolved fresh
//! each render (cheap: tens of small embedded-string TOML parses plus a
//! directory read), so there's nothing here that can go stale.
//!
//! Reads the live active rule set the same way `ui::rules_reference_dialog`
//! does, for the same reason: this dialog used to call the three embedded
//! tier-1 functions directly
//! (`aul_pattern_of_life_rules`/`evtx_security_auditing_rules`/
//! `journald_login_rules`), which is exactly the *baseline*, not necessarily
//! what's actually tagging entries — a downloaded (tier 2) pack wholesale-
//! replaces tier 1 (see `tagging::builtin`'s doc comment) and can name a
//! completely different set of rules, including ones from an older release
//! that predate a rule this dialog would otherwise show as available. That
//! mismatch is exactly what produced the bug this fixed: a newly-added
//! tier-1 rule appeared unchecked (or a stale tier-2 name didn't appear at
//! all) because the checkbox list and `enabled_builtin_rules` were being
//! read from two different rule sets.

use std::collections::BTreeSet;

use eframe::egui;

use crate::tagging::builtin;
use crate::tagging::pack_bundle;
use crate::tagging::rule::Rule;
use crate::tagging::rule_file;
use crate::ui::dialog_window::show_dialog_window;

pub enum BuiltinRulesDialog {
    Closed,
    Open,
}

impl BuiltinRulesDialog {
    pub fn open() -> Self {
        Self::Open
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Renders the dialog if open (a no-op otherwise), mutating `enabled`
    /// in place as the analyst (un)checks rules.
    pub fn ui(&mut self, ctx: &egui::Context, enabled: &mut BTreeSet<String>) {
        let mut close = false;

        if matches!(self, Self::Open) {
            let applied_pack_dir = rule_file::default_applied_pack_dir().ok();
            let active_pack_version = applied_pack_dir
                .as_deref()
                .and_then(pack_bundle::read_applied_manifest)
                .map(|manifest| manifest.pack.pack_version);
            let rules = builtin::active_builtin_rules(applied_pack_dir.as_deref());
            let (aul, evtx, journald, other) = group_by_sourcetype(&rules);

            close = show_dialog_window(
                ctx,
                "peach_builtin_rules_dialog",
                "Built-in Rules",
                [720.0, 560.0],
                true,
                |ui, close| {
                    ui.label(
                        "Which built-in rules apply on every load/re-tag. Hover a rule for \
                         its full match condition and description.",
                    );
                    match active_pack_version {
                        Some(version) => {
                            ui.label(format!(
                                "Showing rule pack version {version} (downloaded via \
                                 File \u{2192} Rule packs...)."
                            ));
                        }
                        None => {
                            ui.label("Showing the built-in baseline.");
                        }
                    }
                    ui.separator();

                    render_rule_group(ui, "AUL", &aul, enabled);
                    ui.separator();
                    render_rule_group(ui, "EVTX", &evtx, enabled);
                    ui.separator();
                    render_rule_group(ui, "journald", &journald, enabled);
                    if !other.is_empty() {
                        ui.separator();
                        render_rule_group(ui, "Other", &other, enabled);
                    }

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

/// Splits `rules` into AUL/EVTX/journald groups by each rule's own
/// `sourcetype` match condition, plus a catch-all fourth group for
/// anything that doesn't declare one of those three — same reasoning as
/// `ui::rules_reference_dialog::build_sections`: a rule this dialog
/// doesn't recognize (e.g. from a downloaded pack with unexpected content)
/// is still shown rather than silently dropped, since it would otherwise
/// stay enabled in `enabled_builtin_rules` with no way to inspect or
/// disable it from here.
fn group_by_sourcetype(rules: &[Rule]) -> (Vec<Rule>, Vec<Rule>, Vec<Rule>, Vec<Rule>) {
    let mut aul = Vec::new();
    let mut evtx = Vec::new();
    let mut journald = Vec::new();
    let mut other = Vec::new();

    for rule in rules {
        let sourcetype = rule
            .rule
            .match_fields
            .get("sourcetype")
            .and_then(|v| v.as_str());
        match sourcetype {
            Some("aul") => aul.push(rule.clone()),
            Some("evtx") => evtx.push(rule.clone()),
            Some("journald") => journald.push(rule.clone()),
            _ => other.push(rule.clone()),
        }
    }

    (aul, evtx, journald, other)
}

fn render_rule_group(
    ui: &mut egui::Ui,
    heading: &str,
    rules: &[Rule],
    enabled: &mut BTreeSet<String>,
) {
    ui.horizontal(|ui| {
        ui.strong(format!("{heading} ({})", rules.len()));
        if ui.small_button("Select all").clicked() {
            for rule in rules {
                enabled.insert(rule.rule.name.clone());
            }
        }
        if ui.small_button("Select none").clicked() {
            for rule in rules {
                enabled.remove(&rule.rule.name);
            }
        }
    });
    egui::ScrollArea::vertical()
        .id_salt(heading)
        .max_height(180.0)
        .show(ui, |ui| {
            for rule in rules {
                let mut checked = enabled.contains(&rule.rule.name);
                let hover = format!(
                    "{}\n\nMatch: {}\nTag: {}",
                    rule.rule
                        .description
                        .as_deref()
                        .unwrap_or("(no description)"),
                    format_match_fields(&rule.rule.match_fields),
                    rule.rule.tag.value,
                );
                if ui
                    .checkbox(
                        &mut checked,
                        format!("{} \u{2192} {}", rule.rule.name, rule.rule.tag.value),
                    )
                    .on_hover_text(hover)
                    .changed()
                {
                    if checked {
                        enabled.insert(rule.rule.name.clone());
                    } else {
                        enabled.remove(&rule.rule.name);
                    }
                }
            }
        });
}

/// Short, human-readable summary of a rule's `[rule.match]` table for the
/// hover tooltip — `sourcetype` omitted (implied by which section the rule
/// is in), `message_contains` lists truncated to avoid a wall of text for
/// AUL rules with 20+ substrings (the full list is always in
/// `rules/examples/*.toml`/docs/rules-reference.md, this is a lookup aid,
/// not a rule editor).
fn format_match_fields(match_fields: &toml::Table) -> String {
    let mut parts = Vec::new();
    for (key, value) in match_fields {
        if key == "sourcetype" {
            continue;
        }
        let rendered = match value {
            toml::Value::Array(items) => {
                let strings: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
                if strings.len() > 3 {
                    format!(
                        "{}, {}, {}, (+{} more)",
                        strings[0],
                        strings[1],
                        strings[2],
                        strings.len() - 3
                    )
                } else {
                    strings.join(", ")
                }
            }
            toml::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        parts.push(format!("{key} = {rendered}"));
    }
    if parts.is_empty() {
        "(sourcetype only)".to_string()
    } else {
        parts.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_is_open() {
        assert!(BuiltinRulesDialog::open().is_open());
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!BuiltinRulesDialog::Closed.is_open());
    }

    #[test]
    fn group_by_sourcetype_splits_into_the_three_known_groups() {
        let rules = vec![
            Rule::from_toml_str(
                "[rule]\nname = \"aul_a\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
            )
            .unwrap(),
            Rule::from_toml_str(
                "[rule]\nname = \"evtx_a\"\n[rule.match]\nsourcetype = \"evtx\"\n[rule.tag]\nvalue = \"t\"\n",
            )
            .unwrap(),
            Rule::from_toml_str(
                "[rule]\nname = \"journald_a\"\n[rule.match]\nsourcetype = \"journald\"\n[rule.tag]\nvalue = \"t\"\n",
            )
            .unwrap(),
        ];

        let (aul, evtx, journald, other) = group_by_sourcetype(&rules);

        assert_eq!(aul.len(), 1);
        assert_eq!(aul[0].rule.name, "aul_a");
        assert_eq!(evtx.len(), 1);
        assert_eq!(evtx[0].rule.name, "evtx_a");
        assert_eq!(journald.len(), 1);
        assert_eq!(journald[0].rule.name, "journald_a");
        assert!(other.is_empty());
    }

    #[test]
    fn group_by_sourcetype_puts_unrecognized_sourcetypes_in_other() {
        let rules = vec![
            Rule::from_toml_str(
                "[rule]\nname = \"generic\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"t\"\n",
            )
            .unwrap(),
        ];

        let (aul, evtx, journald, other) = group_by_sourcetype(&rules);

        assert!(aul.is_empty());
        assert!(evtx.is_empty());
        assert!(journald.is_empty());
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].rule.name, "generic");
    }

    #[test]
    fn format_match_fields_with_only_sourcetype_says_so() {
        let mut table = toml::Table::new();
        table.insert(
            "sourcetype".to_string(),
            toml::Value::String("evtx".to_string()),
        );
        assert_eq!(format_match_fields(&table), "(sourcetype only)");
    }

    #[test]
    fn format_match_fields_truncates_long_arrays() {
        let mut table = toml::Table::new();
        table.insert(
            "message_contains".to_string(),
            toml::Value::Array(
                ["a", "b", "c", "d", "e"]
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        let formatted = format_match_fields(&table);
        assert!(formatted.contains("a, b, c, (+2 more)"), "{formatted}");
    }

    #[test]
    fn format_match_fields_shows_short_arrays_in_full() {
        let mut table = toml::Table::new();
        table.insert(
            "message_contains".to_string(),
            toml::Value::Array(vec![
                toml::Value::String("a".to_string()),
                toml::Value::String("b".to_string()),
            ]),
        );
        assert_eq!(format_match_fields(&table), "message_contains = a, b");
    }

    #[test]
    fn format_match_fields_shows_a_plain_value() {
        let mut table = toml::Table::new();
        table.insert("event_id".to_string(), toml::Value::Integer(4625));
        assert_eq!(format_match_fields(&table), "event_id = 4625");
    }
}
