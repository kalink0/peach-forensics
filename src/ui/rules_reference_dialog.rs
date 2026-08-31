//! "Rules reference" — every currently active AUL/EVTX/journald tagging
//! rule's match condition, tag, and description, grouped by sourcetype.
//!
//! Built from [`tagging::builtin::active_builtin_rules`] every time the
//! dialog opens, **not** from the static `docs/rules-reference.md` file this
//! dialog used to embed via `include_str!`. That file is generated once at
//! build time from `rules/examples/*.toml` — accurate for the embedded
//! (tier 1) baseline, but silently stale the moment a downloaded (tier 2)
//! rule pack is applied via **File → Rule packs...**, since tier 2
//! wholesale-replaces tier 1 rather than adding to it (see
//! `tagging::builtin`'s doc comment). Reading the live active rule set
//! instead means this dialog always matches whatever's actually tagging
//! entries right now, whichever tier that is.
//!
//! One consequence: the old "Open on GitHub..." button pointed at that same
//! static file, which only ever matches this dialog's content while tier 1
//! is active — a downloaded pack has no single corresponding page on
//! GitHub. The button stays, but is disabled (with an explanatory tooltip)
//! whenever a downloaded pack is active rather than linking to something
//! that no longer matches what's on screen.
//!
//! Headings/prose go through [`egui_commonmark`] for clickable links and
//! real heading styles; each pack's rule table is hand-built with
//! `egui_extras::TableBuilder` instead (real column wrapping, real per-row
//! height for rules with many predicates) — same split the previous,
//! markdown-doc-backed version of this dialog used.

use eframe::egui;
use egui_commonmark::{CommonMarkCache, CommonMarkViewer};
use egui_extras::{Column, TableBuilder};

use crate::tagging::builtin;
use crate::tagging::pack_bundle;
use crate::tagging::rule::Rule;
use crate::tagging::rule_file;
use crate::ui::dialog_window::show_dialog_window;

/// The GitHub copy of the build-time-generated reference doc — only ever
/// accurate while the embedded (tier 1) baseline is active, see this
/// module's doc comment. Gated accordingly in the UI.
const RULES_REFERENCE_URL: &str =
    "https://github.com/kalink0/peach-forensics/blob/main/docs/rules-reference.md";

/// One rule, flattened for table display. `name` already carries the
/// rule's own version suffix (e.g. `aul_airplane_mode (v3)`) when present,
/// rather than a separate column — keeps the table at the same four
/// columns the previous doc-backed version had.
pub struct RuleRow {
    name: String,
    match_condition: String,
    tag: String,
    description: String,
}

/// One sourcetype's worth of rules — `heading_markdown` is rendered once
/// through `CommonMarkViewer`, the rows through `TableBuilder`.
pub struct Section {
    heading_markdown: String,
    rules: Vec<RuleRow>,
}

impl RuleRow {
    fn from_rule(rule: &Rule) -> Self {
        let name = match &rule.rule.version {
            Some(version) => format!("{} (v{version})", rule.rule.name),
            None => rule.rule.name.clone(),
        };
        RuleRow {
            name,
            match_condition: format_match(&rule.rule.match_fields),
            tag: rule.rule.tag.value.clone(),
            description: rule.rule.description.clone().unwrap_or_default(),
        }
    }

    fn matches_filter(&self, filter_lower: &str) -> bool {
        filter_lower.is_empty()
            || self.name.to_lowercase().contains(filter_lower)
            || self.match_condition.to_lowercase().contains(filter_lower)
            || self.tag.to_lowercase().contains(filter_lower)
            || self.description.to_lowercase().contains(filter_lower)
    }
}

pub enum RulesReferenceDialog {
    Closed,
    Open {
        /// `None` — the embedded baseline is active, the only case where
        /// [`RULES_REFERENCE_URL`] still shows the same rules as this
        /// dialog. `Some` — a downloaded pack's own `pack_version` (read
        /// from its `manifest.toml`, best-effort, same as
        /// `ui::rule_pack_dialog`'s header) is active instead, and the
        /// "Open on GitHub..." button is disabled accordingly.
        active_pack_version: Option<u32>,
        /// Parsed once at open time, not every frame — same reasoning
        /// `RawFieldsDialog` pretty-prints `fields` once.
        sections: Vec<Section>,
        /// `egui_commonmark`'s image/layout cache — persists across frames
        /// on purpose; recreating it every frame would defeat its point.
        cache: CommonMarkCache,
        /// Case-insensitive substring filter over every rule's name, match
        /// condition, tag, and description. A pack section disappears
        /// entirely once none of its rules match, rather than showing an
        /// empty table under a heading.
        filter: String,
    },
}

impl RulesReferenceDialog {
    pub fn open() -> Self {
        let applied_pack_dir = rule_file::default_applied_pack_dir().ok();
        let active_pack_version = applied_pack_dir
            .as_deref()
            .and_then(pack_bundle::read_applied_manifest)
            .map(|manifest| manifest.pack.pack_version);
        let rules = builtin::active_builtin_rules(applied_pack_dir.as_deref());
        Self::Open {
            active_pack_version,
            sections: build_sections(&rules),
            cache: CommonMarkCache::default(),
            filter: String::new(),
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        let mut close = false;

        if let Self::Open {
            active_pack_version,
            sections,
            cache,
            filter,
        } = self
        {
            close = show_dialog_window(
                ctx,
                "peach_rules_reference_dialog",
                "Rules Reference",
                [860.0, 660.0],
                true,
                |ui, close| {
                    // Pinned to the bottom *before* the scroll area below —
                    // same reasoning as `activity_log_dialog`'s bottom bar:
                    // an unbounded `ScrollArea` claims all remaining space
                    // in its parent `Ui` first, which for this dialog's
                    // hundred-plus rules (some `TableBuilder` rows well
                    // over 400px tall for a rule with 20+ predicates) grew
                    // the whole window far past the screen instead of
                    // scrolling, taking the Close button down with it and
                    // out of reach. `Panel::bottom` reserves its own space
                    // up front regardless of source order, so the button
                    // stays visible and the scroll area gets exactly what's
                    // left of the window's actual (bounded) height.
                    egui::Panel::bottom("peach_rules_reference_dialog_bottom_bar").show(ui, |ui| {
                        ui.add_space(4.0);
                        if ui.button("Close").clicked() {
                            *close = true;
                        }
                        ui.add_space(4.0);
                    });

                    render_active_pack_line(ui, *active_pack_version);

                    ui.horizontal(|ui| {
                        ui.label("Filter:");
                        ui.text_edit_singleline(filter);
                        let github_button = ui.add_enabled(
                            active_pack_version.is_none(),
                            egui::Button::new("Open on GitHub..."),
                        );
                        let github_button = if active_pack_version.is_some() {
                            github_button.on_disabled_hover_text(
                                "A downloaded rule pack is active — the GitHub copy only \
                                 matches the built-in baseline, not this pack.",
                            )
                        } else {
                            github_button
                        };
                        if github_button.clicked() {
                            ui.ctx()
                                .open_url(egui::OpenUrl::same_tab(RULES_REFERENCE_URL));
                        }
                    });
                    ui.separator();

                    let filter_lower = filter.trim().to_lowercase();

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if filter_lower.is_empty() {
                            CommonMarkViewer::new().show(
                                ui,
                                cache,
                                "Built from the rules actually active in this session right \
                                 now, not a fixed snapshot — this updates whenever a \
                                 different rule pack is applied. See **File → Rule packs...** \
                                 to check for updates.",
                            );
                        }

                        for section in sections.iter() {
                            let visible_rules: Vec<&RuleRow> = section
                                .rules
                                .iter()
                                .filter(|r| r.matches_filter(&filter_lower))
                                .collect();
                            if visible_rules.is_empty() {
                                continue;
                            }

                            CommonMarkViewer::new().show(ui, cache, &section.heading_markdown);
                            render_rule_table(ui, &visible_rules);
                            ui.add_space(12.0);
                        }
                    });
                },
            );
        }

        if close {
            *self = Self::Closed;
        }
    }
}

fn render_active_pack_line(ui: &mut egui::Ui, active_pack_version: Option<u32>) {
    match active_pack_version {
        Some(version) => {
            ui.label(format!(
                "Showing rule pack version {version} (applied via Rule packs...)."
            ));
        }
        None => {
            ui.label(format!(
                "Showing the built-in baseline — Peach {}, built {}.",
                env!("CARGO_PKG_VERSION"),
                env!("PEACH_BUILD_DATE"),
            ));
        }
    }
}

/// Groups `rules` into one [`Section`] per sourcetype (AUL, EVTX,
/// journald), sorted by rule name within each — plus a catch-all "Other"
/// group for anything that doesn't declare one of those three (e.g. a
/// downloaded pack containing a rule with no `sourcetype` match condition
/// at all), so a rule this dialog doesn't recognize is still shown rather
/// than silently dropped.
fn build_sections(rules: &[Rule]) -> Vec<Section> {
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
            Some("aul") => aul.push(rule),
            Some("evtx") => evtx.push(rule),
            Some("journald") => journald.push(rule),
            _ => other.push(rule),
        }
    }

    [
        ("AUL pattern-of-life rules", aul),
        ("EVTX Security-Auditing rules", evtx),
        ("journald rules", journald),
        ("Other rules", other),
    ]
    .into_iter()
    .filter(|(_, group)| !group.is_empty())
    .map(|(label, mut group)| {
        group.sort_by(|a, b| a.rule.name.cmp(&b.rule.name));
        let rules: Vec<RuleRow> = group.iter().map(|r| RuleRow::from_rule(r)).collect();
        Section {
            heading_markdown: format!("## {label} ({})", rules.len()),
            rules,
        }
    })
    .collect()
}

/// Renders a rule's `[rule.match]` table as human-readable lines, one
/// condition per line — `sourcetype` is skipped (already implied by which
/// [`Section`] the rule is in), `message_contains` gets its own bulleted
/// form for its OR-list semantics, everything else is `key = value` with
/// the value in the same syntax the source TOML itself uses (via
/// `toml::Value`'s own `Display`), rather than re-deriving a
/// presentation-only format — what's on screen matches what the rule file
/// actually says.
fn format_match(match_fields: &toml::Table) -> String {
    let mut parts = Vec::new();
    for (key, value) in match_fields {
        if key == "sourcetype" {
            continue;
        }
        if key == "message_contains" {
            parts.push(format_message_contains(value));
        } else {
            parts.push(format!("{key} = {value}"));
        }
    }
    if parts.is_empty() {
        "(sourcetype only)".to_string()
    } else {
        parts.join("\n")
    }
}

fn format_message_contains(value: &toml::Value) -> String {
    match value {
        toml::Value::Array(items) => {
            let bullets: Vec<String> = items.iter().map(|v| format!("• {v}")).collect();
            format!("message contains any of:\n{}", bullets.join("\n"))
        }
        other => format!("message contains {other}"),
    }
}

fn render_rule_table(ui: &mut egui::Ui, rows: &[&RuleRow]) {
    TableBuilder::new(ui)
        // `TableBuilder` wraps its body in its own `ScrollArea` by default
        // (sensible when a table is the only scrollable thing on screen,
        // e.g. `ui::timeline_view`) — here three of these sit inside one
        // outer `ScrollArea` that scrolls the whole dialog, so each
        // table's own scrollbar would just be a redundant, confusing
        // second scrollbar nested inside the first. Disabled; the outer
        // scroll area is the only one that should exist.
        .vscroll(false)
        .striped(true)
        .column(Column::auto().at_least(160.0))
        .column(Column::remainder().at_least(260.0))
        .column(Column::auto().at_least(130.0))
        .column(Column::remainder().at_least(220.0))
        .header(20.0, |mut header| {
            header.col(|ui| {
                ui.strong("Rule name");
            });
            header.col(|ui| {
                ui.strong("Match");
            });
            header.col(|ui| {
                ui.strong("Tag");
            });
            header.col(|ui| {
                ui.strong("Description");
            });
        })
        .body(|mut body| {
            for row in rows {
                body.row(estimate_row_height(row), |mut table_row| {
                    table_row.col(|ui| {
                        ui.label(egui::RichText::new(&row.name).monospace());
                    });
                    table_row.col(|ui| {
                        ui.label(egui::RichText::new(&row.match_condition).monospace());
                    });
                    table_row.col(|ui| {
                        ui.label(egui::RichText::new(&row.tag).monospace());
                    });
                    table_row.col(|ui| {
                        ui.label(&row.description);
                    });
                });
            }
        });
}

/// Approximates the row height a wrapped multi-line `Match` cell needs, so
/// `TableBuilder::body::row` (which wants a height up front, not something
/// it measures after the fact) doesn't clip a rule with many predicates.
/// Counts explicit lines only (each condition/bullet is its own line via
/// [`format_match`]), not word-wrap within a single very long line — an
/// approximation, not exact layout math; worst case one unusually long
/// single line looks slightly cramped, nothing is lost or hidden.
fn estimate_row_height(row: &RuleRow) -> f32 {
    const LINE_HEIGHT: f32 = 16.0;
    const VERTICAL_PADDING: f32 = 10.0;
    let lines = row.match_condition.lines().count().max(1) as f32;
    lines * LINE_HEIGHT + VERTICAL_PADDING
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(toml_text: &str) -> Rule {
        Rule::from_toml_str(toml_text).expect("valid test rule TOML")
    }

    #[test]
    fn format_match_skips_sourcetype_and_renders_key_value_pairs() {
        let r = rule(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_id = 4625\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert_eq!(format_match(&r.rule.match_fields), "event_id = 4625");
    }

    #[test]
    fn format_match_renders_message_contains_array_as_bullets() {
        let r = rule(
            "[rule]\nname = \"e\"\n[rule.match]\nmessage_contains = [\"a\", \"b\"]\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert_eq!(
            format_match(&r.rule.match_fields),
            "message contains any of:\n• \"a\"\n• \"b\""
        );
    }

    #[test]
    fn format_match_renders_a_single_message_contains_string() {
        let r = rule(
            "[rule]\nname = \"e\"\n[rule.match]\nmessage_contains = \"kPhoneNumber\"\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert_eq!(
            format_match(&r.rule.match_fields),
            "message contains \"kPhoneNumber\""
        );
    }

    #[test]
    fn format_match_reports_sourcetype_only_rules_explicitly() {
        let r = rule(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert_eq!(format_match(&r.rule.match_fields), "(sourcetype only)");
    }

    #[test]
    fn rule_row_from_rule_appends_version_when_present() {
        let r = rule(
            "[rule]\nname = \"aul_x\"\nversion = \"3\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"x\"\n",
        );
        let row = RuleRow::from_rule(&r);
        assert_eq!(row.name, "aul_x (v3)");
    }

    #[test]
    fn rule_row_from_rule_omits_version_suffix_when_absent() {
        let r = rule(
            "[rule]\nname = \"aul_x\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"x\"\n",
        );
        let row = RuleRow::from_rule(&r);
        assert_eq!(row.name, "aul_x");
    }

    #[test]
    fn build_sections_groups_by_sourcetype_and_sorts_by_name() {
        let rules = vec![
            rule(
                "[rule]\nname = \"aul_b\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
            ),
            rule(
                "[rule]\nname = \"aul_a\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
            ),
            rule(
                "[rule]\nname = \"evtx_a\"\n[rule.match]\nsourcetype = \"evtx\"\n[rule.tag]\nvalue = \"t\"\n",
            ),
        ];
        let sections = build_sections(&rules);

        assert_eq!(sections.len(), 2);
        assert!(sections[0].heading_markdown.contains("AUL"));
        assert_eq!(sections[0].rules.len(), 2);
        assert_eq!(sections[0].rules[0].name, "aul_a");
        assert_eq!(sections[0].rules[1].name, "aul_b");
        assert!(sections[1].heading_markdown.contains("EVTX"));
    }

    #[test]
    fn build_sections_puts_rules_with_no_recognized_sourcetype_in_other() {
        let rules = vec![rule(
            "[rule]\nname = \"generic_error\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"error\"\n",
        )];
        let sections = build_sections(&rules);

        assert_eq!(sections.len(), 1);
        assert!(sections[0].heading_markdown.contains("Other"));
    }

    /// Regression coverage against the real embedded baseline, not just
    /// the parser/grouping logic in isolation — confirms
    /// `active_builtin_rules(None)` produces all three expected pack
    /// sections with no empty ones.
    #[test]
    fn the_embedded_baseline_groups_into_three_non_empty_sections() {
        let rules = builtin::active_builtin_rules(None);
        let sections = build_sections(&rules);
        assert_eq!(sections.len(), 3);
        for section in &sections {
            assert!(!section.rules.is_empty());
            for row in &section.rules {
                assert!(!row.name.is_empty());
                assert!(!row.tag.is_empty());
            }
        }
    }

    /// `matches_filter` takes an *already-lowercased* filter (the call
    /// site lowercases it once per frame, not once per row) — case
    /// insensitivity comes from lowercasing each field's own content
    /// inside this method, which is what's under test here, e.g. a
    /// lowercase "airplane" filter matching the mixed-case
    /// "Airplane Mode is now 1" match condition.
    #[test]
    fn rule_row_filter_matches_any_field_case_insensitively() {
        let row = RuleRow {
            name: "aul_airplane_mode".to_string(),
            match_condition: "Airplane Mode is now 1".to_string(),
            tag: "airplane_mode".to_string(),
            description: "Airplane mode enabled or disabled".to_string(),
        };
        assert!(row.matches_filter(""));
        assert!(row.matches_filter("airplane"));
        assert!(row.matches_filter("now 1"));
        assert!(row.matches_filter("enabled or disabled"));
        assert!(!row.matches_filter("bluetooth"));
    }

    #[test]
    fn open_starts_dialog_open_with_no_filter_and_no_active_pack_version() {
        let dialog = RulesReferenceDialog::open();
        assert!(dialog.is_open());
        assert!(matches!(
            &dialog,
            RulesReferenceDialog::Open {
                filter,
                ..
            } if filter.is_empty()
        ));
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!RulesReferenceDialog::Closed.is_open());
    }
}
