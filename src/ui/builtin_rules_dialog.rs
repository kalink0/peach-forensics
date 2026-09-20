//! "Built-in Rules" picker — lets the analyst see every currently active
//! tagging rule (match condition, tag, description) and choose exactly which
//! ones are enabled, rather than only an all-or-nothing pack switch. Doubles
//! as the in-app rule reference — the same information
//! [docs/rules-reference.md](../../docs/rules-reference.md) documents,
//! generated from the same `rules/examples/*.toml` files.
//!
//! One table for every rule, with a search box, a Source dropdown, an
//! enabled/disabled filter and sortable column headers — the model and
//! controls it shares with the read-only reference dialog live in
//! [`crate::ui::rule_list`].
//!
//! Holds no rule *enablement* itself — `PeachApp::enabled_builtin_rules` (a
//! `BTreeSet` of rule names) is the single source of truth for which rules
//! are active, mutated directly through the `&mut` this dialog is handed.
//! The rule list is resolved once when the dialog opens, from
//! [`crate::tagging::builtin::active_builtin_rules`] — the live active set
//! (the same one `ui::rules_reference_dialog` shows), not the embedded
//! baseline: a downloaded (tier 2) pack wholesale-replaces tier 1 (see
//! `tagging::builtin`'s doc comment) and can name a completely different
//! set of rules, so listing the baseline here would show rules that aren't
//! actually tagging anything and hide ones that are. A pack applied while
//! this dialog is already open shows up after reopening it.

use std::collections::BTreeSet;

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::tagging::builtin;
use crate::tagging::pack_bundle;
use crate::tagging::rule_file;
use crate::ui::dialog_window::show_dialog_window;
use crate::ui::rule_list::{
    RuleRow, SortColumn, StatusFilter, ViewState, search_row, sort_header, source_dropdown,
    visible_indices,
};

/// Enables or disables exactly the rules at `indices` (what the table
/// currently shows), leaving every other rule as it was.
fn set_enabled(enabled: &mut BTreeSet<String>, rows: &[RuleRow], indices: &[usize], on: bool) {
    for &i in indices {
        if on {
            enabled.insert(rows[i].name.clone());
        } else {
            enabled.remove(&rows[i].name);
        }
    }
}

pub enum BuiltinRulesDialog {
    Closed,
    Open {
        /// `None` — the embedded baseline is what's listed; `Some` — a
        /// downloaded pack's own version is.
        active_pack_version: Option<u32>,
        rows: Vec<RuleRow>,
        view: ViewState,
        /// Set on open so the search box has the keyboard straight away;
        /// cleared after the first frame.
        focus_search: bool,
    },
}

impl BuiltinRulesDialog {
    pub fn open() -> Self {
        let applied_pack_dir = rule_file::default_applied_pack_dir().ok();
        let active_pack_version = applied_pack_dir
            .as_deref()
            .and_then(pack_bundle::read_applied_manifest)
            .map(|manifest| manifest.pack.pack_version);
        let rules = builtin::active_builtin_rules(applied_pack_dir.as_deref());
        Self::Open {
            active_pack_version,
            rows: rules.iter().map(RuleRow::from_rule).collect(),
            view: ViewState::default(),
            focus_search: true,
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Renders the dialog if open (a no-op otherwise), mutating `enabled`
    /// in place as the analyst (un)checks rules.
    pub fn ui(&mut self, ctx: &egui::Context, enabled: &mut BTreeSet<String>) {
        let mut close = false;

        if let Self::Open {
            active_pack_version,
            rows,
            view,
            focus_search,
        } = self
        {
            close = show_dialog_window(
                ctx,
                "peach_builtin_rules_dialog",
                "Built-in Rules",
                [900.0, 640.0],
                true,
                |ui, close| {
                    // Pinned to the bottom *before* the table below, same
                    // reasoning as `activity_log_dialog`/
                    // `rules_reference_dialog`'s bottom bars: a scrolling
                    // region claims all remaining space in its parent `Ui`
                    // first, which would push a Close button placed after
                    // it out of the window. `Panel::bottom` reserves its
                    // own space up front regardless of source order.
                    egui::Panel::bottom("peach_builtin_rules_dialog_bottom_bar").show(ui, |ui| {
                        ui.add_space(4.0);
                        if ui.button("Close").clicked() {
                            *close = true;
                        }
                        ui.add_space(4.0);
                    });

                    match active_pack_version {
                        Some(version) => ui.label(format!(
                            "Rule pack version {version} (downloaded via File \u{2192} Rule \
                             packs...). Checked rules apply on every load and re-tag."
                        )),
                        None => ui.label(
                            "Built-in baseline. Checked rules apply on every load and re-tag.",
                        ),
                    };

                    search_row(ui, view, focus_search);
                    ui.horizontal(|ui| {
                        source_dropdown(ui, rows, view);
                        ui.label("Show:");
                        ui.selectable_value(&mut view.status, StatusFilter::All, "All");
                        ui.selectable_value(&mut view.status, StatusFilter::Enabled, "Enabled");
                        ui.selectable_value(&mut view.status, StatusFilter::Disabled, "Disabled");
                    });
                    let visible = visible_indices(rows, Some(enabled), view);
                    bulk_toolbar(ui, rows, &visible, enabled);
                    ui.separator();

                    if visible.is_empty() {
                        ui.add_space(6.0);
                        ui.label("No rules match the current filters.");
                    } else {
                        rule_table(ui, rows, &visible, enabled, view);
                    }
                },
            );
        }

        if close {
            *self = Self::Closed;
        }
    }
}

/// The shown-count line and the bulk buttons. They act on the rules the
/// table lists right now, so "Enable shown" after a search enables just the
/// matches.
fn bulk_toolbar(
    ui: &mut egui::Ui,
    rows: &[RuleRow],
    visible: &[usize],
    enabled: &mut BTreeSet<String>,
) {
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !visible.is_empty(),
                egui::Button::new(format!("Enable shown ({})", visible.len())),
            )
            .on_hover_text("Enable every rule the table currently lists")
            .clicked()
        {
            set_enabled(enabled, rows, visible, true);
        }
        if ui
            .add_enabled(
                !visible.is_empty(),
                egui::Button::new(format!("Disable shown ({})", visible.len())),
            )
            .on_hover_text("Disable every rule the table currently lists")
            .clicked()
        {
            set_enabled(enabled, rows, visible, false);
        }
        let enabled_total = rows.iter().filter(|r| enabled.contains(&r.name)).count();
        ui.weak(format!(
            "{} of {} rules shown \u{00B7} {} enabled",
            visible.len(),
            rows.len(),
            enabled_total
        ));
    });
}

/// The rule table. It is the dialog's only scrolling region (no outer
/// `ScrollArea`), so `TableBuilder`'s own vertical scrollbar is the right
/// one — the nested-scroll problem the old per-source layout had doesn't
/// arise here.
fn rule_table(
    ui: &mut egui::Ui,
    rows: &[RuleRow],
    visible: &[usize],
    enabled: &mut BTreeSet<String>,
    view: &mut ViewState,
) {
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .min_scrolled_height(0.0)
        .column(Column::exact(28.0))
        .column(Column::initial(130.0).at_least(60.0).clip(true))
        .column(Column::initial(300.0).at_least(120.0).clip(true))
        .column(Column::initial(190.0).at_least(80.0).clip(true))
        .column(Column::remainder().at_least(160.0).clip(true))
        .header(22.0, |mut header| {
            header.col(|ui| {
                sort_header(ui, "\u{2713}", SortColumn::Enabled, view);
            });
            header.col(|ui| {
                sort_header(ui, "Source", SortColumn::Source, view);
            });
            header.col(|ui| {
                sort_header(ui, "Rule", SortColumn::Rule, view);
            });
            header.col(|ui| {
                sort_header(ui, "Tag", SortColumn::Tag, view);
            });
            header.col(|ui| {
                ui.strong("Description");
            });
        })
        .body(|body| {
            body.rows(20.0, visible.len(), |mut row| {
                let rule = &rows[visible[row.index()]];
                let is_enabled = enabled.contains(&rule.name);

                row.col(|ui| {
                    let mut checked = is_enabled;
                    if ui.checkbox(&mut checked, "").changed() {
                        if checked {
                            enabled.insert(rule.name.clone());
                        } else {
                            enabled.remove(&rule.name);
                        }
                    }
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(rule.source.label()).truncate())
                        .on_hover_text(&rule.hover);
                });
                row.col(|ui| {
                    let text = egui::RichText::new(&rule.display_name).monospace();
                    let text = if is_enabled { text } else { text.weak() };
                    ui.add(egui::Label::new(text).truncate())
                        .on_hover_text(&rule.hover);
                });
                row.col(|ui| {
                    let text = egui::RichText::new(&rule.tag).monospace();
                    let text = if is_enabled { text } else { text.weak() };
                    ui.add(egui::Label::new(text).truncate())
                        .on_hover_text(&rule.hover);
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(&rule.description).truncate())
                        .on_hover_text(&rule.hover);
                });
            });
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagging::rule::Rule;
    use crate::ui::rule_list::Source;

    fn rule(name: &str, sourcetype: &str) -> Rule {
        Rule::from_toml_str(&format!(
            "[rule]\nname = \"{name}\"\n[rule.match]\nsourcetype = \"{sourcetype}\"\n[rule.tag]\nvalue = \"t\"\n"
        ))
        .unwrap()
    }

    fn enabled_of(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn open_is_open() {
        assert!(BuiltinRulesDialog::open().is_open());
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!BuiltinRulesDialog::Closed.is_open());
    }

    #[test]
    fn bulk_enable_and_disable_only_touch_the_shown_rules() {
        let rows: Vec<RuleRow> = [
            rule("evtx_logon", "evtx"),
            rule("aul_wifi", "aul"),
            rule("aul_airplane", "aul"),
        ]
        .iter()
        .map(RuleRow::from_rule)
        .collect();
        let mut enabled = enabled_of(&["evtx_logon"]);
        let view = ViewState {
            search: "aul".into(),
            ..ViewState::default()
        };
        let shown = visible_indices(&rows, Some(&enabled), &view);

        set_enabled(&mut enabled, &rows, &shown, true);
        assert_eq!(
            enabled,
            enabled_of(&["aul_airplane", "aul_wifi", "evtx_logon"])
        );

        set_enabled(&mut enabled, &rows, &shown, false);
        // The hidden rule that was already enabled is untouched.
        assert_eq!(enabled, enabled_of(&["evtx_logon"]));
    }

    /// Runs `frames` frames of the dialog in a headless egui context — no
    /// window, so this catches a panic in the layout/table code, not how it
    /// looks. The screen is large enough that the window is not squeezed.
    fn render(dialog: &mut BuiltinRulesDialog, enabled: &mut BTreeSet<String>, frames: usize) {
        let ctx = egui::Context::default();
        for _ in 0..frames {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1400.0, 900.0),
                )),
                ..egui::RawInput::default()
            };
            let _ = ctx.run_ui(input, |ui| dialog.ui(ui.ctx(), enabled));
        }
    }

    fn dialog_with(view: ViewState) -> BuiltinRulesDialog {
        let mut dialog = BuiltinRulesDialog::open();
        if let BuiltinRulesDialog::Open { view: v, .. } = &mut dialog {
            *v = view;
        }
        dialog
    }

    #[test]
    fn the_dialog_renders_the_shipped_rules_in_every_view_without_panicking() {
        let all_names: BTreeSet<String> = builtin::all_builtin_rules()
            .iter()
            .map(|r| r.rule.name.clone())
            .collect();
        let searching = |text: &str| ViewState {
            search: text.into(),
            ..ViewState::default()
        };
        let mut views = vec![
            ViewState::default(),
            // A search with hits, and one with none (the empty-table branch).
            searching("airplane"),
            searching("no rule contains this text 9f3a"),
            ViewState {
                status: StatusFilter::Enabled,
                ..ViewState::default()
            },
            ViewState {
                status: StatusFilter::Disabled,
                ..ViewState::default()
            },
        ];
        let mut hide_aul = ViewState::default();
        hide_aul.toggle_source(Source::Aul);
        views.push(hide_aul);
        for column in [
            SortColumn::Enabled,
            SortColumn::Source,
            SortColumn::Rule,
            SortColumn::Tag,
        ] {
            for ascending in [true, false] {
                views.push(ViewState {
                    sort_column: column,
                    ascending,
                    ..ViewState::default()
                });
            }
        }

        for view in views {
            // Once with everything enabled, once with nothing.
            for enabled in [all_names.clone(), BTreeSet::new()] {
                let mut enabled = enabled;
                let mut dialog = dialog_with(view.clone());
                render(&mut dialog, &mut enabled, 3);
                assert!(dialog.is_open());
            }
        }
    }

    #[test]
    fn the_search_box_is_focused_on_the_first_frame_only() {
        let mut dialog = BuiltinRulesDialog::open();
        let mut enabled = BTreeSet::new();
        let focus = |d: &BuiltinRulesDialog| match d {
            BuiltinRulesDialog::Open { focus_search, .. } => *focus_search,
            BuiltinRulesDialog::Closed => panic!("dialog closed"),
        };

        assert!(focus(&dialog));
        render(&mut dialog, &mut enabled, 1);
        assert!(!focus(&dialog));
    }

    #[test]
    fn every_shipped_rule_appears_in_the_table_model() {
        let rules = builtin::all_builtin_rules();
        let rows: Vec<RuleRow> = rules.iter().map(RuleRow::from_rule).collect();
        let visible = visible_indices(&rows, Some(&BTreeSet::new()), &ViewState::default());
        assert_eq!(rows.len(), rules.len());
        assert_eq!(visible.len(), rules.len());
        // No rule falls into "Other" (that would mean a pack whose sourcetype
        // the dialogs don't know about).
        assert!(rows.iter().all(|r| r.source != Source::Other));
    }
}
