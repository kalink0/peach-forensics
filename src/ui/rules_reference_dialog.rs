//! "Rules reference" — every currently active tagging rule's match
//! condition, tag, and description, in one table with a search box, a Source
//! dropdown and sortable column headers (the model and controls it shares
//! with the Built-in Rules picker live in [`crate::ui::rule_list`]). Unlike
//! that picker it is read-only. Every row is one line of the same height;
//! selecting a rule shows its complete match condition and description in a
//! panel below the table.
//!
//! The rows are deliberately not sized to their content. A rule can have
//! thirty match phrases, and a table whose rows are each as tall as their
//! longest cell is neither scannable nor, without measuring the text against
//! the real column widths, reliably laid out. One-line rows with a summary
//! in the Match column (the full text is in the tooltip and the detail panel)
//! keep the overview and never clip.
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

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::tagging::builtin;
use crate::tagging::pack_bundle;
use crate::tagging::rule_file;
use crate::ui::dialog_window::show_dialog_window;
use crate::ui::rule_list::{
    RuleRow, SortColumn, ViewState, search_row, sort_header, source_dropdown, visible_indices,
};

/// The GitHub copy of the build-time-generated reference doc — only ever
/// accurate while the embedded (tier 1) baseline is active, see this
/// module's doc comment. Gated accordingly in the UI.
const RULES_REFERENCE_URL: &str =
    "https://github.com/kalink0/peach-forensics/blob/main/docs/rules-reference.md";

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
        rows: Vec<RuleRow>,
        view: ViewState,
        /// The rule whose full details are shown below the table, by name.
        /// Kept when a filter hides its row.
        selected: Option<String>,
        /// Set on open so the search box has the keyboard straight away;
        /// cleared after the first frame.
        focus_search: bool,
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
            rows: rules.iter().map(RuleRow::from_rule).collect(),
            view: ViewState::default(),
            selected: None,
            focus_search: true,
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        let mut close = false;

        if let Self::Open {
            active_pack_version,
            rows,
            view,
            selected,
            focus_search,
        } = self
        {
            close = show_dialog_window(
                ctx,
                "peach_rules_reference_dialog",
                "Rules Reference",
                [960.0, 680.0],
                true,
                |ui, close| {
                    // Pinned to the bottom *before* the table below, same
                    // reasoning as `activity_log_dialog`'s bottom bar: a
                    // scrolling region claims all remaining space in its
                    // parent `Ui` first, which would push a Close button
                    // placed after it out of the window (with this dialog's
                    // hundred-plus rules, some over 400px tall, it grew the
                    // whole window past the screen and took the button with
                    // it). `Panel::bottom` reserves its own space up front
                    // regardless of source order, so the button stays
                    // visible and the table gets exactly what's left of the
                    // window's actual (bounded) height.
                    egui::Panel::bottom("peach_rules_reference_dialog_bottom_bar").show(ui, |ui| {
                        ui.add_space(4.0);
                        if ui.button("Close").clicked() {
                            *close = true;
                        }
                        ui.add_space(4.0);
                    });
                    // Above the Close bar (panels stack from the edge inward),
                    // also declared before the table so the table gets only
                    // what is left.
                    egui::Panel::bottom("peach_rules_reference_dialog_detail").show(ui, |ui| {
                        ui.add_space(4.0);
                        detail_panel(ui, rows, selected.as_deref());
                        ui.add_space(4.0);
                    });

                    render_active_pack_line(ui, *active_pack_version);
                    ui.weak(
                        "Built from the rules actually active in this session right now, not \
                         a fixed snapshot — this updates whenever a different rule pack is \
                         applied. See File \u{2192} Rule packs... to check for updates.",
                    );

                    search_row(ui, view, focus_search);
                    ui.horizontal(|ui| {
                        source_dropdown(ui, rows, view);
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

                    let visible = visible_indices(rows, None, view);
                    ui.weak(format!("{} of {} rules shown", visible.len(), rows.len()));
                    ui.separator();

                    if visible.is_empty() {
                        ui.add_space(6.0);
                        ui.label("No rules match the current filters.");
                    } else {
                        reference_table(ui, rows, &visible, view, selected);
                    }
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

/// Height of every table row. One line of text plus a little air.
const ROW_HEIGHT: f32 = 20.0;

/// The rule table. It is the dialog's only scrolling region (no outer
/// `ScrollArea`), so `TableBuilder`'s own vertical scrollbar is the right
/// one. Every row is one line, so `rows` (fixed height, only the rows on
/// screen are built) is enough. Text that doesn't fit its column is cut with
/// an ellipsis, and the full text is in the row's tooltip and, for the
/// selected rule, the detail panel.
///
/// Clicking any cell selects the rule. The cells carry their own click sense
/// rather than the table row: a row-level `Sense::click` is the shape that
/// interfered with the timeline's row context menu.
fn reference_table(
    ui: &mut egui::Ui,
    rows: &[RuleRow],
    visible: &[usize],
    view: &mut ViewState,
    selected: &mut Option<String>,
) {
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .min_scrolled_height(0.0)
        .column(Column::initial(110.0).at_least(60.0).clip(true))
        .column(Column::initial(230.0).at_least(120.0).clip(true))
        .column(Column::initial(260.0).at_least(120.0).clip(true))
        .column(Column::initial(170.0).at_least(80.0).clip(true))
        .column(Column::remainder().at_least(160.0).clip(true))
        .header(22.0, |mut header| {
            header.col(|ui| {
                sort_header(ui, "Source", SortColumn::Source, view);
            });
            header.col(|ui| {
                sort_header(ui, "Rule", SortColumn::Rule, view);
            });
            header.col(|ui| {
                ui.strong("Match");
            });
            header.col(|ui| {
                sort_header(ui, "Tag", SortColumn::Tag, view);
            });
            header.col(|ui| {
                ui.strong("Description");
            });
        })
        .body(|body| {
            body.rows(ROW_HEIGHT, visible.len(), |mut row| {
                let rule = &rows[visible[row.index()]];
                let is_selected = selected.as_deref() == Some(rule.name.as_str());
                row.set_selected(is_selected);

                let mut clicked = false;
                let mut cell = |ui: &mut egui::Ui, text: egui::RichText, hover: &str| {
                    let response = ui
                        .add(
                            egui::Label::new(text)
                                .truncate()
                                .sense(egui::Sense::click()),
                        )
                        .on_hover_text(hover);
                    clicked |= response.clicked();
                };
                row.col(|ui| {
                    cell(ui, egui::RichText::new(rule.source.label()), &rule.hover);
                });
                row.col(|ui| {
                    cell(
                        ui,
                        egui::RichText::new(&rule.display_name).monospace(),
                        &rule.hover,
                    );
                });
                row.col(|ui| {
                    cell(
                        ui,
                        egui::RichText::new(&rule.match_summary).monospace(),
                        &rule.match_condition,
                    );
                });
                row.col(|ui| {
                    cell(ui, egui::RichText::new(&rule.tag).monospace(), &rule.hover);
                });
                row.col(|ui| {
                    cell(ui, egui::RichText::new(&rule.description), &rule.hover);
                });
                if clicked {
                    *selected = Some(rule.name.clone());
                }
            });
        });
}

/// The selected rule's complete details: name, source and tag, the full
/// description, and the whole match condition, wrapped and scrollable. With
/// nothing selected, a hint — the panel keeps a minimum height either way so
/// the table above doesn't jump when a rule is picked.
fn detail_panel(ui: &mut egui::Ui, rows: &[RuleRow], selected: Option<&str>) {
    ui.set_min_height(110.0);
    let Some(rule) = selected.and_then(|name| rows.iter().find(|r| r.name == name)) else {
        ui.weak("Click a rule to see its full match condition and description here.");
        return;
    };
    ui.horizontal_wrapped(|ui| {
        ui.strong(&rule.display_name);
        ui.weak(format!("\u{00B7} {} \u{00B7} tag", rule.source.label()));
        ui.monospace(&rule.tag);
    });
    if !rule.description.is_empty() {
        ui.add(egui::Label::new(&rule.description).wrap());
    }
    egui::ScrollArea::vertical()
        .id_salt("peach_rules_reference_dialog_detail_scroll")
        .max_height(150.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.add(egui::Label::new(egui::RichText::new(&rule.match_condition).monospace()).wrap());
        });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::tagging::rule::Rule;
    use crate::ui::rule_list::{Source, StatusFilter};

    fn rule(toml_text: &str) -> Rule {
        Rule::from_toml_str(toml_text).expect("valid test rule TOML")
    }

    fn row(toml_text: &str) -> RuleRow {
        RuleRow::from_rule(&rule(toml_text))
    }

    /// The one-line Match cell shows a summary; the full condition is what
    /// the tooltip and the detail panel show, so both must exist and the
    /// summary must never be longer than the full text would need.
    #[test]
    fn a_row_has_a_one_line_summary_and_the_full_multi_line_condition() {
        let r = row(
            "[rule]\nname = \"e\"\n[rule.match]\nmessage_contains = [\"a\", \"b\", \"c\", \"d\", \"e\"]\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert!(!r.match_summary.contains('\n'), "{:?}", r.match_summary);
        assert!(r.match_summary.contains("(+2 more)"), "{}", r.match_summary);
        // "message contains any of:" plus five bullets.
        assert_eq!(r.match_condition.lines().count(), 6);
    }

    #[test]
    fn open_starts_dialog_open_with_no_filter() {
        let dialog = RulesReferenceDialog::open();
        assert!(dialog.is_open());
        assert!(matches!(
            &dialog,
            RulesReferenceDialog::Open { view, selected: None, .. } if view.no_filter()
        ));
    }

    #[test]
    fn closed_is_not_open() {
        assert!(!RulesReferenceDialog::Closed.is_open());
    }

    /// Regression coverage against the real embedded baseline, not just the
    /// grouping logic in isolation: every shipped rule gets a row, none is
    /// in the "Other" catch-all (every embedded rule declares one of the
    /// known sourcetypes), and each has a name and tag.
    #[test]
    fn the_embedded_baseline_lists_every_rule_in_a_known_source() {
        let rules = builtin::active_builtin_rules(None);
        let rows: Vec<RuleRow> = rules.iter().map(RuleRow::from_rule).collect();
        assert_eq!(rows.len(), rules.len());
        for r in &rows {
            assert!(!r.name.is_empty());
            assert!(!r.tag.is_empty());
            assert!(!r.match_condition.is_empty());
            assert_ne!(r.source, Source::Other, "{}", r.name);
        }
        let sources: BTreeSet<Source> = rows.iter().map(|r| r.source).collect();
        assert_eq!(sources.len(), 5);
    }

    /// Runs `frames` frames of the dialog in a headless egui context — no
    /// window, so this catches a panic in the layout/table code, not how it
    /// looks.
    fn render(dialog: &mut RulesReferenceDialog, frames: usize) {
        let ctx = egui::Context::default();
        for _ in 0..frames {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1400.0, 900.0),
                )),
                ..egui::RawInput::default()
            };
            let _ = ctx.run_ui(input, |ui| dialog.ui(ui.ctx()));
        }
    }

    #[test]
    fn the_dialog_renders_the_shipped_rules_in_every_view_without_panicking() {
        let searching = |text: &str| ViewState {
            search: text.into(),
            ..ViewState::default()
        };
        let mut hide_aul = ViewState::default();
        hide_aul.toggle_source(Source::Aul);
        let mut views = vec![
            ViewState::default(),
            searching("airplane"),
            searching("no rule contains this text 9f3a"),
            hide_aul,
            ViewState {
                status: StatusFilter::Disabled,
                ..ViewState::default()
            },
        ];
        for column in [SortColumn::Source, SortColumn::Rule, SortColumn::Tag] {
            for ascending in [true, false] {
                views.push(ViewState {
                    sort_column: column,
                    ascending,
                    ..ViewState::default()
                });
            }
        }

        for view in views {
            let mut dialog = RulesReferenceDialog::open();
            if let RulesReferenceDialog::Open { view: v, .. } = &mut dialog {
                *v = view;
            }
            render(&mut dialog, 3);
            assert!(dialog.is_open());
        }
    }

    /// The detail panel with a real rule selected, with a name that isn't in
    /// the list (a filter never removes it from `rows`, but a stale name
    /// must not panic), and while a search hides the selected rule's row.
    #[test]
    fn the_detail_panel_renders_for_a_present_a_missing_and_a_filtered_out_rule() {
        let first_name = match RulesReferenceDialog::open() {
            RulesReferenceDialog::Open { rows, .. } => rows[0].name.clone(),
            RulesReferenceDialog::Closed => unreachable!(),
        };
        for (selected, search) in [
            (Some(first_name.clone()), ""),
            (Some("no_such_rule".to_string()), ""),
            (Some(first_name), "no rule contains this text 9f3a"),
            (None, ""),
        ] {
            let mut dialog = RulesReferenceDialog::open();
            if let RulesReferenceDialog::Open {
                selected: sel,
                view,
                ..
            } = &mut dialog
            {
                *sel = selected;
                view.search = search.into();
            }
            render(&mut dialog, 3);
            assert!(dialog.is_open());
        }
    }
}
