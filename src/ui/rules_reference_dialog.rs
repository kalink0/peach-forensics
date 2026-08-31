//! "Rules reference" — the full [docs/rules-reference.md](../../docs/rules-reference.md)
//! content (every built-in AUL/EVTX/journald rule's match condition, tag,
//! and description), embedded into the binary (`include_str!`, resolved at
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
//! connectivity and wants that rendering instead.
//!
//! The document has two very different kinds of content, rendered two
//! different ways:
//! - Headings and prose (the intro, and each pack's provenance paragraph)
//!   go through [`egui_commonmark`], so links (iLEAPP, Thesis Friday,
//!   user-guide.md) stay clickable and headings render as headings.
//! - Each pack's rule table is *not* piped through the markdown renderer.
//!   `egui_commonmark`'s table cells don't wrap and treat raw HTML as
//!   literal text rather than a line break — the source doc's `<br>`/
//!   `&bull;` (a GitHub-table shim, see `scripts/gen_rules_reference.py`)
//!   would show up as literal `<br>` text instead of a line break, and a
//!   `Match` cell with 20+ predicates (e.g. `aul_bluetooth_status`) would
//!   force the whole table absurdly wide with no wrapping. [`parse_rule_row`]
//!   instead extracts each row into a [`RuleRow`] and [`render_rule_table`]
//!   draws it with `egui_extras::TableBuilder`, same as the rest of the
//!   app's tables (see `ui::timeline_view`) — real column wrapping, real
//!   per-row height instead.

use eframe::egui;
use egui_commonmark::{CommonMarkCache, CommonMarkViewer};
use egui_extras::{Column, TableBuilder};

use crate::ui::dialog_window::show_dialog_window;

const RULES_REFERENCE_MD: &str = include_str!("../../docs/rules-reference.md");

/// The GitHub copy of the same file — offered as a secondary "if you have
/// internet" option, not the primary path anymore.
const RULES_REFERENCE_URL: &str =
    "https://github.com/kalink0/peach-forensics/blob/main/docs/rules-reference.md";

/// One `| name | match | tag | description |` data row from the source
/// doc's pipe tables. `name`/`tag` are always a single backtick-wrapped
/// code span in the source (see `scripts/gen_rules_reference.py`), so
/// stripping one leading/trailing backtick is exact, not a heuristic.
pub struct RuleRow {
    name: String,
    match_condition: String,
    tag: String,
    description: String,
}

/// One `## `-level section of the doc — one rule pack (AUL/EVTX/journald).
pub struct Section {
    /// The `## ` heading line plus any prose paragraph(s) before the
    /// table, still raw markdown, rendered through `CommonMarkViewer`.
    intro_markdown: String,
    rules: Vec<RuleRow>,
}

impl RuleRow {
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
        /// Everything before the first `## ` heading (title + top-level
        /// intro paragraph) — parsed once at open time, not every frame,
        /// same reasoning `RawFieldsDialog` pretty-prints `fields` once.
        preamble_markdown: String,
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
        let (preamble_markdown, sections) = parse_reference_doc(RULES_REFERENCE_MD);
        Self::Open {
            preamble_markdown,
            sections,
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
            preamble_markdown,
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

                    ui.horizontal(|ui| {
                        ui.label("Filter:");
                        ui.text_edit_singleline(filter);
                        if ui.button("Open on GitHub...").clicked() {
                            ui.ctx()
                                .open_url(egui::OpenUrl::same_tab(RULES_REFERENCE_URL));
                        }
                    });
                    ui.separator();

                    let filter_lower = filter.trim().to_lowercase();

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if filter_lower.is_empty() {
                            CommonMarkViewer::new().show(ui, cache, preamble_markdown);
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

                            CommonMarkViewer::new().show(ui, cache, &section.intro_markdown);
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
/// Counts explicit lines only (each `<br>`-turned-newline is one bullet),
/// not word-wrap within a single very long bullet — an approximation, not
/// exact layout math; worst case one unusually long single line looks
/// slightly cramped, nothing is lost or hidden.
fn estimate_row_height(row: &RuleRow) -> f32 {
    const LINE_HEIGHT: f32 = 16.0;
    const VERTICAL_PADDING: f32 = 10.0;
    let lines = row.match_condition.lines().count().max(1) as f32;
    lines * LINE_HEIGHT + VERTICAL_PADDING
}

/// Splits the source doc into the top-level preamble (everything before
/// the first `## ` heading) and one [`Section`] per `## ` heading.
fn parse_reference_doc(markdown: &str) -> (String, Vec<Section>) {
    let lines: Vec<&str> = markdown.lines().collect();
    let mut i = 0;

    let mut preamble = Vec::new();
    while i < lines.len() && !lines[i].starts_with("## ") {
        preamble.push(lines[i]);
        i += 1;
    }

    let mut sections = Vec::new();
    while i < lines.len() {
        let mut intro = vec![lines[i]]; // the "## " heading line itself
        i += 1;
        while i < lines.len() && !lines[i].starts_with('|') && !lines[i].starts_with("## ") {
            intro.push(lines[i]);
            i += 1;
        }

        let mut rules = Vec::new();
        if i < lines.len() && lines[i].starts_with('|') {
            i += 1; // header row ("| Rule name | Match | Tag | Description |")
            if i < lines.len() && lines[i].starts_with('|') {
                i += 1; // separator row ("|---|---|---|---|")
            }
            while i < lines.len() && lines[i].starts_with('|') {
                if let Some(row) = parse_rule_row(lines[i]) {
                    rules.push(row);
                }
                i += 1;
            }
        }

        while i < lines.len() && lines[i].trim().is_empty() {
            i += 1;
        }

        sections.push(Section {
            intro_markdown: intro.join("\n"),
            rules,
        });
    }

    (preamble.join("\n"), sections)
}

fn parse_rule_row(line: &str) -> Option<RuleRow> {
    let inner = line.trim().strip_prefix('|')?.strip_suffix('|')?;
    let cells: Vec<&str> = inner.split('|').map(str::trim).collect();
    if cells.len() != 4 {
        return None;
    }
    Some(RuleRow {
        name: strip_code_span(cells[0]),
        match_condition: decode_match_cell(cells[1]),
        tag: strip_code_span(cells[2]),
        description: cells[3].to_string(),
    })
}

fn strip_code_span(cell: &str) -> String {
    cell.trim_matches('`').to_string()
}

/// Turns the GitHub-table HTML shim (`<br>` between predicates, `&bull;`
/// before each one — see `scripts/gen_rules_reference.py`) into a real
/// newline/bullet for a plain `egui::Label`. Safe to do unconditionally
/// here (unlike the old monospace-blob dialog, or a markdown renderer):
/// this table is hand-built with `TableBuilder`, not re-serialized as
/// markdown, so nothing needs to stay valid single-line GFM table syntax.
fn decode_match_cell(cell: &str) -> String {
    cell.replace("<br>", "\n").replace("&bull;", "•")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rule_row_strips_code_spans_and_decodes_bullets() {
        let row = parse_rule_row(
            "| `aul_x` | message contains any of:<br>&bull; `a`<br>&bull; `b` | `x_tag` | Some description |",
        )
        .expect("valid row");
        assert_eq!(row.name, "aul_x");
        assert_eq!(
            row.match_condition,
            "message contains any of:\n• `a`\n• `b`"
        );
        assert_eq!(row.tag, "x_tag");
        assert_eq!(row.description, "Some description");
    }

    #[test]
    fn parse_rule_row_handles_a_single_non_list_match() {
        let row = parse_rule_row("| `aul_y` | message contains `kPhoneNumber` | `y_tag` | Desc |")
            .expect("valid row");
        assert_eq!(row.match_condition, "message contains `kPhoneNumber`");
    }

    #[test]
    fn parse_rule_row_rejects_a_line_that_is_not_a_pipe_table_row() {
        assert!(parse_rule_row("Not a table row").is_none());
        assert!(parse_rule_row("| only two | cells |").is_none());
    }

    #[test]
    fn parse_reference_doc_splits_preamble_and_sections() {
        let doc = "\
# Title

Intro paragraph.

## AUL pattern-of-life rules (2)

Some provenance text.

| Rule name | Match | Tag | Description |
|---|---|---|---|
| `aul_a` | message contains `a` | `a_tag` | Rule A |
| `aul_b` | message contains `b` | `b_tag` | Rule B |

## EVTX rules (1)

More provenance text.

| Rule name | Match | Tag | Description |
|---|---|---|---|
| `evtx_a` | `event_id` = `1` | `evtx_a_tag` | Event A |
";
        let (preamble, sections) = parse_reference_doc(doc);
        assert!(preamble.contains("# Title"));
        assert!(preamble.contains("Intro paragraph."));

        assert_eq!(sections.len(), 2);
        assert!(
            sections[0]
                .intro_markdown
                .contains("AUL pattern-of-life rules (2)")
        );
        assert!(sections[0].intro_markdown.contains("Some provenance text."));
        assert_eq!(sections[0].rules.len(), 2);
        assert_eq!(sections[0].rules[0].name, "aul_a");
        assert_eq!(sections[0].rules[1].name, "aul_b");

        assert_eq!(sections[1].rules.len(), 1);
        assert_eq!(sections[1].rules[0].name, "evtx_a");
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

    /// Regression coverage against the actual embedded file, not just the
    /// parser in isolation — confirms `include_str!` resolved a real,
    /// non-empty file with the expected three pack sections and that
    /// parsing it end to end produces a sane, non-empty result.
    #[test]
    fn the_embedded_rules_reference_parses_into_three_non_empty_sections() {
        let (preamble, sections) = parse_reference_doc(RULES_REFERENCE_MD);
        assert!(preamble.contains("Tagging Rule Reference"));
        assert_eq!(sections.len(), 3);
        for section in &sections {
            assert!(!section.rules.is_empty());
            for rule in &section.rules {
                assert!(!rule.name.is_empty());
                assert!(!rule.tag.is_empty());
            }
        }
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
