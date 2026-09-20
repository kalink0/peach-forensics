//! The model and controls the two rule dialogs share
//! ([`crate::ui::builtin_rules_dialog`], the picker that enables/disables
//! rules, and [`crate::ui::rules_reference_dialog`], the read-only
//! reference): one row per rule, a search box, a Source dropdown, sortable
//! column headers, and the filtering/sorting behind them.
//!
//! Both used to be one short list (or table) per source; with over two
//! hundred rules that meant scrolling several separate regions to find one
//! rule, with no way to search. The filtering and sorting ([`ViewState`],
//! [`visible_indices`]) are plain functions with no UI in them, so they are
//! unit-tested directly.

use std::collections::BTreeSet;

use eframe::egui;

use crate::tagging::rule::Rule;

/// Which rule pack a rule belongs to, decided by its own `sourcetype` match
/// condition. Declaration order is the order the table sorts sources in
/// (the order the packs were introduced), not alphabetical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    Aul,
    Evtx,
    Journald,
    IntrusionLog,
    Biome,
    Other,
}

impl Source {
    pub const ALL: [Source; 6] = [
        Source::Aul,
        Source::Evtx,
        Source::Journald,
        Source::IntrusionLog,
        Source::Biome,
        Source::Other,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Source::Aul => "AUL",
            Source::Evtx => "EVTX",
            Source::Journald => "journald",
            Source::IntrusionLog => "Android Intrusion Log",
            Source::Biome => "Apple Biome",
            Source::Other => "Other",
        }
    }

    /// A rule that declares none of the known sourcetypes (e.g. one from a
    /// downloaded pack with unexpected content) lands in `Other` rather than
    /// being dropped: it would otherwise stay enabled in
    /// `enabled_builtin_rules` with no way to inspect or disable it from the
    /// UI.
    pub fn of(rule: &Rule) -> Self {
        match rule
            .rule
            .match_fields
            .get("sourcetype")
            .and_then(|v| v.as_str())
        {
            Some("aul") => Source::Aul,
            Some("evtx") => Source::Evtx,
            Some("journald") => Source::Journald,
            Some("intrusion_log") => Source::IntrusionLog,
            Some("biome") => Source::Biome,
            _ => Source::Other,
        }
    }
}

/// One rule, flattened for display and searching. Built once per dialog
/// open, not every frame.
pub struct RuleRow {
    /// The rule's name — also the key in `enabled_builtin_rules`.
    pub(crate) name: String,
    /// `name` plus the rule's own version (`aul_airplane_mode (v3)`) when it
    /// has one.
    pub(crate) display_name: String,
    pub(crate) source: Source,
    pub(crate) tag: String,
    pub(crate) description: String,
    /// The whole match condition, one condition per line
    /// ([`format_match`]).
    pub(crate) match_condition: String,
    /// The match condition on a single line, long lists abbreviated
    /// ([`format_match_fields`]) — what a one-line table cell shows.
    pub(crate) match_summary: String,
    /// Tooltip: description, a short match summary and the tag.
    pub(crate) hover: String,
    /// Lowercased text the search box looks through: name, tag, description,
    /// source and the *complete* match condition — every `message_contains`
    /// needle, not the abbreviated form the tooltip shows — so a search for
    /// a phrase finds the rule that matches it.
    haystack: String,
}

impl RuleRow {
    pub fn from_rule(rule: &Rule) -> Self {
        let name = rule.rule.name.clone();
        let display_name = match &rule.rule.version {
            Some(version) => format!("{name} (v{version})"),
            None => name.clone(),
        };
        let source = Source::of(rule);
        let tag = rule.rule.tag.value.clone();
        let description = rule.rule.description.clone().unwrap_or_default();
        let match_summary = format_match_fields(&rule.rule.match_fields);
        let hover = format!(
            "{}\n\nMatch: {match_summary}\nTag: {tag}",
            if description.is_empty() {
                "(no description)"
            } else {
                &description
            },
        );
        let haystack = format!(
            "{name}\n{tag}\n{description}\n{}\n{}",
            source.label(),
            full_match_text(&rule.rule.match_fields)
        )
        .to_lowercase();
        RuleRow {
            name,
            display_name,
            source,
            tag,
            description,
            match_condition: format_match(&rule.rule.match_fields),
            match_summary,
            hover,
            haystack,
        }
    }
}

/// Every key and value of a rule's `[rule.match]` table as searchable text,
/// arrays and nested tables flattened in full (unlike
/// [`format_match_fields`], which abbreviates for a tooltip).
fn full_match_text(match_fields: &toml::Table) -> String {
    fn push(out: &mut String, value: &toml::Value) {
        match value {
            toml::Value::String(s) => {
                out.push_str(s);
                out.push('\n');
            }
            toml::Value::Array(items) => items.iter().for_each(|item| push(out, item)),
            toml::Value::Table(table) => {
                for (key, inner) in table {
                    out.push_str(key);
                    out.push('\n');
                    push(out, inner);
                }
            }
            other => {
                out.push_str(&other.to_string());
                out.push('\n');
            }
        }
    }
    let mut out = String::new();
    for (key, value) in match_fields {
        out.push_str(key);
        out.push('\n');
        push(&mut out, value);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    /// Only meaningful where rules can be enabled (the picker); without an
    /// enabled set every rule counts as enabled and this column sorts as a
    /// tie.
    Enabled,
    Source,
    Rule,
    Tag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusFilter {
    All,
    Enabled,
    Disabled,
}

/// Everything the analyst can change about how the table looks — none of it
/// touches which rules are enabled.
#[derive(Debug, Clone)]
pub struct ViewState {
    pub(crate) search: String,
    /// Sources hidden from the table. An exclusion set, like the timeline's
    /// Sources dropdown: a source that isn't loaded can't be left hidden by
    /// accident.
    pub(crate) hidden_sources: BTreeSet<Source>,
    pub(crate) status: StatusFilter,
    pub(crate) sort_column: SortColumn,
    pub(crate) ascending: bool,
}

impl Default for ViewState {
    fn default() -> Self {
        ViewState {
            search: String::new(),
            hidden_sources: BTreeSet::new(),
            status: StatusFilter::All,
            sort_column: SortColumn::Source,
            ascending: true,
        }
    }
}

impl ViewState {
    /// True when no search, source or status filter is narrowing the table.
    pub(crate) fn no_filter(&self) -> bool {
        self.search.trim().is_empty()
            && self.hidden_sources.is_empty()
            && self.status == StatusFilter::All
    }

    pub(crate) fn reset_filters(&mut self) {
        self.search.clear();
        self.hidden_sources.clear();
        self.status = StatusFilter::All;
    }

    /// Clicking the sorted column flips its direction; clicking another
    /// column sorts by it ascending.
    pub(crate) fn toggle_sort(&mut self, column: SortColumn) {
        if self.sort_column == column {
            self.ascending = !self.ascending;
        } else {
            self.sort_column = column;
            self.ascending = true;
        }
    }

    pub(crate) fn toggle_source(&mut self, source: Source) {
        if !self.hidden_sources.remove(&source) {
            self.hidden_sources.insert(source);
        }
    }

    /// Shows only `source`, hides every other one in `present`.
    pub(crate) fn solo_source(&mut self, source: Source, present: &[Source]) {
        self.hidden_sources = present.iter().copied().filter(|s| *s != source).collect();
    }

    pub(crate) fn show_all_sources(&mut self) {
        self.hidden_sources.clear();
    }

    fn accepts(&self, row: &RuleRow, is_enabled: bool) -> bool {
        if self.hidden_sources.contains(&row.source) {
            return false;
        }
        match self.status {
            StatusFilter::All => {}
            StatusFilter::Enabled if !is_enabled => return false,
            StatusFilter::Disabled if is_enabled => return false,
            _ => {}
        }
        // Every whitespace-separated word must appear somewhere in the row.
        let search = self.search.to_lowercase();
        search
            .split_whitespace()
            .all(|word| row.haystack.contains(word))
    }
}

/// Indices into `rows` of the rules the table shows, in display order.
/// `enabled` is the set of enabled rule names, or `None` where rules have no
/// enabled state (the read-only reference), in which case every rule counts
/// as enabled. The sort key is the chosen column (reversed when descending);
/// ties always fall back to source then name, ascending, so the order is
/// deterministic.
pub fn visible_indices(
    rows: &[RuleRow],
    enabled: Option<&BTreeSet<String>>,
    view: &ViewState,
) -> Vec<usize> {
    let is_enabled = |row: &RuleRow| enabled.is_none_or(|set| set.contains(&row.name));
    let mut indices: Vec<usize> = (0..rows.len())
        .filter(|&i| view.accepts(&rows[i], is_enabled(&rows[i])))
        .collect();
    indices.sort_by(|&a, &b| {
        let (ra, rb) = (&rows[a], &rows[b]);
        let primary = match view.sort_column {
            // Ascending puts enabled rules first: `false` (= enabled) < `true`.
            SortColumn::Enabled => (!is_enabled(ra)).cmp(&!is_enabled(rb)),
            SortColumn::Source => ra.source.cmp(&rb.source),
            SortColumn::Rule => ra.name.cmp(&rb.name),
            SortColumn::Tag => ra.tag.cmp(&rb.tag),
        };
        let primary = if view.ascending {
            primary
        } else {
            primary.reverse()
        };
        primary
            .then_with(|| ra.source.cmp(&rb.source))
            .then_with(|| ra.name.cmp(&rb.name))
    });
    indices
}

/// The search box with a **Reset filters** button. `focus_search` gives the
/// box the keyboard on the first frame and is cleared afterwards.
pub fn search_row(ui: &mut egui::Ui, view: &mut ViewState, focus_search: &mut bool) {
    ui.horizontal(|ui| {
        ui.label("Search:");
        let search = ui.add(
            egui::TextEdit::singleline(&mut view.search)
                .hint_text("name, tag, description or match text")
                .desired_width(340.0),
        );
        if *focus_search {
            search.request_focus();
            *focus_search = false;
        }
        if ui
            .add_enabled(!view.no_filter(), egui::Button::new("Reset filters"))
            .on_hover_text("Clear the search and show every source and state again")
            .clicked()
        {
            view.reset_filters();
        }
    });
}

/// The Source dropdown, in the same shape as the timeline's filter
/// dropdowns: a checkbox and a count per value, an **only** button, and a
/// **Show all** button. The counts are each source's total, regardless of
/// the other filters, and the dropdown says so.
pub fn source_dropdown(ui: &mut egui::Ui, rows: &[RuleRow], view: &mut ViewState) {
    let present: Vec<Source> = Source::ALL
        .into_iter()
        .filter(|s| rows.iter().any(|r| r.source == *s))
        .collect();
    let hidden = present
        .iter()
        .filter(|s| view.hidden_sources.contains(*s))
        .count();
    let label = if hidden == 0 {
        "Source".to_string()
    } else {
        format!("Source ({hidden} hidden)")
    };
    ui.menu_button(label, |ui| {
        ui.weak("Counts are all rules of that source, ignoring the other filters.");
        for source in &present {
            let total = rows.iter().filter(|r| r.source == *source).count();
            ui.horizontal(|ui| {
                let mut shown = !view.hidden_sources.contains(source);
                if ui.checkbox(&mut shown, source.label()).changed() {
                    view.toggle_source(*source);
                }
                ui.weak(format!("({total})"));
                if ui
                    .small_button("only")
                    .on_hover_text("Show only this source, hide every other one")
                    .clicked()
                {
                    view.solo_source(*source, &present);
                    ui.close();
                }
            });
        }
        ui.separator();
        if ui.button("Show all").clicked() {
            view.show_all_sources();
            ui.close();
        }
    });
}

/// A column header that sorts by `column` when clicked, with an arrow on the
/// column currently sorted by.
pub fn sort_header(ui: &mut egui::Ui, label: &str, column: SortColumn, view: &mut ViewState) {
    let arrow = if view.sort_column != column {
        ""
    } else if view.ascending {
        " \u{25B2}"
    } else {
        " \u{25BC}"
    };
    let button =
        egui::Button::new(egui::RichText::new(format!("{label}{arrow}")).strong()).frame(false);
    if ui
        .add(button)
        .on_hover_text("Click to sort, click again to reverse")
        .clicked()
    {
        view.toggle_sort(column);
    }
}

/// Renders a rule's `[rule.match]` table as human-readable lines, one
/// condition per line — `sourcetype` is skipped (the Source column already
/// says it), `message_contains` gets its own bulleted form for its OR-list
/// semantics, everything else is `key = value` with the value in the same
/// syntax the source TOML itself uses (via `toml::Value`'s own `Display`),
/// rather than re-deriving a presentation-only format — what's on screen
/// matches what the rule file actually says.
pub fn format_match(match_fields: &toml::Table) -> String {
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

/// Short, human-readable summary of a rule's `[rule.match]` table for a
/// hover tooltip — `sourcetype` omitted (implied by the Source column),
/// `message_contains` lists truncated to avoid a wall of text for AUL rules
/// with 20+ substrings (the full list is always in `rules/examples/*.toml`
/// and the reference dialog, this is a lookup aid, not a rule editor).
pub fn format_match_fields(match_fields: &toml::Table) -> String {
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

    /// A one-condition rule in the given pack.
    fn rule(name: &str, sourcetype: &str, tag: &str, description: &str) -> Rule {
        Rule::from_toml_str(&format!(
            "[rule]\nname = \"{name}\"\ndescription = \"{description}\"\n[rule.match]\nsourcetype = \"{sourcetype}\"\n[rule.tag]\nvalue = \"{tag}\"\n"
        ))
        .unwrap()
    }

    fn rows(rules: &[Rule]) -> Vec<RuleRow> {
        rules.iter().map(RuleRow::from_rule).collect()
    }

    fn names(rows: &[RuleRow], indices: &[usize]) -> Vec<String> {
        indices.iter().map(|&i| rows[i].name.clone()).collect()
    }

    fn sample() -> Vec<RuleRow> {
        rows(&[
            rule("evtx_logon", "evtx", "logon_success", "Successful logon"),
            rule("aul_wifi", "aul", "wifi_status", "WiFi state changes"),
            rule(
                "aul_airplane",
                "aul",
                "airplane_mode",
                "Airplane mode toggled",
            ),
            rule("journald_ssh", "journald", "ssh_logon", "SSH logon"),
        ])
    }

    fn enabled_of(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn searching(text: &str) -> ViewState {
        ViewState {
            search: text.into(),
            ..ViewState::default()
        }
    }

    /// Rule names the table lists for `view`, with no enabled set (the
    /// reference dialog's case).
    fn listed(rows: &[RuleRow], view: &ViewState) -> Vec<String> {
        names(rows, &visible_indices(rows, None, view))
    }

    #[test]
    fn source_of_a_rule_follows_its_sourcetype_and_falls_back_to_other() {
        let known = [
            ("aul", Source::Aul),
            ("evtx", Source::Evtx),
            ("journald", Source::Journald),
            ("intrusion_log", Source::IntrusionLog),
            ("biome", Source::Biome),
        ];
        for (sourcetype, expected) in known {
            assert_eq!(Source::of(&rule("r", sourcetype, "t", "d")), expected);
        }
        let no_sourcetype = Rule::from_toml_str(
            "[rule]\nname = \"generic\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert_eq!(Source::of(&no_sourcetype), Source::Other);
        assert_eq!(
            Source::of(&rule("r", "something_new", "t", "d")),
            Source::Other
        );
    }

    #[test]
    fn a_row_appends_the_version_to_its_display_name_when_present() {
        let with = Rule::from_toml_str(
            "[rule]\nname = \"aul_x\"\nversion = \"3\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"x\"\n",
        )
        .unwrap();
        let without = rule("aul_x", "aul", "x", "");
        assert_eq!(RuleRow::from_rule(&with).display_name, "aul_x (v3)");
        assert_eq!(RuleRow::from_rule(&with).name, "aul_x");
        assert_eq!(RuleRow::from_rule(&without).display_name, "aul_x");
    }

    #[test]
    fn the_default_view_lists_everything_ordered_by_source_then_name() {
        assert_eq!(
            listed(&sample(), &ViewState::default()),
            ["aul_airplane", "aul_wifi", "evtx_logon", "journald_ssh"]
        );
    }

    #[test]
    fn search_is_case_insensitive_and_needs_every_word() {
        let rows = sample();
        let found = |text: &str| listed(&rows, &searching(text));

        assert_eq!(found("AIRPLANE"), ["aul_airplane"]);
        // Two words: both must be present, in any order and any field.
        assert_eq!(found("logon success"), ["evtx_logon"]);
        assert!(found("logon nonsense").is_empty());
        // Blank / whitespace-only search shows everything.
        assert_eq!(found("   ").len(), 4);
    }

    #[test]
    fn search_looks_at_the_tag_the_source_and_every_match_needle() {
        let with_needles = Rule::from_toml_str(
            "[rule]\nname = \"aul_many\"\n[rule.match]\nsourcetype = \"aul\"\nmessage_contains = [\"a\", \"b\", \"c\", \"deeply_hidden_needle\"]\n[rule.tag]\nvalue = \"the_tag\"\n",
        )
        .unwrap();
        let rows = rows(&[with_needles]);
        let found = |search: &str| !listed(&rows, &searching(search)).is_empty();

        assert!(found("the_tag"));
        assert!(found("aul"));
        // The tooltip abbreviates to three needles; search must not.
        assert!(found("deeply_hidden_needle"));
        assert!(!found("not_anywhere"));
    }

    #[test]
    fn search_finds_a_value_inside_an_event_data_condition() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"evtx_rdp\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_id = 4624\nevent_data = { LogonType = 10 }\n[rule.tag]\nvalue = \"rdp_logon\"\n",
        )
        .unwrap();
        assert_eq!(listed(&rows(&[rule]), &searching("logontype")).len(), 1);
    }

    #[test]
    fn hiding_a_source_removes_its_rules() {
        let rows = sample();
        let mut view = ViewState::default();
        view.toggle_source(Source::Aul);
        assert_eq!(listed(&rows, &view), ["evtx_logon", "journald_ssh"]);
        view.toggle_source(Source::Aul);
        assert_eq!(listed(&rows, &view).len(), 4);
    }

    #[test]
    fn only_keeps_one_source_and_show_all_undoes_it() {
        let rows = sample();
        let present = [Source::Aul, Source::Evtx, Source::Journald];
        let mut view = ViewState::default();

        view.solo_source(Source::Evtx, &present);
        assert_eq!(listed(&rows, &view), ["evtx_logon"]);

        view.show_all_sources();
        assert!(view.hidden_sources.is_empty());
        assert_eq!(listed(&rows, &view).len(), 4);
    }

    #[test]
    fn the_status_filter_splits_enabled_from_disabled() {
        let rows = sample();
        let enabled = enabled_of(&["aul_wifi", "journald_ssh"]);
        let with_status = |status| ViewState {
            status,
            ..ViewState::default()
        };
        let listed_with = |status| {
            names(
                &rows,
                &visible_indices(&rows, Some(&enabled), &with_status(status)),
            )
        };

        assert_eq!(
            listed_with(StatusFilter::Enabled),
            ["aul_wifi", "journald_ssh"]
        );
        assert_eq!(
            listed_with(StatusFilter::Disabled),
            ["aul_airplane", "evtx_logon"]
        );
    }

    /// Without an enabled set (the reference dialog) every rule counts as
    /// enabled, so the status filter never hides anything by accident.
    #[test]
    fn without_an_enabled_set_every_rule_counts_as_enabled() {
        let rows = sample();
        let with_status = |status| ViewState {
            status,
            ..ViewState::default()
        };
        assert_eq!(listed(&rows, &with_status(StatusFilter::Enabled)).len(), 4);
        assert!(listed(&rows, &with_status(StatusFilter::Disabled)).is_empty());
    }

    #[test]
    fn filters_combine() {
        let rows = sample();
        let enabled = enabled_of(&["aul_wifi"]);
        let view = ViewState {
            search: "aul".into(),
            status: StatusFilter::Disabled,
            ..ViewState::default()
        };
        assert_eq!(
            names(&rows, &visible_indices(&rows, Some(&enabled), &view)),
            ["aul_airplane"]
        );
    }

    #[test]
    fn sorting_by_rule_and_tag_and_reversing() {
        let rows = sample();
        let mut view = ViewState::default();

        view.toggle_sort(SortColumn::Rule);
        assert_eq!(
            listed(&rows, &view),
            ["aul_airplane", "aul_wifi", "evtx_logon", "journald_ssh"]
        );
        view.toggle_sort(SortColumn::Rule); // same column again → descending
        assert!(!view.ascending);
        assert_eq!(
            listed(&rows, &view),
            ["journald_ssh", "evtx_logon", "aul_wifi", "aul_airplane"]
        );

        view.toggle_sort(SortColumn::Tag); // new column → ascending again
        assert!(view.ascending);
        // airplane_mode < logon_success < ssh_logon < wifi_status
        assert_eq!(
            listed(&rows, &view),
            ["aul_airplane", "evtx_logon", "journald_ssh", "aul_wifi"]
        );
    }

    #[test]
    fn sorting_by_the_enabled_column_puts_enabled_rules_first_when_ascending() {
        let rows = sample();
        let enabled = enabled_of(&["journald_ssh", "aul_wifi"]);
        let mut view = ViewState::default();
        view.toggle_sort(SortColumn::Enabled);

        // Enabled first; within each group source-then-name.
        assert_eq!(
            names(&rows, &visible_indices(&rows, Some(&enabled), &view)),
            ["aul_wifi", "journald_ssh", "aul_airplane", "evtx_logon"]
        );
        view.toggle_sort(SortColumn::Enabled);
        assert_eq!(
            names(&rows, &visible_indices(&rows, Some(&enabled), &view)),
            ["aul_airplane", "evtx_logon", "aul_wifi", "journald_ssh"]
        );
    }

    /// Rules with the same tag: the tie must resolve the same way every
    /// time, not by whatever order the rules happened to load in.
    #[test]
    fn ties_break_deterministically_by_source_then_name() {
        let rows = rows(&[
            rule("evtx_b", "evtx", "same", ""),
            rule("aul_z", "aul", "same", ""),
            rule("aul_a", "aul", "same", ""),
        ]);
        let mut view = ViewState::default();
        view.toggle_sort(SortColumn::Tag);
        for descending in [false, true] {
            view.ascending = !descending;
            assert_eq!(listed(&rows, &view), ["aul_a", "aul_z", "evtx_b"]);
        }
    }

    #[test]
    fn reset_filters_clears_search_sources_and_status_but_keeps_the_sort() {
        let mut view = ViewState {
            search: "x".into(),
            status: StatusFilter::Disabled,
            ..ViewState::default()
        };
        view.toggle_source(Source::Aul);
        view.toggle_sort(SortColumn::Tag);
        assert!(!view.no_filter());

        view.reset_filters();
        assert!(view.no_filter());
        assert_eq!(view.sort_column, SortColumn::Tag);
    }

    fn table(toml_text: &str) -> toml::Table {
        Rule::from_toml_str(toml_text).unwrap().rule.match_fields
    }

    #[test]
    fn format_match_skips_sourcetype_and_renders_key_value_pairs() {
        let m = table(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_id = 4625\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert_eq!(format_match(&m), "event_id = 4625");
    }

    #[test]
    fn format_match_renders_message_contains_array_as_bullets() {
        let m = table(
            "[rule]\nname = \"e\"\n[rule.match]\nmessage_contains = [\"a\", \"b\"]\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert_eq!(
            format_match(&m),
            "message contains any of:\n• \"a\"\n• \"b\""
        );
    }

    #[test]
    fn format_match_renders_a_single_message_contains_string() {
        let m = table(
            "[rule]\nname = \"e\"\n[rule.match]\nmessage_contains = \"kPhoneNumber\"\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert_eq!(format_match(&m), "message contains \"kPhoneNumber\"");
    }

    #[test]
    fn format_match_reports_sourcetype_only_rules_explicitly() {
        let m = table(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
        );
        assert_eq!(format_match(&m), "(sourcetype only)");
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

    /// The shipped RDP rule's `event_data` is an inline table; both formats
    /// must keep it on one readable line.
    #[test]
    fn an_event_data_table_renders_on_one_line_in_both_formats() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("rules/examples/evtx_4624_rdp_logon.toml"),
        )
        .unwrap();
        let match_fields = Rule::from_toml_str(&text).unwrap().rule.match_fields;

        for formatted in [
            format_match_fields(&match_fields),
            format_match(&match_fields),
        ] {
            assert!(formatted.contains("LogonType = 10"), "{formatted}");
        }
        assert!(!format_match_fields(&match_fields).contains('\n'));
    }
}
