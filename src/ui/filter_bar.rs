use std::collections::HashMap;

use eframe::egui;
use egui_extras::DatePickerButton;

use crate::db::timeline_queries::{self, COLUMN_FILTER_FIELDS, Query};
use crate::ui::colors::categorical_color;
use crate::ui::dialog_window::show_dialog_window;

/// The time-range popup's own editable state — a date, an hour/minute/
/// second, and an on/off checkbox, per bound. Unlike every other row in
/// this file, this can't be derived fresh from `self.text` each frame the
/// way `has_term`/`has_source_hidden_term` are: a [`jiff::civil::Date`]
/// widget (or a `DragValue`) needs a real, persistent value to point its
/// `&mut` at while the analyst is mid-interaction with the calendar popup,
/// not something re-parsed (and potentially fought over) every frame. It's
/// seeded once at [`FilterBar::new`] — today's date, midnight for After,
/// the last second of the day for Before (sensible defaults for "the whole
/// day", still freely adjustable) — and only ever changes from further UI
/// interaction. **Apply** is what actually writes it into the query text,
/// **Clear** resets it back to disabled.
struct TimeRangeDraft {
    after_enabled: bool,
    after_date: jiff::civil::Date,
    after_hour: u8,
    after_minute: u8,
    after_second: u8,
    before_enabled: bool,
    before_date: jiff::civil::Date,
    before_hour: u8,
    before_minute: u8,
    before_second: u8,
}

impl TimeRangeDraft {
    fn new() -> Self {
        // System-local "today" — a cosmetic starting point for the picker
        // widget, not evidence data, so this doesn't run into the
        // determinism principle that governs *parsed* timestamps: the
        // value that actually lands in the query is whatever the analyst
        // explicitly picks and confirms with **Apply**.
        let today = jiff::Zoned::now().date();
        Self {
            after_enabled: false,
            after_date: today,
            after_hour: 0,
            after_minute: 0,
            after_second: 0,
            before_enabled: false,
            before_date: today,
            before_hour: 23,
            before_minute: 59,
            before_second: 59,
        }
    }
}

/// Search box + quick level/tag-filter buttons + per-source visibility
/// chips. All three are a low-effort entry point into the same query
/// language the text box edits, rather than a second, separate filter
/// mechanism that would need reconciling with it.
///
/// Selecting several values in the Level/Tag rows is meant as "match any
/// of these" — but the search grammar has no operator precedence or
/// parentheses, so appending several bare `field=value` terms joined by
/// `OR` would silently mean
/// something else entirely as soon as any other `AND`-ed term is also
/// present (`level=ERROR tag=a OR tag=b` parses left-to-right as
/// `(level=ERROR AND tag=a) OR tag=b`, not `level=ERROR AND (tag=a OR
/// tag=b)`). Representing the whole selection as a single anchored regex
/// alternation (`field~^(?:a|b)$`) sidesteps that entirely: it's always
/// exactly one term, so it composes correctly with everything else no
/// matter what else is in the query.
///
/// The source-visibility row (see [`Self::source_visibility_row`]) is the
/// opposite shape on purpose: it's an *exclusion* list (hiding a source
/// adds a `NOT source_id=<id>` term), not an inclusion one, so it doesn't
/// need — and deliberately doesn't use — the regex-alternation trick above.
pub struct FilterBar {
    text: String,
    time_range_draft: TimeRangeDraft,
    /// Whether the Time range window ([`Self::time_range_row`]) is open —
    /// unlike every `menu_button` popup above, an `egui::Window`'s open
    /// state has to be tracked explicitly; egui doesn't manage it
    /// internally the way it does for a menu.
    time_range_open: bool,
}

impl FilterBar {
    pub fn new() -> Self {
        Self {
            text: String::new(),
            time_range_draft: TimeRangeDraft::new(),
            time_range_open: false,
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

    /// Adds or replaces the `field=value` term for one of
    /// [`COLUMN_FILTER_FIELDS`] — `pub`, unlike every other term-mutating
    /// method here, because `app.rs`'s row-context-menu dispatch
    /// (`RowAction::FilterByColumn`) needs to call it from outside this
    /// module, the way it already calls the plain `pub` [`Self::set_text`]
    /// for "Show context around this event". `field` isn't validated
    /// against [`COLUMN_FILTER_FIELDS`] here — the only caller
    /// (`timeline_view`'s "Filter by..." submenu) already only ever
    /// constructs a `RowAction::FilterByColumn` from that same list, so
    /// there's nothing to enforce redundantly.
    pub fn set_column_filter(&mut self, field: &str, value: &str) {
        self.set_single_value_term(field, Some(value));
    }

    /// `available_levels` should be `(value, display-label)` pairs for the
    /// distinct `level` values currently in the loaded data — see
    /// `TimelineView::distinct_levels` for why the label can differ from the
    /// value (a human-readable name for sourcetypes with numeric levels,
    /// e.g. EVTX's `"2"` labeled `"2 (Error)"`, while the query term stays
    /// the bare `"2"`). `available_tags` are the distinct
    /// `import_tags.tag_value`s (both queried fresh after each load/re-tag —
    /// which tags exist depends entirely on which rules were selected, so a
    /// fixed button set wouldn't fit either). `available_sources` are
    /// `(source_file_id, display-label)` pairs, one per loaded source (see
    /// `app.rs`'s call site — built from `loaded_sources` directly, no
    /// query needed).
    ///
    /// `level_counts`/`tag_counts`/`source_counts` are whole-loaded-timeline
    /// event counts (`TimelineView::tag_counts` and siblings) shown next to
    /// each value — a value missing from the map (nothing counted it yet,
    /// or the count query hasn't run) renders as `0`, not a missing/blank
    /// count, so a dropdown never shows a value with no number next to it.
    ///
    /// Returns the freshly parsed [`Query`] only on the frame something
    /// changed, so the caller re-runs the count/window queries only when
    /// there's an actual reason to.
    #[allow(clippy::too_many_arguments)]
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        available_levels: &[(String, String)],
        available_tags: &[String],
        available_sources: &[(String, String)],
        level_counts: &HashMap<String, usize>,
        tag_counts: &HashMap<String, usize>,
        source_counts: &HashMap<String, usize>,
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

        changed |= self.quick_filter_row(ui, "Level", "level", available_levels, level_counts);
        changed |= self.tag_filter_row(ui, available_tags, tag_counts);
        changed |= self.source_visibility_row(ui, available_sources, source_counts);
        changed |= self.time_range_row(ui);
        changed |= self.column_filter_chip_row(ui);

        changed.then(|| Query::parse(&self.text))
    }

    /// Shown once at the top of every dropdown popup below the counts
    /// appear in — without this, a number next to a checkbox reads by
    /// default as "how many match my current search", which is exactly
    /// what it *isn't*: see [`crate::db::timeline_queries::tag_counts`]'s
    /// doc comment for why a live, filter-relative count isn't what these
    /// are.
    const COUNTS_ARE_WHOLE_TIMELINE_CAPTION: &'static str =
        "Counts are for the whole loaded timeline, not the current filter.";

    /// Popup height cap shared by every dropdown row below — long enough to
    /// show a good handful of values without scrolling, short enough that a
    /// rule pack's worth of tags (dozens) doesn't blow the popup off the
    /// bottom of the screen. Same reasoning as the timeline's own bounded
    /// windowing: never let one filter's value list dictate how much of the
    /// screen the whole app takes up.
    const DROPDOWN_MAX_HEIGHT: f32 = 280.0;

    /// A dropdown button ("Level ▾", or "Level ▾ (2)" once something's
    /// selected) opening a scrollable checkbox list — one row per
    /// `(value, display-label)` pair, all selected values of the same field
    /// combined via a single `field~^(?:...)$` term (see the struct docs
    /// for why not several `field=value OR ...` terms). A dropdown rather
    /// than a row of always-visible buttons: an inclusion list can have as
    /// many values as the loaded data does (AUL's built-in rule pack alone
    /// is 33 tags), and a row of buttons for all of them would push the
    /// timeline further down the screen with every new value, with no
    /// bound.
    fn quick_filter_row(
        &mut self,
        ui: &mut egui::Ui,
        label: &str,
        field: &str,
        values: &[(String, String)],
        counts: &HashMap<String, usize>,
    ) -> bool {
        if values.is_empty() {
            return false;
        }
        let mut changed = false;
        let selected = self.term_values(field);
        let button_label = if selected.is_empty() {
            label.to_string()
        } else {
            format!("{label} ({})", selected.len())
        };
        ui.menu_button(button_label, |ui| {
            ui.weak(Self::COUNTS_ARE_WHOLE_TIMELINE_CAPTION);
            egui::ScrollArea::vertical()
                .max_height(Self::DROPDOWN_MAX_HEIGHT)
                .show(ui, |ui| {
                    for (value, display) in values {
                        let count = counts.get(value).copied().unwrap_or(0);
                        ui.horizontal(|ui| {
                            let mut active = self.has_term(field, value);
                            if ui.checkbox(&mut active, display.as_str()).changed() {
                                self.toggle_term(field, value);
                                changed = true;
                            }
                            ui.weak(format!("({count})"));
                            if ui
                                .small_button("only")
                                .on_hover_text(
                                    "Select only this value, deselecting every other one",
                                )
                                .clicked()
                            {
                                self.set_term_values(field, std::slice::from_ref(value));
                                changed = true;
                                ui.close();
                            }
                        });
                    }
                });
            // Outside the `ScrollArea`, same reasoning as the Sources
            // dropdown's own "Show all": with enough values to need
            // scrolling, a reset action buried at the bottom of the
            // scrolled content would need scrolling all the way down to
            // reach — most needed exactly when there's a lot to reset.
            ui.separator();
            if ui.button("Show all").clicked() {
                self.set_term_values(field, &[]);
                changed = true;
                ui.close();
            }
        });
        changed
    }

    /// Same dropdown shape as [`Self::quick_filter_row`] for `tag`, plus an
    /// "Untagged" checkbox for `NOT tag=*` — entries with no tag at all,
    /// which the per-value checkboxes can't express since they only ever
    /// add positive `tag=...`/`tag~...` conditions. "Untagged" gets no
    /// count next to it: that would need its own
    /// `COUNT(*) WHERE NOT EXISTS (...)` query, which nothing here computes
    /// yet — better no number than a wrong or made-up one.
    fn tag_filter_row(
        &mut self,
        ui: &mut egui::Ui,
        available_tags: &[String],
        counts: &HashMap<String, usize>,
    ) -> bool {
        if available_tags.is_empty() {
            return false;
        }
        let mut changed = false;
        let selected_count = self.term_values("tag").len() + usize::from(self.has_untagged_term());
        let button_label = if selected_count == 0 {
            "Tag".to_string()
        } else {
            format!("Tag ({selected_count})")
        };
        ui.menu_button(button_label, |ui| {
            ui.weak(Self::COUNTS_ARE_WHOLE_TIMELINE_CAPTION);
            egui::ScrollArea::vertical()
                .max_height(Self::DROPDOWN_MAX_HEIGHT)
                .show(ui, |ui| {
                    for value in available_tags {
                        let count = counts.get(value).copied().unwrap_or(0);
                        ui.horizontal(|ui| {
                            let mut active = self.has_term("tag", value);
                            if ui.checkbox(&mut active, value.as_str()).changed() {
                                self.toggle_term("tag", value);
                                changed = true;
                            }
                            ui.weak(format!("({count})"));
                            if ui
                                .small_button("only")
                                .on_hover_text(
                                    "Select only this tag, deselecting every other tag and Untagged",
                                )
                                .clicked()
                            {
                                self.set_tag_block(std::slice::from_ref(value), false);
                                changed = true;
                                ui.close();
                            }
                        });
                    }
                    ui.separator();
                    let mut untagged_active = self.has_untagged_term();
                    if ui
                        .checkbox(&mut untagged_active, "Untagged")
                        .on_hover_text("Entries with no tag at all (NOT tag=*)")
                        .changed()
                    {
                        self.toggle_untagged_term();
                        changed = true;
                    }
                });
            // Outside the `ScrollArea`, same reasoning as Level/Sources —
            // clears both the tag selection and Untagged in one go.
            ui.separator();
            if ui.button("Show all").clicked() {
                self.set_tag_block(&[], false);
                changed = true;
                ui.close();
            }
        });
        changed
    }

    /// A dropdown button ("Sources ▾", or "Sources ▾ (2 hidden)" once
    /// something's hidden) opening a scrollable checklist — one row per
    /// loaded source, checked/highlighted means "visible" (the default, no
    /// filter term at all), unchecking one adds a `NOT source_id=<id>` term
    /// to hide just that source's rows without unloading it. Each source's
    /// label is coloured via [`categorical_color`] hashed from its
    /// `source_file_id`, matching how the Level/Tags timeline columns are
    /// coloured — stable across sessions, not assignment-order-based.
    ///
    /// Every row also gets a small **only** button — [`Self::solo_source`],
    /// "show just this one, hide every other loaded source" — a common
    /// enough need (isolate one source's timeline) that requiring N-1
    /// individual unchecks to get there would be its own usability problem,
    /// and a **Show all** button to undo any solo/manual hiding in one
    /// click.
    ///
    /// Unlike [`Self::tag_filter_row`], there's no combined-OR block to
    /// maintain: hiding several sources is "not A and not B", which the
    /// grammar's ordinary left-to-right `AND` fold already produces
    /// correctly from independent `NOT` terms in any position — see the
    /// struct docs.
    fn source_visibility_row(
        &mut self,
        ui: &mut egui::Ui,
        sources: &[(String, String)],
        counts: &HashMap<String, usize>,
    ) -> bool {
        if sources.is_empty() {
            return false;
        }
        let mut changed = false;
        let hidden_count = sources
            .iter()
            .filter(|(id, _)| self.has_source_hidden_term(id))
            .count();
        let button_label = if hidden_count == 0 {
            "Sources".to_string()
        } else {
            format!("Sources ({hidden_count} hidden)")
        };
        let dark_mode = ui.visuals().dark_mode;
        ui.menu_button(button_label, |ui| {
            ui.weak(Self::COUNTS_ARE_WHOLE_TIMELINE_CAPTION);
            egui::ScrollArea::vertical()
                .max_height(Self::DROPDOWN_MAX_HEIGHT)
                .show(ui, |ui| {
                    for (id, label) in sources {
                        let count = counts.get(id).copied().unwrap_or(0);
                        ui.horizontal(|ui| {
                            let mut visible = !self.has_source_hidden_term(id);
                            let color = categorical_color(id, dark_mode);
                            if ui
                                .checkbox(&mut visible, egui::RichText::new(label).color(color))
                                .changed()
                            {
                                self.toggle_source_hidden_term(id);
                                changed = true;
                            }
                            ui.weak(format!("({count})"));
                            if ui
                                .small_button("only")
                                .on_hover_text("Show only this source, hide every other one")
                                .clicked()
                            {
                                self.solo_source(id, sources);
                                changed = true;
                                ui.close();
                            }
                        });
                    }
                });
            // Outside the `ScrollArea`, not the last item inside it: with
            // enough loaded sources to actually need scrolling, "Show all"
            // being part of the scrolled content would mean scrolling all
            // the way down just to reach the one button that's most useful
            // exactly when there are many sources to reset at once.
            ui.separator();
            if ui.button("Show all").clicked() {
                self.show_all_sources(sources);
                changed = true;
                ui.close();
            }
        });
        changed
    }

    /// A dropdown button ("Time range ▾", or "Time range ▾ (2)" once both
    /// bounds are set) for picking `after=`/`before=` via a calendar
    /// instead of typing an ISO timestamp by hand. Deliberately date-only,
    /// not a full date-*and*-time picker: `after=`/`before=` already accept
    /// hand-typed time-of-day precision for when that's actually needed,
    /// and minute-level narrowing already has its own dedicated path — the
    /// row context menu's "Show context around this event" (± 1/5/15/60
    /// min). A calendar's natural grain is a day, so that's what this
    /// covers.
    ///
    /// Date *and* time-of-day, via three `DragValue` spinners next to the
    /// calendar — click-drag or click-to-type, same as any other egui
    /// numeric field, no extra widget/dependency needed beyond what
    /// `egui`/`egui_extras` already provide. Both bounds always write the
    /// full `<date>T<hour>:<minute>:<second>` form, never a bare date: a
    /// bare date means literal midnight (see `parse_query_timestamp`'s
    /// documented handling), which as a *before* bound would silently
    /// exclude the rest of the picked day if the analyst hadn't explicitly
    /// dialed the time forward — writing the explicit, currently-set
    /// hour/minute/second sidesteps that regardless of what the analyst
    /// has adjusted them to. Defaults to midnight for After and the last
    /// second of the day for Before ("the whole day", the common case),
    /// freely adjustable from there.
    ///
    /// Unlike every checkbox-list dropdown above, this doesn't have a
    /// "Show all"/**only** pair in the same shape — there's no discrete
    /// value list to pick one of or reset to "every value". **Clear**
    /// plays the equivalent "back to unfiltered" role instead.
    ///
    /// A real, separate OS window ([`show_dialog_window`]), like every
    /// dialog in this app — originally a plain `egui::Window` here
    /// specifically, before that became the shared default: nesting
    /// [`DatePickerButton`] (it opens its *own* independent floating
    /// `Area`, with its own "close on click elsewhere" logic, no
    /// awareness of whatever popup it's nested inside) inside a
    /// `menu_button` popup like every other row here made the *outer*
    /// popup read a click on the calendar as "clicked outside me" and
    /// close before a date could ever be picked — confirmed by reading
    /// `DatePickerButton`'s implementation after a real "it disappears the
    /// moment I try to click it" report. A real OS window doesn't have
    /// that auto-close-on-outside-click behavior to conflict with the
    /// nested `Area` in the first place.
    fn time_range_row(&mut self, ui: &mut egui::Ui) -> bool {
        let mut changed = false;
        let active_count = usize::from(self.bound_term_value("after").is_some())
            + usize::from(self.bound_term_value("before").is_some());
        let button_label = if active_count == 0 {
            "Time range".to_string()
        } else {
            format!("Time range ({active_count})")
        };
        if ui.button(button_label).clicked() {
            self.time_range_open = true;
        }

        let mut apply_clicked = false;
        let mut clear_clicked = false;
        if self.time_range_open {
            let draft = &mut self.time_range_draft;
            let ctx = ui.ctx().clone();
            let should_close = show_dialog_window(
                &ctx,
                "peach_time_range_window",
                "Time range",
                [360.0, 170.0],
                false,
                |ui, close| {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut draft.after_enabled, "After");
                        ui.add_enabled(
                            draft.after_enabled,
                            DatePickerButton::new(&mut draft.after_date)
                                .id_salt("filter_bar_after_date"),
                        );
                        Self::time_of_day_spinners(
                            ui,
                            draft.after_enabled,
                            &mut draft.after_hour,
                            &mut draft.after_minute,
                            &mut draft.after_second,
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut draft.before_enabled, "Before");
                        ui.add_enabled(
                            draft.before_enabled,
                            DatePickerButton::new(&mut draft.before_date)
                                .id_salt("filter_bar_before_date"),
                        );
                        Self::time_of_day_spinners(
                            ui,
                            draft.before_enabled,
                            &mut draft.before_hour,
                            &mut draft.before_minute,
                            &mut draft.before_second,
                        );
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Apply").clicked() {
                            apply_clicked = true;
                            *close = true;
                        }
                        if ui.button("Clear").clicked() {
                            clear_clicked = true;
                            *close = true;
                        }
                    });
                },
            );
            // Same reasoning as every other `set_bound_term`/`solo_source`
            // caller in this file: `draft` (borrowing `self.time_range_draft`)
            // must go out of scope before any `&mut self` method call below —
            // Rust can't see that those only touch *other* fields. Its last
            // use is inside `show_dialog_window` above, so a plain field
            // write here (not a method call) is still fine.
            if should_close {
                self.time_range_open = false;
            }
        }

        if apply_clicked {
            // Both values computed from `draft` before any `self.set_bound_term`
            // call — that takes `&mut self`, which can't overlap with `draft`
            // (an immutable borrow of one of `self`'s fields) still being alive
            // for a later use.
            let draft = &self.time_range_draft;
            let after = draft.after_enabled.then(|| {
                Self::format_bound(
                    draft.after_date,
                    draft.after_hour,
                    draft.after_minute,
                    draft.after_second,
                )
            });
            let before = draft.before_enabled.then(|| {
                Self::format_bound(
                    draft.before_date,
                    draft.before_hour,
                    draft.before_minute,
                    draft.before_second,
                )
            });
            self.set_bound_term("after", after.as_deref());
            self.set_bound_term("before", before.as_deref());
            self.time_range_open = false;
            changed = true;
        }
        if clear_clicked {
            self.time_range_draft.after_enabled = false;
            self.time_range_draft.before_enabled = false;
            self.set_bound_term("after", None);
            self.set_bound_term("before", None);
            self.time_range_open = false;
            changed = true;
        }
        changed
    }

    /// Three zero-padded `DragValue` spinners (H : M : S) for
    /// [`Self::time_range_row`] — click-drag or click-to-type, same as any
    /// other egui numeric field. `enabled` mirrors the calendar button
    /// right next to these: greyed out and non-interactive while that
    /// bound's checkbox is off, same as the date picker.
    fn time_of_day_spinners(
        ui: &mut egui::Ui,
        enabled: bool,
        hour: &mut u8,
        minute: &mut u8,
        second: &mut u8,
    ) {
        ui.add_enabled(
            enabled,
            egui::DragValue::new(hour)
                .range(0..=23)
                .custom_formatter(|n, _| format!("{n:02.0}")),
        );
        ui.label(":");
        ui.add_enabled(
            enabled,
            egui::DragValue::new(minute)
                .range(0..=59)
                .custom_formatter(|n, _| format!("{n:02.0}")),
        );
        ui.label(":");
        ui.add_enabled(
            enabled,
            egui::DragValue::new(second)
                .range(0..=59)
                .custom_formatter(|n, _| format!("{n:02.0}")),
        );
    }

    /// Renders one bound's full value for the query text — always the
    /// explicit `<date>T<hour>:<minute>:<second>` form, never a bare date
    /// (see [`Self::time_range_row`]'s doc comment for why).
    fn format_bound(date: jiff::civil::Date, hour: u8, minute: u8, second: u8) -> String {
        format!("{date}T{hour:02}:{minute:02}:{second:02}")
    }

    /// The current value of a single-value `field=value` term (`after=`/
    /// `before=` — never repeated, unlike Level/Tag's multi-value
    /// alternation), if present.
    fn bound_term_value(&self, field: &str) -> Option<String> {
        let prefix = format!("{field}=");
        self.text
            .split_whitespace()
            .find(|t| t.starts_with(&prefix))
            .map(|t| t[prefix.len()..].to_string())
    }

    /// Adds, replaces, or removes (`value: None`) a single-value
    /// `field=value` term in place, leaving every other token untouched —
    /// same idea as [`Self::set_term_values`], simpler since there's only
    /// ever at most one value, never an alternation to build.
    fn set_bound_term(&mut self, field: &str, value: Option<&str>) {
        let prefix = format!("{field}=");
        let tokens: Vec<&str> = self.text.split_whitespace().collect();
        let existing_idx = tokens.iter().position(|t| t.starts_with(&prefix));

        let mut rebuilt: Vec<String> = tokens.iter().map(|t| t.to_string()).collect();
        match (existing_idx, value) {
            (Some(idx), Some(v)) => rebuilt[idx] = format!("{field}={v}"),
            (Some(idx), None) => {
                rebuilt.remove(idx);
            }
            (None, Some(v)) => rebuilt.push(format!("{field}={v}")),
            (None, None) => {}
        }
        self.text = rebuilt.join(" ");
    }

    /// "Active filters:" chip row — one removable chip per currently-set
    /// [`COLUMN_FILTER_FIELDS`] term (Sourcetype/Host/Process/Event ID/
    /// Subsystem/Category), populated via the row context menu's "Filter
    /// by..." submenu (`ui::timeline_view::RowAction::FilterByColumn`).
    /// Only shown once at least one is actually active — an empty "Active
    /// filters:" label with nothing after it would just be noise.
    fn column_filter_chip_row(&mut self, ui: &mut egui::Ui) -> bool {
        let active = self.column_filter_terms();
        if active.is_empty() {
            return false;
        }
        let mut changed = false;
        ui.horizontal_wrapped(|ui| {
            ui.label("Active filters:");
            for (field, label, value) in &active {
                if ui
                    .small_button(format!("{label} = {value} ✕"))
                    .on_hover_text(format!("Remove this filter ({field}={value})"))
                    .clicked()
                {
                    self.set_single_value_term(field, None);
                    changed = true;
                }
            }
            if active.len() > 1 && ui.button("Clear all").clicked() {
                for (field, _, _) in &active {
                    self.set_single_value_term(field, None);
                }
                changed = true;
            }
        });
        changed
    }

    /// Every currently-set [`COLUMN_FILTER_FIELDS`] term as
    /// `(field, label, value)` triples, for [`Self::column_filter_chip_row`].
    /// Scans via the real [`timeline_queries::tokenize`], not
    /// `str::split_whitespace` like every other `*_term`/`*_value` helper
    /// in this file — these values (a process name, a hostname) routinely
    /// contain whitespace where Level/Tag values, `source_id` UUIDs, and
    /// ISO dates never do, so a naive whitespace split would see a quoted
    /// `host="My Host"` term as two separate (and wrong) tokens.
    fn column_filter_terms(&self) -> Vec<(&'static str, &'static str, String)> {
        let tokens = timeline_queries::tokenize(&self.text);
        COLUMN_FILTER_FIELDS
            .iter()
            .filter_map(|&(field, label)| {
                let prefix = format!("{field}=");
                tokens
                    .iter()
                    .find(|t| t.starts_with(&prefix))
                    .map(|t| (field, label, t[prefix.len()..].to_string()))
            })
            .collect()
    }

    /// Adds, replaces, or removes (`value: None`) a single `field=value`
    /// term for one of [`COLUMN_FILTER_FIELDS`] — the private worker behind
    /// [`Self::set_column_filter`] and the chip row's remove buttons.
    /// Rebuilds the *whole* query text through the real
    /// [`timeline_queries::tokenize`] rather than splicing into a
    /// `split_whitespace` token list like [`Self::set_bound_term`] does,
    /// because these values need quote-awareness (see
    /// [`Self::column_filter_terms`]). Rebuilding through the real
    /// tokenizer and re-quoting *every* token that needs it (not just this
    /// field's) is what keeps this safe for the rest of the query text
    /// too: a hand-typed quoted phrase elsewhere round-trips losslessly
    /// through this — `tokenize` strips its quotes, requoting puts them
    /// back, since the only thing this grammar's quoting ever protects is
    /// internal whitespace, and that's exactly what
    /// [`Self::quote_token_if_needed`] checks for.
    fn set_single_value_term(&mut self, field: &str, value: Option<&str>) {
        let prefix = format!("{field}=");
        let tokens = timeline_queries::tokenize(&self.text);
        let existing_idx = tokens.iter().position(|t| t.starts_with(&prefix));

        let mut rebuilt = tokens;
        match (existing_idx, value) {
            (Some(idx), Some(v)) => rebuilt[idx] = format!("{field}={v}"),
            (Some(idx), None) => {
                rebuilt.remove(idx);
            }
            (None, Some(v)) => rebuilt.push(format!("{field}={v}")),
            (None, None) => {}
        }

        self.text = rebuilt
            .iter()
            .map(|t| Self::quote_token_if_needed(t))
            .collect::<Vec<_>>()
            .join(" ");
    }

    /// Wraps `token` in `"..."` if it contains whitespace — the only case
    /// [`timeline_queries::tokenize`] needs quoting for at all (its only
    /// two special characters are `"`, which toggles quoting, and
    /// whitespace, which splits tokens unless quoted). A `"` inside the
    /// value itself can't be represented by this grammar's quoting (no
    /// escape mechanism) and is left as-is — a known, narrow limitation
    /// shared with the rest of this module's `"`-based quoting, not
    /// something introduced here.
    fn quote_token_if_needed(token: &str) -> String {
        if token.chars().any(char::is_whitespace) {
            format!("\"{token}\"")
        } else {
            token.to_string()
        }
    }

    /// Hides every loaded source except `id` — "solo" it. Implemented as
    /// per-source toggles against the current state rather than rebuilding
    /// the hidden-set from scratch, so it composes with
    /// [`Self::toggle_source_hidden_term`]/[`Self::has_source_hidden_term`]
    /// through the exact same term shape instead of a parallel code path.
    fn solo_source(&mut self, id: &str, all_sources: &[(String, String)]) {
        for (other_id, _) in all_sources {
            let should_be_hidden = other_id != id;
            if self.has_source_hidden_term(other_id) != should_be_hidden {
                self.toggle_source_hidden_term(other_id);
            }
        }
    }

    /// Clears every hidden-source term — shows every loaded source again.
    fn show_all_sources(&mut self, all_sources: &[(String, String)]) {
        for (id, _) in all_sources {
            if self.has_source_hidden_term(id) {
                self.toggle_source_hidden_term(id);
            }
        }
    }

    /// The exact `NOT`-prefixed token pair a hidden source's term is
    /// written as — same two-token shape as the Tag row's fixed
    /// `NOT tag=*` ([`Self::UNTAGGED_TERM`]), just parameterized per
    /// source instead of a single constant, since any number of sources
    /// can be independently hidden at once.
    fn source_hidden_token(id: &str) -> String {
        format!("source_id={id}")
    }

    fn has_source_hidden_term(&self, id: &str) -> bool {
        let target = Self::source_hidden_token(id);
        let tokens: Vec<&str> = self.text.split_whitespace().collect();
        tokens
            .windows(2)
            .any(|w| w[0].eq_ignore_ascii_case("NOT") && w[1] == target)
    }

    /// Adds or removes exactly this source's `NOT source_id=<id>` term,
    /// leaving every other term — including any *other* hidden source's
    /// term — untouched. `source_file_id` is a UUID (see
    /// [`crate::model::event_id::SourceFileId`]), so it never contains
    /// whitespace and needs no quoting the way a raw path would, unlike
    /// [`Field::SourceFile`](crate::db::timeline_queries::Field::SourceFile).
    fn toggle_source_hidden_term(&mut self, id: &str) {
        let target = Self::source_hidden_token(id);
        let tokens: Vec<&str> = self.text.split_whitespace().collect();
        let existing = tokens
            .windows(2)
            .position(|w| w[0].eq_ignore_ascii_case("NOT") && w[1] == target);

        let mut rebuilt: Vec<String> = tokens.iter().map(|t| t.to_string()).collect();
        match existing {
            Some(idx) => {
                rebuilt.drain(idx..idx + 2);
            }
            None => {
                rebuilt.push("NOT".to_string());
                rebuilt.push(target);
            }
        }
        self.text = rebuilt.join(" ");
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

    /// The Level/Tag dropdowns' "Show all" button calls `set_term_values`/
    /// `set_tag_block` directly with an empty selection — not N individual
    /// `toggle_term` calls — so these exercise that exact call shape rather
    /// than relying on the toggle tests above to stand in for it.
    #[test]
    fn show_all_for_a_quick_filter_field_clears_the_whole_selection_at_once() {
        let mut bar = FilterBar::new();
        bar.toggle_term("level", "ERROR");
        bar.toggle_term("level", "WARN");
        bar.toggle_term("level", "INFO");

        bar.set_term_values("level", &[]);

        assert_eq!(bar.text(), "");
        assert!(!bar.has_term("level", "ERROR"));
        assert!(!bar.has_term("level", "WARN"));
        assert!(!bar.has_term("level", "INFO"));
    }

    /// The "only" button next to each Level/Tag value calls
    /// `set_term_values`/`set_tag_block` with a single-element slice — same
    /// underlying mechanism as "Show all" (an empty one), just narrowed to
    /// exactly one value instead of none, and available on every dropdown
    /// for the same reason "Show all" is: consistent actions across
    /// Level/Tag/Sources, not something Sources alone gets.
    #[test]
    fn only_for_a_quick_filter_field_selects_just_that_value() {
        let mut bar = FilterBar::new();
        bar.toggle_term("level", "ERROR");
        bar.toggle_term("level", "WARN");
        bar.toggle_term("level", "INFO");

        bar.set_term_values("level", &["WARN".to_string()]);

        assert_eq!(bar.text(), "level~^(?:WARN)$");
        assert!(!bar.has_term("level", "ERROR"));
        assert!(bar.has_term("level", "WARN"));
        assert!(!bar.has_term("level", "INFO"));
    }

    #[test]
    fn only_for_tag_selects_just_that_tag_and_clears_untagged() {
        let mut bar = FilterBar::new();
        bar.toggle_term("tag", "wifi_status");
        bar.toggle_term("tag", "screen_lock_state");
        bar.toggle_untagged_term();

        bar.set_tag_block(&["wifi_status".to_string()], false);

        assert_eq!(bar.text(), "tag~^(?:wifi_status)$");
        assert!(bar.has_term("tag", "wifi_status"));
        assert!(!bar.has_term("tag", "screen_lock_state"));
        assert!(!bar.has_untagged_term());
    }

    #[test]
    fn format_bound_writes_the_full_t_separated_form_zero_padded() {
        let date = jiff::civil::Date::new(2026, 7, 29).unwrap();

        assert_eq!(
            FilterBar::format_bound(date, 0, 0, 0),
            "2026-07-29T00:00:00"
        );
        assert_eq!(
            FilterBar::format_bound(date, 9, 5, 3),
            "2026-07-29T09:05:03"
        );
        assert_eq!(
            FilterBar::format_bound(date, 23, 59, 59),
            "2026-07-29T23:59:59"
        );
    }

    #[test]
    fn set_bound_term_adds_replaces_and_removes_a_single_value_term() {
        let mut bar = FilterBar::new();
        assert_eq!(bar.bound_term_value("after"), None);

        bar.set_bound_term("after", Some("2026-07-29"));
        assert_eq!(bar.text(), "after=2026-07-29");
        assert_eq!(
            bar.bound_term_value("after"),
            Some("2026-07-29".to_string())
        );

        // Replacing an existing value doesn't duplicate the term.
        bar.set_bound_term("after", Some("2026-08-01"));
        assert_eq!(bar.text(), "after=2026-08-01");

        bar.set_bound_term("after", None);
        assert_eq!(bar.text(), "");
        assert_eq!(bar.bound_term_value("after"), None);
    }

    #[test]
    fn after_and_before_bound_terms_are_independent() {
        let mut bar = FilterBar::new();
        bar.set_bound_term("after", Some("2026-07-29"));
        bar.set_bound_term("before", Some("2026-07-31T23:59:59"));

        assert!(bar.text().contains("after=2026-07-29"));
        assert!(bar.text().contains("before=2026-07-31T23:59:59"));

        bar.set_bound_term("after", None);
        assert_eq!(bar.bound_term_value("after"), None);
        assert_eq!(
            bar.bound_term_value("before"),
            Some("2026-07-31T23:59:59".to_string())
        );
    }

    #[test]
    fn set_bound_term_leaves_other_fields_alone() {
        let mut bar = FilterBar::new();
        bar.toggle_term("level", "ERROR");

        bar.set_bound_term("after", Some("2026-07-29"));

        assert!(bar.text().contains("level~^(?:ERROR)$"));
        assert!(bar.text().contains("after=2026-07-29"));
    }

    #[test]
    fn quote_token_if_needed_only_quotes_tokens_with_whitespace() {
        assert_eq!(
            FilterBar::quote_token_if_needed("process=svchost.exe"),
            "process=svchost.exe"
        );
        assert_eq!(
            FilterBar::quote_token_if_needed("process=Windows Explorer"),
            "\"process=Windows Explorer\""
        );
    }

    #[test]
    fn set_column_filter_adds_a_term_without_quoting_when_the_value_has_no_spaces() {
        let mut bar = FilterBar::new();

        bar.set_column_filter("host", "DESKTOP-ABC123");

        assert_eq!(bar.text(), "host=DESKTOP-ABC123");
        assert_eq!(
            bar.column_filter_terms(),
            vec![("host", "Host", "DESKTOP-ABC123".to_string())]
        );
    }

    #[test]
    fn set_column_filter_quotes_a_value_containing_spaces() {
        let mut bar = FilterBar::new();

        bar.set_column_filter("process", "Windows Explorer");

        assert_eq!(bar.text(), "\"process=Windows Explorer\"");
        // Round-trips correctly through the real query grammar too, not
        // just this module's own scanning — the whole point of quoting.
        let query = Query::parse(bar.text());
        assert_eq!(query.terms.len(), 1);
        assert_eq!(
            bar.column_filter_terms(),
            vec![("process", "Process", "Windows Explorer".to_string())]
        );
    }

    #[test]
    fn set_column_filter_replaces_rather_than_duplicates() {
        let mut bar = FilterBar::new();
        bar.set_column_filter("host", "old-host");

        bar.set_column_filter("host", "new-host");

        assert_eq!(bar.text(), "host=new-host");
    }

    #[test]
    fn set_column_filter_none_removes_the_term() {
        let mut bar = FilterBar::new();
        bar.set_column_filter("host", "some-host");

        bar.set_single_value_term("host", None);

        assert_eq!(bar.text(), "");
        assert!(bar.column_filter_terms().is_empty());
    }

    #[test]
    fn multiple_column_filters_stay_independent() {
        let mut bar = FilterBar::new();
        bar.set_column_filter("host", "DESKTOP-1");
        bar.set_column_filter("process", "explorer.exe");
        bar.set_column_filter("subsystem", "com.apple.foo");

        let mut terms = bar.column_filter_terms();
        terms.sort();
        assert_eq!(
            terms,
            vec![
                ("host", "Host", "DESKTOP-1".to_string()),
                ("process", "Process", "explorer.exe".to_string()),
                ("subsystem", "Subsystem", "com.apple.foo".to_string()),
            ]
        );

        // Removing one leaves the others untouched.
        bar.set_single_value_term("process", None);
        let mut remaining = bar.column_filter_terms();
        remaining.sort();
        assert_eq!(
            remaining,
            vec![
                ("host", "Host", "DESKTOP-1".to_string()),
                ("subsystem", "Subsystem", "com.apple.foo".to_string()),
            ]
        );
    }

    #[test]
    fn column_filter_survives_alongside_a_quoted_free_text_phrase() {
        // Regression guard for the rebuild-through-tokenize approach:
        // set_single_value_term rebuilds the *whole* text, so an unrelated
        // hand-typed quoted phrase elsewhere must still round-trip losslessly.
        let mut bar = FilterBar::new();
        bar.set_text("\"login failed\"".to_string());

        bar.set_column_filter("host", "DESKTOP-1");

        assert!(bar.text().contains("host=DESKTOP-1"));
        let query = Query::parse(bar.text());
        assert_eq!(query.terms.len(), 2);
    }

    #[test]
    fn show_all_for_tag_clears_values_and_untagged_together() {
        let mut bar = FilterBar::new();
        bar.toggle_term("tag", "wifi_status");
        bar.toggle_term("tag", "screen_lock_state");
        bar.toggle_untagged_term();

        bar.set_tag_block(&[], false);

        assert_eq!(bar.text(), "");
        assert!(!bar.has_term("tag", "wifi_status"));
        assert!(!bar.has_term("tag", "screen_lock_state"));
        assert!(!bar.has_untagged_term());
    }

    #[test]
    fn show_all_for_tag_leaves_other_fields_alone() {
        let mut bar = FilterBar::new();
        bar.toggle_term("level", "ERROR");
        bar.toggle_term("tag", "wifi_status");

        bar.set_tag_block(&[], false);

        assert_eq!(bar.text(), "level~^(?:ERROR)$");
    }

    #[test]
    fn hiding_a_source_writes_a_not_source_id_term() {
        let mut bar = FilterBar::new();
        assert!(!bar.has_source_hidden_term("abc-123"));

        bar.toggle_source_hidden_term("abc-123");

        assert_eq!(bar.text(), "NOT source_id=abc-123");
        assert!(bar.has_source_hidden_term("abc-123"));
    }

    #[test]
    fn showing_a_hidden_source_again_removes_its_term() {
        let mut bar = FilterBar::new();
        bar.toggle_source_hidden_term("abc-123");

        bar.toggle_source_hidden_term("abc-123");

        assert_eq!(bar.text(), "");
        assert!(!bar.has_source_hidden_term("abc-123"));
    }

    #[test]
    fn hiding_two_sources_produces_two_independent_not_terms() {
        let mut bar = FilterBar::new();
        bar.toggle_source_hidden_term("aaa");
        bar.toggle_source_hidden_term("bbb");

        assert_eq!(bar.text(), "NOT source_id=aaa NOT source_id=bbb");
        assert!(bar.has_source_hidden_term("aaa"));
        assert!(bar.has_source_hidden_term("bbb"));

        // Showing one again leaves the other untouched.
        bar.toggle_source_hidden_term("aaa");
        assert_eq!(bar.text(), "NOT source_id=bbb");
        assert!(!bar.has_source_hidden_term("aaa"));
        assert!(bar.has_source_hidden_term("bbb"));
    }

    #[test]
    fn hiding_a_source_does_not_disturb_other_terms() {
        let mut bar = FilterBar::new();
        bar.toggle_term("level", "ERROR");

        bar.toggle_source_hidden_term("abc-123");

        assert!(bar.text().contains("level~^(?:ERROR)$"));
        assert!(bar.text().contains("NOT source_id=abc-123"));
    }

    fn three_sources() -> Vec<(String, String)> {
        vec![
            ("aaa".to_string(), "a.evtx".to_string()),
            ("bbb".to_string(), "b.evtx".to_string()),
            ("ccc".to_string(), "c.evtx".to_string()),
        ]
    }

    #[test]
    fn soloing_a_source_hides_every_other_loaded_source() {
        let mut bar = FilterBar::new();
        let sources = three_sources();

        bar.solo_source("bbb", &sources);

        assert!(!bar.has_source_hidden_term("bbb"));
        assert!(bar.has_source_hidden_term("aaa"));
        assert!(bar.has_source_hidden_term("ccc"));
    }

    #[test]
    fn soloing_a_source_that_already_has_some_hidden_only_changes_what_needs_to_change() {
        let mut bar = FilterBar::new();
        let sources = three_sources();
        bar.toggle_source_hidden_term("ccc"); // pre-existing, unrelated hide

        bar.solo_source("aaa", &sources);

        assert!(!bar.has_source_hidden_term("aaa"));
        assert!(bar.has_source_hidden_term("bbb"));
        assert!(bar.has_source_hidden_term("ccc"));
        // Exactly two NOT terms, not a stray duplicate from toggling "ccc"
        // off and back on again.
        assert_eq!(
            bar.text().matches("NOT source_id=").count(),
            2,
            "text was: {:?}",
            bar.text()
        );
    }

    #[test]
    fn soloing_again_on_an_already_soloed_source_is_a_no_op() {
        let mut bar = FilterBar::new();
        let sources = three_sources();
        bar.solo_source("bbb", &sources);
        let after_first_solo = bar.text().to_string();

        bar.solo_source("bbb", &sources);

        assert_eq!(bar.text(), after_first_solo);
    }

    #[test]
    fn show_all_sources_clears_every_hidden_term() {
        let mut bar = FilterBar::new();
        let sources = three_sources();
        bar.solo_source("bbb", &sources);

        bar.show_all_sources(&sources);

        assert_eq!(bar.text(), "");
        for (id, _) in &sources {
            assert!(!bar.has_source_hidden_term(id));
        }
    }

    #[test]
    fn show_all_sources_leaves_unrelated_terms_alone() {
        let mut bar = FilterBar::new();
        let sources = three_sources();
        bar.toggle_term("level", "ERROR");
        bar.solo_source("bbb", &sources);

        bar.show_all_sources(&sources);

        assert_eq!(bar.text(), "level~^(?:ERROR)$");
    }
}
