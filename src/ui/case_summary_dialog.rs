//! "Case Summary" dialog (`View > Case Summary...`) — an at-a-glance
//! breakdown of a loaded case: total events, per-source/per-sourcetype/
//! per-level counts, tag coverage, and the covered time range including a
//! daily-activity histogram.
//!
//! The same [`crate::db::timeline_queries::CaseSummary`] data and rendering
//! also serve two other spots (see [`CaseSummaryPurpose`]): a preview shown
//! before "Export portable case..." actually runs — scoped to the current
//! search filter, so the analyst sees exactly what's about to be bundled,
//! not the whole session — and an automatic summary shown right after a
//! successful "Import portable case..." so the result is visible without an
//! extra click.

use eframe::egui;

use crate::db::timeline_queries::CaseSummary;
use crate::model::timezone_spec::TimezoneSpec;
use crate::ui::colors::categorical_color;
use crate::ui::dialog_window::show_dialog_window;

/// How many rows the per-source bar chart shows before collapsing the rest
/// into a "+N more" line. [`CaseSummary::sources`] itself never truncates
/// (see its own doc comment) — only this dialog's rendering does, and says
/// so.
const MAX_SOURCE_ROWS: usize = 15;

/// Precision timestamps are formatted at for the earliest/latest labels —
/// same format `export`'s CSV/JSON timestamps use, for the same reason:
/// millisecond precision plus the timezone's own offset via
/// [`TimezoneSpec::format_utc`], so a label is unambiguous on its own.
const LABEL_TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f";

pub enum CaseSummaryPurpose {
    Info,
    ExportConfirm,
}

pub enum CaseSummaryDialogOutcome {
    ExportConfirmed,
}

pub enum CaseSummaryDialog {
    Closed,
    // Boxed: `Closed` carries nothing, so an unboxed `OpenCaseSummaryDialog`
    // (which owns a whole `CaseSummary`, potentially hundreds of sources)
    // would make every value this size — same reasoning as
    // `RawFieldsDialog`.
    Open(Box<OpenCaseSummaryDialog>),
}

pub struct OpenCaseSummaryDialog {
    title: String,
    summary: CaseSummary,
    /// `None` when not meaningful for this purpose — the export preview
    /// isn't about session load history, only the standalone/import-result
    /// views are.
    skipped_files: Option<usize>,
    /// Pre-formatted once at open time (display timezone applied) — same
    /// "format once, not every frame" reasoning as
    /// `RawFieldsDialog::open`'s `fields_pretty`.
    earliest_label: Option<String>,
    latest_label: Option<String>,
    purpose: CaseSummaryPurpose,
}

impl CaseSummaryDialog {
    pub fn open_info(
        title: String,
        summary: CaseSummary,
        skipped_files: Option<usize>,
        display_tz: &TimezoneSpec,
    ) -> Self {
        Self::new(
            title,
            summary,
            skipped_files,
            CaseSummaryPurpose::Info,
            display_tz,
        )
    }

    /// A confirmation-flavored open: rendered with "Cancel"/"Export..."
    /// buttons instead of a single "Close" — see [`CaseSummaryDialogOutcome`].
    pub fn open_export_confirm(summary: CaseSummary, display_tz: &TimezoneSpec) -> Self {
        Self::new(
            "Export portable case".to_string(),
            summary,
            None,
            CaseSummaryPurpose::ExportConfirm,
            display_tz,
        )
    }

    fn new(
        title: String,
        summary: CaseSummary,
        skipped_files: Option<usize>,
        purpose: CaseSummaryPurpose,
        display_tz: &TimezoneSpec,
    ) -> Self {
        let earliest_label = summary
            .earliest_utc
            .map(|dt| display_tz.format_utc(dt, LABEL_TIMESTAMP_FORMAT));
        let latest_label = summary
            .latest_utc
            .map(|dt| display_tz.format_utc(dt, LABEL_TIMESTAMP_FORMAT));
        Self::Open(Box::new(OpenCaseSummaryDialog {
            title,
            summary,
            skipped_files,
            earliest_label,
            latest_label,
            purpose,
        }))
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Renders the dialog if open (a no-op otherwise). Returns
    /// `Some(ExportConfirmed)` exactly once, the frame the analyst clicks
    /// "Export..." in [`CaseSummaryPurpose::ExportConfirm`] mode — `app.rs`
    /// is what actually opens the save-file dialog in response, so this
    /// stays pure rendering plus reporting, same division of labor every
    /// other dialog in this module uses.
    pub fn ui(&mut self, ctx: &egui::Context) -> Option<CaseSummaryDialogOutcome> {
        let Self::Open(state) = self else {
            return None;
        };
        let OpenCaseSummaryDialog {
            title,
            summary,
            skipped_files,
            earliest_label,
            latest_label,
            purpose,
        } = state.as_ref();

        let mut outcome = None;
        let close = show_dialog_window(
            ctx,
            "peach_case_summary_dialog",
            title,
            [560.0, 620.0],
            true,
            |ui, close| {
                render_summary(
                    ui,
                    summary,
                    *skipped_files,
                    earliest_label.as_deref(),
                    latest_label.as_deref(),
                );
                ui.separator();
                match purpose {
                    CaseSummaryPurpose::Info => {
                        if ui.button("Close").clicked() {
                            *close = true;
                        }
                    }
                    CaseSummaryPurpose::ExportConfirm => {
                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                *close = true;
                            }
                            if ui.button("Export...").clicked() {
                                outcome = Some(CaseSummaryDialogOutcome::ExportConfirmed);
                                *close = true;
                            }
                        });
                    }
                }
            },
        );

        if close {
            *self = Self::Closed;
        }
        outcome
    }
}

fn render_summary(
    ui: &mut egui::Ui,
    summary: &CaseSummary,
    skipped_files: Option<usize>,
    earliest_label: Option<&str>,
    latest_label: Option<&str>,
) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        let untagged = summary.total_entries.saturating_sub(summary.tagged_entries);
        let tagged_pct = if summary.total_entries > 0 {
            100.0 * summary.tagged_entries as f64 / summary.total_entries as f64
        } else {
            0.0
        };
        ui.label(format!(
            "{} entries across {} source(s), {} sourcetype(s)",
            summary.total_entries,
            summary.sources.len(),
            summary.sourcetype_counts.len(),
        ));
        ui.label(format!(
            "{} tagged ({tagged_pct:.1}%), {untagged} untagged",
            summary.tagged_entries,
        ));
        if let Some(skipped) = skipped_files {
            ui.label(format!(
                "{skipped} file(s) skipped during loading (see Activity Log for why)"
            ));
        }
        match (earliest_label, latest_label) {
            (Some(earliest), Some(latest)) => {
                ui.label(format!("Time range: {earliest} \u{2192} {latest}"));
            }
            _ => {
                ui.weak("No timestamped entries.");
            }
        }

        ui.add_space(8.0);
        ui.strong("Entries per sourcetype");
        if summary.sourcetype_counts.is_empty() {
            ui.weak("(none)");
        } else {
            horizontal_bar_chart(
                ui,
                "sourcetype",
                summary
                    .sourcetype_counts
                    .iter()
                    .map(|(label, count)| (label.as_str(), *count)),
            );
        }

        ui.add_space(8.0);
        ui.strong("Entries per source");
        if summary.sources.is_empty() {
            ui.weak("(none)");
        } else {
            let shown = summary.sources.len().min(MAX_SOURCE_ROWS);
            horizontal_bar_chart(
                ui,
                "source",
                summary.sources[..shown]
                    .iter()
                    .map(|s| (s.path.as_str(), s.entry_count)),
            );
            if summary.sources.len() > shown {
                let remaining_entries: usize =
                    summary.sources[shown..].iter().map(|s| s.entry_count).sum();
                ui.weak(format!(
                    "+{} more source(s) ({remaining_entries} entries, not shown above)",
                    summary.sources.len() - shown
                ));
            }
        }

        ui.add_space(8.0);
        ui.strong("Level breakdown");
        if summary.level_counts.is_empty() {
            ui.weak("No leveled entries.");
        } else {
            horizontal_bar_chart(
                ui,
                "level",
                summary
                    .level_counts
                    .iter()
                    .map(|(label, count)| (label.as_str(), *count)),
            );
        }

        if let Some(histogram) = &summary.daily_histogram {
            ui.add_space(8.0);
            ui.strong("Daily activity (UTC days)");
            daily_histogram_chart(ui, histogram);
        }
    });
}

/// Renders `rows` as a label / filled-bar / count grid — `id_salt` must be
/// unique among the grids shown in one dialog frame (`egui::Grid` needs a
/// stable, collision-free `Id`; every call in [`render_summary`] shares the
/// same parent `ui`, so a fixed literal per call site isn't enough on its
/// own without this). Bar color is [`categorical_color`] keyed by the row's
/// own label — the same hashed palette already used for the Level/Tags
/// timeline columns everywhere else in the app, so this dialog's colors
/// read as part of the same system instead of a second, unrelated palette.
fn horizontal_bar_chart<'a>(
    ui: &mut egui::Ui,
    id_salt: &str,
    rows: impl Iterator<Item = (&'a str, usize)>,
) {
    let rows: Vec<(&str, usize)> = rows.collect();
    let max_count = rows.iter().map(|(_, count)| *count).max().unwrap_or(0);
    let dark_mode = ui.visuals().dark_mode;
    let track_color = ui.visuals().extreme_bg_color;

    egui::Grid::new(ui.id().with(("case_summary_bar_chart", id_salt)))
        .num_columns(3)
        .spacing([8.0, 4.0])
        .show(ui, |ui| {
            for (label, count) in rows {
                ui.label(label);
                let bar_width = 220.0f32.min((ui.available_width() - 60.0).max(20.0));
                let (rect, _response) =
                    ui.allocate_exact_size(egui::vec2(bar_width, 16.0), egui::Sense::hover());
                let frac = if max_count > 0 {
                    count as f32 / max_count as f32
                } else {
                    0.0
                };
                let filled = egui::Rect::from_min_size(
                    rect.min,
                    egui::vec2(rect.width() * frac, rect.height()),
                );
                let painter = ui.painter();
                painter.rect_filled(rect, 2.0, track_color);
                painter.rect_filled(filled, 2.0, categorical_color(label, dark_mode));
                ui.label(count.to_string());
                ui.end_row();
            }
        });
}

/// Thin vertical bars, one per day in `histogram`, height proportional to
/// that day's count — a fixed color (via [`categorical_color`] keyed by a
/// constant label, not per-day) since these bars aren't categorical the way
/// sourcetype/level/source rows are; using the same hashed palette function
/// still keeps the color harmonized with the rest of the app across every
/// theme instead of a hand-picked literal that might clash with Geek/
/// Rainbow's unusual palettes.
fn daily_histogram_chart(ui: &mut egui::Ui, histogram: &[(chrono::NaiveDate, usize)]) {
    if histogram.is_empty() {
        return;
    }
    let max_count = histogram
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(0)
        .max(1);
    let dark_mode = ui.visuals().dark_mode;
    let track_color = ui.visuals().extreme_bg_color;
    let bar_color = categorical_color("case-summary-daily-activity", dark_mode);

    let chart_height = 60.0;
    let (rect, _response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), chart_height),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    painter.rect_filled(rect, 2.0, track_color);

    let bar_width = rect.width() / histogram.len() as f32;
    for (i, (_day, count)) in histogram.iter().enumerate() {
        let frac = *count as f32 / max_count as f32;
        let bar_height = rect.height() * frac;
        let x = rect.min.x + i as f32 * bar_width;
        let bar_rect = egui::Rect::from_min_size(
            egui::pos2(x, rect.max.y - bar_height),
            egui::vec2(bar_width.max(1.0), bar_height),
        );
        painter.rect_filled(bar_rect, 0.0, bar_color);
    }
}
