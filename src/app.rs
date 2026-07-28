use std::path::{Path, PathBuf};
use std::sync::mpsc;

use anyhow::Context;
use eframe::egui;

use crate::db::timeline_schema::setup_timeline_schema;
use crate::model::log_entry::LogEntry;
use crate::parsers::aul::AulParser;
use crate::parsers::text_config::TextConfigParser;
use crate::parsers::{LogParser, ParserConfig, parse_source};
use crate::tagging::engine::apply_import_time;
use crate::tagging::rule::Rule;
use crate::ui::timeline_view::TimelineView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Aul,
    Text,
}

enum LoadOutcome {
    Done(Result<(usize, usize), String>),
}

enum LoadState {
    Idle,
    Loading,
    Done {
        inserted: usize,
        tags_applied: usize,
    },
    Failed(String),
}

pub struct PeachApp {
    db_path: PathBuf,
    source_kind: SourceKind,
    source_path: Option<PathBuf>,
    parser_config_path: Option<PathBuf>,
    rule_paths: Vec<PathBuf>,
    load_state: LoadState,
    load_rx: Option<mpsc::Receiver<LoadOutcome>>,
    timeline: TimelineView,
}

impl PeachApp {
    fn new() -> Self {
        // Placeholder location ahead of the real workdir selection
        // (Milestones 13/14) — needs to be a real file, not `:memory:`,
        // since the load runs on a worker thread with its own connection
        // (`duckdb::Connection` isn't `Send`) while the UI thread reads
        // through a separate connection to the same file.
        let db_path =
            std::env::temp_dir().join(format!("peach-session-{}.duckdb", uuid::Uuid::new_v4()));
        Self {
            db_path: db_path.clone(),
            source_kind: SourceKind::Aul,
            source_path: None,
            parser_config_path: None,
            rule_paths: Vec::new(),
            load_state: LoadState::Idle,
            load_rx: None,
            timeline: TimelineView::new(db_path),
        }
    }

    fn start_load(&mut self) {
        let Some(source_path) = self.source_path.clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.load_rx = Some(rx);
        self.load_state = LoadState::Loading;

        let db_path = self.db_path.clone();
        let source_kind = self.source_kind;
        let parser_config_path = self.parser_config_path.clone();
        let rule_paths = self.rule_paths.clone();

        std::thread::spawn(move || {
            let result = run_load(
                source_kind,
                &source_path,
                parser_config_path.as_deref(),
                &rule_paths,
                &db_path,
            )
            .map_err(|err| format!("{err:#}"));
            let _ = tx.send(LoadOutcome::Done(result));
        });
    }
}

impl eframe::App for PeachApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.load_rx {
            match rx.try_recv() {
                Ok(LoadOutcome::Done(result)) => {
                    match result {
                        Ok((inserted, tags_applied)) => {
                            self.load_state = LoadState::Done {
                                inserted,
                                tags_applied,
                            };
                            self.timeline.refresh();
                        }
                        Err(err) => self.load_state = LoadState::Failed(err),
                    }
                    self.load_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ui.ctx().request_repaint();
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.load_state =
                        LoadState::Failed("load worker disconnected unexpectedly".to_string());
                    self.load_rx = None;
                }
            }
        }

        egui::Panel::top("controls").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Sourcetype:");
                ui.selectable_value(&mut self.source_kind, SourceKind::Aul, "AUL (.logarchive)");
                ui.selectable_value(
                    &mut self.source_kind,
                    SourceKind::Text,
                    "Text (config-based)",
                );
            });

            ui.horizontal(|ui| {
                let pick_label = match self.source_kind {
                    SourceKind::Aul => "Choose .logarchive folder...",
                    SourceKind::Text => "Choose log file...",
                };
                if ui.button(pick_label).clicked() {
                    let picked = match self.source_kind {
                        SourceKind::Aul => rfd::FileDialog::new().pick_folder(),
                        SourceKind::Text => rfd::FileDialog::new().pick_file(),
                    };
                    if let Some(picked) = picked {
                        self.source_path = Some(picked);
                    }
                }
                if let Some(source_path) = &self.source_path {
                    ui.label(source_path.display().to_string());
                }
            });

            if self.source_kind == SourceKind::Text {
                ui.horizontal(|ui| {
                    if ui.button("Choose parser config (TOML)...").clicked()
                        && let Some(picked) = rfd::FileDialog::new()
                            .add_filter("TOML", &["toml"])
                            .pick_file()
                    {
                        self.parser_config_path = Some(picked);
                    }
                    if let Some(config_path) = &self.parser_config_path {
                        ui.label(config_path.display().to_string());
                    }
                });
            }

            ui.horizontal(|ui| {
                if ui
                    .button("Choose tagging rules (TOML, optional)...")
                    .clicked()
                    && let Some(picked) = rfd::FileDialog::new()
                        .add_filter("TOML", &["toml"])
                        .pick_files()
                {
                    self.rule_paths = picked;
                }
                if self.rule_paths.is_empty() {
                    ui.label("(none selected — import-time tagging skipped)");
                } else {
                    ui.label(format!("{} rule file(s) selected", self.rule_paths.len()));
                }
            });

            let can_load = !matches!(self.load_state, LoadState::Loading)
                && self.source_path.is_some()
                && (self.source_kind != SourceKind::Text || self.parser_config_path.is_some());

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(can_load, egui::Button::new("Load"))
                    .clicked()
                {
                    self.start_load();
                }
                match &self.load_state {
                    LoadState::Idle => {}
                    LoadState::Loading => {
                        ui.spinner();
                        ui.label("Loading...");
                    }
                    LoadState::Done {
                        inserted,
                        tags_applied,
                    } => {
                        ui.label(format!(
                            "Loaded {inserted} entries, applied {tags_applied} tags"
                        ));
                    }
                    LoadState::Failed(err) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {err}"));
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            self.timeline.ui(ui);
        });
    }
}

/// Runs on a background thread so the UI stays responsive — this can mean
/// parsing and inserting millions of rows for a large AUL source. Opens its
/// own DuckDB connection (`Connection` isn't `Send`) and bulk-inserts via
/// the DuckDB Appender rather than row-by-row `INSERT` statements.
fn run_load(
    source_kind: SourceKind,
    source_path: &Path,
    parser_config_path: Option<&Path>,
    rule_paths: &[PathBuf],
    db_path: &Path,
) -> anyhow::Result<(usize, usize)> {
    let conn = duckdb::Connection::open(db_path)?;
    setup_timeline_schema(&conn)?;

    let (parser, config): (&dyn LogParser, ParserConfig) = match source_kind {
        SourceKind::Aul => (
            &AulParser,
            ParserConfig::from_toml_str("[parser]\nname = \"aul\"\nsourcetype = \"aul\"\n")?,
        ),
        SourceKind::Text => {
            let config_path = parser_config_path
                .ok_or_else(|| anyhow::anyhow!("no parser config selected for a text source"))?;
            let config_text = std::fs::read_to_string(config_path)?;
            (
                &TextConfigParser,
                ParserConfig::from_toml_str(&config_text)?,
            )
        }
    };
    // The config's sourcetype is authoritative, not `parser.sourcetype()`:
    // TextConfigParser serves many different sourcetypes (nginx, syslog,
    // ...) depending on which config is loaded, so its own sourcetype() is
    // just a generic marker (see parsers/mod.rs doc comment).
    let sourcetype = config.parser.sourcetype.clone();

    let entries: Vec<LogEntry> = parse_source(parser, source_path, &config)?;
    if entries.is_empty() {
        return Ok((0, 0));
    }

    insert_source_record(&conn, &entries[0], source_path, &sourcetype)?;

    let mut appender = conn.appender("log_entries")?;
    for entry in &entries {
        appender.append_row(duckdb::params![
            entry.event_id.source_file_id.to_string(),
            entry.event_id.sequence_number.value() as i64,
            entry.timestamp_utc.naive_utc(),
            entry.level,
            entry.message,
            entry.raw,
            entry.fields,
        ])?;
    }
    drop(appender);

    let rules = rule_paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read rule file {}", path.display()))?;
            Rule::from_toml_str(&text)
                .with_context(|| format!("invalid rule file {}", path.display()))
        })
        .collect::<anyhow::Result<Vec<Rule>>>()?;
    let tags_applied = apply_import_time(&conn, &rules, &entries, &sourcetype)?;

    Ok((entries.len(), tags_applied))
}

fn insert_source_record(
    conn: &duckdb::Connection,
    first_entry: &LogEntry,
    source_path: &Path,
    sourcetype: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
         VALUES (?, ?, ?, ?, ?)",
        duckdb::params![
            first_entry.event_id.source_file_id.to_string(),
            source_path.display().to_string(),
            sourcetype,
            Option::<String>::None,
            Option::<String>::None,
        ],
    )?;
    Ok(())
}

pub fn run() -> anyhow::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Peach",
        native_options,
        Box::new(|_cc| Ok(Box::new(PeachApp::new()))),
    )
    .map_err(|err| anyhow::anyhow!("failed to run peach GUI: {err}"))
}
