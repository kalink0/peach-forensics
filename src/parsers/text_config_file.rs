//! Reading, writing, and listing text-parser config files for the "Define
//! format..." dialog (`ui::format_dialog`) — the dialog only renders
//! widgets, this module owns the actual `parsers/` directory and the
//! draft-to-TOML/TOML-to-draft conversion.
//!
//! There's deliberately no separate "profile" format like crush's
//! `CustomFormatProfile`/`ProfileManager`: a saved config *is* a real
//! parser-config TOML file, the exact same shape
//! [`crate::parsers::text_config::TextConfigParser`] reads for a real
//! load — so there's nothing that can drift between "what the dialog
//! saved" and "what a load actually uses".

use std::path::{Path, PathBuf};

use anyhow::Context;
use directories::ProjectDirs;

use crate::parsers::ParserConfig;
use crate::parsers::text_config::{PatternConfig, TextParserFields};

/// Default per-user directory for text-parser configs saved from the
/// "Define format..." dialog — same `ProjectDirs` layout as
/// [`crate::tagging::rule_file::default_user_rules_dir`], a sibling
/// `parsers` directory rather than the repo's `parsers/examples/` (that
/// one ships read-only, not a place to write into).
pub fn default_user_parsers_dir() -> anyhow::Result<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "peach")
        .context("could not determine a per-user data directory on this platform")?;
    let dir = project_dirs.data_dir().join("parsers");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create parsers directory {}", dir.display()))?;
    Ok(dir)
}

/// One saved config, as listed in the "Define format..." dialog's
/// saved-profile picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedConfig {
    pub path: PathBuf,
    pub name: String,
    pub sourcetype: String,
}

/// Every `*.toml` file directly under `dir` that parses as a valid
/// [`ParserConfig`], sorted by name. A file that fails to parse (e.g.
/// mid-edit by hand, or not a parser config at all) is silently skipped
/// rather than shown broken — best-effort listing, same reasoning as
/// `tagging::rule::load_rules` skipping files it can't read.
pub fn list_saved_configs(dir: &Path) -> Vec<SavedConfig> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut configs: Vec<SavedConfig> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).ok()?;
            let config = ParserConfig::from_toml_str(&text).ok()?;
            Some(SavedConfig {
                path,
                name: config.parser.name,
                sourcetype: config.parser.sourcetype,
            })
        })
        .collect();
    configs.sort_by(|a, b| a.name.cmp(&b.name));
    configs
}

/// The "Define format..." dialog's editable fields — one-to-one with what
/// [`TextParserFields`]/[`crate::parsers::ParserConfigBody`] need, as plain
/// `String`s so egui's text edits can bind directly to them. An empty
/// string means "not set" for every optional field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextFormatDraft {
    pub name: String,
    pub sourcetype: String,
    pub regex: String,
    pub timestamp_format: String,
    pub multiline_start_pattern: String,
    pub assume_offset: String,
    pub level_group: String,
    pub message_group: String,
}

impl TextFormatDraft {
    /// Loads an existing config file's fields back into a draft, for the
    /// dialog's "Load" button — editing/reusing a saved config rather than
    /// starting from a blank one every time.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config = ParserConfig::from_toml_str(&text)
            .with_context(|| format!("failed to parse {} as a parser config", path.display()))?;
        let fields: TextParserFields = toml::Value::Table(config.parser.extra)
            .try_into()
            .with_context(|| format!("{} is not a valid text parser config", path.display()))?;
        let PatternConfig {
            regex,
            timestamp_format,
            multiline_start_pattern,
            assume_offset,
        } = fields.pattern;
        Ok(Self {
            name: config.parser.name,
            sourcetype: config.parser.sourcetype,
            regex,
            timestamp_format,
            multiline_start_pattern: multiline_start_pattern.unwrap_or_default(),
            assume_offset: assume_offset.unwrap_or_default(),
            level_group: fields
                .field_mapping
                .get("level")
                .cloned()
                .unwrap_or_default(),
            message_group: fields
                .field_mapping
                .get("message")
                .cloned()
                .unwrap_or_default(),
        })
    }

    /// Whether there's enough here to write a well-formed parser config —
    /// gates the dialog's Save/"Save & Use" buttons. Deliberately not a
    /// full validation (regex-contains-a-timestamp-group, assume_offset
    /// syntax, ...) — the preview already surfaces those per line, and the
    /// real load path re-validates unconditionally regardless of what this
    /// dialog let through, so duplicating that here would just be a second
    /// copy of the same checks to keep in sync.
    pub fn is_saveable(&self) -> bool {
        !self.name.trim().is_empty()
            && !self.sourcetype.trim().is_empty()
            && !self.regex.trim().is_empty()
            && !self.timestamp_format.trim().is_empty()
            && regex::Regex::new(self.regex.trim()).is_ok()
    }

    /// Renders as a real parser-config TOML file
    /// [`crate::parsers::text_config::TextConfigParser`] can load directly.
    /// A plain string template (not `toml_edit`) — unlike
    /// `tagging::rule_file::append_message_contains_pattern`'s edit of an
    /// existing hand-commented file, this always writes a brand-new file
    /// wholesale from the draft's own state, so there's no existing
    /// formatting/comments to preserve.
    fn to_toml(&self) -> String {
        let mut out = format!(
            "[parser]\nname = \"{}\"\nsourcetype = \"{}\"\n\n[parser.pattern]\nregex = \"{}\"\ntimestamp_format = \"{}\"\n",
            escape(self.name.trim()),
            escape(self.sourcetype.trim()),
            escape(self.regex.trim()),
            escape(self.timestamp_format.trim()),
        );
        if !self.multiline_start_pattern.trim().is_empty() {
            out.push_str(&format!(
                "multiline_start_pattern = \"{}\"\n",
                escape(self.multiline_start_pattern.trim())
            ));
        }
        if !self.assume_offset.trim().is_empty() {
            out.push_str(&format!(
                "assume_offset = \"{}\"\n",
                escape(self.assume_offset.trim())
            ));
        }
        if !self.level_group.trim().is_empty() || !self.message_group.trim().is_empty() {
            out.push_str("\n[parser.field_mapping]\n");
            if !self.level_group.trim().is_empty() {
                out.push_str(&format!(
                    "level = \"{}\"\n",
                    escape(self.level_group.trim())
                ));
            }
            if !self.message_group.trim().is_empty() {
                out.push_str(&format!(
                    "message = \"{}\"\n",
                    escape(self.message_group.trim())
                ));
            }
        }
        out
    }
}

/// TOML basic strings only need `\` and `"` escaped for the values this
/// module writes (plain UI-entered text, no control characters expected)
/// — same reasoning and same escaping as
/// `tagging::rule_file::escape_toml_string`, duplicated rather than shared
/// since it's a two-line pure function and the two modules otherwise have
/// no reason to depend on each other.
fn escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Writes `draft` to `dir` under a slugified filename derived from its
/// name (reusing `tagging::rule_file::slugify` — same "human-readable name
/// -> filesystem-safe stem" need, no reason for a second implementation),
/// overwriting an existing file of the same name. Returns the path written.
pub fn save(dir: &Path, draft: &TextFormatDraft) -> anyhow::Result<PathBuf> {
    let path = dir.join(format!(
        "{}.toml",
        crate::tagging::rule_file::slugify(&draft.name)
    ));
    std::fs::write(&path, draft.to_toml())
        .with_context(|| format!("failed to write parser config {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, unique scratch directory for one test — same
    /// pid+nanosecond-timestamp uniqueness scheme as
    /// `tagging::rule_file::tests::temp_path`, just a directory instead of
    /// a single file since these tests exercise `list_saved_configs` too.
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "peach-text-config-file-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_draft() -> TextFormatDraft {
        TextFormatDraft {
            name: "Nginx Access".to_string(),
            sourcetype: "nginx".to_string(),
            regex: r"^(?P<timestamp>\S+) (?P<level_raw>\w+) (?P<msg>.*)$".to_string(),
            timestamp_format: "%Y-%m-%dT%H:%M:%S%z".to_string(),
            multiline_start_pattern: String::new(),
            assume_offset: String::new(),
            level_group: "level_raw".to_string(),
            message_group: "msg".to_string(),
        }
    }

    #[test]
    fn save_writes_a_config_the_real_parser_config_loader_accepts() {
        let dir = temp_dir("save-writes");

        let draft = sample_draft();
        let path = save(&dir, &draft).unwrap();
        assert!(path.ends_with("nginx_access.toml"));

        let text = std::fs::read_to_string(&path).unwrap();
        let config = ParserConfig::from_toml_str(&text).unwrap();
        assert_eq!(config.parser.name, "Nginx Access");
        assert_eq!(config.parser.sourcetype, "nginx");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_then_from_file_round_trips_every_field() {
        let dir = temp_dir("round-trip");

        let draft = sample_draft();
        let path = save(&dir, &draft).unwrap();
        let loaded = TextFormatDraft::from_file(&path).unwrap();
        assert_eq!(loaded, draft);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn round_trip_preserves_optional_fields_when_set() {
        let dir = temp_dir("optional-fields");

        let mut draft = sample_draft();
        draft.multiline_start_pattern = r"^\d{4}-\d{2}-\d{2}".to_string();
        draft.assume_offset = "+02:00".to_string();
        let path = save(&dir, &draft).unwrap();
        let loaded = TextFormatDraft::from_file(&path).unwrap();
        assert_eq!(loaded, draft);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn escapes_backslashes_and_quotes_so_the_file_stays_valid_toml() {
        let dir = temp_dir("escaping");

        let mut draft = sample_draft();
        draft.regex = r#"^(?P<timestamp>\S+) "(?P<msg>.*)"$"#.to_string();
        let path = save(&dir, &draft).unwrap();
        let loaded = TextFormatDraft::from_file(&path).unwrap();
        assert_eq!(loaded.regex, draft.regex);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn is_saveable_requires_name_sourcetype_regex_and_timestamp_format() {
        let draft = sample_draft();
        assert!(draft.is_saveable());

        let mut missing_name = draft.clone();
        missing_name.name = "   ".to_string();
        assert!(!missing_name.is_saveable());

        let mut bad_regex = draft.clone();
        bad_regex.regex = "(unclosed".to_string();
        assert!(!bad_regex.is_saveable());

        let mut missing_ts_format = draft.clone();
        missing_ts_format.timestamp_format = String::new();
        assert!(!missing_ts_format.is_saveable());
    }

    #[test]
    fn list_saved_configs_skips_unparsable_files_and_sorts_by_name() {
        let dir = temp_dir("listing");

        let mut zebra = sample_draft();
        zebra.name = "Zebra".to_string();
        save(&dir, &zebra).unwrap();
        let mut apple = sample_draft();
        apple.name = "Apple".to_string();
        save(&dir, &apple).unwrap();
        // Valid TOML, but no `[parser]` table — must fail `ParserConfig`
        // deserialization and be skipped, not panic the listing.
        std::fs::write(dir.join("not_a_config.toml"), "not = \"a parser config\"\n").unwrap();

        let configs = list_saved_configs(&dir);
        assert_eq!(
            configs.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["Apple", "Zebra"]
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
