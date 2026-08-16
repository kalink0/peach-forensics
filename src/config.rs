//! Persistent app settings — theme, load thread count, and optional
//! overrides for where session files (`.duckdb`/`.sqlite`, see
//! [`crate::session::persist::SessionPaths`]) and analyst-created rule
//! files (see [`crate::tagging::rule_file`]) get created.
//!
//! Lives in its own TOML file under the OS *config* directory
//! (`ProjectDirs::config_dir`), deliberately separate from the sessions/
//! rules directories themselves: those are exactly the things this file can
//! override, so settings have to live somewhere fixed, or overriding their
//! own storage location would be circular.

use std::path::{Path, PathBuf};

use anyhow::Context;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::session::persist;
use crate::tagging::rule_file;

/// Window chrome color scheme. Deliberately toolkit-agnostic (no `egui`
/// import here) — turning this into actual colors is `crate::ui::theme`'s
/// job, so this module stays plain data like the rest of `Settings`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    /// Follow the OS light/dark preference.
    #[default]
    System,
    Light,
    Dark,
    /// Phosphor-green terminal look, shared with crush's "Geek" theme.
    Geek,
    /// Continuously hue-cycling palette, animated every frame — shared
    /// signature with crush's "Rainbow" theme (same ~12.5s cycle, same
    /// HSV formula).
    Rainbow,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Overrides [`persist::default_sessions_dir`] when set. `None` (the
    /// default, and what a fresh install has) means "use the OS-standard
    /// per-user data directory".
    pub sessions_dir: Option<PathBuf>,
    /// Window chrome theme, applied on startup and whenever changed via
    /// View > Theme. `#[serde(default)]` so `config.toml` files saved
    /// before this field existed still load fine.
    #[serde(default)]
    pub theme: Theme,
    /// Worker threads for parsing a multi-file folder load (EVTX/journald/
    /// Text) in parallel — `None` (the default) auto-picks from available
    /// CPU parallelism via [`default_load_threads`]. Irrelevant for AUL or
    /// a single-file load: both are always exactly one parse unit, nothing
    /// to spread across threads. `#[serde(default)]` for the same
    /// backward-compat reason `theme` has it.
    #[serde(default)]
    pub load_threads: Option<usize>,
    /// Overrides [`rule_file::default_user_rules_dir`] when set — where
    /// rules created via the timeline's "Tag all matching (advanced)..."
    /// dialog get written. `None` (the default) means the OS-standard
    /// per-user data directory, same reasoning as `sessions_dir`. Pointing
    /// this at an analyst-chosen folder (e.g. one they put under their own
    /// git repo) is deliberately supported: `rules/examples/` in the Peach
    /// repo itself is a read-only reference library, not meant to be a
    /// personal rule collection's home. `#[serde(default)]` for the same
    /// backward-compat reason `theme`/`load_threads` have it.
    #[serde(default)]
    pub rules_dir: Option<PathBuf>,
}

impl Settings {
    /// Resolves the effective sessions directory — the configured override
    /// if set, otherwise the OS default — creating it if it doesn't exist
    /// yet, same as `default_sessions_dir` always did on its own.
    pub fn sessions_dir(&self) -> anyhow::Result<PathBuf> {
        let Some(dir) = &self.sessions_dir else {
            return persist::default_sessions_dir();
        };
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create sessions directory {}", dir.display()))?;
        Ok(dir.clone())
    }

    /// Resolves the effective rules directory — same override-or-default
    /// shape as [`Self::sessions_dir`].
    pub fn rules_dir(&self) -> anyhow::Result<PathBuf> {
        let Some(dir) = &self.rules_dir else {
            return rule_file::default_user_rules_dir();
        };
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create rules directory {}", dir.display()))?;
        Ok(dir.clone())
    }

    /// The thread count a folder load should actually use — the configured
    /// override if set, otherwise [`default_load_threads`].
    pub fn effective_load_threads(&self) -> usize {
        self.load_threads.unwrap_or_else(default_load_threads)
    }
}

/// Auto-picked worker thread count for parsing a multi-file folder load —
/// capped at 8 even on many-core machines, the same cap crush uses for its
/// own "Indexing Threads" default: past a handful of threads, contention
/// on the single DuckDB writer (see `app.rs::run_load`) dominates, so more
/// parser threads stop helping well before core count does.
pub fn default_load_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8)
}

fn config_file_path() -> anyhow::Result<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "peach")
        .context("could not determine a per-user config directory on this platform")?;
    Ok(project_dirs.config_dir().join("config.toml"))
}

/// Best-effort: a missing or corrupt config file just means "use defaults"
/// — settings are a convenience, not something that should ever be able to
/// stop the app from starting.
pub fn load() -> Settings {
    config_file_path()
        .ok()
        .map(|path| load_from(&path))
        .unwrap_or_default()
}

pub fn save(settings: &Settings) -> anyhow::Result<()> {
    save_to(&config_file_path()?, settings)
}

fn load_from(path: &Path) -> Settings {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_to(path: &Path, settings: &Settings) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    }
    let text = toml::to_string_pretty(settings).context("failed to serialize settings")?;
    std::fs::write(path, text)
        .with_context(|| format!("failed to write config file {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "peach-config-test-{}-{}-{name}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn defaults_to_no_override() {
        assert_eq!(Settings::default().sessions_dir, None);
    }

    #[test]
    fn save_and_load_round_trip_an_override() {
        let path = temp_config_path("round-trip");
        let settings = Settings {
            sessions_dir: Some(PathBuf::from("/tmp/some-case-drive/peach-sessions")),
            theme: Theme::Geek,
            load_threads: Some(3),
            rules_dir: Some(PathBuf::from("/tmp/some-case-drive/peach-rules")),
        };

        save_to(&path, &settings).unwrap();
        let loaded = load_from(&path);

        assert_eq!(loaded, settings);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn load_from_a_missing_file_falls_back_to_defaults() {
        let path = temp_config_path("missing");
        assert!(!path.exists());

        assert_eq!(load_from(&path), Settings::default());
    }

    #[test]
    fn load_from_a_file_predating_the_theme_field_defaults_to_system() {
        let path = temp_config_path("no-theme-field");
        std::fs::write(&path, b"sessions_dir = \"/tmp/some-case-drive\"\n").unwrap();

        let loaded = load_from(&path);

        assert_eq!(loaded.theme, Theme::System);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn load_from_a_file_predating_the_load_threads_field_defaults_to_automatic() {
        let path = temp_config_path("no-load-threads-field");
        std::fs::write(&path, b"sessions_dir = \"/tmp/some-case-drive\"\n").unwrap();

        let loaded = load_from(&path);

        assert_eq!(loaded.load_threads, None);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn effective_load_threads_falls_back_to_the_automatic_default() {
        let settings = Settings::default();
        assert_eq!(settings.effective_load_threads(), default_load_threads());
    }

    #[test]
    fn effective_load_threads_uses_the_configured_override() {
        let settings = Settings {
            load_threads: Some(3),
            ..Settings::default()
        };
        assert_eq!(settings.effective_load_threads(), 3);
    }

    #[test]
    fn default_load_threads_is_at_least_one_and_capped_at_eight() {
        let threads = default_load_threads();
        assert!((1..=8).contains(&threads));
    }

    #[test]
    fn load_from_a_corrupt_file_falls_back_to_defaults_instead_of_failing() {
        let path = temp_config_path("corrupt");
        std::fs::write(&path, b"this is not valid toml {{{").unwrap();

        assert_eq!(load_from(&path), Settings::default());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn sessions_dir_creates_and_returns_the_configured_override() {
        let dir = std::env::temp_dir().join(format!(
            "peach-config-test-sessions-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!dir.exists());
        let settings = Settings {
            sessions_dir: Some(dir.clone()),
            ..Settings::default()
        };

        let resolved = settings.sessions_dir().unwrap();

        assert_eq!(resolved, dir);
        assert!(dir.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn defaults_to_no_rules_dir_override() {
        assert_eq!(Settings::default().rules_dir, None);
    }

    #[test]
    fn rules_dir_creates_and_returns_the_configured_override() {
        let dir = std::env::temp_dir().join(format!(
            "peach-config-test-rules-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!dir.exists());
        let settings = Settings {
            rules_dir: Some(dir.clone()),
            ..Settings::default()
        };

        let resolved = settings.rules_dir().unwrap();

        assert_eq!(resolved, dir);
        assert!(dir.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_from_a_file_predating_the_rules_dir_field_defaults_to_none() {
        let path = temp_config_path("no-rules-dir-field");
        std::fs::write(&path, b"sessions_dir = \"/tmp/some-case-drive\"\n").unwrap();

        let loaded = load_from(&path);

        assert_eq!(loaded.rules_dir, None);
        std::fs::remove_file(path).unwrap();
    }
}
