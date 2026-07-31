//! Persistent app settings — currently just an optional override for where
//! session files (`.duckdb`/`.sqlite`, see
//! [`crate::session::persist::SessionPaths`]) get created.
//!
//! Lives in its own TOML file under the OS *config* directory
//! (`ProjectDirs::config_dir`), deliberately separate from the sessions
//! directory itself: that one is exactly the thing this file can override,
//! so settings have to live somewhere fixed, or overriding their own
//! storage location would be circular.

use std::path::{Path, PathBuf};

use anyhow::Context;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::session::persist;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Overrides [`persist::default_sessions_dir`] when set. `None` (the
    /// default, and what a fresh install has) means "use the OS-standard
    /// per-user data directory".
    pub sessions_dir: Option<PathBuf>,
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
        };

        let resolved = settings.sessions_dir().unwrap();

        assert_eq!(resolved, dir);
        assert!(dir.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
