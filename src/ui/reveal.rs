//! Opening a path in the OS file manager — shared by `session_dialog`'s
//! per-session "Open folder" and `settings_dialog`'s "Open folder" for the
//! configured sessions/rules directories. Best-effort: spawns and returns,
//! doesn't wait for or check an exit status (`explorer.exe` in particular is
//! well known to report a nonzero exit code even on success).

use std::path::Path;

use anyhow::Context;

/// Opens `dir` itself in the OS file manager.
pub(crate) fn open_folder(dir: &Path) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(dir)
            .spawn()
            .context("failed to launch Explorer")?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(dir)
            .spawn()
            .context("failed to launch Finder")?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(dir)
            .spawn()
            .context("failed to launch the file manager (is xdg-open installed?)")?;
    }
    Ok(())
}

/// Opens the OS file manager with `path` itself selected (Explorer/Finder)
/// — Linux just opens the containing folder instead, since there's no
/// cross-desktop convention for "open and select a specific file" to rely
/// on there.
pub(crate) fn reveal_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(format!("/select,{}", path.display()))
            .spawn()
            .context("failed to launch Explorer")?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg("-R")
            .arg(path)
            .spawn()
            .context("failed to launch Finder")?;
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        open_folder(path.parent().unwrap_or(path))
    }
}
