use std::path::PathBuf;

use clap::Parser;

/// Peach — DFIR log workbench. Can be started standalone or handed
/// evidence paths by crush; runs fully independently afterward (no IPC).
#[derive(Parser, Debug)]
#[command(name = "peach")]
struct Cli {
    /// Pre-fill a source to load (repeatable). Peach still requires
    /// explicit confirmation (sourcetype, parser config) before actually
    /// loading it — this only queues the path, per the "user chooses
    /// deliberately" principle (no mandatory auto-detection).
    #[arg(long = "add-source")]
    add_source: Vec<PathBuf>,

    /// A directory to delete when Peach closes (repeatable) — e.g. a temp
    /// extraction directory crush created to hand off zipped evidence.
    /// Only ever deletes exactly what's given here, and only if it's under
    /// the OS temp directory (a safety net against a mistaken path).
    #[arg(long = "cleanup-dir")]
    cleanup_dir: Vec<PathBuf>,

    /// Disable session persistence for this run: the session's `.duckdb`/
    /// `.sqlite` are written to a one-off temp directory instead of the
    /// persistent sessions directory, and that temp directory is removed
    /// on exit regardless of whether it holds data. For evidence crush
    /// hands off from a temp extraction or a decrypted source — this run
    /// must not leave a durable, unencrypted session copy behind.
    #[arg(long = "ephemeral-session")]
    ephemeral_session: bool,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = peach::app::run(cli.add_source, cli.cleanup_dir, cli.ephemeral_session) {
        eprintln!("peach: {err:#}");
        std::process::exit(1);
    }
}
