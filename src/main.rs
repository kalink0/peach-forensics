use std::path::PathBuf;

use clap::Parser;

/// Peach — forensic multi-log viewer. Can be started standalone or handed
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
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = peach::app::run(cli.add_source, cli.cleanup_dir) {
        eprintln!("peach: {err:#}");
        std::process::exit(1);
    }
}
