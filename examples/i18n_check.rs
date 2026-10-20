//! Translation report for CI and translators: per language, how much is
//! translated, which messages are still missing, and any errors.
//!
//!     cargo run --example i18n_check
//!
//! Exit code 1 if any translation file has errors (syntax, unknown key,
//! duplicate, placeholder mismatch); missing messages only produce
//! warnings. Under GitHub Actions it also emits annotations on the
//! offending `.ftl` lines and a summary table for the run page.

use std::fmt::Write as _;
use std::path::Path;

use peach::i18n::{self, FALLBACK_LANGUAGE, LanguageInfo, catalog::CatalogError};

fn main() {
    let languages = i18n::available_languages();
    let github = std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true");
    let total = languages.first().map_or(0, |l| l.report.total);

    println!("Translation report — reference: {FALLBACK_LANGUAGE}, {total} messages\n");
    let mut summary =
        String::from("## Translations\n\n| Language | Translated | Status |\n|---|---|---|\n");
    let mut failed = false;

    for language in languages.iter().filter(|l| l.code != FALLBACK_LANGUAGE) {
        let report = &language.report;
        let file = format!("i18n/{}/peach.ftl", language.code);
        let status = if report.has_errors() {
            "ERRORS"
        } else if report.missing.is_empty() {
            "complete"
        } else {
            "incomplete (missing text shows in English)"
        };
        println!(
            "{} — {}% ({}/{}) — {status}",
            display_name(language),
            report.coverage_percent(),
            report.translated,
            report.total
        );
        let _ = writeln!(
            summary,
            "| {} | {}% ({}/{}) | {status} |",
            display_name(language),
            report.coverage_percent(),
            report.translated,
            report.total
        );

        let source = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(&file))
            .unwrap_or_default();
        for error in &report.errors {
            failed = true;
            let line = error_line(error, &source);
            println!("  error: {file}:{line}: {error}");
            if github {
                println!("::error file={file},line={line}::{error}");
            }
        }
        if !report.missing.is_empty() {
            println!("  missing ({}):", report.missing.len());
            for id in &report.missing {
                println!("    {id}");
            }
            if github {
                println!(
                    "::warning file={file}::{} is {}% translated, {} messages missing (shown in English)",
                    language.code,
                    report.coverage_percent(),
                    report.missing.len()
                );
            }
        }
        println!();
    }

    // The English reference itself can only have syntax/duplicate errors.
    if let Some(english) = languages.iter().find(|l| l.code == FALLBACK_LANGUAGE) {
        for error in &english.report.errors {
            failed = true;
            println!("error: i18n/{FALLBACK_LANGUAGE}/peach.ftl: {error}");
        }
    }

    if github && let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, summary.as_bytes()));
    }

    if failed {
        println!("Translation files have errors — see above and i18n/README.md.");
        std::process::exit(1);
    }
}

fn display_name(language: &LanguageInfo) -> String {
    match &language.name {
        Some(name) => format!("{} ({name})", language.code),
        None => language.code.clone(),
    }
}

/// Line to point an annotation at: the parser's own line for syntax
/// errors, otherwise the line the offending message starts on.
fn error_line(error: &CatalogError, source: &str) -> usize {
    if let Some(line) = error.line() {
        return line.max(1);
    }
    let id = match error {
        CatalogError::Syntax { .. } | CatalogError::InvalidLanguageCode { .. } => return 1,
        CatalogError::Duplicate { id }
        | CatalogError::Orphaned { id }
        | CatalogError::PlaceholderMismatch { id, .. } => id,
    };
    source
        .lines()
        .position(|line| {
            line.strip_prefix(id.as_str())
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .map_or(1, |index| index + 1)
}
