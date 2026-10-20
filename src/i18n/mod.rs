//! UI translations — Fluent files under `i18n/<language>/peach.ftl`,
//! embedded into the binary, looked up through [`crate::fl!`].
//!
//! Display layer only: nothing that reaches the timeline/session databases,
//! an export or a persisted log goes through here, so the same evidence
//! produces byte-identical stored data whatever language the UI shows.
//!
//! English (`i18n/en/peach.ftl`) is the reference and the fallback: a
//! message a translation doesn't define yet renders in English, and `fl!`
//! checks at compile time that every message id it's given exists in the
//! English file. A new language is a new directory under `i18n/`, picked up
//! by the embed without any code change.

pub mod catalog;

use std::sync::LazyLock;

use anyhow::{Context, bail};
use i18n_embed::fluent::{FluentLanguageLoader, fluent_language_loader};
use i18n_embed::{I18nAssets, LanguageLoader};
use rust_embed::RustEmbed;

/// Language code of the reference/fallback translation — same value as
/// `fallback_language` in `i18n.toml`, which `fl!` reads at compile time.
pub const FALLBACK_LANGUAGE: &str = "en";

const FILE_NAME: &str = "peach.ftl";

#[derive(RustEmbed)]
#[folder = "i18n/"]
pub struct Localizations;

/// The process-wide loader every [`crate::fl!`] call reads from. Starts out
/// English-only; [`select_language`] switches it.
pub static LOADER: LazyLock<FluentLanguageLoader> = LazyLock::new(|| {
    let loader = fluent_language_loader!();
    load(&loader, &Localizations, FALLBACK_LANGUAGE)
        .expect("the English translation is embedded in the binary");
    loader
});

/// Looks up a UI message in the current language — `fl!("message-id")` or
/// `fl!("message-id", name = value, ...)`. The message id and argument
/// names are checked against `i18n/en/peach.ftl` at compile time.
#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::i18n::LOADER, $message_id)
    }};
    ($message_id:literal, $($args:expr),*) => {{
        i18n_embed_fl::fl!($crate::i18n::LOADER, $message_id, $($args),*)
    }};
}

/// One translation shipped in the binary, for the Settings language list.
#[derive(Debug, Clone)]
pub struct LanguageInfo {
    pub code: String,
    /// The file's own `language-name`, if it sets one yet.
    pub name: Option<String>,
    pub report: catalog::Report,
}

impl LanguageInfo {
    /// A language with errors in its file is listed but can't be selected.
    pub fn is_selectable(&self) -> bool {
        !self.report.has_errors()
    }
}

/// Every embedded translation, English first, the rest by code.
pub fn available_languages() -> Vec<LanguageInfo> {
    languages_in(&Localizations)
}

/// Switches the UI to `code` (`None` means English). Refuses an unknown
/// language or one whose file has errors and leaves the current language
/// untouched in that case — the caller decides how to surface it, a broken
/// file is never loaded half-way.
pub fn select_language(code: Option<&str>) -> anyhow::Result<()> {
    select_in(&LOADER, &Localizations, code)
}

fn file_source(assets: &dyn I18nAssets, code: &str) -> Option<String> {
    let files = assets.get_files(&format!("{code}/{FILE_NAME}"));
    let bytes = files.first()?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn languages_in(assets: &dyn I18nAssets) -> Vec<LanguageInfo> {
    let reference_source = file_source(assets, FALLBACK_LANGUAGE).unwrap_or_default();
    let (reference, _) = catalog::parse_catalog(&reference_source);

    let mut codes: Vec<String> = assets
        .filenames_iter()
        .filter_map(|path| {
            let (code, file) = path.split_once('/')?;
            (file == FILE_NAME).then(|| code.to_string())
        })
        .collect();
    codes.sort();
    codes.dedup();
    codes.sort_by_key(|code| code != FALLBACK_LANGUAGE);

    codes
        .into_iter()
        .map(|code| {
            let source = file_source(assets, &code).unwrap_or_default();
            let mut report = catalog::check(&reference, &source);
            // A code that isn't a valid language identifier can't be
            // loaded at all — same consequence as a broken file.
            if code
                .parse::<i18n_embed::unic_langid::LanguageIdentifier>()
                .is_err()
            {
                report
                    .errors
                    .push(catalog::CatalogError::InvalidLanguageCode { code: code.clone() });
            }
            LanguageInfo {
                name: catalog::plain_text_message(&source, "language-name"),
                code,
                report,
            }
        })
        .collect()
}

fn select_in(
    loader: &FluentLanguageLoader,
    assets: &dyn I18nAssets,
    code: Option<&str>,
) -> anyhow::Result<()> {
    let code = code.unwrap_or(FALLBACK_LANGUAGE);
    let Some(info) = languages_in(assets).into_iter().find(|l| l.code == code) else {
        bail!("language \"{code}\" is not available");
    };
    if !info.is_selectable() {
        bail!("the translation file for \"{code}\" has errors");
    }
    load(loader, assets, code)
}

fn load(loader: &FluentLanguageLoader, assets: &dyn I18nAssets, code: &str) -> anyhow::Result<()> {
    let language = code
        .parse()
        .with_context(|| format!("\"{code}\" is not a valid language code"))?;
    loader
        .load_languages(assets, &[language])
        .with_context(|| format!("failed to load the \"{code}\" translation"))?;
    // Fluent wraps every placeholder in Unicode direction-isolation marks by
    // default, which egui renders as visible boxes. Has to be reapplied
    // after each load: it's a per-bundle setting.
    loader.set_use_isolating(false);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `en` (reference), `zz` (partial, valid), `yy` (broken) — an
    /// artificial set kept apart from the shipped files, so these tests
    /// pin down the mechanics without depending on real translations.
    #[derive(RustEmbed)]
    #[folder = "tests/fixtures/i18n/"]
    struct FixtureLocalizations;

    fn fixture_loader() -> FluentLanguageLoader {
        let loader = FluentLanguageLoader::new("peach", FALLBACK_LANGUAGE.parse().unwrap());
        load(&loader, &FixtureLocalizations, FALLBACK_LANGUAGE).unwrap();
        loader
    }

    #[test]
    fn fixture_languages_are_listed_english_first() {
        let codes: Vec<String> = languages_in(&FixtureLocalizations)
            .into_iter()
            .map(|l| l.code)
            .collect();
        assert_eq!(codes, vec!["en", "yy", "zz"]);
    }

    #[test]
    fn a_translated_message_is_shown_in_the_selected_language() {
        let loader = fixture_loader();
        select_in(&loader, &FixtureLocalizations, Some("zz")).unwrap();
        assert_eq!(loader.get("greeting"), "[ZZ] Hello");
    }

    #[test]
    fn an_untranslated_message_falls_back_to_english() {
        let loader = fixture_loader();
        select_in(&loader, &FixtureLocalizations, Some("zz")).unwrap();
        assert_eq!(loader.get("farewell"), "Goodbye");
    }

    #[test]
    fn placeholders_render_without_isolation_marks() {
        let loader = fixture_loader();
        select_in(&loader, &FixtureLocalizations, Some("zz")).unwrap();
        let args = std::collections::HashMap::from([("count", 3)]);
        assert_eq!(loader.get_args("skipped", args), "[ZZ] 3 skipped");
    }

    #[test]
    fn a_broken_language_is_refused_and_the_current_one_stays() {
        let loader = fixture_loader();
        select_in(&loader, &FixtureLocalizations, Some("zz")).unwrap();
        assert!(select_in(&loader, &FixtureLocalizations, Some("yy")).is_err());
        assert_eq!(loader.get("greeting"), "[ZZ] Hello");
    }

    #[test]
    fn an_unknown_language_is_refused() {
        let loader = fixture_loader();
        assert!(select_in(&loader, &FixtureLocalizations, Some("xx")).is_err());
        assert_eq!(loader.get("greeting"), "Hello");
    }

    #[test]
    fn selecting_none_goes_back_to_english() {
        let loader = fixture_loader();
        select_in(&loader, &FixtureLocalizations, Some("zz")).unwrap();
        select_in(&loader, &FixtureLocalizations, None).unwrap();
        assert_eq!(loader.get("greeting"), "Hello");
    }

    #[test]
    fn language_info_reports_name_coverage_and_selectability() {
        let languages = languages_in(&FixtureLocalizations);
        let zz = languages.iter().find(|l| l.code == "zz").unwrap();
        assert_eq!(zz.name.as_deref(), Some("Zedish"));
        assert!(zz.is_selectable());
        assert!(zz.report.coverage_percent() < 100);
        let yy = languages.iter().find(|l| l.code == "yy").unwrap();
        assert!(!yy.is_selectable());
    }

    #[test]
    fn the_global_loader_starts_in_english() {
        assert_eq!(crate::fl!("common-save"), "Save");
        assert_eq!(
            crate::fl!("settings-load-threads-on-this-machine", count = 4),
            "(4 on this machine)"
        );
    }

    /// The same hard checks CI's `i18n_check` report applies, run on every
    /// platform as part of `cargo test`: a shipped translation with errors
    /// fails the build, a merely incomplete one doesn't.
    #[test]
    fn shipped_translations_have_no_errors() {
        let languages = available_languages();
        assert!(languages.iter().any(|l| l.code == FALLBACK_LANGUAGE));
        let problems: Vec<String> = languages
            .iter()
            .flat_map(|l| {
                l.report.errors.iter().map(move |e| match e.line() {
                    Some(line) => format!("i18n/{}/{FILE_NAME}:{line}: {e}", l.code),
                    None => format!("i18n/{}/{FILE_NAME}: {e}", l.code),
                })
            })
            .collect();
        assert!(problems.is_empty(), "\n{}", problems.join("\n"));
    }

    #[test]
    fn the_english_reference_is_complete_and_named() {
        let english = &available_languages()[0];
        assert_eq!(english.code, FALLBACK_LANGUAGE);
        assert_eq!(english.name.as_deref(), Some("English"));
        assert_eq!(english.report.coverage_percent(), 100);
    }
}
