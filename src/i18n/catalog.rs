//! Structural check of one translation file against the English reference
//! — pure (no loader, no egui), so the same logic backs the shipped-file
//! test, the CI report (`examples/i18n_check.rs`) and the Settings
//! dialog's per-language status.
//!
//! Splits findings into two classes on purpose:
//!
//! - **Errors** — the file is broken in a way that would show the analyst
//!   something wrong: invalid Fluent syntax (the bundle silently drops the
//!   broken entries), a message the English file doesn't have (never shown,
//!   most likely a typo of a real key), a duplicate message, or a
//!   placeholder mismatch (a count or path that silently goes missing or
//!   renders as an error marker). A language with errors is not selectable.
//! - **Missing messages** — not translated yet. Not an error: the UI falls
//!   back to the English text for exactly those messages, and coverage
//!   below 100% is an accepted state for every language.

use std::collections::{BTreeMap, BTreeSet};

use fluent_syntax::ast;

/// Message id → the `$variables` it references anywhere in its value or
/// attributes, all select-expression variants included.
pub type Catalog = BTreeMap<String, BTreeSet<String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    /// Invalid Fluent syntax, with the 1-based line it starts on.
    Syntax { line: usize, message: String },
    /// The directory name isn't a valid language code, so the file can't
    /// be loaded at all.
    InvalidLanguageCode { code: String },
    /// Message defined more than once in the same file.
    Duplicate { id: String },
    /// Message the English reference doesn't define.
    Orphaned { id: String },
    /// The translation's set of `$variables` differs from the English one.
    PlaceholderMismatch {
        id: String,
        expected: BTreeSet<String>,
        found: BTreeSet<String>,
    },
}

impl CatalogError {
    /// The 1-based line a syntax error starts on; `None` for the other
    /// kinds, which are about a whole message rather than a position.
    pub fn line(&self) -> Option<usize> {
        match self {
            Self::Syntax { line, .. } => Some(*line),
            _ => None,
        }
    }
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax { message, .. } => write!(f, "syntax error: {message}"),
            Self::InvalidLanguageCode { code } => write!(
                f,
                "\"{code}\" is not a valid language code (directory name under i18n/)"
            ),
            Self::Duplicate { id } => write!(f, "\"{id}\" is defined more than once"),
            Self::Orphaned { id } => write!(
                f,
                "\"{id}\" does not exist in the English file (typo, or a key that was renamed/removed)"
            ),
            Self::PlaceholderMismatch {
                id,
                expected,
                found,
            } => write!(
                f,
                "\"{id}\" uses placeholders {} but the English text uses {}",
                format_vars(found),
                format_vars(expected)
            ),
        }
    }
}

fn format_vars(vars: &BTreeSet<String>) -> String {
    if vars.is_empty() {
        return "(none)".to_string();
    }
    vars.iter()
        .map(|v| format!("{{ ${v} }}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parses one `.ftl` file into a [`Catalog`]. Syntax errors and duplicate
/// messages are returned alongside whatever did parse — a single broken
/// entry shouldn't hide every other finding in the same file.
pub fn parse_catalog(source: &str) -> (Catalog, Vec<CatalogError>) {
    let mut errors = Vec::new();
    let resource = match fluent_syntax::parser::parse(source) {
        Ok(resource) => resource,
        Err((resource, parse_errors)) => {
            errors.extend(parse_errors.into_iter().map(|err| CatalogError::Syntax {
                line: line_of(source, err.pos.start),
                message: err.kind.to_string(),
            }));
            resource
        }
    };

    let mut catalog = Catalog::new();
    for entry in &resource.body {
        let ast::Entry::Message(message) = entry else {
            continue;
        };
        let mut vars = BTreeSet::new();
        if let Some(value) = &message.value {
            collect_pattern_vars(value, &mut vars);
        }
        for attribute in &message.attributes {
            collect_pattern_vars(&attribute.value, &mut vars);
        }
        let id = message.id.name.to_string();
        if catalog.insert(id.clone(), vars).is_some() {
            errors.push(CatalogError::Duplicate { id });
        }
    }
    (catalog, errors)
}

fn line_of(source: &str, byte_offset: usize) -> usize {
    source[..byte_offset.min(source.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

fn collect_pattern_vars(pattern: &ast::Pattern<&str>, vars: &mut BTreeSet<String>) {
    for element in &pattern.elements {
        if let ast::PatternElement::Placeable { expression } = element {
            collect_expression_vars(expression, vars);
        }
    }
}

fn collect_expression_vars(expression: &ast::Expression<&str>, vars: &mut BTreeSet<String>) {
    match expression {
        ast::Expression::Select { selector, variants } => {
            collect_inline_vars(selector, vars);
            for variant in variants {
                collect_pattern_vars(&variant.value, vars);
            }
        }
        ast::Expression::Inline(inline) => collect_inline_vars(inline, vars),
    }
}

fn collect_inline_vars(inline: &ast::InlineExpression<&str>, vars: &mut BTreeSet<String>) {
    match inline {
        ast::InlineExpression::VariableReference { id } => {
            vars.insert(id.name.to_string());
        }
        ast::InlineExpression::FunctionReference { arguments, .. } => {
            collect_call_vars(arguments, vars);
        }
        ast::InlineExpression::TermReference {
            arguments: Some(arguments),
            ..
        } => collect_call_vars(arguments, vars),
        ast::InlineExpression::Placeable { expression } => {
            collect_expression_vars(expression, vars);
        }
        _ => {}
    }
}

fn collect_call_vars(arguments: &ast::CallArguments<&str>, vars: &mut BTreeSet<String>) {
    for positional in &arguments.positional {
        collect_inline_vars(positional, vars);
    }
    for named in &arguments.named {
        collect_inline_vars(&named.value, vars);
    }
}

/// The value of message `id` if it's plain text (no placeholders) — used
/// for `language-name`, read straight from a file rather than through a
/// loader, since a loader would fall back to the English name.
pub fn plain_text_message(source: &str, id: &str) -> Option<String> {
    let resource = match fluent_syntax::parser::parse(source) {
        Ok(resource) | Err((resource, _)) => resource,
    };
    resource.body.iter().find_map(|entry| {
        let ast::Entry::Message(message) = entry else {
            return None;
        };
        if message.id.name != id {
            return None;
        }
        let mut text = String::new();
        for element in &message.value.as_ref()?.elements {
            match element {
                ast::PatternElement::TextElement { value } => text.push_str(value),
                ast::PatternElement::Placeable { .. } => return None,
            }
        }
        let text = text.trim().to_string();
        (!text.is_empty()).then_some(text)
    })
}

/// Result of checking one translation against the English reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub errors: Vec<CatalogError>,
    /// English message ids this translation doesn't define (yet).
    pub missing: Vec<String>,
    /// Messages translated, out of `total` in the English reference.
    pub translated: usize,
    pub total: usize,
}

impl Report {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Whole-number coverage percentage, rounded down — so "100" only ever
    /// means every message is actually translated.
    pub fn coverage_percent(&self) -> usize {
        if self.total == 0 {
            return 100;
        }
        self.translated * 100 / self.total
    }
}

/// Checks `translation_source` against the already-parsed English
/// `reference`.
pub fn check(reference: &Catalog, translation_source: &str) -> Report {
    let (translation, mut errors) = parse_catalog(translation_source);

    for (id, found) in &translation {
        match reference.get(id) {
            None => errors.push(CatalogError::Orphaned { id: id.clone() }),
            Some(expected) if expected != found => {
                errors.push(CatalogError::PlaceholderMismatch {
                    id: id.clone(),
                    expected: expected.clone(),
                    found: found.clone(),
                });
            }
            Some(_) => {}
        }
    }

    let missing: Vec<String> = reference
        .keys()
        .filter(|id| !translation.contains_key(*id))
        .cloned()
        .collect();
    Report {
        errors,
        translated: reference.len() - missing.len(),
        total: reference.len(),
        missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> Catalog {
        let (catalog, errors) = parse_catalog(
            "hello = Hello\n\
             skipped = { $count ->\n    [one] One record skipped\n   *[other] { $count } records skipped\n}\n\
             path-label = (default) { $path }\n",
        );
        assert!(errors.is_empty(), "{errors:?}");
        catalog
    }

    #[test]
    fn parse_catalog_collects_variables_from_select_variants() {
        let catalog = reference();
        assert_eq!(catalog["hello"], BTreeSet::new());
        assert_eq!(catalog["skipped"], BTreeSet::from(["count".to_string()]));
        assert_eq!(catalog["path-label"], BTreeSet::from(["path".to_string()]));
    }

    #[test]
    fn parse_catalog_ignores_terms_and_comments() {
        let (catalog, errors) =
            parse_catalog("# comment\n-brand = Peach\nabout = About { -brand }\n");
        assert!(errors.is_empty());
        assert_eq!(catalog.keys().collect::<Vec<_>>(), vec!["about"]);
    }

    #[test]
    fn an_empty_translation_has_no_errors_and_zero_coverage() {
        let report = check(&reference(), "# Translation not started yet.\n");
        assert!(!report.has_errors());
        assert_eq!(report.translated, 0);
        assert_eq!(report.total, 3);
        assert_eq!(report.coverage_percent(), 0);
        assert_eq!(report.missing, vec!["hello", "path-label", "skipped"]);
    }

    #[test]
    fn a_partial_translation_is_not_an_error() {
        let report = check(&reference(), "hello = Hallo\n");
        assert!(!report.has_errors());
        assert_eq!(report.coverage_percent(), 33);
        assert_eq!(report.missing, vec!["path-label", "skipped"]);
    }

    #[test]
    fn coverage_only_reaches_100_when_everything_is_translated() {
        let report = check(
            &reference(),
            "hello = Hallo\n\
             skipped = { $count } übersprungen\n\
             path-label = (Standard) { $path }\n",
        );
        assert!(!report.has_errors());
        assert_eq!(report.coverage_percent(), 100);
    }

    #[test]
    fn a_syntax_error_is_reported_with_its_line_number() {
        let report = check(&reference(), "hello = Hallo\npath-label (Standard)\n");
        assert_eq!(report.errors.len(), 1);
        assert!(
            matches!(report.errors[0], CatalogError::Syntax { line: 2, .. }),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn an_unknown_key_is_an_orphan_error() {
        let report = check(&reference(), "helo = Hallo\n");
        assert_eq!(
            report.errors,
            vec![CatalogError::Orphaned {
                id: "helo".to_string()
            }]
        );
    }

    #[test]
    fn a_misspelled_placeholder_is_an_error() {
        let report = check(&reference(), "path-label = (Standard) { $pfad }\n");
        assert!(matches!(
            report.errors.as_slice(),
            [CatalogError::PlaceholderMismatch { id, .. }] if id == "path-label"
        ));
    }

    #[test]
    fn a_dropped_placeholder_is_an_error() {
        let report = check(&reference(), "path-label = (Standard)\n");
        assert!(matches!(
            report.errors.as_slice(),
            [CatalogError::PlaceholderMismatch { .. }]
        ));
    }

    #[test]
    fn a_plural_variant_without_the_number_is_fine_if_another_variant_uses_it() {
        let report = check(
            &reference(),
            "skipped = { $count ->\n    [one] Ein Datensatz übersprungen\n   *[other] { $count } Datensätze übersprungen\n}\n",
        );
        assert!(!report.has_errors(), "{:?}", report.errors);
    }

    #[test]
    fn a_duplicate_key_is_an_error() {
        let report = check(&reference(), "hello = Hallo\nhello = Servus\n");
        assert_eq!(
            report.errors,
            vec![CatalogError::Duplicate {
                id: "hello".to_string()
            }]
        );
    }

    #[test]
    fn errors_render_as_readable_sentences() {
        let error = CatalogError::PlaceholderMismatch {
            id: "path-label".to_string(),
            expected: BTreeSet::from(["path".to_string()]),
            found: BTreeSet::from(["pfad".to_string()]),
        };
        assert_eq!(
            error.to_string(),
            "\"path-label\" uses placeholders { $pfad } but the English text uses { $path }"
        );
    }
}
