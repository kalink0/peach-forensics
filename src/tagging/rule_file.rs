//! Creating and extending `message_contains` tagging rules from the UI
//! (right-click "tag all matching") — a different concern from
//! [`crate::tagging::rule::Rule`], which only ever *reads* a rule file.
//!
//! Extending an existing rule's pattern list goes through `toml_edit`
//! rather than `toml`'s own (de)serialization: the shipped `rules/examples/
//! aul_*.toml` files carry hand-written provenance comments (where each
//! pattern was ported from), and a plain parse-mutate-reserialize round
//! trip through `toml::Value` would silently drop every comment in the
//! file. `toml_edit` preserves formatting/comments for the parts it
//! doesn't touch.

use std::path::{Path, PathBuf};

use anyhow::Context;
use directories::ProjectDirs;
use toml_edit::{Array, DocumentMut, Item, Value};

/// Default per-user directory for rules created from the UI (right-click
/// "tag all matching") — same `ProjectDirs` layout as
/// [`crate::session::persist::default_sessions_dir`], a sibling `rules`
/// directory rather than `rules/examples/` (that one ships in the repo as
/// a read-only reference library, not a place to write into).
pub fn default_user_rules_dir() -> anyhow::Result<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "peach")
        .context("could not determine a per-user data directory on this platform")?;
    let dir = project_dirs.data_dir().join("rules");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create rules directory {}", dir.display()))?;
    Ok(dir)
}

/// Turns a rule/tag name into a filesystem-safe file stem: lowercase,
/// non-alphanumeric runs collapsed to a single underscore, trimmed — so
/// "Screen Lock!" and "screen_lock" both land on `screen_lock.toml`
/// instead of silently becoming two different files or an invalid path.
pub fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut last_was_underscore = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_underscore = false;
        } else if !last_was_underscore && !slug.is_empty() {
            slug.push('_');
            last_was_underscore = true;
        }
    }
    while slug.ends_with('_') {
        slug.pop();
    }
    if slug.is_empty() {
        "rule".to_string()
    } else {
        slug
    }
}

/// Writes a brand-new single-pattern `message_contains` rule file. Used
/// when the analyst picks "New tag..." in the tagging UI — there's no
/// existing file to preserve formatting in, so a plain string template is
/// enough (unlike [`append_message_contains_pattern`]).
///
/// Deliberately not scoped to a `sourcetype`: the analyst is tagging by
/// message content across whatever's loaded, same as the "generic,
/// cross-source" example in the tagging docs — a level or subsystem
/// condition can always be added by hand-editing the resulting file.
pub fn create_message_contains_rule(
    path: &Path,
    rule_name: &str,
    pattern: &str,
    tag_value: &str,
) -> anyhow::Result<()> {
    let escaped_pattern = escape_toml_string(pattern);
    let contents = format!(
        "[rule]\nname = \"{rule_name}\"\ndescription = \"Created from the timeline's advanced tagging dialog\"\n\n[rule.match]\nmessage_contains = \"{escaped_pattern}\"\n\n[rule.tag]\nvalue = \"{tag_value}\"\n",
    );
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write new rule file {}", path.display()))
}

/// Adds `pattern` to an existing rule file's `message_contains` list (a
/// bare string is normalized into a one-element array first), unless it's
/// already present. Preserves every comment and unrelated table in the
/// file.
pub fn append_message_contains_pattern(path: &Path, pattern: &str) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read rule file {}", path.display()))?;
    let mut doc = text
        .parse::<DocumentMut>()
        .with_context(|| format!("failed to parse rule file {} as TOML", path.display()))?;

    let match_table = doc
        .get_mut("rule")
        .and_then(|rule| rule.get_mut("match"))
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| anyhow::anyhow!("{} has no [rule.match] table", path.display()))?;

    match match_table.get_mut("message_contains") {
        Some(item) => {
            let existing = item.as_value().cloned().ok_or_else(|| {
                anyhow::anyhow!("message_contains in {} is not a value", path.display())
            })?;
            match existing {
                Value::Array(mut array) => {
                    let already_present = array.iter().any(|v| v.as_str() == Some(pattern));
                    if !already_present {
                        array.push(pattern);
                        *item = Item::Value(Value::Array(array));
                    }
                }
                Value::String(existing) => {
                    if existing.value() != pattern {
                        let mut array = Array::new();
                        array.push(existing.value().as_str());
                        array.push(pattern);
                        *item = Item::Value(Value::Array(array));
                    }
                }
                other => anyhow::bail!(
                    "message_contains in {} is a {}, expected a string or array",
                    path.display(),
                    other.type_name()
                ),
            }
        }
        None => {
            let mut array = Array::new();
            array.push(pattern);
            match_table.insert("message_contains", Item::Value(Value::Array(array)));
        }
    }

    std::fs::write(path, doc.to_string())
        .with_context(|| format!("failed to write rule file {}", path.display()))
}

/// TOML basic strings only need `\` and `"` escaped for the values this
/// module writes (plain substrings, no control characters expected from
/// UI-entered text).
fn escape_toml_string(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagging::rule::Rule;

    #[test]
    fn slugify_lowercases_and_collapses_separators() {
        assert_eq!(slugify("Screen Lock!"), "screen_lock");
        assert_eq!(slugify("screen_lock"), "screen_lock");
        assert_eq!(slugify("  wifi -- status  "), "wifi_status");
    }

    #[test]
    fn slugify_never_produces_an_empty_or_trailing_underscore_string() {
        assert_eq!(slugify("!!!"), "rule");
        assert_eq!(slugify(""), "rule");
        assert_eq!(slugify("trailing---"), "trailing");
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "peach-rule-file-test-{}-{}-{name}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn create_message_contains_rule_produces_a_parseable_matching_rule() {
        let path = temp_path("create");
        create_message_contains_rule(&path, "my_rule", "Screen did lock", "screen_lock").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let rule = Rule::from_toml_str(&text).unwrap();

        assert_eq!(rule.rule.name, "my_rule");
        assert_eq!(rule.rule.tag.value, "screen_lock");
        assert!(rule.matches(
            "aul",
            None,
            Some("Screen did lock now"),
            &serde_json::Value::Null
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn append_turns_a_bare_string_into_an_array_and_keeps_matching() {
        let path = temp_path("append-scalar");
        create_message_contains_rule(&path, "my_rule", "Screen did lock", "screen_lock").unwrap();

        append_message_contains_pattern(&path, "screen is unlocked").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let rule = Rule::from_toml_str(&text).unwrap();
        let null = serde_json::Value::Null;
        assert!(rule.matches("aul", None, Some("Screen did lock now"), &null));
        assert!(rule.matches("aul", None, Some("the screen is unlocked"), &null));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn append_extends_an_existing_array_without_duplicating() {
        let path = temp_path("append-array");
        std::fs::write(
            &path,
            "[rule]\nname = \"r\"\n[rule.match]\nsourcetype = \"aul\"\nmessage_contains = [\"a\", \"b\"]\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        append_message_contains_pattern(&path, "c").unwrap();
        append_message_contains_pattern(&path, "a").unwrap(); // already present

        let text = std::fs::read_to_string(&path).unwrap();
        let rule = Rule::from_toml_str(&text).unwrap();
        let null = serde_json::Value::Null;
        assert!(rule.matches("aul", None, Some("has a in it"), &null));
        assert!(rule.matches("aul", None, Some("has c in it"), &null));
        assert_eq!(
            text.matches("\"a\"").count(),
            1,
            "must not duplicate an existing pattern"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn append_preserves_unrelated_comments_in_the_file() {
        let path = temp_path("append-comments");
        std::fs::write(
            &path,
            "# provenance comment\n[rule]\nname = \"r\"\ndescription = \"d\"\n[rule.match]\nsourcetype = \"aul\"\nmessage_contains = \"a\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        append_message_contains_pattern(&path, "b").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# provenance comment"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn create_message_contains_rule_escapes_quotes_and_backslashes_in_the_pattern() {
        let path = temp_path("escape");
        create_message_contains_rule(&path, "r", r#"say "hi" \ ok"#, "t").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let rule = Rule::from_toml_str(&text).unwrap();
        assert!(rule.matches(
            "aul",
            None,
            Some(r#"prefix say "hi" \ ok suffix"#),
            &serde_json::Value::Null
        ));
        std::fs::remove_file(&path).unwrap();
    }
}
