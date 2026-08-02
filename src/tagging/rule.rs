use thiserror::Error;

/// A tagging rule, deserialized from a rule TOML file. `match` can contain
/// a mix of normalized fields
/// (`sourcetype`, `level`, `message`) and source-specific fields (e.g. AUL
/// `subsystem`, EVTX `event_id`) — anything not recognized as normalized is
/// looked up in the entry's `fields` JSON. All conditions in one rule must
/// hold (AND) for it to match.
///
/// `message_contains` is a substring variant of `message`: the value is
/// either a single string or an array of strings, and the rule matches if
/// `message` contains *any* of them. This exists because most real-world
/// pattern-of-life categorization (see the AUL rule pack under
/// `rules/examples/`) keys off recognizable substrings in free-text log
/// messages, not off exact equality or structured fields — matching the
/// approach forensic tools like iLEAPP use for the same Apple Unified Log
/// data.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Rule {
    pub rule: RuleBody,
    /// `message_contains` needles, precomputed once from
    /// `rule.match_fields` here at parse time rather than rebuilt on every
    /// [`Rule::matches`] call. Import-time tagging runs `matches()` once per
    /// (entry, rule) pair — millions of times for a large AUL load — so
    /// re-deriving this `Vec` from the TOML value on every call would mean
    /// millions of redundant allocations for a list that never changes
    /// after the rule is loaded.
    #[serde(skip)]
    message_contains_needles: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RuleBody {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "match")]
    pub match_fields: toml::Table,
    pub tag: TagSpec,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TagSpec {
    pub value: String,
}

#[derive(Debug, Error)]
#[error("invalid tagging rule: {0}")]
pub struct RuleParseError(#[from] toml::de::Error);

impl Rule {
    pub fn from_toml_str(s: &str) -> Result<Self, RuleParseError> {
        let mut rule: Rule = toml::from_str(s)?;
        rule.message_contains_needles = rule
            .rule
            .match_fields
            .get("message_contains")
            .map(|value| {
                toml_value_as_strings(value)
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Ok(rule)
    }

    /// Takes the pieces of an entry that matching actually needs, rather
    /// than a full `LogEntry` — re-tagging streams rows straight out of
    /// DuckDB and shouldn't have to materialize `raw`/`timestamp_utc`/
    /// `event_id` just to call this.
    pub fn matches(
        &self,
        sourcetype: &str,
        level: Option<&str>,
        message: Option<&str>,
        fields: &serde_json::Value,
    ) -> bool {
        self.rule
            .match_fields
            .iter()
            .all(|(key, expected)| match key.as_str() {
                "sourcetype" => expected.as_str() == Some(sourcetype),
                "level" => level.is_some_and(|actual| expected.as_str() == Some(actual)),
                "message" => message.is_some_and(|actual| expected.as_str() == Some(actual)),
                "message_contains" => message.is_some_and(|actual| {
                    self.message_contains_needles
                        .iter()
                        .any(|needle| actual.contains(needle.as_str()))
                }),
                other => fields
                    .get(other)
                    .is_some_and(|actual| toml_matches_json(expected, actual)),
            })
    }
}

/// Reads `message_contains`'s value as a list of substrings to search for,
/// accepting either a bare string or an array of strings. Any other shape
/// (e.g. an integer) yields an empty list, so a malformed rule simply never
/// matches rather than panicking.
fn toml_value_as_strings(value: &toml::Value) -> Vec<&str> {
    match value {
        toml::Value::String(s) => vec![s.as_str()],
        toml::Value::Array(items) => items.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn toml_matches_json(expected: &toml::Value, actual: &serde_json::Value) -> bool {
    match (expected, actual) {
        (toml::Value::String(e), serde_json::Value::String(a)) => e == a,
        (toml::Value::Integer(e), serde_json::Value::Number(a)) => a.as_i64() == Some(*e),
        (toml::Value::Float(e), serde_json::Value::Number(a)) => a.as_f64() == Some(*e),
        (toml::Value::Boolean(e), serde_json::Value::Bool(a)) => e == a,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shipped rule file in `rules/examples/` (the AUL
    /// pattern-of-life pack, see `docs/`) must parse and have a non-empty
    /// name/tag — a broken TOML file in there would otherwise only surface
    /// when an analyst actually tries to load it in the app.
    #[test]
    fn every_shipped_rule_file_parses() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/examples");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let rule = Rule::from_toml_str(&text)
                .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
            assert!(!rule.rule.name.is_empty(), "{}: empty name", path.display());
            assert!(
                !rule.rule.tag.value.is_empty(),
                "{}: empty tag value",
                path.display()
            );
            checked += 1;
        }
        assert!(checked > 0, "no rule files found in {}", dir.display());
    }

    #[test]
    fn parses_the_evtx_style_example() {
        let toml_text = r#"
[rule]
name = "failed_logon"
description = "Windows fehlgeschlagene Anmeldung"

[rule.match]
sourcetype = "evtx"
event_id = 4625

[rule.tag]
value = "auth_failure"
"#;
        let rule = Rule::from_toml_str(toml_text).unwrap();

        assert_eq!(rule.rule.name, "failed_logon");
        assert_eq!(rule.rule.tag.value, "auth_failure");
        assert_eq!(
            rule.rule
                .match_fields
                .get("sourcetype")
                .and_then(|v| v.as_str()),
            Some("evtx")
        );
    }

    #[test]
    fn parses_the_generic_level_example() {
        let toml_text = r#"
[rule]
name = "generic_error"
description = "Cross-Source: alles mit level=ERROR"

[rule.match]
level = "ERROR"

[rule.tag]
value = "error"
"#;
        let rule = Rule::from_toml_str(toml_text).unwrap();

        assert_eq!(rule.rule.name, "generic_error");
        assert_eq!(rule.rule.tag.value, "error");
    }

    #[test]
    fn malformed_rule_toml_is_an_error_not_a_panic() {
        let result = Rule::from_toml_str("this is not valid toml [[[");

        assert!(result.is_err());
    }

    #[test]
    fn matches_on_generic_level_field() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"error\"\n",
        )
        .unwrap();

        let null = serde_json::Value::Null;
        assert!(rule.matches("text_config", Some("ERROR"), None, &null));
        assert!(!rule.matches("text_config", Some("INFO"), None, &null));
        assert!(!rule.matches("text_config", None, None, &null));
    }

    #[test]
    fn matches_on_sourcetype() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let null = serde_json::Value::Null;

        assert!(rule.matches("aul", None, None, &null));
        assert!(!rule.matches("evtx", None, None, &null));
    }

    #[test]
    fn matches_on_source_specific_field_in_fields_json() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"failed_logon\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_id = 4625\n[rule.tag]\nvalue = \"auth_failure\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({"event_id": 4625});
        let wrong_id = serde_json::json!({"event_id": 4624});
        let missing_field = serde_json::json!({});

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &wrong_id));
        assert!(!rule.matches("evtx", None, None, &missing_field));
    }

    #[test]
    fn matches_message_contains_against_array_of_substrings() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"screen_lock\"\n[rule.match]\nmessage_contains = [\"Screen did lock\", \"screen is unlocked\"]\n[rule.tag]\nvalue = \"screen_lock_state\"\n",
        )
        .unwrap();
        let null = serde_json::Value::Null;

        assert!(rule.matches("aul", None, Some("Screen did lock now"), &null));
        assert!(rule.matches("aul", None, Some("the screen is unlocked"), &null));
        assert!(!rule.matches("aul", None, Some("unrelated message"), &null));
        assert!(!rule.matches("aul", None, None, &null));
    }

    #[test]
    fn matches_message_contains_against_a_single_bare_string() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"flashlight\"\n[rule.match]\nmessage_contains = \"[Flashlight Controller]\"\n[rule.tag]\nvalue = \"flashlight\"\n",
        )
        .unwrap();
        let null = serde_json::Value::Null;

        assert!(rule.matches("aul", None, Some("[Flashlight Controller] on"), &null));
        assert!(!rule.matches("aul", None, Some("unrelated"), &null));
    }

    #[test]
    fn message_contains_needles_are_precomputed_once_at_parse_time() {
        let array_rule = Rule::from_toml_str(
            "[rule]\nname = \"a\"\n[rule.match]\nmessage_contains = [\"foo\", \"bar\"]\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert_eq!(array_rule.message_contains_needles, vec!["foo", "bar"]);

        let bare_string_rule = Rule::from_toml_str(
            "[rule]\nname = \"b\"\n[rule.match]\nmessage_contains = \"foo\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert_eq!(bare_string_rule.message_contains_needles, vec!["foo"]);

        let no_message_contains_rule = Rule::from_toml_str(
            "[rule]\nname = \"c\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert!(no_message_contains_rule.message_contains_needles.is_empty());
    }

    #[test]
    fn message_contains_with_non_string_value_never_matches() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"bad\"\n[rule.match]\nmessage_contains = 42\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        assert!(!rule.matches("aul", None, Some("anything"), &serde_json::Value::Null));
    }

    #[test]
    fn all_conditions_must_match() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"evtx\"\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let null = serde_json::Value::Null;

        assert!(rule.matches("evtx", Some("ERROR"), None, &null));
        assert!(!rule.matches("text_config", Some("ERROR"), None, &null));
    }
}
