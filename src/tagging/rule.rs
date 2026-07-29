use thiserror::Error;

/// A tagging rule, deserialized from a rule TOML file. `match` can contain
/// a mix of normalized fields
/// (`sourcetype`, `level`, `message`) and source-specific fields (e.g. AUL
/// `subsystem`, EVTX `event_id`) — anything not recognized as normalized is
/// looked up in the entry's `fields` JSON. All conditions in one rule must
/// hold (AND) for it to match.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Rule {
    pub rule: RuleBody,
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
        Ok(toml::from_str(s)?)
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
                other => fields
                    .get(other)
                    .is_some_and(|actual| toml_matches_json(expected, actual)),
            })
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
