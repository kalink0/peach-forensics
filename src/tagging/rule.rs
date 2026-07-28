use thiserror::Error;

use crate::model::log_entry::LogEntry;

/// A tagging rule, deserialized from a rule TOML file (section 6 of
/// CLAUDE.md). `match` can contain a mix of normalized fields
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

    /// `sourcetype` is passed in separately since [`LogEntry`] doesn't
    /// carry it — the parser/config that produced the entry knows it.
    pub fn matches(&self, entry: &LogEntry, sourcetype: &str) -> bool {
        self.rule
            .match_fields
            .iter()
            .all(|(key, expected)| match key.as_str() {
                "sourcetype" => expected.as_str() == Some(sourcetype),
                "level" => entry
                    .level
                    .as_deref()
                    .is_some_and(|actual| expected.as_str() == Some(actual)),
                "message" => entry
                    .message
                    .as_deref()
                    .is_some_and(|actual| expected.as_str() == Some(actual)),
                other => entry
                    .fields
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
    use crate::model::event_id::{EventId, SequenceNumber, SourceFileId};
    use chrono::Utc;

    fn sample_entry(
        level: Option<&str>,
        message: Option<&str>,
        fields: serde_json::Value,
    ) -> LogEntry {
        LogEntry {
            event_id: EventId {
                source_file_id: SourceFileId::new_random(),
                sequence_number: SequenceNumber::from_raw(0),
            },
            timestamp_utc: Utc::now(),
            level: level.map(str::to_string),
            message: message.map(str::to_string),
            raw: "raw".to_string(),
            fields,
        }
    }

    #[test]
    fn parses_the_evtx_style_example_from_claude_md() {
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
    fn parses_the_generic_level_example_from_claude_md() {
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

        let matching = sample_entry(Some("ERROR"), None, serde_json::Value::Null);
        let non_matching = sample_entry(Some("INFO"), None, serde_json::Value::Null);
        let missing = sample_entry(None, None, serde_json::Value::Null);

        assert!(rule.matches(&matching, "text_config"));
        assert!(!rule.matches(&non_matching, "text_config"));
        assert!(!rule.matches(&missing, "text_config"));
    }

    #[test]
    fn matches_on_sourcetype() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let entry = sample_entry(None, None, serde_json::Value::Null);

        assert!(rule.matches(&entry, "aul"));
        assert!(!rule.matches(&entry, "evtx"));
    }

    #[test]
    fn matches_on_source_specific_field_in_fields_json() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"failed_logon\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_id = 4625\n[rule.tag]\nvalue = \"auth_failure\"\n",
        )
        .unwrap();

        let matching = sample_entry(None, None, serde_json::json!({"event_id": 4625}));
        let wrong_id = sample_entry(None, None, serde_json::json!({"event_id": 4624}));
        let missing_field = sample_entry(None, None, serde_json::json!({}));

        assert!(rule.matches(&matching, "evtx"));
        assert!(!rule.matches(&wrong_id, "evtx"));
        assert!(!rule.matches(&missing_field, "evtx"));
    }

    #[test]
    fn all_conditions_must_match() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"evtx\"\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let both_match = sample_entry(Some("ERROR"), None, serde_json::Value::Null);
        let only_level_matches = sample_entry(Some("ERROR"), None, serde_json::Value::Null);

        assert!(rule.matches(&both_match, "evtx"));
        assert!(!rule.matches(&only_level_matches, "text_config"));
    }
}
