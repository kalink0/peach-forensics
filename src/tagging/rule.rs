use thiserror::Error;

/// A tagging rule, deserialized from a rule TOML file. `match` can contain
/// a mix of normalized fields (`sourcetype`, `level`, `message`, `event_id`,
/// `provider`) and source-specific fields (e.g. AUL `subsystem`) — anything
/// not recognized as normalized is looked up as a flat top-level key in the
/// entry's `fields` JSON. `event_id`/`provider` need their own sourcetype-aware
/// resolution rather than that flat lookup: EVTX's `fields` nests them under
/// `Event.System` (see [`normalized_field`]), unlike AUL's genuinely flat
/// `subsystem`/`category`. All conditions in one rule must hold (AND) for it
/// to match.
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
                "event_id" | "provider" | "host" | "process" | "subsystem" | "category" => {
                    normalized_field(key, sourcetype, fields)
                        .or_else(|| fields.get(key))
                        .is_some_and(|actual| toml_matches_json(expected, actual))
                }
                other => fields
                    .get(other)
                    .is_some_and(|actual| toml_matches_json(expected, actual)),
            })
    }
}

/// Resolves normalized match keys that don't live at a flat top-level key
/// in every sourcetype's `fields` JSON to their actual sourcetype-specific
/// location — a flat `fields.get(key)` (the fallback every other
/// source-specific match key uses, and still tried second via
/// [`Rule::matches`]'s `.or_else`, e.g. for AUL's genuinely flat
/// `subsystem`/`category`/`process` or a `text_config` parser whose
/// `field_mapping` happens to produce a top-level key with the same name)
/// would never find EVTX's `event_id`/`provider`/`host`/`subsystem`
/// (nested under `Event.System`) or journald's `host`/`process` (which live
/// under `_HOSTNAME`/`SYSLOG_IDENTIFIER`/`_COMM`, not `host`/`process`).
///
/// Same paths `parsers::evtx::template_rendered_message` resolves against,
/// and the same ones `db::timeline_queries`'s `host_case_sql`/
/// `process_case_sql`/`subsystem_case_sql`/`event_code_case_sql` (backing
/// both the Host/Process/Subsystem/Event ID timeline columns and their
/// `host=`/`process=`/`subsystem=`/`event_id=` search-grammar filters)
/// already use — kept in sync with those rather than re-derived, since a
/// rule condition on one of these fields is meant to match exactly what the
/// analyst sees in that column. `provider` and `subsystem` deliberately
/// resolve to the same path: `provider` is EVTX's equivalent of AUL's
/// `subsystem` (per `docs/field-extraction.md`), and the Advanced tagging
/// dialog's "Filter by..."-derived field conditions always use the
/// normalized `subsystem` keyword, never `provider` — `provider` stays
/// accepted here only because it's the term the tagging docs' own example
/// rules use. Sourcetype/key combinations with no known nested path
/// (including AUL, which has no `event_id`/`provider` concept, only its own
/// already-flat `subsystem`/`category`/`process`) resolve to `None`, same
/// as an absent generic field — the `.or_else(|| fields.get(key))` fallback
/// in `Rule::matches` is what makes AUL's flat fields work at all.
fn normalized_field<'a>(
    key: &str,
    sourcetype: &str,
    fields: &'a serde_json::Value,
) -> Option<&'a serde_json::Value> {
    match (sourcetype, key) {
        ("evtx", "event_id") => fields.pointer("/Event/System/EventID"),
        ("evtx", "provider" | "subsystem") => {
            fields.pointer("/Event/System/Provider_attributes/Name")
        }
        ("evtx", "host") => fields.pointer("/Event/System/Computer"),
        ("journald", "host") => fields.pointer("/_HOSTNAME"),
        ("journald", "process") => fields
            .pointer("/SYSLOG_IDENTIFIER")
            .or_else(|| fields.pointer("/_COMM")),
        _ => None,
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

    /// `fields` here mirrors the real nested shape `parsers::evtx` actually
    /// produces (`{"Event": {"System": {"EventID": ...}}}`), not a flat
    /// `{"event_id": ...}` — the earlier version of this test used the flat
    /// shape and passed even though `event_id` rules never matched a real
    /// EVTX entry, because `Rule::matches` only fell back to a top-level
    /// `fields.get()` lookup. Keep this nested; it's the only thing that
    /// would have caught that.
    #[test]
    fn matches_on_evtx_event_id_via_nested_json_path() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"failed_logon\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_id = 4625\n[rule.tag]\nvalue = \"auth_failure\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({"Event": {"System": {"EventID": 4625}}});
        let wrong_id = serde_json::json!({"Event": {"System": {"EventID": 4624}}});
        let missing_field = serde_json::json!({"Event": {"System": {}}});

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &wrong_id));
        assert!(!rule.matches("evtx", None, None, &missing_field));
    }

    #[test]
    fn matches_on_evtx_provider_via_nested_json_path() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"security_auditing\"\n[rule.match]\nsourcetype = \"evtx\"\nprovider = \"Microsoft-Windows-Security-Auditing\"\n[rule.tag]\nvalue = \"security_auditing\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({
            "Event": {"System": {"Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"}}}
        });
        let other_provider = serde_json::json!({
            "Event": {"System": {"Provider_attributes": {"Name": "Microsoft-Windows-Kernel-General"}}}
        });

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &other_provider));
    }

    /// `subsystem` on EVTX must resolve the same nested path `provider`
    /// does — the Advanced tagging dialog's "Filter by..."-derived field
    /// conditions always write `subsystem` (the normalized keyword shared
    /// with AUL, matching the timeline's Subsystem column), never
    /// `provider`, so a rule using that keyword must still match real EVTX
    /// data. Regression guard for the same class of bug `event_id`/
    /// `provider` had before `normalized_field` existed: routing a
    /// normalized keyword through the generic flat `fields.get` fallback
    /// silently never matches EVTX's nested shape.
    #[test]
    fn matches_on_evtx_subsystem_via_the_same_nested_path_as_provider() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"security_auditing\"\n[rule.match]\nsourcetype = \"evtx\"\nsubsystem = \"Microsoft-Windows-Security-Auditing\"\n[rule.tag]\nvalue = \"security_auditing\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({
            "Event": {"System": {"Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"}}}
        });
        let other_provider = serde_json::json!({
            "Event": {"System": {"Provider_attributes": {"Name": "Microsoft-Windows-Kernel-General"}}}
        });

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &other_provider));
    }

    #[test]
    fn matches_on_evtx_host_via_nested_json_path() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"h\"\n[rule.match]\nsourcetype = \"evtx\"\nhost = \"WORKSTATION1\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({"Event": {"System": {"Computer": "WORKSTATION1"}}});
        let other_host = serde_json::json!({"Event": {"System": {"Computer": "WORKSTATION2"}}});

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &other_host));
    }

    /// journald's own field names (`_HOSTNAME`, `SYSLOG_IDENTIFIER`/
    /// `_COMM`) don't literally spell "host"/"process" — same nested-vs-flat
    /// mismatch as EVTX, just with flat-but-differently-named keys instead
    /// of a nested path.
    #[test]
    fn matches_on_journald_host_and_process_via_their_actual_field_names() {
        let host_rule = Rule::from_toml_str(
            "[rule]\nname = \"h\"\n[rule.match]\nsourcetype = \"journald\"\nhost = \"web01\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let process_rule = Rule::from_toml_str(
            "[rule]\nname = \"p\"\n[rule.match]\nsourcetype = \"journald\"\nprocess = \"sshd\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let entry = serde_json::json!({"_HOSTNAME": "web01", "SYSLOG_IDENTIFIER": "sshd"});
        let other_entry = serde_json::json!({"_HOSTNAME": "web02", "_COMM": "cron"});

        assert!(host_rule.matches("journald", None, None, &entry));
        assert!(!host_rule.matches("journald", None, None, &other_entry));
        assert!(process_rule.matches("journald", None, None, &entry));
        assert!(!process_rule.matches("journald", None, None, &other_entry));

        // `_COMM` fallback when `SYSLOG_IDENTIFIER` is absent.
        let comm_only = serde_json::json!({"_COMM": "sshd"});
        assert!(process_rule.matches("journald", None, None, &comm_only));
    }

    /// An `event_id`/`provider` rule is EVTX-specific by construction — a
    /// non-evtx sourcetype has no known path to resolve them against
    /// (`normalized_field` returns `None`), so the condition never holds
    /// regardless of what happens to be in `fields`.
    #[test]
    fn evtx_normalized_fields_never_match_a_non_evtx_sourcetype() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nevent_id = 4625\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let looks_like_it_could_match = serde_json::json!({"Event": {"System": {"EventID": 4625}}});

        assert!(!rule.matches("aul", None, None, &looks_like_it_could_match));
        assert!(!rule.matches("text_config", None, None, &looks_like_it_could_match));
    }

    /// Regression guard for the generic fallback path (`fields.get(other)`)
    /// that source-specific-but-not-normalized fields like AUL's flat
    /// `subsystem` still rely on — `event_id`/`provider` gained their own
    /// sourcetype-aware match arm, but everything else must keep going
    /// through the flat top-level lookup unchanged.
    #[test]
    fn matches_on_a_flat_source_specific_field_via_generic_fallback() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"mdns\"\n[rule.match]\nsourcetype = \"aul\"\nsubsystem = \"com.apple.mDNSResponder\"\n[rule.tag]\nvalue = \"mdns\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({"subsystem": "com.apple.mDNSResponder"});
        let other_subsystem = serde_json::json!({"subsystem": "com.apple.wifi"});

        assert!(rule.matches("aul", None, None, &matching));
        assert!(!rule.matches("aul", None, None, &other_subsystem));
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
