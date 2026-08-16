//! Rule packs shipped inside the binary itself, rather than as loose files
//! the analyst has to locate and select — so they work the same in a
//! release build with no repo checkout nearby as they do in this
//! development tree.

use crate::tagging::rule::Rule;

include!(concat!(env!("OUT_DIR"), "/aul_builtin_rules.rs"));
include!(concat!(env!("OUT_DIR"), "/evtx_builtin_rules.rs"));

/// The AUL pattern-of-life rule pack (`rules/examples/aul_*.toml`),
/// embedded at compile time by `build.rs` and parsed here. Every file in
/// that directory ships in every build automatically — see `build.rs`'s
/// doc comment.
///
/// Parsing panics on failure rather than returning `Result`: these strings
/// are fixed at compile time, not user input, and
/// `tagging::rule::tests::every_shipped_rule_file_parses` already asserts
/// every file in `rules/examples/` parses — a failure here would mean that
/// invariant broke, which is a build-time bug to fix, not a runtime
/// condition to handle gracefully.
pub fn aul_pattern_of_life_rules() -> Vec<Rule> {
    AUL_RULE_TOMLS
        .iter()
        .map(|text| Rule::from_toml_str(text).expect("embedded AUL rule TOML failed to parse"))
        .collect()
}

/// The EVTX Security-Auditing tagging pack (`rules/examples/evtx_*.toml`),
/// the tagging companion to the built-in EVTX message templates
/// (`parsers::evtx_templates`, `message_templates/examples/evtx_*.toml`) —
/// same embedding mechanism, same "every file in the directory ships
/// automatically" property, see `build.rs`'s doc comment. Every rule in
/// this pack relies on `tagging::rule`'s EVTX-specific `event_id`/`provider`
/// resolution (`normalized_field`) to actually match anything.
///
/// Parsing panics on failure for the same reason as
/// [`aul_pattern_of_life_rules`]: fixed at compile time, not user input,
/// already covered by `tagging::rule::tests::every_shipped_rule_file_parses`.
pub fn evtx_security_auditing_rules() -> Vec<Rule> {
    EVTX_RULE_TOMLS
        .iter()
        .map(|text| Rule::from_toml_str(text).expect("embedded EVTX rule TOML failed to parse"))
        .collect()
}

/// Both built-in packs together, AUL first then EVTX — every rule the
/// "Built-in rules..." picker (`ui::builtin_rules_dialog`) can show and
/// `app::load_rules` can filter by name. A fresh `Vec` on every call, same
/// as the two pack functions it wraps — cheap enough (tens of small TOML
/// parses) that nothing here caches it.
pub fn all_builtin_rules() -> Vec<Rule> {
    let mut rules = aul_pattern_of_life_rules();
    rules.extend(evtx_security_auditing_rules());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_every_aul_rule_file_and_all_parse() {
        let rules = aul_pattern_of_life_rules();
        // Kept as a loose lower bound, not an exact count: the pack grows
        // over time, and pinning an exact number here would just make this
        // test something to edit every time a rule file is added, not a
        // real correctness check.
        assert!(
            rules.len() >= 33,
            "expected at least 33 embedded AUL rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn all_embedded_rules_match_sourcetype_aul() {
        // Every rule in this pack is AUL-specific — if one weren't, merging
        // this pack into a non-AUL load/retag call would tag rows it
        // shouldn't. Not load-bearing for correctness (each rule's own
        // `sourcetype = "aul"` match condition already prevents cross-source
        // tagging on its own), but a real gap here would be a sign this
        // pack picked up a file it shouldn't have.
        for rule in aul_pattern_of_life_rules() {
            assert_eq!(
                rule.rule
                    .match_fields
                    .get("sourcetype")
                    .and_then(|v| v.as_str()),
                Some("aul"),
                "rule {} does not match sourcetype = \"aul\"",
                rule.rule.name
            );
        }
    }

    #[test]
    fn known_tag_values_are_present() {
        let tags: Vec<String> = aul_pattern_of_life_rules()
            .iter()
            .map(|r| r.rule.tag.value.clone())
            .collect();
        for expected in ["wifi_status", "biometric_sensor_events", "driving_state"] {
            assert!(
                tags.iter().any(|t| t == expected),
                "expected tag {expected} among embedded AUL rules, got {tags:?}"
            );
        }
    }

    #[test]
    fn embeds_every_evtx_rule_file_and_all_parse() {
        let rules = evtx_security_auditing_rules();
        // Same "loose lower bound" reasoning as the AUL pack's equivalent
        // test — 15 Security-Auditing event IDs are shipped today, more can
        // be added later without this test needing an edit.
        assert!(
            rules.len() >= 15,
            "expected at least 15 embedded EVTX rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn all_embedded_evtx_rules_match_sourcetype_evtx() {
        for rule in evtx_security_auditing_rules() {
            assert_eq!(
                rule.rule
                    .match_fields
                    .get("sourcetype")
                    .and_then(|v| v.as_str()),
                Some("evtx"),
                "rule {} does not match sourcetype = \"evtx\"",
                rule.rule.name
            );
        }
    }

    #[test]
    fn evtx_known_tag_values_are_present() {
        let tags: Vec<String> = evtx_security_auditing_rules()
            .iter()
            .map(|r| r.rule.tag.value.clone())
            .collect();
        for expected in ["logon_success", "auth_failure", "process_creation"] {
            assert!(
                tags.iter().any(|t| t == expected),
                "expected tag {expected} among embedded EVTX rules, got {tags:?}"
            );
        }
    }

    /// The regression this whole pack exists to guard against: a rule can
    /// parse fine and declare `sourcetype = "evtx"` while still never
    /// matching a real entry, if its `event_id`/`provider` condition isn't
    /// resolved against EVTX's actual nested `fields` shape (see
    /// `tagging::rule::normalized_field`'s doc comment for the bug this
    /// fixed). Exercises the shipped 4624 rule against a realistic nested
    /// `fields` blob end to end, not just that it parses.
    #[test]
    fn embedded_evtx_logon_success_rule_matches_a_realistic_nested_record() {
        let rules = evtx_security_auditing_rules();
        let logon_success = rules
            .iter()
            .find(|r| r.rule.tag.value == "logon_success")
            .expect("expected an embedded rule tagging logon_success");

        let fields = serde_json::json!({"Event": {"System": {"EventID": 4624}}});
        assert!(logon_success.matches("evtx", None, None, &fields));

        let wrong_event = serde_json::json!({"Event": {"System": {"EventID": 4625}}});
        assert!(!logon_success.matches("evtx", None, None, &wrong_event));
    }

    #[test]
    fn all_builtin_rules_combines_both_packs() {
        let all = all_builtin_rules();
        let aul_count = aul_pattern_of_life_rules().len();
        let evtx_count = evtx_security_auditing_rules().len();

        assert_eq!(all.len(), aul_count + evtx_count);
        assert!(all.iter().any(|r| r.rule.tag.value == "wifi_status"));
        assert!(all.iter().any(|r| r.rule.tag.value == "logon_success"));
    }

    #[test]
    fn every_builtin_rule_name_is_unique() {
        // The picker dialog and `app::load_rules` both key off `rule.name`
        // — a collision between the two packs (or within one) would mean
        // enabling/disabling one rule silently affects another.
        let names: Vec<String> = all_builtin_rules()
            .iter()
            .map(|r| r.rule.name.clone())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "duplicate rule name found among built-in rules"
        );
    }
}
