//! Rule packs shipped inside the binary itself, rather than as loose files
//! the analyst has to locate and select — so they work the same in a
//! release build with no repo checkout nearby as they do in this
//! development tree.

use crate::tagging::rule::Rule;

include!(concat!(env!("OUT_DIR"), "/aul_builtin_rules.rs"));

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
}
