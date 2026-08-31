//! Rule packs shipped inside the binary itself, rather than as loose files
//! the analyst has to locate and select — so they work the same in a
//! release build with no repo checkout nearby as they do in this
//! development tree.

use std::path::Path;

use crate::tagging::rule::Rule;
use crate::tagging::rule_file;

include!(concat!(env!("OUT_DIR"), "/aul_builtin_rules.rs"));
include!(concat!(env!("OUT_DIR"), "/evtx_builtin_rules.rs"));
include!(concat!(env!("OUT_DIR"), "/journald_builtin_rules.rs"));

/// The AUL pattern-of-life rule pack (`rules/examples/aul_*.toml`),
/// embedded at compile time by `build.rs` and parsed here. Every file in
/// that directory ships in every build automatically — see `build.rs`'s
/// doc comment.
///
/// Parsing panics on failure rather than returning `Result`: these strings
/// are fixed at compile time, not user input, and
/// `tagging::rule::tests::every_shipped_rule_file_parses_and_is_versioned` already asserts
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
/// already covered by `tagging::rule::tests::every_shipped_rule_file_parses_and_is_versioned`.
pub fn evtx_security_auditing_rules() -> Vec<Rule> {
    EVTX_RULE_TOMLS
        .iter()
        .map(|text| Rule::from_toml_str(text).expect("embedded EVTX rule TOML failed to parse"))
        .collect()
}

/// The journald tagging pack (`rules/examples/journald_*.toml`) — login/
/// logoff, privileged commands, and account-management events sourced
/// directly from OpenSSH, sudo, and shadow-utils' own logging code (see
/// each rule file's header comment for its specific citation), not
/// re-derived from memory. Every rule scopes itself to a specific
/// `process` (journald's `SYSLOG_IDENTIFIER`, e.g. `sshd`/`sudo`/
/// `useradd`) as well as `sourcetype = "journald"`, since journald's
/// message text alone (unlike EVTX's structured `event_id`) is the only
/// signal available and several daemons could otherwise coincidentally
/// share a substring.
///
/// Parsing panics on failure for the same reason as
/// [`aul_pattern_of_life_rules`]: fixed at compile time, not user input,
/// already covered by `tagging::rule::tests::every_shipped_rule_file_parses_and_is_versioned`.
pub fn journald_login_rules() -> Vec<Rule> {
    JOURNALD_RULE_TOMLS
        .iter()
        .map(|text| Rule::from_toml_str(text).expect("embedded journald rule TOML failed to parse"))
        .collect()
}

/// All three built-in packs together, AUL then EVTX then journald — every
/// rule the "Built-in rules..." picker (`ui::builtin_rules_dialog`) can
/// show and `app::load_rules` can filter by name. A fresh `Vec` on every
/// call, same as the three pack functions it wraps — cheap enough (tens of
/// small TOML parses) that nothing here caches it.
pub fn all_builtin_rules() -> Vec<Rule> {
    let mut rules = aul_pattern_of_life_rules();
    rules.extend(evtx_security_auditing_rules());
    rules.extend(journald_login_rules());
    rules
}

/// [`all_builtin_rules`] (the embedded tier-1 baseline), unless
/// `applied_pack_dir` holds a currently-applied tier-2 rule pack — a
/// directory `tagging::pack_bundle::load_pack_bundle`'s output has been
/// moved into, see `docs/design/rule-pack-updates.md` §3's three-tier
/// model — in which case tier 2 **wholesale replaces** tier 1 rather than
/// adding to it, per that section's precedence decision.
///
/// Deliberately all-or-nothing on the tier-2 side: if the directory
/// exists but is empty, unreadable, or contains even one file that fails
/// to parse as a rule, this falls all the way back to the embedded
/// baseline rather than silently using a partial tier-2 set — a rule pack
/// is meant to be a known-good full snapshot (§4), so a broken one is
/// worth treating as *no* update rather than an unpredictable partial one.
/// `manifest.toml` (present alongside the rule files, not a rule itself)
/// is skipped explicitly, not treated as a parse failure.
///
/// This is the read side only — `applied_pack_dir` is written by
/// `tagging::pack_bundle::apply_bundle`, called from the "Rule packs..."
/// UI (`docs/design/rule-pack-updates.md` step 7), never from here.
pub fn active_builtin_rules(applied_pack_dir: Option<&Path>) -> Vec<Rule> {
    if let Some(pack) = applied_pack_dir.and_then(load_applied_pack) {
        return pack;
    }
    all_builtin_rules()
}

/// [`active_builtin_rules`]'s `name → version` shape — what
/// `tagging::pack_diff::diff` compares a candidate bundle's manifest
/// against to compute the "Rule packs..." preview (new/modified/removed).
/// A rule with no `version` (an older/hand-written one — `version` is
/// `Option`, see `tagging::rule::RuleBody`) is skipped rather than given a
/// placeholder: it can't participate in a version comparison at all, and
/// showing it as spuriously "new" or "removed" on every check would be
/// worse than just leaving it out of the diff (it still tags normally —
/// this only affects what the update preview *shows*).
pub fn active_rule_versions(
    applied_pack_dir: Option<&Path>,
) -> crate::tagging::pack_diff::RuleVersions {
    active_builtin_rules(applied_pack_dir)
        .into_iter()
        .filter_map(|rule| rule.rule.version.map(|version| (rule.rule.name, version)))
        .collect()
}

/// `None` on anything short of "every `*.toml` file in `dir` other than
/// `manifest.toml` parsed as a valid rule, and there was at least one" —
/// see [`active_builtin_rules`]'s doc comment for why this is all-or-nothing.
fn load_applied_pack(dir: &Path) -> Option<Vec<Rule>> {
    let paths = rule_file::scan_rules_dir(dir).ok()?;
    let mut rules = Vec::with_capacity(paths.len());
    for path in paths {
        if path.file_name().and_then(|n| n.to_str()) == Some("manifest.toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).ok()?;
        rules.push(Rule::from_toml_str(&text).ok()?);
    }
    if rules.is_empty() { None } else { Some(rules) }
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
            rules.len() >= 37,
            "expected at least 37 embedded AUL rules, got {}",
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

    /// Regression guard for the highest-sensitivity rule in the AUL pack —
    /// a rule that's supposed to flag entries carrying a phone number in
    /// plain text (see `rules/examples/aul_dialed_number_recovery.toml`)
    /// had better actually match one, and not accidentally match ordinary
    /// call-tracking noise that doesn't contain a number at all.
    #[test]
    fn embedded_dialed_number_recovery_rule_matches_a_realistic_message() {
        let rules = aul_pattern_of_life_rules();
        let dialed_number = rules
            .iter()
            .find(|r| r.rule.tag.value == "dialed_number_recovery")
            .expect("expected an embedded rule tagging dialed_number_recovery");

        let message = "kPhoneNumber\": \"0652441234\", kActionType\": 0";
        assert!(dialed_number.matches("aul", None, Some(message), &serde_json::Value::Null));

        let unrelated = "Started tracking call";
        assert!(!dialed_number.matches("aul", None, Some(unrelated), &serde_json::Value::Null));
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
        // test — 35 Security-Auditing event IDs are shipped today, more can
        // be added later without this test needing an edit.
        assert!(
            rules.len() >= 35,
            "expected at least 35 embedded EVTX rules, got {}",
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
    fn embeds_every_journald_rule_file_and_all_parse() {
        let rules = journald_login_rules();
        // Same "loose lower bound" reasoning as the other two packs' own
        // tests — 15 rules shipped today, more can be added later without
        // this test needing an edit.
        assert!(
            rules.len() >= 15,
            "expected at least 15 embedded journald rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn all_embedded_journald_rules_match_sourcetype_journald() {
        for rule in journald_login_rules() {
            assert_eq!(
                rule.rule
                    .match_fields
                    .get("sourcetype")
                    .and_then(|v| v.as_str()),
                Some("journald"),
                "rule {} does not match sourcetype = \"journald\"",
                rule.rule.name
            );
        }
    }

    #[test]
    fn journald_known_tag_values_are_present() {
        let tags: Vec<String> = journald_login_rules()
            .iter()
            .map(|r| r.rule.tag.value.clone())
            .collect();
        for expected in ["logon_success", "auth_failure", "password_changed"] {
            assert!(
                tags.iter().any(|t| t == expected),
                "expected tag {expected} among embedded journald rules, got {tags:?}"
            );
        }
    }

    /// Regression guard for the same class of bug the EVTX pack's own
    /// `embedded_evtx_logon_success_rule_matches_a_realistic_nested_record`
    /// test guards against: a rule can parse and declare the right
    /// `sourcetype` while still never matching real data if its `process`
    /// condition isn't actually resolved against journald's flat
    /// `SYSLOG_IDENTIFIER` field. Exercises the shipped SSH logon-success
    /// rule against a realistic flat `fields` blob end to end.
    #[test]
    fn embedded_journald_ssh_logon_success_rule_matches_a_realistic_record() {
        let rules = journald_login_rules();
        let logon_success = rules
            .iter()
            .find(|r| r.rule.tag.value == "logon_success")
            .expect("expected an embedded rule tagging logon_success");

        let fields = serde_json::json!({"SYSLOG_IDENTIFIER": "sshd"});
        let message = "Accepted password for alice from 10.0.0.5 port 51000 ssh2";
        assert!(logon_success.matches("journald", None, Some(message), &fields));

        let wrong_process = serde_json::json!({"SYSLOG_IDENTIFIER": "cron"});
        assert!(!logon_success.matches("journald", None, Some(message), &wrong_process));

        let wrong_message = "Failed password for alice from 10.0.0.5 port 51000 ssh2";
        assert!(!logon_success.matches("journald", None, Some(wrong_message), &fields));
    }

    /// Regression guard for `journald_kernel_boot.toml`'s `_TRANSPORT`
    /// condition specifically — an underscore-prefixed flat field going
    /// through `Rule::matches`'s generic fallback (not a normalized key
    /// like `process`), easy to get silently wrong.
    #[test]
    fn embedded_journald_kernel_boot_rule_matches_a_realistic_record() {
        let rules = journald_login_rules();
        let boot = rules
            .iter()
            .find(|r| r.rule.tag.value == "system_boot")
            .expect("expected an embedded rule tagging system_boot");

        let fields = serde_json::json!({"_TRANSPORT": "kernel"});
        let message = "Linux version 6.8.0-generic (buildd@host) #1 SMP";
        assert!(boot.matches("journald", None, Some(message), &fields));

        let wrong_transport = serde_json::json!({"_TRANSPORT": "syslog"});
        assert!(!boot.matches("journald", None, Some(message), &wrong_transport));

        let wrong_message = "Linux CPU throttling active";
        assert!(!boot.matches("journald", None, Some(wrong_message), &fields));
    }

    #[test]
    fn all_builtin_rules_combines_all_three_packs() {
        let all = all_builtin_rules();
        let aul_count = aul_pattern_of_life_rules().len();
        let evtx_count = evtx_security_auditing_rules().len();
        let journald_count = journald_login_rules().len();

        assert_eq!(all.len(), aul_count + evtx_count + journald_count);
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

    fn temp_dir_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "peach-builtin-test-dir-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn active_builtin_rules_falls_back_to_embedded_when_no_dir_is_given() {
        let active = active_builtin_rules(None);
        assert_eq!(active.len(), all_builtin_rules().len());
    }

    #[test]
    fn active_builtin_rules_falls_back_to_embedded_when_the_dir_does_not_exist() {
        let dir = temp_dir_path("missing");
        let active = active_builtin_rules(Some(&dir));
        assert_eq!(active.len(), all_builtin_rules().len());
    }

    #[test]
    fn active_builtin_rules_falls_back_to_embedded_when_the_dir_is_empty() {
        let dir = temp_dir_path("empty");
        std::fs::create_dir_all(&dir).unwrap();

        let active = active_builtin_rules(Some(&dir));

        assert_eq!(active.len(), all_builtin_rules().len());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn active_builtin_rules_wholesale_replaces_the_embedded_baseline() {
        let dir = temp_dir_path("applied");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("aul_custom.toml"),
            "[rule]\nname = \"aul_custom\"\nversion = \"1\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"custom\"\n",
        )
        .unwrap();
        // Not a rule file, must be skipped rather than tried as one.
        std::fs::write(
            dir.join("manifest.toml"),
            "[pack]\npack_version = 1\nreleased_at = \"2026-09-01\"\nmin_peach_version = \"0.0.1\"\n",
        )
        .unwrap();

        let active = active_builtin_rules(Some(&dir));

        // Exactly the tier-2 rule, not the embedded baseline merged in —
        // wholesale replacement, not an addition.
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].rule.name, "aul_custom");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn active_builtin_rules_falls_back_entirely_if_one_file_fails_to_parse() {
        let dir = temp_dir_path("broken");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("aul_good.toml"),
            "[rule]\nname = \"aul_good\"\nversion = \"1\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"good\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("aul_bad.toml"), "this is not valid toml [[[").unwrap();

        let active = active_builtin_rules(Some(&dir));

        // All-or-nothing: one broken file means the whole applied pack is
        // distrusted, not "every rule except the broken one".
        assert_eq!(active.len(), all_builtin_rules().len());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn active_rule_versions_maps_every_embedded_rules_name_to_its_version() {
        let versions = active_rule_versions(None);
        assert_eq!(versions.len(), all_builtin_rules().len());
        assert_eq!(versions.get("aul_airplane_mode"), Some(&"1".to_string()));
    }

    #[test]
    fn active_rule_versions_reflects_the_applied_pack_when_present() {
        let dir = temp_dir_path("active-versions-applied");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("aul_custom.toml"),
            "[rule]\nname = \"aul_custom\"\nversion = \"9\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"custom\"\n",
        )
        .unwrap();

        let versions = active_rule_versions(Some(&dir));

        assert_eq!(versions.len(), 1);
        assert_eq!(versions.get("aul_custom"), Some(&"9".to_string()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
