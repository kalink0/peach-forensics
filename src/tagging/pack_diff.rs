//! Computes what a candidate rule pack (built-in baseline, or a downloaded
//! update — see `docs/design/rule-pack-updates.md`) actually changes
//! relative to what's currently active, from nothing but each rule's
//! `name`/`version` (`tagging::rule::RuleBody::version`). Deliberately not
//! a hand-maintained changelog field in a bundle's manifest: a derived diff
//! can't drift from what the bundle actually contains, the way a
//! separately-authored list of "what changed" always risks doing.
//!
//! Pure and I/O-free on purpose — this is the one piece the eventual
//! bundle-loading code, the preview UI, and their tests can all share
//! without any of them needing a real file on disk.

use std::collections::BTreeMap;

/// name → version. `BTreeMap` rather than `HashMap` specifically for
/// deterministic iteration order — [`diff`]'s output ordering must not
/// depend on hash-seed randomization, per this project's own determinism
/// principle (same inputs, same result, every time).
pub type RuleVersions = BTreeMap<String, String>;

/// What changed between `active` (the currently loaded rule pack) and
/// `candidate` (a bundle being considered for application), by rule name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulePackDiff {
    /// In `candidate` but not `active`.
    pub new: Vec<String>,
    /// In both, but `candidate`'s version differs from `active`'s.
    pub modified: Vec<String>,
    /// In `active` but not `candidate` — the case worth flagging most
    /// prominently in a preview: a rule an analyst has been relying on
    /// would simply stop tagging anything from here on, with no error to
    /// notice it by unless this list surfaces it first.
    pub removed: Vec<String>,
}

impl RulePackDiff {
    pub fn is_empty(&self) -> bool {
        self.new.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }
}

/// Computes [`RulePackDiff`] from two `name → version` maps. Both inputs
/// are sorted by name already (a `BTreeMap`'s own iteration order), so the
/// three output lists come out name-sorted with no extra sort step needed.
pub fn diff(active: &RuleVersions, candidate: &RuleVersions) -> RulePackDiff {
    let mut new = Vec::new();
    let mut modified = Vec::new();

    for (name, candidate_version) in candidate {
        match active.get(name) {
            None => new.push(name.clone()),
            Some(active_version) if active_version != candidate_version => {
                modified.push(name.clone());
            }
            Some(_) => {}
        }
    }

    let removed = active
        .keys()
        .filter(|name| !candidate.contains_key(*name))
        .cloned()
        .collect();

    RulePackDiff {
        new,
        modified,
        removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(pairs: &[(&str, &str)]) -> RuleVersions {
        pairs
            .iter()
            .map(|(name, version)| (name.to_string(), version.to_string()))
            .collect()
    }

    #[test]
    fn identical_maps_produce_an_empty_diff() {
        let active = versions(&[("a", "1"), ("b", "2")]);
        let candidate = active.clone();

        let result = diff(&active, &candidate);

        assert!(result.is_empty());
    }

    #[test]
    fn a_name_only_in_the_candidate_is_new() {
        let active = versions(&[("a", "1")]);
        let candidate = versions(&[("a", "1"), ("b", "1")]);

        let result = diff(&active, &candidate);

        assert_eq!(result.new, vec!["b"]);
        assert!(result.modified.is_empty());
        assert!(result.removed.is_empty());
    }

    #[test]
    fn a_name_in_both_with_a_different_version_is_modified() {
        let active = versions(&[("a", "1")]);
        let candidate = versions(&[("a", "2")]);

        let result = diff(&active, &candidate);

        assert_eq!(result.modified, vec!["a"]);
        assert!(result.new.is_empty());
        assert!(result.removed.is_empty());
    }

    #[test]
    fn a_name_only_in_active_is_removed() {
        let active = versions(&[("a", "1"), ("b", "1")]);
        let candidate = versions(&[("a", "1")]);

        let result = diff(&active, &candidate);

        assert_eq!(result.removed, vec!["b"]);
        assert!(result.new.is_empty());
        assert!(result.modified.is_empty());
    }

    #[test]
    fn a_name_in_both_with_the_same_version_is_unchanged_and_not_reported() {
        let active = versions(&[("a", "1")]);
        let candidate = versions(&[("a", "1")]);

        let result = diff(&active, &candidate);

        assert!(result.is_empty());
    }

    #[test]
    fn mixed_new_modified_and_removed_all_at_once() {
        // "kept_same" unchanged, "kept_bumped" modified, "gone" removed,
        // "fresh" new — a v3-ships-mostly-untouched-rules scenario like the
        // one discussed for this feature: most of a pack can stay at its
        // original version across many releases.
        let active = versions(&[("kept_same", "1"), ("kept_bumped", "1"), ("gone", "1")]);
        let candidate = versions(&[("kept_same", "1"), ("kept_bumped", "2"), ("fresh", "1")]);

        let result = diff(&active, &candidate);

        assert_eq!(result.new, vec!["fresh"]);
        assert_eq!(result.modified, vec!["kept_bumped"]);
        assert_eq!(result.removed, vec!["gone"]);
    }

    #[test]
    fn output_lists_are_name_sorted() {
        let active = RuleVersions::new();
        let candidate = versions(&[("zebra", "1"), ("apple", "1"), ("mango", "1")]);

        let result = diff(&active, &candidate);

        assert_eq!(result.new, vec!["apple", "mango", "zebra"]);
    }

    #[test]
    fn empty_active_and_candidate_is_an_empty_diff() {
        let result = diff(&RuleVersions::new(), &RuleVersions::new());
        assert!(result.is_empty());
    }
}
