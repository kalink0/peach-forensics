//! Built-in text-parser format starters (`parsers/examples/*.toml`),
//! embedded at compile time by `build.rs` — same mechanism as
//! [`crate::tagging::builtin`]'s AUL/EVTX/journald rule packs, applied here
//! to the *other* kind of TOML config this app reads. Unlike those rule
//! packs (which apply automatically, no analyst action needed), these are
//! starting points loaded into "Define format..." (`ui::format_dialog`) —
//! a text log's actual shape varies too much file to file for a built-in
//! preset to ever apply itself blindly the way a fixed EVTX `event_id`
//! can.

use crate::parsers::text_config_file::TextFormatDraft;

include!(concat!(env!("OUT_DIR"), "/builtin_text_parsers.rs"));

/// One built-in format, ready to load straight into a
/// [`TextFormatDraft`] — `name`/`sourcetype` pulled back out for display in
/// the picker without the caller needing to parse `toml` a second time
/// just to label a menu entry.
pub struct BuiltinTextFormat {
    pub name: String,
    pub sourcetype: String,
    pub toml: &'static str,
}

/// Every built-in text-parser starter, in the order `build.rs` found the
/// files (alphabetical by filename — see `embed_toml_dir`'s doc comment).
///
/// Parsing panics on failure rather than returning `Result`, same
/// reasoning as `tagging::builtin`'s pack functions: these strings are
/// fixed at compile time, not user input, and
/// `text_config_file::tests::every_shipped_builtin_format_parses` already
/// asserts every file in `parsers/examples/` parses as a valid
/// [`TextFormatDraft`] — a failure here would mean that invariant broke,
/// a build-time bug to fix, not a runtime condition to handle gracefully.
pub fn builtin_text_formats() -> Vec<BuiltinTextFormat> {
    TEXT_PARSER_TOMLS
        .iter()
        .map(|text| {
            let draft = TextFormatDraft::from_toml_str(text)
                .expect("embedded text parser TOML failed to parse");
            BuiltinTextFormat {
                name: draft.name,
                sourcetype: draft.sourcetype,
                toml: text,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_every_built_in_text_format_and_all_parse() {
        let formats = builtin_text_formats();
        // Loose lower bound, not an exact count — same reasoning as
        // `tagging::builtin`'s own pack-size tests.
        assert!(
            formats.len() >= 3,
            "expected at least 3 embedded text formats, got {}",
            formats.len()
        );
    }

    #[test]
    fn every_built_in_format_name_is_unique() {
        // The picker in `ui::format_dialog` lists these by name — a
        // collision would make two entries indistinguishable in the UI.
        let names: Vec<String> = builtin_text_formats()
            .iter()
            .map(|f| f.name.clone())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "duplicate name found among built-in text formats"
        );
    }
}
