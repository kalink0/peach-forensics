//! Built-in EVTX message templates, embedded at compile time from
//! `message_templates/examples/evtx_*.toml` (same `build.rs` mechanism as
//! `tagging::builtin`'s AUL rule pack — see there for why embedding rather
//! than loading loose files).
//!
//! # Why this exists
//!
//! [`crate::parsers::evtx`]'s `message` is `Event.RenderingInfo.Message`
//! when present — but that's only ever present for pre-rendered sources
//! (e.g. Windows Event Forwarding), never for a plain `winevt\Logs\*.evtx`
//! read directly, since real rendering needs the source machine's
//! message-resource DLLs/templates, which nothing in this stack ships or
//! emulates. For the small set of high-value Security-auditing-style
//! events an IR analyst reaches for first, this fills that gap with a
//! curated, TOML-defined template per `(provider, event_id)` — the same
//! approach forensic tools like EricZimmerman's EvtxECmd take (its Maps,
//! MIT-licensed, were consulted as a reference for which events are worth
//! covering and which `EventData` fields they carry).
//!
//! # Forensic distinction from `RenderingInfo.Message`
//!
//! A template-rendered message is Peach's own reconstruction from
//! `EventData`, not something the event source embedded — qualitatively
//! different provenance from a literal `RenderingInfo.Message`, which is
//! why [`render_for_event`] prefixes its output with [`RENDERED_PREFIX`].
//! An analyst must never be able to mistake a Peach guess for
//! source-provided text. [`crate::parsers::evtx::to_parsed_record`] only
//! calls into this module when `RenderingInfo.Message` is absent — a real
//! source-provided message always wins.
//!
//! # Placeholder resolution
//!
//! `{FieldName}` in a template is replaced with `Event.EventData.FieldName`
//! (a plain string lookup — `EventData`'s named-`Data` form, e.g.
//! `<Data Name="TargetUserName">bob</Data>`, is what the `evtx` crate
//! flattens into a plain `{"TargetUserName": "bob", ...}` object, confirmed
//! against its own `event_json_sample_with_event_data.snap` test
//! fixture — unrelated to the `separate_json_attributes` setting
//! `parsers::evtx` also configures, which only affects elements that mix
//! attributes *and* text, not `Data`'s `Name`-as-key form). A placeholder
//! with no matching field is left as the literal `{FieldName}` text rather
//! than silently dropped or blanked — visible, unmistakably not real data,
//! consistent with the forensic "make gaps visible, don't guess" principle
//! (CLAUDE.md §0.1). This also means positional/unnamed `<Data>` events
//! (legacy manifest-free providers using the classic `%1`/`%2` scheme) fail
//! visibly rather than silently: `EventData` there isn't an object at all,
//! so every placeholder in a template mistakenly matched against one stays
//! unresolved — a template pointed at the wrong kind of provider shows
//! itself immediately rather than rendering something plausible-looking
//! but wrong.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde::Deserialize;

include!(concat!(env!("OUT_DIR"), "/evtx_builtin_templates.rs"));

/// Prepended to every template-rendered message — see the module doc
/// comment's "Forensic distinction" section for why this must never be
/// omitted.
pub const RENDERED_PREFIX: &str = "[Peach] ";

#[derive(Deserialize)]
struct TemplateFile {
    template: Vec<TemplateEntry>,
}

#[derive(Deserialize)]
struct TemplateEntry {
    provider: String,
    event_id: u32,
    message: String,
}

/// Keyed by `event_id` first (a plain `u32`, no allocation to look up)
/// rather than `(provider, event_id)`: this is looked up once per parsed
/// EVTX record — potentially millions of times for a large source — and a
/// `HashMap<(String, u32), _>` would force building an owned `String` key
/// on every single lookup just to throw it away. Grouped by event ID, the
/// handful of entries that share one (rare — only real case in the shipped
/// set is none, but nothing stops two providers from reusing an ID) are
/// disambiguated by a cheap `&str` scan afterward.
fn built_in_templates() -> &'static HashMap<u32, Vec<(String, String)>> {
    static TEMPLATES: OnceLock<HashMap<u32, Vec<(String, String)>>> = OnceLock::new();
    TEMPLATES.get_or_init(|| {
        let mut map: HashMap<u32, Vec<(String, String)>> = HashMap::new();
        for text in EVTX_TEMPLATE_TOMLS {
            let file: TemplateFile =
                toml::from_str(text).expect("embedded EVTX template TOML failed to parse");
            for entry in file.template {
                map.entry(entry.event_id)
                    .or_default()
                    .push((entry.provider, entry.message));
            }
        }
        map
    })
}

fn placeholder_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"\{([A-Za-z0-9_]+)\}").unwrap())
}

/// Substitutes `{FieldName}` placeholders in `template` with the matching
/// key's value from `event_data` (expected to be `Event.EventData`, a JSON
/// object for the named-`Data` providers this module targets). A
/// placeholder with no matching key — including every placeholder, when
/// `event_data` is `None` or not an object at all — is left as its literal
/// `{FieldName}` text; see the module doc comment's "Placeholder
/// resolution" section for why that's deliberate, not a bug.
fn render(template: &str, event_data: Option<&serde_json::Value>) -> String {
    placeholder_pattern()
        .replace_all(template, |caps: &Captures| {
            let field_name = &caps[1];
            event_data
                .and_then(|data| data.get(field_name))
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| caps[0].to_string())
        })
        .into_owned()
}

/// The rendered, [`RENDERED_PREFIX`]-marked message for `(provider,
/// event_id)`, or `None` if no built-in template covers this combination —
/// [`crate::parsers::evtx::to_parsed_record`]'s only entry point into this
/// module.
pub fn render_for_event(
    provider: &str,
    event_id: u32,
    event_data: Option<&serde_json::Value>,
) -> Option<String> {
    let template = built_in_templates()
        .get(&event_id)?
        .iter()
        .find(|(p, _)| p == provider)
        .map(|(_, message)| message.as_str())?;
    Some(format!("{RENDERED_PREFIX}{}", render(template, event_data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_every_shipped_template_file_and_all_parse() {
        // Kept as a loose lower bound, not an exact count — same reasoning
        // as `tagging::builtin`'s equivalent AUL test: the pack grows over
        // time, and pinning an exact number would just make this something
        // to edit on every addition rather than a real correctness check.
        let total: usize = built_in_templates().values().map(Vec::len).sum();
        assert!(
            total >= 15,
            "expected at least 15 embedded EVTX templates, got {total}"
        );
    }

    #[test]
    fn render_substitutes_a_known_field() {
        let event_data = serde_json::json!({"TargetUserName": "bob"});
        assert_eq!(
            render("Account: {TargetUserName}", Some(&event_data)),
            "Account: bob"
        );
    }

    #[test]
    fn render_leaves_an_unresolved_placeholder_literal() {
        let event_data = serde_json::json!({"TargetUserName": "bob"});
        assert_eq!(
            render(
                "Account: {TargetUserName}, group: {GroupName}",
                Some(&event_data)
            ),
            "Account: bob, group: {GroupName}"
        );
    }

    #[test]
    fn render_leaves_every_placeholder_literal_without_event_data() {
        assert_eq!(
            render("Account: {TargetUserName}", None),
            "Account: {TargetUserName}"
        );
    }

    #[test]
    fn render_for_event_returns_none_for_an_unknown_combination() {
        assert_eq!(render_for_event("Some Other Provider", 9999, None), None);
    }

    #[test]
    fn render_for_event_is_prefixed_and_uses_event_data() {
        let event_data = serde_json::json!({
            "TargetUserName": "bob",
            "TargetDomainName": "CORP",
            "LogonType": "3",
            "WorkstationName": "WS01",
            "IpAddress": "10.0.0.5",
            "IpPort": "49222",
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
        });

        let rendered = render_for_event(
            "Microsoft-Windows-Security-Auditing",
            4624,
            Some(&event_data),
        )
        .unwrap();

        assert!(rendered.starts_with(RENDERED_PREFIX));
        assert!(rendered.contains("bob"));
        assert!(rendered.contains("CORP"));
        assert!(
            !rendered.contains('{'),
            "no placeholder should be left unresolved: {rendered}"
        );
    }

    #[test]
    fn render_for_event_does_not_cross_wires_between_providers_sharing_an_event_id() {
        // 4624 only exists for Security-Auditing in the shipped set — a
        // different provider using the same numeric ID must not pick it up.
        assert_eq!(render_for_event("Some Other Provider", 4624, None), None);
    }
}
