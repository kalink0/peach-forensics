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
//! A template-rendered message is Peach's own reconstruction from the
//! record's `EventData`/`UserData`, not something the event source embedded — qualitatively
//! different provenance from a literal `RenderingInfo.Message`, which is
//! why [`render_for_event`] prefixes its output with [`RENDERED_PREFIX`].
//! An analyst must never be able to mistake a Peach guess for
//! source-provided text. [`crate::parsers::evtx::to_parsed_record`] only
//! calls into this module when `RenderingInfo.Message` is absent — a real
//! source-provided message always wins.
//!
//! # Placeholder resolution
//!
//! `{FieldName}` in a template is replaced with that field of the record's
//! *payload* (see [`event_payload`]): `Event.EventData` for the
//! named-`Data` providers — its form, e.g.
//! `<Data Name="TargetUserName">bob</Data>`, is what the `evtx` crate
//! flattens into a plain `{"TargetUserName": "bob", ...}` object, confirmed
//! against its own `event_json_sample_with_event_data.snap` test fixture,
//! unrelated to the `separate_json_attributes` setting `parsers::evtx` also
//! configures, which only affects elements that mix attributes *and* text —
//! or the one element under `Event.UserData` for providers that log there
//! instead (Terminal Services' `UserData/EventXML`, for one).
//!
//! A JSON string is used as is. A JSON number or bool is rendered as its
//! plain text: the `evtx` crate delivers `LogonType` as the integer `10`,
//! not the string `"10"`, and `SessionID` the same way, so a string-only
//! lookup left those placeholders unresolved on real records.
//!
//! A placeholder with no matching field is left as the literal
//! `{FieldName}` text rather than silently dropped or blanked — visible,
//! unmistakably not real data, consistent with the forensic principle of
//! making gaps visible instead of guessing. This also means
//! positional/unnamed `<Data>` events (legacy manifest-free providers using
//! the classic `%1`/`%2` scheme) fail visibly rather than silently:
//! `EventData` there isn't an object at all, so every placeholder in a
//! template mistakenly matched against one stays unresolved — a template
//! pointed at the wrong kind of provider shows itself immediately rather
//! than rendering something plausible-looking but wrong. A `null`, object
//! or array value is treated the same way, as unresolved.

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

/// The object a record's fields live in, given its `Event` JSON: the
/// `EventData` object when there is one, otherwise the single element under
/// `UserData`.
///
/// Providers that log through the classic `EventData` put their named
/// fields there. Others — Terminal Services' `LocalSessionManager` and
/// `RemoteConnectionManager` among them — log a `UserData` block instead,
/// whose only element (`EventXML` in every Terminal Services case) holds the
/// fields, next to its own `<Name>_attributes` entry carrying the `xmlns`.
/// That attributes entry is skipped. If `UserData` has more than one element
/// the payload is ambiguous and `None` is returned rather than picking one.
///
/// `EventData` may also be present but `null` (an event with no fields at
/// all); that falls through to `UserData`, which is then absent too.
pub fn event_payload(event: &serde_json::Value) -> Option<&serde_json::Value> {
    if let Some(event_data) = event.get("EventData").filter(|v| v.is_object()) {
        return Some(event_data);
    }
    let user_data = event.get("UserData")?.as_object()?;
    let mut elements = user_data
        .iter()
        .filter(|(name, value)| !name.ends_with("_attributes") && value.is_object())
        .map(|(_, value)| value);
    let element = elements.next()?;
    elements.next().is_none().then_some(element)
}

/// A JSON scalar as the text a template placeholder is replaced with:
/// strings as is, numbers and bools in their plain JSON form. Anything else
/// (`null`, arrays, objects) has no faithful one-line text and stays
/// unresolved.
fn scalar_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Substitutes `{FieldName}` placeholders in `template` with the matching
/// key's value from `payload` (a record's [`event_payload`], a JSON object).
/// A placeholder with no matching key — including every placeholder, when
/// `payload` is `None` or not an object at all — is left as its literal
/// `{FieldName}` text; see the module doc comment's "Placeholder
/// resolution" section for why that's deliberate, not a bug.
fn render(template: &str, payload: Option<&serde_json::Value>) -> String {
    placeholder_pattern()
        .replace_all(template, |caps: &Captures| {
            let field_name = &caps[1];
            payload
                .and_then(|data| data.get(field_name))
                .and_then(scalar_text)
                .unwrap_or_else(|| caps[0].to_string())
        })
        .into_owned()
}

/// The rendered, [`RENDERED_PREFIX`]-marked message for `(provider,
/// event_id)`, or `None` if no built-in template covers this combination —
/// [`crate::parsers::evtx::to_parsed_record`]'s only entry point into this
/// module. `payload` is the record's [`event_payload`].
pub fn render_for_event(
    provider: &str,
    event_id: u32,
    payload: Option<&serde_json::Value>,
) -> Option<String> {
    let template = built_in_templates()
        .get(&event_id)?
        .iter()
        .find(|(p, _)| p == provider)
        .map(|(_, message)| message.as_str())?;
    Some(format!("{RENDERED_PREFIX}{}", render(template, payload)))
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
            // An integer, as the `evtx` crate delivers it on real records.
            "LogonType": 3,
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
    fn render_resolves_numbers_and_bools_but_not_null_or_structures() {
        let payload = serde_json::json!({
            "LogonType": 10,
            "Elevated": true,
            "Empty": null,
            "Nested": {"a": 1},
            "List": [1, 2],
        });
        assert_eq!(render("{LogonType}/{Elevated}", Some(&payload)), "10/true");
        assert_eq!(
            render("{Empty}|{Nested}|{List}", Some(&payload)),
            "{Empty}|{Nested}|{List}"
        );
    }

    /// The shape a real Terminal Services `LocalSessionManager` record has:
    /// no `EventData`, the fields in `UserData/EventXML`, `SessionID` a
    /// number.
    fn local_session_manager_event() -> serde_json::Value {
        serde_json::json!({
            "System": {"EventID": 21},
            "UserData": {
                "EventXML_attributes": {"xmlns": "Event_NS"},
                "EventXML": {"User": "HOST\\alice", "SessionID": 1, "Address": "LOCAL"}
            }
        })
    }

    #[test]
    fn event_payload_reads_the_user_data_element_and_skips_its_attributes() {
        let event = local_session_manager_event();
        let payload = event_payload(&event).unwrap();
        assert_eq!(payload["Address"], "LOCAL");
        assert_eq!(payload["SessionID"], 1);
    }

    #[test]
    fn event_payload_prefers_event_data_when_it_is_an_object() {
        let event = serde_json::json!({
            "EventData": {"TargetUserName": "bob"},
            "UserData": {"EventXML": {"User": "ignored"}}
        });
        assert_eq!(event_payload(&event).unwrap()["TargetUserName"], "bob");
    }

    #[test]
    fn event_payload_falls_through_a_null_event_data_and_is_none_without_fields() {
        let with_user_data = serde_json::json!({
            "EventData": null,
            "UserData": {"EventXML": {"User": "alice"}}
        });
        assert_eq!(event_payload(&with_user_data).unwrap()["User"], "alice");

        // No fields at all: null EventData, or nothing but an xmlns.
        assert_eq!(event_payload(&serde_json::json!({"EventData": null})), None);
        assert_eq!(
            event_payload(
                &serde_json::json!({"UserData": {"EventXML_attributes": {"xmlns": "x"}}})
            ),
            None
        );
        assert_eq!(event_payload(&serde_json::json!({})), None);
    }

    /// Two elements under `UserData` would mean guessing which one holds the
    /// fields; the payload is refused instead.
    #[test]
    fn event_payload_is_none_when_user_data_is_ambiguous() {
        let event = serde_json::json!({
            "UserData": {"First": {"a": 1}, "Second": {"b": 2}}
        });
        assert_eq!(event_payload(&event), None);
    }

    #[test]
    fn a_local_session_manager_record_renders_from_user_data() {
        let event = local_session_manager_event();
        let rendered = render_for_event(
            "Microsoft-Windows-TerminalServices-LocalSessionManager",
            21,
            event_payload(&event),
        )
        .unwrap();

        assert!(rendered.starts_with(RENDERED_PREFIX));
        assert!(rendered.contains("HOST\\alice"), "{rendered}");
        assert!(rendered.contains("LOCAL"), "{rendered}");
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
