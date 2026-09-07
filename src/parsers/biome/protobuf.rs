//! A schema-less protobuf wire-format decoder for SEGB record payloads.
//!
//! SEGB payloads are protobuf messages with no `.proto` schema available —
//! peach has no way to know what a given field number *means*, only what
//! wire type it was encoded with. This mirrors crush-forensics' own
//! hand-rolled approach (`crush/parsers/proto_wire.py` +
//! `segb_parser.py::_parse_protobuf`) rather than a schema-based decoder
//! like iLEAPP's Python `blackboxprotobuf` dependency — there's no
//! comparable well-established Rust crate for schema-less protobuf
//! decoding to lean on, and a from-scratch decoder is exactly what both
//! reference implementations already do in Python.
//!
//! Output shape: a JSON object keyed by field-number strings (`"1"`,
//! `"2"`, …), matching both reference implementations' own convention —
//! this is what lets `tagging::rule`'s biome-specific `normalized_field`
//! keys address specific fields by number (see
//! `docs/design/biome-rule-pack-research.md`'s Tier 2 section). A field
//! seen more than once becomes a JSON array of its occurrences rather than
//! silently keeping only the last one.

use serde_json::{Map, Value, json};

/// Protobuf's own spec-defined ceiling on field numbers.
const MAX_FIELD_NUMBER: u64 = 1 << 29;
/// Caps recursive "try this length-delimited field as a nested message"
/// attempts — SEGB payloads aren't deeply nested in practice, so this is
/// generous headroom, not a tight budget.
const MAX_DECODE_DEPTH: usize = 32;
/// A global cap on the total number of fields decoded across a whole
/// [`decode_message`] call, including every recursive nested-message
/// attempt — mirrors why iLEAPP had to patch a work-budget bug into the
/// Python `blackboxprotobuf` library it vendors: unbounded speculative
/// "try to reparse these bytes as a nested message" recursion is a real
/// DoS-shaped risk for a schema-less decoder, and a from-scratch Rust port
/// inherits that exact problem class from scratch with no equivalent
/// battle-testing yet.
const MAX_DECODE_WORK: usize = 100_000;

/// Decodes `bytes` as a schema-less protobuf message. Never fails: on a
/// truncated varint, an invalid field number, an unsupported wire type
/// (`start_group`/`end_group`), or exhausting the decode-work budget,
/// whatever fields decoded before that point are kept and a sibling
/// `"_decode_error"` string key records why decoding stopped early — a
/// partial, visibly-flagged result rather than silently discarding the
/// whole record (see [`crate::parsers::biome`]'s module doc comment and
/// CLAUDE.md's error-visibility principle). This mirrors iLEAPP's own
/// `_records()`, which catches a `blackboxprotobuf` decode exception and
/// still yields the record rather than dropping it.
pub fn decode_message(bytes: &[u8]) -> Value {
    let mut budget = MAX_DECODE_WORK;
    decode_message_impl(bytes, 0, &mut budget)
}

fn decode_message_impl(bytes: &[u8], depth: usize, budget: &mut usize) -> Value {
    let mut fields: Map<String, Value> = Map::new();

    if depth >= MAX_DECODE_DEPTH {
        fields.insert(
            "_decode_error".to_string(),
            Value::String("maximum nesting depth exceeded".to_string()),
        );
        return Value::Object(fields);
    }

    let mut pos = 0usize;
    let mut error: Option<String> = None;

    while pos < bytes.len() {
        if *budget == 0 {
            error = Some("decode work budget exceeded".to_string());
            break;
        }
        *budget -= 1;

        let tag_start = pos;
        let Some(tag) = read_varint(bytes, &mut pos) else {
            error = Some(format!("unterminated varint tag at byte {tag_start}"));
            break;
        };
        let field_number = tag >> 3;
        let wire_type = (tag & 0x7) as u8;
        if field_number == 0 || field_number >= MAX_FIELD_NUMBER {
            error = Some(format!(
                "invalid field number {field_number} at byte {tag_start}"
            ));
            break;
        }

        let Some(value) = decode_field_value(wire_type, bytes, &mut pos, depth, budget) else {
            error = Some(format!(
                "unsupported or truncated wire type {wire_type} for field {field_number} \
                 at byte {tag_start}"
            ));
            break;
        };

        insert_or_accumulate(&mut fields, field_number.to_string(), value);
    }

    if let Some(err) = error {
        fields.insert("_decode_error".to_string(), Value::String(err));
    }
    Value::Object(fields)
}

/// Inserts `value` under `key`, turning a second occurrence of the same
/// field number into a JSON array rather than overwriting the first —
/// protobuf allows a field number to repeat, and silently keeping only the
/// last occurrence would lose data CLAUDE.md's forensic principles say
/// must be kept.
fn insert_or_accumulate(fields: &mut Map<String, Value>, key: String, value: Value) {
    match fields.get_mut(&key) {
        None => {
            fields.insert(key, value);
        }
        Some(Value::Array(existing)) => existing.push(value),
        Some(existing) => {
            let previous = std::mem::replace(existing, Value::Null);
            *existing = Value::Array(vec![previous, value]);
        }
    }
}

fn decode_field_value(
    wire_type: u8,
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
    budget: &mut usize,
) -> Option<Value> {
    match wire_type {
        // Varint — stored as the raw bit pattern reinterpreted as a signed
        // 64-bit integer, with no attempt to guess zigzag/sign encoding
        // without a schema (matches crush's own approach).
        0 => {
            let raw = read_varint(bytes, pos)?;
            Some(json!(raw as i64))
        }
        // Fixed64 — always decoded as a double, matching crush's approach;
        // a separate heuristic layer (not implemented here) could guess
        // Cocoa/Unix/Chrome timestamp semantics for *display* purposes,
        // but that never changes what's stored here.
        1 => {
            let raw = read_fixed(bytes, pos, 8)?;
            Some(json!(f64::from_bits(u64::from_le_bytes(
                raw.try_into().unwrap()
            ))))
        }
        // Fixed32 — always decoded as a float.
        5 => {
            let raw = read_fixed(bytes, pos, 4)?;
            Some(json!(f32::from_bits(u32::from_le_bytes(
                raw.try_into().unwrap()
            ))))
        }
        // Length-delimited — could be a string, arbitrary bytes, or a
        // nested message; keep all three interpretations side by side
        // rather than committing to one and losing the others.
        2 => {
            let len = read_varint(bytes, pos)?;
            let len = usize::try_from(len).ok()?;
            if *pos + len > bytes.len() {
                return None;
            }
            let raw = &bytes[*pos..*pos + len];
            *pos += len;

            let utf8 = std::str::from_utf8(raw).ok().map(str::to_string);
            let nested = decode_nested_best_effort(raw, depth, budget);
            Some(json!({
                "utf8": utf8,
                "nested": nested,
                "hex": hex_encode(raw),
            }))
        }
        // start_group (3) / end_group (4) and anything else: neither
        // reference implementation supports groups for SEGB payloads.
        _ => None,
    }
}

/// Attempts to reparse `raw` as a nested protobuf message, but only keeps
/// the result if it's unambiguous: non-empty, and decoded with no
/// `_decode_error` at all (a partial/failed nested reparse would be more
/// misleading than useful, since `utf8`/`hex` already preserve `raw` in
/// full either way).
fn decode_nested_best_effort(raw: &[u8], depth: usize, budget: &mut usize) -> Option<Value> {
    if raw.is_empty() || *budget == 0 {
        return None;
    }
    let nested = decode_message_impl(raw, depth + 1, budget);
    match &nested {
        Value::Object(map) if !map.is_empty() && !map.contains_key("_decode_error") => Some(nested),
        _ => None,
    }
}

fn read_fixed<'a>(bytes: &'a [u8], pos: &mut usize, width: usize) -> Option<&'a [u8]> {
    if *pos + width > bytes.len() {
        return None;
    }
    let raw = &bytes[*pos..*pos + width];
    *pos += width;
    Some(raw)
}

/// Standard LEB128 varint decode. Caps continuation bytes at 10 (70 bits
/// of shift) — the maximum a valid 64-bit varint ever needs — to reject
/// pathological input that never terminates rather than looping until the
/// buffer ends.
fn read_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if shift >= 64 || *pos >= bytes.len() {
            return None;
        }
        let byte = bytes[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A compact, single-line human-readable rendering of a [`decode_message`]
/// result — `"1: \"US/Pacific\"  |  2: -25200"` — for streams with no
/// documented field semantics, so *something* readable shows instead of
/// nothing at all. Mirrors crush-forensics' own
/// `segb_parser.py::_render_proto_payload`/`_render_field` (same
/// numeric-field-order, same `"fn: value"` shape, same "show raw bytes
/// alongside a nested-message guess rather than only the guess" rule) —
/// this is the exact rendering crush's SEGB viewer shows in its one
/// "Payload" column for every stream, known or not. Renders directly from
/// the already-decoded JSON tree rather than re-parsing the raw payload
/// bytes a second time, since [`decode_message`] already did that work.
///
/// `None` for a payload with nothing to show at all (an empty message, or
/// one whose only content is `_decode_error` with zero decoded fields
/// before it) — a decode error alongside at least one real field is still
/// rendered, appended as a trailing `"decode error: ..."` note rather than
/// suppressing the fields that *did* decode.
pub fn render_payload_summary(payload: &Value) -> Option<String> {
    let Value::Object(map) = payload else {
        return None;
    };

    let mut fields: Vec<(u64, &Value)> = map
        .iter()
        .filter(|(key, _)| key.as_str() != "_decode_error")
        .filter_map(|(key, value)| key.parse::<u64>().ok().map(|n| (n, value)))
        .collect();
    fields.sort_by_key(|(field_number, _)| *field_number);

    let mut parts: Vec<String> = fields
        .into_iter()
        .filter_map(|(field_number, value)| render_field_summary(field_number, value))
        .collect();

    if let Some(err) = map.get("_decode_error").and_then(Value::as_str) {
        parts.push(format!("decode error: {err}"));
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("  |  "))
    }
}

fn render_field_summary(field_number: u64, value: &Value) -> Option<String> {
    match value {
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().filter_map(render_scalar_summary).collect();
            match rendered.len() {
                0 => None,
                1 => Some(format!("{field_number}: {}", rendered[0])),
                _ => Some(format!("{field_number}: [{}]", rendered.join(", "))),
            }
        }
        other => render_scalar_summary(other).map(|rendered| format!("{field_number}: {rendered}")),
    }
}

/// Renders one field's value — a bare number for varint/fixed32/fixed64,
/// or the `{utf8, nested, hex}` shape [`decode_field_value`] produces for
/// length-delimited fields, in priority order: a clean UTF-8 string first,
/// then a cleanly-reparsed nested message (rendered recursively, wrapped
/// in `{...}`), falling back to a byte-count-and-hex-preview for anything
/// that's neither.
fn render_scalar_summary(value: &Value) -> Option<String> {
    match value {
        Value::Number(n) => Some(n.to_string()),
        Value::Object(_) => {
            if let Some(s) = value.get("utf8").and_then(Value::as_str) {
                return Some(format!("{s:?}"));
            }
            if let Some(nested) = value.get("nested")
                && let Some(inner) = render_payload_summary(nested)
            {
                return Some(format!("{{{inner}}}"));
            }
            let hex = value.get("hex").and_then(Value::as_str).unwrap_or("");
            let byte_len = hex.len() / 2;
            const PREVIEW_HEX_CHARS: usize = 32; // 16 bytes
            let preview: String = hex.chars().take(PREVIEW_HEX_CHARS).collect();
            let ellipsis = if hex.len() > PREVIEW_HEX_CHARS {
                "…"
            } else {
                ""
            };
            Some(format!("<{byte_len} B: {preview}{ellipsis}>"))
        }
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_bytes(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn tag(field_number: u64, wire_type: u8) -> Vec<u8> {
        varint_bytes((field_number << 3) | wire_type as u64)
    }

    #[test]
    fn decodes_a_varint_field() {
        let mut bytes = tag(1, 0);
        bytes.extend(varint_bytes(150));

        let decoded = decode_message(&bytes);
        assert_eq!(decoded["1"], json!(150));
        assert!(decoded.get("_decode_error").is_none());
    }

    #[test]
    fn decodes_a_fixed64_field_as_a_double() {
        let mut bytes = tag(2, 1);
        bytes.extend_from_slice(&1.5f64.to_le_bytes());

        let decoded = decode_message(&bytes);
        assert_eq!(decoded["2"], json!(1.5));
    }

    #[test]
    fn decodes_a_fixed32_field_as_a_float() {
        let mut bytes = tag(3, 5);
        bytes.extend_from_slice(&2.5f32.to_le_bytes());

        let decoded = decode_message(&bytes);
        assert_eq!(decoded["3"], json!(2.5f32));
    }

    #[test]
    fn decodes_a_length_delimited_utf8_string() {
        let mut bytes = tag(4, 2);
        bytes.extend(varint_bytes(5));
        bytes.extend_from_slice(b"hello");

        let decoded = decode_message(&bytes);
        assert_eq!(decoded["4"]["utf8"], json!("hello"));
        assert_eq!(decoded["4"]["hex"], json!("68656c6c6f"));
        assert_eq!(decoded["4"]["nested"], Value::Null);
    }

    #[test]
    fn a_repeated_field_number_becomes_an_array() {
        let mut bytes = tag(5, 0);
        bytes.extend(varint_bytes(1));
        bytes.extend(tag(5, 0));
        bytes.extend(varint_bytes(2));

        let decoded = decode_message(&bytes);
        assert_eq!(decoded["5"], json!([1, 2]));
    }

    #[test]
    fn a_cleanly_reparsing_nested_message_is_exposed_under_nested() {
        // Field 4's payload is itself a valid protobuf message: one varint
        // field (field 1 = 42).
        let mut inner = tag(1, 0);
        inner.extend(varint_bytes(42));

        let mut bytes = tag(4, 2);
        bytes.extend(varint_bytes(inner.len() as u64));
        bytes.extend(&inner);

        let decoded = decode_message(&bytes);
        assert_eq!(decoded["4"]["nested"]["1"], json!(42));
        // The raw bytes stay available too, never discarded in favor of
        // only the nested interpretation.
        assert!(decoded["4"]["hex"].as_str().is_some());
    }

    #[test]
    fn bytes_that_dont_reparse_cleanly_leave_nested_null_but_keep_hex_and_utf8() {
        // Not valid UTF-8 and not a plausible nested message either (a
        // single 0xFF byte's high bits look like a continuing varint tag
        // that never terminates within the buffer).
        let raw: &[u8] = &[0xFF];
        let mut bytes = tag(6, 2);
        bytes.extend(varint_bytes(raw.len() as u64));
        bytes.extend_from_slice(raw);

        let decoded = decode_message(&bytes);
        assert_eq!(decoded["6"]["nested"], Value::Null);
        assert_eq!(decoded["6"]["hex"], json!("ff"));
    }

    #[test]
    fn invalid_field_number_zero_produces_a_decode_error_with_partial_fields_kept() {
        let mut bytes = tag(1, 0);
        bytes.extend(varint_bytes(7));
        // A second field with an invalid field number 0.
        bytes.extend(tag(0, 0));
        bytes.extend(varint_bytes(1));

        let decoded = decode_message(&bytes);
        assert_eq!(decoded["1"], json!(7));
        assert!(
            decoded["_decode_error"]
                .as_str()
                .unwrap()
                .contains("invalid field number 0")
        );
    }

    #[test]
    fn a_group_wire_type_produces_a_decode_error_not_a_panic() {
        let bytes = tag(1, 3); // start_group

        let decoded = decode_message(&bytes);
        assert!(decoded.get("_decode_error").is_some());
    }

    #[test]
    fn a_truncated_varint_produces_a_decode_error_not_a_panic() {
        // Every byte has its continuation bit set, and the buffer ends
        // before a terminating byte — must reject cleanly, not hang or
        // panic.
        let bytes = vec![0x80u8; 3];

        let decoded = decode_message(&bytes);
        assert!(decoded.get("_decode_error").is_some());
    }

    #[test]
    fn an_empty_message_decodes_to_an_empty_object_with_no_error() {
        let decoded = decode_message(&[]);
        assert_eq!(decoded, json!({}));
    }

    #[test]
    fn render_payload_summary_orders_by_field_number_and_quotes_strings() {
        let payload = json!({
            "2": 42,
            "1": {"utf8": "US/Pacific", "nested": null, "hex": "..."}
        });
        assert_eq!(
            render_payload_summary(&payload).unwrap(),
            "1: \"US/Pacific\"  |  2: 42"
        );
    }

    #[test]
    fn render_payload_summary_sorts_numerically_not_lexically() {
        // "10" must sort after "2", not between "1" and "2".
        let payload = json!({"1": 1, "2": 2, "10": 10});
        assert_eq!(
            render_payload_summary(&payload).unwrap(),
            "1: 1  |  2: 2  |  10: 10"
        );
    }

    #[test]
    fn render_payload_summary_collapses_a_single_repeated_value_but_lists_several() {
        let single = json!({"1": [7]});
        let multiple = json!({"1": [7, 8]});
        assert_eq!(render_payload_summary(&single).unwrap(), "1: 7");
        assert_eq!(render_payload_summary(&multiple).unwrap(), "1: [7, 8]");
    }

    #[test]
    fn render_payload_summary_shows_a_byte_preview_for_undecodable_bytes() {
        let payload = json!({"1": {"utf8": null, "nested": null, "hex": "ff00"}});
        assert_eq!(render_payload_summary(&payload).unwrap(), "1: <2 B: ff00>");
    }

    #[test]
    fn render_payload_summary_renders_a_nested_message_recursively() {
        let payload = json!({
            "1": {"utf8": null, "nested": {"1": {"utf8": "inner", "nested": null, "hex": "..."}}, "hex": "..."}
        });
        assert_eq!(
            render_payload_summary(&payload).unwrap(),
            "1: {1: \"inner\"}"
        );
    }

    #[test]
    fn render_payload_summary_appends_a_decode_error_note_after_real_fields() {
        let payload = json!({"1": 1, "_decode_error": "invalid field number 0 at byte 2"});
        assert_eq!(
            render_payload_summary(&payload).unwrap(),
            "1: 1  |  decode error: invalid field number 0 at byte 2"
        );
    }

    #[test]
    fn render_payload_summary_is_none_for_an_empty_payload() {
        assert_eq!(render_payload_summary(&json!({})), None);
    }
}
