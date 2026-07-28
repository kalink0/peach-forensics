use chrono::{DateTime, Utc};

use crate::model::event_id::EventId;

/// A single normalized timeline entry, per section 4.2 of CLAUDE.md.
///
/// `raw` is mandatory, never optional: peach's forensic principle (section
/// 0.1) is that normalization must never lose or overwrite the original
/// source data.
#[derive(Debug, Clone, PartialEq)]
pub struct LogEntry {
    pub event_id: EventId,
    pub timestamp_utc: DateTime<Utc>,
    pub level: Option<String>,
    pub message: Option<String>,
    pub raw: String,
    pub fields: serde_json::Value,
}

/// A [`LogEntry`] before its stable [`EventId`] has been assigned.
///
/// Parsers ([`crate::parsers::LogParser`]) produce these; `event_id`
/// assignment is centralized (see [`crate::parsers::parse_source`]) so that
/// `source_file_id`/`sequence_number` assignment works identically across
/// every parser implementation, rather than each parser computing its own.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedRecord {
    pub timestamp_utc: DateTime<Utc>,
    pub level: Option<String>,
    pub message: Option<String>,
    pub raw: String,
    pub fields: serde_json::Value,
}
