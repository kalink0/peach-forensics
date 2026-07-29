use chrono::Utc;
use rusqlite::{Connection, Result, params};

use crate::model::event_id::{EventId, SequenceNumber, SourceFileId};

/// A manually-set analyst tag (the fourth, analyst-driven tagging layer —
/// not rule-based, lives in the SQLite session-DB rather than
/// `import_tags`).
#[derive(Debug, Clone, PartialEq)]
pub struct AnalystTag {
    pub event_id: EventId,
    pub tag_value: String,
    pub note: Option<String>,
    pub created_at: i64,
}

/// Records a manual tag against `event_id`. `created_at` is Unix-epoch
/// seconds, set here (not by the caller) so it's always accurate.
pub fn add_analyst_tag(
    conn: &Connection,
    event_id: EventId,
    tag_value: &str,
    note: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO analyst_tags (event_id_source, event_id_seq, tag_value, note, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event_id.source_file_id.to_string(),
            event_id.sequence_number.value() as i64,
            tag_value,
            note,
            Utc::now().timestamp(),
        ],
    )?;
    Ok(())
}

/// All manual tags recorded for one event, oldest first.
pub fn list_analyst_tags_for_event(
    conn: &Connection,
    event_id: EventId,
) -> Result<Vec<AnalystTag>> {
    let mut stmt = conn.prepare(
        "SELECT event_id_source, event_id_seq, tag_value, note, created_at
         FROM analyst_tags
         WHERE event_id_source = ?1 AND event_id_seq = ?2
         ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map(
        params![
            event_id.source_file_id.to_string(),
            event_id.sequence_number.value() as i64
        ],
        row_to_analyst_tag,
    )?;
    rows.collect()
}

/// Every manual tag in the session, oldest first.
pub fn list_all_analyst_tags(conn: &Connection) -> Result<Vec<AnalystTag>> {
    let mut stmt = conn.prepare(
        "SELECT event_id_source, event_id_seq, tag_value, note, created_at
         FROM analyst_tags
         ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map([], row_to_analyst_tag)?;
    rows.collect()
}

fn row_to_analyst_tag(row: &rusqlite::Row<'_>) -> Result<AnalystTag> {
    let source_file_id: String = row.get(0)?;
    let sequence_number: i64 = row.get(1)?;
    let source_file_id: SourceFileId = source_file_id.parse().map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!(
                "invalid source_file_id in database: {err}"
            ))),
        )
    })?;

    Ok(AnalystTag {
        event_id: EventId {
            source_file_id,
            sequence_number: SequenceNumber::from_raw(sequence_number as u64),
        },
        tag_value: row.get(2)?,
        note: row.get(3)?,
        created_at: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_schema::setup_session_schema;
    use crate::model::event_id::SequenceCounter;

    fn open_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        setup_session_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn add_and_list_a_tag_for_one_event() {
        let conn = open_test_db();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceNumber::from_raw(0),
        };

        add_analyst_tag(&conn, event_id, "reviewed", Some("looks suspicious")).unwrap();

        let tags = list_analyst_tags_for_event(&conn, event_id).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].event_id, event_id);
        assert_eq!(tags[0].tag_value, "reviewed");
        assert_eq!(tags[0].note.as_deref(), Some("looks suspicious"));
    }

    #[test]
    fn a_note_is_optional() {
        let conn = open_test_db();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceNumber::from_raw(0),
        };

        add_analyst_tag(&conn, event_id, "flagged", None).unwrap();

        let tags = list_analyst_tags_for_event(&conn, event_id).unwrap();
        assert_eq!(tags[0].note, None);
    }

    #[test]
    fn an_event_can_have_multiple_tags() {
        let conn = open_test_db();
        let event_id = EventId {
            source_file_id: SourceFileId::new_random(),
            sequence_number: SequenceNumber::from_raw(0),
        };

        add_analyst_tag(&conn, event_id, "reviewed", None).unwrap();
        add_analyst_tag(&conn, event_id, "flagged", None).unwrap();

        let tags = list_analyst_tags_for_event(&conn, event_id).unwrap();
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn list_for_event_only_returns_that_events_tags() {
        let conn = open_test_db();
        let source_file_id = SourceFileId::new_random();
        let mut counter = SequenceCounter::new();
        let event_a = EventId {
            source_file_id,
            sequence_number: counter.next_sequence_number(),
        };
        let event_b = EventId {
            source_file_id,
            sequence_number: counter.next_sequence_number(),
        };

        add_analyst_tag(&conn, event_a, "tag_a", None).unwrap();
        add_analyst_tag(&conn, event_b, "tag_b", None).unwrap();

        let tags_a = list_analyst_tags_for_event(&conn, event_a).unwrap();
        assert_eq!(tags_a.len(), 1);
        assert_eq!(tags_a[0].tag_value, "tag_a");
    }

    #[test]
    fn list_all_returns_every_tag_in_the_session() {
        let conn = open_test_db();
        let mut counter = SequenceCounter::new();
        let source_file_id = SourceFileId::new_random();

        add_analyst_tag(
            &conn,
            EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            },
            "tag_a",
            None,
        )
        .unwrap();
        add_analyst_tag(
            &conn,
            EventId {
                source_file_id,
                sequence_number: counter.next_sequence_number(),
            },
            "tag_b",
            None,
        )
        .unwrap();

        let all = list_all_analyst_tags(&conn).unwrap();
        assert_eq!(all.len(), 2);
    }
}
