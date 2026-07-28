use std::fmt;

use thiserror::Error;
use uuid::Uuid;

/// Stable identifier for one loaded source (file or, for bundle-style
/// sources like AUL `.logarchive`s, directory), assigned fresh at import
/// time — not derived from file content or path.
///
/// Peach only ever reads evidence (section 0.1); integrity hashing is the
/// acquisition tool's job, not Peach's. `source_file_id` exists solely so
/// [`EventId`] can always point back to "this loaded source, this position
/// within it" — that only needs uniqueness, not content-derivation.
/// Consequence: re-loading the same file twice is **not** detected or
/// deduplicated — it produces two independent sources with duplicate
/// entries. See the `source-file-id-design` project note for the full
/// rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceFileId(Uuid);

impl SourceFileId {
    pub fn new_random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for SourceFileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Error)]
#[error("invalid source file id: {0}")]
pub struct SourceFileIdParseError(#[from] uuid::Error);

impl std::str::FromStr for SourceFileId {
    type Err = SourceFileIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Position of an entry within a single parsing run of a source file.
/// Assigned in strict ascending order by [`SequenceCounter`], independent of
/// timestamp or message content, so genuine duplicates (e.g. retry loops
/// within the same second) stay distinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SequenceNumber(u64);

impl SequenceNumber {
    pub fn value(self) -> u64 {
        self.0
    }

    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }
}

/// Hands out strictly ascending [`SequenceNumber`]s for one parsing run.
#[derive(Debug, Default)]
pub struct SequenceCounter(u64);

impl SequenceCounter {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn next_sequence_number(&mut self) -> SequenceNumber {
        let seq = SequenceNumber(self.0);
        self.0 += 1;
        seq
    }
}

/// Stable composite key for a single timeline entry, per section 4.1 of
/// CLAUDE.md: `(source_file_id, sequence_number)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId {
    pub source_file_id: SourceFileId,
    pub sequence_number: SequenceNumber,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn new_random_produces_distinct_ids() {
        let a = SourceFileId::new_random();
        let b = SourceFileId::new_random();

        assert_ne!(a, b);
    }

    #[test]
    fn display_and_from_str_round_trip() {
        let id = SourceFileId::new_random();

        let parsed = SourceFileId::from_str(&id.to_string()).unwrap();

        assert_eq!(id, parsed);
    }

    #[test]
    fn from_str_rejects_garbage() {
        let result = SourceFileId::from_str("not a uuid");

        assert!(result.is_err());
    }

    #[test]
    fn sequence_counter_is_strictly_ascending() {
        let mut counter = SequenceCounter::new();

        let first = counter.next_sequence_number();
        let second = counter.next_sequence_number();
        let third = counter.next_sequence_number();

        assert_eq!(first.value(), 0);
        assert_eq!(second.value(), 1);
        assert_eq!(third.value(), 2);
    }

    #[test]
    fn distinct_sequence_numbers_keep_duplicate_content_distinguishable() {
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

        assert_ne!(event_a, event_b);
    }
}
