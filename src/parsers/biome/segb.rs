//! Reads Apple's SEGB ("Segmented Biome") envelope format — the container
//! that wraps individual protobuf records inside a `biome/streams/.../local`
//! or `.../remote` file. Two on-disk variants exist, distinguished by where
//! the `"SEGB"` magic sits and by header/framing shape: v2
//! ([`read_v2_records`]) and v1 ([`read_v1_records`]).
//!
//! Ported from, and checked line-by-line against, the actual upstream
//! reference implementation: [`cclgroupltd/ccl-segb`](https://github.com/cclgroupltd/ccl-segb)
//! (CCL Forensics, MIT License), specifically `ccl_segb2.py` and
//! `ccl_segb1.py` at commit `e218d7e9e5266b833d345ba4be9cf1f7e2ea1b57`
//! (2026-07-11) — the same commit crush-forensics and iLEAPP vendor
//! verbatim. That commit is itself a fix for three real trailer-parsing
//! bugs in v2 (unrecognized trailer state, duplicate `end_offset` entries,
//! stale too-short entries) found against real device data; all three are
//! ported here too, not just the "happy path" reader. `ccl_segb1.py` was
//! not part of that hardening pass (last changed upstream 2024-05-13) and
//! has no bounds checks of its own; the v1 reader here adds them, see
//! [`read_v1_records`].
//!
//! # On-disk layout (v1)
//!
//! - 56-byte file header: `end_of_data_offset: u32` LE (absolute, from the
//!   start of the file), 48 bytes not interpreted by the reference
//!   implementation, then the 4-byte magic `"SEGB"` at offset 52.
//! - Records follow the header back to back until `end_of_data_offset`:
//!   a 32-byte record header (`record_length: i32`, `state: i32` — an
//!   [`EntryState`] raw value —, `timestamp1: f64`, `timestamp2: f64`, both
//!   Cocoa time, `crc32_stored: u32`, an `i32` of unknown meaning, all LE),
//!   then `record_length` payload bytes, then padding that aligns the next
//!   record header to an 8-byte boundary (absolute file offset).
//!
//! # On-disk layout (v2)
//!
//! - 32-byte file header: 4-byte magic `"SEGB"`, `entries_count: i32` LE,
//!   `creation_timestamp: f64` LE (Cocoa time, decoded but not otherwise
//!   used — matches upstream, which reads it and discards it too), 16
//!   bytes of unknown padding.
//! - A trailer of `entries_count` fixed 16-byte entries at the *end* of the
//!   file (`entries_count * 16` bytes before EOF): `end_offset: i32` LE
//!   (relative to the start of the data area, i.e. relative to byte 32),
//!   `state: i32` LE (an [`EntryState`] raw value), `timestamp: f64` LE
//!   (Cocoa time — this is the record's only timestamp in v2).
//! - The data area (right after the 32-byte header) holds one entry per
//!   trailer slot, walked in ascending `end_offset` order: an 8-byte
//!   mini-header (`crc32_stored: u32` LE, 4 bytes unknown), then the raw
//!   protobuf payload, then 0-3 padding bytes aligning the next entry's
//!   start to a 4-byte boundary (relative to `end_offset`).

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};

/// Both SEGB variants share this magic; only its position in the file
/// differs (last 4 bytes of a 56-byte header for v1, first 4 bytes of a
/// 32-byte header for v2).
const MAGIC: &[u8; 4] = b"SEGB";

const V1_HEADER_LENGTH: usize = 56;
const V1_RECORD_HEADER_LENGTH: usize = 32;
const V1_ALIGNMENT: usize = 8;
const V2_HEADER_LENGTH: usize = 32;
const V2_TRAILER_ENTRY_LENGTH: usize = 16;
const V2_ENTRY_HEADER_LENGTH: usize = 8;

/// 2001-01-01T00:00:00Z minus 1970-01-01T00:00:00Z, in seconds — the
/// Cocoa/Mac Absolute Time epoch offset from Unix epoch, matching
/// `ccl_segb_common.py`'s `COCOA_EPOCH`.
const COCOA_EPOCH_UNIX_SECONDS: f64 = 978_307_200.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegbVersion {
    V1,
    V2,
}

/// Mirrors `ccl_segb_common.py`'s `EntryState` IntEnum exactly: `Written`
/// (1) and `Deleted` (3) both carry real, readable record data; `Unknown`
/// (4) marks a v2 trailer slot that was never written to (see
/// [`read_v2_records`]'s doc comment on why those are skipped rather than
/// surfaced as empty records). In v1 every state sits in a record header
/// in front of its own payload bytes, so a v1 `Unknown` record is kept
/// like any other. Any other raw value isn't a valid state at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    Written,
    Deleted,
    Unknown,
}

impl EntryState {
    fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            1 => Some(EntryState::Written),
            3 => Some(EntryState::Deleted),
            4 => Some(EntryState::Unknown),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            EntryState::Written => "written",
            EntryState::Deleted => "deleted",
            EntryState::Unknown => "unknown",
        }
    }
}

/// One decoded SEGB record. `payload` is the exact, still-undecoded
/// protobuf bytes — decoding those is [`super::protobuf`]'s job, kept
/// entirely separate from envelope parsing.
#[derive(Debug, Clone)]
pub struct SegbRecord {
    pub state: EntryState,
    pub timestamp_utc: DateTime<Utc>,
    pub payload: Vec<u8>,
    /// Byte offset (from the start of the file) where this record's
    /// mini-header begins — kept for forensic traceability, not used by
    /// parsing itself.
    pub record_offset: u64,
    /// Whether the record's stored CRC32 matches one computed over
    /// `payload`. Deliberately never turned into a parse failure — see the
    /// module-level rationale in `docs/design/biome-rule-pack-research.md`
    /// and `read_v2_records`'s doc comment: a mismatch here still leaves a
    /// structurally intact, fully readable payload, and the reference
    /// implementation itself only exposes this as an inspectable property,
    /// never raises on it.
    pub crc_valid: bool,
    /// Header values only SEGB v1 records carry; `None` for v2.
    pub v1: Option<SegbV1Extra>,
}

/// The two v1 record-header values with no v2 counterpart, kept as read so
/// nothing from the header is lost. `timestamp_utc` on [`SegbRecord`] is
/// v1's `timestamp1`, the one iLEAPP's Biome modules use as the record's
/// time; `timestamp2` stays raw (Cocoa seconds) because its meaning is not
/// documented by the reference implementation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SegbV1Extra {
    pub timestamp2_raw: f64,
    pub unknown_value: i32,
}

/// Sniffs which SEGB variant (if any) `bytes` starts with, checking v1's
/// signature first and then v2's — the same order `ccl_segb.py`'s own
/// dispatcher uses. Doesn't attempt to decode anything.
pub fn detect_version(bytes: &[u8]) -> anyhow::Result<SegbVersion> {
    if bytes.len() >= V1_HEADER_LENGTH && bytes[52..56] == *MAGIC {
        return Ok(SegbVersion::V1);
    }
    if bytes.len() >= 4 && bytes[0..4] == *MAGIC {
        return Ok(SegbVersion::V2);
    }
    bail!("not a recognized SEGB v1 or v2 file (no matching magic signature found)");
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_f64(bytes: &[u8], offset: usize) -> f64 {
    f64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Decodes a Cocoa/Mac Absolute Time value (seconds since 2001-01-01) into
/// a UTC timestamp — matches `ccl_segb_common.py::decode_cocoa_time`. Kept
/// fallible (rather than clamping/guessing) since a garbage timestamp is a
/// sign of real corruption worth surfacing as a visible error, not silently
/// coercing to some default instant.
pub(super) fn decode_cocoa_time(seconds: f64) -> anyhow::Result<DateTime<Utc>> {
    if !seconds.is_finite() {
        bail!("Cocoa timestamp {seconds} is not a finite number");
    }
    let unix_seconds = seconds + COCOA_EPOCH_UNIX_SECONDS;
    let whole_seconds = unix_seconds.floor();
    let nanos = ((unix_seconds - whole_seconds) * 1e9).round() as u32;
    DateTime::from_timestamp(whole_seconds as i64, nanos).ok_or_else(|| {
        anyhow!("Cocoa timestamp {seconds} (unix seconds {unix_seconds}) is out of range")
    })
}

struct TrailerEntry {
    end_offset: i32,
    state: EntryState,
    timestamp_raw: f64,
}

/// Reads every record out of a SEGB v2 buffer. The outer `Result` fails
/// only for whole-file structural problems (bad magic, an `entries_count`
/// that would make the trailer larger than the file); the inner
/// per-`SegbRecord` `Result`s are for record-level problems affecting only
/// that one record (a computed read would run past EOF) — a caller can
/// still keep every record read successfully before such a point, matching
/// every other parser's `skip_bad_records` contract.
///
/// A trailer entry can also simply produce *no* record at all (neither
/// `Ok` nor `Err`) in three cases ported directly from `ccl_segb2.py`'s own
/// behavior, not invented here:
/// - its raw state doesn't map to a known [`EntryState`] (a zeroed/unused
///   trailer slot),
/// - its state is [`EntryState::Unknown`] (v2's "empty record" marker —
///   unlike `Deleted`, there is no readable payload behind this slot at
///   all, so unlike this project's usual "never drop recoverable data"
///   stance, there is nothing here to keep),
/// - it's a "stale" entry whose computed length is smaller than the 8-byte
///   entry mini-header, meaning it points into a region a later record has
///   already reused.
pub fn read_v2_records(bytes: &[u8]) -> anyhow::Result<Vec<anyhow::Result<SegbRecord>>> {
    if bytes.len() < V2_HEADER_LENGTH {
        bail!("file is shorter than the {V2_HEADER_LENGTH}-byte SEGB v2 header");
    }
    if bytes[0..4] != *MAGIC {
        bail!(
            "unexpected file magic: expected {:02x?}, got {:02x?}",
            MAGIC,
            &bytes[0..4]
        );
    }

    let entries_count = read_i32(bytes, 4);
    if entries_count < 0 {
        bail!("SEGB v2 header reports a negative entries_count ({entries_count})");
    }
    let entries_count = entries_count as usize;

    let trailer_bytes_len = entries_count
        .checked_mul(V2_TRAILER_ENTRY_LENGTH)
        .context("entries_count overflow while computing trailer size")?;
    if trailer_bytes_len > bytes.len() {
        bail!(
            "SEGB v2 header's entries_count ({entries_count}) implies a trailer larger than \
             the file itself"
        );
    }
    let trailer_start = bytes.len() - trailer_bytes_len;
    if trailer_start < V2_HEADER_LENGTH {
        bail!("SEGB v2 trailer overlaps the file header — file is truncated or corrupt");
    }

    let mut trailer: Vec<TrailerEntry> = Vec::with_capacity(entries_count);
    for i in 0..entries_count {
        let entry_offset = trailer_start + i * V2_TRAILER_ENTRY_LENGTH;
        let end_offset = read_i32(bytes, entry_offset);
        let state_raw = read_i32(bytes, entry_offset + 4);
        let timestamp_raw = read_f64(bytes, entry_offset + 8);
        // Some SEGB v2 files contain zeroed/unused trailer slots (state 0,
        // end offset 0); they reference no record data, so they're skipped
        // here before any length computation even happens — matches
        // ccl_segb2.py's hardening fix exactly.
        let Some(state) = EntryState::from_raw(state_raw) else {
            continue;
        };
        trailer.push(TrailerEntry {
            end_offset,
            state,
            timestamp_raw,
        });
    }

    trailer.sort_by_key(|entry| entry.end_offset);

    let mut records: Vec<anyhow::Result<SegbRecord>> = Vec::new();
    // Absolute byte offset into `bytes` of the next unread entry — starts
    // right after the header, exactly like the Python reader's
    // `stream.seek(HEADER_LENGTH, ...)`.
    let mut stream_pos: i64 = V2_HEADER_LENGTH as i64;
    let mut previous: Option<(i32, SegbRecord)> = None;

    for entry in trailer {
        if entry.state == EntryState::Unknown {
            continue;
        }

        if let Some((prev_end_offset, prev_record)) = &previous
            && entry.end_offset == *prev_end_offset
        {
            // Two trailer entries can share an end offset (e.g. a record
            // that was written and later marked deleted); both reference
            // the same data region, already read once — reuse it rather
            // than re-reading the stream (which would either desync or
            // double-count bytes).
            match decode_cocoa_time(entry.timestamp_raw) {
                Ok(timestamp_utc) => records.push(Ok(SegbRecord {
                    state: entry.state,
                    timestamp_utc,
                    payload: prev_record.payload.clone(),
                    record_offset: prev_record.record_offset,
                    crc_valid: prev_record.crc_valid,
                    v1: None,
                })),
                Err(err) => records.push(Err(err)),
            }
            continue;
        }

        // `end_offset` is relative to the start of the data area (right
        // after the header); this is how many bytes remain to be read for
        // this entry from the current stream position.
        let entry_length = entry.end_offset as i64 - stream_pos + V2_HEADER_LENGTH as i64;
        if entry_length < V2_ENTRY_HEADER_LENGTH as i64 {
            // Stale trailer entry left behind after the data area was
            // reused by a newer record — its original data is gone.
            continue;
        }
        let entry_length = entry_length as usize;

        let read_start = stream_pos as usize;
        let read_end = read_start.checked_add(entry_length);
        let Some(read_end) = read_end.filter(|&end| end <= bytes.len()) else {
            // Neither reference implementation guards against this — a
            // Python `stream.read(n)` past EOF just silently returns fewer
            // bytes. Surfacing it as a visible per-record error instead
            // (and stopping, since there's no safe offset to resync to)
            // makes the truncation visible rather than silently accepting
            // truncated data.
            records.push(Err(anyhow!(
                "record ending at data-area offset {} would read past the end of the file",
                entry.end_offset
            )));
            break;
        };

        let record_offset = stream_pos as u64;
        let entry_raw = &bytes[read_start..read_end];
        let crc32_stored = read_u32(entry_raw, 0);
        let payload = entry_raw[V2_ENTRY_HEADER_LENGTH..].to_vec();
        let crc32_calculated = crc32fast::hash(&payload);

        stream_pos = read_end as i64;
        // Align to a 4-byte boundary, relative to `end_offset` (matches
        // Python's `end_offset % 4` — equivalent to aligning the absolute
        // stream position too, since the 32-byte header is itself already
        // 4-byte aligned).
        let remainder = entry.end_offset.rem_euclid(4);
        if remainder != 0 {
            stream_pos += (4 - remainder) as i64;
        }

        match decode_cocoa_time(entry.timestamp_raw) {
            Ok(timestamp_utc) => {
                let record = SegbRecord {
                    state: entry.state,
                    timestamp_utc,
                    payload,
                    record_offset,
                    crc_valid: crc32_stored == crc32_calculated,
                    v1: None,
                };
                previous = Some((entry.end_offset, record.clone()));
                records.push(Ok(record));
            }
            Err(err) => records.push(Err(err)),
        }
    }

    Ok(records)
}

/// Reads every record out of a SEGB v1 buffer, following `ccl_segb1.py`'s
/// `read_segb1_stream`: records are walked from the end of the 56-byte
/// header while the position is below the header's `end_of_data_offset`,
/// each record's payload is `record_length` bytes after its 32-byte
/// header, and the next header starts at the next 8-byte boundary.
///
/// Same `Result` contract as [`read_v2_records`]. Where the reference
/// implementation has no check, this reader adds one and makes the problem
/// visible instead:
/// - a record header or payload that would run past the end of the file
///   (Python's `read(n)` would silently return fewer bytes) and a negative
///   `record_length` are a per-record error that ends the walk, since
///   there is no trustworthy offset to continue from;
/// - an unrecognized state raw value or an undecodable `timestamp1` (where
///   the reference raises and aborts the whole file) is a per-record error,
///   and the walk continues with the next record, because the record's
///   length — and therefore where the next one starts — is still known.
///
/// Unlike v2, `Unknown` (4) records are returned, not skipped: in v1 the
/// state sits in front of the record's own payload bytes, so there is data
/// behind it.
pub fn read_v1_records(bytes: &[u8]) -> anyhow::Result<Vec<anyhow::Result<SegbRecord>>> {
    if bytes.len() < V1_HEADER_LENGTH {
        bail!("file is shorter than the {V1_HEADER_LENGTH}-byte SEGB v1 header");
    }
    if bytes[52..56] != *MAGIC {
        bail!(
            "unexpected file magic: expected {:02x?} at offset 52, got {:02x?}",
            MAGIC,
            &bytes[52..56]
        );
    }
    let end_of_data_offset = read_u32(bytes, 0) as usize;

    let mut records: Vec<anyhow::Result<SegbRecord>> = Vec::new();
    let mut pos = V1_HEADER_LENGTH;

    while pos < end_of_data_offset {
        let header_end = pos + V1_RECORD_HEADER_LENGTH;
        if header_end > bytes.len() {
            records.push(Err(anyhow!(
                "record header at offset {pos} would read past the end of the file \
                 (end of data per file header: {end_of_data_offset}, file size: {})",
                bytes.len()
            )));
            break;
        }
        let record_length = read_i32(bytes, pos);
        let state_raw = read_i32(bytes, pos + 4);
        let timestamp1_raw = read_f64(bytes, pos + 8);
        let timestamp2_raw = read_f64(bytes, pos + 16);
        let crc32_stored = read_u32(bytes, pos + 24);
        let unknown_value = read_i32(bytes, pos + 28);

        if record_length < 0 {
            records.push(Err(anyhow!(
                "record at offset {pos} has a negative length ({record_length})"
            )));
            break;
        }
        let record_offset = header_end;
        let Some(data_end) = record_offset
            .checked_add(record_length as usize)
            .filter(|&end| end <= bytes.len())
        else {
            records.push(Err(anyhow!(
                "record at offset {pos} ({record_length} bytes) would read past the end of \
                 the file"
            )));
            break;
        };

        let payload = bytes[record_offset..data_end].to_vec();
        pos = data_end;
        let remainder = pos % V1_ALIGNMENT;
        if remainder != 0 {
            pos += V1_ALIGNMENT - remainder;
        }

        let Some(state) = EntryState::from_raw(state_raw) else {
            records.push(Err(anyhow!(
                "record at offset {record_offset} has an unrecognized state ({state_raw})"
            )));
            continue;
        };
        match decode_cocoa_time(timestamp1_raw) {
            Ok(timestamp_utc) => records.push(Ok(SegbRecord {
                state,
                timestamp_utc,
                crc_valid: crc32_stored == crc32fast::hash(&payload),
                payload,
                record_offset: record_offset as u64,
                v1: Some(SegbV1Extra {
                    timestamp2_raw,
                    unknown_value,
                }),
            })),
            Err(err) => records.push(Err(
                err.context(format!("timestamp1 of record at offset {record_offset}"))
            )),
        }
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic SEGB v2 buffer with real on-disk alignment
    /// padding between entries, mirroring `crush/tests/test_ccl_segb2.py`'s
    /// `_build_segb2()` helper (same project, same author, ported here
    /// rather than re-derived) — `end_offset` in the trailer is the
    /// *unpadded* boundary, matching the real format.
    fn build_segb2(entries: &[(&[u8], i32)]) -> Vec<u8> {
        let mut data_area = Vec::new();
        let mut trailer_entries = Vec::new();
        for (payload, state_raw) in entries {
            let crc = crc32fast::hash(payload);
            data_area.extend_from_slice(&crc.to_le_bytes());
            data_area.extend_from_slice(&0i32.to_le_bytes());
            data_area.extend_from_slice(payload);
            let end_offset = data_area.len() as i32;
            trailer_entries.push((end_offset, *state_raw));
            let remainder = end_offset.rem_euclid(4);
            if remainder != 0 {
                data_area.extend(std::iter::repeat_n(0u8, (4 - remainder) as usize));
            }
        }

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(trailer_entries.len() as i32).to_le_bytes());
        out.extend_from_slice(&0f64.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&data_area);
        for (end_offset, state_raw) in trailer_entries {
            out.extend_from_slice(&end_offset.to_le_bytes());
            out.extend_from_slice(&state_raw.to_le_bytes());
            out.extend_from_slice(&0f64.to_le_bytes());
        }
        out
    }

    #[test]
    fn detect_version_recognizes_v2_signature_at_start() {
        let bytes = build_segb2(&[(b"x", 1)]);
        assert_eq!(detect_version(&bytes).unwrap(), SegbVersion::V2);
    }

    #[test]
    fn detect_version_recognizes_v1_signature_at_offset_52() {
        let mut header = vec![0u8; V1_HEADER_LENGTH];
        header[52..56].copy_from_slice(MAGIC);
        assert_eq!(detect_version(&header).unwrap(), SegbVersion::V1);
    }

    #[test]
    fn detect_version_rejects_neither_signature() {
        let bytes = vec![0u8; 64];
        assert!(detect_version(&bytes).is_err());
    }

    /// One synthetic v1 record: payload, raw state, raw `timestamp1`, and
    /// whether to store the payload's real CRC32.
    struct V1Entry<'a> {
        payload: &'a [u8],
        state_raw: i32,
        timestamp1: f64,
        valid_crc: bool,
    }

    fn v1(payload: &[u8], state_raw: i32) -> V1Entry<'_> {
        V1Entry {
            payload,
            state_raw,
            timestamp1: 700_000_000.0,
            valid_crc: true,
        }
    }

    /// Builds a SEGB v1 buffer the way `ccl_segb1.py` reads it: 56-byte
    /// header (end-of-data offset first, magic at 52), then per record a
    /// 32-byte header, the payload and padding to the next 8-byte boundary.
    /// `end_of_data_offset` is the position after the last payload.
    fn build_segb1(entries: &[V1Entry]) -> Vec<u8> {
        let mut out = vec![0u8; V1_HEADER_LENGTH];
        out[52..56].copy_from_slice(MAGIC);
        let mut end_of_data = V1_HEADER_LENGTH;
        for entry in entries {
            let remainder = out.len() % V1_ALIGNMENT;
            if remainder != 0 {
                out.extend(std::iter::repeat_n(0u8, V1_ALIGNMENT - remainder));
            }
            let crc = if entry.valid_crc {
                crc32fast::hash(entry.payload)
            } else {
                crc32fast::hash(entry.payload) ^ 1
            };
            out.extend_from_slice(&(entry.payload.len() as i32).to_le_bytes());
            out.extend_from_slice(&entry.state_raw.to_le_bytes());
            out.extend_from_slice(&entry.timestamp1.to_le_bytes());
            out.extend_from_slice(&(entry.timestamp1 + 1.0).to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&0i32.to_le_bytes());
            out.extend_from_slice(entry.payload);
            end_of_data = out.len();
        }
        out[0..4].copy_from_slice(&(end_of_data as u32).to_le_bytes());
        out
    }

    #[test]
    fn v1_records_are_read_in_order_with_8_byte_alignment() {
        // "first" is 5 bytes, so 3 padding bytes follow it before the next
        // record header (56 + 32 + 5 = 93 -> 96).
        let bytes = build_segb1(&[v1(b"first", 1), v1(b"second-entry", 3)]);

        let records = read_v1_records(&bytes).unwrap();

        assert_eq!(records.len(), 2);
        let first = records[0].as_ref().unwrap();
        let second = records[1].as_ref().unwrap();
        assert_eq!(first.payload, b"first");
        assert_eq!(first.state, EntryState::Written);
        assert_eq!(first.record_offset, 88);
        assert!(first.crc_valid);
        assert_eq!(second.payload, b"second-entry");
        assert_eq!(second.state, EntryState::Deleted);
        assert_eq!(second.record_offset, 96 + 32);
        let extra = first.v1.unwrap();
        assert_eq!(extra.timestamp2_raw, 700_000_001.0);
        assert_eq!(extra.unknown_value, 0);
        assert_eq!(
            first.timestamp_utc,
            decode_cocoa_time(700_000_000.0).unwrap()
        );
    }

    /// A real v1 file (see `tests/fixtures/biome/README.md`). Expected
    /// values are `ccl_segb1.py`'s output for the same file.
    #[test]
    fn decodes_the_real_device_segb1_fixture() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/biome/Device.Wireless.Bluetooth.segb1"
        ))
        .unwrap();
        assert_eq!(detect_version(&bytes).unwrap(), SegbVersion::V1);

        let records: Vec<SegbRecord> = read_v1_records(&bytes)
            .unwrap()
            .into_iter()
            .map(Result::unwrap)
            .collect();

        let expected = [
            (88, EntryState::Deleted, "2024-01-21T18:37:21.769812", false),
            (
                184,
                EntryState::Deleted,
                "2024-01-21T20:09:53.319835",
                false,
            ),
            (280, EntryState::Written, "2024-07-28T17:26:30.785707", true),
            (376, EntryState::Written, "2024-07-28T17:48:12.543322", true),
        ];
        assert_eq!(records.len(), expected.len());
        for (record, (offset, state, time, crc_valid)) in records.iter().zip(expected) {
            assert_eq!(record.record_offset, offset);
            assert_eq!(record.state, state);
            // The reference rounds to whole microseconds, Peach keeps
            // nanoseconds, so compare within half a microsecond.
            let expected_time =
                chrono::NaiveDateTime::parse_from_str(time, "%Y-%m-%dT%H:%M:%S%.6f")
                    .unwrap()
                    .and_utc();
            let diff = (record.timestamp_utc - expected_time)
                .num_nanoseconds()
                .unwrap();
            assert!(diff.abs() <= 500, "{time}: off by {diff} ns");
            assert_eq!(record.crc_valid, crc_valid);
            assert_eq!(record.payload.len(), 57);
            // In this file both timestamps of every record are equal.
            assert_eq!(
                decode_cocoa_time(record.v1.unwrap().timestamp2_raw).unwrap(),
                record.timestamp_utc
            );
        }
        // Deleted records are zeroed; the written ones carry the device.
        assert!(records[0].payload.iter().all(|&b| b == 0));
        let written = String::from_utf8_lossy(&records[2].payload);
        assert!(written.contains("08:65:18:75:5E:75"));
        assert!(written.contains("AirPods"));
    }

    #[test]
    fn v1_header_without_records_yields_nothing() {
        let bytes = build_segb1(&[]);
        assert!(read_v1_records(&bytes).unwrap().is_empty());
    }

    #[test]
    fn v1_unknown_state_records_are_kept_because_they_carry_data() {
        let bytes = build_segb1(&[v1(b"data", 4)]);

        let records = read_v1_records(&bytes).unwrap();

        assert_eq!(records.len(), 1);
        let record = records[0].as_ref().unwrap();
        assert_eq!(record.state, EntryState::Unknown);
        assert_eq!(record.payload, b"data");
    }

    #[test]
    fn v1_crc_mismatch_is_reported_not_rejected() {
        let mut entry = v1(b"payload", 1);
        entry.valid_crc = false;
        let bytes = build_segb1(&[entry]);

        let records = read_v1_records(&bytes).unwrap();

        assert!(!records[0].as_ref().unwrap().crc_valid);
    }

    #[test]
    fn v1_unrecognized_state_is_an_error_and_the_walk_continues() {
        let bytes = build_segb1(&[v1(b"bad", 9), v1(b"good", 1)]);

        let records = read_v1_records(&bytes).unwrap();

        assert_eq!(records.len(), 2);
        let err = records[0].as_ref().unwrap_err();
        assert!(format!("{err:#}").contains("unrecognized state (9)"));
        assert_eq!(records[1].as_ref().unwrap().payload, b"good");
    }

    #[test]
    fn v1_undecodable_timestamp1_is_an_error_and_the_walk_continues() {
        let mut bad = v1(b"bad", 1);
        bad.timestamp1 = f64::NAN;
        let bytes = build_segb1(&[bad, v1(b"good", 1)]);

        let records = read_v1_records(&bytes).unwrap();

        assert_eq!(records.len(), 2);
        assert!(records[0].is_err());
        assert_eq!(records[1].as_ref().unwrap().payload, b"good");
    }

    #[test]
    fn v1_payload_past_end_of_file_is_an_error_and_stops() {
        let mut bytes = build_segb1(&[v1(b"first", 1), v1(b"second-entry", 1)]);
        bytes.truncate(bytes.len() - 4);

        let records = read_v1_records(&bytes).unwrap();

        assert_eq!(records.len(), 2);
        assert!(records[0].is_ok());
        let err = records[1].as_ref().unwrap_err();
        assert!(format!("{err:#}").contains("past the end of the file"));
    }

    #[test]
    fn v1_record_header_past_end_of_file_is_an_error() {
        let mut bytes = build_segb1(&[]);
        // Claims data up to offset 200, but the file ends right after the
        // file header.
        bytes[0..4].copy_from_slice(&200u32.to_le_bytes());

        let records = read_v1_records(&bytes).unwrap();

        assert_eq!(records.len(), 1);
        assert!(records[0].is_err());
    }

    #[test]
    fn v1_negative_record_length_is_an_error_and_stops() {
        let mut bytes = build_segb1(&[v1(b"first", 1), v1(b"second", 1)]);
        bytes[56..60].copy_from_slice(&(-5i32).to_le_bytes());

        let records = read_v1_records(&bytes).unwrap();

        assert_eq!(records.len(), 1);
        let err = records[0].as_ref().unwrap_err();
        assert!(format!("{err:#}").contains("negative length (-5)"));
    }

    #[test]
    fn v1_short_file_or_wrong_magic_fails_the_whole_file() {
        assert!(read_v1_records(&[0u8; 40]).is_err());
        assert!(read_v1_records(&[0u8; 64]).is_err());
    }

    #[test]
    fn decodes_the_real_minimal_segb2_fixture() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/biome/minimal.segb2"
        ))
        .unwrap();

        assert_eq!(detect_version(&bytes).unwrap(), SegbVersion::V2);
        let records = read_v2_records(&bytes).unwrap();
        assert_eq!(records.len(), 1);
        let record = records[0].as_ref().unwrap();
        assert_eq!(record.payload, vec![0x12, 0x04, b't', b'e', b's', b't']);
        assert_eq!(record.state, EntryState::Written);
        assert!(record.crc_valid);
    }

    #[test]
    fn well_formed_file_parses_normally() {
        let bytes = build_segb2(&[(b"first", 1), (b"second-entry", 1)]);

        let records = read_v2_records(&bytes).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].as_ref().unwrap().payload, b"first");
        assert_eq!(records[1].as_ref().unwrap().payload, b"second-entry");
        assert!(records.iter().all(|r| r.as_ref().unwrap().crc_valid));
    }

    #[test]
    fn invalid_trailer_state_is_skipped_not_an_error() {
        // 99 doesn't map to any EntryState — `build_segb2` still writes a
        // real header+payload+alignment for it (matching how a genuine
        // zeroed/unused trailer slot's data area bytes exist on disk even
        // though nothing valid points at them), but no record should ever
        // come out for it. Mirrors crush-forensics' own regression test
        // for this exact case.
        let bytes = build_segb2(&[(b"hello world!", 1), (b"junk", 99)]);

        let records = read_v2_records(&bytes).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_ref().unwrap().payload, b"hello world!");
    }

    #[test]
    fn duplicate_end_offset_reuses_previous_entrys_data() {
        let payload: &[u8] = b"shared-entry-data";
        let crc = crc32fast::hash(payload);
        let mut entry_bytes = Vec::new();
        entry_bytes.extend_from_slice(&crc.to_le_bytes());
        entry_bytes.extend_from_slice(&0i32.to_le_bytes());
        entry_bytes.extend_from_slice(payload);
        let end_offset = entry_bytes.len() as i32;
        let remainder = end_offset.rem_euclid(4);
        if remainder != 0 {
            entry_bytes.extend(std::iter::repeat_n(0u8, (4 - remainder) as usize));
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&2i32.to_le_bytes());
        bytes.extend_from_slice(&0f64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&entry_bytes);
        bytes.extend_from_slice(&end_offset.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes()); // Written
        bytes.extend_from_slice(&0f64.to_le_bytes());
        bytes.extend_from_slice(&end_offset.to_le_bytes());
        bytes.extend_from_slice(&3i32.to_le_bytes()); // Deleted
        bytes.extend_from_slice(&0f64.to_le_bytes());

        let records = read_v2_records(&bytes).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].as_ref().unwrap().payload, payload);
        assert_eq!(records[1].as_ref().unwrap().payload, payload);
        assert_eq!(records[0].as_ref().unwrap().state, EntryState::Written);
        assert_eq!(records[1].as_ref().unwrap().state, EntryState::Deleted);
    }

    #[test]
    fn stale_trailer_entry_with_too_small_length_is_skipped() {
        let payload: &[u8] = b"first-real-entry";
        let mut entry_bytes = Vec::new();
        entry_bytes.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
        entry_bytes.extend_from_slice(&0i32.to_le_bytes());
        entry_bytes.extend_from_slice(payload);
        assert_eq!(entry_bytes.len(), 24); // 8-byte header + 16-byte payload, already 4-aligned

        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&2i32.to_le_bytes());
        bytes.extend_from_slice(&0f64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&entry_bytes);
        // entry1 ends at offset 24; a stale trailer slot at offset 27
        // computes to length 27 - 56 + 32 = 3, below the 8-byte minimum.
        bytes.extend_from_slice(&24i32.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0f64.to_le_bytes());
        bytes.extend_from_slice(&27i32.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0f64.to_le_bytes());

        let records = read_v2_records(&bytes).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_ref().unwrap().payload, payload);
    }

    #[test]
    fn crc_mismatch_is_surfaced_not_treated_as_a_parse_failure() {
        let payload: &[u8] = b"tampered";
        let mut entry_bytes = Vec::new();
        // Deliberately wrong CRC.
        entry_bytes.extend_from_slice(&0xdead_beefu32.to_le_bytes());
        entry_bytes.extend_from_slice(&0i32.to_le_bytes());
        entry_bytes.extend_from_slice(payload);
        let end_offset = entry_bytes.len() as i32;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0f64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&entry_bytes);
        bytes.extend_from_slice(&end_offset.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0f64.to_le_bytes());

        let records = read_v2_records(&bytes).unwrap();

        assert_eq!(records.len(), 1);
        let record = records[0].as_ref().unwrap();
        assert_eq!(record.payload, payload);
        assert!(!record.crc_valid);
    }

    #[test]
    fn entries_count_implying_a_too_large_trailer_is_a_file_level_error() {
        let mut bytes = vec![0u8; V2_HEADER_LENGTH];
        bytes[0..4].copy_from_slice(MAGIC);
        bytes[4..8].copy_from_slice(&1000i32.to_le_bytes());

        assert!(read_v2_records(&bytes).is_err());
    }

    #[test]
    fn decode_cocoa_time_round_trips_the_cocoa_epoch_itself() {
        // 0 seconds since the Cocoa epoch is 2001-01-01T00:00:00Z exactly.
        let decoded = decode_cocoa_time(0.0).unwrap();
        assert_eq!(decoded.to_string(), "2001-01-01 00:00:00 UTC");
    }
}
