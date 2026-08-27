use std::path::Path;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};

use crate::model::log_entry::ParsedRecord;
use crate::parsers::{LogParser, ParserConfig, SkippedRecord};

/// Hand-rolled reader for the systemd journal binary file format.
///
/// Unlike EVTX and AUL, there is no dependency-safe crate to wrap here: the
/// only pure-Rust, cross-platform reader for the raw binary format
/// (`systemd-journal-sdk`) is GPL-3.0-or-later, which would pull peach's
/// Apache-2.0-licensed, statically-linked binary under GPL copyleft on
/// distribution — a project-wide licensing decision, not a parser
/// implementation detail, so it was rejected in favor of implementing the
/// format directly. The alternative `journald` crate binds against
/// `libsystemd`, which is Linux-only and would break the Windows/macOS
/// legs of Peach's cross-platform CI matrix.
///
/// Format reference: <https://systemd.io/JOURNAL_FILE_FORMAT/>. Rather than
/// following the hash-table/entry-array linked lists real `libsystemd`
/// uses for keyed lookups (which we don't need — we want every entry, in
/// order, not a keyed query), this reads the file as a flat arena: walk
/// object headers sequentially from `header_size` to `tail_object_offset`,
/// picking out `OBJECT_ENTRY` objects as we go. This is simpler *and* more
/// forensically robust: it doesn't depend on the hash-table/array chains
/// being intact, so it still finds every entry in a journal whose index
/// structures are partially corrupted — the linked-list-following approach
/// real journald read tooling uses would silently stop early in that case.
///
/// `level` is the raw `PRIORITY` field value verbatim (syslog priority
/// digit `"0"`-`"7"`) — not remapped, same convention as EVTX's `Level` and
/// AUL's `LogType`. `message` is the `MESSAGE` field, since journald (unlike
/// EVTX) stores literal message text rather than a template + parameters.
/// `raw`/`fields` hold every field on the entry (including synthesized
/// `__REALTIME_TIMESTAMP`/`__MONOTONIC_TIMESTAMP`/`__SEQNUM`, matching real
/// sd-journal's own naming for these — they come from the `ENTRY` object's
/// header, not a stored field, in both implementations).
///
/// Both the "regular" and "compact" (`HEADER_INCOMPATIBLE_COMPACT`, systemd
/// 254+ — the default on every current distro, verified against this
/// format's own source: `journal-def.h`'s `EntryObject`/`DataObject`
/// definitions) entry formats are implemented — forensic parsers don't get
/// to treat "the format most machines actually produce" as optional just
/// because support for it didn't exist yet when the rest of the parser was
/// written. Compact mode changes two things, both handled here: each
/// `ENTRY` object's item array shrinks from 16 bytes/item (8-byte object
/// offset + 8-byte hash) to 4 bytes/item (just a 32-bit object offset, no
/// hash, per `write_entry_item()` in `journal-file.c` — raw byte offset,
/// not scaled, which is also why compact-mode files are capped at 4 GiB);
/// and every `DATA` object gains 8 extra bytes before its payload (compact
/// mode's `tail_entry_array_offset`/`tail_entry_array_n_entries`, unused by
/// this parser's flat-scan design — see below — but still present in the
/// byte layout and must be skipped over to find the real payload).
///
/// Known limitations, surfaced rather than silently worked around:
/// - Only LZ4-compressed field values are decompressed (journald's default
///   compression since systemd ~246). XZ/ZSTD-compressed fields are left
///   visible with a placeholder value noting the unsupported algorithm,
///   rather than being silently dropped — consistent with how AUL surfaces
///   unresolved oversize strings instead of dropping them.
/// - Only little-endian journal files are supported (universal on modern
///   Linux since systemd unified the on-disk format around v246; older
///   big-endian archives are out of scope).
/// - A single corrupt/truncated object aborts the whole parse by default.
///   `skip_bad_records` distinguishes two cases: a corrupt *entry* (its
///   object header parsed fine, so its size — and therefore the next
///   object's offset — is known) is skippable and parsing continues past
///   it. A corrupt object *header* is not: its size is exactly what failed
///   to parse, so there is no safe way to know where the next object starts
///   without guessing — this crosses the line from "one bad record" into
///   "the file's structure is no longer trustworthy from here on", which
///   would mean fabricating a resync point rather than reading one. In that
///   case skip mode keeps every entry parsed before the corruption as a
///   normal, successful (partial) result, plus one final [`SkippedRecord`]
///   noting where and why it stopped — it does not scan forward hunting for
///   the next plausible object.
///
/// No config-driven field-mapping, like EVTX/AUL — `ParserConfig.extra` is
/// unused.
pub struct JournaldFileParser;

impl LogParser for JournaldFileParser {
    fn sourcetype(&self) -> &str {
        "journald"
    }

    fn parse(
        &self,
        path: &Path,
        _config: &ParserConfig,
        skip_bad_records: bool,
    ) -> anyhow::Result<(Vec<ParsedRecord>, Vec<SkippedRecord>)> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read journal file {}", path.display()))?;
        parse_bytes(&bytes, skip_bad_records)
    }
}

const SIGNATURE: [u8; 8] = *b"LPKSHHRH";

const OBJECT_HEADER_SIZE: u64 = 16;
const DATA_OBJECT_FIXED_SIZE: u64 = 48;
/// Extra bytes before a compact-mode `DATA` object's payload — the
/// `tail_entry_array_offset`/`tail_entry_array_n_entries` `le32` pair that
/// only exists in `DataObject`'s `compact` union arm (`journal-def.h`).
const DATA_OBJECT_COMPACT_EXTRA: u64 = 8;
const ENTRY_FIXED_SIZE: u64 = 48;
/// Regular-mode entry item: `{ object_offset: le64, hash: le64 }`.
const ENTRY_ITEM_SIZE: u64 = 16;
/// Compact-mode entry item: `{ object_offset: le32 }` — no hash field.
const ENTRY_ITEM_SIZE_COMPACT: u64 = 4;

const OBJECT_TYPE_DATA: u8 = 1;
const OBJECT_TYPE_ENTRY: u8 = 3;

const OBJECT_COMPRESSED_XZ: u8 = 1 << 0;
const OBJECT_COMPRESSED_LZ4: u8 = 1 << 1;
const OBJECT_COMPRESSED_ZSTD: u8 = 1 << 2;

const INCOMPATIBLE_COMPRESSED_XZ: u32 = 1 << 0;
const INCOMPATIBLE_COMPRESSED_LZ4: u32 = 1 << 1;
const INCOMPATIBLE_KEYED_HASH: u32 = 1 << 2;
const INCOMPATIBLE_COMPRESSED_ZSTD: u32 = 1 << 3;
const INCOMPATIBLE_COMPACT: u32 = 1 << 4;
const KNOWN_INCOMPATIBLE_FLAGS: u32 = INCOMPATIBLE_COMPRESSED_XZ
    | INCOMPATIBLE_COMPRESSED_LZ4
    | INCOMPATIBLE_KEYED_HASH
    | INCOMPATIBLE_COMPRESSED_ZSTD
    | INCOMPATIBLE_COMPACT;

/// Minimum header length we need to read (through `tail_object_offset` at
/// byte 144) — the header grew over successive systemd versions but only by
/// appending fields, so every real journal file is at least this long.
const MIN_HEADER_LEN: usize = 144;

struct Header {
    header_size: u64,
    tail_object_offset: u64,
    /// `HEADER_INCOMPATIBLE_COMPACT` — changes `ENTRY`/`DATA` object byte
    /// layout, not the header's own layout, so this is the only header
    /// field that needs to be threaded down into object parsing.
    compact: bool,
}

fn parse_header(bytes: &[u8]) -> anyhow::Result<Header> {
    if bytes.len() < MIN_HEADER_LEN {
        bail!(
            "file too small to contain a journal header ({} bytes, need at least {MIN_HEADER_LEN})",
            bytes.len()
        );
    }
    if bytes[0..8] != SIGNATURE {
        bail!("not a systemd journal file: signature mismatch");
    }

    let incompatible_flags = read_u32(bytes, 12);
    let unknown_flags = incompatible_flags & !KNOWN_INCOMPATIBLE_FLAGS;
    if unknown_flags != 0 {
        bail!(
            "journal file uses unrecognized incompatible feature flags ({unknown_flags:#x}) — refusing to guess at the format rather than risk misreading it"
        );
    }
    let compact = incompatible_flags & INCOMPATIBLE_COMPACT != 0;

    let header_size = read_u64(bytes, 88);
    let tail_object_offset = read_u64(bytes, 136);

    if (header_size as usize) < MIN_HEADER_LEN {
        bail!("journal header reports an implausibly small header_size ({header_size})");
    }
    if (header_size as usize) > bytes.len() {
        bail!(
            "journal header_size ({header_size}) is larger than the file itself ({} bytes)",
            bytes.len()
        );
    }

    Ok(Header {
        header_size,
        tail_object_offset,
        compact,
    })
}

struct ObjectHeader {
    object_type: u8,
    flags: u8,
    size: u64,
}

fn read_object_header(bytes: &[u8], offset: u64) -> anyhow::Result<ObjectHeader> {
    let offset_usize = usize::try_from(offset).context("object offset overflows usize")?;
    if offset_usize + OBJECT_HEADER_SIZE as usize > bytes.len() {
        bail!("object at offset {offset} is truncated (file ends before its header)");
    }
    let object_type = bytes[offset_usize];
    let flags = bytes[offset_usize + 1];
    let size = read_u64(bytes, offset_usize + 8);
    if size < OBJECT_HEADER_SIZE {
        bail!("object at offset {offset} reports an impossible size ({size} bytes)");
    }
    if offset + size > bytes.len() as u64 {
        bail!("object at offset {offset} (size {size}) extends past the end of the file");
    }
    Ok(ObjectHeader {
        object_type,
        flags,
        size,
    })
}

fn align8(n: u64) -> u64 {
    n.div_ceil(8) * 8
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn parse_bytes(
    bytes: &[u8],
    skip_bad_records: bool,
) -> anyhow::Result<(Vec<ParsedRecord>, Vec<SkippedRecord>)> {
    let header = parse_header(bytes)?;
    let mut records = Vec::new();
    let mut skipped = Vec::new();

    if header.tail_object_offset == 0 {
        return Ok((records, skipped));
    }

    let mut offset = align8(header.header_size);
    while offset <= header.tail_object_offset {
        let object = match read_object_header(bytes, offset)
            .with_context(|| format!("failed to read object at offset {offset}"))
        {
            Ok(object) => object,
            // Unrecoverable under skip mode too: the object's size is
            // exactly what failed to read, so there's no safe next offset
            // to resync to without guessing. Keep everything parsed so far
            // as a normal partial result instead of discarding it.
            Err(err) if skip_bad_records => {
                skipped.push(SkippedRecord {
                    location: format!("offset {offset:#x}"),
                    reason: format!(
                        "{err:#} — journal structure unreadable from this point; \
                         {} entr{} recovered before it, remainder of the file skipped",
                        records.len(),
                        if records.len() == 1 { "y" } else { "ies" },
                    ),
                });
                break;
            }
            Err(err) => return Err(err),
        };
        if object.object_type == OBJECT_TYPE_ENTRY {
            match parse_entry_object(bytes, offset, object.size, header.compact)
                .with_context(|| format!("failed to parse ENTRY object at offset {offset}"))
            {
                Ok(record) => records.push(record),
                Err(err) if skip_bad_records => skipped.push(SkippedRecord {
                    location: format!("entry at offset {offset:#x}"),
                    reason: format!("{err:#}"),
                }),
                Err(err) => return Err(err),
            }
        }
        offset = align8(offset + object.size);
    }

    Ok((records, skipped))
}

fn parse_entry_object(
    bytes: &[u8],
    offset: u64,
    size: u64,
    compact: bool,
) -> anyhow::Result<ParsedRecord> {
    let fixed_start = offset + OBJECT_HEADER_SIZE;
    let items_start = fixed_start + ENTRY_FIXED_SIZE;
    if items_start > offset + size {
        bail!("ENTRY object is smaller than the fixed entry header ({size} bytes)");
    }

    let seqnum = read_u64(bytes, fixed_start as usize);
    let realtime = read_u64(bytes, (fixed_start + 8) as usize);
    let monotonic = read_u64(bytes, (fixed_start + 16) as usize);

    let item_size = if compact {
        ENTRY_ITEM_SIZE_COMPACT
    } else {
        ENTRY_ITEM_SIZE
    };
    let items_end = offset + size;
    let item_area = items_end - items_start;
    if !item_area.is_multiple_of(item_size) {
        bail!("ENTRY object item area ({item_area} bytes) isn't a whole number of entry items");
    }
    let n_items = item_area / item_size;

    let mut fields = serde_json::Map::new();
    let mut message = None;
    let mut level = None;

    for i in 0..n_items {
        let item_offset = (items_start + i * item_size) as usize;
        // Compact items are a bare `le32` object offset (no hash field);
        // regular items are `le64` — see this module's doc comment.
        let data_object_offset = if compact {
            read_u32(bytes, item_offset) as u64
        } else {
            read_u64(bytes, item_offset)
        };
        let (key, value) = read_data_object_field(bytes, data_object_offset, compact)
            .with_context(|| {
                format!("entry item {i}: failed to resolve DATA object at {data_object_offset}")
            })?;
        if key == "MESSAGE" {
            message = Some(value.clone());
        }
        if key == "PRIORITY" {
            level = Some(value.clone());
        }
        fields.insert(key, serde_json::Value::String(value));
    }

    fields.insert(
        "__REALTIME_TIMESTAMP".to_string(),
        serde_json::Value::String(realtime.to_string()),
    );
    fields.insert(
        "__MONOTONIC_TIMESTAMP".to_string(),
        serde_json::Value::String(monotonic.to_string()),
    );
    fields.insert(
        "__SEQNUM".to_string(),
        serde_json::Value::String(seqnum.to_string()),
    );

    let timestamp_utc = realtime_micros_to_utc(realtime)
        .with_context(|| format!("entry seqnum {seqnum}: invalid __REALTIME_TIMESTAMP"))?;
    let fields = serde_json::Value::Object(fields);
    let raw = serde_json::to_string(&fields).context("failed to serialize journald entry")?;

    Ok(ParsedRecord {
        timestamp_utc,
        level,
        message,
        raw,
        fields,
    })
}

/// Resolves a `DATA` object to its `(field_name, value)` pair, decompressing
/// the payload if needed. Journald payloads are `FIELD=VALUE` bytes.
fn read_data_object_field(
    bytes: &[u8],
    offset: u64,
    compact: bool,
) -> anyhow::Result<(String, String)> {
    let object = read_object_header(bytes, offset)?;
    if object.object_type != OBJECT_TYPE_DATA {
        bail!(
            "expected a DATA object at offset {offset}, found type {}",
            object.object_type
        );
    }

    // Compact mode's `DataObject` union arm adds an 8-byte
    // `tail_entry_array_offset`/`tail_entry_array_n_entries` pair before the
    // payload that the regular arm doesn't have — see this module's doc
    // comment. This parser never reads those two fields (no hash-table/
    // array-chain traversal), just skips past them to find the payload.
    let compact_extra = if compact {
        DATA_OBJECT_COMPACT_EXTRA
    } else {
        0
    };
    let payload_start = offset + OBJECT_HEADER_SIZE + DATA_OBJECT_FIXED_SIZE + compact_extra;
    let payload_end = offset + object.size;
    if payload_start > payload_end {
        bail!("DATA object at offset {offset} is smaller than its fixed header");
    }
    let payload_start = payload_start as usize;
    let payload_end = payload_end as usize;
    let raw_payload = &bytes[payload_start..payload_end];

    if object.flags & OBJECT_COMPRESSED_LZ4 != 0 {
        let decompressed = decompress_lz4(raw_payload)
            .with_context(|| format!("DATA object at offset {offset}: LZ4 decompression"))?;
        return split_field(&decompressed);
    }
    if object.flags & (OBJECT_COMPRESSED_XZ | OBJECT_COMPRESSED_ZSTD) != 0 {
        let algorithm = if object.flags & OBJECT_COMPRESSED_XZ != 0 {
            "XZ"
        } else {
            "ZSTD"
        };
        // The field name itself lives inside the compressed payload, so
        // there's no real key to report — a synthetic, offset-qualified key
        // keeps the gap visible instead of silently swallowing the field.
        return Ok((
            format!("_UNSUPPORTED_COMPRESSED_FIELD@{offset}"),
            format!(
                "<{algorithm}-compressed field, {} bytes, not decompressed>",
                raw_payload.len()
            ),
        ));
    }

    split_field(raw_payload)
}

fn split_field(payload: &[u8]) -> anyhow::Result<(String, String)> {
    let text = String::from_utf8_lossy(payload);
    let (key, value) = text
        .split_once('=')
        .ok_or_else(|| anyhow!("field payload has no '=' separator: {text:?}"))?;
    Ok((key.to_string(), value.to_string()))
}

/// journald compresses individual field payloads by prefixing the
/// uncompressed size as a little-endian u64, then the raw LZ4 block (not
/// the LZ4 frame format) — matching `LZ4_compress`/`LZ4_decompress_safe` as
/// used by `journal-file.c`'s `compress_blob`.
fn decompress_lz4(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() < 8 {
        bail!("LZ4-compressed payload too short to contain a size prefix");
    }
    let uncompressed_size = read_u64(payload, 0);
    let uncompressed_size =
        usize::try_from(uncompressed_size).context("uncompressed size overflows usize")?;
    let block = &payload[8..];
    lz4_flex::block::decompress(block, uncompressed_size)
        .map_err(|err| anyhow!("LZ4 block decompression failed: {err}"))
}

fn realtime_micros_to_utc(realtime: u64) -> anyhow::Result<DateTime<Utc>> {
    let micros = i64::try_from(realtime).context("realtime timestamp overflows i64")?;
    DateTime::<Utc>::from_timestamp_micros(micros)
        .ok_or_else(|| anyhow!("realtime timestamp {micros} microseconds is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal, valid journal file byte-for-byte, so these tests
    /// exercise the real binary parsing logic rather than a stand-in.
    struct FakeJournalBuilder {
        bytes: Vec<u8>,
        compact: bool,
    }

    impl FakeJournalBuilder {
        fn new() -> Self {
            let mut bytes = vec![0u8; 208];
            bytes[0..8].copy_from_slice(&SIGNATURE);
            bytes[88..96].copy_from_slice(&208u64.to_le_bytes());
            Self {
                bytes,
                compact: false,
            }
        }

        fn set_incompatible_flags(&mut self, flags: u32) -> &mut Self {
            self.bytes[12..16].copy_from_slice(&flags.to_le_bytes());
            self
        }

        /// Marks this journal `HEADER_INCOMPATIBLE_COMPACT` — sets the
        /// header flag *and* switches every subsequent
        /// `push_data_object*`/`push_entry_object` call on this builder to
        /// compact-mode byte layout, so a test doesn't have to keep the two
        /// in sync by hand.
        fn compact(&mut self) -> &mut Self {
            self.compact = true;
            self.set_incompatible_flags(INCOMPATIBLE_COMPACT)
        }

        fn push_data_object(&mut self, field: &str) -> u64 {
            self.push_data_object_raw(field.as_bytes(), 0)
        }

        fn push_data_object_lz4(&mut self, field: &str) -> u64 {
            let uncompressed = field.as_bytes();
            let compressed_block = lz4_flex::block::compress(uncompressed);
            let mut payload = Vec::with_capacity(8 + compressed_block.len());
            payload.extend_from_slice(&(uncompressed.len() as u64).to_le_bytes());
            payload.extend_from_slice(&compressed_block);
            self.push_data_object_raw(&payload, OBJECT_COMPRESSED_LZ4)
        }

        fn push_data_object_raw(&mut self, payload: &[u8], flags: u8) -> u64 {
            let offset = self.bytes.len() as u64;
            let compact_extra = if self.compact {
                DATA_OBJECT_COMPACT_EXTRA
            } else {
                0
            };
            let size =
                OBJECT_HEADER_SIZE + DATA_OBJECT_FIXED_SIZE + compact_extra + payload.len() as u64;
            self.bytes.push(OBJECT_TYPE_DATA);
            self.bytes.push(flags);
            self.bytes.extend_from_slice(&[0u8; 6]);
            self.bytes.extend_from_slice(&size.to_le_bytes());
            self.bytes
                .extend_from_slice(&[0u8; DATA_OBJECT_FIXED_SIZE as usize]);
            if self.compact {
                self.bytes
                    .extend_from_slice(&[0u8; DATA_OBJECT_COMPACT_EXTRA as usize]);
            }
            self.bytes.extend_from_slice(payload);
            self.pad_align8();
            offset
        }

        fn push_entry_object(&mut self, seqnum: u64, realtime: u64, item_offsets: &[u64]) -> u64 {
            let offset = self.bytes.len() as u64;
            let item_size = if self.compact {
                ENTRY_ITEM_SIZE_COMPACT
            } else {
                ENTRY_ITEM_SIZE
            };
            let size =
                OBJECT_HEADER_SIZE + ENTRY_FIXED_SIZE + item_offsets.len() as u64 * item_size;
            self.bytes.push(OBJECT_TYPE_ENTRY);
            self.bytes.push(0);
            self.bytes.extend_from_slice(&[0u8; 6]);
            self.bytes.extend_from_slice(&size.to_le_bytes());
            self.bytes.extend_from_slice(&seqnum.to_le_bytes());
            self.bytes.extend_from_slice(&realtime.to_le_bytes());
            self.bytes.extend_from_slice(&0u64.to_le_bytes()); // monotonic
            self.bytes.extend_from_slice(&[0u8; 16]); // boot_id
            self.bytes.extend_from_slice(&0u64.to_le_bytes()); // xor_hash
            for &item_offset in item_offsets {
                if self.compact {
                    self.bytes
                        .extend_from_slice(&(item_offset as u32).to_le_bytes());
                } else {
                    self.bytes.extend_from_slice(&item_offset.to_le_bytes());
                    self.bytes.extend_from_slice(&0u64.to_le_bytes()); // hash, unused
                }
            }
            self.pad_align8();
            self.bytes[136..144].copy_from_slice(&offset.to_le_bytes());
            offset
        }

        fn pad_align8(&mut self) {
            while !self.bytes.len().is_multiple_of(8) {
                self.bytes.push(0);
            }
        }

        /// Appends a malformed object header — a declared size smaller than
        /// `OBJECT_HEADER_SIZE`, which `read_object_header` rejects as
        /// impossible — and points `tail_object_offset` at it. Simulates
        /// the one corruption case `parse_bytes` cannot resync past even
        /// under skip mode (the object's own size, needed to find the next
        /// object, is what failed to read).
        fn push_corrupt_object_header(&mut self) -> u64 {
            let offset = self.bytes.len() as u64;
            self.bytes.push(OBJECT_TYPE_ENTRY);
            self.bytes.push(0);
            self.bytes.extend_from_slice(&[0u8; 6]);
            self.bytes.extend_from_slice(&3u64.to_le_bytes());
            self.bytes[136..144].copy_from_slice(&offset.to_le_bytes());
            offset
        }

        fn finish(self) -> Vec<u8> {
            self.bytes
        }
    }

    #[test]
    fn parses_a_single_uncompressed_entry_with_two_fields() {
        let mut builder = FakeJournalBuilder::new();
        let message_offset = builder.push_data_object("MESSAGE=hello world");
        let priority_offset = builder.push_data_object("PRIORITY=6");
        // 2024-01-01T00:00:00Z in microseconds since the epoch.
        builder.push_entry_object(1, 1_704_067_200_000_000, &[message_offset, priority_offset]);
        let bytes = builder.finish();

        let (records, _skipped) = parse_bytes(&bytes, false).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message.as_deref(), Some("hello world"));
        assert_eq!(records[0].level.as_deref(), Some("6"));
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(
            records[0].fields.get("__SEQNUM").and_then(|v| v.as_str()),
            Some("1")
        );
    }

    #[test]
    fn decompresses_lz4_field_values() {
        let mut builder = FakeJournalBuilder::new();
        let message_offset =
            builder.push_data_object_lz4("MESSAGE=this value was lz4-compressed on disk");
        builder.push_entry_object(1, 0, &[message_offset]);
        let bytes = builder.finish();

        let (records, _skipped) = parse_bytes(&bytes, false).unwrap();

        assert_eq!(
            records[0].message.as_deref(),
            Some("this value was lz4-compressed on disk")
        );
    }

    #[test]
    fn xz_compressed_field_is_visible_but_marked_unsupported_not_dropped() {
        let mut builder = FakeJournalBuilder::new();
        let data_offset = builder.push_data_object_raw(b"whatever bytes", OBJECT_COMPRESSED_XZ);
        builder.push_entry_object(1, 0, &[data_offset]);
        let bytes = builder.finish();

        let (records, _skipped) = parse_bytes(&bytes, false).unwrap();

        let fields = records[0].fields.as_object().unwrap();
        let (key, value) = fields
            .iter()
            .find(|(k, _)| k.starts_with("_UNSUPPORTED_COMPRESSED_FIELD"))
            .expect("unsupported field should still be present, just marked");
        assert!(key.contains('@'));
        assert!(value.as_str().unwrap().contains("XZ"));
    }

    #[test]
    fn parses_a_single_entry_in_compact_format() {
        let mut builder = FakeJournalBuilder::new();
        builder.compact();
        let message_offset = builder.push_data_object("MESSAGE=hello compact world");
        let priority_offset = builder.push_data_object("PRIORITY=6");
        builder.push_entry_object(1, 1_704_067_200_000_000, &[message_offset, priority_offset]);
        let bytes = builder.finish();

        let (records, _skipped) = parse_bytes(&bytes, false).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message.as_deref(), Some("hello compact world"));
        assert_eq!(records[0].level.as_deref(), Some("6"));
        assert_eq!(
            records[0].timestamp_utc,
            DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn decompresses_lz4_field_values_in_compact_format() {
        let mut builder = FakeJournalBuilder::new();
        builder.compact();
        let message_offset =
            builder.push_data_object_lz4("MESSAGE=this value was lz4-compressed on disk");
        builder.push_entry_object(1, 0, &[message_offset]);
        let bytes = builder.finish();

        let (records, _skipped) = parse_bytes(&bytes, false).unwrap();

        assert_eq!(
            records[0].message.as_deref(),
            Some("this value was lz4-compressed on disk")
        );
    }

    #[test]
    fn multiple_entries_are_returned_in_scan_order_in_compact_format() {
        let mut builder = FakeJournalBuilder::new();
        builder.compact();
        let first_offset = builder.push_data_object("MESSAGE=first");
        builder.push_entry_object(1, 100, &[first_offset]);
        let second_offset = builder.push_data_object("MESSAGE=second");
        builder.push_entry_object(2, 200, &[second_offset]);
        let bytes = builder.finish();

        let (records, _skipped) = parse_bytes(&bytes, false).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message.as_deref(), Some("first"));
        assert_eq!(records[1].message.as_deref(), Some("second"));
    }

    #[test]
    fn unknown_incompatible_flag_is_rejected_rather_than_guessed_at() {
        let mut builder = FakeJournalBuilder::new();
        builder.set_incompatible_flags(1 << 30);
        let bytes = builder.finish();

        let result = parse_bytes(&bytes, false);

        assert!(result.is_err());
    }

    #[test]
    fn bad_signature_is_rejected() {
        let bytes = vec![0u8; 208];

        let result = parse_bytes(&bytes, false);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn truncated_file_is_rejected_not_panicking() {
        let bytes = vec![0u8; 10];

        let result = parse_bytes(&bytes, false);

        assert!(result.is_err());
    }

    #[test]
    fn empty_journal_with_no_entries_parses_to_an_empty_list() {
        let builder = FakeJournalBuilder::new();
        let bytes = builder.finish();

        let (records, _skipped) = parse_bytes(&bytes, false).unwrap();

        assert!(records.is_empty());
    }

    #[test]
    fn object_claiming_to_extend_past_end_of_file_is_rejected() {
        let mut builder = FakeJournalBuilder::new();
        let offset = builder.bytes.len() as u64;
        builder.bytes.push(OBJECT_TYPE_ENTRY);
        builder.bytes.push(0);
        builder.bytes.extend_from_slice(&[0u8; 6]);
        // Claim a size far larger than the actual remaining file content.
        builder.bytes.extend_from_slice(&10_000u64.to_le_bytes());
        builder.bytes[136..144].copy_from_slice(&offset.to_le_bytes());
        let bytes = builder.finish();

        let result = parse_bytes(&bytes, false);

        assert!(result.is_err());
    }

    #[test]
    fn multiple_entries_are_returned_in_scan_order() {
        let mut builder = FakeJournalBuilder::new();
        let first_offset = builder.push_data_object("MESSAGE=first");
        builder.push_entry_object(1, 100, &[first_offset]);
        let second_offset = builder.push_data_object("MESSAGE=second");
        builder.push_entry_object(2, 200, &[second_offset]);
        let bytes = builder.finish();

        let (records, _skipped) = parse_bytes(&bytes, false).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message.as_deref(), Some("first"));
        assert_eq!(records[1].message.as_deref(), Some("second"));
    }

    #[test]
    fn parse_rejects_a_nonexistent_path() {
        let config = ParserConfig::from_toml_str(
            "[parser]\nname = \"journald\"\nsourcetype = \"journald\"\n",
        )
        .unwrap();
        let result =
            JournaldFileParser.parse(Path::new("/nonexistent/path.journal"), &config, false);

        assert!(result.is_err());
    }

    /// Regression test for the "skip bad records" invariant: `false` must
    /// still hard-fail on a corrupt entry exactly as before this parameter
    /// existed.
    #[test]
    fn skip_bad_records_false_still_hard_fails_on_a_corrupt_entry() {
        let mut builder = FakeJournalBuilder::new();
        let good_offset = builder.push_data_object("MESSAGE=first");
        builder.push_entry_object(1, 100, &[good_offset]);
        // References a wildly out-of-bounds DATA object offset — the ENTRY
        // object's own header is fine, only its item resolution fails.
        builder.push_entry_object(2, 200, &[999_999]);
        let bytes = builder.finish();

        let result = parse_bytes(&bytes, false);

        assert!(result.is_err());
    }

    #[test]
    fn skip_bad_records_true_skips_a_corrupt_entry_and_keeps_the_rest() {
        let mut builder = FakeJournalBuilder::new();
        let first_offset = builder.push_data_object("MESSAGE=first");
        builder.push_entry_object(1, 100, &[first_offset]);
        builder.push_entry_object(2, 200, &[999_999]);
        let third_offset = builder.push_data_object("MESSAGE=third");
        builder.push_entry_object(3, 300, &[third_offset]);
        let bytes = builder.finish();

        let (records, skipped) = parse_bytes(&bytes, true).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message.as_deref(), Some("first"));
        assert_eq!(records[1].message.as_deref(), Some("third"));
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].location.contains("entry at offset"));
    }

    /// The one corruption case skip mode can't recover from: a malformed
    /// *object header* (not just a malformed entry) leaves no safe way to
    /// find the next object. `false` must still hard-fail on it exactly as
    /// before.
    #[test]
    fn skip_bad_records_false_still_hard_fails_on_a_corrupt_object_header() {
        let mut builder = FakeJournalBuilder::new();
        let good_offset = builder.push_data_object("MESSAGE=first");
        builder.push_entry_object(1, 100, &[good_offset]);
        builder.push_corrupt_object_header();
        let bytes = builder.finish();

        let result = parse_bytes(&bytes, false);

        assert!(result.is_err());
    }

    #[test]
    fn skip_bad_records_true_keeps_entries_recovered_before_a_corrupt_header() {
        let mut builder = FakeJournalBuilder::new();
        let first_offset = builder.push_data_object("MESSAGE=first");
        builder.push_entry_object(1, 100, &[first_offset]);
        let second_offset = builder.push_data_object("MESSAGE=second");
        builder.push_entry_object(2, 200, &[second_offset]);
        builder.push_corrupt_object_header();
        let bytes = builder.finish();

        let (records, skipped) = parse_bytes(&bytes, true).unwrap();

        assert_eq!(
            records.len(),
            2,
            "both entries before the corruption survive"
        );
        assert_eq!(records[0].message.as_deref(), Some("first"));
        assert_eq!(records[1].message.as_deref(), Some("second"));
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("2 entries recovered"));
    }
}
