use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::path::{Path, PathBuf};

use macos_unifiedlogs::dsc::SharedCacheStrings;
use macos_unifiedlogs::filesystem::LogFileType;
use macos_unifiedlogs::traits::{FileProvider, SourceFile};
use macos_unifiedlogs::uuidtext::UUIDText;
use walkdir::WalkDir;

/// A [`FileProvider`] for a raw filesystem extraction, where AUL's tracev3
/// data (`Persist`/`Special`/`Signpost`/`HighVolume`/`timesync`) and its
/// uuidtext/dsc string-resolution data live as two **separate** directory
/// trees — `.../db/diagnostics` and `.../db/uuidtext` — the way they
/// actually sit on a live device, rather than flattened together into one
/// `.logarchive` bundle the way `log collect` repackages them for
/// portability.
///
/// `macos_unifiedlogs::filesystem::LogarchiveProvider` (the crate's other
/// provider, wrapped by [`super::AulProvider::Bundle`]) assumes the
/// flattened bundle layout: its `read_uuidtext`/`read_dsc_uuid` build
/// lookup paths directly as `<base>/<XX>/<file>` and `<base>/dsc/<file>`,
/// with no `uuidtext/` segment. Pointed at a raw extraction's `diagnostics`
/// folder (or its parent), those reads look in the wrong place and fail
/// for nearly every entry — not with an error, just a generic "Failed to
/// get string message..." placeholder baked into `message`, which is easy
/// to mistake for missing/incomplete source data rather than a path bug
/// (this happened during testing: a 6.4M-entry real-device import came out
/// ~98% unresolved before this provider existed).
///
/// This provider is `macos_unifiedlogs::filesystem::LiveSystemProvider`'s
/// own strategy generalized: that one hardcodes `/private/var/db/diagnostics`
/// and `/private/var/db/uuidtext` for reading a *live* macOS system: same
/// split, just parameterized on an arbitrary root instead of an absolute
/// live-system path, so it works against an offline extraction too.
pub struct RawExtractionProvider {
    diagnostics_root: PathBuf,
    uuidtext_root: PathBuf,
    uuidtext_cache: HashMap<String, UUIDText>,
    dsc_cache: HashMap<String, SharedCacheStrings>,
}

impl RawExtractionProvider {
    pub fn new(diagnostics_root: PathBuf, uuidtext_root: PathBuf) -> Self {
        Self {
            diagnostics_root,
            uuidtext_root,
            uuidtext_cache: HashMap::new(),
            dsc_cache: HashMap::new(),
        }
    }
}

struct LocalSourceFile {
    reader: File,
    source: String,
}

impl LocalSourceFile {
    fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            reader: File::open(path)?,
            source: path.display().to_string(),
        })
    }
}

impl SourceFile for LocalSourceFile {
    fn reader(&mut self) -> Box<&mut dyn Read> {
        Box::new(&mut self.reader)
    }

    fn source_path(&self) -> &str {
        &self.source
    }
}

fn walk_matching(
    root: &Path,
    wanted: LogFileType,
) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
    Box::new(
        WalkDir::new(root)
            .sort_by(|a, b| a.file_name().cmp(b.file_name()))
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(move |entry| LogFileType::from(entry.path()) == wanted)
            .filter_map(|entry| {
                Some(Box::new(LocalSourceFile::open(entry.path()).ok()?) as Box<dyn SourceFile>)
            }),
    )
}

/// UUIDs may arrive missing a leading `0` (or two) — same normalization
/// `LogarchiveProvider`/`LiveSystemProvider` apply — since the crate strips
/// leading zeroes when it extracts the UUID from a tracev3 record.
fn normalize_uuid(uuid: &str) -> Result<String, Error> {
    match uuid.len() {
        31 => Ok(format!("0{uuid}")),
        30 => Ok(format!("00{uuid}")),
        32 => Ok(uuid.to_string()),
        _ => Err(Error::new(
            ErrorKind::NotFound,
            format!("uuid length not correct: {uuid}"),
        )),
    }
}

/// Evicts one entry that isn't `keep_a` or `keep_b` once `cache` grows past
/// `capacity`, so both `update_uuid`/`update_dsc` stay a bounded cache
/// instead of growing forever — deliberately not the eviction loop
/// `LogarchiveProvider::update_dsc` uses upstream (`while len() > cap { if
/// let Some(key) = keys().next() { if key == a || key == b { continue } ...
/// } }`): if the very first key iterated is always the protected one, that
/// `continue` never removes anything and never terminates. `find` here
/// looks past the protected keys instead of retrying the same one.
fn evict_one_unprotected<V>(
    cache: &mut HashMap<String, V>,
    capacity: usize,
    keep_a: &str,
    keep_b: &str,
) {
    if cache.len() <= capacity {
        return;
    }
    if let Some(key) = cache
        .keys()
        .find(|key| key.as_str() != keep_a && key.as_str() != keep_b)
        .cloned()
    {
        cache.remove(&key);
    }
}

impl FileProvider for RawExtractionProvider {
    fn tracev3_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        walk_matching(&self.diagnostics_root, LogFileType::TraceV3)
    }

    fn uuidtext_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        walk_matching(&self.uuidtext_root, LogFileType::UUIDText)
    }

    fn read_uuidtext(&self, uuid: &str) -> Result<UUIDText, Error> {
        let uuid = normalize_uuid(uuid)?;
        let mut path = self.uuidtext_root.clone();
        path.push(&uuid[0..2]);
        path.push(&uuid[2..]);

        let mut buf = Vec::new();
        LocalSourceFile::open(&path)?.reader.read_to_end(&mut buf)?;

        UUIDText::parse_uuidtext(&buf)
            .map(|(_, result)| result)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to parse uuidtext file {}: {err:?}", path.display()),
                )
            })
    }

    fn cached_uuidtext(&self, uuid: &str) -> Option<&UUIDText> {
        self.uuidtext_cache.get(uuid)
    }

    fn update_uuid(&mut self, uuid: &str, uuid2: &str) {
        let Ok(result) = self.read_uuidtext(uuid) else {
            return;
        };
        evict_one_unprotected(&mut self.uuidtext_cache, 30, uuid, uuid2);
        self.uuidtext_cache.insert(uuid.to_string(), result);
    }

    fn dsc_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        walk_matching(&self.uuidtext_root, LogFileType::Dsc)
    }

    fn read_dsc_uuid(&self, uuid: &str) -> Result<SharedCacheStrings, Error> {
        let uuid = normalize_uuid(uuid)?;
        let mut path = self.uuidtext_root.clone();
        path.push("dsc");
        path.push(&uuid);

        let mut buf = Vec::new();
        LocalSourceFile::open(&path)?.reader.read_to_end(&mut buf)?;

        SharedCacheStrings::parse_dsc(&buf)
            .map(|(_, result)| result)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to parse dsc file {}: {err:?}", path.display()),
                )
            })
    }

    fn cached_dsc(&self, uuid: &str) -> Option<&SharedCacheStrings> {
        self.dsc_cache.get(uuid)
    }

    fn update_dsc(&mut self, uuid: &str, uuid2: &str) {
        let Ok(result) = self.read_dsc_uuid(uuid) else {
            return;
        };
        evict_one_unprotected(&mut self.dsc_cache, 2, uuid, uuid2);
        self.dsc_cache.insert(uuid.to_string(), result);
    }

    fn timesync_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        walk_matching(&self.diagnostics_root, LogFileType::Timesync)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "peach-raw-extraction-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn read_uuidtext_looks_under_the_uuidtext_root_not_the_diagnostics_root() {
        let diagnostics_root = temp_dir("diag");
        let uuidtext_root = temp_dir("uuid");
        let uuid = "A3C2D349FD2B370A849F7A36DB0A725D";
        std::fs::create_dir_all(uuidtext_root.join("A3")).unwrap();
        std::fs::write(
            uuidtext_root.join("A3").join(&uuid[2..]),
            b"not a real uuidtext file",
        )
        .unwrap();

        let provider = RawExtractionProvider::new(diagnostics_root, uuidtext_root);
        let result = provider.read_uuidtext(uuid);

        // The file was found (proving the path was constructed correctly)
        // and only failed at binary parsing, not at "no such file".
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn read_uuidtext_reports_not_found_when_the_file_is_missing() {
        let provider = RawExtractionProvider::new(temp_dir("diag2"), temp_dir("uuid2"));

        let result = provider.read_uuidtext("A3C2D349FD2B370A849F7A36DB0A725D");

        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn read_dsc_uuid_looks_under_uuidtext_root_slash_dsc() {
        let uuidtext_root = temp_dir("uuid3");
        let uuid = "9D17D0C7902E31B2BC48C62D4C090E90";
        std::fs::create_dir_all(uuidtext_root.join("dsc")).unwrap();
        std::fs::write(uuidtext_root.join("dsc").join(uuid), b"not a real dsc file").unwrap();

        let provider = RawExtractionProvider::new(temp_dir("diag3"), uuidtext_root);
        let result = provider.read_dsc_uuid(uuid);

        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn short_uuids_get_leading_zeroes_restored() {
        assert_eq!(
            normalize_uuid(&"A".repeat(31)).unwrap(),
            format!("0{}", "A".repeat(31))
        );
        assert_eq!(
            normalize_uuid(&"A".repeat(30)).unwrap(),
            format!("00{}", "A".repeat(30))
        );
        assert!(normalize_uuid("too-short").is_err());
    }

    #[test]
    fn evict_one_unprotected_never_removes_a_protected_key_and_terminates() {
        let mut cache: HashMap<String, ()> = HashMap::new();
        cache.insert("keep-a".to_string(), ());
        cache.insert("keep-b".to_string(), ());
        cache.insert("evictable".to_string(), ());

        evict_one_unprotected(&mut cache, 2, "keep-a", "keep-b");

        assert_eq!(cache.len(), 2);
        assert!(cache.contains_key("keep-a"));
        assert!(cache.contains_key("keep-b"));
    }

    #[test]
    fn evict_one_unprotected_is_a_no_op_under_capacity() {
        let mut cache: HashMap<String, ()> = HashMap::new();
        cache.insert("a".to_string(), ());

        evict_one_unprotected(&mut cache, 2, "x", "y");

        assert_eq!(cache.len(), 1);
    }
}
