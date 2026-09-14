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
///
/// Unlike before 0.7, this provider does no uuidtext/dsc caching of its own —
/// `FileProvider` dropped the `cached_*`/`update_*` methods that hook used to
/// exist for, in favor of the crate's own pluggable `StringCache`. See
/// `super::bounded_cache` for where that caching now lives.
pub struct RawExtractionProvider {
    diagnostics_root: PathBuf,
    uuidtext_root: PathBuf,
}

impl RawExtractionProvider {
    pub fn new(diagnostics_root: PathBuf, uuidtext_root: PathBuf) -> Self {
        Self {
            diagnostics_root,
            uuidtext_root,
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
    fn reader(&mut self) -> impl Read {
        &mut self.reader
    }

    fn source_path(&self) -> &str {
        &self.source
    }
}

fn walk_matching(root: &Path, wanted: LogFileType) -> impl Iterator<Item = LocalSourceFile> {
    WalkDir::new(root)
        .sort_by(|a, b| a.file_name().cmp(b.file_name()))
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(move |entry| LogFileType::from(entry.path()) == wanted)
        .filter_map(|entry| LocalSourceFile::open(entry.path()).ok())
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

impl FileProvider for RawExtractionProvider {
    fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile> {
        walk_matching(&self.diagnostics_root, LogFileType::TraceV3)
    }

    fn uuidtext_files(&self) -> impl Iterator<Item = impl SourceFile> {
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

    fn dsc_files(&self) -> impl Iterator<Item = impl SourceFile> {
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

    fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile> {
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
}
