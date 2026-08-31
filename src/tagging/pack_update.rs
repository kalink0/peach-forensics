//! Checks GitHub Releases for a rule-pack bundle newer than what's
//! currently applied, and downloads it. **The only network call in the
//! entire app**, and strictly user-initiated (the "Check for updates"
//! button, per `docs/design/rule-pack-updates.md` step 7) — nothing here
//! is ever called automatically or in the background, per that document's
//! §2 local-only principle.
//!
//! Checks **`kalink0/peach-rules`, a separate repo from this one** — §6's
//! revised decision: an earlier draft shared this repo's own Releases list
//! with app releases, disambiguated by a `peach-rules-` tag prefix, but
//! that meant every rule-pack release risked being flagged GitHub's
//! "Latest" release ahead of the actual newest app version (or needed
//! `prerelease`/`make_latest` workarounds to prevent it) — a category
//! mismatch, not really what either flag is for. A dedicated repo where
//! *every* release is a rule pack sidesteps this outright: tags are a
//! plain `v{N}` there, "Latest" always means "latest rule pack", nothing
//! to disambiguate.
//!
//! Depends on the tag/asset naming decided in §6: one combined bundle per
//! release, tag `v{N}`, asset `peach-rules-v{N}.zip` (kept descriptive
//! even though the tag itself dropped the prefix, since the asset name
//! travels outside repo context — e.g. once downloaded to disk) — the
//! same scheme `scripts/publish_rule_pack.py` produces.

use std::path::Path;

use anyhow::Context;

const RELEASES_URL: &str = "https://api.github.com/repos/kalink0/peach-rules/releases";

/// GitHub's REST API rejects a request with no `User-Agent` at all (403),
/// so this is required, not just polite.
const USER_AGENT: &str = concat!("peach-forensics/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
}

/// A rule-pack release found to be newer than whatever's currently
/// applied (or, if nothing has ever been applied, simply a valid release).
#[derive(Debug, Clone, PartialEq)]
pub struct AvailableUpdate {
    pub pack_version: u32,
    pub tag_name: String,
    pub download_url: String,
}

/// Checks GitHub for the newest `v{N}` release (in `kalink0/peach-rules`)
/// that both has a matching `peach-rules-v{N}.zip` asset and is newer than
/// `current_pack_version` (`None` — no tier-2 pack applied yet — counts as
/// "any valid release is newer"). `Ok(None)` means "reachable, nothing
/// newer", distinct from `Err` ("couldn't check at all") — the caller
/// needs to tell those apart to show the right message.
pub fn check_for_update(
    current_pack_version: Option<u32>,
) -> anyhow::Result<Option<AvailableUpdate>> {
    let releases: Vec<GithubRelease> = ureq::get(RELEASES_URL)
        .header("User-Agent", USER_AGENT)
        .call()
        .context("failed to reach GitHub to check for rule pack updates")?
        .body_mut()
        .read_json()
        .context("failed to parse GitHub's release list")?;
    Ok(pick_latest_update(&releases, current_pack_version))
}

/// Downloads `update`'s asset to `dest_path`. Only fetches bytes — it's
/// `tagging::pack_bundle::load_pack_bundle`'s job to verify them
/// afterward, this function doesn't trust its own download.
pub fn download_update(update: &AvailableUpdate, dest_path: &Path) -> anyhow::Result<()> {
    let mut response = ureq::get(&update.download_url)
        .header("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("failed to download {}", update.download_url))?;
    let mut out = std::fs::File::create(dest_path)
        .with_context(|| format!("failed to create {}", dest_path.display()))?;
    std::io::copy(&mut response.body_mut().as_reader(), &mut out)
        .context("failed to write the downloaded rule pack to disk")?;
    Ok(())
}

/// Pure — parses `v{N}` tag names among `releases` (see [`tag_pack_version`]
/// for what's rejected — a defensively-kept check even though
/// `kalink0/peach-rules` shouldn't realistically have any non-rule-pack
/// tags in it, unlike the shared-repo scheme this replaced), and picks the
/// release with the highest `N` that both has a `peach-rules-v{N}.zip`
/// asset and is newer than `current_pack_version`. Kept separate from
/// [`check_for_update`] so this selection logic is testable without a real
/// network call.
fn pick_latest_update(
    releases: &[GithubRelease],
    current_pack_version: Option<u32>,
) -> Option<AvailableUpdate> {
    releases
        .iter()
        .filter_map(|release| {
            let pack_version = tag_pack_version(&release.tag_name)?;
            let expected_asset_name = format!("peach-rules-v{pack_version}.zip");
            let asset = release
                .assets
                .iter()
                .find(|asset| asset.name == expected_asset_name)?;
            Some((pack_version, release, asset))
        })
        .filter(|(pack_version, _, _)| {
            current_pack_version.is_none_or(|current| *pack_version > current)
        })
        .max_by_key(|(pack_version, _, _)| *pack_version)
        .map(|(pack_version, release, asset)| AvailableUpdate {
            pack_version,
            tag_name: release.tag_name.clone(),
            download_url: asset.browser_download_url.clone(),
        })
}

/// Extracts `N` from a `v{N}` tag name — `None` for anything else. A
/// `v0.3.0`-style app-release tag would also return `None` here (the
/// dotted remainder after stripping `v` doesn't parse as a plain `u32`),
/// which no longer matters in practice now that rule packs live in their
/// own repo (`docs/design/rule-pack-updates.md` §6), but costs nothing to
/// keep correct.
fn tag_pack_version(tag_name: &str) -> Option<u32> {
    tag_name.strip_prefix('v')?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag_name: &str, asset_names: &[&str]) -> GithubRelease {
        GithubRelease {
            tag_name: tag_name.to_string(),
            assets: asset_names
                .iter()
                .map(|name| GithubReleaseAsset {
                    name: name.to_string(),
                    browser_download_url: format!("https://example.com/{name}"),
                })
                .collect(),
        }
    }

    #[test]
    fn tag_pack_version_parses_the_rules_tag_scheme() {
        assert_eq!(tag_pack_version("v1"), Some(1));
        assert_eq!(tag_pack_version("v42"), Some(42));
    }

    #[test]
    fn tag_pack_version_rejects_dotted_and_non_numeric_tags() {
        // "v0.3.0" is what an app-release tag looks like — this repo
        // shouldn't ever have one, but the parser stays correct anyway.
        assert_eq!(tag_pack_version("v0.3.0"), None);
        assert_eq!(tag_pack_version("nightly"), None);
        assert_eq!(tag_pack_version("vbeta"), None);
        assert_eq!(tag_pack_version("rules-v1"), None);
    }

    #[test]
    fn no_releases_at_all_means_no_update() {
        assert_eq!(pick_latest_update(&[], None), None);
    }

    #[test]
    fn a_single_valid_release_is_picked_when_nothing_is_currently_applied() {
        let releases = [release("v1", &["peach-rules-v1.zip"])];

        let update = pick_latest_update(&releases, None).unwrap();

        assert_eq!(update.pack_version, 1);
        assert_eq!(update.tag_name, "v1");
        assert_eq!(
            update.download_url,
            "https://example.com/peach-rules-v1.zip"
        );
    }

    #[test]
    fn picks_the_highest_pack_version_among_several_releases() {
        let releases = [
            release("v1", &["peach-rules-v1.zip"]),
            release("v3", &["peach-rules-v3.zip"]),
            release("v2", &["peach-rules-v2.zip"]),
        ];

        let update = pick_latest_update(&releases, None).unwrap();

        assert_eq!(update.pack_version, 3);
    }

    #[test]
    fn a_stray_non_matching_tag_in_the_list_is_ignored() {
        // Shouldn't realistically happen in a dedicated rule-pack repo,
        // but a differently-shaped tag must not be mistaken for one.
        let releases = [
            release("nightly", &["something.tar.gz"]),
            release("v1", &["peach-rules-v1.zip"]),
        ];

        let update = pick_latest_update(&releases, None).unwrap();

        assert_eq!(update.pack_version, 1);
    }

    #[test]
    fn a_release_with_a_tag_but_no_matching_asset_is_ignored() {
        // A malformed/manually-created release: right tag, wrong (or no)
        // asset name — must not be picked, since there'd be nothing valid
        // to actually download.
        let releases = [
            release("v2", &["something-else.zip"]),
            release("v1", &["peach-rules-v1.zip"]),
        ];

        let update = pick_latest_update(&releases, None).unwrap();

        assert_eq!(update.pack_version, 1);
    }

    #[test]
    fn nothing_newer_than_the_current_pack_version_is_no_update() {
        let releases = [release("v3", &["peach-rules-v3.zip"])];

        assert_eq!(pick_latest_update(&releases, Some(3)), None);
        assert_eq!(pick_latest_update(&releases, Some(5)), None);
    }

    #[test]
    fn only_releases_newer_than_current_are_offered() {
        let releases = [
            release("v1", &["peach-rules-v1.zip"]),
            release("v2", &["peach-rules-v2.zip"]),
            release("v3", &["peach-rules-v3.zip"]),
        ];

        let update = pick_latest_update(&releases, Some(1)).unwrap();

        assert_eq!(update.pack_version, 3);
    }
}
