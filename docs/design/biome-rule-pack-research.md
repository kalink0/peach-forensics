# Biome/SEGB tagging rule pack — research notes

Status: research only, nothing implemented here yet. Copied over from a crush-forensics
session (2026-09-07) where the Crush-side prerequisites were built. This file is the
starting point for whoever picks up the actual peach-forensics rule pack work.

## Context

Idea (crush-forensics, 2026-09-03): treat a folder of Apple Biome/SEGB streams as a
source peach can ingest, with a Biome tagging rule pack — reusing peach's existing
rules-directory mechanism instead of building a tagging/correlation engine inside Crush,
and instead of justifying a whole new standalone app just for SEGB.

**Why:** Biome/SEGB analysis wants cross-file correlation + a rules engine over many
similarly-shaped records — exactly what peach already provides generically for
AUL/EVTX/journald/intrusion_log.

## What Crush already does (shipped 2026-09-07)

- `crush/parsers/segb_parser.py`: `_stream_name(node_path)` derives the Biome stream
  name purely from path shape (no payload inspection) — the directory named after the
  stream itself, one level above a `local/`/`remote/` leaf, e.g.
  `.../streams/restricted/Device.Wireless.Bluetooth/local/<file>` ->
  `Device.Wireless.Bluetooth`. Surfaced as a "Stream" field in Crush's Properties panel.
- `is_biome_streams_node(node)`: matches only `.../private/var/db/biome/streams`
  (case-insensitive path suffix). **Deliberately scoped to just this one location** —
  its stream names are reasonably well understood (community research below), unlike
  other Biome roots (e.g. iOS's per-app `Library/Biome/streams`) whose semantics aren't
  established yet. A streams/ folder's *children* look identical regardless of root —
  only the path tells you which location's meaning is actually known.
- New context-menu action "Send Biome Streams to Peach…", visible only for that scoped
  path. Reuses the existing single-folder `_send_to_peach()` path (same one already
  used for `.logarchive`/iOS-diagnostics folders) — hands peach the **whole folder
  untouched**, peach is expected to recurse over it itself. This was a deliberate
  choice over pre-flattening SEGB to JSONL in Crush first.

**Implication for this repo:** peach needs to be able to walk a folder shaped like
`.../biome/streams/<visibility>/<StreamName>/local/*` (and `/remote/*`) and parse the
SEGB v1/v2 binary format itself (no existing peach ingestion for this — see "Open
design question" below).

## Source hygiene warning

Do NOT trust a general web search's AI-generated summary for this topic without
verifying against the actual page — one such summary fabricated a false claim ("crush
already has a schema ported from iLEAPP, 21 streams") that isn't in the actual cited
source. The real source (a bebinary4n6.blogspot.com post) says the opposite: Crush's
SEGB support is schema-less/exploration-only, iLEAPP is cited only as an external
reference. Verified by fetching the actual page content before relying on it.

**Reliable local sources used instead** (all present as local checkouts on this
machine, `~/Documents/git/`): `iLEAPP` (ground-truth field mappings, read the
`scripts/artifacts/biome*.py` files directly), `peach-forensics` (this repo — rule
format, `docs/rules-reference.md`, `src/tagging/builtin.rs`), `peach-rules` (rule
format spec in `README.md`).

## Peach rule-pack format (from this repo's own docs, for reference)

Plain TOML, one rule per file under `rules/examples/*.toml`. `[rule.match]` supports:
`sourcetype`, `level`, `message`, `message_contains` (OR-list), a handful of
sourcetype-aware normalized keys (`event_id` for EVTX, `event_type` +
`security_event_tag` for `intrusion_log`, `process` for journald), or arbitrary flat
`fields` keys.

The **`intrusion_log`** pack (48 rules, Android SecurityLog) is the closest structural
precedent for Biome — most of its rules match purely on a normalized tag/type key with
**no message-content parsing at all**. That's the shape "Tier 1" below is designed to
fit.

## Tier 1 — pure stream-presence rules (no payload decoding needed)

Mirrors `intrusion_log`'s `event_type` + `security_event_tag` pattern: one rule per
stream, matching a normalized `stream` key (would need to be added as a new
sourcetype-aware match key, analogous to `event_id`/`security_event_tag`). Sourced from
iLEAPP's 62 `biome*.py` artifact modules (~90 stream/artifact mappings total).

| Category | Example streams (path suffix) | Tag idea |
|---|---|---|
| Lock/security | `Device.ScreenLocked`, `Device.KeybagLocked`, `_DKEvent.Device.IsLockedImputed` | `screen_locked`, `keybag_locked` |
| Power | `Device.Power.BatteryLevel`, `Device.Power.PluggedIn`, `Device.Power.LowPowerMode`, `Device.Thermals.BatteryTemperature` | `battery_level`, `power_plugged_in` |
| Connectivity | `Device.Wireless.Bluetooth`, `Device.Wireless.WiFi`, `_DKEvent.Wifi.Connection`, `CarPlay.Connected` | `bluetooth_activity`, `wifi_activity` |
| Airplane/cellular | `Device.Wireless.AirplaneMode`, `Device.Wireless.CellularDataEnabled` | `airplane_mode`, `cellular_toggle` |
| App lifecycle | `App.Activity`, `App.Installation`, `App.InFocus`, `_DKEvent.App.InFocus` | `app_installed`, `app_in_focus` |
| Communication | `Messages.Read`, `ProactiveHarvesting.Mail`, `ProactiveHarvesting.Messages` | `message_read`, `harvested_communication` |
| Siri | `Siri.Remembers.CallHistory`, `Siri.Remembers.MessageHistory`, `Siri.Remembers.AudioHistory` | `siri_remembers_activity` |
| Location | `Location.Visit`, `_DKEvent.App.LocationActivity` | `location_visit` |
| Safari | `_DKEvent.Safari.History`, `Safari.Navigations` | `safari_activity` |
| Notifications | `Notification` (public), `Notification.Usage` | `notification_activity` |
| Misc pattern-of-life | `Clock.Alarm`, `Wallet.Transaction`, `Emoji.Engagement`, `Device.TimeZone` | one tag each |

Full path list (all ~90, from iLEAPP's own `__artifacts_v2__` dicts — re-derive by
grepping `~/Documents/git/iLEAPP/scripts/artifacts/biome*.py` for `"paths":` if this
list needs refreshing against a newer iLEAPP checkout):

```
_DKEvent.System.AirplaneMode, App.Activity, App.Installation,
_DKEvent.App.Install / App.Install, App.Intents.Transcript,
AppleIntelligence.Availability, AppleIntelligence.Reporting.AssetDeliveryLog.*,
AppleIntelligence.Reporting.SafetyOverrides, App.LocationActivity,
App.RelevantShortcuts, App.WebUsage, Audio.Route, Media.Route,
Autonaming.Messages.MessageIds, Backlight / Device.Display.Backlight,
_DKEvent.Device.BatteryPercentage, Device.Wireless.Bluetooth, Device.BootSession,
CameraCapture.AutoFocusROI, _DKEvent.Carplay.IsConnected, Clock.Alarm,
Device.Metadata, Device.Display.InterfaceOrientation, Device.Power.LowPowerMode,
Device.Wireless.AirplaneMode, Device.Wireless.CellularDataEnabled,
CarPlay.Connected, Device.Thermals.BatteryTemperature, Device.ScreenLocked,
Device.KeybagLocked, Device.Power.BatteryLevel, Device.Power.PluggedIn,
Device.Power.EnergyMode, Device.SilentMode, _DKEvent.Device.IsPluggedIn,
Device.TimeZone, Device.Wireless.WiFi, Discoverability.Signals,
_DKEvent.Audio.InputRoute, _DKEvent.Audio.OutputRoute, _DKEvent.Clock.Alarm,
_DKEvent.Device.IsLockedImputed, _DKEvent.Device.LowPowerMode,
_DKEvent.Display.Orientation, _DKEvent.Siri.Ui, _DKEvent.Settings.DoNotDisturb,
_DKEvent.App.InFocus, _DKEvent.Keybag.IsLocked,
CommCenter.Call.EmergencyVoiceCall, Emoji.Engagement, FrontBoard.DisplayElement,
OSAnalytics.Hardware.Reliability, App.InFocus, AppIntent / App.Intent,
_DKEvent.App.LocationActivity, Location.Visit, Device.Networking.EdgeSelection,
NotesContent, Notification (public), Notification.Usage, NowPlaying / Media.NowPlaying,
AeroML.Insights.PhotosSearchInsights, Safari.Navigations, _DKEvent.Safari.History,
Safari.WebPagePerformance, MLSE.ShareSheet.ConversationUserInteraction,
ShareSheet.Feedback, Siri.Remembers.AssistantSuggestions (local+remote),
Siri.Remembers.AudioHistory (local+remote), Siri.Remembers.CallHistory (local+remote),
Siri.Remembers.InteractionHistory (local+remote),
Siri.Remembers.MessageHistory (local+remote), Siri.UI,
ProactiveHarvesting.Mail, ProactiveHarvesting.Messages, Messages.Read,
ScreenTime.AppUsage, Keyboard.TokenFrequency, SystemSettings.SearchTerms,
TextInputSession / Text.InputSession, UserActivityMetadata /
UniversalRecents.UserActivity.Metadata, Wallet.Transaction, _DKEvent.Wifi.Connection
```

(A few `biome*.py` modules target Biome SQLite databases, not SEGB files —
`biomeApplePaySecurity.py`, `biomeIntelligenceEntity.py`, `biomeSetsStores.py`,
`biomeSync.py` — out of scope here, not part of the `streams/` layout.)

## Tier 2 — needs actual field content

Known field numbers straight from iLEAPP source (protobuf field-number keys, e.g.
`message.get('3')`):

- `ScreenTime.AppUsage`: field 1 = event code (undocumented, stored as-is), field 3 = bundle ID
- `Keyboard.TokenFrequency`: field 1.1 = token text, field 3 = frequency
- `App.Intent`: field 2 = app ID, field 4 = classname, field 5 = action, plus
  per-app payload parsing for Instagram/WhatsApp/SMS/Maps/etc. — see
  `iLEAPP/scripts/artifacts/biomeIntents.py` for the full app-specific branches
- `ProactiveHarvesting.Mail`: field 3 = message date (CFAbsoluteTime, raw bits of a
  little-endian double), field 11 = subject, field 2 = message ID, field 10 =
  from/to headers (name/value pairs) — see `iLEAPP/scripts/artifacts/biomeStreams.py`
- Full per-stream field maps for any of the other ~85 modules: read the corresponding
  `biome*.py` file directly in `~/Documents/git/iLEAPP/scripts/artifacts/`, same pattern.

## Open design question — RESOLVED, see "Decision" below

Whether Tier 2 rules are even reachable through peach's current `fields`-lookup match
mechanism, since SEGB payloads are nested protobuf (field numbers as keys, often with
nested dicts/lists) rather than the flat structure peach's generic `fields` lookup
assumes. Two options were on the table:

1. A biome-specific normalized-key mechanism in peach's own ingestion (like EVTX's
   `event_id` resolving against its nested JSON shape) — bigger lift, keeps SEGB
   parsing entirely in peach's Rust code.
2. Pre-flatten in Crush before handoff (export decoded records as JSONL with a flat
   `stream` + `field_<N>` shape) instead of handing peach the raw folder — smaller lift
   for peach (no SEGB binary parser needed there at all), but changes the "hand off the
   whole folder, peach recurses" mechanism already built and shipped in Crush
   (2026-09-07) — would need that changed too if this direction is chosen.

The Crush-side folder handoff assumed peach parses SEGB itself (option 1's premise),
since that's what got built. That assumption is now the decided direction — see below.

## Decision (2026-09-07): option 1 — peach parses SEGB itself

**Peach will implement its own SEGB v1/v2 envelope reader and a schema-less protobuf
decoder in Rust**, rather than having Crush pre-flatten to JSONL. Reasoning, in order
of weight:

1. **The core objection to option 1 — no independent way to verify a hand-rolled
   envelope reader — no longer holds for SEGB v2.** After this research pass, the
   Crush side was hardened (commit `98f49f3`, "fix: SEGB v2 reader crashes on real
   trailer edge cases"): `crush/third_party/ccl_segb/ccl_segb2.py` was re-vendored
   **verbatim** from the actual upstream project,
   [`cclgroupltd/ccl-segb`](https://github.com/cclgroupltd/ccl-segb) (MIT), at pinned
   commit `e218d7e9e5266b833d345ba4be9cf1f7e2ea1b57` (2026-07-11) — with an explicit
   in-file policy: fix bugs upstream, re-vendor, never hand-patch in place. This fixes
   three real trailer-parsing edge cases (a trailer slot with an unrecognized state
   value, two trailer entries sharing the same `end_offset`, a stale trailer entry
   pointing into an already-consumed region) and ships a synthetic byte-level test
   suite (`crush/tests/test_ccl_segb2.py`, a `_build_segb2()` construction helper plus
   4 cases: the 3 edge cases + a regression baseline). This turns "reconstruct SEGB v2
   from reverse-engineered notes" into "port an upstream-tracked, tested reference" —
   a fundamentally safer and cheaper task than it looked like at the start of this
   research.
2. **The protobuf field decoder is the same cost either way.** It's schema-less and
   hand-rolled in both reference implementations (no crate exists in either language's
   ecosystem for this) and is needed identically whether Crush pre-flattens (option 2)
   or Peach decodes it itself (option 1). This component doesn't change the tradeoff
   between the two options at all — it was never a reason to prefer option 2.
3. **Option 2 would require reworking Crush's already-shipped "hand off the whole
   folder untouched" mechanism.** Option 1 leaves it alone entirely. With the
   envelope-verification risk that used to justify that rework now largely closed for
   v2, there's less reason to pay it.
4. **SEGB v1 is explicitly deferred, not implemented in the first pass.**
   `ccl_segb1.py` was *not* touched by the upstream hardening commit above — no
   re-vendoring provenance header, no new test, no fixture. Per CCL's own upstream
   project, there has been no newer `ccl-segb` release, so no v1 hardening is expected
   to appear from that source soon either — and v1 files are increasingly rare in
   real-world captures (newer iOS/macOS versions predominantly produce v2). Building a
   v1 reader to the same confidence bar as the now-verified v2 one would mean redoing
   from-scratch edge-case discovery with zero external verification — not worth paying
   for now. Peach will still **detect** v1 files by signature (so they're never
   silently mis-parsed as v2 or silently skipped) and surface a clear, visible
   "SEGB v1 not yet supported" error per file — consistent with CLAUDE.md §0.1's
   "Fehler sichtbar machen, nicht verschlucken" principle — rather than shipping an
   unverified v1 reader. v1 support is a tracked future item, revisited only if real
   v1 data turns up or CCL's upstream moves again.

See the `feature/biome-segb-parser` branch's commit history for the step-by-step
implementation built on this decision.
