# Rule-Pack Source Review Log

Peach's built-in tagging rule packs (`rules/examples/*.toml`) are curated from external
research — blog series, published references, official documentation — rather than
written from scratch. Some of these sources publish new material over time (a recurring
blog series, an updated PDF edition), and nothing in the repo says which entries have
already been checked for a new rule and which haven't.

**Purpose of this file:** a maintainer/research log, per source, of what has been
reviewed and what came of it — so the same article never gets checked twice, and so
gaps (published but not yet reviewed) stay visible instead of silently falling through.
This is *not* a citation list — the citation for each shipped rule still lives in that
rule file's own header comment, and the generated, user-facing index of those citations
is [docs/rules-reference.md](../docs/rules-reference.md).

**One section per source**, added as sources get tracked — starting with Thesis Friday.
Each entry needs:

- **Reviewed** — date it was checked (YYYY-MM-DD), or `—` if not yet reviewed
- **Outcome** — `rule added` (name the rule file), `no new rule` (state *why* — already
  covered, out of scope, insufficient evidence), or `pending`
- **Notes** — anything a future review should know (methodology caveats, deferred
  follow-ups, version/build the finding was tested on)

When picking something up: add a row (or fill in a `pending` one) — don't just edit a
rule file and leave this log stale. A source with no `pending` rows left simply means
"fully caught up as of the newest reviewed entry", not "nothing more will ever appear."

---

## Thesis Friday (Tim Korver) — https://thesisfriday.com/

Recurring AUL/forensic-research blog series; frequently the origin of higher-precision
predicates than the iLEAPP-PDF baseline the rest of the AUL pack is sourced from (see
that baseline's own note in `aul_*.toml` header comments generally, and
[docs/rules-reference.md](../docs/rules-reference.md) for which rules cite which).

| # | Title | Reviewed | Outcome | Rule file(s) | Notes |
|---|---|---|---|---|---|
| 1 | AUL – FaceID authentication | 2026-08-30 | no new rule | `aul_biometric_sensor_events.toml` | Predicates (`PearlCamFrameReceived`, `getFaceDetectInfo`) already in `aul_biometric_sensor_events.toml` from the iLEAPP baseline. |
| 2 | AUL – Device orientation | 2026-08-16 | rule added | `aul_device_orientation.toml` | |
| 3 | AUL – Phone Application | 2026-08-30 | no new rule | `aul_app_launch.toml` | "Allowing tap for icon view" already in `aul_app_launch.toml`. Two finer predicates seen (`"Icon tapped:"`, `"Executing request: <SBMainWorkspaceTransitionRequest"`) aren't literally covered but describe the same tap→launch event already tagged — low value, not added. |
| 4 | Proces-flow Apple Unified Log | 2026-08-30 | no new rule | | Methodology only (Sysdiagnose-vs-AUL decision flowchart), no predicates in the post body. |
| 5 | AUL pattern of the native iOS application (Mail) | 2026-08-30 | no new rule | `aul_app_launch.toml` | All three predicates already covered by `aul_app_launch.toml`'s generic substrings — confirms that rule generalizes across apps. |
| 6 | Acquiring the Apple Unified Log – Terminal | 2026-08-30 | no new rule | | Acquisition methodology (`log collect`, chain-of-custody), no detection predicates. |
| 7 | Apple Unified Log or Sysdiagnose? | 2026-08-30 | no new rule | | Comparative study (event counts/TTL), no detection predicates. |
| 8 | AUL – Physical Buttons Volume | 2026-08-30 | no new rule | `aul_audio_volume.toml` | All predicates already in `aul_audio_volume.toml`. |
| 9 | AUL connecting a USB cable | 2026-08-30 | rule added | `aul_usb_power_connections.toml` | Verbatim log line confirmed `"pluggedIn 1"` (RestrictedPerfMode's `evaluatePowerMode`, a second independent subsystem from the existing predicates) — added. `"display 1"` from the same line was left out: it's the screen-on state, not charging-specific by itself, and Peach's OR-only `message_contains` can't require display+pluggedIn together in one predicate. |
| 10 | AUL – Artefacts on a iPhone 6 (iOS 12.5.7) | 2026-08-30 | no new rule | `aul_biometric_sensor_events.toml`, `aul_screen_lock_state.toml` | Touch ID / Home Button predicates already covered (`kAppleBiometricFinger`, `Home Button Was Pressed`). `"passcodeLocked = NO"` (iOS 12-era `softwareupdateservicesd`) not covered — old-OS-specific, low priority, not added. |
| 11 | How to – CLI – Cheatsheet | 2026-08-30 | no new rule | | CLI reference PDF, not a predicate/detection post. |
| 12 | AUL – First Glance at iOS 26 | 2026-08-30 | no new rule | `aul_biometric_sensor_events.toml`, `aul_unlock_sessions.toml` | Corrected after a verbatim re-check: `"FD Distance"`/`"ER Distance"` live *inside* the same `getFaceDetectInfo` log line already matched by `aul_biometric_sensor_events.toml`, and `handle_async_keybag_unlock` is on the same line as the already-matched `"apfs is being UN-locked"`. Both apparent gaps were an artifact of the first, coarser summary reading fields out of context — a useful example of why the verbatim-quote pass matters. |
| 13 | AUL – Detecting Airplane Mode Activation in iOS 26 Beta | 2026-08-16 | rule added | `aul_airplane_mode.toml` | extended an existing rule, not a new file |
| 14 | AUL – Touch Events | 2026-08-30 | no new rule | `aul_touchscreen_events.toml` | `"received tapToWake"` and contact-presence already covered by `aul_touchscreen_events.toml`. `"Dispatching digitizer event"` (raw digitizer flags) not covered — low value on top of what's already tagged, not added. Tested on iOS 18.5. |
| 15 | Generating a Sysdiagnose via AssistiveTouch | 2026-08-30 | rule added | `aul_sysdiagnose_generation.toml` (new file) | Genuinely new event, not covered by any existing rule — new tag `sysdiagnose_generation`. Verbatim check confirmed both OS-generation message variants share the `"Generating sysdiagnose"` substring. Tested iOS 18.2.1 and iOS 12.5.7. |
| 16 | Unlocking a MacBook with the Touch ID Sensor | 2026-08-16 | rule added | `aul_biometric_sensor_events.toml` | extended an existing rule (`setFingerOnState: FingerON`), not a new file |
| 17 | Touch Events on the iOS On-Screen Keyboard | 2026-08-30 | rule added | `aul_keyboard_activity_touch.toml` (new file) | `appTouchDown`/`appTouchUp`/`appTouchDragged` under category `KeyboardSignposts` already covered. The separate `"touch down"`/`"touch drag"` pair under category `KeyboardTouch` (verbatim-confirmed as its own subsystem/category, distinct log lines) was added as a companion rule, same pattern and same tag as `aul_keyboard_activity_signposts.toml`. |
| 18 | Apple Watch Crown and side button interactions | 2026-08-16 | rule added | `aul_watch_crown_button.toml` | |
| 19 | Emergency SOS – Decoding the Cross-Device "Help" Handshake | 2026-08-30 | rule added | `aul_emergency_sos.toml` | iPhone-side predicates already covered. Added the two locationd-side predicates (`EmergencyEnablementAssertion`, `kCLEmergencyEnablementAssertion`) — earlier in the chain than sosd's own broadcasts. The post's third predicate, the watch-side `"Description: Button long-held"`, turned out on cross-check to be the *exact* generic long-hold predicate already in `aul_watch_crown_button.toml` (#18) — deliberately left out of this rule rather than double-tagging every ordinary long hold as `emergency_sos`; correlate the two rules' tags by timestamp instead. Tested watchOS 26.2. |
| 20 | Project Stark — Forensic Reconstruction of the CarPlay Handshake | 2026-08-16 | rule added | `aul_carplay_connection.toml` | |
| 21 | Why a single artifact never tells the whole story | 2026-08-30 | no new rule | | ALR-method essay (part of a 6-week series); uses existing Face ID predicates purely as illustration, explicitly "not casework". |
| 22 | Reading the Unified Log by evidential strength, not by timestamp | 2026-08-30 | no new rule | | ALR-method essay, series intro; same illustrative Face ID example as #21/#25, no new predicates. |
| 23 | The anchor comes from outside the log | 2026-08-30 | no new rule | | ALR-method essay; no predicates, discusses investigative-window sizing as methodology only. |
| 24 | Recovering a dialed number from the Unified Log | 2026-08-16 | rule added | `aul_dialed_number_recovery.toml` | tested on iOS 26.6 (build 23G71) |
| 25 | Proximity is not causality | 2026-08-30 | no new rule | | ALR-method essay; contrasts `prewarmCamera` vs. actual auth as a reasoning example, no new predicates. |
| 26 | Same unlock, three different stories | 2026-08-30 | rule added | `aul_unlock_sessions.toml`, `aul_biometric_sensor_events.toml` | macOS Touch-ID-vs-password disambiguation, verbatim-confirmed against six actual log lines. `"Transition: locked ->"` already covered. Added to `aul_unlock_sessions.toml`: `"matchResult:timestamp: MATCH"`, `"has received no-match"`, `"lockScreenImmediateFromTouchIDPress"`, `"authenticated as user"`, `"right 'system.login.screensaver'"`. Added to `aul_biometric_sensor_events.toml`: `"TouchID button pressed: 1"` (hardware press, macOS counterpart to the existing iOS "Home Button Was Pressed"). `"Attempt #:"` left out as too generic/collision-prone on its own. Tested macOS 26.6.2 (build 25G83), Mac16,8/M4 Pro. |
| 27 | Backward reasoning from a provable endpoint | 2026-09-04 | no new rule | | ALR-method essay (principle 4); discusses FileVault/Touch ID/session-state reasoning conceptually, no quoted log lines or predicates. |

**Gaps:** none left within #1–27 as of 2026-09-04 — every episode has been reviewed,
and every candidate found in that pass has been resolved one way or another. New
episodes (#28+) start as `pending` when published.

**Methodology note on this batch:** the first read of each post used an AI-summarized
extraction, which surfaced two false positives (#12's two "gaps" both turned out to
already be on the same log line as an already-matched predicate, just described out of
context by the summary). Every row marked `rule added` above was re-checked with a
second, verbatim-quote-only pass before anything was written into a `.toml` file — but
that is still a blog post's own quoted log lines, not an independent read of a real raw
device record. Per [[aul_pattern_of_life_categorization]]'s own lesson: treat these as a
solid first cut, not a substitute for spot-checking against real AUL data if/when that
becomes available.

---

## Android Intrusion Logging — AOSP / MVT / ALEAPP

Not a blog series — tracked as a single entry. The Intrusion Logging feature itself
comes from [Amnesty International Security Lab's
announcement](https://securitylab.amnesty.org/latest/2026/05/android-intrusion-logging-as-a-new-source-of-data-for-consensual-forensic-analysis/)
(built by Google with Amnesty for spyware/"consensual" forensic analysis). Primary
source for the rule content is AOSP's own `SecurityLogTags.logtags`/`SecurityLog.java`
(Apache-2.0), for tag ID, tag_key, and description in all 46 `security_event` rules
plus `dns_event`/`connect_event` (`rules/examples/intrusion_log_*.toml`, 48 files).
Cross-confirmed against two independent tools that parse real device exports of the
same format: Amnesty's own [Mobile Verification
Toolkit](https://github.com/mvt-project/mvt) (`SECURITY_EVENT_TAGS`) and
[ALEAPP](https://github.com/abrignoni/ALEAPP) (`intrusionDetectionStore.py`'s
`_SECURITY_TAGS`) — cited for validation only, not as a text source. See each rule
file's header comment for the exact citation. Android's own docs describe this feature as still being expanded, so worth re-checking against a fresh AOSP/MVT state when a new SecurityLog tag ships.

**Reviewed:** 2026-09-02.
