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

---

## iLEAPP `logarchive` — Alexis Brignoni et al. — https://github.com/abrignoni/iLEAPP

The rest of the AUL pack is sourced from the reference post ["Apple Unified Log
Predicates in iLEAPP: The Reference"](https://leapps.org/blog-post?post=2026-08-01-unified-log-predicate-reference)
(2026-08-01), a snapshot of iLEAPP's `scripts/artifacts/logarchive.py` at that date.
iLEAPP has kept changing since, so the pack is only as current as that snapshot.

**Compared:** 2026-09-20, against iLEAPP `3de3aa0d` (2026-09-17), `message_contains`
lists only (static text comparison — no rule was run against real AUL data). 24 of the
32 artifacts that map onto an `aul_*.toml` rule have an identical predicate set; the
rows below are everything that differs. Where a row cites the reference post or a
Thesis Friday episode it was re-read verbatim (post body, not a summary).

Rows 1-4 and 8 were additionally checked on 2026-09-20 against one processed AUL load
(6,414,050 records, 2024-11-02 to 2024-12-03, a single device, OS version not
determined), read-only. That is one image: it can show that a predicate does or does
not fire there, not how it behaves on other OS releases.

| # | Artifact / rule file | Reviewed | Outcome | Notes |
|---|---|---|---|---|
| 1 | Navigation — `aul_navigation.toml` | 2026-09-20 | rule changed (v2) | Our 15 English guidance phrases are the reference post's navigation list, which (unlike the other sections) carries no `Observed:`/`Sources:` line. iLEAPP replaced it on 2026-08-25 (commits `88ef812a`, `e1f68bf2`) with `subsystem LIKE 'com.apple.Navigation%'` after the phrases returned 0 rows across six en-US images (117,678,121 records, iOS 16.5–26.5.2); iLEAPP states that spoken-guidance text during live navigation is untested. Real-data check: the 15 phrases matched 0 rows; subsystem `com.apple.Navigation` matched 77 (six categories: MNLocationProvider, MNNavigationXPC, MNNavigationService, MNNavigationStateManager, MNRouteStorage, Navd); `com.apple.corenavigation` (5,239 rows) is a different framework and is not matched. Rule now uses the new `subsystem_prefix` match key (exact-case prefix, string or list); `com.apple.navigation.VirtualGarage` (lowercase `n`, from iLEAPP's images, absent here) is listed explicitly. The tag value is now `maps_navigation_activity` (was `navigation`, which never matched on real data): it means framework activity, not a followed route. |
| 2 | Airplane mode — `aul_airplane_mode.toml` | 2026-09-20 | no change (kept) | `isAirplaneMode = 0/1` (from Thesis Friday #13) is a `Calling _CTServerConnectionGetCellularDataSettings()` getter call, logged by SpringBoard on the way on and by `wifid` on the way off; #13 documents one toggle sequence on one iPhone 12, iOS 26 beta 1. The reference post lists these reads under "not events" ("present by the tens of thousands"). Real-data check: only 15 such rows in the whole load (9 with `= 1`, 6 with `= 0`), from several different callers (`sharingd`, `routined`, `siriactionsd`, SpringBoard) — so the volume claim did not reproduce, but the reads are clearly not toggle events: `= 0` appears from other processes hours before, and again seconds before, the one real toggle. That toggle is logged separately by lines the rule already matches (`Toggle AirPlane Mode state to on`, `Airplane Mode is now 1`, `Airplane mode changed from false to true`). On this OS the two needles add reads, not events; whether iOS 26 still logs the toggle lines is untested. Kept as is: the needles are not wrong, they record a state read rather than an event, and the rule's real toggle detection is unaffected. |
| 3 | USB — `aul_usb_power_connections.toml` | 2026-09-20 | no change (kept) | `pluggedIn 1` (Thesis Friday #9) is the RestrictedPerfMode `evaluatePowerMode` line. The reference post names `evaluatePowerMode` as a state poll present by the tens of thousands and does not collect it. Real-data check: 4,359 `evaluatePowerMode` rows, every one redacted to `evaluatePowerMode resources <private>`, so `pluggedIn 1` matched 0 rows — neither harmful nor useful on this load, and the poll-volume claim could not be tested. The cable-detect predicates (`IOAccessoryUSBConnectShim`, 32 rows) fire as documented; they also catch the `PMRD: Added/Removed IOAccessoryUSBConnectShim … idle sleep preventers` bookkeeping lines around each plug/unplug. Kept as is: the poll concern is untestable on the available load, so nothing supports removing it. Revisit if a load with unredacted `evaluatePowerMode` lines is available. |
| 4 | Touchscreen — `aul_touchscreen_events.toml` | 2026-09-20 | rule changed (v2) | We match `" presence:"`; iLEAPP matches `contact _ presence:` (`_` = one character). Thesis Friday #14's verbatim line is `contact 0 presence: touching`. Real-data check: ours 281 rows, iLEAPP's 181, iLEAPP-only 0 — so ours adds 100 rows (36%) and every one of them is a CommCenter modem line (`… emergency numbers presence: N`, categories `pb.qmi.1`/`pb.qmi.2`), false positives. Contact indices seen were 0–6, so `contact 0`…`contact 9` needles reproduce iLEAPP's set exactly. Note both patterns also tag the `none` (66) and `withinRange` (39) states, not only `touching` (76). Changed: `" presence:"` replaced by `contact 0`…`contact 9 presence:`; on the same load that gives 181 rows, identical to iLEAPP's wildcard pattern (0 disagreements), and drops the 100 modem lines. The `none`/`withinRange` note stays: the rule description now says digitizer state changes rather than fingers on glass. |
| 5 | Dialed numbers — `aul_dialed_number_recovery.toml` (v2), new `aul_call_status_update.toml`, new `aul_dialpad_entry.toml` | 2026-09-20 | rule changed + 2 rules added | Re-read Thesis Friday #24 verbatim. Real-data check: all 10 `kPhoneNumber` matches in the load were `#EmergCon,EMERGENCY:notification,kPhoneNumberStatusNotification` (category `Emergency`) — false positives of the v1 bare-substring rule; scoped to category `call.provider` it matches 0 there. `kActionType` (hang-up block, shares `kUuid`) added to the scoped rule. `Call(StatusUpdate)` (category `call`) and the `ContactSearchManager` "Searching for"/"Search cancelled for" chain became their own rules, since one rule cannot OR across categories. Neither `kActionType`, `Call(StatusUpdate)` nor `ContactSearchManager` occurs in the local load, so those three predicates rest on Thesis Friday #24 (iOS 26.6, one device) and iLEAPP's counts, not on local validation. `ContactSearchManager` is narrowed to the two documented message forms; iLEAPP matches the whole category. |
| 6 | CarPlay — `aul_carplay_connection.toml` (v2) | 2026-09-20 | rule changed | Re-read Thesis Friday #20 verbatim. Added `Found USB DirectLink` (airplayd; the post's wired-session discriminator, reproduced in 3/3 runs). iLEAPP's `CarPlay session vehicle inform` is the same wifid line our `WiFiDeviceManagerSetCarPlaySessionState` needle already matches — no change. iLEAPP's `CarPlay Connection Event` does not occur in the post and its provenance was not found — not added. iLEAPP's broad `session isAuthenticated` also matches the ~70-per-run `:0, isActivated:0` variant; ours stays the `:1, isActivated:1` form. iLEAPP's generic filter lists `…accessories.endpoint.accessroryInfoChanged` (sic) — as spelled it cannot match the real `accessoryInfoChanged` event. No CarPlay session exists in the local load, so nothing here is locally validated. |
| 7 | Uncovered "wide net" patterns | 2026-09-20 | pending | ~25 patterns in iLEAPP's `logarchive_artifacts` catch-all have no rule here (screenshot, walking bout, ringer state, brightness, SOS claw gesture, Siri speech request, accessory connections, charger state, …). The reference post says they have no dedicated report yet; no per-pattern provenance was read. Candidate pool, not validated rules. |
| 8 | Case sensitivity (all `aul_*` rules) | 2026-09-20 | no change needed on this load | iLEAPP's `LIKE` is case-insensitive for ASCII; Peach's `message_contains` is a case-sensitive substring test. Checked on the one concrete pair, iLEAPP `Received Orientation` vs. our `Received orientation.`: 0 rows for the capitalized form, 51 for ours. A case-insensitive scan finds 7 more rows, but those are a different FrontBoard message (`Received orientation update: <FBSOrientationUpdate …>`), not a capitalization variant. No case-driven loss was observed here. |

**Not a gap:** `USB Power (VBUS) Present` — iLEAPP itself calls it version insurance;
every VBUS line on its images already carried the `IOAccessoryUSBConnectShim` prefix
that `aul_usb_power_connections.toml` matches.

**Caveat on this whole section:** iLEAPP's own counts and "poll" classifications are
the maintainer's claims, partly produced with AI assistance (per its commit trailers and
artifact authorship lines); none of them were re-derived here. Rows 1–3 in particular
should be settled against real AUL data before a rule is changed or removed.

---

## EVTX — Remote Desktop / Terminal Services, kernel events, DLEAPP cross-check

Compared 2026-09-20. **Sources:** the providers' own manifest message texts and field
names (OS message resources, as listed in nasbench's
[EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources)), EricZimmerman's
[EvtxECmd maps](https://github.com/EricZimmerman/evtx) (MIT), Microsoft's Security
Auditing reference, ponderthebits' RDP event-log article (2018), and DLEAPP's
`windows*.py` modules at `697333a` (2026-09-20) as an independent cross-check — DLEAPP is
partly AI-authored and itself cites secondary sources, so it pointed at events but was not
used as a citation.

**Real-data check:** one Windows VM's exported `winevt` folder (LocalSessionManager/
Operational, System, Security; 168 / 2,531 / 24,157 records), read-only, run through
Peach's own EVTX parser and the embedded rules. That is one machine: it shows what fires
and how messages render there, not how a rule behaves on other Windows builds. It contains
no `RemoteConnectionManager`, `RdpCoreTS` or `RDPClient` log and no type-10 logon.

| # | Event(s) | Reviewed | Outcome | Notes |
|---|---|---|---|---|
| 1 | RemoteConnectionManager 1149 — `evtx_1149_rdp_connection_established.toml` | 2026-09-20 | rule added | Manifest text is "User authentication succeeded" (fields `Param1`-`Param3` in `UserData`). ponderthebits reports from testing that it is logged for a successful RDP *network* connection before credentials are entered, so the tag is `rdp_connection_established`, not an authentication. Not validated locally. |
| 2 | RdpCoreTS 131 — `evtx_131_rdp_connection_accepted.toml` | 2026-09-20 | rule added | "The server accepted a new {ConnType} connection from client {ClientIP}." Not validated locally. The EvtxECmd map for 98 of the same provider carries PowerShell fields and was not used. |
| 3 | ClientActiveXCore 1024 — `evtx_1024_rdp_client_connect.toml` | 2026-09-20 | rule added | Outbound RDP attempt. The provider is `Microsoft-Windows-TerminalServices-ClientActiveXCore`, not "RDPClient" (that is the channel name). Not validated locally. |
| 4 | LocalSessionManager 21-25 — `evtx_21_..` to `evtx_25_ts_*.toml` | 2026-09-20 | 5 rules added | Fields are in `UserData/EventXML`, `SessionID` is a JSON number. 21/22/23/24 checked on real records (all `Address = LOCAL`, i.e. console sessions — the events do not imply RDP). 25 not present locally. 24/25 reuse the tags of 4779/4778. DLEAPP reports the same five events. |
| 5 | Security 4624/4625, `LogonType` 10 — `evtx_4624_rdp_logon.toml`, `evtx_4625_rdp_logon_failure.toml` | 2026-09-20 | 2 rules added + engine key `event_data` | Microsoft: 10 = RemoteInteractive ("remotely using Terminal Services or Remote Desktop"); 12 = same, for internal auditing; 7 = Unlock. Only 10 is matched. `LogonType` is a JSON integer. No type-10 record locally (types 0, 2, 5), so only the field path/type was validated. |
| 6 | Security 4647 — `evtx_4647_logoff_user_initiated.toml` | 2026-09-20 | rule added | Same tag as 4634. Checked on 20 real records. |
| 7 | Security 4729 / 4733 / 4757 | 2026-09-20 | 3 rules added | Removal counterparts of 4728/4732/4756, same tag. 4729 and 4733 checked on real records; 4757 not present. DLEAPP's account-management module lists them. |
| 8 | Kernel-General 12/13, Kernel-Power 109/42 | 2026-09-20 | 4 rules added | 12 (22 records), 13 (20), 109 (20) checked; 42 not present. Event ID 12 is also logged by `Microsoft-Windows-UserModePowerService` on the same machines, so the provider is part of every match. 12 shares `system_boot` with 6005; 13/109 share `system_shutdown` with 1074. |
| 9 | DLEAPP: 4634, 4648, 7045 | 2026-09-20 | no change | Already covered. DLEAPP's `windowsServices` reads the SYSTEM registry hive — not EVTX, out of scope. |
| 10 | Existing 4624/4625/4634 message templates | 2026-09-20 | bug fixed | On real records the templates showed a literal `{LogonType}`: the field is a JSON integer and the renderer only accepted strings. Now rendered (numbers and bools). Found by checking every built-in template against the real records; of the 18 templates then shipped, 12 had a real sample, and the other 9 of those rendered fully. |
| 11 | Group templates 4728/4732/4756 | 2026-09-20 | improved | `MemberName` is `-` for local accounts on every real record; the templates now also show `MemberSid`. |

**Deliberately not added:** LocalSessionManager 41/42 (session arbitration; 42's meaning
not verified) and 32/34/54 (meaning unknown); RemoteConnectionManager 261 and the other
RdpCoreTS/ClientActiveXCore events; Terminal Services Gateway events; templates for 4778/
4779; a Kernel-Power 42 template (two manifest variants). LocalSessionManager 39/40 render
a message but carry no tag.

**Observation, not acted on:** the 4625 message shows `failure reason: %%2313` — that is
the source value (a message-table reference), rendered faithfully; translating the common
`%%` codes would be a separate, sourced mapping.

