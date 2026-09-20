use thiserror::Error;

/// A tagging rule, deserialized from a rule TOML file. `match` can contain
/// a mix of normalized fields (`sourcetype`, `level`, `message`, `event_id`,
/// `provider`) and source-specific fields (e.g. AUL `subsystem`) — anything
/// not recognized as normalized is looked up as a flat top-level key in the
/// entry's `fields` JSON. `event_id`/`provider` need their own sourcetype-aware
/// resolution rather than that flat lookup: EVTX's `fields` nests them under
/// `Event.System` (see [`normalized_field`]), unlike AUL's genuinely flat
/// `subsystem`/`category`. All conditions in one rule must hold (AND) for it
/// to match.
///
/// `message_contains` is a substring variant of `message`: the value is
/// either a single string or an array of strings, and the rule matches if
/// `message` contains *any* of them. This exists because most real-world
/// pattern-of-life categorization (see the AUL rule pack under
/// `rules/examples/`) keys off recognizable substrings in free-text log
/// messages, not off exact equality or structured fields — matching the
/// approach forensic tools like iLEAPP use for the same Apple Unified Log
/// data.
///
/// `subsystem_prefix` is the same idea for the normalized `subsystem`
/// field (AUL's flat `subsystem`, EVTX's provider name): a string or array
/// of strings, matching if the subsystem *starts with* any of them. A
/// prefix rather than a substring test on purpose — a family such as AUL's
/// `com.apple.Navigation` has members that only differ by suffix, while an
/// unrelated `com.apple.corenavigation` (thousands of records on a real
/// image) must not be swept in. Case-sensitive, like every other match key:
/// a family that spells its members with different capitalization lists
/// each spelling explicitly instead of relying on a silent case fold.
///
/// `event_data` is an inline table of field/value pairs that must all equal
/// the same-named field of an EVTX record's payload — its `EventData`, or the
/// `UserData` element for providers that log there (see
/// [`crate::parsers::evtx_templates::event_payload`]), e.g.
/// `event_data = { LogonType = 10 }`. Values compare by type: an integer
/// against a JSON number, a string against a JSON string, so the TOML has to
/// use the type the record actually carries (`LogonType` is a number,
/// `Address` a string). It exists because a field like the logon type is what
/// tells an RDP logon from any other 4624, and it is not at a flat top-level
/// key the way AUL's are. An empty table, a non-table value, a non-EVTX entry
/// or a record without a payload never matches.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Rule {
    pub rule: RuleBody,
    /// `subsystem_prefix` values, precomputed at parse time for the same
    /// reason as `message_contains_needles`. Empty strings are dropped: an
    /// empty prefix would match every entry that has a subsystem at all, so
    /// a rule whose only prefix is `""` must match nothing instead.
    #[serde(skip)]
    subsystem_prefixes: Vec<String>,
    /// `message_contains` needles, precomputed once from
    /// `rule.match_fields` here at parse time rather than rebuilt on every
    /// [`Rule::matches`] call. Import-time tagging runs `matches()` once per
    /// (entry, rule) pair — millions of times for a large AUL load — so
    /// re-deriving this `Vec` from the TOML value on every call would mean
    /// millions of redundant allocations for a list that never changes
    /// after the rule is loaded.
    #[serde(skip)]
    message_contains_needles: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RuleBody {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// A curator-maintained, plain-incrementing counter ("1", "2", ...),
    /// bumped whenever this rule's `match`/`tag` semantics change —
    /// independent of a rule *pack*'s own release version (see
    /// `docs/design/rule-pack-updates.md`). `None` for rule files that
    /// predate this field or were hand-written outside the shipped packs
    /// (e.g. via "Tag all matching (advanced)...") — versioning is a
    /// property of the curated built-in packs, not a requirement for every
    /// rule a user ever writes.
    #[serde(default)]
    pub version: Option<String>,
    #[serde(rename = "match")]
    pub match_fields: toml::Table,
    pub tag: TagSpec,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TagSpec {
    pub value: String,
}

#[derive(Debug, Error)]
#[error("invalid tagging rule: {0}")]
pub struct RuleParseError(#[from] toml::de::Error);

impl Rule {
    pub fn from_toml_str(s: &str) -> Result<Self, RuleParseError> {
        let mut rule: Rule = toml::from_str(s)?;
        rule.message_contains_needles = match_strings(&rule.rule.match_fields, "message_contains");
        rule.subsystem_prefixes = match_strings(&rule.rule.match_fields, "subsystem_prefix")
            .into_iter()
            .filter(|prefix| !prefix.is_empty())
            .collect();
        Ok(rule)
    }

    /// Takes the pieces of an entry that matching actually needs, rather
    /// than a full `LogEntry` — re-tagging streams rows straight out of
    /// DuckDB and shouldn't have to materialize `raw`/`timestamp_utc`/
    /// `event_id` just to call this.
    pub fn matches(
        &self,
        sourcetype: &str,
        level: Option<&str>,
        message: Option<&str>,
        fields: &serde_json::Value,
    ) -> bool {
        self.rule
            .match_fields
            .iter()
            .all(|(key, expected)| match key.as_str() {
                "sourcetype" => expected.as_str() == Some(sourcetype),
                "level" => level.is_some_and(|actual| expected.as_str() == Some(actual)),
                "message" => message.is_some_and(|actual| expected.as_str() == Some(actual)),
                "message_contains" => message.is_some_and(|actual| {
                    self.message_contains_needles
                        .iter()
                        .any(|needle| actual.contains(needle.as_str()))
                }),
                "subsystem_prefix" => normalized_field("subsystem", sourcetype, fields)
                    .or_else(|| fields.get("subsystem"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|actual| {
                        self.subsystem_prefixes
                            .iter()
                            .any(|prefix| actual.starts_with(prefix.as_str()))
                    }),
                "event_data" => expected.as_table().is_some_and(|wanted| {
                    !wanted.is_empty()
                        && fields
                            .get("Event")
                            .and_then(crate::parsers::evtx_templates::event_payload)
                            .is_some_and(|payload| {
                                wanted.iter().all(|(name, value)| {
                                    payload
                                        .get(name)
                                        .is_some_and(|actual| toml_matches_json(value, actual))
                                })
                            })
                }),
                "event_id"
                | "provider"
                | "host"
                | "process"
                | "subsystem"
                | "category"
                | "bundle_id"
                | "app_id"
                | "intent_classname"
                | "intent_action"
                | "token_text"
                | "token_frequency"
                | "mail_subject"
                | "mail_message_id"
                | "state_raw"
                | "wifi_ssid"
                | "timezone_name"
                | "safari_host"
                | "safari_url"
                | "harvested_message_content"
                | "harvested_message_sender"
                | "message_id"
                | "bluetooth_mac"
                | "bluetooth_name" => normalized_field(key, sourcetype, fields)
                    .or_else(|| fields.get(key))
                    .is_some_and(|actual| toml_matches_json(expected, actual)),
                other => fields
                    .get(other)
                    .is_some_and(|actual| toml_matches_json(expected, actual)),
            })
    }
}

/// Resolves normalized match keys that don't live at a flat top-level key
/// in every sourcetype's `fields` JSON to their actual sourcetype-specific
/// location — a flat `fields.get(key)` (the fallback every other
/// source-specific match key uses, and still tried second via
/// [`Rule::matches`]'s `.or_else`, e.g. for AUL's genuinely flat
/// `subsystem`/`category`/`process` or a `text_config` parser whose
/// `field_mapping` happens to produce a top-level key with the same name)
/// would never find EVTX's `event_id`/`provider`/`host`/`subsystem`
/// (nested under `Event.System`) or journald's `host`/`process` (which live
/// under `_HOSTNAME`/`SYSLOG_IDENTIFIER`/`_COMM`, not `host`/`process`).
///
/// Same paths `parsers::evtx::template_rendered_message` resolves against,
/// and the same ones `db::timeline_queries`'s `host_case_sql`/
/// `process_case_sql`/`subsystem_case_sql`/`event_code_case_sql` (backing
/// both the Host/Process/Subsystem/Event ID timeline columns and their
/// `host=`/`process=`/`subsystem=`/`event_id=` search-grammar filters)
/// already use — kept in sync with those rather than re-derived, since a
/// rule condition on one of these fields is meant to match exactly what the
/// analyst sees in that column. `provider` and `subsystem` deliberately
/// resolve to the same path: `provider` is EVTX's equivalent of AUL's
/// `subsystem` (per `docs/field-extraction.md`), and the Advanced tagging
/// dialog's "Filter by..."-derived field conditions always use the
/// normalized `subsystem` keyword, never `provider` — `provider` stays
/// accepted here only because it's the term the tagging docs' own example
/// rules use. Sourcetype/key combinations with no known nested path
/// (including AUL, which has no `event_id`/`provider` concept, only its own
/// already-flat `subsystem`/`category`/`process`) resolve to `None`, same
/// as an absent generic field — the `.or_else(|| fields.get(key))` fallback
/// in `Rule::matches` is what makes AUL's flat fields work at all.
///
/// Biome's arm is a genuinely different shape from every other sourcetype
/// here: its normalized keys don't have one fixed path each, because a raw
/// protobuf field *number* isn't semantically stable across streams (field
/// `3` is a bundle ID in `ScreenTime.AppUsage` but a message-date bit
/// pattern in `ProactiveHarvesting.Mail`) — unlike EVTX's `EventID`, which
/// means the same thing everywhere. So this arm first reads the record's
/// own flat `stream` field (written directly onto `fields` by
/// `parsers::biome`, the same way `event_type` is for `intrusion_log`) and
/// only then decides which `/payload/...` pointer path a key resolves to —
/// see `docs/design/biome-rule-pack-research.md`'s Tier 2 section for where
/// each field number/path comes from (iLEAPP's `biome*.py` modules).
/// `state_raw` runs the same idea in reverse: several structurally
/// identical binary-state streams (locked/connected/enabled/plugged-in)
/// all share this one key name resolving to the same field number (1, or
/// 2 for `Device.Wireless.WiFi`), since the raw 0/1 *shape* is identical
/// even though what "1" means differs per stream — the match arm for
/// `state_raw` groups those streams together rather than repeating the
/// same pointer for each.
fn normalized_field<'a>(
    key: &str,
    sourcetype: &str,
    fields: &'a serde_json::Value,
) -> Option<&'a serde_json::Value> {
    match (sourcetype, key) {
        ("evtx", "event_id") => fields.pointer("/Event/System/EventID"),
        ("evtx", "provider" | "subsystem") => {
            fields.pointer("/Event/System/Provider_attributes/Name")
        }
        ("evtx", "host") => fields.pointer("/Event/System/Computer"),
        ("journald", "host") => fields.pointer("/_HOSTNAME"),
        ("journald", "process") => fields
            .pointer("/SYSLOG_IDENTIFIER")
            .or_else(|| fields.pointer("/_COMM")),
        ("biome", key) => {
            let stream = fields.get("stream").and_then(serde_json::Value::as_str);
            match (stream, key) {
                (Some("ScreenTime.AppUsage"), "bundle_id") => fields.pointer("/payload/3/utf8"),
                (Some("Keyboard.TokenFrequency"), "token_text") => {
                    fields.pointer("/payload/1/nested/1/utf8")
                }
                (Some("Keyboard.TokenFrequency"), "token_frequency") => {
                    fields.pointer("/payload/3")
                }
                (Some("App.Intent"), "app_id") => fields.pointer("/payload/2/utf8"),
                (Some("App.Intent"), "intent_classname") => fields.pointer("/payload/4/utf8"),
                (Some("App.Intent"), "intent_action") => fields.pointer("/payload/5/utf8"),
                (Some("ProactiveHarvesting.Mail"), "mail_subject") => {
                    fields.pointer("/payload/11/utf8")
                }
                (Some("ProactiveHarvesting.Mail"), "mail_message_id") => {
                    fields.pointer("/payload/2/utf8")
                }
                // A plain 0/1 integer, reused across every stream whose only
                // interesting payload content is a binary state — "1" means
                // something different per stream (locked vs. connected vs.
                // enabled), which is exactly why each one still needs its
                // own rule/tag pair even though the lookup is shared. Not a
                // JSON bool: the schema-less decoder never guesses varint
                // semantics (see `parsers::biome::protobuf`), so rules
                // match the raw integer (`state_raw = 1`), not `= true`.
                (
                    Some(
                        "Device.ScreenLocked"
                        | "Device.KeybagLocked"
                        | "CarPlay.Connected"
                        | "Device.Wireless.AirplaneMode"
                        | "Device.Wireless.CellularDataEnabled"
                        | "Device.Power.LowPowerMode"
                        | "Device.Power.PluggedIn",
                    ),
                    "state_raw",
                ) => fields.pointer("/payload/1"),
                (Some("Device.Wireless.WiFi"), "state_raw") => fields.pointer("/payload/2"),
                (Some("Device.Wireless.WiFi"), "wifi_ssid") => fields.pointer("/payload/1/utf8"),
                (Some("Device.TimeZone"), "timezone_name") => fields.pointer("/payload/2/utf8"),
                (Some("Safari.Navigations"), "safari_host") => fields.pointer("/payload/1/utf8"),
                (Some("Safari.Navigations"), "safari_url") => fields.pointer("/payload/8/utf8"),
                (Some("ProactiveHarvesting.Messages"), "harvested_message_content") => {
                    fields.pointer("/payload/10/utf8")
                }
                (Some("ProactiveHarvesting.Messages"), "harvested_message_sender") => {
                    fields.pointer("/payload/11/nested/1/utf8")
                }
                (Some("Messages.Read"), "message_id") => fields.pointer("/payload/1"),
                (Some("Device.Wireless.Bluetooth"), "bluetooth_mac") => {
                    fields.pointer("/payload/1/utf8")
                }
                (Some("Device.Wireless.Bluetooth"), "bluetooth_name") => {
                    fields.pointer("/payload/2/utf8")
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Owned copy of one `match` key's string list (see
/// [`toml_value_as_strings`]) — empty when the key is absent or malformed.
fn match_strings(match_fields: &toml::Table, key: &str) -> Vec<String> {
    match_fields
        .get(key)
        .map(|value| {
            toml_value_as_strings(value)
                .into_iter()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Reads a `match` value (`message_contains`, `subsystem_prefix`) as a list
/// of strings to search for, accepting either a bare string or an array of
/// strings. Any other shape (e.g. an integer) yields an empty list, so a
/// malformed rule simply never matches rather than panicking.
fn toml_value_as_strings(value: &toml::Value) -> Vec<&str> {
    match value {
        toml::Value::String(s) => vec![s.as_str()],
        toml::Value::Array(items) => items.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn toml_matches_json(expected: &toml::Value, actual: &serde_json::Value) -> bool {
    match (expected, actual) {
        (toml::Value::String(e), serde_json::Value::String(a)) => e == a,
        (toml::Value::Integer(e), serde_json::Value::Number(a)) => a.as_i64() == Some(*e),
        (toml::Value::Float(e), serde_json::Value::Number(a)) => a.as_f64() == Some(*e),
        (toml::Value::Boolean(e), serde_json::Value::Bool(a)) => e == a,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shipped rule file in `rules/examples/` (the
    /// AUL/EVTX/journald/intrusion_log packs, see `docs/`) must parse, have
    /// a non-empty name/tag, and carry
    /// a non-empty `version` — a broken TOML file, or one someone forgot to
    /// version when adding it, would otherwise only surface much later
    /// (an unversioned rule silently can't participate in the rule-pack
    /// diff/changelog described in `docs/design/rule-pack-updates.md`).
    #[test]
    fn every_shipped_rule_file_parses_and_is_versioned() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/examples");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let rule = Rule::from_toml_str(&text)
                .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
            assert!(!rule.rule.name.is_empty(), "{}: empty name", path.display());
            assert!(
                !rule.rule.tag.value.is_empty(),
                "{}: empty tag value",
                path.display()
            );
            assert!(
                rule.rule.version.as_deref().is_some_and(|v| !v.is_empty()),
                "{}: missing or empty version",
                path.display()
            );
            checked += 1;
        }
        assert!(checked > 0, "no rule files found in {}", dir.display());
    }

    /// Loads one shipped rule file by name, so the tests below exercise the
    /// rule as actually released rather than a copy of it.
    fn shipped_rule(file_name: &str) -> Rule {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rules/examples")
            .join(file_name);
        let text = std::fs::read_to_string(&path).unwrap();
        Rule::from_toml_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    fn aul(rule: &Rule, category: &str, message: &str) -> bool {
        rule.matches(
            "aul",
            None,
            Some(message),
            &serde_json::json!({ "category": category }),
        )
    }

    /// `kPhoneNumber` is also a substring of an emergency-contact
    /// notification (category `Emergency`); on a real load all ten matches
    /// of the bare substring were that notification and none a dialed number.
    #[test]
    fn shipped_dialed_number_rule_is_scoped_to_call_provider() {
        let rule = shipped_rule("aul_dialed_number_recovery.toml");
        let setup = "#I {\n\t\"kActionId\": \"49B8935B\",\n\t\"kActionType\": 0,\n\t\"kUuid\": \"2FCB034A\",\n\t\"kPhoneNumber\": \"065244****\"\n}";
        let teardown = "#I {\n\t\"kActionType\": 2,\n\t\"kUuid\": \"2FCB034A\"\n}";
        let emergency = "#EmergCon,EMERGENCY:notification,kPhoneNumberStatusNotification";

        assert!(aul(&rule, "call.provider", setup));
        assert!(aul(&rule, "call.provider", teardown));
        assert!(!aul(&rule, "Emergency", emergency));
        assert!(!aul(&rule, "call.provider", "#I Updating config for CSD"));
        assert!(!aul(&rule, "Emergency", setup));
    }

    #[test]
    fn shipped_call_status_rule_requires_category_call() {
        let rule = shipped_rule("aul_call_status_update.toml");
        let status = "Call(StatusUpdate) InitializingMedia -> Dialing for call <private>";

        assert!(aul(&rule, "call", status));
        assert!(!aul(&rule, "call.provider", status));
        assert!(!aul(&rule, "call", "#I isEmergencyWiFiAllowed is false"));
    }

    #[test]
    fn shipped_dialpad_rule_requires_the_contact_search_category() {
        let rule = shipped_rule("aul_dialpad_entry.toml");

        assert!(aul(
            &rule,
            "ContactSearchManager",
            "Searching for 065244****"
        ));
        assert!(aul(
            &rule,
            "ContactSearchManager",
            "Search cancelled for 06"
        ));
        assert!(!aul(
            &rule,
            "ContactSearchManager",
            "Unrelated search state"
        ));
        // A bare "Searching for" outside the category is far too generic.
        assert!(!aul(&rule, "Spotlight", "Searching for photos"));
    }

    #[test]
    fn shipped_carplay_rule_matches_the_wired_marker_and_only_the_activated_handshake() {
        let rule = shipped_rule("aul_carplay_connection.toml");
        let any = |message: &str| aul(&rule, "General", message);

        assert!(any("Found USB DirectLink on the network interface en3"));
        assert!(any("Found USB DirectLink on the network interface en2"));
        assert!(!any("Interface en3 is not a DirectLink interface"));
        assert!(any("session isAuthenticated:1, isActivated:1"));
        assert!(!any("session isAuthenticated:0, isActivated:0"));
        assert!(any(
            "WiFiDeviceManagerSetCarPlaySessionState: CarPlay session vehicle inform: model EC40, manufacturer VolvoCars, hardware version qcom 5.0, isSessionActive Y"
        ));
    }

    /// The bare ` presence:` fragment used to also tag CommCenter modem
    /// lines as touch activity (100 of 281 matches on a real load).
    #[test]
    fn shipped_touchscreen_rule_needs_a_contact_index_before_presence() {
        let rule = shipped_rule("aul_touchscreen_events.toml");
        let any = |message: &str| aul(&rule, "TouchEvents", message);

        assert!(any("contact 0 presence: touching"));
        assert!(any("contact 6 presence: withinRange"));
        assert!(any("received tapToWake"));
        assert!(!any("#I Local emergency numbers presence: 1"));
        assert!(!any("#I SIM card emergency numbers presence: 0"));
    }

    /// An EVTX record shaped like the ones the parser produces: provider and
    /// event ID under `Event.System`, plus whatever payload the caller gives.
    fn evtx_entry(provider: &str, event_id: u32, payload: serde_json::Value) -> serde_json::Value {
        let mut event = serde_json::json!({
            "System": {
                "EventID": event_id,
                "Provider_attributes": {"Name": provider},
            }
        });
        for (key, value) in payload.as_object().unwrap() {
            event[key] = value.clone();
        }
        serde_json::json!({ "Event": event })
    }

    fn evtx_matches(rule: &Rule, entry: &serde_json::Value) -> bool {
        rule.matches("evtx", None, None, entry)
    }

    /// `LogonType` is an integer in real records (seen as 0, 2 and 5), and
    /// only type 10 — RemoteInteractive — is a Remote Desktop logon.
    #[test]
    fn shipped_rdp_logon_rules_match_logon_type_10_only() {
        let security = "Microsoft-Windows-Security-Auditing";
        for (file, event_id) in [
            ("evtx_4624_rdp_logon.toml", 4624),
            ("evtx_4625_rdp_logon_failure.toml", 4625),
        ] {
            let rule = shipped_rule(file);
            let logon = |logon_type: u32| {
                evtx_entry(
                    security,
                    event_id,
                    serde_json::json!({"EventData": {"LogonType": logon_type}}),
                )
            };
            assert!(evtx_matches(&rule, &logon(10)), "{file}: type 10");
            for other in [0, 2, 3, 5, 7, 12] {
                assert!(!evtx_matches(&rule, &logon(other)), "{file}: type {other}");
            }
        }
        // 4624's rule must not fire for a 4625 with type 10, and vice versa.
        let failure_with_type_10 = evtx_entry(
            security,
            4625,
            serde_json::json!({"EventData": {"LogonType": 10}}),
        );
        assert!(!evtx_matches(
            &shipped_rule("evtx_4624_rdp_logon.toml"),
            &failure_with_type_10
        ));
    }

    /// Terminal Services events reuse small event IDs (21, 22, ... 1024), so
    /// each rule is tied to its provider; the same ID from another provider
    /// must not be tagged.
    #[test]
    fn shipped_terminal_services_rules_are_scoped_to_their_provider() {
        let lsm = "Microsoft-Windows-TerminalServices-LocalSessionManager";
        let cases = [
            ("evtx_21_ts_session_logon.toml", lsm, 21),
            ("evtx_22_ts_shell_start.toml", lsm, 22),
            ("evtx_23_ts_session_logoff.toml", lsm, 23),
            ("evtx_24_ts_session_disconnect.toml", lsm, 24),
            ("evtx_25_ts_session_reconnect.toml", lsm, 25),
            (
                "evtx_1149_rdp_connection_established.toml",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                1149,
            ),
            (
                "evtx_131_rdp_connection_accepted.toml",
                "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
                131,
            ),
            (
                "evtx_1024_rdp_client_connect.toml",
                "Microsoft-Windows-TerminalServices-ClientActiveXCore",
                1024,
            ),
        ];
        for (file, provider, event_id) in cases {
            let rule = shipped_rule(file);
            let record = |provider: &str, id: u32| {
                evtx_entry(
                    provider,
                    id,
                    serde_json::json!({"UserData": {"EventXML": {"User": "HOST\\alice"}}}),
                )
            };
            assert!(evtx_matches(&rule, &record(provider, event_id)), "{file}");
            assert!(
                !evtx_matches(&rule, &record("Some Other Provider", event_id)),
                "{file}: same ID, other provider"
            );
            assert!(
                !evtx_matches(&rule, &record(provider, event_id + 1000)),
                "{file}: same provider, other ID"
            );
        }
    }

    /// Event 12 is also logged by `Microsoft-Windows-UserModePowerService`
    /// on the same machines; only the kernel's own record is a boot marker.
    #[test]
    fn shipped_kernel_boot_rule_ignores_the_other_provider_using_event_id_12() {
        let rule = shipped_rule("evtx_12_kernel_general_os_started.toml");
        let record = |provider: &str| evtx_entry(provider, 12, serde_json::json!({}));

        assert!(evtx_matches(
            &rule,
            &record("Microsoft-Windows-Kernel-General")
        ));
        assert!(!evtx_matches(
            &rule,
            &record("Microsoft-Windows-UserModePowerService")
        ));
    }

    /// A rule that shares a tag with an existing one is meant to: the same
    /// real-world event, logged by a different provider.
    #[test]
    fn shipped_terminal_services_and_security_session_events_share_their_tags() {
        let tag = |file: &str| shipped_rule(file).rule.tag.value;
        assert_eq!(
            tag("evtx_24_ts_session_disconnect.toml"),
            tag("evtx_4779_session_disconnected.toml")
        );
        assert_eq!(
            tag("evtx_25_ts_session_reconnect.toml"),
            tag("evtx_4778_session_reconnected.toml")
        );
        assert_eq!(
            tag("evtx_4647_logoff_user_initiated.toml"),
            tag("evtx_4634_logoff.toml")
        );
        assert_eq!(
            tag("evtx_4733_group_membership_removed.toml"),
            tag("evtx_4732_group_membership_change.toml")
        );
    }

    /// `com.apple.corenavigation` is a different framework (5,239 records
    /// on a real load, versus 77 for `com.apple.Navigation`).
    #[test]
    fn shipped_navigation_rule_matches_the_maps_framework_subsystem_only() {
        let rule = shipped_rule("aul_navigation.toml");
        let sub =
            |name: &str| rule.matches("aul", None, None, &serde_json::json!({"subsystem": name}));

        assert!(sub("com.apple.Navigation"));
        assert!(sub("com.apple.navigation.VirtualGarage"));
        assert!(!sub("com.apple.corenavigation"));
        assert!(!sub("com.apple.Maps"));
    }

    #[test]
    fn parses_the_evtx_style_example() {
        let toml_text = r#"
[rule]
name = "failed_logon"
description = "Windows fehlgeschlagene Anmeldung"

[rule.match]
sourcetype = "evtx"
event_id = 4625

[rule.tag]
value = "auth_failure"
"#;
        let rule = Rule::from_toml_str(toml_text).unwrap();

        assert_eq!(rule.rule.name, "failed_logon");
        assert_eq!(rule.rule.tag.value, "auth_failure");
        assert_eq!(
            rule.rule
                .match_fields
                .get("sourcetype")
                .and_then(|v| v.as_str()),
            Some("evtx")
        );
    }

    #[test]
    fn parses_the_generic_level_example() {
        let toml_text = r#"
[rule]
name = "generic_error"
description = "Cross-Source: alles mit level=ERROR"

[rule.match]
level = "ERROR"

[rule.tag]
value = "error"
"#;
        let rule = Rule::from_toml_str(toml_text).unwrap();

        assert_eq!(rule.rule.name, "generic_error");
        assert_eq!(rule.rule.tag.value, "error");
    }

    #[test]
    fn parses_an_explicit_version_field() {
        let toml_text = r#"
[rule]
name = "aul_airplane_mode"
description = "..."
version = "3"

[rule.match]
sourcetype = "aul"

[rule.tag]
value = "airplane_mode"
"#;
        let rule = Rule::from_toml_str(toml_text).unwrap();
        assert_eq!(rule.rule.version.as_deref(), Some("3"));
    }

    #[test]
    fn version_defaults_to_none_when_absent() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert_eq!(rule.rule.version, None);
    }

    #[test]
    fn malformed_rule_toml_is_an_error_not_a_panic() {
        let result = Rule::from_toml_str("this is not valid toml [[[");

        assert!(result.is_err());
    }

    #[test]
    fn matches_on_generic_level_field() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"error\"\n",
        )
        .unwrap();

        let null = serde_json::Value::Null;
        assert!(rule.matches("text_config", Some("ERROR"), None, &null));
        assert!(!rule.matches("text_config", Some("INFO"), None, &null));
        assert!(!rule.matches("text_config", None, None, &null));
    }

    #[test]
    fn matches_on_sourcetype() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let null = serde_json::Value::Null;

        assert!(rule.matches("aul", None, None, &null));
        assert!(!rule.matches("evtx", None, None, &null));
    }

    /// `fields` here mirrors the real nested shape `parsers::evtx` actually
    /// produces (`{"Event": {"System": {"EventID": ...}}}`), not a flat
    /// `{"event_id": ...}` — the earlier version of this test used the flat
    /// shape and passed even though `event_id` rules never matched a real
    /// EVTX entry, because `Rule::matches` only fell back to a top-level
    /// `fields.get()` lookup. Keep this nested; it's the only thing that
    /// would have caught that.
    #[test]
    fn matches_on_evtx_event_id_via_nested_json_path() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"failed_logon\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_id = 4625\n[rule.tag]\nvalue = \"auth_failure\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({"Event": {"System": {"EventID": 4625}}});
        let wrong_id = serde_json::json!({"Event": {"System": {"EventID": 4624}}});
        let missing_field = serde_json::json!({"Event": {"System": {}}});

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &wrong_id));
        assert!(!rule.matches("evtx", None, None, &missing_field));
    }

    #[test]
    fn matches_on_evtx_provider_via_nested_json_path() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"security_auditing\"\n[rule.match]\nsourcetype = \"evtx\"\nprovider = \"Microsoft-Windows-Security-Auditing\"\n[rule.tag]\nvalue = \"security_auditing\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({
            "Event": {"System": {"Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"}}}
        });
        let other_provider = serde_json::json!({
            "Event": {"System": {"Provider_attributes": {"Name": "Microsoft-Windows-Kernel-General"}}}
        });

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &other_provider));
    }

    /// `subsystem` on EVTX must resolve the same nested path `provider`
    /// does — the Advanced tagging dialog's "Filter by..."-derived field
    /// conditions always write `subsystem` (the normalized keyword shared
    /// with AUL, matching the timeline's Subsystem column), never
    /// `provider`, so a rule using that keyword must still match real EVTX
    /// data. Regression guard for the same class of bug `event_id`/
    /// `provider` had before `normalized_field` existed: routing a
    /// normalized keyword through the generic flat `fields.get` fallback
    /// silently never matches EVTX's nested shape.
    #[test]
    fn matches_on_evtx_subsystem_via_the_same_nested_path_as_provider() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"security_auditing\"\n[rule.match]\nsourcetype = \"evtx\"\nsubsystem = \"Microsoft-Windows-Security-Auditing\"\n[rule.tag]\nvalue = \"security_auditing\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({
            "Event": {"System": {"Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"}}}
        });
        let other_provider = serde_json::json!({
            "Event": {"System": {"Provider_attributes": {"Name": "Microsoft-Windows-Kernel-General"}}}
        });

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &other_provider));
    }

    #[test]
    fn matches_on_evtx_host_via_nested_json_path() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"h\"\n[rule.match]\nsourcetype = \"evtx\"\nhost = \"WORKSTATION1\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({"Event": {"System": {"Computer": "WORKSTATION1"}}});
        let other_host = serde_json::json!({"Event": {"System": {"Computer": "WORKSTATION2"}}});

        assert!(rule.matches("evtx", None, None, &matching));
        assert!(!rule.matches("evtx", None, None, &other_host));
    }

    /// journald's own field names (`_HOSTNAME`, `SYSLOG_IDENTIFIER`/
    /// `_COMM`) don't literally spell "host"/"process" — same nested-vs-flat
    /// mismatch as EVTX, just with flat-but-differently-named keys instead
    /// of a nested path.
    #[test]
    fn matches_on_journald_host_and_process_via_their_actual_field_names() {
        let host_rule = Rule::from_toml_str(
            "[rule]\nname = \"h\"\n[rule.match]\nsourcetype = \"journald\"\nhost = \"web01\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let process_rule = Rule::from_toml_str(
            "[rule]\nname = \"p\"\n[rule.match]\nsourcetype = \"journald\"\nprocess = \"sshd\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let entry = serde_json::json!({"_HOSTNAME": "web01", "SYSLOG_IDENTIFIER": "sshd"});
        let other_entry = serde_json::json!({"_HOSTNAME": "web02", "_COMM": "cron"});

        assert!(host_rule.matches("journald", None, None, &entry));
        assert!(!host_rule.matches("journald", None, None, &other_entry));
        assert!(process_rule.matches("journald", None, None, &entry));
        assert!(!process_rule.matches("journald", None, None, &other_entry));

        // `_COMM` fallback when `SYSLOG_IDENTIFIER` is absent.
        let comm_only = serde_json::json!({"_COMM": "sshd"});
        assert!(process_rule.matches("journald", None, None, &comm_only));
    }

    /// An `event_id`/`provider` rule is EVTX-specific by construction — a
    /// non-evtx sourcetype has no known path to resolve them against
    /// (`normalized_field` returns `None`), so the condition never holds
    /// regardless of what happens to be in `fields`.
    #[test]
    fn evtx_normalized_fields_never_match_a_non_evtx_sourcetype() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nevent_id = 4625\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let looks_like_it_could_match = serde_json::json!({"Event": {"System": {"EventID": 4625}}});

        assert!(!rule.matches("aul", None, None, &looks_like_it_could_match));
        assert!(!rule.matches("text_config", None, None, &looks_like_it_could_match));
    }

    /// Regression guard for the generic fallback path (`fields.get(other)`)
    /// that source-specific-but-not-normalized fields like AUL's flat
    /// `subsystem` still rely on — `event_id`/`provider` gained their own
    /// sourcetype-aware match arm, but everything else must keep going
    /// through the flat top-level lookup unchanged.
    #[test]
    fn matches_on_a_flat_source_specific_field_via_generic_fallback() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"mdns\"\n[rule.match]\nsourcetype = \"aul\"\nsubsystem = \"com.apple.mDNSResponder\"\n[rule.tag]\nvalue = \"mdns\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({"subsystem": "com.apple.mDNSResponder"});
        let other_subsystem = serde_json::json!({"subsystem": "com.apple.wifi"});

        assert!(rule.matches("aul", None, None, &matching));
        assert!(!rule.matches("aul", None, None, &other_subsystem));
    }

    /// Biome's Tier 1 `stream` key needs zero `normalized_field` support at
    /// all — the parser writes it as a plain flat top-level key, so it
    /// resolves through the untouched generic fallback, exactly like
    /// `intrusion_log`'s `event_type`.
    #[test]
    fn matches_on_biome_stream_via_generic_fallback() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"screen_locked\"\n[rule.match]\nsourcetype = \"biome\"\nstream = \"Device.ScreenLocked\"\n[rule.tag]\nvalue = \"screen_locked\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({"stream": "Device.ScreenLocked"});
        let other_stream = serde_json::json!({"stream": "Device.Wireless.Bluetooth"});

        assert!(rule.matches("biome", None, None, &matching));
        assert!(!rule.matches("biome", None, None, &other_stream));
    }

    #[test]
    fn matches_on_biome_screentime_bundle_id_via_stream_conditioned_pointer() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"app_usage\"\n[rule.match]\nsourcetype = \"biome\"\nstream = \"ScreenTime.AppUsage\"\nbundle_id = \"com.example.app\"\n[rule.tag]\nvalue = \"app_usage\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({
            "stream": "ScreenTime.AppUsage",
            "payload": {"3": {"utf8": "com.example.app", "nested": null, "hex": "..."}}
        });
        let other_bundle = serde_json::json!({
            "stream": "ScreenTime.AppUsage",
            "payload": {"3": {"utf8": "com.other.app", "nested": null, "hex": "..."}}
        });

        assert!(rule.matches("biome", None, None, &matching));
        assert!(!rule.matches("biome", None, None, &other_bundle));
    }

    #[test]
    fn matches_on_biome_keyboard_token_text_via_nested_pointer() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"token\"\n[rule.match]\nsourcetype = \"biome\"\nstream = \"Keyboard.TokenFrequency\"\ntoken_text = \"hello\"\n[rule.tag]\nvalue = \"token\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({
            "stream": "Keyboard.TokenFrequency",
            "payload": {"1": {"nested": {"1": {"utf8": "hello", "nested": null, "hex": "..."}}, "utf8": null, "hex": "..."}}
        });

        assert!(rule.matches("biome", None, None, &matching));
    }

    /// Regression guard for the whole reason `normalized_field`'s biome arm
    /// checks `stream` before resolving a pointer path: a raw protobuf
    /// field number means something different in every stream, so a
    /// `ProactiveHarvesting.Mail` record's field 3 (a message-date bit
    /// pattern, stored as a plain integer, not `{"utf8": ...}`) must never
    /// satisfy a `bundle_id` rule that only makes sense for
    /// `ScreenTime.AppUsage`.
    #[test]
    fn biome_bundle_id_from_one_stream_does_not_leak_into_another_streams_field_3() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"app_usage\"\n[rule.match]\nsourcetype = \"biome\"\nbundle_id = \"com.example.app\"\n[rule.tag]\nvalue = \"app_usage\"\n",
        )
        .unwrap();

        let mail_record = serde_json::json!({
            "stream": "ProactiveHarvesting.Mail",
            "payload": {"3": 4_868_046_054_186_926_080_i64}
        });

        assert!(!rule.matches("biome", None, None, &mail_record));
    }

    #[test]
    fn biome_normalized_fields_never_match_a_non_biome_sourcetype() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"b\"\n[rule.match]\nbundle_id = \"com.example.app\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let looks_like_it_could_match = serde_json::json!({
            "stream": "ScreenTime.AppUsage",
            "payload": {"3": {"utf8": "com.example.app", "nested": null, "hex": "..."}}
        });

        assert!(!rule.matches("aul", None, None, &looks_like_it_could_match));
    }

    /// `state_raw` is shared by several structurally identical binary-state
    /// streams — this pins down that the *same* key name resolves to
    /// different field numbers (field 1 for most, field 2 for WiFi) purely
    /// based on which stream the record carries.
    #[test]
    fn matches_on_biome_state_raw_shared_across_streams_with_different_field_numbers() {
        let locked_rule = Rule::from_toml_str(
            "[rule]\nname = \"l\"\n[rule.match]\nsourcetype = \"biome\"\nstream = \"Device.ScreenLocked\"\nstate_raw = 1\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let wifi_rule = Rule::from_toml_str(
            "[rule]\nname = \"w\"\n[rule.match]\nsourcetype = \"biome\"\nstream = \"Device.Wireless.WiFi\"\nstate_raw = 1\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let locked = serde_json::json!({"stream": "Device.ScreenLocked", "payload": {"1": 1}});
        let unlocked = serde_json::json!({"stream": "Device.ScreenLocked", "payload": {"1": 0}});
        let wifi_connected = serde_json::json!({"stream": "Device.Wireless.WiFi", "payload": {"1": {"utf8": "HomeNet", "nested": null, "hex": "..."}, "2": 1}});

        assert!(locked_rule.matches("biome", None, None, &locked));
        assert!(!locked_rule.matches("biome", None, None, &unlocked));
        assert!(wifi_rule.matches("biome", None, None, &wifi_connected));
        // The locked rule's field-1 lookup must not accidentally match
        // WiFi's field 1 (the SSID, not a state).
        assert!(!locked_rule.matches("biome", None, None, &wifi_connected));
    }

    #[test]
    fn matches_on_biome_reachable_only_keys_with_no_built_in_rule() {
        let ssid_rule = Rule::from_toml_str(
            "[rule]\nname = \"s\"\n[rule.match]\nsourcetype = \"biome\"\nstream = \"Device.Wireless.WiFi\"\nwifi_ssid = \"HomeNet\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let tz_rule = Rule::from_toml_str(
            "[rule]\nname = \"tz\"\n[rule.match]\nsourcetype = \"biome\"\nstream = \"Device.TimeZone\"\ntimezone_name = \"Europe/Berlin\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let wifi = serde_json::json!({
            "stream": "Device.Wireless.WiFi",
            "payload": {"1": {"utf8": "HomeNet", "nested": null, "hex": "..."}, "2": 1}
        });
        let tz = serde_json::json!({
            "stream": "Device.TimeZone",
            "payload": {"2": {"utf8": "Europe/Berlin", "nested": null, "hex": "..."}}
        });

        assert!(ssid_rule.matches("biome", None, None, &wifi));
        assert!(tz_rule.matches("biome", None, None, &tz));
    }

    #[test]
    fn matches_on_biome_nested_harvested_message_sender() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"m\"\n[rule.match]\nsourcetype = \"biome\"\nstream = \"ProactiveHarvesting.Messages\"\nharvested_message_sender = \"+15551234567\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        let matching = serde_json::json!({
            "stream": "ProactiveHarvesting.Messages",
            "payload": {"11": {"nested": {"1": {"utf8": "+15551234567", "nested": null, "hex": "..."}}, "utf8": null, "hex": "..."}}
        });

        assert!(rule.matches("biome", None, None, &matching));
    }

    #[test]
    fn matches_message_contains_against_array_of_substrings() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"screen_lock\"\n[rule.match]\nmessage_contains = [\"Screen did lock\", \"screen is unlocked\"]\n[rule.tag]\nvalue = \"screen_lock_state\"\n",
        )
        .unwrap();
        let null = serde_json::Value::Null;

        assert!(rule.matches("aul", None, Some("Screen did lock now"), &null));
        assert!(rule.matches("aul", None, Some("the screen is unlocked"), &null));
        assert!(!rule.matches("aul", None, Some("unrelated message"), &null));
        assert!(!rule.matches("aul", None, None, &null));
    }

    #[test]
    fn matches_message_contains_against_a_single_bare_string() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"flashlight\"\n[rule.match]\nmessage_contains = \"[Flashlight Controller]\"\n[rule.tag]\nvalue = \"flashlight\"\n",
        )
        .unwrap();
        let null = serde_json::Value::Null;

        assert!(rule.matches("aul", None, Some("[Flashlight Controller] on"), &null));
        assert!(!rule.matches("aul", None, Some("unrelated"), &null));
    }

    #[test]
    fn message_contains_needles_are_precomputed_once_at_parse_time() {
        let array_rule = Rule::from_toml_str(
            "[rule]\nname = \"a\"\n[rule.match]\nmessage_contains = [\"foo\", \"bar\"]\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert_eq!(array_rule.message_contains_needles, vec!["foo", "bar"]);

        let bare_string_rule = Rule::from_toml_str(
            "[rule]\nname = \"b\"\n[rule.match]\nmessage_contains = \"foo\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert_eq!(bare_string_rule.message_contains_needles, vec!["foo"]);

        let no_message_contains_rule = Rule::from_toml_str(
            "[rule]\nname = \"c\"\n[rule.match]\nsourcetype = \"aul\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert!(no_message_contains_rule.message_contains_needles.is_empty());
    }

    #[test]
    fn message_contains_with_non_string_value_never_matches() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"bad\"\n[rule.match]\nmessage_contains = 42\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        assert!(!rule.matches("aul", None, Some("anything"), &serde_json::Value::Null));
    }

    /// The real motivating family: AUL's MapsNavigation framework logs under
    /// `com.apple.Navigation` (categories and process vary per OS release),
    /// plus a member spelled with a lowercase `n`. An unrelated
    /// `com.apple.corenavigation` shares a case-insensitive *substring* with
    /// both but is not part of the family.
    #[test]
    fn subsystem_prefix_matches_a_string_or_any_array_entry_on_aul() {
        let single = Rule::from_toml_str(
            "[rule]\nname = \"nav\"\n[rule.match]\nsourcetype = \"aul\"\nsubsystem_prefix = \"com.apple.Navigation\"\n[rule.tag]\nvalue = \"navigation\"\n",
        )
        .unwrap();
        let list = Rule::from_toml_str(
            "[rule]\nname = \"nav\"\n[rule.match]\nsourcetype = \"aul\"\nsubsystem_prefix = [\"com.apple.Navigation\", \"com.apple.navigation.VirtualGarage\"]\n[rule.tag]\nvalue = \"navigation\"\n",
        )
        .unwrap();
        let sub = |name: &str| serde_json::json!({ "subsystem": name });

        assert!(single.matches("aul", None, None, &sub("com.apple.Navigation")));
        assert!(single.matches("aul", None, None, &sub("com.apple.Navigation.Extra")));
        assert!(!single.matches(
            "aul",
            None,
            None,
            &sub("com.apple.navigation.VirtualGarage")
        ));

        assert!(list.matches("aul", None, None, &sub("com.apple.Navigation")));
        assert!(list.matches(
            "aul",
            None,
            None,
            &sub("com.apple.navigation.VirtualGarage")
        ));
        assert!(!list.matches("aul", None, None, &sub("com.apple.corenavigation")));
        assert!(!list.matches("aul", None, None, &sub("com.apple.navigation")));
        assert!(!list.matches("aul", None, None, &sub("Other.com.apple.Navigation")));
    }

    #[test]
    fn subsystem_prefix_never_matches_a_missing_or_non_string_subsystem() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"nav\"\n[rule.match]\nsubsystem_prefix = \"com.apple.Navigation\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();

        assert!(!rule.matches("aul", None, None, &serde_json::Value::Null));
        assert!(!rule.matches("aul", None, None, &serde_json::json!({})));
        assert!(!rule.matches("aul", None, None, &serde_json::json!({"subsystem": 7})));
    }

    /// An empty prefix would match every entry that has a subsystem — a
    /// rule like that must match nothing rather than tag the whole timeline.
    #[test]
    fn subsystem_prefix_with_only_empty_or_malformed_values_never_matches() {
        let with_subsystem = serde_json::json!({"subsystem": "com.apple.Navigation"});
        for value in ["\"\"", "[\"\"]", "[]", "42"] {
            let rule = Rule::from_toml_str(&format!(
                "[rule]\nname = \"bad\"\n[rule.match]\nsubsystem_prefix = {value}\n[rule.tag]\nvalue = \"t\"\n"
            ))
            .unwrap();
            assert!(
                !rule.matches("aul", None, None, &with_subsystem),
                "subsystem_prefix = {value} must not match"
            );
        }

        let mixed = Rule::from_toml_str(
            "[rule]\nname = \"mixed\"\n[rule.match]\nsubsystem_prefix = [\"\", \"com.apple.Navigation\"]\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        assert_eq!(mixed.subsystem_prefixes, vec!["com.apple.Navigation"]);
        assert!(!mixed.matches(
            "aul",
            None,
            None,
            &serde_json::json!({"subsystem": "unrelated"})
        ));
    }

    /// `subsystem` resolves EVTX's provider name the same way the plain
    /// `provider`/`subsystem` keys do, so a whole provider family
    /// (`Microsoft-Windows-TerminalServices-*`) can be matched by prefix.
    #[test]
    fn subsystem_prefix_resolves_the_evtx_provider_name() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"ts\"\n[rule.match]\nsourcetype = \"evtx\"\nsubsystem_prefix = \"Microsoft-Windows-TerminalServices\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let provider = |name: &str| serde_json::json!({"Event": {"System": {"Provider_attributes": {"Name": name}}}});

        assert!(rule.matches(
            "evtx",
            None,
            None,
            &provider("Microsoft-Windows-TerminalServices-LocalSessionManager")
        ));
        assert!(!rule.matches(
            "evtx",
            None,
            None,
            &provider("Microsoft-Windows-Security-Auditing")
        ));
        // Still ANDed with the other conditions, including sourcetype.
        assert!(!rule.matches(
            "aul",
            None,
            None,
            &provider("Microsoft-Windows-TerminalServices-LocalSessionManager")
        ));
    }

    fn evtx_record(event: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "Event": event })
    }

    /// `LogonType` reaches the JSON as an integer, so the rule value is an
    /// integer too; a string `"10"` is a different type and does not match.
    #[test]
    fn event_data_matches_an_event_data_field_by_type() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"rdp\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_id = 4624\nevent_data = { LogonType = 10 }\n[rule.tag]\nvalue = \"rdp_logon\"\n",
        )
        .unwrap();
        let logon = |logon_type: serde_json::Value| {
            evtx_record(serde_json::json!({
                "System": {"EventID": 4624},
                "EventData": {"LogonType": logon_type, "TargetUserName": "alice"}
            }))
        };

        assert!(rule.matches("evtx", None, None, &logon(serde_json::json!(10))));
        assert!(!rule.matches("evtx", None, None, &logon(serde_json::json!(5))));
        assert!(!rule.matches("evtx", None, None, &logon(serde_json::json!("10"))));
        // Still ANDed with `event_id`.
        let other_event = evtx_record(serde_json::json!({
            "System": {"EventID": 4625},
            "EventData": {"LogonType": 10}
        }));
        assert!(!rule.matches("evtx", None, None, &other_event));
    }

    /// Terminal Services logs into `UserData/EventXML`, not `EventData`.
    #[test]
    fn event_data_also_reads_the_user_data_element_and_requires_every_pair() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"local\"\n[rule.match]\nsourcetype = \"evtx\"\nevent_data = { Address = \"LOCAL\", SessionID = 1 }\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let record = |address: &str, session: u64| {
            evtx_record(serde_json::json!({
                "UserData": {
                    "EventXML_attributes": {"xmlns": "Event_NS"},
                    "EventXML": {"User": "HOST\\alice", "SessionID": session, "Address": address}
                }
            }))
        };

        assert!(rule.matches("evtx", None, None, &record("LOCAL", 1)));
        assert!(!rule.matches("evtx", None, None, &record("10.0.0.5", 1)));
        assert!(!rule.matches("evtx", None, None, &record("LOCAL", 2)));
    }

    #[test]
    fn event_data_never_matches_a_malformed_condition_or_a_record_without_payload() {
        let with_event_data = evtx_record(serde_json::json!({"EventData": {"LogonType": 10}}));
        for value in ["{}", "10", "\"LogonType\"", "[10]"] {
            let rule = Rule::from_toml_str(&format!(
                "[rule]\nname = \"bad\"\n[rule.match]\nevent_data = {value}\n[rule.tag]\nvalue = \"t\"\n"
            ))
            .unwrap();
            assert!(
                !rule.matches("evtx", None, None, &with_event_data),
                "event_data = {value} must not match"
            );
        }

        let rule = Rule::from_toml_str(
            "[rule]\nname = \"r\"\n[rule.match]\nevent_data = { LogonType = 10 }\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        // No EventData/UserData, EventData null, and a non-EVTX entry.
        assert!(!rule.matches("evtx", None, None, &evtx_record(serde_json::json!({}))));
        assert!(!rule.matches(
            "evtx",
            None,
            None,
            &evtx_record(serde_json::json!({"EventData": null}))
        ));
        assert!(!rule.matches(
            "aul",
            None,
            None,
            &serde_json::json!({"LogonType": 10, "subsystem": "x"})
        ));
    }

    #[test]
    fn all_conditions_must_match() {
        let rule = Rule::from_toml_str(
            "[rule]\nname = \"e\"\n[rule.match]\nsourcetype = \"evtx\"\nlevel = \"ERROR\"\n[rule.tag]\nvalue = \"t\"\n",
        )
        .unwrap();
        let null = serde_json::Value::Null;

        assert!(rule.matches("evtx", Some("ERROR"), None, &null));
        assert!(!rule.matches("text_config", Some("ERROR"), None, &null));
    }
}
