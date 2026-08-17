//! A timezone the analyst can name in a config value: either a fixed
//! offset (`"+02:00"`, `"UTC"`, `"Z"` — the shape `assume_offset` always
//! accepted before this existed) or a real IANA zone name (`"Europe/Berlin"`,
//! `"America/New_York"`) via `chrono-tz`. One shared type for every place
//! Peach needs a timezone from the analyst rather than the log data itself:
//! `parsers::text_config`'s per-source `assume_offset` and the new
//! session-wide `Settings::default_source_timezone`/`display_timezone`.
//!
//! IANA names matter here specifically because a *fixed* offset is wrong
//! for a case that spans a DST transition — the same "Europe/Berlin" data
//! is `+01:00` in January and `+02:00` in July, and a fixed-offset
//! `assume_offset`/display setting would silently apply the wrong one to
//! half the timeline. `chrono_tz::Tz` resolves that correctly because it
//! carries the whole IANA transition table, not just one number.

use anyhow::{Context, anyhow};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimezoneSpec {
    Fixed(FixedOffset),
    Named(chrono_tz::Tz),
}

impl TimezoneSpec {
    /// Parses `s` as either a fixed offset (`"+HH:MM"`/`"-HH:MM"`/`"UTC"`/
    /// `"Z"`) or an IANA zone name — fixed-offset syntax is tried first, so
    /// `"UTC"` always resolves to [`Self::Fixed`] (zero offset) rather than
    /// `chrono_tz::Tz::UTC`, keeping it the same tiny/cheap value it always
    /// was for the by far most common case.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Ok(offset) = parse_fixed_offset(s) {
            return Ok(Self::Fixed(offset));
        }
        s.trim()
            .parse::<chrono_tz::Tz>()
            .map(Self::Named)
            .map_err(|_| {
                anyhow!(
                    "invalid timezone '{s}': expected a fixed offset ('+02:00', '-05:00', \
                     'UTC'), or an IANA zone name ('Europe/Berlin', 'America/New_York', ...)"
                )
            })
    }

    /// Resolves a *naive* local timestamp (no offset of its own) against
    /// this timezone into an absolute UTC instant — what `assume_offset`/
    /// `Settings::default_source_timezone` are for: the log line only ever
    /// carries local wall-clock time, this fills in which timezone that
    /// local time was actually in. `None` if the local time is ambiguous
    /// (occurs twice, during a "fall back" DST transition) or nonexistent
    /// (skipped entirely, during a "spring forward" transition) —
    /// `Tz::from_local_datetime`'s own `LocalResult::single()` already
    /// distinguishes those from success, same as `FixedOffset` always did,
    /// this only adds the same possibility for a *named* zone (a fixed
    /// offset is never ambiguous/nonexistent, every local time maps to
    /// exactly one instant).
    pub fn resolve_local(&self, naive: NaiveDateTime) -> Option<DateTime<Utc>> {
        match self {
            Self::Fixed(offset) => offset
                .from_local_datetime(&naive)
                .single()
                .map(|dt| dt.with_timezone(&Utc)),
            Self::Named(tz) => tz
                .from_local_datetime(&naive)
                .single()
                .map(|dt| dt.with_timezone(&Utc)),
        }
    }

    /// Formats a known UTC instant in this timezone — what the display
    /// timezone and CSV/JSON export are for. Always unambiguous (unlike
    /// [`Self::resolve_local`]): converting *from* a real instant *to*
    /// local time never hits the "occurs twice"/"doesn't occur" DST
    /// problem, that's only possible going the other direction.
    ///
    /// `fmt` must not itself print an offset/zone abbreviation (`%z`/`%Z`)
    /// — this always appends one (`%:z`, e.g. `+02:00`) itself, so the
    /// result is self-describing no matter which zone was configured: a
    /// reader can tell what timezone a value is in from the value alone,
    /// not from having to already know Peach's current setting. That
    /// matters most for CSV/JSON export, which can outlive the session
    /// that produced it.
    pub fn format_utc(&self, utc: DateTime<Utc>, fmt: &str) -> String {
        let with_offset = format!("{fmt} %:z");
        match self {
            Self::Fixed(offset) => utc.with_timezone(offset).format(&with_offset).to_string(),
            Self::Named(tz) => utc.with_timezone(tz).format(&with_offset).to_string(),
        }
    }
}

/// `pub(crate)` — [`TimezoneSpec::parse`] tries this first; also reused
/// directly by anything that only ever wants a fixed offset, not a full
/// [`TimezoneSpec`].
pub(crate) fn parse_fixed_offset(s: &str) -> anyhow::Result<FixedOffset> {
    let trimmed = s.trim();
    if trimmed.eq_ignore_ascii_case("utc") || trimmed == "Z" || trimmed == "z" {
        return Ok(FixedOffset::east_opt(0).unwrap());
    }

    let invalid = || anyhow!("invalid offset '{s}': expected '+HH:MM' or '-HH:MM'");

    let (sign, rest) = match trimmed.as_bytes().first() {
        Some(b'+') => (1, &trimmed[1..]),
        Some(b'-') => (-1, &trimmed[1..]),
        _ => return Err(invalid()),
    };
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(invalid());
    }
    let hours: i32 = digits[0..2].parse().map_err(|_| invalid())?;
    let minutes: i32 = digits[2..4].parse().map_err(|_| invalid())?;
    let total_seconds = sign * (hours * 3600 + minutes * 60);

    FixedOffset::east_opt(total_seconds).with_context(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_utc_and_z_as_fixed_zero_offset() {
        assert_eq!(
            TimezoneSpec::parse("UTC").unwrap(),
            TimezoneSpec::Fixed(FixedOffset::east_opt(0).unwrap())
        );
        assert_eq!(
            TimezoneSpec::parse("Z").unwrap(),
            TimezoneSpec::Fixed(FixedOffset::east_opt(0).unwrap())
        );
    }

    #[test]
    fn parse_accepts_a_fixed_offset() {
        assert_eq!(
            TimezoneSpec::parse("+02:00").unwrap(),
            TimezoneSpec::Fixed(FixedOffset::east_opt(2 * 3600).unwrap())
        );
        assert_eq!(
            TimezoneSpec::parse("-0500").unwrap(),
            TimezoneSpec::Fixed(FixedOffset::east_opt(-5 * 3600).unwrap())
        );
    }

    #[test]
    fn parse_accepts_an_iana_zone_name() {
        assert_eq!(
            TimezoneSpec::parse("Europe/Berlin").unwrap(),
            TimezoneSpec::Named(chrono_tz::Europe::Berlin)
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(TimezoneSpec::parse("not a timezone").is_err());
        assert!(TimezoneSpec::parse("europe/berlin").is_err());
    }

    #[test]
    fn resolve_local_with_fixed_offset_matches_the_old_behavior() {
        let spec = TimezoneSpec::parse("+02:00").unwrap();
        let naive =
            NaiveDateTime::parse_from_str("2026-07-28 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(
            spec.resolve_local(naive).unwrap(),
            DateTime::parse_from_rfc3339("2026-07-28T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    /// The whole point of adding IANA support: the same wall-clock time in
    /// Berlin resolves to a *different* UTC instant in winter (CET, +01:00)
    /// than in summer (CEST, +02:00) — a fixed offset can't do this at all.
    #[test]
    fn resolve_local_with_named_zone_is_dst_aware() {
        let spec = TimezoneSpec::parse("Europe/Berlin").unwrap();

        let winter =
            NaiveDateTime::parse_from_str("2026-01-15 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(
            spec.resolve_local(winter).unwrap(),
            DateTime::parse_from_rfc3339("2026-01-15T11:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );

        let summer =
            NaiveDateTime::parse_from_str("2026-07-15 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(
            spec.resolve_local(summer).unwrap(),
            DateTime::parse_from_rfc3339("2026-07-15T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn resolve_local_returns_none_for_a_nonexistent_spring_forward_time() {
        // Europe/Berlin, 2026-03-29: clocks jump from 02:00 to 03:00 —
        // 02:30 never happens that day.
        let spec = TimezoneSpec::parse("Europe/Berlin").unwrap();
        let naive =
            NaiveDateTime::parse_from_str("2026-03-29 02:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert!(spec.resolve_local(naive).is_none());
    }

    #[test]
    fn format_utc_always_includes_a_self_describing_offset() {
        let utc = DateTime::parse_from_rfc3339("2026-07-15T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let fixed = TimezoneSpec::parse("+02:00").unwrap();
        assert_eq!(
            fixed.format_utc(utc, "%Y-%m-%d %H:%M:%S"),
            "2026-07-15 12:00:00 +02:00"
        );

        let named = TimezoneSpec::parse("Europe/Berlin").unwrap();
        assert_eq!(
            named.format_utc(utc, "%Y-%m-%d %H:%M:%S"),
            "2026-07-15 12:00:00 +02:00"
        );

        let winter_utc = DateTime::parse_from_rfc3339("2026-01-15T11:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            named.format_utc(winter_utc, "%Y-%m-%d %H:%M:%S"),
            "2026-01-15 12:00:00 +01:00"
        );
    }
}
