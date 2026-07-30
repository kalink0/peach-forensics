use eframe::egui::Color32;

/// Validated 8-hue categorical palette (CVD-safe adjacent pairs in both
/// light and dark mode) — see the project's dataviz-skill palette
/// reference. Index-parallel with [`DARK`]: slot `i` is the same hue
/// stepped for each surface, not a different color.
const LIGHT: [Color32; 8] = [
    Color32::from_rgb(0x2a, 0x78, 0xd6), // blue
    Color32::from_rgb(0xeb, 0x68, 0x34), // orange
    Color32::from_rgb(0x1b, 0xaf, 0x7a), // aqua
    Color32::from_rgb(0xed, 0xa1, 0x00), // yellow
    Color32::from_rgb(0xe8, 0x7b, 0xa4), // magenta
    Color32::from_rgb(0x00, 0x83, 0x00), // green
    Color32::from_rgb(0x4a, 0x3a, 0xa7), // violet
    Color32::from_rgb(0xe3, 0x49, 0x48), // red
];

const DARK: [Color32; 8] = [
    Color32::from_rgb(0x39, 0x87, 0xe5),
    Color32::from_rgb(0xd9, 0x59, 0x26),
    Color32::from_rgb(0x19, 0x9e, 0x70),
    Color32::from_rgb(0xc9, 0x85, 0x00),
    Color32::from_rgb(0xd5, 0x51, 0x81),
    Color32::from_rgb(0x00, 0x83, 0x00),
    Color32::from_rgb(0x90, 0x85, 0xe9),
    Color32::from_rgb(0xe6, 0x67, 0x67),
];

/// Deterministically picks one of the 8 categorical slots for `value` —
/// the same level/tag string always gets the same color, this session and
/// every future one, without tracking assignment order (which would drift
/// with load order and violate the forensic determinism principle: same
/// input, same result, always). Unlike a chart legend, level and tag
/// values here are open-ended (AUL `LogType` names, analyst-authored tag
/// names from `rules/examples/*.toml`), not a fixed ≤8-series set — the
/// text label is always shown alongside the color, so a hash collision
/// past 8 distinct values costs a shared hue, not a lost identity.
pub fn categorical_color(value: &str, dark_mode: bool) -> Color32 {
    let palette = if dark_mode { &DARK } else { &LIGHT };
    palette[(fnv1a(value) % palette.len() as u64) as usize]
}

/// FNV-1a: fixed and simple, unlike `std::collections::hash_map::
/// DefaultHasher`, which makes no cross-version/cross-build stability
/// guarantee and would silently reshuffle every color between otherwise
/// identical runs.
fn fnv1a(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_u32(color: Color32) -> u32 {
        u32::from_be_bytes([color.r(), color.g(), color.b(), color.a()])
    }

    #[test]
    fn same_value_always_gets_the_same_color() {
        assert_eq!(
            categorical_color("wifi_status", false),
            categorical_color("wifi_status", false)
        );
    }

    #[test]
    fn light_and_dark_variants_differ() {
        let value = "screen_lock_state";
        assert_ne!(
            categorical_color(value, false),
            categorical_color(value, true)
        );
    }

    #[test]
    fn palette_has_eight_distinct_slots_per_mode() {
        let unique_light: std::collections::HashSet<u32> =
            LIGHT.iter().copied().map(as_u32).collect();
        let unique_dark: std::collections::HashSet<u32> =
            DARK.iter().copied().map(as_u32).collect();
        assert_eq!(unique_light.len(), 8);
        assert_eq!(unique_dark.len(), 8);
    }
}
