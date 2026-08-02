//! Window chrome theming. [`crate::config::Theme`] is the persisted,
//! toolkit-agnostic choice; this module is the only place that turns it
//! into actual `egui::Visuals`.

use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, Stroke};

use crate::config::Theme;

/// Applies `theme` to the running app. Idempotent — safe to call every time
/// the analyst picks a theme, and once on startup with the persisted value.
/// For [`Theme::Rainbow`] this only paints the hue-0 starting frame — the
/// actual animation is driven every frame by [`tick`], since a `Visuals`
/// snapshot can't animate on its own.
pub fn apply(ctx: &egui::Context, theme: Theme) {
    match theme {
        Theme::System => ctx.set_theme(egui::ThemePreference::System),
        Theme::Light => ctx.set_visuals(egui::Visuals::light()),
        Theme::Dark => ctx.set_visuals(egui::Visuals::dark()),
        Theme::Geek => ctx.set_visuals(geek_visuals()),
        Theme::Rainbow => ctx.set_visuals(rainbow_visuals(0.0)),
    }
}

/// Full hue cycle every 12.5s — matches crush's `_step_rainbow`, which
/// advances the hue by `0.004` every `50`ms (`0.004 / 0.05 = 0.08`/s).
const RAINBOW_HUE_PER_SECOND: f32 = 0.08;

/// Advances the [`Theme::Rainbow`] animation and keeps it repainting on its
/// own, independent of user interaction — must be called once per frame
/// regardless of the current theme; it's a cheap no-op (and clears
/// `rainbow_start`, so a later switch back to Rainbow restarts the cycle
/// rather than resuming mid-hue) whenever `theme` isn't `Rainbow`.
///
/// Driven off wall-clock elapsed time rather than a fixed step per call:
/// unlike crush's `QTimer` (a guaranteed 50ms interval), egui only repaints
/// on demand, so tying the hue to "how many frames happened" would make the
/// animation speed track frame rate instead of real time.
pub fn tick(ctx: &egui::Context, theme: Theme, rainbow_start: &mut Option<Instant>) {
    if theme != Theme::Rainbow {
        *rainbow_start = None;
        return;
    }
    let start = *rainbow_start.get_or_insert_with(Instant::now);
    let hue = (start.elapsed().as_secs_f32() * RAINBOW_HUE_PER_SECOND).rem_euclid(1.0);
    ctx.set_visuals(rainbow_visuals(hue));
    // Same cadence as crush's QTimer(50) — frequent enough to read as a
    // smooth animation, not so frequent it noticeably burns CPU while idle.
    ctx.request_repaint_after(Duration::from_millis(50));
}

/// Ported from crush's `_rainbow_palette(hue)` — same HSV formula and role
/// mapping, so the two tools' Rainbow themes are the same colors at the
/// same hue, not just the same idea.
fn rainbow_visuals(hue: f32) -> egui::Visuals {
    let text = hsv_to_color32(hue, 0.85, 1.0);
    let dim = hsv_to_color32(hue + 0.05, 0.6, 0.55);
    let bg = hsv_to_color32(hue, 0.25, 0.09);
    let base = hsv_to_color32(hue, 0.18, 0.06);
    let button = hsv_to_color32(hue, 0.20, 0.11);
    let alt_base = hsv_to_color32(hue, 0.2, 0.10);
    let highlight = hsv_to_color32(hue + 0.5, 0.9, 0.95);
    let bright = hsv_to_color32(hue + 0.08, 1.0, 1.0);

    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(text);
    visuals.hyperlink_color = bright;
    visuals.faint_bg_color = alt_base;
    visuals.extreme_bg_color = base;
    visuals.code_bg_color = button;
    visuals.window_fill = bg;
    visuals.panel_fill = bg;
    visuals.selection.bg_fill = highlight;
    visuals.selection.stroke = Stroke::new(1.0, base);

    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.bg_fill = button;
        widget.weak_bg_fill = button;
        widget.fg_stroke = Stroke::new(1.0, text);
        widget.bg_stroke = Stroke::new(1.0, dim);
    }
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, bright);
    visuals.widgets.active.fg_stroke = Stroke::new(1.5, bright);

    visuals
}

/// `h` in any range (wrapped mod 1.0 — callers pass `hue + 0.05`-style
/// offsets that can exceed `1.0`), `s`/`v` in `[0, 1]`. Not sourced from
/// `egui`/`ecolor`'s own `Hsva` type: it exists in the `ecolor` crate but
/// isn't re-exported through `egui`, and pulling in a whole extra
/// dependency for one conversion formula isn't worth it.
fn hsv_to_color32(h: f32, s: f32, v: f32) -> Color32 {
    let h = h.rem_euclid(1.0) * 6.0;
    let i = h.floor() as i32;
    let f = h - h.floor();
    let p = v * (1.0 - s);
    let q = v * (1.0 - s * f);
    let t = v * (1.0 - s * (1.0 - f));
    let (r, g, b) = match i.rem_euclid(6) {
        0 => (v, t, p),
        1 => (q, v, p),
        2 => (p, v, t),
        3 => (p, q, v),
        4 => (t, p, v),
        _ => (v, p, q),
    };
    Color32::from_rgb(
        (r * 255.0).round() as u8,
        (g * 255.0).round() as u8,
        (b * 255.0).round() as u8,
    )
}

/// Phosphor-green terminal look. Ported from crush's `_geek_palette()`
/// (`crush/ui/main_window.py`) so the two tools' "Geek" mode share the same
/// RGB values rather than just the same idea.
fn geek_visuals() -> egui::Visuals {
    let text = Color32::from_rgb(0, 204, 68);
    let dim = Color32::from_rgb(0, 140, 46);
    let bg = Color32::from_rgb(8, 16, 8);
    let base = Color32::from_rgb(4, 10, 4);
    let button = Color32::from_rgb(10, 22, 10);
    let highlight = Color32::from_rgb(0, 180, 60);
    let bright = Color32::from_rgb(0, 255, 100);

    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(text);
    visuals.hyperlink_color = bright;
    visuals.faint_bg_color = button;
    visuals.extreme_bg_color = base;
    visuals.code_bg_color = button;
    visuals.window_fill = bg;
    visuals.panel_fill = bg;
    visuals.selection.bg_fill = highlight;
    visuals.selection.stroke = Stroke::new(1.0, base);

    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.bg_fill = button;
        widget.weak_bg_fill = button;
        widget.fg_stroke = Stroke::new(1.0, text);
        widget.bg_stroke = Stroke::new(1.0, dim);
    }
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, bright);
    visuals.widgets.active.fg_stroke = Stroke::new(1.5, bright);

    visuals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geek_visuals_is_dark_and_uses_the_ported_palette() {
        let visuals = geek_visuals();
        assert!(visuals.dark_mode);
        assert_eq!(
            visuals.override_text_color,
            Some(Color32::from_rgb(0, 204, 68))
        );
        assert_eq!(visuals.panel_fill, Color32::from_rgb(8, 16, 8));
    }

    #[test]
    fn hsv_to_color32_matches_known_primary_colors() {
        // Pure red/green/blue at full saturation/value — the textbook
        // check for an HSV conversion.
        assert_eq!(hsv_to_color32(0.0, 1.0, 1.0), Color32::from_rgb(255, 0, 0));
        assert_eq!(
            hsv_to_color32(1.0 / 3.0, 1.0, 1.0),
            Color32::from_rgb(0, 255, 0)
        );
        assert_eq!(
            hsv_to_color32(2.0 / 3.0, 1.0, 1.0),
            Color32::from_rgb(0, 0, 255)
        );
    }

    #[test]
    fn hsv_to_color32_wraps_hues_outside_zero_to_one() {
        // `rainbow_visuals` passes offsets like `hue + 0.5` that can exceed
        // 1.0 — must wrap, not panic or clamp to a wrong color.
        assert_eq!(hsv_to_color32(1.0, 1.0, 1.0), hsv_to_color32(0.0, 1.0, 1.0));
        assert_eq!(
            hsv_to_color32(1.25, 1.0, 1.0),
            hsv_to_color32(0.25, 1.0, 1.0)
        );
    }

    #[test]
    fn rainbow_visuals_is_dark_and_shifts_with_hue() {
        let at_zero = rainbow_visuals(0.0);
        let at_third = rainbow_visuals(1.0 / 3.0);
        assert!(at_zero.dark_mode);
        assert_ne!(at_zero.panel_fill, at_third.panel_fill);
    }

    #[test]
    fn tick_leaves_rainbow_start_unset_for_a_non_rainbow_theme() {
        let ctx = egui::Context::default();
        let mut start = None;
        tick(&ctx, Theme::Dark, &mut start);
        assert!(start.is_none());
    }

    #[test]
    fn tick_starts_and_keeps_a_stable_clock_for_the_rainbow_theme() {
        let ctx = egui::Context::default();
        let mut start = None;
        tick(&ctx, Theme::Rainbow, &mut start);
        let first_start = start.expect("tick must set a start instant for Rainbow");
        tick(&ctx, Theme::Rainbow, &mut start);
        // Same instant reused across frames — the hue must progress from a
        // stable start, not reset (and jump back to hue 0) on every frame.
        assert_eq!(start, Some(first_start));
    }
}
