//! Shared plumbing for showing a dialog as its own real, native OS window
//! rather than an `egui::Window` confined to the main application window.
//!
//! A plain `egui::Window` (what every dialog in this app used) is drawn
//! *inside* the same OS-level window the main timeline lives in — no
//! amount of drag distance lets it cross that window's own edge, since the
//! pixels simply don't exist outside it. The only way to get a genuinely,
//! freely movable window (draggable onto another monitor, etc.) is egui's
//! multi-viewport support: [`egui::Context::show_viewport_immediate`]
//! spawns a real native window via the backend (`eframe`'s native
//! integration enables this automatically on Linux/macOS/Windows — see
//! `eframe::native::winit_integration::create_egui_context`'s
//! `set_embed_viewports(!IS_DESKTOP)` — no extra configuration needed on
//! Peach's actual target platforms).
//!
//! [`show_dialog_window`] is the one place this app talks to that API, so
//! every dialog gets the same window chrome/close-detection instead of
//! each reimplementing it slightly differently.

use eframe::egui;

/// Shows `content` inside its own native window titled `title`, sized
/// `default_size`. `viewport_id_source` must be a name unique to this
/// dialog (and stable across frames — it's what tells egui "this is the
/// same window as last frame," not a fresh one) — [`egui::ViewportId::from_hash_of`]
/// turns it into the real ID.
///
/// `content` receives the window's content `Ui` (already wrapped in a
/// [`egui::CentralPanel`], matching the opaque, themed background an
/// `egui::Window`'s own frame used to provide) and a `&mut bool` to set
/// when the analyst wants the dialog closed — same "the content closure
/// sets a local `close` flag, the caller acts on it after" shape every
/// dialog already used with `egui::Window`, so converting one over is a
/// matter of swapping which function wraps the closure, not restructuring
/// the closure itself. The OS window's own close button (the taskbar/title
/// bar X) sets that same flag automatically, via
/// [`egui::ViewportInfo::close_requested`] — the analyst doesn't have to
/// find an in-app "Close" button specifically to get rid of the window.
///
/// Call this every frame the dialog should stay open (the same "you need
/// to call this each pass" contract `show_viewport_immediate` itself
/// documents) — typically from inside `if self.is_open() { ... }`, exactly
/// like the `egui::Window` version was always called from inside that same
/// guard.
pub fn show_dialog_window(
    ctx: &egui::Context,
    viewport_id_source: &str,
    title: &str,
    default_size: [f32; 2],
    resizable: bool,
    mut content: impl FnMut(&mut egui::Ui, &mut bool),
) -> bool {
    let viewport_id = egui::ViewportId::from_hash_of(viewport_id_source);
    let mut close = false;
    ctx.show_viewport_immediate(
        viewport_id,
        egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(default_size)
            .with_resizable(resizable),
        |ui, _class| {
            egui::CentralPanel::default().show(ui, |ui| {
                content(ui, &mut close);
            });
            if ui.ctx().input(|i| i.viewport().close_requested()) {
                close = true;
            }
        },
    );
    close
}
