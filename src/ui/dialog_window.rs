//! Shared plumbing for showing a dialog as an `egui::Window` confined to
//! the main application window.
//!
//! This used to spawn a real, independently draggable native OS window per
//! dialog via [`egui::Context::show_viewport_immediate`] (egui's
//! multi-viewport support) — see git history around 2026-08-16 for that
//! version. **Reverted 2026-08-24**: on at least one real Wayland
//! desktop, opening *any* dialog (reproduced down to `About`, the
//! simplest one — static text, no live state, no `request_repaint`
//! anywhere near it) put the whole process into a continuous, growing CPU
//! spin, and the OS window's own close (X) button would sometimes stop
//! responding until the *main* window was refocused first — consistent
//! with egui's own documented cost of immediate viewports ("whenever the
//! parent viewport needs to be repainted, so will the child, and vice
//! versa... N viewports is potentially N times as much CPU work") compounded
//! by several open upstream `emilk/egui` issues about viewport repaint
//! scheduling specifically on Wayland. A forensic tool that can hang the
//! moment an analyst opens *any* dialog is not "fully operable" regardless
//! of how it got there, so this reverts to the always-worked-before
//! embedded-window approach rather than chasing an unconfirmed upstream
//! fix under release pressure. `egui::Context::show_viewport_deferred`
//! (independent per-viewport repaint cycles, no N-times coupling) is
//! egui's own recommended alternative and the likely real fix, but it
//! requires `Fn + Send + Sync + 'static` content instead of this app's
//! current direct-closure-borrows-app-state shape at every call site —
//! a real, scoped follow-up, not a same-day swap.
//!
//! [`show_dialog_window`] stays the one place every dialog in this app
//! talks to for its window chrome, so a future migration (back to
//! viewports, or to `show_viewport_deferred`) only has to change this one
//! function's insides again, not each of the 12+ call sites.

use eframe::egui;

/// Shows `content` inside an `egui::Window` titled `title`, sized
/// `default_size`. `id_source` must be a name unique to this dialog (and
/// stable across frames — it's what tells egui "this is the same window as
/// last frame," not a fresh one); used as the window's [`egui::Id`] rather
/// than relying on `title` for identity, so two dialogs could in principle
/// share a title without colliding.
///
/// `content` receives the window's content `Ui` and a `&mut bool` to set
/// when the analyst wants the dialog closed — the same "the content
/// closure sets a local `close` flag, the caller acts on it after" shape
/// this function has always presented, so no call site needs to change.
/// The window's own title-bar close (X) button sets that same flag
/// automatically, via `egui::Window::open`'s standard behaviour — the
/// analyst doesn't have to find an in-content "Close" button specifically
/// to get rid of the dialog.
///
/// Call this every frame the dialog should stay open — typically from
/// inside `if self.is_open() { ... }`.
pub fn show_dialog_window(
    ctx: &egui::Context,
    id_source: &str,
    title: &str,
    default_size: [f32; 2],
    resizable: bool,
    mut content: impl FnMut(&mut egui::Ui, &mut bool),
) -> bool {
    let mut close = false;
    let mut open = true;
    egui::Window::new(title)
        .id(egui::Id::new(id_source))
        .default_size(default_size)
        .resizable(resizable)
        .collapsible(false)
        .open(&mut open)
        .show(ctx, |ui| {
            content(ui, &mut close);
        });
    close || !open
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `show_dialog_window` inside a single headless `egui::Context`
    /// pass (no native backend needed — same "immediate mode without a
    /// window" pattern egui's own tests use) and returns whatever it
    /// returned, so each test below can assert the close-flag contract in
    /// isolation.
    fn run_once(mut body: impl FnMut(&egui::Context) -> bool) -> bool {
        let ctx = egui::Context::default();
        let mut result = false;
        let _ = ctx.run_ui(egui::RawInput::default(), |ui| {
            result = body(ui.ctx());
        });
        result
    }

    #[test]
    fn stays_open_and_reports_not_closed_when_content_never_sets_close() {
        let closed = run_once(|ctx| {
            show_dialog_window(
                ctx,
                "test_dialog_a",
                "Test",
                [200.0, 100.0],
                true,
                |_, _| {},
            )
        });
        assert!(!closed);
    }

    #[test]
    fn content_setting_close_is_reported_back_to_the_caller() {
        let closed = run_once(|ctx| {
            show_dialog_window(
                ctx,
                "test_dialog_b",
                "Test",
                [200.0, 100.0],
                true,
                |_, close| *close = true,
            )
        });
        assert!(closed);
    }
}
