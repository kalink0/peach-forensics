//! Menu locations as other UI text names them ("File → Rule packs..."),
//! assembled from the same translated labels the menus themselves show, so
//! a pointer to a menu entry always matches what the analyst sees there.

fn join(items: &[String]) -> String {
    items.join(" \u{2192} ")
}

pub fn rule_packs() -> String {
    join(&[crate::fl!("menu-file"), crate::fl!("menu-rule-packs")])
}

pub fn rainbow_theme() -> String {
    join(&[
        crate::fl!("menu-view"),
        crate::fl!("menu-theme"),
        crate::fl!("theme-rainbow"),
    ])
}

pub fn sessions_dir_setting() -> String {
    join(&[
        crate::fl!("settings-title"),
        crate::fl!("settings-sessions-dir-name"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_menu_paths_read_as_the_menus_do() {
        assert_eq!(rule_packs(), "File \u{2192} Rule packs...");
        assert_eq!(rainbow_theme(), "View \u{2192} Theme \u{2192} Rainbow");
        assert_eq!(
            sessions_dir_setting(),
            "Settings \u{2192} Sessions directory"
        );
    }
}
