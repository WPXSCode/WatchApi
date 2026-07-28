#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#![recursion_limit = "256"]

use std::sync::Arc;

#[cfg(windows)]
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
#[cfg(windows)]
use std::sync::atomic::{AtomicIsize, Ordering};
#[cfg(windows)]
use windows_sys::Win32::Foundation::HWND;
#[cfg(windows)]
use windows_sys::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMSBT_NONE, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR,
    DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
};

mod app;
mod gui_support;
mod litellm_proxy;
mod tray;

#[cfg(windows)]
static MAIN_WINDOW_HANDLE: AtomicIsize = AtomicIsize::new(0);

fn main() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("WatchApi Rust")
        .with_inner_size([1280.0, 860.0])
        .with_min_inner_size([920.0, 620.0])
        .with_drag_and_drop(true);
    if let Some(icon) = load_window_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let config_path = std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|pair| pair[0] == "--config")
        .map(|pair| pair[1].clone());
    eframe::run_native(
        "WatchApi Rust",
        options,
        Box::new(move |cc| {
            configure_chinese_fonts(&cc.egui_ctx);
            register_main_window_handle(cc);
            Ok(Box::new(app::WatchApiApp::new(config_path.clone())))
        }),
    )
}

fn register_main_window_handle(cc: &eframe::CreationContext<'_>) {
    #[cfg(windows)]
    if let Ok(handle) = cc.window_handle() {
        if let RawWindowHandle::Win32(handle) = handle.as_raw() {
            tray::set_main_window_handle(handle.hwnd.get());
            MAIN_WINDOW_HANDLE.store(handle.hwnd.get(), Ordering::Relaxed);
            apply_native_window_theme(gui_support::GuiTheme::Dark);
        }
    }
}

#[cfg(windows)]
fn apply_window_decorations(hwnd: isize, theme: gui_support::GuiTheme) {
    let dark_mode: i32 = i32::from(theme == gui_support::GuiTheme::Dark);
    set_dwm_window_attribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark_mode);

    let (caption, text) = match theme {
        gui_support::GuiTheme::Dark => {
            (github_colorref(13, 17, 23), github_colorref(230, 237, 243))
        }
        gui_support::GuiTheme::Light => {
            (github_colorref(246, 248, 250), github_colorref(31, 35, 40))
        }
    };
    set_dwm_window_attribute(hwnd, DWMWA_CAPTION_COLOR, &caption);
    set_dwm_window_attribute(hwnd, DWMWA_BORDER_COLOR, &caption);
    set_dwm_window_attribute(hwnd, DWMWA_TEXT_COLOR, &text);

    let backdrop = DWMSBT_NONE;
    set_dwm_window_attribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &backdrop);
}

#[cfg(windows)]
fn github_colorref(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

pub(crate) fn apply_native_window_theme(theme: gui_support::GuiTheme) {
    #[cfg(windows)]
    {
        let hwnd = MAIN_WINDOW_HANDLE.load(Ordering::Relaxed);
        if hwnd != 0 {
            apply_window_decorations(hwnd, theme);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = theme;
    }
}

#[cfg(windows)]
fn set_dwm_window_attribute<T>(hwnd: isize, attribute: i32, value: &T) {
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd as HWND,
            attribute as u32,
            value as *const T as *const core::ffi::c_void,
            std::mem::size_of::<T>() as u32,
        );
    }
}

fn configure_chinese_fonts(ctx: &egui::Context) {
    let cjk_font = load_first_existing_font(&[
        r"C:\Windows\Fonts\NotoSansSC-VF.ttf",
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
        r"C:\Windows\Fonts\Deng.ttf",
    ]);
    let terminal_font = load_first_existing_font(&[
        r"C:\Windows\Fonts\CascadiaMono.ttf",
        r"C:\Windows\Fonts\CascadiaCode.ttf",
        r"C:\Windows\Fonts\DejaVuSansMono_0.ttf",
        r"C:\Windows\Fonts\consola.ttf",
    ]);
    let mut fonts = egui::FontDefinitions::default();
    if let Some(font_bytes) = cjk_font {
        fonts.font_data.insert(
            "watchapi_cjk".to_string(),
            Arc::new(egui::FontData::from_owned(font_bytes)),
        );
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "watchapi_cjk".to_string());
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .push("watchapi_cjk".to_string());
    }
    if let Some(font_bytes) = terminal_font {
        fonts.font_data.insert(
            "watchapi_terminal".to_string(),
            Arc::new(egui::FontData::from_owned(font_bytes)),
        );
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .insert(0, "watchapi_terminal".to_string());
    }
    ctx.set_fonts(fonts);
}

fn load_first_existing_font(paths: &[&str]) -> Option<Vec<u8>> {
    paths.iter().find_map(|path| std::fs::read(path).ok())
}

fn load_window_icon() -> Option<Arc<egui::IconData>> {
    let icon_path = app_root().join("assets").join("watchapi.png");
    let image = image::ImageReader::open(icon_path)
        .ok()?
        .decode()
        .ok()?
        .into_rgba8();
    let (width, height) = image.dimensions();
    Some(Arc::new(egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }))
}

fn app_root() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn main_window_handle_applies_selected_native_theme_decorations() {
        let source = include_str!("main.rs");
        let register_block = source
            .split("fn register_main_window_handle")
            .nth(1)
            .and_then(|tail| tail.split("fn configure_chinese_fonts").next())
            .expect("main window handle registration block should be discoverable");

        assert!(
            register_block.contains("apply_native_window_theme(gui_support::GuiTheme::Dark);"),
            "Windows native title bar and resize border must be initialized after the HWND is available"
        );
        assert!(source.contains("pub(crate) fn apply_native_window_theme"));
        assert!(source.contains("gui_support::GuiTheme::Light"));
        assert!(source.contains("DWMWA_USE_IMMERSIVE_DARK_MODE"));
        assert!(source.contains("DWMWA_CAPTION_COLOR"));
        assert!(source.contains("DWMWA_BORDER_COLOR"));
        assert!(source.contains("DWMWA_SYSTEMBACKDROP_TYPE"));
    }
}
