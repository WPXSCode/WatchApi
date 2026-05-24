#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::sync::Arc;

#[cfg(windows)]
use raw_window_handle::{HasWindowHandle, RawWindowHandle};

mod app;
mod gui_support;
mod litellm_proxy;
mod tray;

fn main() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("WatchApi Rust")
        .with_inner_size([1280.0, 860.0])
        .with_min_inner_size([920.0, 620.0]);
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
        }
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
