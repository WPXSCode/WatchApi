use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Mutex, Once};

#[cfg(windows)]
use windows_sys::Win32::Foundation::HWND;
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, IsWindow, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
};

const RESTORE_ID: &str = "watchapi_restore";
const EXIT_ID: &str = "watchapi_exit";
const EMBEDDED_ICON_PNG: &[u8] = include_bytes!("../assets/watchapi.png");
static INSTALL_HANDLERS_ONCE: Once = Once::new();
static ACTION_QUEUE: Mutex<VecDeque<TrayAction>> = Mutex::new(VecDeque::new());
#[cfg(windows)]
static MAIN_WINDOW_HWND: Mutex<Option<isize>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Restore,
    Exit,
}

#[cfg(windows)]
pub fn set_main_window_handle(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    if let Ok(mut stored) = MAIN_WINDOW_HWND.lock() {
        *stored = Some(hwnd);
    }
}

#[cfg(windows)]
fn restore_native_main_window() {
    let hwnd = MAIN_WINDOW_HWND.lock().ok().and_then(|stored| *stored);
    let Some(hwnd) = hwnd else {
        return;
    };
    let hwnd = hwnd as HWND;
    unsafe {
        if IsWindow(hwnd) == 0 {
            return;
        }
        ShowWindow(hwnd, SW_SHOW);
        ShowWindow(hwnd, SW_RESTORE);
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd);
    }
}

#[cfg(not(windows))]
fn restore_native_main_window() {}

pub struct WatchApiTray {
    #[cfg(not(target_os = "linux"))]
    icon: tray_icon::TrayIcon,
    last_status: Mutex<Option<(usize, usize)>>,
    #[cfg(not(target_os = "linux"))]
    restore_id: tray_icon::menu::MenuId,
    #[cfg(not(target_os = "linux"))]
    exit_id: tray_icon::menu::MenuId,
}

impl WatchApiTray {
    #[cfg(not(target_os = "linux"))]
    pub fn create(running_count: usize, error_count: usize) -> Result<Self, String> {
        use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
        use tray_icon::TrayIconBuilder;

        let restore = MenuItem::with_id(RESTORE_ID, "显示 WatchApi", true, None);
        let exit = MenuItem::with_id(EXIT_ID, "退出 WatchApi", true, None);
        let menu = Menu::new();
        menu.append(&MenuItem::new(
            crate::gui_support::tray_status_label(running_count, error_count),
            false,
            None,
        ))
        .map_err(|err| err.to_string())?;
        menu.append(&PredefinedMenuItem::separator())
            .map_err(|err| err.to_string())?;
        menu.append(&restore).map_err(|err| err.to_string())?;
        menu.append(&exit).map_err(|err| err.to_string())?;

        let mut builder = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("WatchApi")
            .with_menu_on_left_click(false)
            .with_menu_on_right_click(true);
        if let Some(icon) = load_icon() {
            builder = builder.with_icon(icon);
        }
        let icon = builder.build().map_err(|err| err.to_string())?;
        Ok(Self {
            icon,
            last_status: Mutex::new(Some((running_count, error_count))),
            restore_id: restore.id().clone(),
            exit_id: exit.id().clone(),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn create(_running_count: usize, _error_count: usize) -> Result<Self, String> {
        Err("Linux 托盘依赖系统 libappindicator/gtk，当前构建禁用。".to_string())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn poll_action(&self) -> Option<TrayAction> {
        use tray_icon::menu::MenuEvent;
        use tray_icon::{MouseButton, TrayIconEvent};

        if let Some(action) = pop_queued_action() {
            return Some(action);
        }
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.restore_id {
                return Some(TrayAction::Restore);
            }
            if event.id == self.exit_id {
                return Some(TrayAction::Exit);
            }
        }
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if matches!(
                event,
                TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }
            ) {
                return Some(TrayAction::Restore);
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    pub fn poll_action(&self) -> Option<TrayAction> {
        None
    }

    #[cfg(not(target_os = "linux"))]
    pub fn update_status(&self, running_count: usize, error_count: usize) {
        if !record_status_change(&self.last_status, running_count, error_count) {
            return;
        }
        let _ = self.icon.set_tooltip(Some(format!(
            "WatchApi | {}",
            crate::gui_support::tray_status_label(running_count, error_count)
        )));
    }

    #[cfg(target_os = "linux")]
    pub fn update_status(&self, _running_count: usize, _error_count: usize) {}
}

pub fn install_event_wakeup(ctx: egui::Context) {
    INSTALL_HANDLERS_ONCE.call_once(move || {
        let menu_ctx = ctx.clone();
        tray_icon::menu::MenuEvent::set_event_handler(Some(
            move |event: tray_icon::menu::MenuEvent| {
                if event.id.0 == RESTORE_ID {
                    push_queued_action(TrayAction::Restore);
                    restore_native_main_window();
                    menu_ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    menu_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    menu_ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    menu_ctx.request_repaint();
                } else if event.id.0 == EXIT_ID {
                    push_queued_action(TrayAction::Exit);
                    restore_native_main_window();
                    menu_ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    menu_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    menu_ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    menu_ctx.request_repaint();
                }
            },
        ));

        let tray_ctx = ctx;
        tray_icon::TrayIconEvent::set_event_handler(Some(
            move |event: tray_icon::TrayIconEvent| {
                if matches!(
                    event,
                    tray_icon::TrayIconEvent::DoubleClick {
                        button: tray_icon::MouseButton::Left,
                        ..
                    }
                ) {
                    push_queued_action(TrayAction::Restore);
                    restore_native_main_window();
                    tray_ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    tray_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    tray_ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    tray_ctx.request_repaint();
                }
            },
        ));
    });
}

fn push_queued_action(action: TrayAction) {
    if let Ok(mut queue) = ACTION_QUEUE.lock() {
        queue.push_back(action);
    }
}

fn pop_queued_action() -> Option<TrayAction> {
    ACTION_QUEUE
        .lock()
        .ok()
        .and_then(|mut queue| queue.pop_front())
}

fn record_status_change(
    last_status: &Mutex<Option<(usize, usize)>>,
    running_count: usize,
    error_count: usize,
) -> bool {
    let Ok(mut last_status) = last_status.lock() else {
        return true;
    };
    let next_status = (running_count, error_count);
    if last_status.as_ref() == Some(&next_status) {
        return false;
    }
    *last_status = Some(next_status);
    true
}

#[cfg(not(target_os = "linux"))]
fn load_icon() -> Option<tray_icon::Icon> {
    load_embedded_icon().or_else(load_icon_from_path)
}

#[cfg(not(target_os = "linux"))]
fn load_embedded_icon() -> Option<tray_icon::Icon> {
    let image = image::load_from_memory(EMBEDDED_ICON_PNG)
        .ok()?
        .into_rgba8();
    let (width, height) = image.dimensions();
    tray_icon::Icon::from_rgba(image.into_raw(), width, height).ok()
}

#[cfg(not(target_os = "linux"))]
fn load_icon_from_path() -> Option<tray_icon::Icon> {
    for path in icon_path_candidates() {
        if let Ok(icon) = tray_icon::Icon::from_path(&path, None) {
            return Some(icon);
        }
    }
    None
}

fn icon_path() -> PathBuf {
    app_root().join("assets").join("watchapi.ico")
}

fn icon_path_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![icon_path()];
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("assets").join("watchapi.ico"));
    }
    candidates
}

fn app_root() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_actions_are_fifo() {
        while pop_queued_action().is_some() {}
        push_queued_action(TrayAction::Restore);
        push_queued_action(TrayAction::Exit);

        assert_eq!(pop_queued_action(), Some(TrayAction::Restore));
        assert_eq!(pop_queued_action(), Some(TrayAction::Exit));
        assert_eq!(pop_queued_action(), None);
    }

    #[test]
    fn tray_wakeup_restores_hidden_viewport_before_queue_consumption() {
        let source = include_str!("tray.rs");
        let wakeup_block = source
            .split("pub fn install_event_wakeup")
            .nth(1)
            .and_then(|tail| tail.split("fn push_queued_action").next())
            .expect("tray wakeup block should be discoverable");

        assert!(wakeup_block.contains("ViewportCommand::Visible(true)"));
        assert!(wakeup_block.contains("ViewportCommand::Minimized(false)"));
        assert!(wakeup_block.contains("ViewportCommand::Focus"));
        assert!(wakeup_block.contains("request_repaint()"));
    }

    #[test]
    fn tray_wakeup_uses_native_restore_for_hidden_windows() {
        let source = include_str!("tray.rs");
        let wakeup_block = source
            .split("pub fn install_event_wakeup")
            .nth(1)
            .and_then(|tail| tail.split("fn push_queued_action").next())
            .expect("tray wakeup block should be discoverable");

        assert!(source.contains("fn restore_native_main_window()"));
        assert!(source.contains("ShowWindow(hwnd, SW_SHOW)"));
        assert!(source.contains("ShowWindow(hwnd, SW_RESTORE)"));
        assert!(source.contains("SetForegroundWindow(hwnd)"));
        assert!(
            wakeup_block
                .matches("restore_native_main_window();")
                .count()
                >= 3,
            "托盘显示、退出和双击都必须先原生恢复窗口，不能只依赖隐藏窗口后的 egui repaint"
        );
    }

    #[test]
    fn tray_status_updates_are_deduplicated() {
        let last_status = Mutex::new(Some((2, 1)));

        assert!(!record_status_change(&last_status, 2, 1));
        assert!(!record_status_change(&last_status, 2, 1));
        assert!(record_status_change(&last_status, 3, 1));
        assert!(!record_status_change(&last_status, 3, 1));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn embedded_tray_icon_is_loadable() {
        assert!(load_embedded_icon().is_some());
    }
}
