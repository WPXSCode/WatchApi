use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor, Processor, Rgb};
use parking_lot::Mutex;
use std::sync::Arc;

const MAX_SCROLLBACK_LINES: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalRgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalCellView {
    pub c: char,
    pub fg: TerminalRgb,
    pub bg: TerminalRgb,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikeout: bool,
    pub inverse: bool,
    pub hidden: bool,
    pub wide: bool,
    pub wide_spacer: bool,
    pub wrapline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalView {
    pub revision: u64,
    pub rows: usize,
    pub cols: usize,
    pub scrollback_lines: usize,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub cursor_shape: TerminalCursorShape,
    pub display_offset: usize,
    pub modes: TerminalModeView,
    pub cells: Vec<TerminalCellView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TerminalCursorShape {
    #[default]
    Block,
    Underline,
    Beam,
    HollowBlock,
    Hidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TerminalModeView {
    pub bracketed_paste: bool,
    pub alt_screen: bool,
    pub alternate_scroll: bool,
    pub app_cursor: bool,
    pub sgr_mouse: bool,
    pub mouse_reporting: bool,
    pub mouse_report_click: bool,
    pub mouse_drag: bool,
    pub mouse_motion: bool,
    pub focus_in_out: bool,
}

pub struct TerminalEmulator {
    term: Term<TerminalEventSink>,
    processor: Processor,
    pty_writes: Arc<Mutex<Vec<String>>>,
    revision: u64,
}

#[derive(Debug, Clone, Copy)]
struct TerminalSize {
    rows: usize,
    cols: usize,
}

impl Dimensions for TerminalSize {
    fn total_lines(&self) -> usize {
        self.screen_lines()
    }

    fn screen_lines(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.cols
    }
}

impl TerminalEmulator {
    pub fn new(rows: usize, cols: usize) -> Self {
        let size = TerminalSize {
            rows: rows.max(1),
            cols: cols.max(2),
        };
        let pty_writes = Arc::new(Mutex::new(Vec::new()));
        let event_sink = TerminalEventSink {
            pty_writes: Arc::clone(&pty_writes),
        };
        let config = Config {
            scrolling_history: MAX_SCROLLBACK_LINES,
            ..Config::default()
        };
        Self {
            term: Term::new(config, &size, event_sink),
            processor: Processor::new(),
            pty_writes,
            revision: 1,
        }
    }

    pub fn resize(&mut self, rows: usize, cols: usize) {
        let size = TerminalSize {
            rows: rows.max(1),
            cols: cols.max(2),
        };
        self.term.resize(size);
        self.bump_revision();
    }

    pub fn advance(&mut self, bytes: &[u8]) -> Vec<String> {
        if bytes.is_empty() {
            return self.drain_pty_writes();
        }
        self.processor.advance(&mut self.term, bytes);
        self.bump_revision();
        self.drain_pty_writes()
    }

    pub fn clear_screen_and_scrollback(&mut self) {
        self.term.scroll_display(Scroll::Bottom);
        self.processor
            .advance(&mut self.term, b"\x1b[2J\x1b[3J\x1b[H");
        self.bump_revision();
        let _ = self.drain_pty_writes();
    }

    pub fn scroll_display(&mut self, delta: i32) {
        if delta == 0 {
            return;
        }
        let before = self.term.grid().display_offset();
        let max_offset = self.max_display_offset();
        let target = (before as i64 + delta as i64).clamp(0, max_offset as i64) as usize;
        if target == before {
            return;
        }
        let safe_delta = target as i32 - before as i32;
        self.term.scroll_display(Scroll::Delta(safe_delta));
        self.bump_revision_if_display_offset_changed(before);
    }

    pub fn scroll_bottom(&mut self) {
        let before = self.term.grid().display_offset();
        self.term.scroll_display(Scroll::Bottom);
        self.bump_revision_if_display_offset_changed(before);
    }

    pub fn scroll_to_offset(&mut self, offset: usize) {
        let current = self.term.grid().display_offset();
        let target = offset.min(
            self.term
                .grid()
                .total_lines()
                .saturating_sub(self.term.screen_lines()),
        );
        let delta = target as i32 - current as i32;
        self.scroll_display(delta);
    }

    pub fn drain_pty_writes(&self) -> Vec<String> {
        std::mem::take(&mut *self.pty_writes.lock())
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn modes(&self) -> TerminalModeView {
        mode_view(*self.term.mode())
    }

    pub fn view(&self) -> TerminalView {
        let rows = self.term.screen_lines();
        let cols = self.term.columns();
        let scrollback_lines = self.term.grid().total_lines().saturating_sub(rows);
        let cursor = self.term.grid().cursor.point;
        let display_offset = self.term.grid().display_offset();
        let cursor_shape = cursor_shape_view(self.term.cursor_style().shape, *self.term.mode());
        let mut cells = Vec::with_capacity(rows * cols);
        for indexed in self.term.grid().display_iter().take(rows * cols) {
            cells.push(cell_view(indexed.cell));
        }
        while cells.len() < rows * cols {
            cells.push(cell_view(&Cell::default()));
        }

        TerminalView {
            revision: self.revision,
            rows,
            cols,
            scrollback_lines,
            cursor_row: (cursor.line.0 + display_offset as i32).max(0) as usize,
            cursor_col: cursor.column.0,
            cursor_shape,
            display_offset,
            modes: mode_view(*self.term.mode()),
            cells,
        }
    }

    fn max_display_offset(&self) -> usize {
        self.term
            .grid()
            .total_lines()
            .saturating_sub(self.term.screen_lines())
    }

    fn bump_revision_if_display_offset_changed(&mut self, before: usize) {
        if self.term.grid().display_offset() != before {
            self.bump_revision();
        }
    }

    fn bump_revision(&mut self) {
        self.revision = self.revision.wrapping_add(1).max(1);
    }
}

#[derive(Clone)]
struct TerminalEventSink {
    pty_writes: Arc<Mutex<Vec<String>>>,
}

impl EventListener for TerminalEventSink {
    fn send_event(&self, event: Event) {
        if let Event::PtyWrite(text) = event {
            self.pty_writes.lock().push(text);
        }
    }
}

fn mode_view(mode: TermMode) -> TerminalModeView {
    TerminalModeView {
        bracketed_paste: mode.contains(TermMode::BRACKETED_PASTE),
        alt_screen: mode.contains(TermMode::ALT_SCREEN),
        alternate_scroll: mode.contains(TermMode::ALTERNATE_SCROLL),
        app_cursor: mode.contains(TermMode::APP_CURSOR),
        sgr_mouse: mode.contains(TermMode::SGR_MOUSE),
        mouse_reporting: mode.intersects(TermMode::MOUSE_MODE),
        mouse_report_click: mode.contains(TermMode::MOUSE_REPORT_CLICK),
        mouse_drag: mode.contains(TermMode::MOUSE_DRAG),
        mouse_motion: mode.contains(TermMode::MOUSE_MOTION),
        focus_in_out: mode.contains(TermMode::FOCUS_IN_OUT),
    }
}

fn cursor_shape_view(shape: CursorShape, mode: TermMode) -> TerminalCursorShape {
    if !mode.contains(TermMode::SHOW_CURSOR) {
        return TerminalCursorShape::Hidden;
    }
    match shape {
        CursorShape::Block => TerminalCursorShape::Block,
        CursorShape::Underline => TerminalCursorShape::Underline,
        CursorShape::Beam => TerminalCursorShape::Beam,
        CursorShape::HollowBlock => TerminalCursorShape::HollowBlock,
        CursorShape::Hidden => TerminalCursorShape::Hidden,
    }
}

fn cell_view(cell: &Cell) -> TerminalCellView {
    let inverse = cell.flags.contains(Flags::INVERSE);
    let mut fg = color_to_rgb(cell.fg, default_foreground());
    let mut bg = color_to_rgb(cell.bg, default_background());
    let dim = cell.flags.contains(Flags::DIM);
    if dim {
        fg = dim_rgb(fg);
    }
    if inverse {
        std::mem::swap(&mut fg, &mut bg);
    }
    let wide_spacer = cell
        .flags
        .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER);
    TerminalCellView {
        c: if wide_spacer { ' ' } else { cell.c },
        fg,
        bg,
        bold: cell.flags.contains(Flags::BOLD),
        dim,
        italic: cell.flags.contains(Flags::ITALIC),
        underline: cell.flags.intersects(Flags::ALL_UNDERLINES),
        strikeout: cell.flags.contains(Flags::STRIKEOUT),
        inverse,
        hidden: cell.flags.contains(Flags::HIDDEN),
        wide: cell.flags.contains(Flags::WIDE_CHAR),
        wide_spacer,
        wrapline: cell.flags.contains(Flags::WRAPLINE),
    }
}

fn dim_rgb(rgb: TerminalRgb) -> TerminalRgb {
    TerminalRgb {
        r: ((rgb.r as u16 * 2) / 3) as u8,
        g: ((rgb.g as u16 * 2) / 3) as u8,
        b: ((rgb.b as u16 * 2) / 3) as u8,
    }
}

fn color_to_rgb(color: Color, fallback: TerminalRgb) -> TerminalRgb {
    match color {
        Color::Spec(rgb) => Some(rgb_to_view(rgb)),
        Color::Named(named) => named_color_to_rgb(named),
        Color::Indexed(index) => indexed_color_to_rgb(index),
    }
    .unwrap_or(fallback)
}

fn rgb_to_view(rgb: Rgb) -> TerminalRgb {
    TerminalRgb {
        r: rgb.r,
        g: rgb.g,
        b: rgb.b,
    }
}

fn default_foreground() -> TerminalRgb {
    TerminalRgb {
        r: 220,
        g: 226,
        b: 232,
    }
}

fn default_background() -> TerminalRgb {
    TerminalRgb { r: 0, g: 0, b: 0 }
}

fn named_color_to_rgb(color: NamedColor) -> Option<TerminalRgb> {
    Some(match color {
        NamedColor::Black => TerminalRgb { r: 0, g: 0, b: 0 },
        NamedColor::Red => TerminalRgb {
            r: 205,
            g: 49,
            b: 49,
        },
        NamedColor::Green => TerminalRgb {
            r: 13,
            g: 188,
            b: 121,
        },
        NamedColor::Yellow => TerminalRgb {
            r: 229,
            g: 229,
            b: 16,
        },
        NamedColor::Blue => TerminalRgb {
            r: 36,
            g: 114,
            b: 200,
        },
        NamedColor::Magenta => TerminalRgb {
            r: 188,
            g: 63,
            b: 188,
        },
        NamedColor::Cyan => TerminalRgb {
            r: 17,
            g: 168,
            b: 205,
        },
        NamedColor::White => TerminalRgb {
            r: 229,
            g: 229,
            b: 229,
        },
        NamedColor::BrightBlack => TerminalRgb {
            r: 102,
            g: 102,
            b: 102,
        },
        NamedColor::BrightRed => TerminalRgb {
            r: 241,
            g: 76,
            b: 76,
        },
        NamedColor::BrightGreen => TerminalRgb {
            r: 35,
            g: 209,
            b: 139,
        },
        NamedColor::BrightYellow => TerminalRgb {
            r: 245,
            g: 245,
            b: 67,
        },
        NamedColor::BrightBlue => TerminalRgb {
            r: 59,
            g: 142,
            b: 234,
        },
        NamedColor::BrightMagenta => TerminalRgb {
            r: 214,
            g: 112,
            b: 214,
        },
        NamedColor::BrightCyan => TerminalRgb {
            r: 41,
            g: 184,
            b: 219,
        },
        NamedColor::BrightWhite => TerminalRgb {
            r: 255,
            g: 255,
            b: 255,
        },
        NamedColor::Foreground | NamedColor::BrightForeground => default_foreground(),
        NamedColor::Background => default_background(),
        NamedColor::DimBlack => TerminalRgb { r: 0, g: 0, b: 0 },
        NamedColor::DimRed => TerminalRgb {
            r: 128,
            g: 31,
            b: 31,
        },
        NamedColor::DimGreen => TerminalRgb {
            r: 8,
            g: 128,
            b: 82,
        },
        NamedColor::DimYellow => TerminalRgb {
            r: 128,
            g: 128,
            b: 9,
        },
        NamedColor::DimBlue => TerminalRgb {
            r: 22,
            g: 72,
            b: 128,
        },
        NamedColor::DimMagenta => TerminalRgb {
            r: 128,
            g: 42,
            b: 128,
        },
        NamedColor::DimCyan => TerminalRgb {
            r: 12,
            g: 128,
            b: 152,
        },
        NamedColor::DimWhite => TerminalRgb {
            r: 128,
            g: 128,
            b: 128,
        },
        NamedColor::DimForeground => TerminalRgb {
            r: 128,
            g: 132,
            b: 136,
        },
        _ => return None,
    })
}

fn indexed_color_to_rgb(index: u8) -> Option<TerminalRgb> {
    if index < 16 {
        return named_color_to_rgb(match index {
            0 => NamedColor::Black,
            1 => NamedColor::Red,
            2 => NamedColor::Green,
            3 => NamedColor::Yellow,
            4 => NamedColor::Blue,
            5 => NamedColor::Magenta,
            6 => NamedColor::Cyan,
            7 => NamedColor::White,
            8 => NamedColor::BrightBlack,
            9 => NamedColor::BrightRed,
            10 => NamedColor::BrightGreen,
            11 => NamedColor::BrightYellow,
            12 => NamedColor::BrightBlue,
            13 => NamedColor::BrightMagenta,
            14 => NamedColor::BrightCyan,
            _ => NamedColor::BrightWhite,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(view: &TerminalView, row: usize) -> String {
        view.cells[row * view.cols..(row + 1) * view.cols]
            .iter()
            .map(|cell| cell.c)
            .collect::<String>()
    }

    #[test]
    fn terminal_emulator_interprets_cursor_position_and_overwrite() {
        let mut emulator = TerminalEmulator::new(3, 8);

        emulator.advance(b"hello\x1b[1;1HY");

        assert_eq!(line_text(&emulator.view(), 0), "Yello   ");
    }

    #[test]
    fn terminal_emulator_interprets_clear_screen() {
        let mut emulator = TerminalEmulator::new(2, 8);

        emulator.advance(b"old\x1b[2J\x1b[Hnew");

        assert_eq!(line_text(&emulator.view(), 0), "new     ");
        assert_eq!(line_text(&emulator.view(), 1), "        ");
    }
    #[test]
    fn terminal_emulator_updates_carriage_return_progress_in_place() {
        let mut emulator = TerminalEmulator::new(2, 20);
        let initial_revision = emulator.revision();

        emulator.advance(b"working 9s");
        let first_revision = emulator.revision();
        emulator.advance(b"\rworking 10s");
        let second_revision = emulator.revision();
        let line = line_text(&emulator.view(), 0);

        assert!(first_revision > initial_revision);
        assert!(second_revision > first_revision);
        assert!(line.starts_with("working 10s"));
        assert!(!line.starts_with("working 9s"));
    }

    #[test]
    fn terminal_emulator_local_clear_removes_screen_and_scrollback() {
        let mut emulator = TerminalEmulator::new(2, 8);

        emulator.advance(b"one\r\ntwo\r\nthree");
        emulator.scroll_display(1);
        assert!(emulator.view().scrollback_lines > 0);

        emulator.clear_screen_and_scrollback();
        let view = emulator.view();

        assert_eq!(view.scrollback_lines, 0);
        assert_eq!(view.display_offset, 0);
        assert_eq!(line_text(&view, 0), "        ");
        assert_eq!(line_text(&view, 1), "        ");
    }

    #[test]
    fn terminal_emulator_preserves_basic_ansi_color() {
        let mut emulator = TerminalEmulator::new(1, 8);

        emulator.advance(b"\x1b[31mR");
        let view = emulator.view();

        assert_eq!(view.cells[0].c, 'R');
        assert_eq!(
            view.cells[0].fg,
            TerminalRgb {
                r: 205,
                g: 49,
                b: 49
            }
        );
    }

    #[test]
    fn terminal_emulator_exposes_mouse_reporting_modes() {
        let mut emulator = TerminalEmulator::new(1, 8);

        emulator.advance(b"\x1b[?1000h\x1b[?1006h");
        let click = emulator.view().modes;

        assert!(click.mouse_reporting);
        assert!(click.mouse_report_click);
        assert!(click.sgr_mouse);
        assert!(!click.mouse_drag);
        assert!(!click.mouse_motion);

        emulator.advance(b"\x1b[?1002h");
        let drag = emulator.view().modes;

        assert!(drag.mouse_reporting);
        assert!(!drag.mouse_report_click);
        assert!(drag.mouse_drag);
        assert!(!drag.mouse_motion);

        emulator.advance(b"\x1b[?1003h");
        let motion = emulator.view().modes;

        assert!(motion.mouse_reporting);
        assert!(!motion.mouse_report_click);
        assert!(!motion.mouse_drag);
        assert!(motion.mouse_motion);
    }

    #[test]
    fn terminal_emulator_exposes_focus_reporting_mode() {
        let mut emulator = TerminalEmulator::new(1, 8);

        emulator.advance(b"\x1b[?1004h");
        assert!(emulator.view().modes.focus_in_out);

        emulator.advance(b"\x1b[?1004l");
        assert!(!emulator.view().modes.focus_in_out);
    }

    #[test]
    fn terminal_emulator_scroll_noops_do_not_bump_revision() {
        let mut emulator = TerminalEmulator::new(2, 8);
        let initial_revision = emulator.revision();

        emulator.scroll_display(1);
        emulator.scroll_bottom();

        assert_eq!(emulator.revision(), initial_revision);

        emulator.advance(b"one\r\ntwo\r\nthree");
        let output_revision = emulator.revision();
        assert_eq!(emulator.view().display_offset, 0);

        emulator.scroll_bottom();
        emulator.scroll_to_offset(0);

        assert_eq!(emulator.revision(), output_revision);

        emulator.scroll_display(1);
        let scrolled_revision = emulator.revision();
        let scrolled_offset = emulator.view().display_offset;
        assert!(scrolled_revision > output_revision);
        assert!(scrolled_offset > 0);

        emulator.scroll_display(i32::MAX);

        assert_eq!(emulator.view().display_offset, scrolled_offset);
        assert_eq!(emulator.revision(), scrolled_revision);

        emulator.scroll_display(i32::MIN);
        let bottom_revision = emulator.revision();
        assert_eq!(emulator.view().display_offset, 0);
        assert!(bottom_revision > scrolled_revision);

        emulator.scroll_display(i32::MIN);
        assert_eq!(emulator.revision(), bottom_revision);

        emulator.scroll_display(1);
        let scrolled_again_revision = emulator.revision();
        assert!(scrolled_again_revision > bottom_revision);

        emulator.scroll_bottom();
        let final_bottom_revision = emulator.revision();
        assert_eq!(emulator.view().display_offset, 0);
        assert!(final_bottom_revision > scrolled_again_revision);

        emulator.scroll_bottom();

        assert_eq!(emulator.revision(), final_bottom_revision);
    }
    #[test]
    fn terminal_emulator_scrolls_display_history() {
        let mut emulator = TerminalEmulator::new(2, 8);

        emulator.advance(b"one\r\ntwo\r\nthree");
        assert_eq!(line_text(&emulator.view(), 0), "two     ");

        emulator.scroll_display(1);
        let view = emulator.view();

        assert_eq!(view.display_offset, 1);
        assert_eq!(line_text(&view, 0), "one     ");
    }

    #[test]
    fn terminal_emulator_preserves_more_than_one_screen_of_history() {
        let mut emulator = TerminalEmulator::new(2, 8);

        emulator.advance(b"one\r\ntwo\r\nthree\r\nfour\r\nfive");
        emulator.scroll_display(3);
        let view = emulator.view();

        assert!(
            view.display_offset >= 3,
            "terminal should preserve multi-line scrollback, got offset {}",
            view.display_offset
        );
        assert_eq!(line_text(&view, 0), "one     ");
    }

    #[test]
    fn terminal_emulator_limits_scrollback_history() {
        let mut emulator = TerminalEmulator::new(2, 8);
        for index in 0..(MAX_SCROLLBACK_LINES + 50) {
            emulator.advance(format!("{index}\r\n").as_bytes());
        }

        assert!(emulator.view().scrollback_lines <= MAX_SCROLLBACK_LINES);
    }

    #[test]
    fn terminal_emulator_keeps_manual_scrollback_position_when_output_arrives() {
        let mut emulator = TerminalEmulator::new(2, 8);

        emulator.advance(b"one\r\ntwo\r\nthree");
        emulator.scroll_display(1);
        assert_eq!(emulator.view().display_offset, 1);

        emulator.advance(b"\r\nfour");
        let view = emulator.view();

        assert!(
            view.display_offset > 0,
            "new output must not force a manually scrolled terminal back to bottom"
        );
        assert_ne!(line_text(&view, 0), "three   ");
    }
}
