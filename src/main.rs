//! avcscope -- a read-only TUI for analyzing SELinux AVC denials.
//!
//! Design constraints (by request):
//!   * Strictly read-only. It cannot add or change rules, labels, booleans,
//!     ports, or the enforcing mode. It can only read logs and run read-only
//!     query commands, and it *suggests* remediations as text for the human.
//!   * Vim keybindings.
//!   * Always shows the current mode: ENFORCING | PERMISSIVE | DISABLED.
//!   * Repeated denials are de-duplicated, with a per-group count and a global
//!     running total (unique vs. total).

mod avc;
mod hints;
mod selinux;

use std::io;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use avc::AggDenial;
use hints::HintKind;
use selinux::{EnforceStatus, Source};

const TITLE: &str = "avcscope — SELinux denial analyzer (read-only)";

// ---- palette -------------------------------------------------------------
const C_ACCENT: Color = Color::Rgb(122, 162, 247); // soft blue
const C_SRC: Color = Color::Rgb(125, 207, 255); // cyan-ish: subject type
const C_TGT: Color = Color::Rgb(224, 175, 104); // amber: target type
const C_PERM: Color = Color::Rgb(247, 118, 142); // red/pink: the action
const C_DIM: Color = Color::Rgb(120, 124, 150);
const C_COUNT: Color = Color::Rgb(158, 206, 106); // green

#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode {
    Normal,
    Detail,
    Search,
    Command,
    Help,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SortKey {
    Count,
    LastSeen,
    SourceType,
}

impl SortKey {
    fn label(&self) -> &'static str {
        match self {
            SortKey::Count => "count",
            SortKey::LastSeen => "recent",
            SortKey::SourceType => "src-type",
        }
    }
    fn next(self) -> SortKey {
        match self {
            SortKey::Count => SortKey::LastSeen,
            SortKey::LastSeen => SortKey::SourceType,
            SortKey::SourceType => SortKey::Count,
        }
    }
}

struct App {
    denials: Vec<AggDenial>,
    filtered: Vec<usize>, // indices into `denials` passing the current search
    selected: usize,      // index into `filtered`
    list_state: ListState,
    status: EnforceStatus,
    source: Source,
    file: Option<String>,
    demo: bool,
    total_raw: usize,
    mode: Mode,
    sort: SortKey,
    search: String,
    command: String,
    detail_scroll: u16,
    list_height: usize,
    message: String,
    last_status_check: Instant,
    should_quit: bool,
}

impl App {
    fn new(
        denials: Vec<AggDenial>,
        total_raw: usize,
        status: EnforceStatus,
        source: Source,
        file: Option<String>,
        demo: bool,
    ) -> App {
        let mut app = App {
            denials,
            filtered: Vec::new(),
            selected: 0,
            list_state: ListState::default(),
            status,
            source,
            file,
            demo,
            total_raw,
            mode: Mode::Normal,
            sort: SortKey::Count,
            search: String::new(),
            command: String::new(),
            detail_scroll: 0,
            list_height: 10,
            message: String::new(),
            last_status_check: Instant::now(),
            should_quit: false,
        };
        app.apply_sort();
        app
    }

    /// Status to display, with a synthetic fallback so the colored badge is
    /// still meaningful when running the demo on a non-SELinux box.
    fn display_status(&self) -> (EnforceStatus, bool) {
        if self.demo && matches!(self.status, EnforceStatus::Disabled | EnforceStatus::Unknown) {
            (EnforceStatus::Enforcing, true)
        } else {
            (self.status, false)
        }
    }

    fn apply_sort(&mut self) {
        match self.sort {
            SortKey::Count => self
                .denials
                .sort_by(|a, b| b.count.cmp(&a.count).then(b.last_ts.total_cmp(&a.last_ts))),
            SortKey::LastSeen => self.denials.sort_by(|a, b| b.last_ts.total_cmp(&a.last_ts)),
            SortKey::SourceType => self
                .denials
                .sort_by(|a, b| a.scontext.ty.cmp(&b.scontext.ty).then(b.count.cmp(&a.count))),
        }
        self.recompute_filter();
    }

    fn recompute_filter(&mut self) {
        let q = self.search.to_lowercase();
        self.filtered = self
            .denials
            .iter()
            .enumerate()
            .filter(|(_, d)| q.is_empty() || d.search_blob().contains(&q))
            .map(|(i, _)| i)
            .collect();
        if self.filtered.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len() - 1;
        }
        self.detail_scroll = 0;
    }

    fn current(&self) -> Option<&AggDenial> {
        self.filtered.get(self.selected).map(|&i| &self.denials[i])
    }

    fn move_sel(&mut self, delta: isize) {
        if self.filtered.is_empty() {
            return;
        }
        let len = self.filtered.len() as isize;
        let mut s = self.selected as isize + delta;
        if s < 0 {
            s = 0;
        }
        if s >= len {
            s = len - 1;
        }
        self.selected = s as usize;
        self.detail_scroll = 0;
    }

    fn reload(&mut self) {
        self.status = selinux::detect_status();
        let (text, source) = selinux::load(self.demo, self.file.clone());
        let (denials, total_raw) = avc::aggregate(&text);
        self.denials = denials;
        self.total_raw = total_raw;
        self.source = source;
        self.selected = 0;
        self.apply_sort();
        self.message = "reloaded".into();
    }

    fn run_command(&mut self) {
        let cmd = self.command.trim().trim_start_matches(':').to_string();
        match cmd.as_str() {
            "q" | "quit" => self.should_quit = true,
            "h" | "help" => self.mode = Mode::Help,
            "sort" => {
                self.sort = self.sort.next();
                self.apply_sort();
            }
            "r" | "reload" => self.reload(),
            "" => {}
            other => self.message = format!("unknown command: :{other}"),
        }
        self.command.clear();
    }
}

fn main() -> io::Result<()> {
    let mut force_demo = false;
    let mut file: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--demo" => force_demo = true,
            "--file" => file = args.next(),
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "--version" => {
                println!("avcscope {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other if other.starts_with("--file=") => {
                file = Some(other.trim_start_matches("--file=").to_string());
            }
            _ => {}
        }
    }

    let status = selinux::detect_status();
    let (text, source) = selinux::load(force_demo, file.clone());
    let (denials, total_raw) = avc::aggregate(&text);
    let mut app = App::new(denials, total_raw, status, source, file, force_demo);

    let mut terminal = ratatui::init();
    let res = run(&mut terminal, &mut app);
    ratatui::restore();
    res
}

fn print_usage() {
    println!(
        "avcscope — read-only SELinux denial analyzer\n\n\
         USAGE:\n  \
         avcscope [--demo] [--file PATH]\n  \
         ausearch -m AVC,USER_AVC -ts today | avcscope\n\n\
         SOURCES (auto, in order): --file, piped stdin, `ausearch`, \
         /var/log/audit/audit.log, then built-in demo.\n\n\
         This tool is strictly read-only: it never changes SELinux policy, \
         labels, booleans, ports, or the enforcing mode."
    );
}

fn run(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key.code, key.modifiers);
                }
            }
        } else if app.last_status_check.elapsed() >= Duration::from_secs(2) {
            // Periodically refresh the live mode so the badge stays accurate.
            if !app.demo {
                app.status = selinux::detect_status();
            }
            app.last_status_check = Instant::now();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    app.message.clear();
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    let half = (app.list_height / 2).max(1) as isize;

    match app.mode {
        Mode::Search => match code {
            KeyCode::Char(c) => {
                app.search.push(c);
                app.recompute_filter();
            }
            KeyCode::Backspace => {
                app.search.pop();
                app.recompute_filter();
            }
            KeyCode::Enter => app.mode = Mode::Normal, // keep the filter
            KeyCode::Esc => {
                app.search.clear();
                app.recompute_filter();
                app.mode = Mode::Normal;
            }
            _ => {}
        },
        Mode::Command => match code {
            KeyCode::Char(c) => app.command.push(c),
            KeyCode::Backspace => {
                app.command.pop();
            }
            KeyCode::Enter => {
                app.run_command();
                app.mode = Mode::Normal;
            }
            KeyCode::Esc => {
                app.command.clear();
                app.mode = Mode::Normal;
            }
            _ => {}
        },
        Mode::Help => {
            if matches!(code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?')) {
                app.mode = Mode::Normal;
            }
        }
        Mode::Normal | Mode::Detail => match code {
            KeyCode::Char('q') => {
                if app.mode == Mode::Detail {
                    app.mode = Mode::Normal;
                } else {
                    app.should_quit = true;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => app.move_sel(1),
            KeyCode::Char('k') | KeyCode::Up => app.move_sel(-1),
            KeyCode::Char('g') => app.selected = 0,
            KeyCode::Char('G') => {
                if !app.filtered.is_empty() {
                    app.selected = app.filtered.len() - 1;
                }
            }
            KeyCode::Char('d') if ctrl => {
                if app.mode == Mode::Detail {
                    app.detail_scroll = app.detail_scroll.saturating_add(half as u16);
                } else {
                    app.move_sel(half);
                }
            }
            KeyCode::Char('u') if ctrl => {
                if app.mode == Mode::Detail {
                    app.detail_scroll = app.detail_scroll.saturating_sub(half as u16);
                } else {
                    app.move_sel(-half);
                }
            }
            KeyCode::Char('s') => {
                app.sort = app.sort.next();
                app.apply_sort();
            }
            KeyCode::Char('r') => app.reload(),
            KeyCode::Char('/') => {
                app.search.clear();
                app.recompute_filter();
                app.mode = Mode::Search;
            }
            KeyCode::Char(':') => {
                app.command.clear();
                app.command.push(':');
                app.mode = Mode::Command;
            }
            KeyCode::Char('?') => app.mode = Mode::Help,
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                if app.current().is_some() {
                    app.mode = Mode::Detail;
                }
            }
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left => {
                if app.mode == Mode::Detail {
                    app.mode = Mode::Normal;
                } else if !app.search.is_empty() {
                    app.search.clear();
                    app.recompute_filter();
                }
            }
            _ => {}
        },
    }
}

// ---- rendering -----------------------------------------------------------

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(1),    // body
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    render_header(f, app, chunks[0]);

    if app.mode == Mode::Detail {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
            .split(chunks[1]);
        render_list(f, app, body[0]);
        render_detail(f, app, body[1]);
    } else {
        render_list(f, app, chunks[1]);
    }

    render_footer(f, app, chunks[2]);

    if app.mode == Mode::Help {
        render_help(f, f.area());
    }
}

fn render_header(f: &mut Frame, app: &mut App, area: Rect) {
    let (status, synthetic) = app.display_status();
    let (bg, fg) = match status {
        EnforceStatus::Enforcing => (Color::Rgb(190, 40, 40), Color::White),
        EnforceStatus::Permissive => (Color::Rgb(200, 160, 30), Color::Black),
        EnforceStatus::Disabled => (Color::Rgb(80, 80, 90), Color::White),
        EnforceStatus::Unknown => (Color::Rgb(120, 60, 160), Color::White),
    };
    let badge_text = if synthetic {
        format!(" {} (demo) ", status.label())
    } else {
        format!(" {} ", status.label())
    };

    let unique = app.denials.len();
    let line = Line::from(vec![
        Span::styled(
            badge_text,
            Style::default().bg(bg).fg(fg).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("denials: ", Style::default().fg(C_DIM)),
        Span::styled(
            format!("{unique}"),
            Style::default().fg(C_COUNT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" unique / ", Style::default().fg(C_DIM)),
        Span::styled(
            format!("{}", app.total_raw),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" total", Style::default().fg(C_DIM)),
        Span::styled("    sort: ", Style::default().fg(C_DIM)),
        Span::styled(app.sort.label(), Style::default().fg(C_ACCENT)),
        if app.search.is_empty() {
            Span::raw("")
        } else {
            Span::styled(
                format!("    filter: /{}", app.search),
                Style::default().fg(C_TGT),
            )
        },
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_DIM))
        .title(Span::styled(
            format!(" {TITLE} "),
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(Paragraph::new(line).block(block), area);
}

fn render_list(f: &mut Frame, app: &mut App, area: Rect) {
    app.list_height = area.height.saturating_sub(2) as usize;

    let items: Vec<ListItem> = app
        .filtered
        .iter()
        .map(|&i| {
            let d = &app.denials[i];
            let perm_color = if d.outcome == "granted" { C_COUNT } else { C_PERM };
            let line = Line::from(vec![
                Span::styled(
                    format!("×{:<4} ", d.count),
                    Style::default().fg(C_COUNT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<10}", truncate(&d.comm, 10)),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!(" {{{}}} ", d.perms.join(" ")),
                    Style::default().fg(perm_color),
                ),
                Span::styled(d.scontext.ty.clone(), Style::default().fg(C_SRC)),
                Span::styled(" → ", Style::default().fg(C_DIM)),
                Span::styled(d.tcontext.ty.clone(), Style::default().fg(C_TGT)),
                Span::styled(format!(" [{}]", d.tclass), Style::default().fg(C_DIM)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let title = if app.filtered.is_empty() {
        " no denials match ".to_string()
    } else {
        format!(" denials ({}) ", app.filtered.len())
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_DIM))
                .title(Span::styled(title, Style::default().fg(C_ACCENT))),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(45, 50, 80))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    if app.filtered.is_empty() {
        app.list_state.select(None);
    } else {
        app.list_state.select(Some(app.selected));
    }
    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn render_detail(f: &mut Frame, app: &mut App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    if let Some(d) = app.current() {
        let header = |k: &str, v: String, color: Color| {
            Line::from(vec![
                Span::styled(format!("{k:<12}"), Style::default().fg(C_DIM)),
                Span::styled(v, Style::default().fg(color)),
            ])
        };

        lines.push(Line::from(Span::styled(
            d.summary(),
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(header("outcome", d.outcome.clone(), C_PERM));
        lines.push(header("permission", d.perms.join(", "), C_PERM));
        lines.push(header("class", d.tclass.clone(), Color::White));
        lines.push(header(
            "permissive",
            match d.permissive {
                Some(true) => "yes (was permissive)".into(),
                Some(false) => "no (enforcing)".into(),
                None => "n/a".into(),
            },
            C_DIM,
        ));
        lines.push(Line::from(""));

        lines.push(Line::from(Span::styled(
            "subject (scontext)",
            Style::default().fg(C_SRC).add_modifier(Modifier::BOLD),
        )));
        lines.push(header("  user", d.scontext.user.clone(), C_DIM));
        lines.push(header("  role", d.scontext.role.clone(), C_DIM));
        lines.push(header("  type", d.scontext.ty.clone(), C_SRC));
        lines.push(header("  level", d.scontext.level.clone(), C_DIM));

        lines.push(Line::from(Span::styled(
            "target (tcontext)",
            Style::default().fg(C_TGT).add_modifier(Modifier::BOLD),
        )));
        lines.push(header("  user", d.tcontext.user.clone(), C_DIM));
        lines.push(header("  role", d.tcontext.role.clone(), C_DIM));
        lines.push(header("  type", d.tcontext.ty.clone(), C_TGT));
        lines.push(header("  level", d.tcontext.level.clone(), C_DIM));
        lines.push(Line::from(""));

        lines.push(header(
            "occurrences",
            format!("{} (de-duplicated)", d.count),
            C_COUNT,
        ));
        lines.push(header("first seen", fmt_time(d.first_ts), C_DIM));
        lines.push(header("last seen", fmt_time(d.last_ts), C_DIM));
        lines.push(header("distinct pids", format!("{}", d.pids.len()), C_DIM));

        if !d.paths.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("paths ({})", d.paths.len()),
                Style::default().fg(C_DIM),
            )));
            for p in d.paths.iter().take(8) {
                lines.push(Line::from(Span::styled(
                    format!("  {p}"),
                    Style::default().fg(Color::White),
                )));
            }
            if d.paths.len() > 8 {
                lines.push(Line::from(Span::styled(
                    format!("  … and {} more", d.paths.len() - 8),
                    Style::default().fg(C_DIM),
                )));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "── diagnosis (read-only suggestions) ──",
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        )));
        for h in hints::diagnose(d) {
            let (mark, color) = match h.kind {
                HintKind::Likely => ("◆ likely  ", C_PERM),
                HintKind::Consider => ("○ consider", C_TGT),
                HintKind::Inspect => ("» inspect ", C_SRC),
                HintKind::Caution => ("! caution ", Color::Rgb(187, 154, 247)),
            };
            lines.push(Line::from(Span::styled(
                mark.to_string(),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(Span::styled(
                format!("  {}", h.text),
                Style::default().fg(Color::White),
            )));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("raw record", Style::default().fg(C_DIM))));
        lines.push(Line::from(Span::styled(
            d.sample_raw.clone(),
            Style::default().fg(C_DIM).add_modifier(Modifier::ITALIC),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "no denial selected",
            Style::default().fg(C_DIM),
        )));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_DIM))
        .title(Span::styled(
            " detail  (^d/^u scroll · h/Esc back) ",
            Style::default().fg(C_ACCENT),
        ));
    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));
    f.render_widget(para, area);
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let content = match app.mode {
        Mode::Search => Line::from(vec![
            Span::styled("/", Style::default().fg(C_TGT).add_modifier(Modifier::BOLD)),
            Span::styled(app.search.clone(), Style::default().fg(Color::White)),
            Span::styled("▏", Style::default().fg(C_ACCENT)),
            Span::styled("   (Enter: keep · Esc: clear)", Style::default().fg(C_DIM)),
        ]),
        Mode::Command => Line::from(vec![
            Span::styled(app.command.clone(), Style::default().fg(Color::White)),
            Span::styled("▏", Style::default().fg(C_ACCENT)),
            Span::styled("   (:q :sort :reload :help)", Style::default().fg(C_DIM)),
        ]),
        _ => {
            let keys = "j/k move · g/G top/btm · ^d/^u page · l/Enter detail · / search · s sort · r reload · ? help · q quit";
            Line::from(vec![
                Span::styled(format!("{}  ", app.source.describe()), Style::default().fg(C_TGT)),
                Span::styled("│ ", Style::default().fg(C_DIM)),
                if app.message.is_empty() {
                    Span::styled(keys, Style::default().fg(C_DIM))
                } else {
                    Span::styled(app.message.clone(), Style::default().fg(C_COUNT))
                },
            ])
        }
    };
    f.render_widget(Paragraph::new(content), area);
}

fn render_help(f: &mut Frame, area: Rect) {
    let rect = centered_rect(64, 80, area);
    f.render_widget(Clear, rect);

    let kv = |k: &str, v: &str| {
        Line::from(vec![
            Span::styled(format!("  {k:<14}"), Style::default().fg(C_ACCENT)),
            Span::styled(v.to_string(), Style::default().fg(Color::White)),
        ])
    };
    let head = |t: &str| {
        Line::from(Span::styled(
            t.to_string(),
            Style::default().fg(C_TGT).add_modifier(Modifier::BOLD),
        ))
    };

    let lines = vec![
        head("Navigation"),
        kv("j / k", "down / up"),
        kv("g / G", "jump to top / bottom"),
        kv("Ctrl-d / -u", "half page (or scroll detail)"),
        Line::from(""),
        head("Views"),
        kv("l / Enter", "open detail for selected denial"),
        kv("h / Esc", "back out of detail / clear filter"),
        kv("/", "incremental search (Enter keep, Esc clear)"),
        kv("s", "cycle sort: count → recent → src-type"),
        kv("r", "reload from source"),
        kv(":", "command line — :q :sort :reload :help"),
        kv("?", "toggle this help"),
        kv("q", "quit (or close detail)"),
        Line::from(""),
        head("About"),
        Line::from(Span::styled(
            "  Repeated denials are collapsed by",
            Style::default().fg(C_DIM),
        )),
        Line::from(Span::styled(
            "  (outcome, perms, scontext, tcontext, class, comm);",
            Style::default().fg(C_DIM),
        )),
        Line::from(Span::styled(
            "  ×N is the group size; header shows unique/total.",
            Style::default().fg(C_DIM),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  READ-ONLY: never changes policy, labels,",
            Style::default().fg(C_PERM),
        )),
        Line::from(Span::styled(
            "  booleans, ports, or the enforcing mode.",
            Style::default().fg(C_PERM),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  press ? / Esc / q to close",
            Style::default().fg(C_ACCENT),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_ACCENT))
        .title(Span::styled(
            " help ",
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(
        Paragraph::new(lines).block(block).alignment(Alignment::Left),
        rect,
    );
}

// ---- helpers -------------------------------------------------------------

fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v[1])[1]
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Format an epoch timestamp as a UTC time-of-day (no external date crate).
fn fmt_time(ts: f64) -> String {
    if ts <= 0.0 {
        return "n/a".into();
    }
    let secs = ts as i64;
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{h:02}:{m:02}:{s:02} UTC")
}
