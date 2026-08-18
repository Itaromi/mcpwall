//! `mcpwall log` — reading the journal back.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use mcpwall::journal;

#[derive(Args)]
pub struct LogArgs {
    /// Number of lines.
    #[arg(short = 'n', long, default_value_t = 20)]
    pub tail: i64,

    /// Follow the journal continuously.
    #[arg(short, long)]
    pub follow: bool,

    /// Counters instead of lines.
    #[arg(long)]
    pub stats: bool,

    /// One JSON line per entry.
    #[arg(long)]
    pub json: bool,
}

pub fn run(db: PathBuf, args: LogArgs) -> Result<()> {
    if !db.exists() {
        println!("no journal at {} — nothing to show", db.display());
        return Ok(());
    }
    let conn = journal::open_readonly(&db)?;

    if args.stats {
        let s = journal::stats(&conn)?;
        println!("sessions        {}", s.sessions);
        println!("calls           {}", s.entries);
        println!("blocked         {}", s.denied);
        println!("pending         {}", s.asked);
        if !s.servers.is_empty() {
            println!("\nservers");
            for (name, n) in &s.servers {
                println!("  {n:>8}  {name}");
            }
        }
        if !s.by_method.is_empty() {
            println!("\nmethods");
            for (m, n) in &s.by_method {
                println!("  {n:>8}  {m}");
            }
        }
        return Ok(());
    }

    let mut last = 0i64;
    for (id, line) in journal::tail(&conn, args.tail, 0)? {
        print_line(&line, args.json);
        last = last.max(id);
    }

    if args.follow {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(300));
            for (id, line) in journal::tail(&conn, 500, last)? {
                print_line(&line, args.json);
                last = last.max(id);
            }
        }
    }
    Ok(())
}

fn print_line(line: &journal::LogLine, as_json: bool) {
    if as_json {
        let v = serde_json::json!({
            "ts_ms": line.ts_ms,
            "direction": line.direction,
            "method": line.method,
            "disposition": line.disposition,
            "verdict": line.verdict,
            "rule": line.rule,
            "server": line.server,
            "scope": line.scope_key,
            "scope_source": line.scope_source,
            "bytes": line.bytes,
        });
        println!("{v}");
        return;
    }

    let arrow = if line.direction == "to_server" {
        "->"
    } else {
        "<-"
    };
    let verdict = match line.verdict.as_deref() {
        Some("deny") => "  BLOCKED",
        Some("ask") => "  PENDING",
        _ => "",
    };
    println!(
        "{}  {arrow} {:<28} {:<12} {}{}",
        hhmmss(line.ts_ms),
        line.method.as_deref().unwrap_or("(response)"),
        line.server.as_deref().unwrap_or("?"),
        line.scope_key,
        verdict
    );
}

/// Approximate clock time with no calendar dependency: all we need is to place
/// a line within the day.
fn hhmmss(ms: i64) -> String {
    let secs = ms / 1000;
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}")
}
