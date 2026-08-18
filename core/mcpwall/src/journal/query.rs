//! Reading the journal back.
//!
//! Read-only connections, deliberately separate from the writer task: the UI
//! polls these frequently, and must never be able to get in the way of the
//! shim's writes. WAL is what makes that safe.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

use super::{init_schema, now_ms};

/// A row as rendered by `mcpwall log`.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub ts_ms: i64,
    pub direction: String,
    pub method: Option<String>,
    pub disposition: String,
    pub verdict: Option<String>,
    pub rule: Option<String>,
    pub server: Option<String>,
    pub scope_key: String,
    pub scope_source: String,
    pub bytes: i64,
}

/// Counters for `mcpwall log --stats`.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub sessions: i64,
    pub entries: i64,
    pub denied: i64,
    pub asked: i64,
    pub by_method: Vec<(String, i64)>,
    pub servers: Vec<(String, i64)>,
}

pub fn open_readonly(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .with_context(|| format!("opening {}", path.display()))?;
    Ok(conn)
}

pub fn tail(conn: &Connection, limit: i64, since_id: i64) -> Result<Vec<(i64, LogLine)>> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.ts_ms, e.direction, e.method, e.disposition, e.verdict, e.rule,
                s.server_name, s.scope_key, s.scope_source, e.bytes
         FROM entries e JOIN sessions s ON s.id = e.session_id
         WHERE e.id > ?1
         ORDER BY e.id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![since_id, limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            LogLine {
                ts_ms: r.get(1)?,
                direction: r.get(2)?,
                method: r.get(3)?,
                disposition: r.get(4)?,
                verdict: r.get(5)?,
                rule: r.get(6)?,
                server: r.get(7)?,
                scope_key: r.get(8)?,
                scope_source: r.get(9)?,
                bytes: r.get(10)?,
            },
        ))
    })?;

    let mut out: Vec<(i64, LogLine)> = rows.collect::<rusqlite::Result<_>>()?;
    out.reverse(); // chronological order for display
    Ok(out)
}

/// Records what a server just advertised, and returns the tools whose
/// advertisement has changed since we last saw them.
///
/// A tool seen for the first time never counts as drift. Everything is a first
/// time on the day mcpwall is installed, and a firewall whose opening move is
/// to question every tool the user already relies on has taught them, in one
/// session, to click through its prompts.
///
/// The new hash is stored **whether or not it drifted**. The alternative — keep
/// the old one until the user rules on it — makes every subsequent call raise
/// the same alarm about the same change, and one decision is one prompt.
///
/// Writes are the daemon's own, not the shim's writer task: this runs once per
/// `tools/list`, a few times per session, and is not on the hot path.
pub fn record_descriptions(
    db: &Path,
    server: &str,
    tools: &[(String, String)],
) -> Result<Vec<String>> {
    if tools.is_empty() {
        return Ok(Vec::new());
    }
    let conn = Connection::open(db).with_context(|| format!("opening {}", db.display()))?;
    init_schema(&conn)?;

    let now = now_ms();
    let mut drifted = Vec::new();

    let tx = conn.unchecked_transaction()?;
    for (tool, sha) in tools {
        let previous: Option<String> = tx
            .query_row(
                "SELECT sha256 FROM tool_descriptions WHERE server = ?1 AND tool = ?2",
                (server, tool),
                |r| r.get(0),
            )
            .optional()?;

        match previous {
            Some(old) if &old != sha => drifted.push(tool.clone()),
            _ => {}
        }

        tx.execute(
            "INSERT INTO tool_descriptions (server, tool, sha256, first_seen_ms, last_seen_ms)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(server, tool) DO UPDATE SET sha256 = ?3, last_seen_ms = ?4",
            (server, tool, sha, now),
        )?;
    }
    tx.commit()?;

    Ok(drifted)
}

/// Today's counters, for the popover: (calls, blocked, active sessions).
///
/// A separate, read-only query: the UI polls frequently, and must never be able
/// to get in the way of the shim's writer task.
pub fn today_counters(db: &Path) -> Result<(i64, i64, i64)> {
    if !db.exists() {
        return Ok((0, 0, 0));
    }
    let conn = open_readonly(db)?;
    let since = now_ms() - 24 * 3600 * 1000;

    let calls: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE ts_ms >= ?1",
        [since],
        |r| r.get(0),
    )?;
    let blocked: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE ts_ms >= ?1 AND verdict = 'deny'",
        [since],
        |r| r.get(0),
    )?;
    let sessions: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE started_ms >= ?1",
        [since],
        |r| r.get(0),
    )?;
    Ok((calls, blocked, sessions))
}

pub fn stats(conn: &Connection) -> Result<Stats> {
    let mut s = Stats {
        sessions: conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?,
        entries: conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))?,
        denied: conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE verdict = 'deny'",
            [],
            |r| r.get(0),
        )?,
        asked: conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE verdict = 'ask'",
            [],
            |r| r.get(0),
        )?,
        ..Default::default()
    };

    let mut stmt = conn.prepare(
        "SELECT method, COUNT(*) c FROM entries WHERE method IS NOT NULL
         GROUP BY method ORDER BY c DESC LIMIT 20",
    )?;
    s.by_method = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut stmt = conn.prepare(
        "SELECT COALESCE(s.server_name, s.command), COUNT(e.id) c
         FROM sessions s LEFT JOIN entries e ON e.session_id = s.id
         GROUP BY 1 ORDER BY c DESC LIMIT 20",
    )?;
    s.servers = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    Ok(s)
}
