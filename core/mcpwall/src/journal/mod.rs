//! SQLite journal.
//!
//! Two paths, because not all events are worth the same:
//!
//! - **volume** — allowed calls. Bounded channel; on saturation we drop the
//!   entry rather than slow the relay down, and we count the loss.
//! - **decisions** — `deny`, `ask`, alerts. Rare by nature, **guaranteed
//!   write**. An audit tool that loses the very event justifying its existence
//!   has no reason to exist: that is the line the user exports into a security
//!   ticket.
//!
//! Pressure is reduced at the source rather than managed at saturation: WAL,
//! `synchronous = NORMAL`, and writes grouped per transaction. The loss counter
//! must stay at zero; if it climbs, that is a bug, not an operating regime.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

/// Capacity of the volume channel. To be measured against real traffic.
const VOLUME_CAPACITY: usize = 4096;
/// Number of entries per transaction.
const BATCH_MAX: usize = 256;
/// Longest a pending entry may wait before being written.
const BATCH_LINGER: Duration = Duration::from_millis(200);

/// One journal row.
#[derive(Debug, Clone)]
pub struct Entry {
    pub ts_ms: i64,
    pub session_id: i64,
    pub direction: &'static str,
    pub method: Option<String>,
    pub disposition: String,
    pub verdict: Option<String>,
    pub rule: Option<String>,
    /// Excerpt of the arguments, truncated. **Must never contain the value of a
    /// detected secret** — we store the kind and a prefix.
    pub preview: Option<String>,
    pub bytes: i64,
}

impl Entry {
    pub fn now(session_id: i64, direction: &'static str, disposition: impl Into<String>) -> Self {
        Self {
            ts_ms: now_ms(),
            session_id,
            direction,
            method: None,
            disposition: disposition.into(),
            verdict: None,
            rule: None,
            preview: None,
            bytes: 0,
        }
    }

    /// Is an entry a decision, and therefore a guaranteed write?
    fn is_decision(&self) -> bool {
        matches!(self.verdict.as_deref(), Some("deny") | Some("ask")) || self.rule.is_some()
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Description of a session, written at `initialize` time.
#[derive(Debug, Clone, Default)]
pub struct SessionRow {
    pub started_ms: i64,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub protocol_version: Option<String>,
    pub scope_key: String,
    /// Scope provenance. Persisted: it is what decides whether `forever` can be
    /// offered later.
    pub scope_source: String,
    pub command: String,
}

enum Msg {
    Entry(Box<Entry>),
    Session(Box<SessionRow>, oneshot::Sender<i64>),
    UpdateSession(i64, Box<SessionRow>),
    Flush(oneshot::Sender<()>),
}

/// Write handle, cheap and clonable.
#[derive(Clone)]
pub struct Journal {
    volume: mpsc::Sender<Msg>,
    /// Decisions do not go through the bounded channel: losing them is out of the question.
    decisions: mpsc::UnboundedSender<Msg>,
    dropped: Arc<AtomicU64>,
}

impl Journal {
    /// Opens the database and starts the writer task.
    pub fn open(path: &Path) -> Result<(Self, tokio::task::JoinHandle<()>)> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::start(conn)
    }

    /// In-memory variant, for tests.
    pub fn open_in_memory() -> Result<(Self, tokio::task::JoinHandle<()>)> {
        Self::start(Connection::open_in_memory().context("in-memory database")?)
    }

    fn start(conn: Connection) -> Result<(Self, tokio::task::JoinHandle<()>)> {
        init_schema(&conn)?;

        let (vol_tx, vol_rx) = mpsc::channel(VOLUME_CAPACITY);
        let (dec_tx, dec_rx) = mpsc::unbounded_channel();
        let dropped = Arc::new(AtomicU64::new(0));

        let handle = tokio::spawn(writer_loop(conn, vol_rx, dec_rx));

        Ok((
            Self {
                volume: vol_tx,
                decisions: dec_tx,
                dropped,
            },
            handle,
        ))
    }

    /// Records an entry.
    ///
    /// A decision takes the guaranteed channel. A volume entry is dropped if
    /// the channel is full: slowing the relay down would cost more than losing
    /// one line out of a thousand allowed calls.
    pub fn log(&self, entry: Entry) {
        let msg = Msg::Entry(Box::new(entry.clone()));
        if entry.is_decision() {
            let _ = self.decisions.send(msg);
            return;
        }
        if self.volume.try_send(msg).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Opens a session and returns its identifier.
    pub async fn open_session(&self, row: SessionRow) -> Option<i64> {
        let (tx, rx) = oneshot::channel();
        self.decisions.send(Msg::Session(Box::new(row), tx)).ok()?;
        rx.await.ok()
    }

    pub fn update_session(&self, id: i64, row: SessionRow) {
        let _ = self.decisions.send(Msg::UpdateSession(id, Box::new(row)));
    }

    /// Entries lost since startup. Surfaced by `mcpwall log --stats` and by the
    /// UI: "47 entries lost today" is information the user is entitled to have.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Waits until everything submitted has been written.
    pub async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.decisions.send(Msg::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
    }
}

mod query;
mod schema;
mod writer;

pub use query::{LogLine, Stats, open_readonly, record_descriptions, stats, tail, today_counters};
use schema::init_schema;
use writer::writer_loop;

pub fn default_db_path() -> PathBuf {
    home_dir().join(".mcpwall").join("journal.db")
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
