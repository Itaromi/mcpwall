//! Journal SQLite.
//!
//! Deux chemins, parce que tous les événements ne se valent pas :
//!
//! - **volume** — appels autorisés. Canal borné ; en cas de saturation on jette
//!   l'entrée plutôt que de ralentir le relais, et on compte la perte.
//! - **décisions** — `deny`, `ask`, alertes. Rares par nature, **écriture
//!   garantie**. Un outil d'audit qui perd l'événement justifiant son existence
//!   n'a plus de raison d'être : c'est cette ligne-là que l'utilisateur exporte
//!   dans un ticket de sécurité.
//!
//! La pression est réduite à la source plutôt que gérée à la saturation : WAL,
//! `synchronous = NORMAL`, et regroupement des écritures par transaction. Le
//! compteur de pertes doit rester à zéro ; s'il monte, c'est un bug, pas un
//! régime de fonctionnement.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

/// Capacité du canal volume. À mesurer sur trafic réel.
const VOLUME_CAPACITY: usize = 4096;
/// Nombre d'entrées par transaction.
const BATCH_MAX: usize = 256;
/// Âge maximal d'une entrée en attente avant écriture.
const BATCH_LINGER: Duration = Duration::from_millis(200);

/// Une ligne de journal.
#[derive(Debug, Clone)]
pub struct Entry {
    pub ts_ms: i64,
    pub session_id: i64,
    pub direction: &'static str,
    pub method: Option<String>,
    pub disposition: String,
    pub verdict: Option<String>,
    pub rule: Option<String>,
    /// Extrait des arguments, tronqué. **Ne doit jamais contenir la valeur d'un
    /// secret détecté** — on stocke le type et un préfixe.
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

    /// Une entrée est-elle une décision, donc à écriture garantie ?
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

/// Description d'une session, écrite à l'`initialize`.
#[derive(Debug, Clone, Default)]
pub struct SessionRow {
    pub started_ms: i64,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub protocol_version: Option<String>,
    pub scope_key: String,
    /// Provenance du scope. Persistée : c'est elle qui décide si `forever` est
    /// offrable plus tard.
    pub scope_source: String,
    pub command: String,
}

enum Msg {
    Entry(Box<Entry>),
    Session(Box<SessionRow>, oneshot::Sender<i64>),
    UpdateSession(i64, Box<SessionRow>),
    Flush(oneshot::Sender<()>),
}

/// Poignée d'écriture, clonable et bon marché.
#[derive(Clone)]
pub struct Journal {
    volume: mpsc::Sender<Msg>,
    /// Les décisions ne passent pas par le canal borné : les perdre est exclu.
    decisions: mpsc::UnboundedSender<Msg>,
    dropped: Arc<AtomicU64>,
}

impl Journal {
    /// Ouvre la base et démarre la tâche d'écriture.
    pub fn open(path: &Path) -> Result<(Self, tokio::task::JoinHandle<()>)> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création de {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("ouverture de {}", path.display()))?;
        Self::start(conn)
    }

    /// Variante en mémoire, pour les tests.
    pub fn open_in_memory() -> Result<(Self, tokio::task::JoinHandle<()>)> {
        Self::start(Connection::open_in_memory().context("base en mémoire")?)
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

    /// Enregistre une entrée.
    ///
    /// Une décision emprunte le canal garanti. Une entrée de volume est jetée
    /// si le canal est plein : ralentir le relais coûterait plus cher que
    /// perdre une ligne d'un appel autorisé parmi mille.
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

    /// Ouvre une session et rend son identifiant.
    pub async fn open_session(&self, row: SessionRow) -> Option<i64> {
        let (tx, rx) = oneshot::channel();
        self.decisions.send(Msg::Session(Box::new(row), tx)).ok()?;
        rx.await.ok()
    }

    pub fn update_session(&self, id: i64, row: SessionRow) {
        let _ = self.decisions.send(Msg::UpdateSession(id, Box::new(row)));
    }

    /// Entrées perdues depuis le démarrage. Exposé par `mcpwall log --stats` et
    /// par l'UI : « 47 entrées perdues aujourd'hui » est une information que
    /// l'utilisateur a le droit d'avoir.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Attend que tout ce qui a été soumis soit écrit.
    pub async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.decisions.send(Msg::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    // WAL : lectures concurrentes pendant les écritures, indispensable pour que
    // `log --tail` n'attende pas la tâche d'écriture.
    // NORMAL plutôt que FULL : un fsync par transaction coûterait plus que ce
    // que vaut la garantie, pour un journal d'audit local.
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("activation du WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("réglage de synchronous")?;
    conn.pragma_update(None, "foreign_keys", "ON").ok();

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sessions (
            id               INTEGER PRIMARY KEY,
            started_ms       INTEGER NOT NULL,
            server_name      TEXT,
            server_version   TEXT,
            client_name      TEXT,
            client_version   TEXT,
            protocol_version TEXT,
            scope_key        TEXT NOT NULL,
            scope_source     TEXT NOT NULL,
            command          TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entries (
            id          INTEGER PRIMARY KEY,
            ts_ms       INTEGER NOT NULL,
            session_id  INTEGER NOT NULL REFERENCES sessions(id),
            direction   TEXT NOT NULL,
            method      TEXT,
            disposition TEXT NOT NULL,
            verdict     TEXT,
            rule        TEXT,
            preview     TEXT,
            bytes       INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS entries_ts       ON entries(ts_ms);
        CREATE INDEX IF NOT EXISTS entries_session  ON entries(session_id);
        CREATE INDEX IF NOT EXISTS entries_verdict  ON entries(verdict) WHERE verdict IS NOT NULL;
        "#,
    )
    .context("création du schéma")?;
    Ok(())
}

async fn writer_loop(
    mut conn: Connection,
    mut volume: mpsc::Receiver<Msg>,
    mut decisions: mpsc::UnboundedReceiver<Msg>,
) {
    let mut pending: Vec<Entry> = Vec::with_capacity(BATCH_MAX);
    let mut ticker = tokio::time::interval(BATCH_LINGER);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let msg = tokio::select! {
            // Les décisions passent devant : elles sont rares et prioritaires.
            biased;
            Some(m) = decisions.recv() => Some(m),
            Some(m) = volume.recv() => Some(m),
            _ = ticker.tick() => {
                flush_pending(&mut conn, &mut pending);
                continue;
            }
            else => None,
        };

        let Some(msg) = msg else { break };

        match msg {
            Msg::Entry(e) => {
                let decision = e.is_decision();
                pending.push(*e);
                // Une décision n'attend pas le prochain lot : si le processus
                // meurt dans les 200 ms, c'est précisément elle qu'il ne faut
                // pas avoir perdue.
                if decision || pending.len() >= BATCH_MAX {
                    flush_pending(&mut conn, &mut pending);
                }
            }
            Msg::Session(row, reply) => {
                flush_pending(&mut conn, &mut pending);
                let id = insert_session(&conn, &row).unwrap_or(0);
                let _ = reply.send(id);
            }
            Msg::UpdateSession(id, row) => {
                flush_pending(&mut conn, &mut pending);
                if let Err(e) = update_session(&conn, id, &row) {
                    tracing::warn!(erreur = %e, "mise à jour de session impossible");
                }
            }
            Msg::Flush(reply) => {
                flush_pending(&mut conn, &mut pending);
                let _ = reply.send(());
            }
        }
    }

    flush_pending(&mut conn, &mut pending);
}

fn flush_pending(conn: &mut Connection, pending: &mut Vec<Entry>) {
    if pending.is_empty() {
        return;
    }
    // Une transaction pour tout le lot : c'est ce qui rend l'écriture assez
    // bon marché pour que les pertes restent théoriques.
    let result = (|| -> rusqlite::Result<()> {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO entries
                 (ts_ms, session_id, direction, method, disposition, verdict, rule, preview, bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for e in pending.iter() {
                stmt.execute(rusqlite::params![
                    e.ts_ms,
                    e.session_id,
                    e.direction,
                    e.method,
                    e.disposition,
                    e.verdict,
                    e.rule,
                    e.preview,
                    e.bytes,
                ])?;
            }
        }
        tx.commit()
    })();

    if let Err(e) = result {
        // On ne panique pas : le journal est un service, pas le produit. Perdre
        // un lot est regrettable ; tuer la session de l'agent serait pire.
        tracing::error!(erreur = %e, entrées = pending.len(), "écriture du journal impossible");
    }
    pending.clear();
}

fn insert_session(conn: &Connection, row: &SessionRow) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO sessions
         (started_ms, server_name, server_version, client_name, client_version,
          protocol_version, scope_key, scope_source, command)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            row.started_ms,
            row.server_name,
            row.server_version,
            row.client_name,
            row.client_version,
            row.protocol_version,
            row.scope_key,
            row.scope_source,
            row.command,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn update_session(conn: &Connection, id: i64, row: &SessionRow) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE sessions SET
           server_name = COALESCE(?2, server_name),
           server_version = COALESCE(?3, server_version),
           client_name = COALESCE(?4, client_name),
           client_version = COALESCE(?5, client_version),
           protocol_version = COALESCE(?6, protocol_version),
           scope_key = ?7,
           scope_source = ?8
         WHERE id = ?1",
        rusqlite::params![
            id,
            row.server_name,
            row.server_version,
            row.client_name,
            row.client_version,
            row.protocol_version,
            row.scope_key,
            row.scope_source,
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Lecture
// ---------------------------------------------------------------------------

/// Une ligne telle que la rend `mcpwall log`.
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

/// Compteurs de `mcpwall log --stats`.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub sessions: i64,
    pub entries: i64,
    pub denied: i64,
    pub asked: i64,
    pub by_method: Vec<(String, i64)>,
    pub servers: Vec<(String, i64)>,
}

pub fn default_db_path() -> PathBuf {
    home_dir().join(".mcpwall").join("journal.db")
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn open_readonly(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .with_context(|| format!("ouverture de {}", path.display()))?;
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
    out.reverse(); // ordre chronologique à l'affichage
    Ok(out)
}

/// Compteurs du jour, pour le popover : (appels, bloqués, sessions actives).
///
/// Lecture indépendante et en seule lecture : l'UI interroge fréquemment, et
/// elle ne doit jamais pouvoir gêner la tâche d'écriture du shim.
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
