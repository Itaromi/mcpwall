//! The writer task: the only thing that writes to the database.
//!
//! Two channels feed it and they are not equal. Volume entries are dropped when
//! the bounded channel is full, because slowing the relay down costs more than
//! losing one line in a thousand allowed calls. Decisions take the unbounded
//! channel and are never dropped: an audit tool that loses the very event
//! justifying its existence has no reason to exist.

use rusqlite::Connection;
use tokio::sync::mpsc;

use super::{BATCH_LINGER, BATCH_MAX, Entry, Msg, SessionRow};

pub(super) async fn writer_loop(
    mut conn: Connection,
    mut volume: mpsc::Receiver<Msg>,
    mut decisions: mpsc::UnboundedReceiver<Msg>,
) {
    let mut pending: Vec<Entry> = Vec::with_capacity(BATCH_MAX);
    let mut ticker = tokio::time::interval(BATCH_LINGER);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let msg = tokio::select! {
            // Decisions go first: they are rare and take priority.
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
                // A decision does not wait for the next batch: if the process
                // dies within 200 ms, that is precisely the one we must not
                // have lost.
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
                    tracing::warn!(error = %e, "could not update session");
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
    // One transaction for the whole batch: that is what makes writing cheap
    // enough for losses to stay theoretical.
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
        // We do not panic: the journal is a service, not the product. Losing a
        // batch is regrettable; killing the agent's session would be worse.
        tracing::error!(error = %e, entries = pending.len(), "could not write the journal");
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
// Reading
// ---------------------------------------------------------------------------
