//! The database schema, created on open and never migrated in place.
//!
//! `CREATE TABLE IF NOT EXISTS` throughout: adding a table is additive and safe
//! on an existing journal. Changing the meaning of a column is not, and needs a
//! migration — the labels stored here are a contract (spec §12).

use anyhow::{Context, Result};
use rusqlite::Connection;

pub(super) fn init_schema(conn: &Connection) -> Result<()> {
    // WAL: concurrent reads during writes, essential so that `log --tail` does
    // not wait on the writer task.
    // NORMAL rather than FULL: one fsync per transaction would cost more than
    // the guarantee is worth, for a local audit journal.
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("enabling WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("setting synchronous")?;
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

        -- What each tool looked like the last time we were shown it.
        --
        -- On disk rather than in the daemon's memory because a rug-pull is
        -- measured in weeks: the server serves an honest description while it
        -- is being approved and a different one once it is trusted. A record
        -- that died with the process would only ever catch a server that
        -- changed its mind inside a single session, which is the one case
        -- nobody is worried about.
        CREATE TABLE IF NOT EXISTS tool_descriptions (
            server      TEXT NOT NULL,
            tool        TEXT NOT NULL,
            sha256      TEXT NOT NULL,
            first_seen_ms INTEGER NOT NULL,
            last_seen_ms  INTEGER NOT NULL,
            PRIMARY KEY (server, tool)
        );
        "#,
    )
    .context("creating the schema")?;
    Ok(())
}
