//! `mcpwall wrap` — the stdio shim.
//!
//! One process per MCP server, started by the client rather than by us.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use clap::Args;

use mcpwall::ipc;
use mcpwall::ipc::client::{DaemonClient, SessionInfo};
use mcpwall::journal::Journal;
use mcpwall::protocol::mcp::{AllowAll, DecisionPoint};
use mcpwall::transport::observer::JournalObserver;
use mcpwall::transport::session::{SessionConfig, run as run_session};

#[derive(Args)]
pub struct WrapArgs {
    /// Project this session belongs to.
    ///
    /// Written by `mcpwall init` into the client configuration. It is the most
    /// trustworthy link of the provenance chain: deterministic and identical
    /// across clients, where the inherited cwd changes meaning depending on who
    /// starts the shim.
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Daemon socket. Defaults to `~/.mcpwall/daemon.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// Upstream server command, after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<OsString>,
}

pub async fn run(db: PathBuf, args: WrapArgs) -> Result<i32> {
    let mut command = args.command.into_iter();
    let Some(program) = command.next() else {
        bail!("missing upstream command after `--`");
    };
    let rest: Vec<OsString> = command.collect();

    let display = std::iter::once(&program)
        .chain(rest.iter())
        .map(|s| s.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");

    // A journal failure must not stop the MCP server from starting: we
    // degrade to a bare relay rather than break the session.
    let (journal, writer) = match Journal::open(&db) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "journal unavailable, relaying without journalling");
            Journal::open_in_memory()?
        }
    };

    let observer = JournalObserver::new(journal.clone(), display, args.project.clone()).await;

    // The decision point is the daemon if it answers, otherwise nothing. No
    // daemon degrades to observation only: that is the availability rule of §4,
    // and it is what lets the app be closed without paralysing the MCP servers.
    let socket = args.socket.clone().unwrap_or_else(ipc::socket_path);
    let decision: Arc<dyn DecisionPoint> = match DaemonClient::connect(
        &socket,
        false,
        SessionInfo {
            scope_key: observer.scope_key(),
            scope_source: observer.scope_source().as_str().to_owned(),
            scope_paths: observer.scope_paths(),
            server: None,
            session_id: observer.session_id(),
        },
    ) {
        Some(c) => Arc::new(c),
        None => Arc::new(AllowAll),
    };

    let mut config = SessionConfig::new(program, rest);
    config.project = args.project;

    let code = run_session(
        config,
        tokio::io::stdin(),
        tokio::io::stdout(),
        observer.clone(),
        decision,
    )
    .await?;

    // The session is over: we guarantee everything is written before handing
    // back control, otherwise the last entries would be lost on exit.
    journal.flush().await;
    let dropped = journal.dropped();
    drop(journal);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer).await;

    if dropped > 0 {
        tracing::warn!(dropped, "journal entries lost");
    }
    Ok(code)
}
