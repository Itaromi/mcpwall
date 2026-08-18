//! `mcpwall proxy` — the streamable HTTP transport.
//!
//! Long-lived and load-bearing, unlike the stdio shim: clients have been
//! pointed at its URL, so servers routed through it are unreachable while it
//! is stopped.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Args;

use mcpwall::ipc;
use mcpwall::ipc::client::{DaemonClient, SessionInfo};
use mcpwall::protocol::mcp::{AllowAll, DecisionPoint};
use mcpwall::transport::http;

#[derive(Args)]
pub struct ProxyArgs {
    /// Route table. Defaults to `~/.mcpwall/routes.json`, written by `init`.
    #[arg(long)]
    pub routes: Option<PathBuf>,

    /// Address to listen on. Overrides what the route table declares.
    #[arg(long)]
    pub listen: Option<String>,

    /// Daemon socket. Defaults to `~/.mcpwall/daemon.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    let path = args.routes.unwrap_or_else(ipc::routes_path);
    let mut table = if path.exists() {
        http::RouteTable::load(&path)?
    } else {
        // Started before `init` has written anything: listening with no route
        // is correct and says so, where exiting would send the app's supervisor
        // into a restart loop over a file that is simply not there yet.
        tracing::warn!(path = %path.display(), "no route table, nothing to proxy yet");
        http::RouteTable::default()
    };
    if let Some(listen) = args.listen {
        table.listen = listen;
    }

    let (addr, routes) = table.resolve()?;

    // The same degraded mode as the shim: no daemon means no policy, not a
    // dead proxy. Here the distinction matters more than anywhere else,
    // because a proxy that refuses to start takes the user's servers with it.
    let socket = args.socket.unwrap_or_else(ipc::socket_path);
    let decision: Arc<dyn DecisionPoint> = match DaemonClient::connect(
        &socket,
        false,
        SessionInfo {
            server: Some("http-proxy".to_owned()),
            ..SessionInfo::default()
        },
    ) {
        Some(c) => Arc::new(c),
        None => {
            tracing::warn!("daemon unreachable — proxying without policy");
            Arc::new(AllowAll)
        }
    };

    http::serve(http::Proxy::new(routes, decision)?, addr).await
}
