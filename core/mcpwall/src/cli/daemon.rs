//! `mcpwall daemon` — the single authority on the machine.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use mcpwall::{daemon, ipc};

#[derive(Args)]
pub struct DaemonArgs {
    /// Socket to listen on.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Policy file. Created with the default rules if missing.
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

pub async fn run(db: PathBuf, args: DaemonArgs) -> Result<()> {
    daemon::run(
        args.socket.unwrap_or_else(ipc::socket_path),
        args.policy.unwrap_or_else(ipc::policy_path),
        db,
    )
    .await
}
