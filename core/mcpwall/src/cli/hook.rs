//! `mcpwall hook` — Claude Code's built-in tools.
//!
//! Never run by hand: `mcpwall init` wires it into the settings.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use mcpwall::{hook, ipc};

#[derive(Args)]
pub struct HookArgs {
    /// Project this hook was installed for.
    ///
    /// Written by `mcpwall init` when it installs the hook into a project's
    /// settings, and left out when it installs into `~/.claude/settings.json`,
    /// which serves every project at once. Without it the scope falls back to
    /// the `cwd` the hook reports — rank 3 of §6bis, where "always allow" is
    /// not offered.
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Daemon socket. Defaults to `~/.mcpwall/daemon.sock`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

pub fn run(args: HookArgs) -> Result<()> {
    // Diagnostics go to stderr, which Claude Code surfaces without treating it
    // as a decision. Nothing but a verdict may ever reach stdout.
    super::init_tracing();

    let socket = args.socket.unwrap_or_else(ipc::socket_path);
    let Some(input) = hook::read_input(std::io::stdin()) else {
        tracing::warn!("unreadable hook payload, staying out of the way");
        return Ok(());
    };

    if let Some(output) = hook::run(&input, &socket, args.project.as_deref()) {
        println!("{output}");
    }
    Ok(())
}
