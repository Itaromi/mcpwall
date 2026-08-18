#![forbid(unsafe_code)]

//! A single binary. The shim, the daemon, the HTTP proxy, the Claude Code hook
//! and the administrative commands are subcommands of one executable — a single
//! artefact to embed in the app, a single symlink, and no possible version
//! drift between a shim and the daemon it talks to.
//!
//! Everything here is dispatch. The commands live in [`cli`].

mod cli;

fn main() -> anyhow::Result<()> {
    cli::run()
}
