//! The command line.
//!
//! One module per subcommand, each owning its own arguments. `main` does
//! nothing but parse and dispatch — everything a command needs to explain
//! about itself lives next to the code that runs it.

pub mod daemon;
pub mod hook;
pub mod init;
pub mod log;
pub mod proxy;
pub mod wrap;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use mcpwall::journal;

use daemon::DaemonArgs;
use hook::HookArgs;
use init::InitArgs;
use log::LogArgs;
use proxy::ProxyArgs;
use wrap::WrapArgs;

#[derive(Parser)]
#[command(
    name = "mcpwall",
    about = "Local application firewall for coding agents",
    version
)]
pub struct Cli {
    /// Journal database. Defaults to `~/.mcpwall/journal.db`.
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wrap a stdio MCP server and journal its traffic.
    Wrap(WrapArgs),
    /// Inspect the journal.
    Log(LogArgs),
    /// Run the policy daemon. One per machine.
    ///
    /// In M2 it is the macOS app that starts and supervises it as a child
    /// process: the app does not reimplement it.
    Daemon(DaemonArgs),
    /// Proxy streamable HTTP MCP servers.
    ///
    /// Unlike `wrap`, this one is long-lived and load-bearing: an HTTP client
    /// connects to a URL, so the only way to interpose is to be that URL.
    /// Servers routed through it are unreachable while it is stopped. The app
    /// supervises it; `mcpwall restore` puts the original URLs back.
    Proxy(ProxyArgs),
    /// Answer a Claude Code hook. Reads one JSON object on stdin.
    ///
    /// Covers what MCP cannot see: the built-in `Read`, `Edit`, `Bash` and
    /// `WebFetch` tools, which are most of the attack surface and never reach a
    /// server. Same daemon, same policy, same journal. Never meant to be run by
    /// hand; `mcpwall init` wires it into the settings.
    Hook(HookArgs),
    /// Install mcpwall into the existing MCP configurations.
    Init(InitArgs),
    /// Put the configurations back from the backups.
    Restore,
    /// Print the effective policy and check its syntax.
    Policy,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let db = cli.db.clone().unwrap_or_else(journal::default_db_path);

    match cli.command {
        // The shim writes its diagnostics to stderr, never to stdout: stdout
        // belongs to the protocol, and one stray byte there breaks the session.
        Command::Wrap(args) => {
            init_tracing();
            let code = current_thread()?.block_on(wrap::run(db, args))?;
            std::process::exit(code);
        }
        Command::Log(args) => log::run(db, args),
        Command::Daemon(args) => {
            init_tracing_at("info");
            multi_thread()?.block_on(daemon::run(db, args))
        }
        Command::Proxy(args) => {
            init_tracing_at("info");
            multi_thread()?.block_on(proxy::run(args))
        }
        Command::Hook(args) => hook::run(args),
        Command::Init(args) => init::run(args),
        Command::Restore => init::restore(),
        Command::Policy => init::show_policy(),
    }
}

/// The shim relays on one thread: an extra worker would buy nothing and cost a
/// context switch on every frame.
fn current_thread() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

fn multi_thread() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

pub(crate) fn init_tracing() {
    init_tracing_at("warn");
}

pub(crate) fn init_tracing_at(default: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("MCPWALL_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
