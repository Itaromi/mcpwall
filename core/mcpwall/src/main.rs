#![forbid(unsafe_code)]

//! A single binary. The shim, the daemon and the administrative commands are
//! subcommands of one executable — a single artefact to embed in the app, a
//! single symlink, and no possible version drift between shim and daemon.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

use mcpwall::ipc::client::{DaemonClient, SessionInfo};
use mcpwall::journal::{self, Journal};
use mcpwall::protocol::mcp::{AllowAll, DecisionPoint};
use mcpwall::transport::http;
use mcpwall::transport::observer::JournalObserver;
use mcpwall::transport::session::{SessionConfig, run};
use mcpwall::{daemon, hook, ipc, setup};

#[derive(Parser)]
#[command(
    name = "mcpwall",
    about = "Local application firewall for coding agents",
    version
)]
struct Cli {
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

#[derive(Args)]
struct DaemonArgs {
    /// Socket to listen on.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Policy file. Created with the default rules if missing.
    #[arg(long)]
    policy: Option<PathBuf>,
}

#[derive(Args)]
struct ProxyArgs {
    /// Route table. Defaults to `~/.mcpwall/routes.json`, written by `init`.
    #[arg(long)]
    routes: Option<PathBuf>,

    /// Address to listen on. Overrides what the route table declares.
    #[arg(long)]
    listen: Option<String>,

    /// Daemon socket. Defaults to `~/.mcpwall/daemon.sock`.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct HookArgs {
    /// Project this hook was installed for.
    ///
    /// Written by `mcpwall init` when it installs the hook into a project's
    /// settings, and left out when it installs into `~/.claude/settings.json`,
    /// which serves every project at once. Without it the scope falls back to
    /// the `cwd` the hook reports — rank 3 of §6bis, where "always allow" is
    /// not offered.
    #[arg(long)]
    project: Option<PathBuf>,

    /// Daemon socket. Defaults to `~/.mcpwall/daemon.sock`.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct InitArgs {
    /// Actually write. Without this flag, `init` only prints the diff.
    #[arg(long)]
    apply: bool,

    /// Extra projects to search for a `.mcp.json`.
    #[arg(long = "project", value_name = "PATH")]
    projects: Vec<PathBuf>,
}

#[derive(Args)]
struct WrapArgs {
    /// Project this session belongs to.
    ///
    /// Written by `mcpwall init` into the client configuration. It is the most
    /// trustworthy link of the provenance chain: deterministic and identical
    /// across clients, where the inherited cwd changes meaning depending on who
    /// starts the shim.
    #[arg(long)]
    project: Option<PathBuf>,

    /// Daemon socket. Defaults to `~/.mcpwall/daemon.sock`.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Upstream server command, after `--`.
    #[arg(last = true, required = true)]
    command: Vec<OsString>,
}

#[derive(Args)]
struct LogArgs {
    /// Number of lines.
    #[arg(short = 'n', long, default_value_t = 20)]
    tail: i64,

    /// Follow the journal continuously.
    #[arg(short, long)]
    follow: bool,

    /// Counters instead of lines.
    #[arg(long)]
    stats: bool,

    /// One JSON line per entry.
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db = cli.db.clone().unwrap_or_else(journal::default_db_path);

    match cli.command {
        // The shim writes its diagnostics to stderr, never to stdout: stdout
        // belongs to the protocol, and writing one stray byte there would
        // break the session.
        Command::Wrap(args) => {
            init_tracing();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(cmd_wrap(db, args))?;
            std::process::exit(code);
        }
        Command::Log(args) => cmd_log(db, args),
        Command::Daemon(args) => {
            init_tracing_at("info");
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(daemon::run(
                args.socket.unwrap_or_else(ipc::socket_path),
                args.policy.unwrap_or_else(ipc::policy_path),
                db,
            ))
        }
        Command::Proxy(args) => {
            init_tracing_at("info");
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_proxy(db, args))
        }
        Command::Hook(args) => cmd_hook(args),
        Command::Init(args) => cmd_init(args),
        Command::Restore => cmd_restore(),
        Command::Policy => cmd_policy(),
    }
}

fn init_tracing() {
    init_tracing_at("warn");
}

fn init_tracing_at(default: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("MCPWALL_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn cmd_wrap(db: PathBuf, args: WrapArgs) -> Result<i32> {
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

    let code = run(
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

fn cmd_log(db: PathBuf, args: LogArgs) -> Result<()> {
    if !db.exists() {
        println!("no journal at {} — nothing to show", db.display());
        return Ok(());
    }
    let conn = journal::open_readonly(&db)?;

    if args.stats {
        let s = journal::stats(&conn)?;
        println!("sessions        {}", s.sessions);
        println!("calls           {}", s.entries);
        println!("blocked         {}", s.denied);
        println!("pending         {}", s.asked);
        if !s.servers.is_empty() {
            println!("\nservers");
            for (name, n) in &s.servers {
                println!("  {n:>8}  {name}");
            }
        }
        if !s.by_method.is_empty() {
            println!("\nmethods");
            for (m, n) in &s.by_method {
                println!("  {n:>8}  {m}");
            }
        }
        return Ok(());
    }

    let mut last = 0i64;
    for (id, line) in journal::tail(&conn, args.tail, 0)? {
        print_line(&line, args.json);
        last = last.max(id);
    }

    if args.follow {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(300));
            for (id, line) in journal::tail(&conn, 500, last)? {
                print_line(&line, args.json);
                last = last.max(id);
            }
        }
    }
    Ok(())
}

fn print_line(line: &journal::LogLine, as_json: bool) {
    if as_json {
        let v = serde_json::json!({
            "ts_ms": line.ts_ms,
            "direction": line.direction,
            "method": line.method,
            "disposition": line.disposition,
            "verdict": line.verdict,
            "rule": line.rule,
            "server": line.server,
            "scope": line.scope_key,
            "scope_source": line.scope_source,
            "bytes": line.bytes,
        });
        println!("{v}");
        return;
    }

    let arrow = if line.direction == "to_server" {
        "->"
    } else {
        "<-"
    };
    let verdict = match line.verdict.as_deref() {
        Some("deny") => "  BLOCKED",
        Some("ask") => "  PENDING",
        _ => "",
    };
    println!(
        "{}  {arrow} {:<28} {:<12} {}{}",
        hhmmss(line.ts_ms),
        line.method.as_deref().unwrap_or("(response)"),
        line.server.as_deref().unwrap_or("?"),
        line.scope_key,
        verdict
    );
}

/// Approximate clock time with no calendar dependency: all we need is to place
/// a line within the day.
fn hhmmss(ms: i64) -> String {
    let secs = ms / 1000;
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}")
}

// ---------------------------------------------------------------------------
// Streamable HTTP
// ---------------------------------------------------------------------------

async fn cmd_proxy(_db: PathBuf, args: ProxyArgs) -> Result<()> {
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
    let decision: Arc<dyn mcpwall::protocol::mcp::DecisionPoint> = match DaemonClient::connect(
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

// ---------------------------------------------------------------------------
// Claude Code hook
// ---------------------------------------------------------------------------

/// Always exits 0, always with valid stdout or none at all.
///
/// Exit 2 would block the tool call, and every path that reaches it here is one
/// where mcpwall failed to have an opinion — an unparseable payload, an absent
/// daemon, an event we do not handle. Turning our own failure into a refusal of
/// the user's work is the one behaviour §4 rules out. The hook stays silent and
/// lets Claude Code's ordinary permission flow proceed.
fn cmd_hook(args: HookArgs) -> Result<()> {
    // Diagnostics go to stderr, which Claude Code surfaces without treating it
    // as a decision. Nothing but a verdict may ever reach stdout.
    init_tracing();

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

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

fn cmd_init(args: InitArgs) -> Result<()> {
    // The symlink first: configs must point at it, never at the bundle path,
    // otherwise moving the app breaks everything.
    let exe = std::env::current_exe()?;
    let shim = setup::ensure_shim_link(&exe)?;
    println!("shim  {} -> {}", shim.display(), exe.display());

    // HTTP servers are pointed at the local proxy rather than wrapped, so the
    // address it listens on has to be known before the diff is computed. An
    // existing route table keeps its address: the user may have moved it off
    // the default port, and `init` changing it under them would silently
    // break every URL it wrote last time.
    let routes_path = ipc::routes_path();
    let mut table = if routes_path.exists() {
        http::RouteTable::load(&routes_path)?
    } else {
        http::RouteTable::default()
    };
    let listen = table.listen.clone();

    let targets = setup::discover(&args.projects);
    let mut plans = Vec::new();
    for t in &targets {
        match setup::plan(t, &shim, &listen) {
            Ok(p) => plans.push(p),
            Err(e) => println!("\n{}  skipped: {e}", t.path.display()),
        }
    }

    // The hook is planned even when no MCP configuration was found: the
    // built-in tools it covers exist whether or not the user has a single MCP
    // server, and they are most of the attack surface. Returning early on "no
    // MCP configuration" would have left the biggest hole open on exactly the
    // machines that look like they have nothing to protect.
    match setup::plan_hook(&setup::claude_settings_path(), &shim) {
        Ok(p) => plans.push(p),
        Err(e) => println!("\nClaude Code hooks skipped: {e}"),
    }

    if plans.is_empty() {
        println!("\nnothing to configure.");
        return Ok(());
    }

    let mut total = 0;
    for p in &plans {
        // A hook plan lists events, a configuration plan lists servers. Saying
        // "servers: PreToolUse" would be a small lie in the one place the user
        // is being asked to trust us with their files.
        let noun = match p.kind {
            setup::Kind::ClaudeHooks => "events",
            _ => "servers",
        };
        if p.is_noop() {
            if !p.already.is_empty() {
                println!(
                    "\n{}  already installed ({})",
                    p.path.display(),
                    p.already.join(", ")
                );
            }
            report_uncovered(p);
            continue;
        }
        total += p.wrapped.len();
        println!("\n{}  [{}]", p.path.display(), p.kind.label());
        println!("  {noun}: {}", p.wrapped.join(", "));
        report_uncovered(p);
        for line in setup::diff(&p.before, &p.after).lines() {
            println!("  {line}");
        }
    }

    // Said once more at the end, and said in full. Per-file lines scroll away
    // behind the diffs; the number of servers left unprotected is the one thing
    // the user must not miss.
    let uncovered: Vec<_> = plans.iter().flat_map(|p| p.uncovered.iter()).collect();
    if !uncovered.is_empty() {
        println!("\n{} server(s) NOT covered by mcpwall:", uncovered.len());
        for u in &uncovered {
            println!("  {}  — {}", u.name, u.reason);
        }
        println!("  Their traffic goes straight through. See the coverage table in the README.");
    }

    if total == 0 {
        println!("\nnothing to do.");
        return Ok(());
    }

    if !args.apply {
        // Nothing is written before the diff has been shown and accepted.
        println!("\n{total} change(s) to make. Re-run with --apply to write.");
        return Ok(());
    }

    for p in &plans {
        if p.is_noop() {
            continue;
        }
        let backup = setup::apply(p)?;
        println!("wrote  {}  (backup {})", p.path.display(), backup.display());
    }

    // The route table last: a configuration pointing at a proxy that does not
    // know the route yet is a broken server, and this ordering keeps that
    // window to the width of one file write.
    let routes: Vec<_> = plans.iter().flat_map(|p| p.routes.iter()).collect();
    if !routes.is_empty() {
        for (name, upstream) in &routes {
            table.routes.insert((*name).clone(), (*upstream).clone());
        }
        if let Some(dir) = routes_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&routes_path, serde_json::to_string_pretty(&table)? + "\n")?;
        println!(
            "wrote  {}  ({} route(s))",
            routes_path.display(),
            routes.len()
        );
        println!(
            "\n⚠️  The {} HTTP server(s) above now go through the local proxy on {}.\n   \
             Unlike the stdio servers, they are unreachable while it is stopped: an HTTP\n   \
             client connects to a URL, so there is no way to interpose without being in\n   \
             the path. The app supervises it; `mcpwall restore` puts the URLs back.",
            routes.len(),
            table.listen
        );
    }

    println!("\nRestart your MCP clients for the new configuration to take effect.");
    println!("`mcpwall restore` puts everything back.");
    Ok(())
}

/// Names the servers a file leaves unprotected, next to the ones it protects.
/// An absence from the `servers:` line reads as "nothing else here", which is
/// exactly the wrong conclusion.
fn report_uncovered(p: &setup::Plan) {
    for u in &p.uncovered {
        println!("  not covered: {}  ({})", u.name, u.reason);
    }
}

fn cmd_restore() -> Result<()> {
    let restored = setup::restore()?;
    if restored.is_empty() {
        println!("no backup found.");
        return Ok(());
    }
    for p in restored {
        println!("restored  {}", p.display());
    }
    Ok(())
}

fn cmd_policy() -> Result<()> {
    let path = ipc::policy_path();
    let policy = daemon::policy::Policy::load_or_create(&path)?;
    println!("policy         {}", path.display());
    println!("default        {}", policy.default_action().as_str());
    println!("fail_closed    {}", policy.fail_closed());
    println!("ask_timeout    {:?}", policy.ask_timeout());
    println!("\nsyntax valid.");
    Ok(())
}
