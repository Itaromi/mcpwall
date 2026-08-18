//! `mcpwall init`, `restore` and `policy` — onboarding.
//!
//! Nothing is written before the diff has been shown, and every write is
//! reversible with one command. Spec §8: this is where the product is won or
//! lost.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use mcpwall::transport::http;
use mcpwall::{daemon, ipc, setup};

#[derive(Args)]
pub struct InitArgs {
    /// Actually write. Without this flag, `init` only prints the diff.
    #[arg(long)]
    pub apply: bool,

    /// Extra projects to search for a `.mcp.json`.
    #[arg(long = "project", value_name = "PATH")]
    pub projects: Vec<PathBuf>,
}

pub fn run(args: InitArgs) -> Result<()> {
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

pub fn restore() -> Result<()> {
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

pub fn show_policy() -> Result<()> {
    let path = ipc::policy_path();
    let policy = daemon::policy::Policy::load_or_create(&path)?;
    println!("policy         {}", path.display());
    println!("default        {}", policy.default_action().as_str());
    println!("fail_closed    {}", policy.fail_closed());
    println!("ask_timeout    {:?}", policy.ask_timeout());
    println!("\nsyntax valid.");
    Ok(())
}
