#![forbid(unsafe_code)]

//! Binaire unique. Le shim, le daemon et les commandes d'administration sont
//! des sous-commandes d'un même exécutable — un seul artefact à embarquer dans
//! l'app, un seul lien symbolique, et aucune dérive de version possible entre
//! shim et daemon.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

use mcpwall::journal::{self, Journal};
use mcpwall::mcp::AllowAll;
use mcpwall::observer::JournalObserver;
use mcpwall::session::{SessionConfig, run};

#[derive(Parser)]
#[command(
    name = "mcpwall",
    about = "Pare-feu applicatif local pour agents de code",
    version
)]
struct Cli {
    /// Base de journal. Par défaut `~/.mcpwall/journal.db`.
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enveloppe un serveur MCP stdio et journalise son trafic.
    Wrap(WrapArgs),
    /// Consulte le journal.
    Log(LogArgs),
}

#[derive(Args)]
struct WrapArgs {
    /// Projet auquel rattacher la session.
    ///
    /// Écrit par `mcpwall init` dans la configuration du client. C'est le
    /// maillon le plus fiable de la chaîne de provenance : déterministe et
    /// identique sur tous les clients, là où le cwd hérité change de sens selon
    /// qui lance le shim.
    #[arg(long)]
    project: Option<PathBuf>,

    /// Commande du serveur amont, après `--`.
    #[arg(last = true, required = true)]
    command: Vec<OsString>,
}

#[derive(Args)]
struct LogArgs {
    /// Nombre de lignes.
    #[arg(short = 'n', long, default_value_t = 20)]
    tail: i64,

    /// Suit le journal en continu.
    #[arg(short, long)]
    follow: bool,

    /// Compteurs plutôt que lignes.
    #[arg(long)]
    stats: bool,

    /// Une ligne JSON par entrée.
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db = cli.db.clone().unwrap_or_else(journal::default_db_path);

    match cli.command {
        // Le shim écrit ses diagnostics sur stderr, jamais sur stdout : stdout
        // appartient au protocole, et y écrire un octet parasite casserait la
        // session.
        Command::Wrap(args) => {
            init_tracing();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(cmd_wrap(db, args))?;
            std::process::exit(code);
        }
        Command::Log(args) => cmd_log(db, args),
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("MCPWALL_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn cmd_wrap(db: PathBuf, args: WrapArgs) -> Result<i32> {
    let mut command = args.command.into_iter();
    let Some(program) = command.next() else {
        bail!("commande amont manquante après `--`");
    };
    let rest: Vec<OsString> = command.collect();

    let display = std::iter::once(&program)
        .chain(rest.iter())
        .map(|s| s.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");

    // Une panne de journal ne doit pas empêcher le serveur MCP de démarrer :
    // on dégrade en relais nu plutôt que de casser la session.
    let (journal, writer) = match Journal::open(&db) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(erreur = %e, "journal indisponible, relais sans journalisation");
            Journal::open_in_memory()?
        }
    };

    let observer = JournalObserver::new(journal.clone(), display, args.project.clone()).await;

    let mut config = SessionConfig::new(program, rest);
    config.project = args.project;

    let code = run(
        config,
        tokio::io::stdin(),
        tokio::io::stdout(),
        observer.clone(),
        Arc::new(AllowAll),
    )
    .await?;

    // La session est finie : on garantit que tout est écrit avant de rendre la
    // main, sinon les dernières entrées seraient perdues à la sortie.
    journal.flush().await;
    let dropped = journal.dropped();
    drop(journal);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer).await;

    if dropped > 0 {
        tracing::warn!(perdues = dropped, "entrées de journal perdues");
    }
    Ok(code)
}

fn cmd_log(db: PathBuf, args: LogArgs) -> Result<()> {
    if !db.exists() {
        println!("aucun journal en {} — rien à afficher", db.display());
        return Ok(());
    }
    let conn = journal::open_readonly(&db)?;

    if args.stats {
        let s = journal::stats(&conn)?;
        println!("sessions        {}", s.sessions);
        println!("appels          {}", s.entries);
        println!("bloqués         {}", s.denied);
        println!("en attente      {}", s.asked);
        if !s.servers.is_empty() {
            println!("\nserveurs");
            for (name, n) in &s.servers {
                println!("  {n:>8}  {name}");
            }
        }
        if !s.by_method.is_empty() {
            println!("\nméthodes");
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
        Some("deny") => "  BLOQUÉ",
        Some("ask") => "  ATTENTE",
        _ => "",
    };
    println!(
        "{}  {arrow} {:<28} {:<12} {}{}",
        hhmmss(line.ts_ms),
        line.method.as_deref().unwrap_or("(réponse)"),
        line.server.as_deref().unwrap_or("?"),
        line.scope_key,
        verdict
    );
}

/// Heure approchée sans dépendance de calendrier : on n'a besoin que de situer
/// une ligne dans la journée.
fn hhmmss(ms: i64) -> String {
    let secs = ms / 1000;
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}")
}
