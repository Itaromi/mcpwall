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

use mcpwall::client::{DaemonClient, SessionInfo};
use mcpwall::journal::{self, Journal};
use mcpwall::mcp::{AllowAll, DecisionPoint};
use mcpwall::observer::JournalObserver;
use mcpwall::session::{SessionConfig, run};
use mcpwall::{daemon, ipc, policy, setup};

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
    /// Lance le daemon de politique. Un seul par machine.
    ///
    /// En M2 c'est l'app macOS qui le lance et le supervise comme processus
    /// enfant : elle ne le réimplémente pas.
    Daemon(DaemonArgs),
    /// Installe mcpwall dans les configurations MCP existantes.
    Init(InitArgs),
    /// Remet les configurations en état depuis les sauvegardes.
    Restore,
    /// Affiche la politique effective et vérifie sa syntaxe.
    Policy,
}

#[derive(Args)]
struct DaemonArgs {
    /// Socket d'écoute.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Fichier de politique. Créé avec les règles par défaut s'il manque.
    #[arg(long)]
    policy: Option<PathBuf>,
}

#[derive(Args)]
struct InitArgs {
    /// Écrit réellement. Sans ce drapeau, `init` se contente d'afficher le diff.
    #[arg(long)]
    apply: bool,

    /// Projets supplémentaires où chercher un `.mcp.json`.
    #[arg(long = "project", value_name = "CHEMIN")]
    projects: Vec<PathBuf>,
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

    /// Socket du daemon. Par défaut `~/.mcpwall/daemon.sock`.
    #[arg(long)]
    socket: Option<PathBuf>,

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

    // Le point de décision est le daemon s'il répond, sinon rien. L'absence de
    // daemon dégrade en observation seule : c'est la règle de disponibilité §4,
    // et c'est ce qui permet de fermer l'app sans paralyser les serveurs MCP.
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

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

fn cmd_init(args: InitArgs) -> Result<()> {
    // Le lien symbolique d'abord : les configs doivent pointer vers lui, jamais
    // vers le chemin du bundle, sinon déplacer l'app casse tout.
    let exe = std::env::current_exe()?;
    let shim = setup::ensure_shim_link(&exe)?;
    println!("shim  {} -> {}", shim.display(), exe.display());

    let targets = setup::discover(&args.projects);
    if targets.is_empty() {
        println!("\naucune configuration MCP trouvée.");
        return Ok(());
    }

    let mut plans = Vec::new();
    for t in &targets {
        match setup::plan(t, &shim) {
            Ok(p) => plans.push(p),
            Err(e) => println!("\n{}  ignoré : {e}", t.path.display()),
        }
    }

    let mut total = 0;
    for p in &plans {
        if p.is_noop() {
            if !p.already.is_empty() {
                println!(
                    "\n{}  déjà enveloppé ({})",
                    p.path.display(),
                    p.already.len()
                );
            }
            continue;
        }
        total += p.wrapped.len();
        println!("\n{}  [{}]", p.path.display(), p.kind.label());
        println!("  serveurs : {}", p.wrapped.join(", "));
        for line in setup::diff(&p.before, &p.after).lines() {
            println!("  {line}");
        }
    }

    if total == 0 {
        println!("\nrien à faire.");
        return Ok(());
    }

    if !args.apply {
        // Rien n'est écrit sans que le diff ait été montré et accepté.
        println!("\n{total} serveur(s) à envelopper. Relancez avec --apply pour écrire.");
        return Ok(());
    }

    for p in &plans {
        if p.is_noop() {
            continue;
        }
        let backup = setup::apply(p)?;
        println!(
            "écrit  {}  (sauvegarde {})",
            p.path.display(),
            backup.display()
        );
    }

    println!("\nRedémarrez vos clients MCP pour que la nouvelle configuration prenne effet.");
    println!("`mcpwall restore` remet tout en état.");
    Ok(())
}

fn cmd_restore() -> Result<()> {
    let restored = setup::restore()?;
    if restored.is_empty() {
        println!("aucune sauvegarde trouvée.");
        return Ok(());
    }
    for p in restored {
        println!("restauré  {}", p.display());
    }
    Ok(())
}

fn cmd_policy() -> Result<()> {
    let path = ipc::policy_path();
    let policy = policy::Policy::load_or_create(&path)?;
    println!("politique      {}", path.display());
    println!("défaut         {}", policy.default_action().as_str());
    println!("fail_closed    {}", policy.fail_closed());
    println!("ask_timeout    {:?}", policy.ask_timeout());
    println!("\nsyntaxe valide.");
    Ok(())
}
