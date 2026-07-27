//! Le daemon : un seul par machine, hébergé par l'app en M2.
//!
//! Il ne fait que trois choses — évaluer la politique, tenir les overrides de
//! session, et répondre. Tout le reste (relais, journal de trafic) appartient
//! au shim, ce qui garde le daemon assez petit pour qu'une panne y soit rare et
//! qu'une panne y soit survivable.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::ipc::{DecideRequest, DecideResponse, Hello, Outcome};
use crate::policy::{Action, Policy, request_from_frame};
use crate::scope::{Scope, ScopeSource};

pub struct Daemon {
    policy: Mutex<Policy>,
}

impl Daemon {
    pub fn new(policy: Policy) -> Arc<Self> {
        Arc::new(Self {
            policy: Mutex::new(policy),
        })
    }

    /// Écoute sur le socket jusqu'à interruption.
    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // `sockaddr_un.sun_path` fait 104 octets sur macOS, 108 sur Linux. Le
        // dépassement remonte sinon en « path must be shorter than SUN_LEN »,
        // qui n'aide personne. Le chemin par défaut tient largement ; c'est un
        // `--socket` inhabituel ou un home très profond qui déclenche ce cas.
        const SUN_PATH_MAX: usize = 100;
        if socket.as_os_str().len() > SUN_PATH_MAX {
            anyhow::bail!(
                "chemin de socket trop long ({} octets, maximum {SUN_PATH_MAX}) : {}\n\
                 Choisissez un chemin plus court avec --socket.",
                socket.as_os_str().len(),
                socket.display()
            );
        }

        // Un socket résiduel d'un daemon mort empêcherait le bind. On ne le
        // supprime qu'après avoir vérifié que personne ne répond dessus, sinon
        // on volerait le socket d'un daemon vivant.
        if socket.exists() {
            match UnixStream::connect(socket).await {
                Ok(_) => anyhow::bail!(
                    "un daemon écoute déjà sur {} — un seul par machine",
                    socket.display()
                ),
                Err(_) => {
                    std::fs::remove_file(socket).ok();
                }
            }
        }

        let listener = UnixListener::bind(socket)
            .with_context(|| format!("écoute sur {}", socket.display()))?;

        // Le socket ne doit être lisible que par son propriétaire : y écrire,
        // c'est décider des verdicts de sécurité de l'utilisateur.
        restrict_permissions(socket);

        tracing::info!(socket = %socket.display(), "daemon en écoute");

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(erreur = %e, "connexion refusée");
                    continue;
                }
            };
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle(stream).await {
                    tracing::debug!(erreur = %e, "connexion terminée");
                }
            });
        }
    }

    async fn handle(&self, stream: UnixStream) -> Result<()> {
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();

        // Handshake d'abord, verdicts ensuite.
        let Some(first) = lines.next_line().await? else {
            return Ok(());
        };
        let peer: Hello = serde_json::from_str(&first).context("hello illisible")?;

        let mine = Hello::default();
        write
            .write_all(format!("{}\n", serde_json::to_string(&mine)?).as_bytes())
            .await?;

        if !peer.compatible() {
            tracing::warn!(
                shim = peer.mcpwall_ipc,
                daemon = mine.mcpwall_ipc,
                build_shim = %peer.build,
                "version IPC incompatible, le shim passera en fail-open"
            );
            return Ok(());
        }

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let req: DecideRequest = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(erreur = %e, "requête illisible");
                    continue;
                }
            };
            let resp = self.decide(&req).await;
            write
                .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
                .await?;
        }
        Ok(())
    }

    async fn decide(&self, req: &DecideRequest) -> DecideResponse {
        let mut policy = self.policy.lock().await;
        policy.reload_if_changed();

        let source = match req.scope_source.as_str() {
            "injected" => ScopeSource::Injected,
            "roots" => ScopeSource::Roots,
            "cwd" => ScopeSource::Cwd,
            _ => ScopeSource::Unknown,
        };
        let scope = Scope::new(source, req.scope_paths.clone());

        let mut tool_buf = String::new();
        let mut request =
            request_from_frame(&req.method, req.frame.as_bytes(), &scope, &mut tool_buf);
        request.scope_key = &req.scope_key;

        let decision = policy.evaluate(&request);
        let forever_allowed = scope.allows_forever();

        // En M1 il n'y a pas encore d'UI pour répondre à un `ask` : on refuse
        // en attendant, plutôt que d'autoriser en silence. C'est le seul point
        // où mcpwall est volontairement plus strict que sa configuration, et ce
        // sera corrigé par le panneau de décision de M2.
        let outcome = match decision.action {
            Action::Allow => Outcome::Allow,
            Action::Deny | Action::Ask => Outcome::Deny,
        };

        let message = if decision.action == Action::Ask {
            format!(
                "{} (en attente de confirmation — l'interface arrive en M2)",
                decision.agent_message()
            )
        } else {
            decision.agent_message()
        };

        if outcome == Outcome::Deny {
            tracing::info!(
                méthode = %req.method,
                outil = request.tool.unwrap_or("-"),
                règle = decision.rule.as_deref().unwrap_or("-"),
                "appel bloqué"
            );
        }

        DecideResponse {
            outcome,
            rule: decision.rule,
            message,
            forever_allowed,
        }
    }
}

#[cfg(unix)]
fn restrict_permissions(socket: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_socket: &Path) {}

/// Point d'entrée de `mcpwall daemon`.
pub async fn run(socket: PathBuf, policy_path: PathBuf) -> Result<()> {
    let policy = Policy::load_or_create(&policy_path)?;
    tracing::info!(politique = %policy_path.display(), "politique chargée");

    let daemon = Daemon::new(policy);
    let socket_for_cleanup = socket.clone();

    // Le socket doit disparaître à l'arrêt, sinon le prochain démarrage croit
    // qu'un daemon tourne déjà.
    let result = tokio::select! {
        r = daemon.serve(&socket) => r,
        _ = shutdown_signal() => {
            tracing::info!("arrêt demandé");
            Ok(())
        }
    };

    std::fs::remove_file(&socket_for_cleanup).ok();
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        let mut int = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    std::future::pending().await
}
