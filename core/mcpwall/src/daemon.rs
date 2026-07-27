//! Le daemon : un seul par machine, lancé et supervisé par l'app en M2.
//!
//! Il fait quatre choses — évaluer la politique, demander confirmation quand
//! elle le réclame, tenir les décisions déjà prises, et répondre. Tout le reste
//! (relais, journal de trafic) appartient au shim, ce qui garde le daemon assez
//! petit pour qu'une panne y soit rare et surtout survivable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::ipc::{
    Answer, ClientMessage, DecideRequest, DecideResponse, Hello, Outcome, Prompt, ServerMessage,
    Status, Until,
};
use crate::policy::{Action, Decision, Policy, request_from_frame};
use crate::scope::{Scope, ScopeSource};

/// Capacité du canal de diffusion vers les UI.
///
/// Une seule UI en pratique. La marge absorbe une rafale de demandes pendant
/// qu'un panneau est déjà ouvert.
const PROMPT_CHANNEL: usize = 64;

/// Décision enregistrée par l'utilisateur.
#[derive(Debug, Clone)]
struct Override {
    scope_key: String,
    tool: String,
    allow: bool,
}

impl Override {
    fn matches(&self, scope_key: &str, tool: Option<&str>) -> bool {
        self.scope_key == scope_key && Some(self.tool.as_str()) == tool
    }
}

#[derive(Default)]
struct State {
    /// Décisions de portée `session`, oubliées à l'arrêt du daemon.
    session_overrides: Vec<Override>,
    /// Demandes en attente de réponse d'une UI.
    pending: HashMap<u64, oneshot::Sender<Answer>>,
    /// Nombre d'UI abonnées.
    subscribers: usize,
}

pub struct Daemon {
    policy: Mutex<Policy>,
    policy_path: Option<PathBuf>,
    state: Mutex<State>,
    prompts: broadcast::Sender<ServerMessage>,
    next_prompt_id: AtomicU64,
    journal_db: PathBuf,
}

impl Daemon {
    pub fn new(policy: Policy, policy_path: Option<PathBuf>, journal_db: PathBuf) -> Arc<Self> {
        let (prompts, _) = broadcast::channel(PROMPT_CHANNEL);
        Arc::new(Self {
            policy: Mutex::new(policy),
            policy_path,
            state: Mutex::new(State::default()),
            prompts,
            next_prompt_id: AtomicU64::new(1),
            journal_db,
        })
    }

    /// Écoute sur le socket jusqu'à interruption.
    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // `sockaddr_un.sun_path` fait 104 octets sur macOS, 108 sur Linux. Le
        // dépassement remonte sinon en « path must be shorter than SUN_LEN »,
        // qui n'aide personne.
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

        // Le socket ne doit être accessible qu'à son propriétaire : y écrire,
        // c'est décider des verdicts de sécurité de quelqu'un.
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

    async fn handle(self: Arc<Self>, stream: UnixStream) -> Result<()> {
        let (read, write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let write = Arc::new(Mutex::new(write));

        // Handshake d'abord, tout le reste ensuite.
        let Some(first) = lines.next_line().await? else {
            return Ok(());
        };
        let peer: Hello = serde_json::from_str(&first).context("hello illisible")?;

        // On annonce combien de temps un verdict peut prendre, pour que le pair
        // ne renonce pas pendant qu'on attend l'utilisateur.
        let mine = Hello {
            ask_timeout_seconds: Some(self.policy.lock().await.ask_timeout().as_secs()),
            ..Hello::default()
        };
        send_raw(&write, &serde_json::to_string(&mine)?).await?;

        if !peer.compatible() {
            tracing::warn!(
                pair = peer.mcpwall_ipc,
                daemon = mine.mcpwall_ipc,
                build_pair = %peer.build,
                "version IPC incompatible, la connexion passera en fail-open"
            );
            return Ok(());
        }

        let mut subscribed = false;

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let msg: ClientMessage = match serde_json::from_str(&line) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(erreur = %e, "message illisible");
                    continue;
                }
            };

            match msg {
                ClientMessage::Decide(req) => {
                    let resp = self.clone().decide(&req).await;
                    send(&write, &ServerMessage::Verdict(resp)).await?;
                }

                ClientMessage::Subscribe => {
                    if subscribed {
                        continue;
                    }
                    subscribed = true;
                    self.state.lock().await.subscribers += 1;
                    tracing::info!("interface connectée");

                    // Les demandes partent en tâche dédiée : le daemon ne doit
                    // jamais attendre qu'une UI lise pour continuer à servir
                    // les shims.
                    let mut rx = self.prompts.subscribe();
                    let w = write.clone();
                    tokio::spawn(async move {
                        while let Ok(msg) = rx.recv().await {
                            if send(&w, &msg).await.is_err() {
                                break;
                            }
                        }
                    });
                }

                ClientMessage::Answer(answer) => {
                    let mut st = self.state.lock().await;
                    if let Some(tx) = st.pending.remove(&answer.prompt_id) {
                        let _ = tx.send(answer);
                    } else {
                        // Réponse à une demande expirée. Sans trace, l'utilisateur
                        // croirait avoir décidé quelque chose qui n'a pas eu lieu.
                        tracing::info!(
                            prompt_id = answer.prompt_id,
                            "réponse à une demande déjà expirée, ignorée"
                        );
                    }
                }

                ClientMessage::Status => {
                    let status = self.status().await;
                    send(&write, &ServerMessage::Status(status)).await?;
                }
            }
        }

        if subscribed {
            let mut st = self.state.lock().await;
            st.subscribers = st.subscribers.saturating_sub(1);
            tracing::info!("interface déconnectée");
        }
        Ok(())
    }

    async fn decide(self: Arc<Self>, req: &DecideRequest) -> DecideResponse {
        let (decision, scope, tool, timeout) = {
            let mut policy = self.policy.lock().await;
            policy.reload_if_changed();

            let source = parse_source(&req.scope_source);
            let scope = Scope::new(source, req.scope_paths.clone());

            let mut tool_buf = String::new();
            let mut request =
                request_from_frame(&req.method, req.frame.as_bytes(), &scope, &mut tool_buf);
            request.scope_key = &req.scope_key;

            let decision = policy.evaluate(&request);
            let tool = request.tool.map(str::to_owned);
            (decision, scope, tool, policy.ask_timeout())
        };

        let forever_allowed = scope.allows_forever();

        // Une décision déjà prise par l'utilisateur ne lui est pas redemandée.
        if let Some(ov) = self
            .matching_override(&req.scope_key, tool.as_deref())
            .await
        {
            return DecideResponse {
                outcome: if ov { Outcome::Allow } else { Outcome::Deny },
                rule: Some("override".to_owned()),
                message: "décision enregistrée pour ce projet".to_owned(),
                forever_allowed,
            };
        }

        match decision.action {
            Action::Allow => DecideResponse {
                outcome: Outcome::Allow,
                rule: decision.rule,
                message: decision.message,
                forever_allowed,
            },
            Action::Deny => {
                tracing::info!(
                    méthode = %req.method,
                    outil = tool.as_deref().unwrap_or("-"),
                    règle = decision.rule.as_deref().unwrap_or("-"),
                    "appel bloqué"
                );
                DecideResponse {
                    outcome: Outcome::Deny,
                    message: decision.agent_message(),
                    rule: decision.rule,
                    forever_allowed,
                }
            }
            Action::Ask => {
                self.ask(req, &decision, tool.as_deref(), forever_allowed, timeout)
                    .await
            }
        }
    }

    /// Demande confirmation à l'utilisateur.
    async fn ask(
        self: Arc<Self>,
        req: &DecideRequest,
        decision: &Decision,
        tool: Option<&str>,
        forever_allowed: bool,
        timeout: std::time::Duration,
    ) -> DecideResponse {
        let deny = |message: String| DecideResponse {
            outcome: Outcome::Deny,
            rule: decision.rule.clone(),
            message,
            forever_allowed,
        };

        // Sans interface, personne ne peut répondre. On refuse plutôt que
        // d'autoriser en silence — mais on le dit à l'agent, pour qu'il ne
        // conclue pas à une panne de l'outil.
        if self.state.lock().await.subscribers == 0 {
            return deny(format!(
                "{} (aucune interface pour confirmer — lancez l'application mcpwall)",
                decision.agent_message()
            ));
        }

        let prompt_id = self.next_prompt_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.state.lock().await.pending.insert(prompt_id, tx);

        let prompt = Prompt {
            prompt_id,
            method: req.method.clone(),
            tool: tool.map(str::to_owned),
            server: req.server.clone(),
            preview: preview(&req.frame),
            rule: decision.rule.clone(),
            severity: format!("{:?}", decision.severity).to_lowercase(),
            message: decision.message.clone(),
            findings: decision.findings.iter().map(|f| f.describe()).collect(),
            scope_key: req.scope_key.clone(),
            scope_source: req.scope_source.clone(),
            forever_allowed,
            timeout_seconds: timeout.as_secs(),
        };

        if self
            .prompts
            .send(ServerMessage::Prompt(Box::new(prompt)))
            .is_err()
        {
            self.state.lock().await.pending.remove(&prompt_id);
            return deny(format!(
                "{} (interface injoignable)",
                decision.agent_message()
            ));
        }

        let answer = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(a)) => a,
            _ => {
                // Expiration ou UI disparue. On retire la demande et on prévient
                // l'interface pour qu'elle ferme le panneau plutôt que de laisser
                // un bouton qui ne fera plus rien.
                self.state.lock().await.pending.remove(&prompt_id);
                let _ = self.prompts.send(ServerMessage::Withdraw { prompt_id });
                return deny(format!(
                    "{} (délai de confirmation dépassé)",
                    decision.agent_message()
                ));
            }
        };

        // `forever` est refusé si la provenance du scope ne le permet pas, même
        // si l'UI le demande. L'interface est un client, pas une autorité : une
        // permission permanente accordée sur un scope incertain fuirait vers
        // d'autres projets.
        let until = match answer.until {
            Until::Forever if !forever_allowed => {
                tracing::warn!(
                    scope = %req.scope_key,
                    provenance = %req.scope_source,
                    "portée `forever` demandée sur un scope non fiable, rétrogradée en `session`"
                );
                Until::Session
            }
            other => other,
        };

        if let Some(tool) = tool {
            self.record_override(&req.scope_key, tool, answer.allow, until)
                .await;
        }

        if answer.allow {
            DecideResponse {
                outcome: Outcome::Allow,
                rule: decision.rule.clone(),
                message: "autorisé par l'utilisateur".to_owned(),
                forever_allowed,
            }
        } else {
            deny(format!(
                "{} (refusé par l'utilisateur)",
                decision.agent_message()
            ))
        }
    }

    async fn matching_override(&self, scope_key: &str, tool: Option<&str>) -> Option<bool> {
        let st = self.state.lock().await;
        st.session_overrides
            .iter()
            .find(|o| o.matches(scope_key, tool))
            .map(|o| o.allow)
    }

    async fn record_override(&self, scope_key: &str, tool: &str, allow: bool, until: Until) {
        match until {
            // Rien à retenir : la décision ne valait que pour cet appel.
            Until::Once => {}
            Until::Session => {
                self.state.lock().await.session_overrides.push(Override {
                    scope_key: scope_key.to_owned(),
                    tool: tool.to_owned(),
                    allow,
                });
            }
            Until::Forever => {
                // En mémoire d'abord, pour que la décision s'applique même si
                // l'écriture du fichier échoue.
                self.state.lock().await.session_overrides.push(Override {
                    scope_key: scope_key.to_owned(),
                    tool: tool.to_owned(),
                    allow,
                });
                if let Some(path) = &self.policy_path
                    && let Err(e) = crate::policy::append_override(path, scope_key, tool, allow)
                {
                    tracing::error!(erreur = %e, "override permanent non persisté");
                }
            }
        }
    }

    async fn status(&self) -> Status {
        let st = self.state.lock().await;
        let (calls_today, blocked_today, active_sessions) =
            crate::journal::today_counters(&self.journal_db).unwrap_or((0, 0, 0));

        Status {
            calls_today,
            blocked_today,
            active_sessions,
            pending_prompts: st.pending.len() as i64,
            dropped_entries: 0,
            policy_path: self
                .policy_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            ui_connected: st.subscribers > 0,
        }
    }
}

fn parse_source(s: &str) -> ScopeSource {
    match s {
        "injected" => ScopeSource::Injected,
        "roots" => ScopeSource::Roots,
        "cwd" => ScopeSource::Cwd,
        _ => ScopeSource::Unknown,
    }
}

/// Extrait lisible des arguments, tronqué.
///
/// Le panneau doit montrer assez pour décider, pas le message entier — et
/// jamais la valeur d'un secret, que le moteur remplace déjà par son type et un
/// préfixe dans `findings`.
fn preview(frame: &str) -> String {
    const MAX: usize = 400;
    let Ok(v) = serde_json::from_str::<serde_json::Value>(frame) else {
        return frame.chars().take(MAX).collect();
    };
    let params = v
        .get("params")
        .and_then(|p| p.get("arguments").or(Some(p)))
        .map(|p| p.to_string())
        .unwrap_or_default();
    params.chars().take(MAX).collect()
}

async fn send(
    write: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    msg: &ServerMessage,
) -> Result<()> {
    send_raw(write, &serde_json::to_string(msg)?).await
}

async fn send_raw(
    write: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    payload: &str,
) -> Result<()> {
    let mut w = write.lock().await;
    w.write_all(format!("{payload}\n").as_bytes()).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(socket: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_socket: &Path) {}

/// Point d'entrée de `mcpwall daemon`.
pub async fn run(socket: PathBuf, policy_path: PathBuf, journal_db: PathBuf) -> Result<()> {
    let policy = Policy::load_or_create(&policy_path)?;
    tracing::info!(politique = %policy_path.display(), "politique chargée");

    let daemon = Daemon::new(policy, Some(policy_path), journal_db);
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
