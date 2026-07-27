//! Client du daemon, côté shim.
//!
//! Implémente [`DecisionPoint`] par-dessus le socket Unix. C'est le seul
//! endroit où mcpwall peut casser la session d'un utilisateur pour une raison
//! qui ne le regarde pas — un daemon arrêté, une mise à jour en cours — donc
//! c'est ici que la règle de disponibilité §4 s'applique le plus littéralement.
//!
//! ## Pourquoi un thread système et pas une tâche
//!
//! Retenir une frame avant qu'elle n'atteigne l'amont impose que le verdict
//! soit rendu **avant** que le relais poursuive : le point de décision est donc
//! synchrone, appelé depuis le corps d'une pompe async. Si l'I/O du socket
//! vivait sur le même exécuteur, l'attente du verdict bloquerait la tâche qui
//! doit produire ce verdict — un interblocage garanti sur un runtime
//! mono-thread.
//!
//! La connexion vit donc sur un thread système dédié, en I/O bloquante, et le
//! dialogue passe par des canaux `std`. Le relais bloque son thread, le socket
//! progresse sur le sien.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crate::ipc::{ClientMessage, DecideRequest, DecideResponse, Hello, Outcome, ServerMessage};
use crate::mcp::{CallContext, DecisionError, DecisionPoint, Verdict};
use crate::scope::Scope;

/// Délai d'attente d'un verdict quand le daemon n'annonce rien.
///
/// Filet de sécurité pour un daemon vivant mais bloqué, cas que le handshake ne
/// détecte pas. Il ne doit **jamais** être plus court que le temps qu'un
/// utilisateur met à répondre à une demande de confirmation : abandonner trop
/// tôt fait passer l'appel, donc transforme une règle `ask` en `allow` dès que
/// la personne réfléchit. D'où la dérivation à partir du délai annoncé par le
/// daemon dans son hello, et cette valeur seulement en dernier recours.
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(180);

/// Marge ajoutée au délai annoncé par le daemon.
///
/// Le daemon garantit une réponse dans son propre délai ; la marge couvre le
/// trajet et l'ordonnancement, pas l'hésitation de l'utilisateur.
const TIMEOUT_MARGIN: Duration = Duration::from_secs(30);

type Pending = (DecideRequest, mpsc::Sender<Option<DecideResponse>>);

pub struct DaemonClient {
    tx: mpsc::Sender<Pending>,
    /// Le daemon a-t-il déjà été jugé injoignable ?
    ///
    /// Un shim qui a perdu le daemon ne retente pas à chaque appel : ce serait
    /// payer un timeout par outil pour rien.
    degraded: AtomicBool,
    fail_closed: bool,
    session: SessionInfo,
    /// Dérivé du hello du daemon.
    timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct SessionInfo {
    pub scope_key: String,
    pub scope_source: String,
    pub scope_paths: Vec<PathBuf>,
    pub server: Option<String>,
    pub session_id: i64,
}

impl SessionInfo {
    pub fn from_scope(scope: &Scope, session_id: i64) -> Self {
        Self {
            scope_key: scope.key(),
            scope_source: scope.source().as_str().to_owned(),
            scope_paths: scope.paths().to_vec(),
            server: None,
            session_id,
        }
    }
}

impl DaemonClient {
    /// Se connecte et effectue le handshake.
    ///
    /// Rend `None` si le daemon est absent ou parle une autre version : le
    /// shim relaie alors sans politique. C'est un mode dégradé assumé, pas une
    /// erreur — l'app peut être fermée, et fermer l'app ne doit pas paralyser
    /// les serveurs MCP de l'utilisateur.
    pub fn connect(socket: &Path, fail_closed: bool, session: SessionInfo) -> Option<Self> {
        let stream = match UnixStream::connect(socket) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    socket = %socket.display(),
                    erreur = %e,
                    "daemon injoignable — relais sans politique"
                );
                return None;
            }
        };
        // Court pendant le handshake : un daemon qui n'y répond pas est mort,
        // il n'y a personne à attendre. Le délai est rallongé juste après, une
        // fois qu'on sait combien de temps un verdict peut prendre.
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok()?;

        let mut write = stream.try_clone().ok()?;
        let stream_ref = stream.try_clone().ok()?;
        let mut lines = BufReader::new(stream).lines();

        let mine = Hello::default();
        writeln!(write, "{}", serde_json::to_string(&mine).ok()?).ok()?;

        let reply = lines.next()?.ok()?;
        let peer: Hello = serde_json::from_str(&reply).ok()?;

        if !peer.compatible() {
            // Visible exprès : c'est le cas du client MCP resté ouvert pendant
            // une mise à jour, et l'utilisateur doit comprendre pourquoi son
            // pare-feu ne filtre plus.
            tracing::error!(
                shim = mine.mcpwall_ipc,
                daemon = peer.mcpwall_ipc,
                build_daemon = %peer.build,
                "version IPC incompatible — mcpwall NE FILTRE PAS cette session. \
                 Redémarrez le client MCP pour reprendre un shim à jour."
            );
            return None;
        }

        // Le daemon annonce le temps qu'il peut mettre à répondre — il attend
        // l'utilisateur, pas la machine. Abandonner avant lui ferait passer
        // l'appel en silence.
        let timeout = peer
            .ask_timeout_seconds
            .map(|s| Duration::from_secs(s) + TIMEOUT_MARGIN)
            .unwrap_or(FALLBACK_TIMEOUT);
        stream_ref.set_read_timeout(Some(timeout)).ok()?;

        let (tx, rx) = mpsc::channel::<Pending>();

        // Un seul thread possède la connexion : les requêtes sont sérialisées
        // naturellement, sans verrou.
        std::thread::Builder::new()
            .name("mcpwall-ipc".into())
            .spawn(move || {
                for (req, reply) in rx {
                    let response = (|| {
                        let msg = ClientMessage::Decide(Box::new(req));
                        let payload = serde_json::to_string(&msg).ok()?;
                        writeln!(write, "{payload}").ok()?;
                        write.flush().ok()?;

                        // Le shim ne s'abonne pas aux demandes de confirmation :
                        // tout ce qui n'est pas un verdict sur cette connexion
                        // est une anomalie de protocole, pas un message à
                        // interpréter au mieux.
                        let line = lines.next()?.ok()?;
                        match serde_json::from_str::<ServerMessage>(&line).ok()? {
                            ServerMessage::Verdict(v) => Some(v),
                            other => {
                                tracing::warn!(
                                    reçu = ?std::mem::discriminant(&other),
                                    "message inattendu à la place d'un verdict"
                                );
                                None
                            }
                        }
                    })();

                    let failed = response.is_none();
                    let _ = reply.send(response);
                    if failed {
                        break; // connexion morte, les appelants basculeront en dégradé
                    }
                }
            })
            .ok()?;

        Some(Self {
            tx,
            degraded: AtomicBool::new(false),
            fail_closed,
            session,
            timeout,
        })
    }

    pub fn set_server(&mut self, server: Option<String>) {
        self.session.server = server;
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    fn error(&self, reason: &str) -> DecisionError {
        DecisionError {
            reason: reason.to_owned(),
            fail_closed: self.fail_closed,
        }
    }
}

impl DecisionPoint for DaemonClient {
    fn decide(&self, ctx: &CallContext<'_>) -> Result<Verdict, DecisionError> {
        if self.degraded.load(Ordering::Relaxed) {
            return Err(self.error("daemon injoignable (état dégradé)"));
        }

        let req = DecideRequest {
            method: ctx.method.to_owned(),
            frame: String::from_utf8_lossy(ctx.frame).into_owned(),
            scope_key: self.session.scope_key.clone(),
            scope_source: self.session.scope_source.clone(),
            scope_paths: self.session.scope_paths.clone(),
            server: self.session.server.clone(),
            session_id: self.session.session_id,
        };

        let (tx, rx) = mpsc::channel();
        if self.tx.send((req, tx)).is_err() {
            self.degraded.store(true, Ordering::Relaxed);
            return Err(self.error("connexion au daemon fermée"));
        }

        let response = match rx.recv_timeout(self.timeout) {
            Ok(Some(r)) => r,
            Ok(None) => {
                self.degraded.store(true, Ordering::Relaxed);
                return Err(self.error("réponse illisible du daemon"));
            }
            Err(_) => {
                self.degraded.store(true, Ordering::Relaxed);
                return Err(self.error("délai dépassé en attente du verdict"));
            }
        };

        Ok(match response.outcome {
            Outcome::Allow => Verdict::Allow,
            Outcome::Deny => Verdict::Deny {
                rule: response.rule.unwrap_or_else(|| "policy".to_owned()),
                message: response.message,
            },
        })
    }
}

impl DaemonClient {
    /// Délai effectif, dérivé du hello du daemon.
    pub fn decide_timeout(&self) -> Duration {
        self.timeout
    }
}
