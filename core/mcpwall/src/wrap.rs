//! Relais stdio entre un client MCP et un serveur MCP amont.
//!
//! Premier module à I/O du core, et le seul dont une erreur casse une vraie
//! session d'agent. Trois règles y sont tenues sans exception :
//!
//! 1. **Aucun `unwrap()`, aucune panique.** Une panique du shim, c'est la
//!    session de l'utilisateur qui meurt.
//! 2. **On réémet les octets reçus**, via [`Frame::raw`]. Jamais du JSON
//!    reconstruit.
//! 3. **Un échec d'inspection ne casse pas le relais.** Frame incomprise,
//!    dépassement de plafond, observateur en difficulté : le trafic continue.
//!    C'est la règle de disponibilité §4 appliquée au plus bas niveau.
//!
//! Le relais est générique sur `AsyncRead`/`AsyncWrite` et ne connaît ni SQLite
//! ni processus : il se teste avec des tampons en mémoire.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::frame::{Frame, FrameError, FrameSplitter, SplitterStats};
use crate::mcp::{
    CallContext, DecisionPoint, Disposition, MethodScan, Verdict, classify, deny_response,
    scan_method,
};

/// Taille des lectures. Un tampon de pipe fait typiquement 64 Ko.
const READ_BUF: usize = 64 * 1024;

/// Sens de circulation d'une frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client → serveur amont. C'est le sens où l'on peut bloquer.
    ToServer,
    /// Serveur amont → client.
    ToClient,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToServer => "to_server",
            Self::ToClient => "to_client",
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Une frame observée, avec ce qu'on en a compris.
pub struct FrameEvent<'a> {
    pub direction: Direction,
    pub disposition: Disposition,
    /// `None` pour une réponse, ou pour une frame dont la méthode n'a pas pu
    /// être lue — [`FrameEvent::scan`] dit lequel des deux.
    pub method: Option<&'a str>,
    pub scan: &'a MethodScan,
    /// Renseigné uniquement pour les frames passées par le point de décision.
    pub verdict: Option<&'a Verdict>,
    pub frame: &'a Frame,
}

/// Ce qui n'aurait pas dû arriver mais dont on ne meurt pas.
#[derive(Debug)]
pub enum Anomaly {
    /// Frame dépassant le plafond. Les octets sont jetés, jamais relayés.
    Oversize { direction: Direction, limit: usize },
    /// Flux terminé sur une frame sans délimiteur.
    Unterminated { direction: Direction },
    /// Frame bloquée qui n'attend aucune réponse : rien à renvoyer au client.
    DeniedWithoutId { direction: Direction },
    /// Le point de décision n'a pas pu se prononcer. Le trafic est passé — ou
    /// a été bloqué si `fail_closed` est actif.
    DecisionUnavailable {
        direction: Direction,
        reason: String,
        fail_closed: bool,
    },
}

/// Destination de tout ce que le relais observe.
///
/// En M0 c'est le journal SQLite. Les méthodes ne rendent rien : un observateur
/// n'a aucun moyen d'interrompre le relais, par construction.
pub trait Observer: Send + Sync {
    fn on_frame(&self, event: &FrameEvent<'_>);

    fn on_anomaly(&self, anomaly: &Anomaly) {
        let _ = anomaly;
    }

    /// Fin de flux, avec les compteurs du découpeur.
    fn on_eof(&self, direction: Direction, stats: SplitterStats) {
        let _ = (direction, stats);
    }
}

/// Observateur qui jette tout. Utile pour mesurer le coût du relais nu.
pub struct NullObserver;

impl Observer for NullObserver {
    fn on_frame(&self, _event: &FrameEvent<'_>) {}
}

/// Configuration d'une pompe.
pub struct Pump {
    pub direction: Direction,
    pub max_frame_bytes: usize,
    pub observer: Arc<dyn Observer>,
    pub decision: Arc<dyn DecisionPoint>,
    /// Voie de retour pour les réponses de blocage.
    ///
    /// Un `deny` intervient sur une frame qui monte vers le serveur, mais la
    /// réponse doit redescendre vers le client — c'est-à-dire sortir par
    /// **l'autre** pompe. D'où ce canal entre les deux. Sans lui, bloquer
    /// laisserait le client attendre indéfiniment une réponse qui ne vient pas.
    pub denied_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

impl Pump {
    /// Relaie `reader` vers `writer` jusqu'à la fin du flux.
    ///
    /// `injected` alimente le flux sortant en frames qui ne viennent pas de
    /// `reader` — les réponses de blocage fabriquées par l'autre pompe.
    pub async fn run<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        mut injected: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    ) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut splitter = FrameSplitter::new(self.max_frame_bytes);
        let mut buf = vec![0u8; READ_BUF];

        loop {
            let read = match &mut injected {
                // Les deux sources sont concurrentes : une réponse de blocage ne
                // doit pas attendre que l'amont daigne écrire quelque chose.
                Some(rx) => tokio::select! {
                    biased;
                    Some(payload) = rx.recv() => {
                        writer.write_all(&payload).await?;
                        writer.flush().await?;
                        continue;
                    }
                    r = reader.read(&mut buf) => r?,
                },
                None => reader.read(&mut buf).await?,
            };

            if read == 0 {
                break;
            }

            splitter.push(&buf[..read]);

            let mut wrote = false;
            while let Some(result) = splitter.next_frame() {
                match result {
                    Ok(frame) => {
                        if self.handle(&frame, &mut writer).await? {
                            wrote = true;
                        }
                    }
                    Err(FrameError::Oversize { limit }) => {
                        // Les octets sont déjà jetés par le découpeur, rien ne
                        // part vers le pair. On note et on continue : le
                        // découpeur se resynchronise au prochain délimiteur.
                        self.observer.on_anomaly(&Anomaly::Oversize {
                            direction: self.direction,
                            limit,
                        });
                    }
                }
            }

            // Un seul flush par lecture plutôt qu'un par frame : six frames dans
            // un même read() ne doivent pas coûter six syscalls.
            if wrote {
                writer.flush().await?;
            }
        }

        // Dernière frame sans délimiteur : on la relaie quand même — perdre le
        // dernier message d'une session serait pire — mais en ajoutant le
        // terminateur, faute de quoi le pair attendrait la suite indéfiniment.
        if let Some(frame) = splitter.finish() {
            self.observer.on_anomaly(&Anomaly::Unterminated {
                direction: self.direction,
            });
            if self.handle(&frame, &mut writer).await? {
                if !frame.is_terminated() {
                    writer.write_all(b"\n").await?;
                }
                writer.flush().await?;
            }
        }

        self.observer.on_eof(self.direction, splitter.stats());
        Ok(())
    }

    /// Inspecte, décide, relaie. Rend `true` si quelque chose a été écrit.
    async fn handle<W>(&self, frame: &Frame, writer: &mut W) -> io::Result<bool>
    where
        W: AsyncWrite + Unpin,
    {
        let scan = scan_method(frame.content());
        let disposition = classify(&scan);
        let method = match &scan {
            MethodScan::Found { method, .. } => Some(method.as_str()),
            _ => None,
        };

        // Seul le sens montant passe par le point de décision, et seulement pour
        // l'ensemble DECIDE. Tout le reste évite l'appel entièrement.
        let verdict = match (self.direction, disposition, method) {
            (Direction::ToServer, Disposition::Decide, Some(m)) => {
                let ctx = CallContext {
                    method: m,
                    frame: frame.content(),
                };
                match self.decision.decide(&ctx) {
                    Ok(v) => Some(v),
                    // Le point de décision n'a pas su répondre. On ne panique
                    // pas, on ne devine pas : par défaut le trafic passe, et
                    // l'incident est signalé. Casser la session d'un agent
                    // parce que notre propre daemon est tombé serait le pire
                    // arbitrage possible — sauf si l'utilisateur a explicitement
                    // demandé `fail_closed`.
                    Err(err) => {
                        let fail_closed = err.fail_closed;
                        self.observer.on_anomaly(&Anomaly::DecisionUnavailable {
                            direction: self.direction,
                            reason: err.reason,
                            fail_closed,
                        });
                        fail_closed.then(|| Verdict::Deny {
                            rule: "fail_closed".to_owned(),
                            message: "policy engine unavailable".to_owned(),
                        })
                    }
                }
            }
            _ => None,
        };

        self.observer.on_frame(&FrameEvent {
            direction: self.direction,
            disposition,
            method,
            scan: &scan,
            verdict: verdict.as_ref(),
            frame,
        });

        match &verdict {
            Some(Verdict::Deny { rule, message }) => {
                // La frame n'atteint jamais l'amont. La réponse part par la voie
                // de retour, pas par ce writer.
                match deny_response(frame.content(), rule, message) {
                    Some(payload) => {
                        if let Some(tx) = &self.denied_tx {
                            // L'échec d'envoi signifie que l'autre pompe est
                            // déjà terminée : la session se ferme, il n'y a plus
                            // personne pour lire la réponse.
                            let _ = tx.send(payload);
                        }
                    }
                    None => self.observer.on_anomaly(&Anomaly::DeniedWithoutId {
                        direction: self.direction,
                    }),
                }
                Ok(false)
            }
            _ => {
                writer.write_all(frame.raw()).await?;
                Ok(true)
            }
        }
    }
}
