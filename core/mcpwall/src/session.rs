//! Cycle de vie d'une session stdio : lancer l'amont, câbler les pompes,
//! mourir proprement.
//!
//! C'est ici que ce projet casse des sessions réelles s'il est mal écrit. Les
//! quatre modes de défaillance, et ce qu'on en fait :
//!
//! - **Orphelins.** Le client tue le shim ; sans relais de signal, le serveur
//!   amont survit. Trente `node` fantômes après une journée de travail, et
//!   mcpwall est le coupable désigné. On relaie `SIGTERM`/`SIGINT`, puis on
//!   escalade en `SIGKILL` après délai.
//! - **Suspension.** L'amont meurt, le shim reste bloqué sur une lecture qui ne
//!   rendra jamais rien. On surveille le processus en parallèle des pompes.
//! - **Interblocage par contre-pression.** Une tâche par direction, strictement
//!   indépendantes, aucun verrou détenu à travers un `await`. Une réponse de
//!   8 Mo dans un sens ne doit pas empêcher l'autre de progresser.
//! - **Code de sortie perdu.** Le client lit le code de sortie du shim ; il doit
//!   être celui de l'amont, sans quoi un serveur qui échoue au démarrage a l'air
//!   d'avoir réussi.
//!
//! `stderr` n'est pas pompé : il est hérité. Zéro tâche, zéro tampon, zéro
//! troisième descripteur à interbloquer, et le comportement observé est
//! exactement celui de l'amont non enveloppé.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::frame::DEFAULT_MAX_FRAME_BYTES;
use crate::mcp::DecisionPoint;
use crate::wrap::{Direction, Observer, Pump};

/// Délai laissé à l'amont pour sortir après `SIGTERM` avant `SIGKILL`.
const GRACE: Duration = Duration::from_secs(5);

/// Comment lancer et surveiller un serveur MCP amont.
pub struct SessionConfig {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub max_frame_bytes: usize,
    /// Maillon 1 de la chaîne de provenance de scope, injecté par
    /// `mcpwall init` dans la configuration du client.
    pub project: Option<PathBuf>,
}

impl SessionConfig {
    pub fn new(program: impl Into<OsString>, args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            args,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            project: None,
        }
    }
}

/// Lance l'amont, relaie, et rend son code de sortie.
///
/// `stdin`/`stdout` sont fournis par l'appelant plutôt que pris sur le processus
/// afin que les tests puissent conduire une vraie session sans détourner les
/// descripteurs du binaire de test.
pub async fn run<I, O>(
    config: SessionConfig,
    client_in: I,
    client_out: O,
    observer: Arc<dyn Observer>,
    decision: Arc<dyn DecisionPoint>,
) -> Result<i32>
where
    I: tokio::io::AsyncRead + Unpin + Send + 'static,
    O: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut child = Command::new(&config.program)
        .args(&config.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Hérité, pas pompé : le client voit les diagnostics de l'amont
        // exactement comme sans mcpwall.
        .stderr(Stdio::inherit())
        // Sans ça, l'enfant hérite du groupe de processus et reçoit le Ctrl-C du
        // terminal en même temps que nous, ce qui rend l'ordre d'arrêt
        // indéterminé. On veut être seuls maîtres de son arrêt.
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("lancement de {:?}", config.program))?;

    let child_in = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("stdin de l'amont indisponible"))?;
    let child_out = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("stdout de l'amont indisponible"))?;

    // Voie de retour des réponses de blocage : décidées en montée, écrites en
    // descente.
    let (denied_tx, denied_rx) = mpsc::unbounded_channel();

    let up = Pump {
        direction: Direction::ToServer,
        max_frame_bytes: config.max_frame_bytes,
        observer: observer.clone(),
        decision: decision.clone(),
        denied_tx: Some(denied_tx),
    };
    let down = Pump {
        direction: Direction::ToClient,
        max_frame_bytes: config.max_frame_bytes,
        observer: observer.clone(),
        decision,
        denied_tx: None,
    };

    // Deux tâches indépendantes. Aucune n'attend l'autre : une réponse amont de
    // plusieurs mégaoctets ne doit pas empêcher une requête de monter.
    let mut up_task = tokio::spawn(async move { up.run(client_in, child_in, None).await });
    let mut down_task =
        tokio::spawn(async move { down.run(child_out, client_out, Some(denied_rx)).await });

    let mut signals = Signals::new()?;

    // Trois issues possibles : l'amont sort, un signal arrive, ou le client
    // ferme stdin. On les attend toutes en parallèle.
    // Chacune des trois issues est terminale : on ne boucle pas, on attend
    // celle qui se présente la première.
    let status = tokio::select! {
        // L'amont a fini. C'est l'issue normale.
        res = child.wait() => res.context("attente de l'amont")?,

        // Le client nous tue. On transmet, on n'abandonne pas l'enfant.
        sig = signals.next() => {
            let sig = sig.unwrap_or(TermSignal::Term);
            tracing::info!(signal = sig.as_str(), "signal reçu, transmission à l'amont");
            terminate(&mut child, sig).await;
            child.wait().await.context("attente après signal")?
        }

        // Le client a fermé stdin : la pompe montante est arrivée en bout de
        // flux et a libéré le descripteur, ce qui ferme le stdin de l'amont.
        res = &mut up_task => {
            if let Ok(Err(e)) = res {
                tracing::warn!(erreur = %e, "pompe montante interrompue");
            }
            // Arrêt propre selon la spec MCP : fermer stdin, attendre, puis
            // escalader seulement si l'amont s'accroche.
            match tokio::time::timeout(GRACE, child.wait()).await {
                Ok(res) => res.context("attente après EOF client")?,
                Err(_) => {
                    tracing::warn!("l'amont n'a pas quitté après fermeture de stdin");
                    terminate(&mut child, TermSignal::Term).await;
                    child.wait().await.context("attente après escalade")?
                }
            }
        }
    };

    // L'amont est mort : on laisse un instant à la pompe descendante pour vider
    // ce qu'il a écrit avant de sortir, sinon on perdrait sa dernière réponse.
    let _ = tokio::time::timeout(Duration::from_millis(200), &mut down_task).await;
    down_task.abort();
    up_task.abort();

    Ok(exit_code(&status))
}

/// Code de sortie observable par le client.
///
/// Un processus tué par signal n'a pas de code ; la convention shell est
/// `128 + signal`. La reproduire évite qu'un amont tué ressemble à un succès.
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermSignal {
    Term,
    Int,
}

impl TermSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Term => "SIGTERM",
            Self::Int => "SIGINT",
        }
    }
}

/// Transmet le signal à l'amont, puis escalade s'il s'accroche.
///
/// L'escalade n'est pas une politesse : un serveur qui ignore `SIGTERM` et qu'on
/// n'achève pas devient exactement l'orphelin qu'on cherche à éviter.
async fn terminate(child: &mut tokio::process::Child, sig: TermSignal) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        // `Child::kill` de tokio n'envoie que SIGKILL, ce qui priverait l'amont
        // de toute chance de s'arrêter proprement — fermer ses fichiers, vider
        // ses tampons. On passe donc par `kill(2)`, via l'enveloppe sûre de
        // `nix` pour ne pas avoir à déroger au `forbid(unsafe_code)` du core.
        let raw = match sig {
            TermSignal::Term => Signal::SIGTERM,
            TermSignal::Int => Signal::SIGINT,
        };
        if let Ok(pid) = i32::try_from(pid) {
            let _ = kill(Pid::from_raw(pid), raw);
        }
    }

    if tokio::time::timeout(GRACE, child.wait()).await.is_err() {
        tracing::warn!("l'amont ignore {}, escalade en SIGKILL", sig.as_str());
        let _ = child.start_kill();
    }
}

/// Écoute `SIGTERM` et `SIGINT`.
struct Signals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
}

impl Signals {
    fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                term: signal(SignalKind::terminate()).context("écoute de SIGTERM")?,
                int: signal(SignalKind::interrupt()).context("écoute de SIGINT")?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    async fn next(&mut self) -> Option<TermSignal> {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.term.recv() => Some(TermSignal::Term),
                _ = self.int.recv() => Some(TermSignal::Int),
            }
        }
        #[cfg(not(unix))]
        std::future::pending().await
    }
}
