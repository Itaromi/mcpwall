//! Protocole du socket Unix.
//!
//! JSON délimité par retour ligne, comme MCP lui-même — un seul découpeur à
//! maintenir, et un protocole qu'on peut lire avec `nc` en cas de doute.
//!
//! ## Deux rôles sur le même socket
//!
//! - Le **shim** demande des verdicts.
//! - L'**UI** s'abonne aux demandes de confirmation et y répond.
//!
//! Un même daemon sert les deux. Les messages sont étiquetés par un champ
//! `type` plutôt que distingués par leur forme : une réponse d'UI et une
//! demande de verdict n'ont aucune raison de se ressembler, et un protocole
//! qu'on désambiguïse par devinette finit toujours par se tromper.
//!
//! ## Le handshake, et pourquoi il existe malgré le binaire unique
//!
//! Le binaire unique supprime la dérive de version *du disque*, pas celle *des
//! processus*. Un client MCP resté ouvert depuis avant une mise à jour fait
//! encore tourner l'ancien shim, qui parlera à un daemon neuf. Le premier
//! message de chaque connexion porte donc la version du protocole ; en cas
//! d'incompatibilité le shim passe en **fail-open** et écrit un avertissement
//! visible, plutôt que de mal interpréter des verdicts.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Version du protocole IPC. À incrémenter dès qu'un champ change de sens.
///
/// Passée à 2 en M2 : l'ajout du flux de confirmation change la forme des
/// messages. Rien n'étant encore publié, personne n'en souffre — mais c'est
/// exactement le mécanisme qui protégera les mises à jour suivantes.
pub const IPC_VERSION: u32 = 2;

/// Identifiant de build. Deux processus de builds différents peuvent parler le
/// même protocole ; on le transmet pour le diagnostic, pas pour rejeter.
pub fn build_id() -> &'static str {
    option_env!("MCPWALL_BUILD").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Premier message, dans les deux sens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub mcpwall_ipc: u32,
    pub build: String,
    /// Délai maximal que le daemon peut mettre à rendre un verdict, annoncé
    /// par lui seul.
    ///
    /// Le shim doit en dériver le sien. Sans cette annonce il faudrait le
    /// deviner — et un shim qui abandonne avant que l'utilisateur ait cliqué
    /// **laisse passer** l'appel : toute règle `ask` se dégraderait en `allow`
    /// dès que la personne réfléchit quelques secondes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_timeout_seconds: Option<u64>,
}

impl Default for Hello {
    fn default() -> Self {
        Self {
            mcpwall_ipc: IPC_VERSION,
            build: build_id().to_owned(),
            ask_timeout_seconds: None,
        }
    }
}

impl Hello {
    /// Peut-on se comprendre ?
    ///
    /// Égalité stricte. Une compatibilité ascendante approximative serait pire
    /// que le refus : un verdict mal interprété, c'est soit un blocage
    /// fantôme, soit un trou dans le pare-feu.
    pub fn compatible(&self) -> bool {
        self.mcpwall_ipc == IPC_VERSION
    }
}

// ---------------------------------------------------------------------------
// Client → daemon
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Le shim demande un verdict.
    Decide(Box<DecideRequest>),
    /// L'UI s'annonce et reçoit désormais les demandes de confirmation.
    Subscribe,
    /// L'UI répond à une demande.
    Answer(Answer),
    /// L'UI demande l'état courant (compteurs du popover).
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideRequest {
    pub method: String,
    /// Frame MCP complète. Le daemon en extrait ce dont il a besoin ; le shim
    /// ne préjuge pas de ce qui sera pertinent.
    pub frame: String,
    pub scope_key: String,
    pub scope_source: String,
    pub scope_paths: Vec<PathBuf>,
    pub server: Option<String>,
    pub session_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Answer {
    /// Identifiant de la demande à laquelle on répond.
    pub prompt_id: u64,
    pub allow: bool,
    /// Portée de la décision. Le daemon **refuse** `forever` si la provenance
    /// du scope ne le permet pas, même si l'UI le demande : l'interface est un
    /// client comme un autre, pas une autorité.
    pub until: Until,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Until {
    #[default]
    Once,
    Session,
    Forever,
}

// ---------------------------------------------------------------------------
// Daemon → client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Réponse à un [`ClientMessage::Decide`].
    Verdict(DecideResponse),
    /// Demande de confirmation envoyée à l'UI.
    Prompt(Box<Prompt>),
    /// Une demande n'est plus d'actualité : expirée, ou la session est morte.
    /// L'UI doit fermer le panneau correspondant sans rien décider.
    Withdraw { prompt_id: u64 },
    /// Réponse à [`ClientMessage::Status`].
    Status(Status),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideResponse {
    pub outcome: Outcome,
    pub rule: Option<String>,
    pub message: String,
    /// La portée `forever` est-elle offrable pour ce scope ?
    ///
    /// Calculée par le daemon à partir de la provenance et transmise pour que
    /// l'UI n'ait pas à refaire le raisonnement — et ne puisse pas se tromper
    /// en le refaisant.
    #[serde(default)]
    pub forever_allowed: bool,
}

/// Ce que le panneau de décision affiche.
///
/// Tout ce qu'il faut pour décider sans avoir à aller chercher ailleurs : si
/// l'utilisateur doit ouvrir le journal pour comprendre une demande, il
/// cliquera « autoriser » à la place.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    pub prompt_id: u64,
    pub method: String,
    pub tool: Option<String>,
    pub server: Option<String>,
    /// Extrait des arguments, tronqué. Ne contient jamais la valeur d'un secret.
    pub preview: String,
    pub rule: Option<String>,
    pub severity: String,
    pub message: String,
    /// Détails de ce qui a été repéré — type de secret, origine d'une teinte.
    #[serde(default)]
    pub findings: Vec<String>,
    pub scope_key: String,
    pub scope_source: String,
    /// Si faux, l'UI ne doit pas proposer « Toujours autoriser ».
    pub forever_allowed: bool,
    /// Secondes restantes avant expiration, à l'émission.
    pub timeout_seconds: u64,
}

/// Compteurs du popover.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    pub calls_today: i64,
    pub blocked_today: i64,
    pub active_sessions: i64,
    pub pending_prompts: i64,
    /// Entrées de journal perdues. « 47 entrées perdues aujourd'hui » est une
    /// information que l'utilisateur a le droit d'avoir.
    pub dropped_entries: u64,
    pub policy_path: String,
    pub ui_connected: bool,
}

/// Chemin du socket.
pub fn socket_path() -> PathBuf {
    crate::journal::home_dir()
        .join(".mcpwall")
        .join("daemon.sock")
}

pub fn policy_path() -> PathBuf {
    crate::journal::home_dir()
        .join(".mcpwall")
        .join("policy.yaml")
}
