//! Protocole du socket Unix entre shim et daemon.
//!
//! JSON délimité par retour ligne, comme MCP lui-même — un seul découpeur à
//! maintenir, et un protocole qu'on peut lire avec `nc` en cas de doute.
//!
//! ## Le handshake, et pourquoi il existe malgré le binaire unique
//!
//! Le binaire unique supprime la dérive de version *du disque*, pas celle *des
//! processus*. Un client MCP resté ouvert depuis avant une mise à jour fait
//! encore tourner l'ancien shim, qui parlera à un daemon neuf. Le premier
//! message de chaque connexion porte donc la version du protocole et le
//! `build` ; en cas d'incompatibilité le shim passe en **fail-open** et écrit
//! un avertissement visible, plutôt que de mal interpréter des verdicts.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Version du protocole IPC. À incrémenter dès qu'un champ change de sens.
pub const IPC_VERSION: u32 = 1;

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
}

impl Default for Hello {
    fn default() -> Self {
        Self {
            mcpwall_ipc: IPC_VERSION,
            build: build_id().to_owned(),
        }
    }
}

impl Hello {
    /// Peut-on se comprendre ?
    ///
    /// Égalité stricte de version. Une compatibilité ascendante approximative
    /// serait pire que le refus : un verdict mal interprété, c'est soit un
    /// blocage fantôme, soit un trou dans le pare-feu.
    pub fn compatible(&self) -> bool {
        self.mcpwall_ipc == IPC_VERSION
    }
}

/// Demande de verdict.
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Allow,
    Deny,
}

/// Réponse du daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideResponse {
    pub outcome: Outcome,
    pub rule: Option<String>,
    pub message: String,
    /// La portée `forever` est-elle offrable pour ce scope ?
    ///
    /// Calculée par le daemon à partir de la provenance et transmise au shim
    /// pour que l'UI n'ait pas à refaire le raisonnement — et ne puisse pas se
    /// tromper en le refaisant.
    #[serde(default)]
    pub forever_allowed: bool,
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
