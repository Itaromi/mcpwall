//! Unix socket protocol.
//!
//! Newline-delimited JSON, like MCP itself — one splitter to maintain, and a
//! protocol you can read with `nc` when in doubt.
//!
//! ## Two roles on the same socket
//!
//! - The **shim** asks for verdicts.
//! - The **UI** subscribes to confirmation prompts and answers them.
//!
//! One daemon serves both. Messages are tagged by a `type` field rather than
//! told apart by their shape: a UI answer and a verdict request have no reason
//! to resemble each other, and a protocol disambiguated by guesswork always
//! ends up guessing wrong.
//!
//! ## The handshake, and why it exists despite the single binary
//!
//! The single binary removes version drift *on disk*, not *between processes*.
//! An MCP client left open from before an update is still running the old shim,
//! which will talk to a fresh daemon. The first message of every connection
//! therefore carries the protocol version; on incompatibility the shim goes
//! **fail-open** and writes a visible warning, rather than misreading verdicts.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// IPC protocol version. Bump it as soon as any field changes meaning.
///
/// Raised to 2 in M2: adding the confirmation flow changes the shape of the
/// messages. Nothing is published yet, so nobody suffers for it — but this is
/// exactly the mechanism that will protect later updates.
pub const IPC_VERSION: u32 = 2;

/// Build identifier. Two processes from different builds may well speak the
/// same protocol; we pass it along for diagnostics, not to reject.
pub fn build_id() -> &'static str {
    option_env!("MCPWALL_BUILD").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// First message, in both directions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub mcpwall_ipc: u32,
    pub build: String,
    /// Longest the daemon may take to produce a verdict, announced by it alone.
    ///
    /// The shim must derive its own from this. Without the announcement it
    /// would have to guess — and a shim that gives up before the user has
    /// clicked **lets the call through**: every `ask` rule would decay into
    /// `allow` as soon as the person thinks for a few seconds.
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
    /// Can we understand each other?
    ///
    /// Strict equality. Approximate forward compatibility would be worse than
    /// refusal: a misread verdict is either a phantom block or a hole in the
    /// firewall.
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
    /// The shim asks for a verdict.
    Decide(Box<DecideRequest>),
    /// The UI announces itself and from now on receives confirmation prompts.
    Subscribe,
    /// The UI answers a prompt.
    Answer(Answer),
    /// The UI asks for current state (the popover counters).
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideRequest {
    pub method: String,
    /// The complete MCP frame. The daemon extracts what it needs; the shim does
    /// not presume what will turn out to be relevant.
    pub frame: String,
    pub scope_key: String,
    pub scope_source: String,
    pub scope_paths: Vec<PathBuf>,
    pub server: Option<String>,
    pub session_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Answer {
    /// Identifier of the prompt being answered.
    pub prompt_id: u64,
    pub allow: bool,
    /// Scope of the decision. The daemon **refuses** `forever` when the scope's
    /// provenance does not warrant it, even if the UI asks for it: the
    /// interface is a client like any other, not an authority.
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
    /// Answer to a [`ClientMessage::Decide`].
    Verdict(DecideResponse),
    /// Confirmation prompt sent to the UI.
    Prompt(Box<Prompt>),
    /// A prompt is no longer current: expired, or its session died. The UI must
    /// close the corresponding panel without deciding anything.
    Withdraw { prompt_id: u64 },
    /// Answer to [`ClientMessage::Status`].
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
    /// Is the `forever` scope offerable for this scope?
    ///
    /// Computed by the daemon from the provenance and passed along so the UI
    /// need not redo the reasoning — and cannot get it wrong by redoing it.
    #[serde(default)]
    pub forever_allowed: bool,
}

/// What the decision panel displays.
///
/// Everything needed to decide without having to look elsewhere: if the user
/// has to open the journal to understand a prompt, they will click "allow"
/// instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    pub prompt_id: u64,
    pub method: String,
    pub tool: Option<String>,
    pub server: Option<String>,
    /// Excerpt of the arguments, truncated. Never contains a secret's value.
    pub preview: String,
    pub rule: Option<String>,
    pub severity: String,
    pub message: String,
    /// Details of what was spotted — kind of secret, origin of a taint.
    #[serde(default)]
    pub findings: Vec<String>,
    pub scope_key: String,
    pub scope_source: String,
    /// If false, the UI must not offer "Always allow".
    pub forever_allowed: bool,
    /// Seconds left before expiry, as of emission.
    pub timeout_seconds: u64,
}

/// Popover counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    pub calls_today: i64,
    pub blocked_today: i64,
    pub active_sessions: i64,
    pub pending_prompts: i64,
    /// Journal entries lost. "47 entries lost today" is information the user is
    /// entitled to have.
    pub dropped_entries: u64,
    pub policy_path: String,
    pub ui_connected: bool,
}

/// Socket path.
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
