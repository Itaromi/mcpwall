//! The daemon: one per machine, started and supervised by the app as of M2.
//!
//! It does four things — evaluate the policy, ask for confirmation when the
//! policy calls for it, hold the decisions already made, and answer. Everything
//! else (relaying, traffic journal) belongs to the shim, which keeps the daemon
//! small enough that a failure in it is rare and, above all, survivable.

pub mod policy;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::daemon::policy::{Action, Decision, Policy, request_from_frame};
use crate::ipc::{
    Answer, ClientMessage, DecideRequest, DecideResponse, Hello, Outcome, Prompt, ServerMessage,
    Status, Until,
};
use crate::protocol::scope::{Scope, ScopeSource};
use crate::protocol::taint::{Fingerprint, TaintStore, fingerprint};

/// Capacity of the broadcast channel towards the UIs.
///
/// A single UI in practice. The headroom absorbs a burst of prompts while a
/// panel is already open.
const PROMPT_CHANNEL: usize = 64;

/// A decision recorded by the user.
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
    /// `session`-scoped decisions, forgotten when the daemon stops.
    session_overrides: Vec<Override>,
    /// Prompts awaiting an answer from a UI.
    pending: HashMap<u64, oneshot::Sender<Answer>>,
    /// Number of subscribed UIs.
    subscribers: usize,
}

pub struct Daemon {
    policy: Mutex<Policy>,
    policy_path: Option<PathBuf>,
    state: Mutex<State>,
    prompts: broadcast::Sender<ServerMessage>,
    next_prompt_id: AtomicU64,
    journal_db: PathBuf,
    /// Fingerprints of recent local reads, all sessions together.
    ///
    /// Deliberately shared rather than per-session: reading in one project and
    /// exfiltrating from another is the interesting case, and a per-session
    /// store would be blind to exactly it. It holds hashes only, never content,
    /// and everything ages out after `taint::TTL`.
    taint: Mutex<TaintStore>,
    /// `server → tools whose advertisement has changed`, pending a decision.
    ///
    /// The comparison happens when a `tools/list` goes by; the rule fires when
    /// the tool is *called*, which may be several frames later. Something has to
    /// hold the answer in between, and it is small: drift is rare, and an entry
    /// leaves as soon as the call it concerns has been ruled on.
    drifted: Mutex<HashMap<String, HashSet<String>>>,
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
            taint: Mutex::new(TaintStore::new()),
            drifted: Mutex::new(HashMap::new()),
        })
    }

    /// Listens on the socket until interrupted.
    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // `sockaddr_un.sun_path` is 104 bytes on macOS, 108 on Linux. Going
        // over otherwise surfaces as "path must be shorter than SUN_LEN",
        // which helps nobody.
        const SUN_PATH_MAX: usize = 100;
        if socket.as_os_str().len() > SUN_PATH_MAX {
            anyhow::bail!(
                "socket path too long ({} bytes, maximum {SUN_PATH_MAX}): {}\n\
                 Choose a shorter path with --socket.",
                socket.as_os_str().len(),
                socket.display()
            );
        }

        // A leftover socket from a dead daemon would prevent the bind. We only
        // remove it after checking that nobody answers on it, otherwise we
        // would steal a live daemon's socket.
        if socket.exists() {
            match UnixStream::connect(socket).await {
                Ok(_) => anyhow::bail!(
                    "a daemon is already listening on {} — one per machine",
                    socket.display()
                ),
                Err(_) => {
                    std::fs::remove_file(socket).ok();
                }
            }
        }

        let listener = UnixListener::bind(socket)
            .with_context(|| format!("listening on {}", socket.display()))?;

        // The socket must be reachable only by its owner: writing to it means
        // deciding someone's security verdicts.
        restrict_permissions(socket);

        tracing::info!(socket = %socket.display(), "daemon listening");

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "connection refused");
                    continue;
                }
            };
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle(stream).await {
                    tracing::debug!(error = %e, "connection ended");
                }
            });
        }
    }

    async fn handle(self: Arc<Self>, stream: UnixStream) -> Result<()> {
        let (read, write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let write = Arc::new(Mutex::new(write));

        // Handshake first, everything else after.
        let Some(first) = lines.next_line().await? else {
            return Ok(());
        };
        let peer: Hello = serde_json::from_str(&first).context("unreadable hello")?;

        // We announce how long a verdict may take, so the peer does not give
        // up while we are waiting on the user.
        let mine = Hello {
            ask_timeout_seconds: Some(self.policy.lock().await.ask_timeout().as_secs()),
            ..Hello::default()
        };
        send_raw(&write, &serde_json::to_string(&mine)?).await?;

        if !peer.compatible() {
            tracing::warn!(
                peer = peer.mcpwall_ipc,
                daemon = mine.mcpwall_ipc,
                peer_build = %peer.build,
                "incompatible IPC version, this connection will go fail-open"
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
                    tracing::warn!(error = %e, "unreadable message");
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

                    // Prompts go out on a dedicated task: the daemon must
                    // never wait for a UI to read before it can carry on
                    // serving the shims.
                    //
                    // The receiver is created *before* the interface is
                    // counted: a broadcast only reaches receivers that already
                    // existed when it was sent. Counting first would open a
                    // window where a prompt is judged answerable, sent, and
                    // received by nobody — the shim then waits out the whole
                    // ask timeout for an answer that cannot come.
                    let mut rx = self.prompts.subscribe();
                    self.state.lock().await.subscribers += 1;
                    tracing::info!("interface connected");
                    let w = write.clone();
                    tokio::spawn(async move {
                        while let Ok(msg) = rx.recv().await {
                            if send(&w, &msg).await.is_err() {
                                break;
                            }
                        }
                    });
                }

                ClientMessage::Taint(report) => {
                    // No reply: the shim reads one line per message it expects
                    // an answer to, and an unexpected line here would be
                    // consumed as the verdict of its next call.
                    let fp = Fingerprint {
                        ngrams: report.ngrams,
                        tokens: report.tokens,
                    };
                    if !fp.is_empty() {
                        self.taint
                            .lock()
                            .await
                            .record(&fp, &report.origin, Instant::now());
                    }
                }

                ClientMessage::Tools(report) => {
                    // No reply, for the same reason as `Taint`: the shim reads
                    // one line per message it expects an answer to.
                    //
                    // The comparison touches the database, so it goes on a
                    // blocking thread. A `tools/list` carrying a hundred tools
                    // must not stall the executor that other shims' verdicts
                    // are waiting on.
                    let db = self.journal_db.clone();
                    let server = report.server.clone();
                    let tools = report.tools.clone();
                    let found = tokio::task::spawn_blocking(move || {
                        crate::journal::record_descriptions(&db, &server, &tools)
                    })
                    .await;

                    match found {
                        Ok(Ok(changed)) if !changed.is_empty() => {
                            tracing::warn!(
                                server = %report.server,
                                tools = ?changed,
                                "tool description changed since it was last seen"
                            );
                            self.drifted
                                .lock()
                                .await
                                .entry(report.server.clone())
                                .or_default()
                                .extend(changed);
                        }
                        Ok(Ok(_)) => {}
                        // Losing this costs a detection, never a session.
                        Ok(Err(e)) => tracing::warn!(error = %e, "recording tool descriptions"),
                        Err(e) => tracing::warn!(error = %e, "recording tool descriptions"),
                    }
                }

                ClientMessage::Answer(answer) => {
                    let mut st = self.state.lock().await;
                    if let Some(tx) = st.pending.remove(&answer.prompt_id) {
                        let _ = tx.send(answer);
                    } else {
                        // An answer to an expired prompt. With no record, the
                        // user would believe they decided something that never
                        // happened.
                        tracing::info!(
                            prompt_id = answer.prompt_id,
                            "answer to an already-expired prompt, ignored"
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
            tracing::info!("interface disconnected");
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

            // Is anything about to leave that was read from this machine?
            // Checked before evaluation so the rule sees a fact, not a
            // callback. The store is skipped entirely when empty, which is the
            // common case: no read, no cost on the hot path.
            request.tainted = {
                let store = self.taint.lock().await;
                if store.is_empty() {
                    None
                } else {
                    store
                        .overlap(&fingerprint(&request.values.join(" ")), Instant::now())
                        .map(|m| m.origin)
                }
            };

            // Has this tool's advertisement changed since we last saw it?
            //
            // Read here and consumed on the way out, so the same change raises
            // one prompt rather than one per call. The decision the user makes
            // is about the change, and they only get to make it once.
            request.drifted = match request.tool {
                Some(t) => self
                    .drifted
                    .lock()
                    .await
                    .get(
                        req.server
                            .as_deref()
                            .unwrap_or(crate::ipc::client::UNNAMED_SERVER),
                    )
                    .is_some_and(|set| set.contains(t)),
                None => false,
            };

            let decision = policy.evaluate(&request);

            // Consumed whatever the verdict. Leaving it set would raise the
            // same alarm about the same change on every subsequent call, and
            // an alert the user has already answered is the definition of the
            // fatigue §9 warns about.
            if request.drifted
                && let Some(t) = request.tool
                && let Some(set) = self.drifted.lock().await.get_mut(
                    req.server
                        .as_deref()
                        .unwrap_or(crate::ipc::client::UNNAMED_SERVER),
                )
            {
                set.remove(t);
            }

            let tool = request.tool.map(str::to_owned);
            (decision, scope, tool, policy.ask_timeout())
        };

        let forever_allowed = scope.allows_forever();

        // A decision the user has already made is not asked again.
        if let Some(ov) = self
            .matching_override(&req.scope_key, tool.as_deref())
            .await
        {
            return DecideResponse {
                outcome: if ov { Outcome::Allow } else { Outcome::Deny },
                rule: Some("override".to_owned()),
                message: "decision recorded for this project".to_owned(),
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
                    method = %req.method,
                    tool = tool.as_deref().unwrap_or("-"),
                    rule = decision.rule.as_deref().unwrap_or("-"),
                    "call blocked"
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

    /// Asks the user for confirmation.
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

        // With no interface, nobody can answer. We refuse rather than allow
        // silently — but we say so to the agent, so it does not conclude the
        // tool is broken.
        if self.state.lock().await.subscribers == 0 {
            return deny(format!(
                "{} (no interface to confirm with — start the mcpwall application)",
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
                "{} (interface unreachable)",
                decision.agent_message()
            ));
        }

        let answer = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(a)) => a,
            _ => {
                // Expiry, or the UI vanished. We withdraw the prompt and tell
                // the interface, so it closes the panel rather than leaving a
                // button that will no longer do anything.
                self.state.lock().await.pending.remove(&prompt_id);
                let _ = self.prompts.send(ServerMessage::Withdraw { prompt_id });
                return deny(format!(
                    "{} (confirmation timed out)",
                    decision.agent_message()
                ));
            }
        };

        // `forever` is refused when the scope's provenance does not warrant
        // it, even if the UI asks for it. The interface is a client, not an
        // authority: a permanent permission granted on an uncertain scope would
        // leak into other projects.
        let until = match answer.until {
            Until::Forever if !forever_allowed => {
                tracing::warn!(
                    scope = %req.scope_key,
                    provenance = %req.scope_source,
                    "`forever` scope requested on an untrusted scope, downgraded to `session`"
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
                message: "allowed by the user".to_owned(),
                forever_allowed,
            }
        } else {
            deny(format!("{} (denied by the user)", decision.agent_message()))
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
            // Nothing to remember: the decision applied to this call only.
            Until::Once => {}
            Until::Session => {
                self.state.lock().await.session_overrides.push(Override {
                    scope_key: scope_key.to_owned(),
                    tool: tool.to_owned(),
                    allow,
                });
            }
            Until::Forever => {
                // In memory first, so the decision applies even if writing the
                // file fails.
                self.state.lock().await.session_overrides.push(Override {
                    scope_key: scope_key.to_owned(),
                    tool: tool.to_owned(),
                    allow,
                });
                if let Some(path) = &self.policy_path
                    && let Err(e) =
                        crate::daemon::policy::append_override(path, scope_key, tool, allow)
                {
                    tracing::error!(error = %e, "permanent override not persisted");
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

/// Readable excerpt of the arguments, truncated.
///
/// The panel must show enough to decide on, not the whole message — and never
/// the value of a secret, which the engine already replaces with its kind and a
/// prefix in `findings`.
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

/// Entry point of `mcpwall daemon`.
pub async fn run(socket: PathBuf, policy_path: PathBuf, journal_db: PathBuf) -> Result<()> {
    let policy = Policy::load_or_create(&policy_path)?;
    tracing::info!(policy = %policy_path.display(), "policy loaded");

    let daemon = Daemon::new(policy, Some(policy_path), journal_db);
    let socket_for_cleanup = socket.clone();

    // The socket must disappear on shutdown, otherwise the next start believes
    // a daemon is already running.
    let result = tokio::select! {
        r = daemon.serve(&socket) => r,
        _ = shutdown_signal() => {
            tracing::info!("shutdown requested");
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
