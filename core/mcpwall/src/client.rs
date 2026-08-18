//! Daemon client, shim side.
//!
//! Implements [`DecisionPoint`] over the Unix socket. This is the one place
//! where mcpwall can break a user's session for a reason that is none of their
//! business — a stopped daemon, an update in flight — so this is where the
//! availability rule of §4 applies most literally.
//!
//! ## Why a system thread and not a task
//!
//! Holding a frame back before it reaches the upstream requires the verdict to
//! be produced **before** the relay continues: the decision point is therefore
//! synchronous, called from the body of an async pump. If the socket I/O lived
//! on the same executor, waiting for the verdict would block the very task that
//! has to produce it — a guaranteed deadlock on a single-threaded runtime.
//!
//! The connection therefore lives on a dedicated system thread, in blocking
//! I/O, and the conversation goes through `std` channels. The relay blocks its
//! thread, the socket makes progress on its own.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::Duration;

use crate::ipc::{
    ClientMessage, DecideRequest, DecideResponse, Hello, Outcome, ServerMessage, TaintReport,
};
use crate::mcp::{CallContext, DecisionError, DecisionPoint, Verdict};
use crate::scope::Scope;
use crate::taint;

/// How long to wait for a verdict when the daemon announces nothing.
///
/// A safety net for a daemon that is alive but stuck, a case the handshake does
/// not catch. It must **never** be shorter than the time a user takes to answer
/// a confirmation prompt: giving up too early lets the call through, and so
/// turns an `ask` rule into `allow` as soon as the person stops to think. Hence
/// deriving it from the timeout the daemon announces in its hello, and using
/// this value only as a last resort.
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(180);

/// Margin added to the timeout announced by the daemon.
///
/// The daemon guarantees an answer within its own timeout; the margin covers
/// transit and scheduling, not the user's hesitation.
const TIMEOUT_MARGIN: Duration = Duration::from_secs(30);

/// How long a caller will wait for a taint report to reach the socket.
///
/// Short on purpose: losing a report costs a later detection, whereas holding
/// up a `PostToolUse` hook costs the user their tool call. The availability rule
/// of §4 decides that trade-off the same way here as everywhere else.
const TAINT_ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// What the IPC thread may be asked to send.
///
/// Two shapes, and the difference is load-bearing: `Decide` consumes exactly
/// one reply line, `Taint` consumes none. Mixing them up would make a shim read
/// one verdict behind for the rest of the session.
enum Outgoing {
    Decide(Box<DecideRequest>, mpsc::Sender<Option<DecideResponse>>),
    /// The optional sender is acknowledged once the report has been written and
    /// flushed, never before.
    ///
    /// The shim does not use it: it lives for the whole session, so a report
    /// still queued when the call returns will go out well before anything needs
    /// it. The Claude Code hook is the opposite — a process that exists for one
    /// tool call and then exits, which would take the queued report with it.
    Taint(Box<TaintReport>, Option<mpsc::Sender<()>>),
}

/// Ceiling on the reads awaiting their response.
///
/// A server that never answers must not turn this map into a leak for the life
/// of the session.
const MAX_INFLIGHT_READS: usize = 256;

pub struct DaemonClient {
    tx: mpsc::Sender<Outgoing>,
    /// `id` of a local read → what it was reading.
    ///
    /// Filled in on the way up, consumed on the way down. Without it a response
    /// is an anonymous blob: we would not know whether it is worth
    /// fingerprinting, nor what to name as the origin when a refusal cites it.
    inflight_reads: Mutex<HashMap<String, String>>,
    /// Has the daemon already been judged unreachable?
    ///
    /// A shim that has lost the daemon does not retry on every call: that would
    /// mean paying one timeout per tool for nothing.
    degraded: AtomicBool,
    fail_closed: bool,
    session: SessionInfo,
    /// Derived from the daemon's hello.
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
    /// Connects and performs the handshake.
    ///
    /// Returns `None` if the daemon is absent or speaks another version: the
    /// shim then relays without policy. That is an accepted degraded mode, not
    /// an error — the app may be closed, and closing the app must not paralyse
    /// the user's MCP servers.
    pub fn connect(socket: &Path, fail_closed: bool, session: SessionInfo) -> Option<Self> {
        let stream = match UnixStream::connect(socket) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    socket = %socket.display(),
                    error = %e,
                    "daemon unreachable — relaying without policy"
                );
                return None;
            }
        };
        // Short during the handshake: a daemon that does not answer it is dead,
        // there is nobody to wait for. The timeout is extended right after,
        // once we know how long a verdict may take.
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
            // Deliberately loud: this is the MCP client left open across an
            // update, and the user needs to understand why their firewall has
            // stopped filtering.
            tracing::error!(
                shim = mine.mcpwall_ipc,
                daemon = peer.mcpwall_ipc,
                daemon_build = %peer.build,
                "incompatible IPC version — mcpwall IS NOT FILTERING this session. \
                 Restart the MCP client to pick up an up-to-date shim."
            );
            return None;
        }

        // The daemon announces how long it may take to answer — it is waiting
        // on the user, not on the machine. Giving up before it does would let
        // the call through silently.
        let timeout = peer
            .ask_timeout_seconds
            .map(|s| Duration::from_secs(s) + TIMEOUT_MARGIN)
            .unwrap_or(FALLBACK_TIMEOUT);
        stream_ref.set_read_timeout(Some(timeout)).ok()?;

        let (tx, rx) = mpsc::channel::<Outgoing>();

        // A single thread owns the connection: requests are serialised
        // naturally, with no lock.
        std::thread::Builder::new()
            .name("mcpwall-ipc".into())
            .spawn(move || {
                for outgoing in rx {
                    let (req, reply) = match outgoing {
                        Outgoing::Decide(req, reply) => (req, reply),
                        // Fire and forget. A failed write is not fatal: losing a
                        // taint report costs us a later detection, it does not
                        // cost the user their session.
                        Outgoing::Taint(report, ack) => {
                            let msg = ClientMessage::Taint(*report);
                            if let Ok(payload) = serde_json::to_string(&msg) {
                                let _ = writeln!(write, "{payload}");
                                let _ = write.flush();
                            }
                            // After the flush, so that a caller about to exit
                            // knows the bytes have left rather than hoping so.
                            if let Some(ack) = ack {
                                let _ = ack.send(());
                            }
                            continue;
                        }
                    };

                    let response = (|| {
                        let msg = ClientMessage::Decide(req);
                        let payload = serde_json::to_string(&msg).ok()?;
                        writeln!(write, "{payload}").ok()?;
                        write.flush().ok()?;

                        // The shim does not subscribe to confirmation prompts:
                        // anything that is not a verdict on this connection is
                        // a protocol anomaly, not a message to interpret
                        // charitably.
                        let line = lines.next()?.ok()?;
                        match serde_json::from_str::<ServerMessage>(&line).ok()? {
                            ServerMessage::Verdict(v) => Some(v),
                            other => {
                                tracing::warn!(
                                    received = ?std::mem::discriminant(&other),
                                    "unexpected message in place of a verdict"
                                );
                                None
                            }
                        }
                    })();

                    let failed = response.is_none();
                    let _ = reply.send(response);
                    if failed {
                        break; // dead connection, callers will fall back to degraded
                    }
                }
            })
            .ok()?;

        Some(Self {
            tx,
            inflight_reads: Mutex::new(HashMap::new()),
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

    /// Remembers that this `id` is a local read, so its response can be
    /// recognised on the way back down.
    ///
    /// The origin is the path when the arguments carry one, otherwise the tool
    /// name: a refusal that says only "tainted data" tells the user nothing
    /// they can act on.
    fn note_if_local_read(&self, ctx: &CallContext<'_>) {
        let v: serde_json::Value = match serde_json::from_slice(ctx.frame) {
            Ok(v) => v,
            Err(_) => return,
        };
        let params = v.get("params");
        let tool = params.and_then(|p| p.get("name")).and_then(|n| n.as_str());

        if !taint::is_local_read(ctx.method, tool) {
            return;
        }
        let Some(id) = frame_id(ctx.frame) else {
            return; // a notification: no response will come back
        };

        let origin = params
            .and_then(|p| {
                p.get("uri")
                    .or_else(|| p.get("arguments").and_then(|a| a.get("path")))
            })
            .and_then(|s| s.as_str())
            .map(str::to_owned)
            .or_else(|| tool.map(str::to_owned))
            .unwrap_or_else(|| ctx.method.to_owned());

        if let Ok(mut m) = self.inflight_reads.lock() {
            // A server that never answers must not grow this map for the life
            // of the session. Dropping the oldest entries loses a detection,
            // never a session.
            if m.len() >= MAX_INFLIGHT_READS {
                m.clear();
            }
            m.insert(id, origin);
        }
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
            return Err(self.error("daemon unreachable (degraded state)"));
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

        self.note_if_local_read(ctx);

        let (tx, rx) = mpsc::channel();
        if self.tx.send(Outgoing::Decide(Box::new(req), tx)).is_err() {
            self.degraded.store(true, Ordering::Relaxed);
            return Err(self.error("connection to the daemon closed"));
        }

        let response = match rx.recv_timeout(self.timeout) {
            Ok(Some(r)) => r,
            Ok(None) => {
                self.degraded.store(true, Ordering::Relaxed);
                return Err(self.error("unreadable response from the daemon"));
            }
            Err(_) => {
                self.degraded.store(true, Ordering::Relaxed);
                return Err(self.error("timed out waiting for the verdict"));
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

    fn observe_response(&self, frame: &[u8]) {
        // Only responses to a read we marked on the way up are of interest.
        // Everything else — `tools/list` and its kilobytes of schemas, ordinary
        // results — is dropped before anything is parsed twice.
        let Some(id) = frame_id(frame) else {
            return;
        };
        let Some(origin) = self
            .inflight_reads
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&id))
        else {
            return;
        };

        let fp = taint::fingerprint(&String::from_utf8_lossy(frame)).capped();
        if fp.is_empty() {
            return;
        }

        let _ = self.tx.send(Outgoing::Taint(
            Box::new(TaintReport {
                origin,
                ngrams: fp.ngrams,
                tokens: fp.tokens,
            }),
            None,
        ));
    }
}

impl DaemonClient {
    /// Effective timeout, derived from the daemon's hello.
    pub fn decide_timeout(&self) -> Duration {
        self.timeout
    }

    /// Records what a local read returned, outside the correlation the shim
    /// relies on, and **waits for the report to be on the wire**.
    ///
    /// The shim learns an origin on the way up and pairs it with a response on
    /// the way down, inside one long-lived process. The Claude Code hook has
    /// neither half of that: `PreToolUse` and `PostToolUse` are two separate
    /// processes, and the result arrives already paired with the call that
    /// produced it. So the report is sent directly.
    ///
    /// Waiting is not a detail. This process exits as soon as it has written
    /// its answer, and a report still sitting in the channel would die with it —
    /// the taint store would stay empty, and the exfiltration that follows would
    /// go through. The wait is bounded so a stuck daemon cannot hold up the
    /// user's tool call.
    pub fn report_taint(&self, origin: &str, text: &str) {
        let fp = taint::fingerprint(text).capped();
        if fp.is_empty() {
            return;
        }
        let (ack, done) = mpsc::channel();
        if self
            .tx
            .send(Outgoing::Taint(
                Box::new(TaintReport {
                    origin: origin.to_owned(),
                    ngrams: fp.ngrams,
                    tokens: fp.tokens,
                }),
                Some(ack),
            ))
            .is_err()
        {
            return;
        }
        let _ = done.recv_timeout(TAINT_ACK_TIMEOUT);
    }
}

/// `id` of a frame, rendered as text.
///
/// Numbers and strings are both legal JSON-RPC ids, and a server is free to
/// echo `1` where the client sent `"1"`. Normalising to text keeps the two ends
/// of the correlation comparable.
fn frame_id(frame: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    match v.get("id")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
