//! Lifecycle of a stdio session: start the upstream, wire the pumps, die
//! cleanly.
//!
//! This is where this project breaks real sessions if written badly. The four
//! failure modes, and what we do about them:
//!
//! - **Orphans.** The client kills the shim; with no signal relaying, the
//!   upstream server survives. Thirty ghost `node` processes after a day's
//!   work, and mcpwall is the obvious culprit. We relay `SIGTERM`/`SIGINT`,
//!   then escalate to `SIGKILL` after a grace period.
//! - **Hangs.** The upstream dies, the shim stays blocked on a read that will
//!   never return anything. We watch the process alongside the pumps.
//! - **Back-pressure deadlock.** One task per direction, strictly independent,
//!   no lock held across an `await`. An 8 MB response in one direction must not
//!   stop the other from making progress.
//! - **Lost exit code.** The client reads the shim's exit code; it must be the
//!   upstream's, otherwise a server that fails at startup looks like it
//!   succeeded.
//!
//! `stderr` is not pumped: it is inherited. Zero tasks, zero buffers, zero
//! third descriptor to deadlock on, and the observed behaviour is exactly that
//! of the unwrapped upstream.

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

/// Grace given to the upstream to exit after `SIGTERM` before `SIGKILL`.
const GRACE: Duration = Duration::from_secs(5);

/// How to start and supervise an upstream MCP server.
pub struct SessionConfig {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub max_frame_bytes: usize,
    /// Link 1 of the scope provenance chain, injected by `mcpwall init` into
    /// the client configuration.
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

/// Starts the upstream, relays, and returns its exit code.
///
/// `stdin`/`stdout` are supplied by the caller rather than taken from the
/// process so that tests can drive a real session without hijacking the test
/// binary's own descriptors.
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
        // Inherited, not pumped: the client sees the upstream's diagnostics
        // exactly as it would without mcpwall.
        .stderr(Stdio::inherit())
        // Without this the child inherits the process group and receives the
        // terminal's Ctrl-C at the same time we do, which makes the shutdown
        // ordering indeterminate. We want sole control over its shutdown.
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {:?}", config.program))?;

    let child_in = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("upstream stdin unavailable"))?;
    let child_out = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("upstream stdout unavailable"))?;

    // Return path for block responses: decided on the way up, written on the
    // way down.
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

    // Two independent tasks. Neither waits on the other: a multi-megabyte
    // upstream response must not stop a request from going up.
    let mut up_task = tokio::spawn(async move { up.run(client_in, child_in, None).await });
    let mut down_task =
        tokio::spawn(async move { down.run(child_out, client_out, Some(denied_rx)).await });

    let mut signals = Signals::new()?;

    // Three possible outcomes: the upstream exits, a signal arrives, or the
    // client closes stdin. We wait on all three in parallel.
    // Each of the three is terminal: we do not loop, we wait for whichever
    // comes first.
    let status = tokio::select! {
        // The upstream is done. This is the normal outcome.
        res = child.wait() => res.context("waiting for the upstream")?,

        // The client kills us. We pass it on, we do not abandon the child.
        sig = signals.next() => {
            let sig = sig.unwrap_or(TermSignal::Term);
            tracing::info!(signal = sig.as_str(), "signal received, forwarding to the upstream");
            terminate(&mut child, sig).await;
            child.wait().await.context("waiting after signal")?
        }

        // The client closed stdin: the upward pump reached end of stream and
        // released the descriptor, which closes the upstream's stdin.
        res = &mut up_task => {
            if let Ok(Err(e)) = res {
                tracing::warn!(error = %e, "upward pump interrupted");
            }
            // Clean shutdown per the MCP spec: close stdin, wait, then escalate
            // only if the upstream hangs on.
            match tokio::time::timeout(GRACE, child.wait()).await {
                Ok(res) => res.context("waiting after client EOF")?,
                Err(_) => {
                    tracing::warn!("the upstream did not exit after stdin was closed");
                    terminate(&mut child, TermSignal::Term).await;
                    child.wait().await.context("waiting after escalation")?
                }
            }
        }
    };

    // The upstream is dead: give the downward pump a moment to drain what it
    // wrote before exiting, otherwise we would lose its last response.
    let _ = tokio::time::timeout(Duration::from_millis(200), &mut down_task).await;
    down_task.abort();
    up_task.abort();

    Ok(exit_code(&status))
}

/// Exit code as observed by the client.
///
/// A process killed by a signal has no code; the shell convention is
/// `128 + signal`. Reproducing it keeps a killed upstream from looking like a
/// success.
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

/// Forwards the signal to the upstream, then escalates if it hangs on.
///
/// Escalation is not a courtesy: a server that ignores `SIGTERM` and is not
/// finished off becomes exactly the orphan we are trying to avoid.
async fn terminate(child: &mut tokio::process::Child, sig: TermSignal) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        // Tokio's `Child::kill` only sends SIGKILL, which would deny the
        // upstream any chance of shutting down cleanly — closing its files,
        // flushing its buffers. So we go through `kill(2)`, via `nix`'s safe
        // wrapper so as not to have to carve an exception out of the core's
        // `forbid(unsafe_code)`.
        let raw = match sig {
            TermSignal::Term => Signal::SIGTERM,
            TermSignal::Int => Signal::SIGINT,
        };
        if let Ok(pid) = i32::try_from(pid) {
            let _ = kill(Pid::from_raw(pid), raw);
        }
    }

    if tokio::time::timeout(GRACE, child.wait()).await.is_err() {
        tracing::warn!(
            "the upstream ignores {}, escalating to SIGKILL",
            sig.as_str()
        );
        let _ = child.start_kill();
    }
}

/// Listens for `SIGTERM` and `SIGINT`.
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
                term: signal(SignalKind::terminate()).context("listening for SIGTERM")?,
                int: signal(SignalKind::interrupt()).context("listening for SIGINT")?,
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
