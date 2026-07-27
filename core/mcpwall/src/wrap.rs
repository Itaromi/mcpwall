//! Stdio relay between an MCP client and an upstream MCP server.
//!
//! The first I/O module in the core, and the only one whose bugs break a real
//! agent session. Three rules are held here without exception:
//!
//! 1. **No `unwrap()`, no panics.** A panicking shim means the user's session
//!    dies.
//! 2. **We re-emit the bytes we received**, via [`Frame::raw`]. Never
//!    reconstructed JSON.
//! 3. **A failed inspection does not break the relay.** Frame not understood,
//!    ceiling exceeded, observer in trouble: traffic continues. That is the
//!    availability rule of §4 applied at the lowest level.
//!
//! The relay is generic over `AsyncRead`/`AsyncWrite` and knows nothing of
//! SQLite or processes: it can be tested with in-memory buffers.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::frame::{Frame, FrameError, FrameSplitter, SplitterStats};
use crate::mcp::{
    CallContext, DecisionPoint, Disposition, MethodScan, Verdict, classify, deny_response,
    scan_method,
};

/// Read size. A pipe buffer is typically 64 KB.
const READ_BUF: usize = 64 * 1024;

/// Which way a frame is travelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client → upstream server. This is the direction where blocking happens.
    ToServer,
    /// Upstream server → client.
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

/// An observed frame, along with what we made of it.
pub struct FrameEvent<'a> {
    pub direction: Direction,
    pub disposition: Disposition,
    /// `None` for a response, or for a frame whose method could not be read —
    /// [`FrameEvent::scan`] says which of the two.
    pub method: Option<&'a str>,
    pub scan: &'a MethodScan,
    /// Filled in only for frames that went through the decision point.
    pub verdict: Option<&'a Verdict>,
    pub frame: &'a Frame,
}

/// Things that should not have happened but are not fatal.
#[derive(Debug)]
pub enum Anomaly {
    /// Frame over the ceiling. The bytes are discarded, never relayed.
    Oversize { direction: Direction, limit: usize },
    /// Stream ended on a frame with no delimiter.
    Unterminated { direction: Direction },
    /// A blocked frame that expects no response: nothing to send back to the
    /// client.
    DeniedWithoutId { direction: Direction },
    /// The decision point could not rule. Traffic went through — or was
    /// blocked, if `fail_closed` is on.
    DecisionUnavailable {
        direction: Direction,
        reason: String,
        fail_closed: bool,
    },
}

/// Destination for everything the relay observes.
///
/// In M0 this is the SQLite journal. The methods return nothing: an observer
/// has no way of interrupting the relay, by construction.
pub trait Observer: Send + Sync {
    fn on_frame(&self, event: &FrameEvent<'_>);

    fn on_anomaly(&self, anomaly: &Anomaly) {
        let _ = anomaly;
    }

    /// End of stream, with the splitter's counters.
    fn on_eof(&self, direction: Direction, stats: SplitterStats) {
        let _ = (direction, stats);
    }
}

/// An observer that throws everything away. Useful to measure the cost of the
/// bare relay.
pub struct NullObserver;

impl Observer for NullObserver {
    fn on_frame(&self, _event: &FrameEvent<'_>) {}
}

/// Configuration of one pump.
pub struct Pump {
    pub direction: Direction,
    pub max_frame_bytes: usize,
    pub observer: Arc<dyn Observer>,
    pub decision: Arc<dyn DecisionPoint>,
    /// Return path for block responses.
    ///
    /// A `deny` happens on a frame going up to the server, but the response has
    /// to come back down to the client — that is, leave through the **other**
    /// pump. Hence this channel between the two. Without it, blocking would
    /// leave the client waiting forever for a response that never comes.
    pub denied_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

impl Pump {
    /// Relays `reader` into `writer` until end of stream.
    ///
    /// `injected` feeds the outgoing stream with frames that do not come from
    /// `reader` — the block responses manufactured by the other pump.
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
                // The two sources are concurrent: a block response must not
                // wait for the upstream to deign to write something.
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
                        // The bytes have already been discarded by the
                        // splitter, nothing goes to the peer. We note it and
                        // carry on: the splitter resynchronises at the next
                        // delimiter.
                        self.observer.on_anomaly(&Anomaly::Oversize {
                            direction: self.direction,
                            limit,
                        });
                    }
                }
            }

            // One flush per read rather than one per frame: six frames in the
            // same read() must not cost six syscalls.
            if wrote {
                writer.flush().await?;
            }
        }

        // Trailing frame with no delimiter: we relay it anyway — losing the
        // last message of a session would be worse — but we append the
        // terminator, without which the peer would wait forever for the rest.
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

    /// Inspects, decides, relays. Returns `true` if anything was written.
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

        // Only the upward direction goes through the decision point, and only
        // for the DECIDE set. Everything else skips the call entirely.
        let verdict = match (self.direction, disposition, method) {
            (Direction::ToServer, Disposition::Decide, Some(m)) => {
                let ctx = CallContext {
                    method: m,
                    frame: frame.content(),
                };
                match self.decision.decide(&ctx) {
                    Ok(v) => Some(v),
                    // The decision point could not answer. We do not panic and
                    // we do not guess: by default traffic goes through, and the
                    // incident is reported. Breaking an agent's session because
                    // our own daemon went down would be the worst possible
                    // trade — unless the user explicitly asked for
                    // `fail_closed`.
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
                // The frame never reaches the upstream. The response leaves via
                // the return path, not through this writer.
                match deny_response(frame.content(), rule, message) {
                    Some(payload) => {
                        if let Some(tx) = &self.denied_tx {
                            // A send failure means the other pump has already
                            // finished: the session is closing, there is nobody
                            // left to read the response.
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
