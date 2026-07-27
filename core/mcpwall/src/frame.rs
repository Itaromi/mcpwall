//! MCP stdio frame splitting.
//!
//! The MCP spec (revision 2025-11-25, `basic/transports`) requires: "Messages are
//! delimited by newlines, and MUST NOT contain embedded newlines". This module
//! does only that — find the `0x0A` bytes and hand back what lies between. It
//! parses no JSON, never converts to `String`, and does not validate UTF-8: a
//! frame cut in the middle of a multi-byte sequence is a non-event by
//! construction, since we only ever reason about bytes.
//!
//! Deliberately synchronous and I/O-free: `wrap.rs` pushes it whatever `read()`
//! returned. That makes the splitting testable and fuzzable without an async
//! runtime, and keeps the hot part of the relay path free of needless
//! allocation.

use std::fmt;

/// Default ceiling on a single frame.
///
/// A malformed or hostile upstream server that never emits a `\n` would grow the
/// buffer until OOM. Past this threshold we return [`FrameError::Oversize`].
pub const DEFAULT_MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;

/// Buffer compaction threshold. Below it, the consumed prefix is left in place
/// rather than paying for one `memmove` per frame.
const COMPACT_THRESHOLD: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// No `\n` seen within `max_frame_bytes` bytes.
    ///
    /// The splitter then enters discard mode: it throws bytes away until the
    /// next `\n`, then resumes normally. Whether the incident is fatal to the
    /// connection is the transport layer's call — the splitter itself always
    /// knows how to resynchronise.
    Oversize { limit: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversize { limit } => {
                write!(f, "frame exceeding the {limit} byte limit with no newline")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Anomaly counters. They feed `mcpwall log --stats`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SplitterStats {
    /// Frames handed to the caller.
    pub frames: u64,
    /// Input bytes consumed, terminators included.
    pub bytes_in: u64,
    /// Blank lines skipped. A lone `\n` is not a message.
    pub empty_skipped: u64,
    /// [`FrameError::Oversize`] incidents.
    pub oversize: u64,
    /// Bytes thrown away in discard mode, after an `Oversize`.
    pub bytes_discarded: u64,
    /// Frames ended by end of stream rather than by a `\n`.
    pub unterminated: u64,
    /// `\r\n` terminators seen. The spec says `\n`; we tolerate and count.
    pub crlf: u64,
}

/// A frame extracted from the stream.
///
/// It carries two views of the same bytes, and the distinction is not cosmetic:
///
/// - [`content`](Self::content) is for **inspection** — no terminator, no
///   trailing `\r`. This is what we scan and journal.
/// - [`raw`](Self::raw) is for **relaying** — the exact bytes received,
///   terminator included. Writing `content` followed by a `\n` would normalise a
///   `\r\n` into a `\n`, that is, alter the stream of an upstream we do not
///   understand. The relay rewrites nothing.
///
/// `content` is a prefix of `raw`, so there is a single allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    raw: Vec<u8>,
    content_len: usize,
}

impl Frame {
    /// Message bytes, without the delimiter. To inspect and journal.
    pub fn content(&self) -> &[u8] {
        &self.raw[..self.content_len]
    }

    /// Exact bytes received, delimiter included. To re-emit verbatim.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Was the frame closed by a delimiter?
    ///
    /// False only for a trailing frame handed back by [`FrameSplitter::finish`].
    /// The relay must then decide whether to append a `\n` — the peer, after
    /// all, expects a delimited message.
    pub fn is_terminated(&self) -> bool {
        self.raw.len() > self.content_len
    }

    pub fn len(&self) -> usize {
        self.content_len
    }

    pub fn is_empty(&self) -> bool {
        self.content_len == 0
    }

    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }
}

/// Splits a stream into `\n`-delimited frames.
///
/// Usage: [`push`](Self::push) whatever `read()` returned, then loop on
/// [`next_frame`](Self::next_frame) until `None`. At end of stream, call
/// [`finish`](Self::finish) to collect any trailing unterminated frame.
#[derive(Debug)]
pub struct FrameSplitter {
    buf: Vec<u8>,
    /// Start of the in-progress frame within `buf`.
    start: usize,
    /// Index up to which `buf` has already been searched for a `\n`. Avoids
    /// rescanning the same prefix on every `push`, which would make splitting
    /// quadratic on a multi-megabyte frame arriving in small chunks.
    scanned: usize,
    /// Discard mode: throw bytes away until the next `\n`.
    discarding: bool,
    max_frame_bytes: usize,
    stats: SplitterStats,
}

impl Default for FrameSplitter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_BYTES)
    }
}

impl FrameSplitter {
    pub fn new(max_frame_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            scanned: 0,
            discarding: false,
            max_frame_bytes,
            stats: SplitterStats::default(),
        }
    }

    pub fn stats(&self) -> SplitterStats {
        self.stats
    }

    /// Bytes currently held in the buffer, waiting for a `\n`.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Pushes a raw chunk coming out of `read()`.
    pub fn push(&mut self, chunk: &[u8]) {
        self.stats.bytes_in += chunk.len() as u64;
        self.buf.extend_from_slice(chunk);
    }

    /// Returns the next complete frame, if there is one.
    ///
    /// `None` means "I need more bytes", not "end of stream".
    pub fn next_frame(&mut self) -> Option<Result<Frame, FrameError>> {
        loop {
            match memchr::memchr(b'\n', &self.buf[self.scanned..]) {
                Some(offset) => {
                    let newline = self.scanned + offset;

                    if self.discarding {
                        // Leaving discard mode: the oversized frame stops here,
                        // the next one starts clean.
                        // The `\n` is a consumed delimiter, not discarded
                        // payload: it does not count.
                        self.stats.bytes_discarded += (newline - self.start) as u64;
                        self.discarding = false;
                        self.consume_to(newline + 1);
                        continue;
                    }

                    // The ceiling must be checked here too, not only when no
                    // `\n` was found: an oversized frame arriving from a single
                    // `read()`, terminator included, would otherwise slip
                    // through. The ceiling must not depend on how reads split.
                    if newline - self.start > self.max_frame_bytes {
                        self.stats.oversize += 1;
                        self.stats.bytes_discarded += (newline - self.start) as u64;
                        self.consume_to(newline + 1);
                        return Some(Err(FrameError::Oversize {
                            limit: self.max_frame_bytes,
                        }));
                    }

                    let mut end = newline;
                    if end > self.start && self.buf[end - 1] == b'\r' {
                        self.stats.crlf += 1;
                        end -= 1;
                    }
                    // `raw` runs up to and including the `\n`, `content` stops
                    // before the delimiter: content is a prefix of raw.
                    let frame = Frame {
                        raw: self.buf[self.start..=newline].to_vec(),
                        content_len: end - self.start,
                    };
                    self.consume_to(newline + 1);

                    if frame.is_empty() {
                        // Blank line: not an MCP message. We skip it without
                        // surfacing it, but we count it — a server emitting
                        // these violates "MUST NOT write anything to stdout
                        // that is not a valid MCP message".
                        self.stats.empty_skipped += 1;
                        continue;
                    }

                    self.stats.frames += 1;
                    return Some(Ok(frame));
                }
                None => {
                    self.scanned = self.buf.len();

                    if self.discarding {
                        self.stats.bytes_discarded += (self.buf.len() - self.start) as u64;
                        self.consume_to(self.buf.len());
                        return None;
                    }

                    if self.buffered() > self.max_frame_bytes {
                        self.stats.oversize += 1;
                        self.discarding = true;
                        self.stats.bytes_discarded += self.buffered() as u64;
                        self.consume_to(self.buf.len());
                        return Some(Err(FrameError::Oversize {
                            limit: self.max_frame_bytes,
                        }));
                    }

                    return None;
                }
            }
        }
    }

    /// End of stream: returns the residual bytes as one last frame.
    ///
    /// The spec requires a trailing `\n`, but a server killed mid-write, or
    /// simply careless, leaves a bare line. We surface it anyway — losing the
    /// last message of a session would be worse — having counted it in
    /// [`SplitterStats::unterminated`].
    pub fn finish(&mut self) -> Option<Frame> {
        if self.discarding {
            self.stats.bytes_discarded += self.buffered() as u64;
            self.consume_to(self.buf.len());
            return None;
        }

        // Same ceiling at end of stream as everywhere else.
        if self.buffered() > self.max_frame_bytes {
            self.stats.oversize += 1;
            self.stats.bytes_discarded += self.buffered() as u64;
            self.consume_to(self.buf.len());
            return None;
        }

        let mut end = self.buf.len();
        if end > self.start && self.buf[end - 1] == b'\r' {
            end -= 1;
        }
        // No delimiter here: `raw` stops where the stream stops. Any trailing
        // `\r` stays in `raw` — we do not rewrite what we relay.
        let frame = Frame {
            raw: self.buf[self.start..].to_vec(),
            content_len: end - self.start,
        };
        self.consume_to(self.buf.len());

        if frame.is_empty() {
            return None;
        }

        self.stats.frames += 1;
        self.stats.unterminated += 1;
        Some(frame)
    }

    /// Advances `start` and compacts the buffer once the consumed prefix gets
    /// expensive to carry around.
    fn consume_to(&mut self, pos: usize) {
        self.start = pos;
        self.scanned = pos;

        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
            self.scanned = 0;
        } else if self.start >= COMPACT_THRESHOLD {
            self.buf.drain(..self.start);
            self.scanned -= self.start;
            self.start = 0;
        }
    }
}
