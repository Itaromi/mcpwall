//! MCP semantics: identifying the method, classifying frames, the decision
//! point, capturing `initialize`.
//!
//! Two regimes, deliberately asymmetric:
//!
//! - The **method scan** is cheap and runs on every frame. It builds no
//!   structure, allocates only the method name, and tracks brace depth so that
//!   `method` is accepted only as a key of the root object.
//! - **Capturing `initialize`** parses properly with `serde_json`. It runs
//!   twice per session, never on the hot path.
//!
//! I/O-free, like `frame`.

use std::fmt;

/// Cheap scan window, in bytes.
///
/// Beyond it, [`scan_method`] starts a full pass rather than concluding "no
/// method" from silence. A slightly long string `id`, or a serialiser that puts
/// `params` before `method`, is enough to push the key out of the window — that
/// is not a contrived case, it is ordinary traffic.
pub const METHOD_SCAN_WINDOW: usize = 200;

// ---------------------------------------------------------------------------
// Method scan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodScan {
    /// Method extracted from a key of the root object.
    Found {
        method: String,
        /// The window was not enough, the whole frame had to be scanned.
        /// Counted, because a high rate means [`METHOD_SCAN_WINDOW`] needs
        /// widening.
        full_scan: bool,
    },
    /// No root-level `method` key anywhere in the frame.
    ///
    /// This is not an anomaly: a JSON-RPC response (`result` or `error`)
    /// legitimately has no method.
    NoMethod,
    /// A `method` key exists but its value could not be read: non-textual
    /// value, escaping, or a truncated frame.
    ///
    /// Never silent. Classification falls back to [`Disposition::Observe`] — we
    /// journal it, we do not decide on a basis we do not understand.
    Unparsable,
}

/// Identifies a frame's method.
///
/// Tries the window first, then the whole frame. Frames that already fit inside
/// the window are scanned only once.
pub fn scan_method(frame: &[u8]) -> MethodScan {
    if frame.len() <= METHOD_SCAN_WINDOW {
        return match scan_within(frame, frame.len()) {
            Scan::Found(m) => MethodScan::Found {
                method: m,
                full_scan: false,
            },
            Scan::Absent => MethodScan::NoMethod,
            // A frame shorter than the window that still runs out is
            // truncated, not incomplete.
            Scan::Truncated | Scan::Bad => MethodScan::Unparsable,
        };
    }

    match scan_within(frame, METHOD_SCAN_WINDOW) {
        Scan::Found(m) => MethodScan::Found {
            method: m,
            full_scan: false,
        },
        Scan::Bad => MethodScan::Unparsable,
        // Window exhausted, or key absent from the window: we conclude nothing
        // and start again on the complete frame.
        Scan::Truncated | Scan::Absent => match scan_within(frame, frame.len()) {
            Scan::Found(m) => MethodScan::Found {
                method: m,
                full_scan: true,
            },
            Scan::Absent => MethodScan::NoMethod,
            Scan::Truncated | Scan::Bad => MethodScan::Unparsable,
        },
    }
}

enum Scan {
    Found(String),
    /// No root-level `method` key in the portion examined.
    Absent,
    /// The limit was reached before anything could be concluded.
    Truncated,
    /// Key found but its value is unreadable.
    Bad,
}

/// State machine over the first `limit` bytes.
///
/// Tracks brace depth and the "inside a string" state so that `method` is only
/// taken when it is a key of the root object. That is what distinguishes this
/// scan from a substring search: on
/// `{"params":{"method":"x"},"method":"tools/call"}`, a naive search would
/// return `x`.
fn scan_within(frame: &[u8], limit: usize) -> Scan {
    let end = limit.min(frame.len());
    let truncated = end < frame.len();

    let mut i = 0;

    // Skip ahead to the opening of the root object.
    while i < end && frame[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= end {
        return if truncated {
            Scan::Truncated
        } else {
            Scan::Absent
        };
    }
    if frame[i] != b'{' {
        // Array (batching, removed from the spec as of 2025-06-18) or scalar.
        // Not our business here; the violation is reported elsewhere.
        return Scan::Absent;
    }
    let mut depth: i32 = 1;
    i += 1;

    while i < end {
        match frame[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Scan::Absent; // root object closed, no `method`
                }
            }
            b'"' => {
                let Some((content, next, key_escaped)) = read_string(frame, i, end) else {
                    return if truncated {
                        Scan::Truncated
                    } else {
                        Scan::Bad
                    };
                };

                // A string at depth 1 followed by `:` is a root key.
                let mut j = next;
                while j < end && frame[j].is_ascii_whitespace() {
                    j += 1;
                }
                let is_key = j < end && frame[j] == b':';

                if depth == 1 && is_key && !key_escaped && content == b"method" {
                    j += 1;
                    while j < end && frame[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j >= end {
                        return if truncated {
                            Scan::Truncated
                        } else {
                            Scan::Bad
                        };
                    }
                    if frame[j] != b'"' {
                        return Scan::Bad; // non-textual `method`
                    }
                    let Some((value, _, value_escaped)) = read_string(frame, j, end) else {
                        return if truncated {
                            Scan::Truncated
                        } else {
                            Scan::Bad
                        };
                    };
                    if value_escaped {
                        // No legitimate MCP method contains an escape. We
                        // refuse to guess: `Observe`, never `Decide`.
                        return Scan::Bad;
                    }
                    return match std::str::from_utf8(value) {
                        Ok(s) => Scan::Found(s.to_owned()),
                        Err(_) => Scan::Bad,
                    };
                }

                i = if is_key { j } else { next };
            }
            _ => i += 1,
        }
    }

    if truncated {
        Scan::Truncated
    } else {
        Scan::Absent
    }
}

/// Reads the JSON string starting at the quote at `start`.
///
/// Returns the raw content, the index after the closing quote, and whether the
/// string contained an escape. Returns `None` only if it is not closed before
/// `end`.
///
/// Escapes are traversed correctly rather than given up on, and that is not a
/// convenience detail: a scan that bails on the first `\` classifies the frame
/// as `Unparsable` and therefore `Observe`, that is, outside the decision
/// point. A `tools/call` whose `id` contains `\"` would then be enough to
/// bypass the policy. The content returned stays raw — we decode nothing, we
/// only know where the string ends.
fn read_string(frame: &[u8], start: usize, end: usize) -> Option<(&[u8], usize, bool)> {
    debug_assert_eq!(frame[start], b'"');
    let mut i = start + 1;
    let mut escaped = false;
    while i < end {
        match frame[i] {
            b'"' => return Some((&frame[start + 1..i], i + 1, escaped)),
            b'\\' => {
                escaped = true;
                // The next character is literal, including `"` and `\`.
                i += 2;
            }
            _ => i += 1,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// What the shim is allowed to do with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Relay immediately, journal briefly. Zero extra parsing.
    Passthrough,
    /// Journalled in detail, but **never** submitted to the decision point.
    Observe,
    /// Goes through the decision point. May be blocked.
    Decide,
}

/// Methods submitted to the decision point.
///
/// Only add here what is both useful to block and survivable for the agent's
/// session.
const DECIDE: &[&str] = &[
    "tools/call",
    "resources/read",
    "sampling/createMessage",
    "elicitation/create",
];

/// Methods journalled in detail but never blockable.
///
/// `initialize` is here and must stay: blocking it protects nothing and kills
/// the whole session. The two sets are separate precisely so it cannot be moved
/// by accident — see
/// [`initialize_is_never_decidable`](../tests/mcp.rs).
const OBSERVE: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
    "prompts/get",
    // `roots/list` feeds link 2 of the scope provenance chain, and its
    // change notification invalidates it. The shim does not emit these, it
    // sees them go by — hence `Observe` and not `Passthrough`.
    "roots/list",
    "notifications/roots/list_changed",
];

pub fn disposition(method: &str) -> Disposition {
    if DECIDE.contains(&method) {
        Disposition::Decide
    } else if OBSERVE.contains(&method) {
        Disposition::Observe
    } else {
        Disposition::Passthrough
    }
}

/// Classifies a frame from its scan.
pub fn classify(scan: &MethodScan) -> Disposition {
    match scan {
        MethodScan::Found { method, .. } => disposition(method),
        // A response carries no method; it is correlated by `id` further up,
        // not classified here.
        MethodScan::NoMethod => Disposition::Passthrough,
        // We never decide on a frame we did not understand, and we do not let
        // it slip by unrecorded either.
        MethodScan::Unparsable => Disposition::Observe,
    }
}

// ---------------------------------------------------------------------------
// Decision point
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// The shim will answer with a valid `result` carrying `isError: true`.
    /// Never a protocol error, never a closed connection.
    Deny {
        rule: String,
        message: String,
    },
}

/// What we present to the decision point.
#[derive(Debug, Clone)]
pub struct CallContext<'a> {
    pub method: &'a str,
    /// The raw frame. In M1 the daemon parses it to evaluate the policy against
    /// the contents of the arguments.
    pub frame: &'a [u8],
}

/// In M0 the only implementation is [`AllowAll`]. In M1 it is the Unix socket
/// client that implements it.
///
/// **Fallible on purpose.** A socket client must be able to say "I could not
/// reach the daemon" without having to lie `Allow` or panic. The caller treats
/// any `Err` as a journalled `Allow`: that is the availability rule of §4
/// applied to mcpwall's own code. Without this `Result`, the only recourse in
/// M1 would be an `unwrap` in disguise on the shim's path.
pub trait DecisionPoint: Send + Sync {
    fn decide(&self, ctx: &CallContext<'_>) -> Result<Verdict, DecisionError>;
}

/// The decision point could not rule. Never fatal.
#[derive(Debug, Clone)]
pub struct DecisionError {
    pub reason: String,
    /// Does the policy ask to close on failure? Filled in by the daemon client
    /// from `fail_closed`, failing which the caller lets traffic through.
    pub fail_closed: bool,
}

impl DecisionError {
    pub fn open(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            fail_closed: false,
        }
    }
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

/// M0: observation only.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl DecisionPoint for AllowAll {
    fn decide(&self, _ctx: &CallContext<'_>) -> Result<Verdict, DecisionError> {
        Ok(Verdict::Allow)
    }
}

/// Builds the response to send back to the client when a call is blocked.
///
/// The shape is mandated by §5 of the project spec: never a JSON-RPC protocol
/// error, never a closed connection. A valid `result` carrying `isError: true`,
/// which the agent reads as an ordinary tool failure, adapts to, and carries on
/// after.
///
/// Returns `None` if the blocked frame has no `id`: it is a notification, it
/// expects no response and there is nothing to send back. The frame is simply
/// dropped.
///
/// The output is terminated by `\n`: it is a frame ready to write.
pub fn deny_response(frame: &[u8], rule: &str, message: &str) -> Option<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let id = v.get("id")?;
    if id.is_null() {
        return None;
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "isError": true,
            "content": [{
                "type": "text",
                "text": format!("blocked by mcpwall: {message} (rule: {rule})"),
            }],
        },
    });

    let mut out = serde_json::to_vec(&body).ok()?;
    out.push(b'\n');
    Some(out)
}

// ---------------------------------------------------------------------------
// Capturing `initialize`
// ---------------------------------------------------------------------------

/// What we keep from the client's `initialize` request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    /// The version **requested**. The version settled on is the one in
    /// [`ServerHello`].
    pub requested_protocol_version: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    /// Does the client announce the `roots` capability? Determines whether link
    /// 2 of the scope provenance chain has any chance of being fed.
    pub supports_roots: bool,
    pub roots_list_changed: bool,
}

/// What we keep from the server's `initialize` response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerHello {
    /// The **negotiated** version. This is the field we store: the spec wants
    /// the server to answer with the version settled on, which may differ from
    /// the one the client asked for.
    pub protocol_version: Option<String>,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
    /// Top-level keys of `capabilities`, sorted. Enough for the journal without
    /// storing the whole object.
    pub capabilities: Vec<String>,
}

pub fn parse_client_hello(frame: &[u8]) -> Option<ClientHello> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let params = v.get("params")?;
    let roots = params.get("capabilities").and_then(|c| c.get("roots"));

    Some(ClientHello {
        requested_protocol_version: str_at(params, "protocolVersion"),
        client_name: params.get("clientInfo").and_then(|i| str_at(i, "name")),
        client_version: params.get("clientInfo").and_then(|i| str_at(i, "version")),
        supports_roots: roots.is_some(),
        roots_list_changed: roots
            .and_then(|r| r.get("listChanged"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

pub fn parse_server_hello(frame: &[u8]) -> Option<ServerHello> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let result = v.get("result")?;

    let mut capabilities: Vec<String> = result
        .get("capabilities")
        .and_then(serde_json::Value::as_object)
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    capabilities.sort();

    Some(ServerHello {
        protocol_version: str_at(result, "protocolVersion"),
        server_name: result.get("serverInfo").and_then(|i| str_at(i, "name")),
        server_version: result.get("serverInfo").and_then(|i| str_at(i, "version")),
        capabilities,
    })
}

fn str_at(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_owned)
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Passthrough => "passthrough",
            Self::Observe => "observe",
            Self::Decide => "decide",
        })
    }
}
