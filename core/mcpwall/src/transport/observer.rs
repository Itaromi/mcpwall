//! The observer that connects the relay to the journal.
//!
//! It holds the session state: capturing `initialize`, passively listening for
//! roots, resolving the scope. The relay itself knows only bytes and verdicts —
//! session semantics live here.
//!
//! No method returns an error: by construction, an observer in trouble cannot
//! interrupt traffic.

use std::sync::{Arc, Mutex};

use crate::journal::{Entry, Journal, SessionRow, now_ms};
use crate::protocol::frame::SplitterStats;
use crate::protocol::mcp::{MethodScan, Verdict, parse_client_hello, parse_server_hello};
use crate::protocol::scope::{ScopeResolver, ScopeSource, parse_root_uri};
use crate::transport::stdio::{Anomaly, Direction, FrameEvent, Observer};

/// Maximum length of a stored argument excerpt.
///
/// The journal must **never** contain the value of a detected secret. We
/// truncate, and in M1 the policy engine replaces the excerpt with the kind of
/// secret and a prefix.
const PREVIEW_MAX: usize = 200;

#[derive(Default)]
struct State {
    session_id: i64,
    row: SessionRow,
    scope: ScopeResolver,
    /// `id` of the `initialize` request, so its response can be recognised in
    /// the downward stream — that is what carries the negotiated version and
    /// the `serverInfo`.
    initialize_id: Option<String>,
    dirty: bool,
}

pub struct JournalObserver {
    journal: Journal,
    state: Mutex<State>,
}

impl JournalObserver {
    /// Opens the session in the database and returns a ready observer.
    pub async fn new(
        journal: Journal,
        command: String,
        project: Option<std::path::PathBuf>,
    ) -> Arc<Self> {
        let mut scope = ScopeResolver::new();

        // Link 1: the path injected by `mcpwall init`.
        if let Some(p) = project {
            scope.set_injected(crate::protocol::scope::canonicalize_for_scope(&p));
        }
        // Link 3: the cwd inherited from the client, canonicalised.
        if let Ok(cwd) = std::env::current_dir() {
            scope.set_cwd(crate::protocol::scope::canonicalize_for_scope(&cwd));
        }

        let resolved = scope.resolve();
        let row = SessionRow {
            started_ms: now_ms(),
            scope_key: resolved.key(),
            scope_source: resolved.source().as_str().to_owned(),
            command,
            ..Default::default()
        };

        let session_id = journal.open_session(row.clone()).await.unwrap_or(0);

        Arc::new(Self {
            journal,
            state: Mutex::new(State {
                session_id,
                row,
                scope,
                initialize_id: None,
                dirty: false,
            }),
        })
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Excerpt of `params`, truncated on a character boundary.
    fn preview(frame: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(frame).ok()?;
        let params = text.find("\"params\"").unwrap_or(0);
        let slice = &text[params..];
        let end = slice
            .char_indices()
            .map(|(i, c)| i + c.len_utf8())
            .take_while(|&i| i <= PREVIEW_MAX)
            .last()
            .unwrap_or(0);
        Some(slice[..end].to_owned())
    }

    /// Captures what is worth keeping from OBSERVE traffic.
    fn observe_semantics(&self, event: &FrameEvent<'_>) {
        let Ok(mut st) = self.state.lock() else {
            // Poisoned lock: we give up on semantics, not on the relay.
            return;
        };

        match (event.direction, event.method) {
            (Direction::ToServer, Some("initialize")) => {
                if let Some(hello) = parse_client_hello(event.frame.content()) {
                    st.row.client_name = hello.client_name;
                    st.row.client_version = hello.client_version;
                    st.dirty = true;
                }
                st.initialize_id = request_id(event.frame.content());
            }

            // The response to `initialize` carries the **negotiated** version
            // and the `serverInfo`. That is what we store, not the client's
            // request.
            (Direction::ToClient, None) => {
                let is_init_reply = match (&st.initialize_id, request_id(event.frame.content())) {
                    (Some(expected), Some(got)) => *expected == got,
                    _ => false,
                };
                if is_init_reply && let Some(hello) = parse_server_hello(event.frame.content()) {
                    st.row.server_name = hello.server_name;
                    st.row.server_version = hello.server_version;
                    st.row.protocol_version = hello.protocol_version;
                    st.dirty = true;
                }
            }

            // Link 2 of the scope: the roots, observed passively. The request
            // comes from the server, the response from the client — so it
            // travels in the upward direction.
            (Direction::ToServer, None) => {
                if let Some(roots) = parse_roots(event.frame.content()) {
                    st.scope.observe_roots(roots);
                    let resolved = st.scope.resolve();
                    st.row.scope_key = resolved.key();
                    st.row.scope_source = resolved.source().as_str().to_owned();
                    st.dirty = true;
                }
            }

            _ => {}
        }

        if st.dirty {
            st.dirty = false;
            let (id, row) = (st.session_id, st.row.clone());
            drop(st); // never hold a lock across a send
            self.journal.update_session(id, row);
        }
    }
}

impl Observer for JournalObserver {
    fn on_frame(&self, event: &FrameEvent<'_>) {
        if !matches!(event.scan, MethodScan::NoMethod) || event.direction == Direction::ToClient {
            self.observe_semantics(event);
        }

        let session_id = self.state.lock().map(|s| s.session_id).unwrap_or(0);

        let (verdict, rule) = match event.verdict {
            Some(Verdict::Allow) => (Some("allow".to_owned()), None),
            Some(Verdict::Deny { rule, .. }) => (Some("deny".to_owned()), Some(rule.clone())),
            None => (None, None),
        };

        self.journal.log(Entry {
            ts_ms: now_ms(),
            session_id,
            direction: event.direction.as_str(),
            method: event.method.map(str::to_owned),
            disposition: event.disposition.to_string(),
            verdict,
            rule,
            preview: matches!(event.disposition, crate::protocol::mcp::Disposition::Decide)
                .then(|| Self::preview(event.frame.content()))
                .flatten(),
            bytes: event.frame.len() as i64,
        });
    }

    fn on_anomaly(&self, anomaly: &Anomaly) {
        let session_id = self.state.lock().map(|s| s.session_id).unwrap_or(0);

        let (direction, kind, rule) = match anomaly {
            Anomaly::Oversize { direction, limit } => {
                tracing::warn!(limit = limit, "oversized frame rejected");
                (*direction, "oversize", Some("frame_oversize"))
            }
            Anomaly::Unterminated { direction } => (*direction, "unterminated", None),
            Anomaly::DeniedWithoutId { direction } => (*direction, "denied_without_id", None),
            Anomaly::DecisionUnavailable {
                direction,
                reason,
                fail_closed,
            } => {
                tracing::warn!(reason = %reason, fail_closed, "decision point unavailable");
                (*direction, "decision_unavailable", Some("fail_open"))
            }
        };

        self.journal.log(Entry {
            rule: rule.map(str::to_owned),
            ..Entry::now(session_id, direction.as_str(), kind)
        });
    }

    fn on_eof(&self, direction: Direction, stats: SplitterStats) {
        tracing::debug!(
            %direction,
            frames = stats.frames,
            bytes = stats.bytes_in,
            empty = stats.empty_skipped,
            oversize = stats.oversize,
            unterminated = stats.unterminated,
            "end of stream"
        );
    }
}

/// `id` of a request or a response, rendered as text.
///
/// The spec allows an integer or a string; we normalise so comparison need not
/// care about the type.
fn request_id(frame: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    match v.get("id")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Extracts the roots from a response to `roots/list`.
///
/// A root whose URI is not understood is ignored rather than forced into
/// resembling a path: it must never become a permission key.
fn parse_roots(frame: &[u8]) -> Option<Vec<std::path::PathBuf>> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let roots = v.get("result")?.get("roots")?.as_array()?;
    let paths: Vec<_> = roots
        .iter()
        .filter_map(|r| r.get("uri")?.as_str().and_then(parse_root_uri))
        .map(|p| crate::protocol::scope::canonicalize_for_scope(&p))
        .collect();
    (!paths.is_empty()).then_some(paths)
}

/// Current scope provenance, for the UI and the tests.
impl JournalObserver {
    pub fn scope_source(&self) -> ScopeSource {
        self.state
            .lock()
            .map(|s| s.scope.resolve().source())
            .unwrap_or(ScopeSource::Unknown)
    }

    pub fn scope_key(&self) -> String {
        self.state
            .lock()
            .map(|s| s.scope.resolve().key())
            .unwrap_or_else(|_| "unknown".to_owned())
    }

    pub fn scope_paths(&self) -> Vec<std::path::PathBuf> {
        self.state
            .lock()
            .map(|s| s.scope.resolve().paths().to_vec())
            .unwrap_or_default()
    }

    pub fn session_id(&self) -> i64 {
        self.state.lock().map(|s| s.session_id).unwrap_or(0)
    }
}
