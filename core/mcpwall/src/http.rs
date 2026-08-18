//! Streamable HTTP transport.
//!
//! Spec §5. The second of the two transports MCP defines: `POST` carrying one
//! JSON-RPC message, and a response that is either a single JSON body or an SSE
//! stream of them.
//!
//! ## Why this one cannot be a shim
//!
//! Over stdio, mcpwall is started **by the client**, as the server's command.
//! If mcpwall is not installed the client runs the server directly and nothing
//! is lost. That is what makes the availability rule of §4 free: a daemon that
//! is not answering costs a policy, never a session.
//!
//! Over HTTP the client opens a socket to a URL. There is no command to wrap
//! and no process to interpose — the only way in is to **be the URL**, which
//! means a local listener the client is pointed at, forwarding to the real one.
//!
//! The consequence is unavoidable and must not be discovered by the user in
//! production: **if this proxy is not running, the servers routed through it
//! are unreachable.** No amount of fail-open reasoning changes it, because
//! there is nothing left to fail open *to*. The daemon being unreachable is
//! still handled the usual way — traffic goes through unfiltered — but the
//! proxy itself is load-bearing in a way the stdio shim never is. It is
//! supervised like the daemon, and `mcpwall restore` puts the original URLs
//! back.
//!
//! ## Byte passthrough
//!
//! Nothing is re-serialised. A re-encoded body would change its length and
//! invalidate `Content-Length`, and any upstream sensitive to exact bytes would
//! break. Requests are forwarded as received; responses are streamed back
//! chunk by chunk, with a copy taken for observation rather than the stream
//! being buffered to look at it. An SSE stream that we buffered would stop
//! being a stream.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};

use crate::mcp::{
    CallContext, DecisionPoint, Disposition, MethodScan, Verdict, classify, deny_response,
    scan_method,
};

/// Ceiling on a request body held in memory.
///
/// A request has to be read whole before it can be judged: the method and the
/// arguments are the thing being decided on. The same 32 MB ceiling as the
/// frame splitter, for the same reason — beyond it we are no longer looking at
/// a tool call.
pub const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

/// Headers that describe *this* hop and are meaningless past it.
///
/// Forwarding `transfer-encoding` is how a proxy ends up advertising a framing
/// it is not performing.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// On the request, additionally: `host` is the next hop's to set, and
/// `content-length` is recomputed from the body we actually send.
fn strip_from_request(name: &HeaderName) -> bool {
    let n = name.as_str();
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(n))
        || n.eq_ignore_ascii_case("host")
        || n.eq_ignore_ascii_case("content-length")
}

/// On the response, `content-length` is **kept**.
///
/// We do not touch the body, so the length the upstream declared is still the
/// truth. Dropping it would force every response into chunked framing — legal,
/// and still a rewrite of how the message is delimited, on a transport whose
/// rule in §5 is that we relay bytes rather than reformat them. A response with
/// no length, an SSE stream, has nothing to preserve and is chunked as it
/// should be.
fn strip_from_response(name: &HeaderName) -> bool {
    let n = name.as_str();
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(n))
}

/// Where one route sends its traffic.
#[derive(Debug, Clone)]
pub struct Route {
    /// First path segment the client addresses, e.g. `github`.
    pub name: String,
    /// The real server.
    pub upstream: Uri,
}

/// The route table, as `init` writes it.
///
/// ```json
/// { "listen": "127.0.0.1:8787", "routes": { "github": "https://mcp.example/v1" } }
/// ```
///
/// Its own file rather than a section of `policy.yaml`: the policy is meant to
/// be read and edited by a person, while this is generated, and mixing the two
/// invites `init` to rewrite something the user hand-wrote.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RouteTable {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub routes: std::collections::BTreeMap<String, String>,
}

/// Loopback only, and never configurable to anything else by accident.
///
/// This listener forwards to servers holding the user's credentials and answers
/// without authenticating anyone. Bound to `0.0.0.0` it would be an open relay
/// into every MCP server on the machine, reachable from the local network.
fn default_listen() -> String {
    "127.0.0.1:8787".to_owned()
}

impl Default for RouteTable {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            routes: std::collections::BTreeMap::new(),
        }
    }
}

impl RouteTable {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("{} is not valid JSON", path.display()))
    }

    /// Parses the addresses and URLs, refusing anything that is not loopback.
    pub fn resolve(&self) -> Result<(SocketAddr, Vec<Route>)> {
        let addr: SocketAddr = self
            .listen
            .parse()
            .with_context(|| format!("`{}` is not an address", self.listen))?;
        if !addr.ip().is_loopback() {
            anyhow::bail!(
                "refusing to listen on {addr}: this proxy forwards to servers holding your \
                 credentials and authenticates nobody. Bound off loopback it is an open relay \
                 into every MCP server on this machine."
            );
        }

        let mut routes = Vec::new();
        for (name, url) in &self.routes {
            let upstream: Uri = url
                .parse()
                .with_context(|| format!("route `{name}`: `{url}` is not a URL"))?;
            match upstream.scheme_str() {
                Some("http" | "https") => {}
                _ => anyhow::bail!("route `{name}`: only http and https are supported"),
            }
            routes.push(Route {
                name: name.clone(),
                upstream,
            });
        }
        Ok((addr, routes))
    }
}

/// Everything the proxy needs to serve one request.
pub struct Proxy {
    routes: Vec<Route>,
    decision: Arc<dyn DecisionPoint>,
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        BoxBody<Bytes, hyper::Error>,
    >,
}

impl Proxy {
    pub fn new(routes: Vec<Route>, decision: Arc<dyn DecisionPoint>) -> Result<Arc<Self>> {
        // Roots compiled in rather than read from the system store: the binary
        // is meant to be static and to behave identically on a machine whose
        // keychain we have never seen.
        let tls = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();

        Ok(Arc::new(Self {
            routes,
            decision,
            client: Client::builder(TokioExecutor::new()).build(tls),
        }))
    }

    fn route_for(&self, path: &str) -> Option<(&Route, String)> {
        let trimmed = path.trim_start_matches('/');
        let (head, rest) = match trimmed.split_once('/') {
            Some((h, r)) => (h, format!("/{r}")),
            None => (trimmed, String::new()),
        };
        let route = self.routes.iter().find(|r| r.name == head)?;
        Some((route, rest))
    }

    /// Serves one request.
    ///
    /// Never returns an error to the client on our own account: a proxy that
    /// answers 500 because the policy engine had a bad day has broken the
    /// session it was meant to protect.
    pub async fn serve(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
        Ok(self.handle(req).await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "proxying failed");
            text_response(StatusCode::BAD_GATEWAY, "mcpwall: upstream unreachable")
        }))
    }

    async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let path = req.uri().path().to_owned();
        let Some((route, rest)) = self.route_for(&path) else {
            return Ok(text_response(
                StatusCode::NOT_FOUND,
                "mcpwall: no server is routed here",
            ));
        };
        let server = route.name.clone();
        let target = join(&route.upstream, &rest, req.uri().query())?;

        let (parts, body) = req.into_parts();

        // `GET` opens the server→client SSE stream and `DELETE` ends a session.
        // Neither carries a call, so neither is decidable — the same reasoning
        // that keeps `initialize` out of DECIDE in §5. Forwarded untouched.
        if parts.method != Method::POST {
            let forwarded = self.forward(&parts, target, empty_body(), &server).await?;
            return Ok(forwarded);
        }

        let collected = body
            .collect()
            .await
            .context("reading the request body")?
            .to_bytes();

        if collected.len() > MAX_REQUEST_BYTES {
            return Ok(text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "mcpwall: request over the 32 MB ceiling",
            ));
        }

        // One frame per body: JSON-RPC batching was removed in revision
        // 2025-06-18, so a body starting with `[` is a violation to note, not a
        // case to support.
        let scan = scan_method(&collected);
        if let Some(blocked) = self.verdict_for(&scan, &collected) {
            // A refusal is an ordinary tool failure with a 200, exactly as over
            // stdio. A 4xx would tell the client the transport is broken, and
            // the agent would retry the whole session rather than adapt.
            return Ok(json_response(StatusCode::OK, blocked));
        }

        self.forward(&parts, target, full_body(collected), &server)
            .await
    }

    /// The verdict, or `None` when the call goes through.
    fn verdict_for(&self, scan: &MethodScan, frame: &[u8]) -> Option<Vec<u8>> {
        let MethodScan::Found { method, .. } = scan else {
            return None;
        };
        if classify(scan) != Disposition::Decide {
            return None;
        }

        let ctx = CallContext {
            method: method.as_str(),
            frame,
        };
        match self.decision.decide(&ctx) {
            Ok(Verdict::Deny { rule, message }) => deny_response(frame, &rule, &message),
            Ok(Verdict::Allow) => None,
            Err(e) => {
                // Same rule as the stdio path: an unreachable decision point
                // lets traffic through unless the policy says otherwise.
                if e.fail_closed {
                    deny_response(frame, "fail_closed", "policy engine unavailable")
                } else {
                    tracing::warn!(reason = %e.reason, "no verdict, letting it through");
                    None
                }
            }
        }
    }

    async fn forward(
        &self,
        parts: &hyper::http::request::Parts,
        target: Uri,
        body: BoxBody<Bytes, hyper::Error>,
        server: &str,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let mut out = Request::builder().method(parts.method.clone()).uri(target);

        for (name, value) in parts.headers.iter() {
            if !strip_from_request(name) {
                out = out.header(name, value);
            }
        }

        let upstream = self
            .client
            .request(out.body(body).context("building the upstream request")?)
            .await
            .context("calling the upstream")?;

        let (parts, body) = upstream.into_parts();
        let mut builder = Response::builder().status(parts.status);
        for (name, value) in parts.headers.iter() {
            if !strip_from_response(name) {
                builder = builder.header(name, value);
            }
        }

        // Observed as it flows, not after. Buffering an SSE stream to look at
        // it would stop it being a stream: the client would sit waiting for a
        // response that only arrives once the server has finished, which for a
        // long-running tool call is the whole point of SSE.
        let observed = observe_stream(body, self.decision.clone(), server.to_owned());

        builder.body(observed).context("building the response")
    }
}

/// Wraps a response body so every chunk is offered for observation on its way
/// past.
fn observe_stream(
    body: Incoming,
    decision: Arc<dyn DecisionPoint>,
    _server: String,
) -> BoxBody<Bytes, hyper::Error> {
    let mut buffer = Vec::new();
    body.map_frame(move |frame| {
        if let Some(data) = frame.data_ref() {
            buffer.extend_from_slice(data);
            for message in take_messages(&mut buffer) {
                decision.observe_response(&message);
            }
        }
        frame
    })
    .boxed()
}

/// Extracts the complete JSON-RPC messages a buffer holds, leaving the tail.
///
/// Handles both response shapes with one piece of code. A plain JSON body
/// arrives as one message with no framing; an SSE stream arrives as
/// `data:` lines separated by blank ones. Rather than branch on
/// `Content-Type` — which servers get wrong, and which says nothing about a
/// body split across chunk boundaries — we look for what both actually
/// contain: something that parses as a JSON object.
fn take_messages(buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    // SSE: everything up to the last blank-line boundary is complete.
    while let Some(end) = find_event_end(buffer) {
        let event = buffer.drain(..end).collect::<Vec<u8>>();
        for line in event.split(|b| *b == b'\n') {
            let line = strip_cr(line);
            if let Some(rest) = line.strip_prefix(b"data:") {
                let payload = rest.strip_prefix(b" ").unwrap_or(rest);
                if !payload.is_empty() {
                    out.push(payload.to_vec());
                }
            }
        }
    }

    // A plain JSON body has no boundary and no `data:` prefix. It is complete
    // when it parses, and until then the tail is kept for the next chunk.
    if out.is_empty()
        && !buffer.is_empty()
        && serde_json::from_slice::<serde_json::Value>(buffer).is_ok()
    {
        out.push(std::mem::take(buffer));
    }

    // A buffer that will never parse must not grow without bound.
    if buffer.len() > MAX_REQUEST_BYTES {
        buffer.clear();
    }
    out
}

/// Offset just past the first `\n\n` (or `\r\n\r\n`) in the buffer.
fn find_event_end(buffer: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < buffer.len() {
        if buffer[i] == b'\n' && buffer[i + 1] == b'\n' {
            return Some(i + 2);
        }
        if i + 3 < buffer.len() && &buffer[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Builds the upstream URI: the route's target, plus whatever path and query
/// the client added past the route name.
fn join(upstream: &Uri, rest: &str, query: Option<&str>) -> Result<Uri> {
    let mut parts = upstream.clone().into_parts();
    let base = upstream.path().trim_end_matches('/');
    let path = format!("{base}{rest}");
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };

    let with_query = match query {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path,
    };
    parts.path_and_query = Some(with_query.parse().context("building the upstream path")?);
    Uri::from_parts(parts).context("building the upstream URI")
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(bytes: Bytes) -> BoxBody<Bytes, hyper::Error> {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

fn text_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut r = Response::new(full_body(Bytes::from(message.to_owned())));
    *r.status_mut() = status;
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut r = Response::new(full_body(Bytes::from(body)));
    *r.status_mut() = status;
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

/// Listens until the process is stopped.
pub async fn serve(proxy: Arc<Proxy>, addr: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("listening on {addr}"))?;

    tracing::info!(%addr, routes = proxy.routes.len(), "http proxy listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "connection refused");
                continue;
            }
        };
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| proxy.clone().serve(req));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                // SSE responses are long-lived and mostly idle. Without this,
                // hyper would treat a quiet stream as a finished one.
                .keep_alive(true)
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}
