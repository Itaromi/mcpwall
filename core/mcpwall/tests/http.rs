//! The streamable HTTP transport, end to end.
//!
//! Three real processes and a real socket: a fake MCP server on raw TCP, the
//! `mcpwall proxy` in front of it, and the daemon behind it. What is under test
//! is the part no unit can reach — that a refusal reaches the client as an
//! ordinary tool failure, that an SSE response is still a stream by the time it
//! arrives, and that what the stream carried entered the taint store.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mcpwall::transport::http::RouteTable;
use serde_json::Value;

fn mcpwall() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcpwall"))
}

const CREDENTIAL: &str = "not-a-real-credential-4f3a2b1c0d9e8f7a";

const POLICY: &str = r#"
default: allow
fail_closed: false
ask_timeout_seconds: 5
outbound_tools: ["*post*"]
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/forbidden.env"]
    action: deny
    severity: high
    message: "access to a secrets file"
  - id: taint_exfil
    when:
      arg_contains_tainted: true
      tool_is_outbound: true
    action: deny
    severity: critical
    message: "tainted local data in an outbound argument"
overrides: []
"#;

// --- The route table, before anything is served ---

#[test]
fn a_listener_off_loopback_is_refused() {
    // This proxy forwards to servers holding the user's credentials and
    // authenticates nobody. Bound to 0.0.0.0 it is an open relay into every
    // MCP server on the machine, reachable from the local network.
    let table: RouteTable =
        serde_json::from_str(r#"{"listen":"0.0.0.0:8787","routes":{}}"#).expect("json");
    let err = table.resolve().expect_err("must be refused").to_string();
    assert!(err.contains("open relay"), "{err}");
}

#[test]
fn only_http_urls_are_routed() {
    let table: RouteTable =
        serde_json::from_str(r#"{"listen":"127.0.0.1:0","routes":{"x":"file:///etc/passwd"}}"#)
            .expect("json");
    assert!(table.resolve().is_err());
}

#[test]
fn the_default_listener_is_loopback() {
    let table: RouteTable = serde_json::from_str(r#"{"routes":{}}"#).expect("json");
    let (addr, _) = table.resolve().expect("resolve");
    assert!(addr.ip().is_loopback(), "{addr}");
}

// --- The live path ---

struct Stack {
    daemon: Child,
    upstream: Child,
    proxy: Child,
    port: u16,
    dir: PathBuf,
}

impl Stack {
    fn start(tag: &str) -> Self {
        let dir = PathBuf::from(format!("/tmp/mw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("working directory");

        // 1. The real MCP server, which announces the port it got.
        let mut upstream = Command::new(env!("CARGO_BIN_EXE_httpmcp"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("upstream");
        let upstream_port = {
            let out = upstream.stdout.as_mut().expect("stdout");
            let mut line = String::new();
            BufReader::new(out).read_line(&mut line).expect("port line");
            line.trim()
                .strip_prefix("PORT ")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("unreadable port line: {line:?}"))
        };

        // 2. The daemon.
        let socket = dir.join("d.sock");
        let policy = dir.join("policy.yaml");
        std::fs::write(&policy, POLICY).expect("policy");
        let daemon = Command::new(mcpwall())
            .arg("daemon")
            .args(["--socket".as_ref(), socket.as_os_str()])
            .args(["--policy".as_ref(), policy.as_os_str()])
            .args(["--db".as_ref(), dir.join("j.db").as_os_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("daemon");
        wait_for(|| socket.exists(), "the daemon's socket");

        // 3. The proxy, on a port the OS picks so tests can run together.
        let port = free_port();
        let routes = dir.join("routes.json");
        std::fs::write(
            &routes,
            format!(
                r#"{{"listen":"127.0.0.1:{port}","routes":{{"srv":"http://127.0.0.1:{upstream_port}/mcp"}}}}"#
            ),
        )
        .expect("routes");

        let proxy = Command::new(mcpwall())
            .args(["--db".as_ref(), dir.join("j.db").as_os_str()])
            .arg("proxy")
            .args(["--routes".as_ref(), routes.as_os_str()])
            .args(["--socket".as_ref(), socket.as_os_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("proxy");
        wait_for(
            || TcpStream::connect(("127.0.0.1", port)).is_ok(),
            "the proxy's listener",
        );

        Self {
            daemon,
            upstream,
            proxy,
            port,
            dir,
        }
    }

    /// One POST, and the complete raw response.
    fn post(&self, path: &str, body: &str) -> RawResponse {
        self.post_with(path, body, &[])
    }

    fn post_with(&self, path: &str, body: &str, headers: &[(&str, &str)]) -> RawResponse {
        let mut extra = String::new();
        for (name, value) in headers {
            extra.push_str(&format!("{name}: {value}\r\n"));
        }
        self.request(&format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             {extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
    }

    fn request(&self, raw: &str) -> RawResponse {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        s.write_all(raw.as_bytes()).expect("write");
        s.flush().expect("flush");

        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        RawResponse::parse(&buf)
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        for c in [&mut self.proxy, &mut self.daemon, &mut self.upstream] {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct RawResponse {
    status: u16,
    headers: String,
    body: String,
}

impl RawResponse {
    fn parse(bytes: &[u8]) -> Self {
        let text = String::from_utf8_lossy(bytes).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let headers = head.to_lowercase();
        let body = if headers.contains("transfer-encoding: chunked") {
            // A response with no declared length is chunked, and that is
            // correct — it is what a stream looks like on HTTP/1.1. The test
            // client has to speak it rather than the proxy having to avoid it.
            dechunk(body)
        } else {
            body.to_owned()
        };

        Self {
            status,
            headers,
            body,
        }
    }

    /// The JSON-RPC message, wherever it is — a plain body, or inside SSE.
    fn message(&self) -> Value {
        if let Ok(v) = serde_json::from_str::<Value>(self.body.trim()) {
            return v;
        }
        for line in self.body.lines() {
            if let Some(rest) = line.strip_prefix("data:")
                && let Ok(v) = serde_json::from_str::<Value>(rest.trim())
            {
                return v;
            }
        }
        panic!("no JSON-RPC message in the response: {:?}", self.body);
    }
}

/// Reassembles a chunked body.
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size_line.trim(), 16) else {
            break;
        };
        if size == 0 || after.len() < size {
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].strip_prefix("\r\n").unwrap_or(&after[size..]);
    }
    out
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn wait_for(mut ready: impl FnMut() -> bool, what: &str) {
    let start = Instant::now();
    while !ready() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn call(id: u32, tool: &str, args: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
    )
}

// --- Blocking ---

#[test]
fn a_refused_call_never_reaches_the_upstream() {
    let s = Stack::start("http-deny");
    let r = s.post(
        "/srv",
        &call(1, "read_file", r#"{"path":"/x/forbidden.env"}"#),
    );

    // 200, not 4xx. A refusal is an ordinary tool failure; a transport error
    // would make the agent retry the session instead of adapting.
    assert_eq!(r.status, 200, "{}", r.body);
    let m = r.message();
    assert_eq!(m["result"]["isError"], true, "{}", r.body);
    assert!(
        m.get("error").is_none(),
        "never a protocol error: {}",
        r.body
    );
    let text = m["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.starts_with("blocked by mcpwall:"), "{text}");
    assert!(text.contains("secrets_paths"), "{text}");

    // The upstream answers `sent auth=` to any non-read call, so a body that
    // came from it is unmistakable.
    assert!(
        !r.body.contains("sent auth="),
        "the call was forwarded anyway"
    );
}

#[test]
fn an_unknown_route_is_not_a_gateway_into_the_machine() {
    let s = Stack::start("http-route");
    assert_eq!(s.post("/nope", &call(1, "read_file", "{}")).status, 404);
}

// --- Passing through ---

#[test]
fn an_allowed_call_is_forwarded_with_its_headers() {
    // A proxy that dropped `Authorization` would look like it worked, right up
    // to the first server that needs it.
    let s = Stack::start("http-allow");
    let r = s.post_with(
        "/srv",
        &call(1, "http_post", r#"{"body":"hello"}"#),
        &[("Authorization", "Bearer token-123")],
    );

    assert_eq!(r.status, 200, "{}", r.body);
    let text = r.message()["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert_eq!(text, "sent auth=Bearer token-123", "{}", r.body);

    // The upstream declared a length and we did not touch the body, so the
    // length is still the truth. Dropping it would force the response into
    // chunked framing — legal, and still a rewrite of how the message is
    // delimited, which §5 rules out on this transport.
    assert!(
        r.headers.contains("content-length"),
        "the upstream's length must survive: {}",
        r.headers
    );
    assert!(
        !r.headers.contains("transfer-encoding"),
        "a response with a known length must not be re-framed: {}",
        r.headers
    );
}

#[test]
fn a_get_opens_the_event_stream_untouched() {
    // `GET` carries no call, so there is nothing to decide — the same reasoning
    // that keeps `initialize` out of DECIDE.
    let s = Stack::start("http-get");
    let r = s.request(
        "GET /srv HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(r.status, 200);
    assert!(
        r.headers.contains("text/event-stream"),
        "the content type must survive: {}",
        r.headers
    );
    assert!(r.body.contains("notifications/ping"), "{}", r.body);
}

#[test]
fn a_delete_ends_the_session_untouched() {
    let s = Stack::start("http-delete");
    let r = s.request("DELETE /srv HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 204);
}

#[test]
fn a_streamed_response_keeps_its_framing() {
    // Not buffered into one JSON body. An SSE response the proxy collected
    // before answering would stop being a stream — the client would wait for
    // the whole thing, which for a long-running call is exactly what SSE
    // exists to avoid.
    let s = Stack::start("http-sse");
    let r = s.post("/srv", &call(1, "read_file", r#"{"path":"/x/ok.txt"}"#));

    assert_eq!(r.status, 200);
    assert!(r.headers.contains("text/event-stream"), "{}", r.headers);
    assert!(
        !r.headers.contains("content-length"),
        "a length invented for a stream would truncate it: {}",
        r.headers
    );
    assert!(r.body.contains("event: message"), "{}", r.body);
    assert!(
        r.body.starts_with(": mcpwall test stream"),
        "the comment event must survive verbatim: {:?}",
        r.body
    );
}

// --- The whole point ---

#[test]
fn a_secret_read_over_sse_is_recognised_on_its_way_back_out() {
    // The scenario of §1 over the HTTP transport. What makes it worth its own
    // test is where the secret was: inside an SSE event, in a stream the proxy
    // is forwarding chunk by chunk and must observe without holding up.
    let s = Stack::start("http-exfil");

    let read = s.post("/srv", &call(1, "read_file", r#"{"path":"/x/ok.txt"}"#));
    assert!(
        read.body.contains(CREDENTIAL),
        "the upstream must actually serve the credential: {}",
        read.body
    );

    let out = s.post(
        "/srv",
        &call(2, "http_post", &format!(r#"{{"body":"{CREDENTIAL}"}}"#)),
    );
    let m = out.message();
    assert_eq!(
        m["result"]["isError"], true,
        "the exfiltration went through: {}",
        out.body
    );
    let text = m["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.contains("taint_exfil"), "{text}");
}
