//! A streamable HTTP MCP server, written on raw TCP.
//!
//! Deliberately not built on the same HTTP stack as the proxy. What the tests
//! check is the exact bytes crossing the wire — `Content-Length`, SSE framing,
//! a body split across chunks — and a server sharing the proxy's library would
//! agree with it about all three by construction, including where both are
//! wrong.
//!
//! Prints `PORT <n>` on stdout once bound, so the test never has to guess a
//! port or race a fixed one.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

/// Served on a read, as an SSE stream. The credential is the one the taint
/// store has to recognise a moment later.
const CREDENTIAL: &str = "not-a-real-credential-4f3a2b1c0d9e8f7a";

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    println!("PORT {port}");
    let _ = std::io::stdout().flush();

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        std::thread::spawn(move || handle(stream));
    }
}

struct Req {
    method: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

fn read_request(stream: &mut BufReader<TcpStream>) -> Option<Req> {
    let mut line = String::new();
    if stream.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let method = line.split_whitespace().next()?.to_owned();

    let mut headers = Vec::new();
    let mut length = 0usize;
    loop {
        let mut h = String::new();
        if stream.read_line(&mut h).ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((name, value)) = h.split_once(':') {
            let (name, value) = (name.trim().to_owned(), value.trim().to_owned());
            if name.eq_ignore_ascii_case("content-length") {
                length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    let mut body = vec![0u8; length];
    if length > 0 {
        stream.read_exact(&mut body).ok()?;
    }
    Some(Req {
        method,
        body,
        headers,
    })
}

fn handle(stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut out = stream;

    while let Some(req) = read_request(&mut reader) {
        match req.method.as_str() {
            // The server→client stream. Opened, then left alone: what matters
            // is that the proxy forwards it at all, since it carries no call
            // and is therefore never decidable.
            "GET" => {
                write_sse_head(&mut out);
                let _ = out.write_all(b"event: ping\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/ping\"}\n\n");
                let _ = out.flush();
                return;
            }
            "DELETE" => {
                let _ = out.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
                let _ = out.flush();
                continue;
            }
            _ => {}
        }

        // Echoed back so a test can assert the header survived the hop. A
        // proxy that dropped authentication would look like it worked, right
        // up to the first server that needs it.
        let auth = req
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let v: serde_json::Value =
            serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
        let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let tool = v
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");

        match method {
            "initialize" => json(
                &mut out,
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": { "listChanged": true } },
                        "serverInfo": { "name": "httpmcp", "version": "0.1.0" }
                    }
                }),
            ),
            "tools/list" => json(
                &mut out,
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "tools": [
                        { "name": "read_file", "description": "Reads a file." },
                        { "name": "http_post", "description": "Posts a body." }
                    ] }
                }),
            ),
            // A read answers over SSE, in two events split across two writes:
            // the proxy must relay it as a stream and still recognise the
            // message inside it.
            "tools/call" if tool.contains("read") => {
                write_sse_head(&mut out);
                let _ = out.write_all(b": mcpwall test stream\n\n");
                let _ = out.flush();
                let payload = serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{
                        "type": "text",
                        "text": format!("BILLING_TOKEN={CREDENTIAL}\n")
                    }] }
                });
                let _ = out.write_all(format!("event: message\ndata: {payload}\n\n").as_bytes());
                let _ = out.flush();
                return;
            }
            "tools/call" => json(
                &mut out,
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": format!("sent auth={auth}") }] }
                }),
            ),
            _ => json(
                &mut out,
                &serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            ),
        }
    }
}

fn write_sse_head(out: &mut TcpStream) {
    // No `Content-Length`: the length is not known, which is the whole point of
    // a stream, and a proxy that invented one would truncate it.
    let _ = out.write_all(
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: text/event-stream\r\n\
          Cache-Control: no-cache\r\n\
          Connection: close\r\n\r\n",
    );
    let _ = out.flush();
}

fn json(out: &mut TcpStream, body: &serde_json::Value) {
    let body = body.to_string();
    let _ = out.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .as_bytes(),
    );
    let _ = out.flush();
}
