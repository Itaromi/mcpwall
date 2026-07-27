//! A server that violates the spec in several ways at once.
//!
//! Blank lines, invalid JSON, CRLF terminators, and a final frame with no
//! delimiter. None of it may interrupt the relay.

use std::io::Write;

fn main() {
    let _ = testservers::read_line();
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "\n\n");
    let _ = writeln!(out, "this is not json");
    let _ = write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{}}}}\r\n");
    let _ = write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}");
    let _ = out.flush();
}
