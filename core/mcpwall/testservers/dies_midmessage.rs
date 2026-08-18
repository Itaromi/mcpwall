//! A server that dies in the middle of a message.
//!
//! The case where the upstream writes the start of a frame then disappears: the
//! shim must exit cleanly rather than wait for a frame that will never end.

#[path = "support.rs"]
mod support;

use std::io::Write;

fn main() {
    let _ = support::read_line();
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"resu");
    let _ = out.flush();
    std::process::exit(3);
}
