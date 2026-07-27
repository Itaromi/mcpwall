//! Fake MCP servers for the integration tests.
//!
//! Deliberately written with blocking I/O and no dependency on `mcpwall`: they
//! must be free to misbehave without our own code deciding how.

use std::io::{BufRead, Write};

/// Reads one line. `None` at end of stream.
pub fn read_line() -> Option<String> {
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).ok()?;
    (n > 0).then_some(line)
}

pub fn write_line(s: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{s}");
    let _ = out.flush();
}

/// Response to `initialize`, conforming to revision 2025-11-25.
pub fn initialize_result(id: &serde_json::Value, name: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": { "tools": { "listChanged": true } },
            "serverInfo": { "name": name, "version": "0.1.0" }
        }
    })
    .to_string()
}

pub fn parse(line: &str) -> Option<serde_json::Value> {
    serde_json::from_str(line.trim_end()).ok()
}
