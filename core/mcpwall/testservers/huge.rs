//! A server that answers with an 8 MB payload.
//!
//! Checks that back-pressure cannot deadlock: the shim must drain this stream
//! without the other direction ceasing to make progress.

#[path = "support.rs"]
mod support;

fn main() {
    while let Some(line) = support::read_line() {
        let Some(v) = support::parse(&line) else {
            continue;
        };
        let Some(id) = v.get("id").cloned() else {
            continue;
        };
        let blob = "z".repeat(8 * 1024 * 1024);
        support::write_line(
            &serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "content": [{ "type": "text", "text": blob }] }
            })
            .to_string(),
        );
    }
}
