//! A server that answers with an 8 MB payload.
//!
//! Checks that back-pressure cannot deadlock: the shim must drain this stream
//! without the other direction ceasing to make progress.

fn main() {
    while let Some(line) = testservers::read_line() {
        let Some(v) = testservers::parse(&line) else {
            continue;
        };
        let Some(id) = v.get("id").cloned() else {
            continue;
        };
        let blob = "z".repeat(8 * 1024 * 1024);
        testservers::write_line(
            &serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "content": [{ "type": "text", "text": blob }] }
            })
            .to_string(),
        );
    }
}
