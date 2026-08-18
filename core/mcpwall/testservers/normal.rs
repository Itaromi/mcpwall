//! A server that behaves correctly.

#[path = "support.rs"]
mod support;

fn main() {
    while let Some(line) = support::read_line() {
        let Some(v) = support::parse(&line) else {
            continue;
        };
        let id = v.get("id").cloned();
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");

        match (method, id) {
            ("initialize", Some(id)) => {
                support::write_line(&support::initialize_result(&id, "normal"))
            }
            ("tools/list", Some(id)) => support::write_line(
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "tools": [{ "name": "echo", "description": "echoes its input" }] }
                })
                .to_string(),
            ),
            ("tools/call", Some(id)) => support::write_line(
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": "ok" }] }
                })
                .to_string(),
            ),
            // Notifications expect nothing back.
            (_, None) => {}
            (_, Some(id)) => support::write_line(
                &serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} }).to_string(),
            ),
        }
    }
}
