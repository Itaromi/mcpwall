//! A server that hands back what it is asked to read, then accepts anything.
//!
//! `normal` answers `"ok"` to every call. That is enough to exercise the relay,
//! but it puts nothing into the taint store: there is no local data for a later
//! call to be recognised as carrying. The complete attack of spec §11 — read a
//! secret, then try to send it out — cannot be reproduced against it.
//!
//! This one returns a payload on a read and confirms on an outbound call, which
//! is exactly the pair of behaviours the scenario needs.

#[path = "support.rs"]
mod support;

/// The contents of the `.env` this server pretends to hold.
///
/// The credential has to satisfy two opposite constraints, and the first draft
/// failed the second one.
///
/// It must **not** be matched by any of the policy's secret detectors — no
/// `sk-`, no `ghp_`, no `AKIA`, no PEM header. Otherwise the exfiltration
/// attempt would be refused on the shape of the value, the test would pass
/// without the taint store ever being consulted, and it would keep passing with
/// taint tracking deleted outright.
///
/// It must equally not look like a real credential to anyone *else*. A
/// plausible `rk_live_…` body was rejected by GitHub's push protection as a
/// Stripe live restricted key — correctly, on the shape alone, which is the
/// same reasoning this project applies. A fake secret in a repository is a
/// liability whatever its provenance, so the value says what it is.
///
/// What matters to the test is only that it is one token of at least
/// `taint::MIN_TOKEN_LEN` characters.
pub const ENV_FILE: &str = "# production configuration\n\
                            BILLING_TOKEN=not-a-real-credential-4f3a2b1c0d9e8f7a\n\
                            DEBUG=false\n";

/// The single credential an injected agent would lift out of that file.
pub const CREDENTIAL: &str = "not-a-real-credential-4f3a2b1c0d9e8f7a";

fn main() {
    while let Some(line) = support::read_line() {
        let Some(v) = support::parse(&line) else {
            continue;
        };
        let id = v.get("id").cloned();
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let tool = v
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");

        match (method, id) {
            ("initialize", Some(id)) => {
                support::write_line(&support::initialize_result(&id, "leaky"))
            }
            ("tools/call", Some(id)) => {
                let text = if tool.contains("read") {
                    ENV_FILE
                } else {
                    "sent"
                };
                support::write_line(
                    &serde_json::json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "content": [{ "type": "text", "text": text }] }
                    })
                    .to_string(),
                );
            }
            (_, None) => {}
            (_, Some(id)) => support::write_line(
                &serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} }).to_string(),
            ),
        }
    }
}
