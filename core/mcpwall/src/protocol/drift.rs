//! Rug-pull detection: a tool whose description changed under the user.
//!
//! Spec §5. An MCP server can serve one `tools/list` on the day it is approved
//! and a different one a month later. The description is not documentation —
//! it is the text the model reads to decide what the tool does and when to
//! reach for it. Rewriting it after approval turns an audited tool into
//! something else while every name, every signature and every permission the
//! user granted stays exactly as it was.
//!
//! Nothing else in mcpwall would notice. The policy judges arguments, the taint
//! store judges data, and both are looking at a call the model was talked into
//! making. This module watches the text that did the talking.
//!
//! I/O-free, like `frame`, `mcp`, `scope` and `taint`: it stays fuzzable without
//! a runtime, and what it hashes is decided here rather than wherever a frame
//! happens to arrive.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// One advertised tool, reduced to a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDigest {
    pub name: String,
    /// Hex SHA-256. Persisted, therefore a contract: changing what goes into it
    /// changes every stored hash at once, which would read as every tool on the
    /// machine drifting on the same day. That needs a migration, not an edit.
    pub sha256: String,
}

/// The tools a `tools/list` response advertises, or `None` if this is not one.
///
/// Recognised by shape rather than by correlating with the request that asked.
/// `result.tools` as an array is what the schema says a `tools/list` result is,
/// and correlating would mean the shim tracking OBSERVE requests as well —
/// machinery whose only job would be to re-derive something already visible.
///
/// Pagination needs no special handling: a page reports the tools on it, and
/// each is stored under its own name.
pub fn tools_in_response(frame: &[u8]) -> Option<Vec<ToolDigest>> {
    let v: Value = serde_json::from_slice(frame).ok()?;
    let tools = v.get("result")?.get("tools")?.as_array()?;

    let mut out = Vec::with_capacity(tools.len());
    for t in tools {
        let Some(name) = t.get("name").and_then(Value::as_str) else {
            continue;
        };
        out.push(ToolDigest {
            name: name.to_owned(),
            sha256: digest(t),
        });
    }
    (!out.is_empty()).then_some(out)
}

/// What one tool's advertisement hashes to.
///
/// The description **and** the input schema. The spec names the description,
/// which is the vector everyone thinks of; the schema is the one that costs
/// nothing to watch and would otherwise be free real estate. A server that
/// leaves its description untouched and quietly adds an `exfiltrate_to`
/// parameter — or widens an enum, or makes an optional field required — has
/// changed what the tool does just as surely, and every permission the user
/// granted still applies.
///
/// The name is included too, so that a digest cannot be replayed from one tool
/// onto another.
pub fn digest(tool: &Value) -> String {
    let mut h = Sha256::new();
    h.update(b"mcpwall/tool/v1\n");
    h.update(tool.get("name").and_then(Value::as_str).unwrap_or_default());
    h.update(b"\n");
    h.update(
        tool.get("description")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    h.update(b"\n");
    if let Some(schema) = tool.get("inputSchema") {
        h.update(canonical(schema));
    }
    format!("{:x}", h.finalize())
}

/// Renders a value with object keys in sorted order.
///
/// `serde_json` already sorts them — its `Map` is a `BTreeMap` unless the
/// `preserve_order` feature is on. That is the problem: the feature is additive
/// across the whole dependency graph, so any crate anywhere in the tree could
/// switch it on, and every stored hash would change at once. The user would
/// wake up to a confirmation prompt for every tool they own, on a day nothing
/// had actually drifted.
///
/// Twenty lines to not depend on a flag we do not control.
fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}
