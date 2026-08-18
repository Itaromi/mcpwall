//! Turning a frame into something the engine can judge.
//!
//! The paths and the textual values are pulled out of `params` once, here, so
//! that every rule looks at the same extraction rather than re-walking the JSON
//! with its own idea of what counts as an argument.

use std::path::PathBuf;

use crate::protocol::scope::Scope;

// ---------------------------------------------------------------------------
// Request and decision
// ---------------------------------------------------------------------------

/// What we submit to the engine.
pub struct Request<'a> {
    pub method: &'a str,
    /// Tool name, for `tools/call`.
    pub tool: Option<&'a str>,
    /// Paths spotted in the arguments.
    pub paths: Vec<String>,
    /// Textual values of the arguments, for secret detection.
    pub values: Vec<String>,
    /// Origin of the local data recognised in the arguments, when the taint
    /// store found any. Filled in by the daemon, which alone holds the store.
    pub tainted: Option<String>,
    /// Has this tool's advertisement changed since it was last seen?
    ///
    /// Filled in by the daemon, which alone holds the record of what each
    /// server advertised. The engine only reads it — the same shape as
    /// `tainted`, and for the same reason: a rule must see a fact, not call
    /// back into something that could block.
    pub drifted: bool,
    pub scope_key: &'a str,
    pub scope_paths: &'a [PathBuf],
}

impl Request<'_> {
    /// Does an argument path leave the project?
    ///
    /// An unknown scope never returns true: without knowing where the project
    /// is, we cannot say we are leaving it, and pretending otherwise would fire
    /// the rule on all of Claude Desktop's traffic.
    pub(super) fn has_path_outside_scope(&self) -> bool {
        if self.scope_paths.is_empty() {
            return false;
        }
        self.paths.iter().any(|p| {
            let abs = PathBuf::from(p);
            if !abs.is_absolute() {
                return false; // relative to the server's cwd: beyond our reach
            }
            !self.scope_paths.iter().any(|root| abs.starts_with(root))
        })
    }
}

/// Extracts what is evaluable from a `tools/call` or a `resources/read`.
pub fn request_from_frame<'a>(
    method: &'a str,
    frame: &[u8],
    scope: &'a Scope,
    tool_buf: &'a mut String,
) -> Request<'a> {
    let mut paths = Vec::new();
    let mut values = Vec::new();

    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(frame)
        && let Some(params) = v.get("params")
    {
        if let Some(name) = params.get("name").and_then(|n| n.as_str()) {
            tool_buf.push_str(name);
        }
        // `resources/read` carries its path in `uri`.
        if let Some(uri) = params.get("uri").and_then(|u| u.as_str()) {
            if let Some(p) = crate::protocol::scope::parse_root_uri(uri) {
                paths.push(p.to_string_lossy().into_owned());
            }
            values.push(uri.to_owned());
        }
        walk(params, &mut paths, &mut values, 0);
    }

    Request {
        method,
        tool: (!tool_buf.is_empty()).then_some(tool_buf.as_str()),
        paths,
        values,
        // Only the daemon holds the taint store; a request built from a frame
        // alone cannot know, and must not claim otherwise.
        tainted: None,
        // Both are the daemon's to fill in: only it holds the taint store and
        // the record of what each server advertised.
        drifted: false,
        scope_key: "",
        scope_paths: scope.paths(),
    }
}

/// Walks the arguments, collecting strings and paths.
fn walk(v: &serde_json::Value, paths: &mut Vec<String>, values: &mut Vec<String>, depth: u8) {
    // A bounded depth keeps a deeply nested argument from costing time on the
    // hot path.
    if depth > 8 {
        return;
    }
    match v {
        serde_json::Value::String(s) => {
            if looks_like_path(s) {
                paths.push(s.clone());
            }
            values.push(s.clone());
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, paths, values, depth + 1)),
        serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, paths, values, depth + 1)),
        _ => {}
    }
}

fn looks_like_path(s: &str) -> bool {
    (s.starts_with('/') || s.starts_with("~/") || s.starts_with("./") || s.starts_with("../"))
        && !s.contains('\n')
        && s.len() < 4096
}
