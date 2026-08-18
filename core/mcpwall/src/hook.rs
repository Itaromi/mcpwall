//! The Claude Code hook: the blind spot an MCP proxy cannot see.
//!
//! Spec §7. mcpwall sits between MCP clients and MCP servers, so it sees MCP
//! traffic — and Claude Code's built-in tools (`Read`, `Edit`, `Bash`,
//! `WebFetch`) do not go through MCP at all. They are most of the attack
//! surface. The central scenario of §1 does not even need an MCP server to
//! happen: `Read` the `.env`, `WebFetch` it to an attacker. Everything the
//! proxy does would be beside the point.
//!
//! So the same daemon is wired to Claude Code's `PreToolUse` and `PostToolUse`
//! hooks. Same policy file, same taint store, same journal, same decision panel.
//! Nothing here re-implements a decision; this module translates one protocol
//! into another and gets out of the way.
//!
//! ## Two events, two jobs
//!
//! - `PreToolUse` carries the call before it runs, and is the only one that can
//!   block. It becomes a decision request.
//! - `PostToolUse` carries the result and **cannot** block, which is exactly
//!   what taint tracking needs: it is where what a local read returned becomes
//!   known, and where it enters the store.
//!
//! Without the second, the first is close to useless. A policy that can refuse
//! an outbound call but never learns what was read has nothing to recognise in
//! it.
//!
//! ## What this module deliberately does not do
//!
//! **It never answers `allow`.** On a call the policy permits, it writes nothing
//! at all and exits 0, leaving Claude Code's own permission flow exactly as it
//! found it. mcpwall exists to refuse calls the client would have accepted, not
//! to accept ones the client would have questioned; a firewall that quietly
//! widens the permissions around it is a downgrade sold as a feature.
//!
//! **It ignores `mcp__*` tools.** MCP tool calls also raise `PreToolUse`, and
//! they have already crossed the shim. Deciding twice would double every
//! journal entry and — far worse — put the same confirmation prompt in front of
//! the user twice for one call.

use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::ipc::client::{DaemonClient, SessionInfo};
use crate::protocol::mcp::{CallContext, DecisionPoint, Verdict};
use crate::protocol::scope::{ScopeResolver, canonicalize_for_scope};

/// Prefix Claude Code gives to tools that come from an MCP server.
const MCP_PREFIX: &str = "mcp__";

/// What Claude Code writes on the hook's stdin.
///
/// Only the fields we act on are named; the schema carries a good deal more and
/// grows with each release, so unknown fields are ignored rather than refused.
/// A hook that failed to parse would block the user's tool call over a field it
/// never needed.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct HookInput {
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    /// The tool's result, on `PostToolUse`.
    ///
    /// Accepted under either name. The published schema calls it `tool_output`;
    /// `tool_response` is the name it went by earlier and the one some releases
    /// still send. Reading both costs one attribute — and spec §13 is explicit
    /// that these formats change, so the cheap defence is worth having.
    #[serde(alias = "tool_response")]
    pub tool_output: serde_json::Value,
    pub tool_use_id: String,
    pub cwd: String,
    pub session_id: String,
}

/// Which built-in tools produce local data.
///
/// The MCP side classifies by name — spec §6 matches `*read*`, `*file*`,
/// `*exec*` — because a third-party server's tools are not known in advance.
/// Here they are: a fixed, documented set, where guessing would be both less
/// accurate and less honest.
///
/// The outbound half of the question is **not** answered here: it belongs in
/// `outbound_tools` in `policy.yaml`, where the user can see it and change it.
/// `WebFetch` and `WebSearch` are listed among its defaults.
///
/// This half cannot be. Whether a result must be fingerprinted is not a policy
/// choice, it is a fact about the tool, and it is asked on the `PostToolUse`
/// path where nothing is being decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    /// Its result is local data: fingerprint it.
    LocalRead,
    /// Not a source of local data.
    Other,
}

/// Classifies a built-in tool.
///
/// Unknown names fall to `Other`, which includes every tool a future release
/// adds: a new source of local data will be missed until it is listed. That is
/// a false negative, which §6 accepts, and the alternative — fingerprinting
/// every result of every tool — would fill the store with the agent's own
/// output and start refusing the user's ordinary calls.
pub fn classify(tool: &str) -> Builtin {
    match tool {
        // `Bash` is a local read whatever it was asked to do: its output is
        // whatever the command printed. The MCP side's name globs — `*read*`,
        // `*file*`, `*exec*` — get `Read` right and miss this one entirely,
        // and `cat .env` is the shortest path there is from a secret to an
        // agent's context.
        "Read" | "Bash" | "BashOutput" | "Grep" | "Glob" | "NotebookRead" => Builtin::LocalRead,
        _ => Builtin::Other,
    }
}

/// A tool call that mcpwall must not judge, because something else already has.
pub fn is_mcp_tool(tool: &str) -> bool {
    tool.starts_with(MCP_PREFIX)
}

/// Renders the call as the JSON-RPC frame the policy engine already knows how to
/// read.
///
/// Translating instead of adding a second input shape is the whole point. The
/// engine extracts paths, values and secrets from `params.arguments`; give it
/// that and a `Read` of `~/.ssh/id_rsa` is judged by the same `secrets_paths`
/// rule, with the same wording, as the MCP server that reads the same file.
/// Two code paths to the same verdict would drift, and the one that drifted
/// would be the one nobody was watching.
pub fn frame_for(input: &HookInput) -> Vec<u8> {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": format!("hook-{}", input.tool_use_id),
        "method": "tools/call",
        "params": {
            "name": input.tool_name,
            "arguments": input.tool_input,
        }
    })
    .to_string()
    .into_bytes()
}

/// What the hook writes back on stdout.
///
/// `None` means: say nothing, change nothing. That is the answer for everything
/// mcpwall does not refuse.
pub fn deny_output(reason: &str) -> String {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })
    .to_string()
}

/// The scope this hook call belongs to.
///
/// `cwd` is Claude Code's working directory, which is the project — but it
/// reaches us as an observed directory, not as something `mcpwall init`
/// declared, so it enters the chain of §6bis at rank 3 and no higher.
/// Canonicalisation is mandatory there: without it `/tmp` and `/private/tmp`
/// key differently from one session to the next and permissions stop matching.
///
/// The consequence is deliberate: under rank 3 the interface does not offer
/// "always allow". Being unable to grant a permanent permission from a
/// provenance we only inferred is the correct outcome, not a limitation to work
/// around.
fn scope_for(cwd: &str, project: Option<&Path>) -> ScopeResolver {
    let mut resolver = ScopeResolver::new();
    if let Some(p) = project {
        // `mcpwall init` knew which project it was writing the hook for.
        resolver.set_injected(canonicalize_for_scope(p));
    } else if !cwd.is_empty() {
        resolver.set_cwd(canonicalize_for_scope(Path::new(cwd)));
    }
    resolver
}

/// Reads the hook payload from stdin.
pub fn read_input(mut r: impl Read) -> Option<HookInput> {
    let mut buf = String::new();
    r.read_to_string(&mut buf).ok()?;
    serde_json::from_str(&buf).ok()
}

/// The text a `PostToolUse` result reduces to for fingerprinting.
///
/// A string result is taken as is; anything else is rendered as JSON. The
/// shape varies per tool and per release, and the fingerprint only needs the
/// words — chasing every result schema would be work with no payoff.
pub fn output_text(output: &serde_json::Value) -> String {
    match output {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// What a taint report should name as the origin.
///
/// The path when the arguments carry one, the command for `Bash`, the tool name
/// otherwise. A refusal that says only "local data" gives the user nothing to
/// check.
pub fn origin_of(input: &HookInput) -> String {
    let args = &input.tool_input;
    for key in ["file_path", "path", "notebook_path", "pattern", "command"] {
        if let Some(s) = args.get(key).and_then(|v| v.as_str())
            && !s.is_empty()
        {
            return s.to_owned();
        }
    }
    input.tool_name.clone()
}

/// Runs one hook invocation and returns what should go to stdout.
///
/// Every failure path returns `None`. An unreachable daemon, a payload that
/// does not parse, an event we do not handle: none of them may cost the user
/// their tool call. That is the availability rule of §4, and it matters more
/// here than on the MCP side — a broken hook breaks the agent itself, not one
/// of its servers.
pub fn run(input: &HookInput, socket: &Path, project: Option<&Path>) -> Option<String> {
    if is_mcp_tool(&input.tool_name) {
        return None;
    }

    let scope = scope_for(&input.cwd, project).resolve();
    let session = SessionInfo {
        scope_key: scope.key(),
        scope_source: scope.source().as_str().to_owned(),
        scope_paths: scope.paths().to_vec(),
        server: Some("claude-code".to_owned()),
        session_id: 0,
    };

    let client = DaemonClient::connect(socket, false, session)?;

    match input.hook_event_name.as_str() {
        "PreToolUse" => {
            let frame = frame_for(input);
            let ctx = CallContext {
                method: "tools/call",
                frame: &frame,
            };
            match client.decide(&ctx) {
                Ok(Verdict::Deny { rule, message }) => Some(deny_output(&format!(
                    "blocked by mcpwall: {message} (rule: {rule})"
                ))),
                // Allowed, or the daemon could not answer. Either way we stay
                // silent and let Claude Code's own permission flow run.
                _ => None,
            }
        }
        "PostToolUse" => {
            if classify(&input.tool_name) == Builtin::LocalRead {
                let text = output_text(&input.tool_output);
                if !text.is_empty() {
                    client.report_taint(&origin_of(input), &text);
                }
            }
            None
        }
        _ => None,
    }
}
