//! The shape of `policy.yaml`, and the policy shipped on first launch.
//!
//! Deserialisation only — nothing here evaluates anything. `deny_unknown_fields`
//! throughout, so a mistyped condition name is a startup error rather than a
//! rule that silently never fires.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// File model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Allow,
    Ask,
    Deny,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Scope of an override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Until {
    #[default]
    Once,
    Session,
    Forever,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct When {
    /// Glob patterns against paths found in the arguments.
    #[serde(default)]
    pub arg_path_matches: Vec<String>,
    /// Glob patterns against the tool name.
    #[serde(default)]
    pub tool_matches: Vec<String>,
    /// Does an argument path leave the project?
    #[serde(default)]
    pub path_outside_cwd: bool,
    /// Does an argument look like a secret?
    #[serde(default)]
    pub arg_matches_secret: bool,
    /// Does an argument contain tainted local data? **M3.**
    #[serde(default)]
    pub arg_contains_tainted: bool,
    /// Is the tool considered outbound? **M3.**
    #[serde(default)]
    pub tool_is_outbound: bool,
    /// Has the tool's description changed? **M3.**
    #[serde(default)]
    pub tool_description_drift: bool,
    /// MCP methods concerned. Empty = all those in the DECIDE set.
    #[serde(default)]
    pub method_matches: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub when: When,
    pub action: Action,
    #[serde(default)]
    pub severity: Severity,
    /// Explanation shown to the user. Failing that, the `id` serves as the message.
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// Scope key, as produced by [`Scope::key`].
    pub scope: String,
    /// Tool name; a glob pattern is accepted.
    pub tool: String,
    pub action: Action,
    #[serde(default)]
    pub until: Until,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    #[serde(default)]
    pub default: Action,
    /// Block when the daemon is unreachable. **False by default, and that
    /// default is a product decision**: if closing the app breaks every one of
    /// the user's MCP servers, mcpwall is uninstalled within the hour.
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default = "default_ask_timeout")]
    pub ask_timeout_seconds: u64,
    /// Tool names treated as outbound by `tool_is_outbound`.
    ///
    /// Configurable because no fixed list can know the user's servers. The
    /// spec's own list included `*create*`; it is left out here. On a
    /// filesystem server it matches `create_directory` and `create_file`, and
    /// the rule that uses this predicate **denies** — a false positive would
    /// block ordinary work, which §6 forbids more firmly than it forbids a
    /// miss.
    #[serde(default = "default_outbound_tools")]
    pub outbound_tools: Vec<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub overrides: Vec<Override>,
}

fn default_ask_timeout() -> u64 {
    60
}

fn default_outbound_tools() -> Vec<String> {
    [
        "*post*",
        "*send*",
        "*fetch*",
        "*http*",
        "*upload*",
        "*publish*",
        "*mail*",
        "*webhook*",
        "*request*",
        "*curl*",
        // Claude Code's own built-ins, reaching the daemon through the hook of
        // §7. Named exactly rather than covered by a glob: `*search*` would
        // catch every third-party search tool there is, and a rule that fires
        // on ordinary traffic is how a firewall teaches its user to click
        // "allow" without reading.
        "webfetch",
        "websearch",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            default: Action::Allow,
            fail_closed: false,
            ask_timeout_seconds: default_ask_timeout(),
            outbound_tools: default_outbound_tools(),
            rules: Vec::new(),
            overrides: Vec::new(),
        }
    }
}

/// Default policy, written on first launch.
///
/// Deliberately short and entirely `ask`: at rest mcpwall must ask nothing, and
/// only high-confidence rules interrupt.
pub const DEFAULT_POLICY_YAML: &str = r#"# mcpwall policy.
# First matching rule wins, in reading order.

default: allow
fail_closed: false
ask_timeout_seconds: 60

# Tools that send data off the machine. Add your own here: no built-in list can
# know the names your servers use.
outbound_tools:
  - "*post*"
  - "*send*"
  - "*fetch*"
  - "*http*"
  - "*upload*"
  - "*publish*"
  - "*mail*"
  - "*webhook*"
  - "*request*"
  - "*curl*"
  # Claude Code's own built-ins, which reach the daemon through the hook rather
  # than through MCP. Named exactly: "*search*" would catch every third-party
  # search tool there is.
  - "webfetch"
  - "websearch"

rules:
  # Reading a local secret. High confidence: these paths are not read by
  # accident.
  - id: secrets_paths
    when:
      arg_path_matches:
        - "**/.env"
        - "**/.env.*"
        - "~/.ssh/**"
        - "~/.aws/**"
        - "**/id_rsa"
        - "**/id_ed25519"
        - "**/.netrc"
    action: ask
    severity: high
    message: "access to a secrets file"

  # A secret spotted in a call's arguments.
  - id: secret_pattern
    when:
      arg_matches_secret: true
    action: ask
    severity: high
    message: "an argument looks like a secret credential"

  # Write outside the current project.
  - id: outside_project_write
    when:
      tool_matches: ["*write*", "*edit*", "*delete*", "*remove*", "*move*"]
      path_outside_cwd: true
    action: ask
    severity: medium
    message: "write outside the project"

  # Local data read in the last ten minutes, on its way out through a tool that
  # leaves the machine. This is the rule the whole product exists for, and the
  # only one that denies outright rather than asking: there is no legitimate
  # reading of a secret being posted to the network.
  - id: taint_exfil
    when:
      arg_contains_tainted: true
      tool_is_outbound: true
    action: deny
    severity: critical
    message: "tainted local data in an outbound argument"

  # A tool that no longer describes itself the way it did when it was approved.
  # The description is what the model reads to decide when to reach for the
  # tool: rewriting it after approval changes what the tool does while every
  # name and permission stays as it was.
  - id: tool_description_changed
    when:
      tool_description_drift: true
    action: ask
    severity: high
    message: "this tool's description changed since the last session"

overrides: []
"#;
