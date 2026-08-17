//! Policy engine.
//!
//! Deterministic and readable: no LLM analysis, no opaque heuristics. A rule
//! that fires must be explainable to the user in one sentence, otherwise they
//! cannot decide.
//!
//! Two design principles, both dictated by alert fatigue:
//!
//! - **First matching rule, in file order.** No scoring, no combining. The
//!   user must be able to predict what will happen by reading their file top to
//!   bottom.
//! - **A false positive costs more than a false negative.** A rule that
//!   interrupts wrongly trains the user to click "allow" without reading, which
//!   negates the entire product.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;

use crate::scope::Scope;

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

  # M3: requires description drift detection.
  - id: tool_description_changed
    when:
      tool_description_drift: true
    action: ask
    severity: high
    message: "this tool's description changed since the last session"

overrides: []
"#;

// ---------------------------------------------------------------------------
// Compiled policy
// ---------------------------------------------------------------------------

/// A rule with its globs compiled.
struct CompiledRule {
    rule: Rule,
    arg_paths: Option<GlobSet>,
    tools: Option<GlobSet>,
    methods: Option<GlobSet>,
}

pub struct Policy {
    file: PolicyFile,
    rules: Vec<CompiledRule>,
    overrides: Vec<(Override, Option<GlobSet>)>,
    /// Tool names considered outbound, compiled once.
    outbound: Option<GlobSet>,
    /// File mtime at load time, for hot reloading.
    loaded_mtime: Option<SystemTime>,
    path: Option<PathBuf>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::compile(PolicyFile::default(), None, None)
    }
}

impl Policy {
    pub fn parse(text: &str) -> Result<PolicyFile> {
        // An empty file would deserialise into "everything by default", that
        // is `default: allow` with no rules at all: the firewall would disable
        // itself silently. This is not merely theoretical — full disk,
        // interrupted editor, partial write. We refuse, and the caller keeps
        // the previous policy.
        if text.trim().is_empty() {
            anyhow::bail!("empty policy — refused, so filtering is not disabled silently");
        }
        serde_norway::from_str(text).context("unreadable policy")
    }

    /// Loads from a file, writing it if it does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, DEFAULT_POLICY_YAML)
                .with_context(|| format!("writing {}", path.display()))?;
        }
        Self::load(path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file = Self::parse(&text)?;
        let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
        Ok(Self::compile(file, Some(path.to_path_buf()), mtime))
    }

    fn compile(file: PolicyFile, path: Option<PathBuf>, mtime: Option<SystemTime>) -> Self {
        let rules = file
            .rules
            .iter()
            .map(|r| CompiledRule {
                rule: r.clone(),
                arg_paths: build_globs(&r.when.arg_path_matches),
                tools: build_globs(&r.when.tool_matches),
                methods: build_globs(&r.when.method_matches),
            })
            .collect();

        let overrides = file
            .overrides
            .iter()
            .map(|o| (o.clone(), build_globs(std::slice::from_ref(&o.tool))))
            .collect();

        let outbound = build_globs(&file.outbound_tools);

        Self {
            file,
            rules,
            overrides,
            outbound,
            loaded_mtime: mtime,
            path,
        }
    }

    /// Reloads if the file has changed.
    ///
    /// Comparing mtimes rather than watching the filesystem: a `stat` costs
    /// less than a watcher, and reloading does not need to be instantaneous.
    pub fn reload_if_changed(&mut self) -> bool {
        let Some(path) = self.path.clone() else {
            return false;
        };
        let mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        if mtime == self.loaded_mtime {
            return false;
        }
        match Self::load(&path) {
            Ok(fresh) => {
                *self = fresh;
                tracing::info!(file = %path.display(), "policy reloaded");
                true
            }
            Err(e) => {
                // We keep the old policy: a half-edited file must neither
                // throw the firewall wide open nor slam it shut.
                tracing::error!(error = %e, "invalid policy, the previous one stays active");
                self.loaded_mtime = mtime;
                false
            }
        }
    }

    pub fn fail_closed(&self) -> bool {
        self.file.fail_closed
    }

    pub fn ask_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.file.ask_timeout_seconds)
    }

    pub fn default_action(&self) -> Action {
        self.file.default
    }

    /// Evaluates a request.
    pub fn evaluate(&self, req: &Request<'_>) -> Decision {
        // Overrides come before rules: they express a decision the user has
        // already made, which we do not ask again.
        for (ov, tools) in &self.overrides {
            if ov.scope != req.scope_key {
                continue;
            }
            let matches = tools
                .as_ref()
                .map(|g| g.is_match(req.tool.unwrap_or("")))
                .unwrap_or(false);
            if matches {
                return Decision {
                    action: ov.action,
                    rule: Some("override".to_owned()),
                    severity: Severity::Info,
                    message: format!("decision recorded for {}", ov.scope),
                    findings: Vec::new(),
                };
            }
        }

        let findings = collect_findings(req);

        for c in &self.rules {
            if let Some(d) = self.try_rule(c, req, &findings) {
                return d;
            }
        }

        Decision {
            action: self.file.default,
            rule: None,
            severity: Severity::Info,
            message: "default policy".to_owned(),
            findings,
        }
    }

    /// Does this tool send data off the machine?
    ///
    /// An unnamed tool is never outbound: `tool_is_outbound` must not fire on a
    /// method that has no tool at all.
    fn is_outbound(&self, tool: Option<&str>) -> bool {
        let (Some(t), Some(g)) = (tool, &self.outbound) else {
            return false;
        };
        g.is_match(t.to_ascii_lowercase())
    }

    fn try_rule(
        &self,
        c: &CompiledRule,
        req: &Request<'_>,
        findings: &[Finding],
    ) -> Option<Decision> {
        let w = &c.rule.when;

        // A rule whose conditions are all empty matches nothing: otherwise a
        // typo in a condition name would block all traffic.
        // `deny_unknown_fields` already catches the typo; this is the second
        // barrier.
        if is_empty_condition(w) {
            return None;
        }

        if let Some(g) = &c.methods
            && !g.is_match(req.method)
        {
            return None;
        }

        if let Some(g) = &c.tools {
            let tool = req.tool?;
            if !g.is_match(tool) {
                return None;
            }
        }

        if let Some(g) = &c.arg_paths {
            let hit = req
                .paths
                .iter()
                .any(|p| g.is_match(p) || g.is_match(expand_tilde_str(p)));
            if !hit {
                return None;
            }
        }

        if w.path_outside_cwd && !req.has_path_outside_scope() {
            return None;
        }

        if w.arg_matches_secret && !findings.iter().any(|f| matches!(f, Finding::Secret { .. })) {
            return None;
        }

        if w.arg_contains_tainted && req.tainted.is_none() {
            return None;
        }

        if w.tool_is_outbound && !self.is_outbound(req.tool) {
            return None;
        }

        // Still M3. Description drift does not exist yet, so a rule carrying
        // it never fires — an inert rule visible in the file beats an absent
        // rule we would forget to write.
        if w.tool_description_drift {
            return None;
        }

        Some(Decision {
            action: c.rule.action,
            rule: Some(c.rule.id.clone()),
            severity: c.rule.severity,
            message: c
                .rule
                .message
                .clone()
                .unwrap_or_else(|| c.rule.id.replace('_', " ")),
            findings: findings.to_vec(),
        })
    }
}

fn is_empty_condition(w: &When) -> bool {
    w.arg_path_matches.is_empty()
        && w.tool_matches.is_empty()
        && w.method_matches.is_empty()
        && !w.path_outside_cwd
        && !w.arg_matches_secret
        && !w.arg_contains_tainted
        && !w.tool_is_outbound
        && !w.tool_description_drift
}

fn build_globs(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        // `~` is expanded so the policy stays readable; both forms are added,
        // since the argument may arrive as either.
        if let Ok(g) = Glob::new(p) {
            b.add(g);
        }
        if let Some(expanded) = expand_tilde(p)
            && let Ok(g) = Glob::new(&expanded)
        {
            b.add(g);
        }
    }
    b.build().ok()
}

fn expand_tilde(p: &str) -> Option<String> {
    let rest = p.strip_prefix("~/")?;
    Some(format!(
        "{}/{rest}",
        crate::journal::home_dir().to_string_lossy()
    ))
}

fn expand_tilde_str(p: &str) -> &str {
    p
}

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
    pub scope_key: &'a str,
    pub scope_paths: &'a [PathBuf],
}

impl Request<'_> {
    /// Does an argument path leave the project?
    ///
    /// An unknown scope never returns true: without knowing where the project
    /// is, we cannot say we are leaving it, and pretending otherwise would fire
    /// the rule on all of Claude Desktop's traffic.
    fn has_path_outside_scope(&self) -> bool {
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
            if let Some(p) = crate::scope::parse_root_uri(uri) {
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

/// What the engine spotted in the arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A probable secret. **We never store the value** — only its kind and a
    /// truncated prefix, per the project conventions.
    Secret { kind: &'static str, prefix: String },
    /// Local data recognised in the arguments, and where it was read from.
    ///
    /// The origin is what makes a taint refusal actionable. "tainted local data
    /// in an outbound argument" tells the user nothing they can check; naming
    /// the `.env` the payload came from tells them whether they are looking at
    /// an injection or at their own deliberate call. Spec §9 requires the
    /// decision panel to show it.
    ///
    /// The origin is a path or a tool name — never the data itself, which the
    /// taint store does not keep and could not give back.
    Tainted { origin: String },
}

impl Finding {
    pub fn describe(&self) -> String {
        match self {
            Self::Secret { kind, prefix } => format!("{kind} ({prefix}…)"),
            Self::Tainted { origin } => format!("local data read from {origin}"),
        }
    }
}

fn collect_findings(req: &Request<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for v in &req.values {
        if let Some(f) = detect_secret(v)
            && !out.contains(&f)
        {
            out.push(f);
        }
    }
    // The daemon has already done the matching; all that was missing was
    // carrying the answer as far as the person who has to decide.
    if let Some(origin) = &req.tainted {
        out.push(Finding::Tainted {
            origin: origin.clone(),
        });
    }
    out
}

/// Secret detectors, deliberately few and high-confidence.
///
/// Every pattern added here is a potential source of false positives, and a
/// noisy false positive costs more than a false negative: it teaches the user
/// to click "allow" without reading.
fn detect_secret(s: &str) -> Option<Finding> {
    let kind = if s.contains("-----BEGIN") && s.contains("PRIVATE KEY") {
        "private key"
    } else if starts_with_aws_key(s) {
        "AWS access key"
    } else if (s.starts_with("ghp_") && s.len() >= 36)
        || (s.starts_with("github_pat_") && s.len() >= 40)
    {
        // Two prefixes, one kind: the minimum lengths differ because the
        // formats differ, not the nature of the secret.
        "GitHub token"
    } else if s.starts_with("sk-") && s.len() >= 20 {
        "API key"
    } else if s.starts_with("xoxb-") || s.starts_with("xoxp-") {
        "Slack token"
    } else {
        return None;
    };

    Some(Finding::Secret {
        kind,
        prefix: prefix(s),
    })
}

fn starts_with_aws_key(s: &str) -> bool {
    // AKIA followed by 16 uppercase alphanumeric characters.
    let Some(rest) = s.strip_prefix("AKIA") else {
        return false;
    };
    rest.len() >= 16
        && rest[..16]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Truncated prefix, safe to write to the journal.
fn prefix(s: &str) -> String {
    s.chars().take(6).collect()
}

/// Appends a permanent override to the policy file.
///
/// Written by appending text rather than by rewriting the document: a
/// `policy.yaml` is a file the user edits by hand, with their comments and
/// their rule ordering. Re-reading, serialising and rewriting it would lose
/// both — and the first time mcpwall destroys someone's comments, it loses
/// their trust.
pub fn append_override(path: &Path, scope_key: &str, tool: &str, allow: bool) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    // We validate before writing: better to refuse to record a decision than
    // to produce a file the daemon can no longer read back.
    Policy::parse(&text).context("existing policy unreadable, override not added")?;

    let action = if allow { "allow" } else { "deny" };
    let entry = format!(
        "  - scope: \"{}\"\n    tool: \"{}\"\n    action: {action}\n    until: forever\n",
        scope_key.replace('"', "\\\""),
        tool.replace('"', "\\\"")
    );

    let mut updated = if text.contains("\noverrides:") || text.starts_with("overrides:") {
        // `overrides: []` must become an open list before we append to it.
        text.replace("overrides: []", "overrides:")
    } else {
        format!("{}\noverrides:\n", text.trim_end())
    };

    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&entry);

    // Read-back check: we do not write a file we have just broken.
    Policy::parse(&updated).context("the append would have produced an invalid policy")?;

    std::fs::write(path, updated).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub rule: Option<String>,
    pub severity: Severity,
    pub message: String,
    pub findings: Vec<Finding>,
}

impl Decision {
    /// Message intended for the agent, as it will appear in `isError`.
    pub fn agent_message(&self) -> String {
        if self.findings.is_empty() {
            return self.message.clone();
        }
        let details: Vec<String> = self.findings.iter().map(Finding::describe).collect();
        format!("{} [{}]", self.message, details.join(", "))
    }
}
