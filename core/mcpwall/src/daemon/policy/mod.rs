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
//!
//! The engine itself is here. [`model`] is the file it reads, [`request`] turns
//! a frame into something judgeable, and [`findings`] is what got spotted on the
//! way.

mod findings;
mod model;
mod request;

pub use findings::Finding;
pub use model::{Action, DEFAULT_POLICY_YAML, Override, PolicyFile, Rule, Severity, Until, When};
pub use request::{Request, request_from_frame};

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};

use findings::collect_findings;

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

        if w.tool_description_drift && !req.drifted {
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
