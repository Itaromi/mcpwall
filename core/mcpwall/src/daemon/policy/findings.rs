//! What the engine spotted in the arguments, and how it says so.
//!
//! **The value of a secret is never kept** — only its kind and a truncated
//! prefix. This module is the one place that sees credentials in the clear, and
//! everything it hands onward is safe to put in a journal, a prompt or a bug
//! report.

use super::Request;

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
    /// The tool's advertisement changed since it was last seen.
    ///
    /// Named, because "a tool description changed" in a prompt about a call to
    /// `postgres.query` still leaves the user wondering which one.
    Drifted { tool: String },
}

impl Finding {
    pub fn describe(&self) -> String {
        match self {
            Self::Secret { kind, prefix } => format!("{kind} ({prefix}…)"),
            Self::Tainted { origin } => format!("local data read from {origin}"),
            Self::Drifted { tool } => format!("`{tool}` no longer describes itself the same way"),
        }
    }
}

pub(super) fn collect_findings(req: &Request<'_>) -> Vec<Finding> {
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
    if req.drifted
        && let Some(t) = req.tool
    {
        out.push(Finding::Drifted { tool: t.to_owned() });
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
