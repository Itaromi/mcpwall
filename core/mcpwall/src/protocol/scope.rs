//! Resolving which project a session belongs to.
//!
//! Per-project scoping is not a display convenience: it is what stops an
//! "always allow" granted in one repository from applying to another. A wrong
//! scope is a silent permission leak. Hence two principles held throughout this
//! module:
//!
//! 1. **We never guess.** No signal yields [`ScopeSource::Unknown`], not a
//!    plausible value.
//! 2. **Provenance travels with the value.** [`Scope`] always carries its
//!    [`ScopeSource`], because the `forever` scope is only offered for
//!    trustworthy provenances — see [`Scope::allows_forever`].
//!
//! Two layers, deliberately separated: precedence resolution is pure and
//! testable without a filesystem; canonicalisation, which touches the disk,
//! lives in [`canonicalize_for_scope`].

use std::path::{Path, PathBuf};

/// Internal separator for paths inside a scope key.
///
/// `\u{1f}` (unit separator) does not occur in a real path. For the common case
/// — a single root — the key reads exactly as it does in the spec:
/// `project:/Users/marc/myrepo`.
const KEY_SEP: char = '\u{1f}';

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Where the project path came from, in decreasing order of trustworthiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeSource {
    /// 1 — `--project`, written by `mcpwall init` into the wrapped command.
    ///
    /// The strongest signal: at the moment `init` rewrites
    /// `~/myrepo/.mcp.json`, it knows which project this is. Deterministic,
    /// identical across clients, independent of the protocol.
    Injected,
    /// 2 — roots observed passively in a response to `roots/list`.
    ///
    /// Semantically correct, but optional: the shim is not told anything, it
    /// happens to see it go by — and only if an upstream server thinks to ask.
    Roots,
    /// 3 — inherited working directory, canonicalised.
    ///
    /// Its meaning varies by client: correct from Claude Code, unrelated to any
    /// project from Claude Desktop. Usable for grouping and display, not for
    /// granting a permanent permission.
    Cwd,
    /// 4 — no signal at all. An explicit sentinel.
    Unknown,
}

impl ScopeSource {
    /// Precedence rank, 1 being the most trustworthy.
    pub fn rank(self) -> u8 {
        match self {
            Self::Injected => 1,
            Self::Roots => 2,
            Self::Cwd => 3,
            Self::Unknown => 4,
        }
    }

    /// Stable label for the journal and for overrides. Never change it without
    /// a migration: it is persisted.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Injected => "injected",
            Self::Roots => "roots",
            Self::Cwd => "cwd",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ScopeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// A resolved project, with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    source: ScopeSource,
    /// Sorted and deduplicated. A monorepo may legitimately expose several
    /// roots; the scope is the set, not the first one.
    paths: Vec<PathBuf>,
}

impl Scope {
    /// Builds a scope from **already canonicalised** paths.
    ///
    /// Returns [`Scope::unknown`] if the list is empty after normalisation: a
    /// provenance with no path is not a provenance.
    pub fn new(source: ScopeSource, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut paths: Vec<PathBuf> = paths.into_iter().collect();
        paths.sort();
        paths.dedup();

        if paths.is_empty() || source == ScopeSource::Unknown {
            return Self::unknown();
        }
        Self { source, paths }
    }

    pub fn unknown() -> Self {
        Self {
            source: ScopeSource::Unknown,
            paths: Vec::new(),
        }
    }

    pub fn source(&self) -> ScopeSource {
        self.source
    }

    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Scoping key persisted in the journal and in overrides.
    ///
    /// Two scopes with different provenances but the same paths produce the
    /// same key: that is deliberate. A session that starts on `cwd` and is
    /// later confirmed by `roots` must land on the same rules, not create a
    /// parallel set. The provenance is stored alongside, for the `forever`
    /// decision, not inside the key.
    pub fn key(&self) -> String {
        if self.paths.is_empty() {
            return "unknown".to_owned();
        }
        let joined: Vec<String> = self
            .paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        format!("project:{}", joined.join(&KEY_SEP.to_string()))
    }

    /// Human-readable rendering for the UI and `mcpwall log`.
    pub fn display(&self) -> String {
        if self.paths.is_empty() {
            return "unknown project".to_owned();
        }
        let joined: Vec<String> = self
            .paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        joined.join(", ")
    }

    /// Is the `forever` scope offerable for this scope?
    ///
    /// Only for [`Injected`](ScopeSource::Injected) or
    /// [`Roots`](ScopeSource::Roots) provenance. Under `cwd`, the meaning of
    /// the path depends on the client that started the shim; granting a
    /// permanent permission on that basis would let it leak into other
    /// projects. The UI then offers only `once` and `session`.
    pub fn allows_forever(&self) -> bool {
        matches!(self.source, ScopeSource::Injected | ScopeSource::Roots)
    }
}

// ---------------------------------------------------------------------------
// Precedence chain
// ---------------------------------------------------------------------------

/// Accumulates scope signals and yields the best one available.
///
/// The signals do not arrive together: `--project` and the cwd are known at
/// startup, the roots only if an upstream server asks for `roots/list` during
/// the session. The scope can therefore **rise** in trustworthiness along the
/// way. Each journal entry freezes the provenance of the moment; we do not
/// rewrite the past.
#[derive(Debug, Default, Clone)]
pub struct ScopeResolver {
    injected: Option<PathBuf>,
    roots: Vec<PathBuf>,
    cwd: Option<PathBuf>,
}

impl ScopeResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Link 1. Path already canonicalised.
    pub fn set_injected(&mut self, path: PathBuf) {
        self.injected = Some(path);
    }

    /// Link 3. Path already canonicalised.
    pub fn set_cwd(&mut self, path: PathBuf) {
        self.cwd = Some(path);
    }

    /// Link 2. **Replaces** the current set.
    ///
    /// `notifications/roots/list_changed` means the previous list is no longer
    /// valid. Merging would grow the scope indefinitely and make it cover
    /// directories the client no longer exposes.
    pub fn observe_roots(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        self.roots = paths.into_iter().collect();
    }

    /// Yields the best scope available.
    pub fn resolve(&self) -> Scope {
        if let Some(p) = &self.injected {
            return Scope::new(ScopeSource::Injected, [p.clone()]);
        }
        if !self.roots.is_empty() {
            return Scope::new(ScopeSource::Roots, self.roots.clone());
        }
        if let Some(p) = &self.cwd {
            return Scope::new(ScopeSource::Cwd, [p.clone()]);
        }
        Scope::unknown()
    }
}

// ---------------------------------------------------------------------------
// Root URIs
// ---------------------------------------------------------------------------

/// Converts an MCP root's `uri` into a path.
///
/// The spec (revision 2025-11-25, `client/roots`): "This **MUST** be a
/// `file://` URI in the current specification". Any other scheme is ignored
/// rather than forced into resembling a path — a root we do not understand must
/// never become a permission key.
///
/// The returned path is not canonicalised: [`canonicalize_for_scope`] handles
/// that, so this function stays pure.
pub fn parse_root_uri(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://").or_else(|| {
        // The scheme is case-insensitive.
        let (scheme, rest) = uri.split_once("://")?;
        scheme.eq_ignore_ascii_case("file").then_some(rest)
    })?;

    // Strip query and fragment: they mean nothing for a path.
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);

    // `file:///path` (empty authority) or `file://localhost/path`.
    let path = if let Some(p) = rest.strip_prefix('/') {
        // The authority was empty: `rest` starts with the path itself.
        format!("/{p}")
    } else {
        let (authority, p) = rest.split_once('/')?;
        if !authority.eq_ignore_ascii_case("localhost") {
            // A root on a remote host is not a local path.
            return None;
        }
        format!("/{p}")
    };

    let decoded = percent_decode(&path)?;
    let decoded = String::from_utf8(decoded).ok()?;

    if decoded.contains('\0') {
        return None;
    }

    // A trailing slash does not change the directory being named, but it would
    // change the scope key. We normalise, leaving the root `/` alone.
    let trimmed = decoded.trim_end_matches('/');
    let path = if trimmed.is_empty() { "/" } else { trimmed };

    Some(PathBuf::from(path))
}

/// Decodes `%XX` sequences. Returns `None` if one of them is malformed — we
/// would rather ignore a root than manufacture an approximate path from it.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = *bytes.get(i + 1)?;
            let lo = *bytes.get(i + 2)?;
            let hi = (hi as char).to_digit(16)?;
            let lo = (lo as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Disk layer
// ---------------------------------------------------------------------------

/// Canonicalises a path destined to become a scope key.
///
/// Resolves symlinks and `..`. Without it, `/tmp` and `/private/tmp` on macOS
/// give two distinct keys for the same directory, and one session's overrides
/// are not found again by the next.
///
/// On failure — non-existent path, permission denied — we return the original
/// path as-is. Losing canonicalisation degrades the quality of grouping;
/// refusing to start would break the agent's session, which is the wrong side
/// of that trade.
pub fn canonicalize_for_scope(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
