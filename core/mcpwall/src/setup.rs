//! `mcpwall init` and `mcpwall restore`.
//!
//! Onboarding is where this product is won or lost. Three rules follow:
//!
//! 1. **Nothing is written before the diff has been shown.** Silently
//!    rewriting the configuration of someone's working tool is the surest way
//!    to lose their trust on the first try.
//! 2. **Every write is reversible with one command.** Each file touched is
//!    backed up as `.bak.<timestamp>`, and `restore` puts them back.
//! 3. **Configurations point at a stable symlink**, never at the bundle path:
//!    otherwise moving the app would break every one of the user's MCP
//!    servers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use crate::journal::home_dir;

/// Stable location of the binary, which every config points at.
pub fn shim_link() -> PathBuf {
    home_dir().join(".mcpwall").join("bin").join("mcpwall")
}

/// Creates or refreshes the symlink to the current binary.
///
/// Called on the app's first launch and by `init`. The link is remade every
/// time: that is what lets the app be moved without breaking anything.
pub fn ensure_shim_link(target: &Path) -> Result<PathBuf> {
    let link = shim_link();
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(&link);

    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &link)
        .with_context(|| format!("linking {} -> {}", link.display(), target.display()))?;

    Ok(link)
}

/// A client configuration file we know how to handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `~/.claude.json` — global and per-project servers.
    ClaudeGlobal,
    /// A project's `.mcp.json`.
    ProjectMcp,
    /// `~/.cursor/mcp.json`.
    Cursor,
    /// `~/.claude/settings.json` — where the hooks of §7 are declared.
    ///
    /// Not an MCP configuration at all: no server is wrapped here. It is the
    /// only way to reach Claude Code's built-in tools, which never go near an
    /// MCP server and are most of the attack surface.
    ClaudeHooks,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ClaudeGlobal => "Claude Code (global)",
            Self::ProjectMcp => "project",
            Self::Cursor => "Cursor",
            Self::ClaudeHooks => "Claude Code hooks",
        }
    }
}

#[derive(Debug)]
pub struct Target {
    pub path: PathBuf,
    pub kind: Kind,
    /// Project the servers in this file belong to.
    ///
    /// Filled in for a `.mcp.json` — the file lives inside the project, so we
    /// know which one it is. **Empty for global files**: a server declared in
    /// `~/.claude.json` is used from any project, and pinning a `--project` on
    /// it would be lying about the provenance.
    pub project: Option<PathBuf>,
}

/// Discovers the existing configurations.
pub fn discover(extra_projects: &[PathBuf]) -> Vec<Target> {
    let mut out = Vec::new();
    let home = home_dir();

    let claude = home.join(".claude.json");
    if claude.exists() {
        out.push(Target {
            path: claude,
            kind: Kind::ClaudeGlobal,
            project: None,
        });
    }

    let cursor = home.join(".cursor").join("mcp.json");
    if cursor.exists() {
        out.push(Target {
            path: cursor,
            kind: Kind::Cursor,
            project: None,
        });
    }

    let mut projects: Vec<PathBuf> = extra_projects.to_vec();
    if let Ok(cwd) = std::env::current_dir() {
        projects.push(cwd);
    }
    for p in projects {
        let f = p.join(".mcp.json");
        if f.exists() && !out.iter().any(|t| t.path == f) {
            out.push(Target {
                path: f,
                kind: Kind::ProjectMcp,
                project: Some(crate::scope::canonicalize_for_scope(&p)),
            });
        }
    }
    out
}

/// What `init` would do to a file.
#[derive(Debug)]
pub struct Plan {
    pub path: PathBuf,
    pub kind: Kind,
    pub before: String,
    pub after: String,
    pub wrapped: Vec<String>,
    pub already: Vec<String>,
    pub uncovered: Vec<Uncovered>,
}

/// A server left unprotected, and why. Carried all the way to the output so
/// that a coverage hole is something the user reads, not something they have to
/// deduce from an absence.
#[derive(Debug)]
pub struct Uncovered {
    pub name: String,
    pub reason: &'static str,
}

impl Plan {
    pub fn is_noop(&self) -> bool {
        self.wrapped.is_empty()
    }
}

/// Computes the rewrite, without writing anything.
pub fn plan(target: &Target, shim: &Path) -> Result<Plan> {
    let before = std::fs::read_to_string(&target.path)
        .with_context(|| format!("reading {}", target.path.display()))?;
    let mut doc: Value = serde_json::from_str(&before)
        .with_context(|| format!("{} is not valid JSON", target.path.display()))?;

    let mut wrapped = Vec::new();
    let mut already = Vec::new();
    let mut uncovered = Vec::new();

    // `~/.claude.json` carries servers at the root *and* per project. The two
    // locations are handled one after the other rather than collected: two
    // simultaneous mutable borrows on the same document would exist only for
    // the convenience of a single loop.
    //
    // The distinction matters for the scope: under `projects.<dir>` we know
    // which project it is and can inject `--project` (rank 1). At the root we
    // do not — that server is used from anywhere — and inventing a project for
    // it would be lying about the provenance.
    if let Some(projects) = doc.get_mut("projects").and_then(Value::as_object_mut) {
        for (dir, entry) in projects.iter_mut() {
            let project = PathBuf::from(dir);
            let Some(map) = entry.get_mut("mcpServers").and_then(Value::as_object_mut) else {
                continue;
            };
            for (name, cfg) in map.iter_mut() {
                match wrap_entry(cfg, shim, Some(&project)) {
                    WrapResult::Wrapped => wrapped.push(name.clone()),
                    WrapResult::Already => already.push(name.clone()),
                    WrapResult::Uncovered(reason) => uncovered.push(Uncovered {
                        name: name.clone(),
                        reason,
                    }),
                    WrapResult::Skipped => {}
                }
            }
        }
    }

    if let Some(map) = doc.get_mut("mcpServers").and_then(Value::as_object_mut) {
        for (name, cfg) in map.iter_mut() {
            match wrap_entry(cfg, shim, target.project.as_deref()) {
                WrapResult::Wrapped => wrapped.push(name.clone()),
                WrapResult::Already => already.push(name.clone()),
                WrapResult::Uncovered(reason) => uncovered.push(Uncovered {
                    name: name.clone(),
                    reason,
                }),
                WrapResult::Skipped => {}
            }
        }
    }

    let after = serde_json::to_string_pretty(&doc)? + "\n";

    Ok(Plan {
        path: target.path.clone(),
        kind: target.kind,
        before,
        after,
        wrapped,
        already,
        uncovered,
    })
}

// ---------------------------------------------------------------------------
// The Claude Code hook
// ---------------------------------------------------------------------------

/// Where Claude Code reads its settings.
pub fn claude_settings_path() -> PathBuf {
    home_dir().join(".claude").join("settings.json")
}

/// Tools whose result is local data, as a Claude Code matcher.
///
/// `PostToolUse` fires after *every* tool call, and each firing costs a process
/// start. Only these produce anything the taint store can use, so the filtering
/// happens in the matcher rather than after the spawn. It is the same list as
/// `hook::classify`, expressed in the syntax the client understands — and if
/// the two ever disagree the cost is a missed detection, never a wrong verdict.
const LOCAL_READ_MATCHER: &str = "Read|Bash|BashOutput|Grep|Glob|NotebookRead";

/// Plans the installation of the hook into `~/.claude/settings.json`.
///
/// The file is created if it does not exist, with `{}` recorded as its previous
/// content so that `restore` has something to put back — otherwise installing
/// the hook would be the one action `mcpwall restore` could not undo.
///
/// Existing hooks are **appended to, never replaced**. Whatever else the user
/// has wired into `PreToolUse` is none of our business, and a firewall that
/// silently removes someone's tooling on install does not get a second chance.
/// The settings file is a parameter rather than read from `$HOME` inside, so
/// the tests can exercise this against a temporary directory. Mutating the
/// environment instead would make them race each other.
pub fn plan_hook(settings: &Path, shim: &Path) -> Result<Plan> {
    let path = settings.to_path_buf();
    let before = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => s,
        // Missing, or present but empty. Both mean "no settings yet".
        _ => "{}\n".to_owned(),
    };

    let mut doc: Value = serde_json::from_str(&before)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    if !doc.is_object() {
        anyhow::bail!("{} is not a JSON object", path.display());
    }

    let command = format!("{} hook", shim.to_string_lossy());
    let mut installed = Vec::new();
    let mut already = Vec::new();

    let hooks = doc
        .as_object_mut()
        .expect("checked above")
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    if !hooks.is_object() {
        anyhow::bail!("`hooks` in {} is not an object", path.display());
    }

    for (event, matcher) in [
        // Every tool: any rule in the policy may apply to any of them.
        ("PreToolUse", "*"),
        // Only what can feed the taint store.
        ("PostToolUse", LOCAL_READ_MATCHER),
    ] {
        let groups = hooks
            .as_object_mut()
            .expect("checked above")
            .entry(event)
            .or_insert_with(|| Value::Array(Vec::new()));
        let Some(arr) = groups.as_array_mut() else {
            anyhow::bail!("`hooks.{event}` in {} is not an array", path.display());
        };

        if arr.iter().any(|g| mentions_command(g, &command)) {
            already.push(event.to_owned());
            continue;
        }

        arr.push(serde_json::json!({
            "matcher": matcher,
            "hooks": [ { "type": "command", "command": command } ]
        }));
        installed.push(event.to_owned());
    }

    let after = serde_json::to_string_pretty(&doc)? + "\n";

    Ok(Plan {
        path,
        kind: Kind::ClaudeHooks,
        before,
        after,
        wrapped: installed,
        already,
        uncovered: Vec::new(),
    })
}

/// Is our hook already wired into this matcher group?
///
/// Matched on the command string rather than on the shape of the group: the
/// user may have moved it under a different matcher, and installing a second
/// copy would run the hook twice per call.
fn mentions_command(group: &Value, command: &str) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hs| {
            hs.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c == command)
            })
        })
}

enum WrapResult {
    Wrapped,
    Already,
    /// A real server that mcpwall cannot protect yet. Reported, never silently
    /// dropped: a user who believes a server is behind the firewall when it is
    /// not is worse off than a user with no firewall at all.
    Uncovered(&'static str),
    /// Not a server entry we recognise at all.
    Skipped,
}

/// Wraps a server entry, preserving `env`, `args` and everything else
/// verbatim.
fn wrap_entry(cfg: &mut Value, shim: &Path, project: Option<&Path>) -> WrapResult {
    let Some(obj) = cfg.as_object_mut() else {
        return WrapResult::Skipped;
    };

    // HTTP/SSE servers have no command to wrap: the HTTP transport lands in
    // M3. Until then they are declared uncovered, by the presence of a `url`
    // — the one field both HTTP transports share.
    let Some(command) = obj
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        if obj.contains_key("url") {
            return WrapResult::Uncovered("HTTP/SSE transport, not intercepted yet");
        }
        return WrapResult::Skipped;
    };

    let shim_str = shim.to_string_lossy().into_owned();
    if command == shim_str {
        return WrapResult::Already;
    }

    let old_args: Vec<Value> = obj
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut new_args: Vec<Value> = vec![Value::String("wrap".into())];
    if let Some(p) = project {
        new_args.push(Value::String("--project".into()));
        new_args.push(Value::String(p.to_string_lossy().into_owned()));
    }
    new_args.push(Value::String("--".into()));
    new_args.push(Value::String(command.clone()));
    new_args.extend(old_args.iter().cloned());

    // A record of the original command: `restore` relies on the backups, but a
    // human reading the file must be able to understand what was done without
    // going to look for them.
    obj.insert(
        "x-mcpwall-original".into(),
        Value::Object(Map::from_iter([
            ("command".into(), Value::String(command)),
            ("args".into(), Value::Array(old_args)),
        ])),
    );
    obj.insert("command".into(), Value::String(shim_str));
    obj.insert("args".into(), Value::Array(new_args));

    WrapResult::Wrapped
}

/// Backs up, then writes.
///
/// The backup is written from `plan.before` rather than copied from the file.
/// For a file that already exists the two are the same thing — `before` is what
/// was read from it. For one we are creating, `~/.claude/settings.json` on a
/// machine that has none, copying would fail and there would be nothing for
/// `restore` to put back: installing the hook would be the single action
/// `mcpwall restore` could not undo.
pub fn apply(plan: &Plan) -> Result<PathBuf> {
    if let Some(dir) = plan.path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let backup = backup_path(&plan.path);
    std::fs::write(&backup, &plan.before)
        .with_context(|| format!("backing up to {}", backup.display()))?;
    std::fs::write(&plan.path, &plan.after)
        .with_context(|| format!("writing {}", plan.path.display()))?;
    Ok(backup)
}

fn backup_path(path: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut p = path.as_os_str().to_owned();
    p.push(format!(".bak.{stamp}"));
    PathBuf::from(p)
}

/// Available backups, most recent first for each file.
pub fn backups() -> BTreeMap<PathBuf, Vec<PathBuf>> {
    let mut out: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    let home = home_dir();

    // `~/.claude` holds the hook settings. Leaving it out would mean `restore`
    // silently declined to undo the one change `init` makes outside an MCP
    // configuration.
    let mut dirs = vec![home.clone(), home.join(".cursor"), home.join(".claude")];
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if let Some(idx) = name.find(".bak.") {
                let original = dir.join(&name[..idx]);
                out.entry(original).or_default().push(path);
            }
        }
    }

    for v in out.values_mut() {
        v.sort();
        v.reverse(); // most recent first
    }
    out
}

/// Restores each file from its most recent backup.
pub fn restore() -> Result<Vec<PathBuf>> {
    let mut restored = Vec::new();
    for (original, saves) in backups() {
        let Some(latest) = saves.first() else {
            continue;
        };
        std::fs::copy(latest, &original)
            .with_context(|| format!("restoring {}", original.display()))?;
        restored.push(original);
    }
    Ok(restored)
}

/// Minimal unified diff, enough to be read before accepting.
pub fn diff(before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();

    let mut out = String::new();
    let mut i = 0;
    let mut j = 0;

    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            i += 1;
            j += 1;
            continue;
        }
        // Look for the next resynchronisation. Bounded window: we display a
        // readable diff, we are not implementing Myers.
        let mut resync = None;
        'outer: for da in 0..40usize {
            for db in 0..40usize {
                if i + da < a.len() && j + db < b.len() && a[i + da] == b[j + db] {
                    resync = Some((da, db));
                    break 'outer;
                }
            }
        }
        let (da, db) = resync.unwrap_or((a.len() - i, b.len() - j));
        for line in a.iter().skip(i).take(da) {
            out.push_str("- ");
            out.push_str(line);
            out.push('\n');
        }
        for line in b.iter().skip(j).take(db) {
            out.push_str("+ ");
            out.push_str(line);
            out.push('\n');
        }
        i += da;
        j += db;
    }
    out
}
