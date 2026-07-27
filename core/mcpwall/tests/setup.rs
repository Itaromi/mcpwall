//! Onboarding tests.
//!
//! This module rewrites the configuration files of tools people rely on to do
//! their work. A mistake here does not cause a bug, it causes an uninstall. The
//! tests therefore cover what is **preserved** as much as what is changed.

use std::path::{Path, PathBuf};

use mcpwall::setup::{Kind, Plan, Target, diff, plan};
use serde_json::{Value, json};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mcpwall-setup-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("directory");
    d
}

fn write_config(dir: &Path, name: &str, v: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_string_pretty(v).expect("json")).expect("write");
    p
}

fn shim() -> PathBuf {
    PathBuf::from("/Users/x/.mcpwall/bin/mcpwall")
}

fn plan_for(path: &Path, kind: Kind, project: Option<PathBuf>) -> Plan {
    plan(
        &Target {
            path: path.to_path_buf(),
            kind,
            project,
        },
        &shim(),
    )
    .expect("plan")
}

fn parsed(plan: &Plan) -> Value {
    serde_json::from_str(&plan.after).expect("the result must stay valid JSON")
}

// --- What must be preserved ---

#[test]
fn env_and_args_are_kept_verbatim() {
    // Losing an environment variable silently breaks a server, and the user
    // will blame mcpwall — rightly.
    let dir = tmpdir("preserve");
    let cfg = json!({
        "mcpServers": {
            "postgres": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db"],
                "env": { "PGPASSWORD": "secret", "NODE_ENV": "production" },
                "disabled": false
            }
        }
    });
    let path = write_config(&dir, ".mcp.json", &cfg);

    let p = plan_for(
        &path,
        Kind::ProjectMcp,
        Some(PathBuf::from("/Users/x/project")),
    );
    let after = parsed(&p);
    let entry = &after["mcpServers"]["postgres"];

    assert_eq!(entry["env"]["PGPASSWORD"], "secret", "env lost");
    assert_eq!(entry["env"]["NODE_ENV"], "production");
    assert_eq!(entry["disabled"], false, "unknown field lost");

    // The original command and its arguments appear after `--`.
    let args: Vec<&str> = entry["args"]
        .as_array()
        .expect("args")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let sep = args.iter().position(|a| *a == "--").expect("-- separator");
    assert_eq!(args[sep + 1], "npx");
    assert_eq!(
        &args[sep + 2..],
        [
            "-y",
            "@modelcontextprotocol/server-postgres",
            "postgresql://localhost/db"
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_command_points_at_the_link_not_at_the_bundle() {
    // If configs pointed at the bundle path, moving the app would break every
    // one of the user's MCP servers.
    let dir = tmpdir("link");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": ["s.js"]}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    assert_eq!(
        parsed(&p)["mcpServers"]["fs"]["command"],
        shim().to_string_lossy().as_ref()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_original_command_stays_readable_in_the_file() {
    // `restore` relies on the backups, but a human opening the file must be
    // able to understand what was done without going to look for them.
    let dir = tmpdir("trace");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": ["s.js", "--flag"]}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    let orig = &parsed(&p)["mcpServers"]["fs"]["x-mcpwall-original"];
    assert_eq!(orig["command"], "node");
    assert_eq!(orig["args"][0], "s.js");
    assert_eq!(orig["args"][1], "--flag");

    let _ = std::fs::remove_dir_all(&dir);
}

// --- Injecting --project ---

#[test]
fn a_project_mcp_json_receives_its_project() {
    // Link 1 of the provenance chain: the file lives inside the project, so
    // `init` knows which project it is.
    let dir = tmpdir("project");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": []}}}),
    );

    let p = plan_for(
        &path,
        Kind::ProjectMcp,
        Some(PathBuf::from("/Users/x/myrepo")),
    );
    let after = parsed(&p);
    let args: Vec<&str> = after["mcpServers"]["fs"]["args"]
        .as_array()
        .expect("args")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    let i = args
        .iter()
        .position(|a| *a == "--project")
        .expect("--project");
    assert_eq!(args[i + 1], "/Users/x/myrepo");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_global_server_receives_no_project() {
    // A server declared at the root of `~/.claude.json` is used from ten
    // different projects. Pinning a `--project` on it would be lying about the
    // provenance, and that provenance decides whether `forever` is offered.
    let dir = tmpdir("global");
    let path = write_config(
        &dir,
        ".claude.json",
        &json!({"mcpServers": {"github": {"command": "npx", "args": ["-y", "srv"]}}}),
    );

    let p = plan_for(&path, Kind::ClaudeGlobal, None);
    let after = parsed(&p);
    let args: Vec<&str> = after["mcpServers"]["github"]["args"]
        .as_array()
        .expect("args")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    assert!(
        !args.contains(&"--project"),
        "a global server must not be assigned a project: {args:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn per_project_servers_in_claude_json_receive_the_right_project() {
    // `~/.claude.json` also carries servers under `projects.<dir>`. There, the
    // project is known.
    let dir = tmpdir("per-project");
    let path = write_config(
        &dir,
        ".claude.json",
        &json!({
            "projects": {
                "/Users/x/repo-a": { "mcpServers": { "a": { "command": "node", "args": [] } } },
                "/Users/x/repo-b": { "mcpServers": { "b": { "command": "node", "args": [] } } }
            }
        }),
    );

    let p = plan_for(&path, Kind::ClaudeGlobal, None);
    let after = parsed(&p);

    for (repo, srv) in [("/Users/x/repo-a", "a"), ("/Users/x/repo-b", "b")] {
        let args: Vec<&str> = after["projects"][repo]["mcpServers"][srv]["args"]
            .as_array()
            .expect("args")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let i = args
            .iter()
            .position(|a| *a == "--project")
            .expect("--project");
        assert_eq!(args[i + 1], repo);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// --- Idempotence and edge cases ---

#[test]
fn applying_twice_does_not_wrap_twice() {
    // Re-running `init` is a reflex. Double wrapping would produce a shim
    // starting a shim, with two journals and twice the latency.
    let dir = tmpdir("idempotent");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": []}}}),
    );

    let first = plan_for(&path, Kind::ProjectMcp, None);
    assert_eq!(first.wrapped, vec!["fs"]);
    std::fs::write(&path, &first.after).expect("write");

    let second = plan_for(&path, Kind::ProjectMcp, None);
    assert!(
        second.wrapped.is_empty(),
        "re-wrapped: {:?}",
        second.wrapped
    );
    assert_eq!(second.already, vec!["fs"]);
    assert!(second.is_noop());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_http_server_is_skipped() {
    // No `command` to wrap: the HTTP transport lands in M3, and we do not
    // pretend to cover it in the meantime.
    let dir = tmpdir("http");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"remote": {"type": "http", "url": "https://example.com/mcp"}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    assert!(p.wrapped.is_empty());
    assert_eq!(
        parsed(&p)["mcpServers"]["remote"]["url"],
        "https://example.com/mcp"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_with_no_server_produces_no_change() {
    let dir = tmpdir("empty");
    let path = write_config(&dir, ".mcp.json", &json!({"somethingElse": 1}));

    let p = plan_for(&path, Kind::ProjectMcp, None);
    assert!(p.is_noop());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_json_is_refused_without_overwriting() {
    let dir = tmpdir("invalid");
    let path = dir.join(".mcp.json");
    std::fs::write(&path, "{ this is not json").expect("write");

    let r = plan(
        &Target {
            path: path.clone(),
            kind: Kind::ProjectMcp,
            project: None,
        },
        &shim(),
    );
    assert!(r.is_err(), "an unreadable file must make the plan fail");

    // The file is untouched.
    let after = std::fs::read_to_string(&path).expect("read");
    assert_eq!(after, "{ this is not json");

    let _ = std::fs::remove_dir_all(&dir);
}

// --- The diff shown before writing ---

#[test]
fn the_diff_shows_what_changes() {
    // Nothing may be written without the user having been able to read what is
    // about to happen to them.
    let dir = tmpdir("diff");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": ["s.js"]}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    let d = diff(&p.before, &p.after);

    assert!(d.contains("- "), "no line removed: {d}");
    assert!(d.contains("+ "), "no line added: {d}");
    assert!(d.contains("mcpwall"), "the diff must show the shim: {d}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_diff_of_an_unchanged_file_is_empty() {
    assert!(diff("a\nb\n", "a\nb\n").is_empty());
}
