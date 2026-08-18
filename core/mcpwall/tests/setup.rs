//! Onboarding tests.
//!
//! This module rewrites the configuration files of tools people rely on to do
//! their work. A mistake here does not cause a bug, it causes an uninstall. The
//! tests therefore cover what is **preserved** as much as what is changed.

use std::path::{Path, PathBuf};

use mcpwall::setup::{Kind, Plan, Target, apply, diff, plan, plan_hook};
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

/// The proxy address the HTTP routing tests write into URLs.
const LISTEN: &str = "127.0.0.1:8787";

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
        LISTEN,
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
fn an_http_server_is_pointed_at_the_local_proxy() {
    // No `command` to wrap. An HTTP client connects to a URL, so the only way
    // to interpose is to be the URL — the entry is re-pointed at the local
    // proxy, and the real upstream becomes a route.
    let dir = tmpdir("http");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"remote": {"type": "http", "url": "https://example.com/mcp"}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    assert_eq!(p.wrapped, vec!["remote"]);
    assert_eq!(
        parsed(&p)["mcpServers"]["remote"]["url"],
        format!("http://{LISTEN}/remote")
    );
    assert_eq!(
        p.routes,
        vec![("remote".to_owned(), "https://example.com/mcp".to_owned())]
    );
    assert!(
        p.uncovered.is_empty(),
        "it is covered now: {:?}",
        p.uncovered
    );

    // As for a wrapped command: `restore` works from the backups, but a person
    // opening the file must be able to see what was done without them.
    assert_eq!(
        parsed(&p)["mcpServers"]["remote"]["x-mcpwall-original"]["url"],
        "https://example.com/mcp"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_legacy_sse_transport_is_routed_too() {
    // The deprecated transport is still widely deployed. It is recognised by
    // its `url`, the one field both HTTP transports share, so a server declared
    // without an explicit `type` is not missed.
    let dir = tmpdir("sse");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {
            "legacy": {"type": "sse", "url": "https://example.com/sse"},
            "typeless": {"url": "https://example.com/mcp"},
        }}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    let mut names: Vec<_> = p.routes.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, vec!["legacy", "typeless"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn routing_twice_does_not_route_the_proxy_at_itself() {
    // Re-running `init` is a reflex. A second pass must not point the proxy at
    // its own address, which would lose the real upstream entirely.
    let dir = tmpdir("http-twice");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"remote": {"type": "http", "url": "https://example.com/mcp"}}}),
    );

    let first = plan_for(&path, Kind::ProjectMcp, None);
    std::fs::write(&path, &first.after).expect("write");

    let second = plan_for(&path, Kind::ProjectMcp, None);
    assert!(second.is_noop(), "{}", second.after);
    assert!(second.routes.is_empty(), "{:?}", second.routes);
    assert_eq!(
        parsed(&second)["mcpServers"]["remote"]["url"],
        format!("http://{LISTEN}/remote")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stdio_and_an_http_server_are_both_covered() {
    let dir = tmpdir("mixed");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {
            "local": {"command": "node", "args": ["s.js"]},
            "remote": {"type": "http", "url": "https://example.com/mcp"},
        }}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    let mut names = p.wrapped.clone();
    names.sort();
    assert_eq!(names, vec!["local", "remote"]);
    assert!(
        p.uncovered.is_empty(),
        "nothing is left unprotected here: {:?}",
        p.uncovered
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
        LISTEN,
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

// --- The Claude Code hook ---
//
// The hook is what covers the built-in tools of §7, and it is installed into a
// file mcpwall does not own: whatever else the user has wired into their
// settings has to survive it untouched.

#[test]
fn the_hook_is_installed_on_both_events() {
    let dir = tmpdir("hook-fresh");
    let settings = dir.join("settings.json");

    let p = plan_hook(&settings, &shim()).expect("plan");
    assert_eq!(p.wrapped, vec!["PreToolUse", "PostToolUse"]);

    let after: Value = serde_json::from_str(&p.after).expect("valid JSON");
    let command = format!("{} hook", shim().display());

    for event in ["PreToolUse", "PostToolUse"] {
        let group = &after["hooks"][event][0];
        assert_eq!(group["hooks"][0]["type"], "command", "{event}");
        assert_eq!(group["hooks"][0]["command"], command, "{event}");
    }

    // Every tool may be subject to a rule; only some produce local data. The
    // second matcher is what keeps a process from being started after each and
    // every tool call.
    assert_eq!(after["hooks"]["PreToolUse"][0]["matcher"], "*");
    let post = after["hooks"]["PostToolUse"][0]["matcher"]
        .as_str()
        .unwrap_or_default();
    assert!(post.contains("Bash"), "{post}");
    assert!(post.contains("Read"), "{post}");
    assert!(
        !post.contains('*'),
        "the PostToolUse matcher must be a list: {post}"
    );
}

#[test]
fn existing_settings_and_existing_hooks_are_kept() {
    // The failure this guards against is not a bug, it is an uninstall: a
    // firewall that deletes somebody's tooling on install does not get a
    // second chance.
    let dir = tmpdir("hook-existing");
    let settings = write_config(
        &dir,
        "settings.json",
        &json!({
            "model": "opus",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "/usr/local/bin/audit" }] }
                ],
                "Stop": [
                    { "hooks": [{ "type": "command", "command": "/usr/local/bin/notify" }] }
                ]
            }
        }),
    );

    let p = plan_hook(&settings, &shim()).expect("plan");
    let after: Value = serde_json::from_str(&p.after).expect("valid JSON");

    assert_eq!(after["model"], "opus", "unrelated settings must survive");
    assert_eq!(
        after["hooks"]["Stop"][0]["hooks"][0]["command"], "/usr/local/bin/notify",
        "an unrelated event must survive"
    );
    assert_eq!(
        after["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "/usr/local/bin/audit",
        "the user's own PreToolUse hook must survive, and stay first"
    );
    assert_eq!(
        after["hooks"]["PreToolUse"].as_array().map(Vec::len),
        Some(2),
        "ours is appended, not substituted"
    );
}

#[test]
fn installing_twice_does_not_install_twice() {
    // Two copies would run the hook twice per call — and so prompt the user
    // twice for one decision.
    let dir = tmpdir("hook-twice");
    let settings = dir.join("settings.json");

    let first = plan_hook(&settings, &shim()).expect("plan");
    std::fs::write(&settings, &first.after).expect("write");

    let second = plan_hook(&settings, &shim()).expect("replan");
    assert!(second.is_noop(), "{}", second.after);
    assert_eq!(second.already, vec!["PreToolUse", "PostToolUse"]);
}

#[test]
fn a_hook_moved_under_another_matcher_is_still_recognised() {
    // Detection is on the command, not on the shape of the group: a user who
    // narrowed our matcher by hand must not get a second copy on the next
    // `init`.
    let dir = tmpdir("hook-moved");
    let command = format!("{} hook", shim().display());
    let settings = write_config(
        &dir,
        "settings.json",
        &json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash|Read", "hooks": [{ "type": "command", "command": command }] }
                ]
            }
        }),
    );

    let p = plan_hook(&settings, &shim()).expect("plan");
    assert_eq!(
        p.already,
        vec!["PreToolUse"],
        "the user's narrowed matcher must be left as they set it"
    );
    assert_eq!(p.wrapped, vec!["PostToolUse"]);
}

#[test]
fn creating_the_settings_file_is_still_undoable() {
    // `apply` writes the backup from the recorded previous content rather than
    // copying the file, so that installing the hook on a machine with no
    // settings at all is not the one change `mcpwall restore` cannot undo.
    let dir = tmpdir("hook-restore");
    let settings = dir.join("settings.json");
    assert!(!settings.exists());

    let p = plan_hook(&settings, &shim()).expect("plan");
    let backup = apply(&p).expect("apply");

    assert!(settings.exists(), "the file must have been created");
    let restored: Value =
        serde_json::from_str(&std::fs::read_to_string(&backup).expect("backup")).expect("json");
    assert_eq!(
        restored,
        json!({}),
        "the backup must describe a machine with no settings"
    );
}

#[test]
fn settings_that_are_not_an_object_are_refused_without_overwriting() {
    let dir = tmpdir("hook-bad");
    let settings = dir.join("settings.json");
    std::fs::write(&settings, "[1, 2, 3]").expect("write");

    assert!(plan_hook(&settings, &shim()).is_err());
    assert_eq!(
        std::fs::read_to_string(&settings).expect("read"),
        "[1, 2, 3]",
        "a refusal must leave the file exactly as it was"
    );
}

#[test]
fn a_url_we_cannot_proxy_is_named_rather_than_dropped() {
    // Being silent would be the worst of the three outcomes: the user reads a
    // list of protected servers, does not find this one, and concludes it is
    // not there.
    let dir = tmpdir("http-odd");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"ws": {"url": "ws://example.com/mcp"}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    assert!(p.wrapped.is_empty());
    assert!(p.routes.is_empty());
    assert_eq!(
        p.uncovered
            .iter()
            .map(|u| u.name.as_str())
            .collect::<Vec<_>>(),
        vec!["ws"]
    );
    assert_eq!(
        parsed(&p)["mcpServers"]["ws"]["url"],
        "ws://example.com/mcp",
        "and it must be left exactly as it was"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
