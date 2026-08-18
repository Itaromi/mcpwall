//! M1 integration tests: real daemon, real shim, real socket.
//!
//! The test that defines the milestone is
//! [`reading_a_dotenv_is_blocked_without_breaking_the_session`]: blocking must
//! look like an ordinary tool failure, not like a crash.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn mcpwall() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcpwall"))
}

/// A fake server.
///
/// Located through the constant Cargo defines for each binary of this package,
/// not by guessing a sibling of the shim: that guess silently produced a path
/// to a binary nothing had built, and every test that starts a real process
/// failed for a reason that had nothing to do with the product.
fn server(name: &str) -> PathBuf {
    PathBuf::from(match name {
        "normal" => env!("CARGO_BIN_EXE_normal"),
        "silent" => env!("CARGO_BIN_EXE_silent"),
        "huge" => env!("CARGO_BIN_EXE_huge"),
        "malformed" => env!("CARGO_BIN_EXE_malformed"),
        "dies_midmessage" => env!("CARGO_BIN_EXE_dies_midmessage"),
        "ignores_sigterm" => env!("CARGO_BIN_EXE_ignores_sigterm"),
        other => panic!("unknown fake server: {other}"),
    })
}

/// A short working directory.
///
/// `sockaddr_un.sun_path` is only 104 bytes on macOS; CI's temporary directory
/// is enough to blow past it.
fn workdir(tag: &str) -> PathBuf {
    let d = PathBuf::from(format!("/tmp/mw-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("working directory");
    d
}

/// A daemon started for the duration of one test, killed on the way out.
struct Daemon {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
}

impl Daemon {
    fn start(tag: &str, policy: &str) -> Self {
        let dir = workdir(tag);
        let socket = dir.join("d.sock");
        let policy_path = dir.join("policy.yaml");
        std::fs::write(&policy_path, policy).expect("policy");

        let child = Command::new(mcpwall())
            .arg("daemon")
            .args(["--socket".as_ref(), socket.as_os_str()])
            .args(["--policy".as_ref(), policy_path.as_os_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("starting the daemon");

        // Wait for the socket to appear rather than sleeping at random.
        let start = Instant::now();
        while !socket.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(socket.exists(), "the daemon did not create its socket");

        Self { child, socket, dir }
    }

    /// Drives a session through the shim and returns its output.
    fn session(&self, input: &str) -> String {
        let mut child = Command::new(mcpwall())
            .args(["--db".as_ref(), self.dir.join("j.db").as_os_str()])
            .arg("wrap")
            .args(["--socket".as_ref(), self.socket.as_os_str()])
            .arg("--")
            .arg(server("normal"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("starting the shim");

        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(input.as_bytes());
        }
        let out = child.wait_with_output().expect("waiting for the shim");
        assert_eq!(out.status.code(), Some(0), "the session must exit cleanly");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"T","version":"1"}}}"#;

const POLICY: &str = r#"
default: allow
fail_closed: false
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env", "**/id_rsa"]
    action: deny
    severity: high
    message: "access to a secrets file"
  - id: secret_pattern
    when:
      arg_matches_secret: true
    action: deny
    message: "an argument looks like a secret credential"
overrides: []
"#;

/// Extracts the responses, indexed by `id`.
fn by_id(out: &str) -> std::collections::BTreeMap<i64, serde_json::Value> {
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| Some((v.get("id")?.as_i64()?, v)))
        .collect()
}

// --- The milestone exit criterion ---

#[test]
fn reading_a_dotenv_is_blocked_without_breaking_the_session() {
    let d = Daemon::start("m1-env", POLICY);

    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/Users/x/project/.env\"}}}}}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/Users/x/project/README.md\"}}}}}}\n"
    );
    let out = d.session(&input);
    let responses = by_id(&out);

    // initialize goes through: blocking it would kill the whole session.
    let init = responses.get(&1).expect("initialize response");
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25");

    // The .env is blocked, in the shape of an ordinary tool failure.
    let denied = responses.get(&2).expect("response to the .env");
    assert_eq!(denied["result"]["isError"], true);
    assert!(denied.get("error").is_none(), "never a protocol error");
    let text = denied["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.starts_with("blocked by mcpwall:"), "{text}");
    assert!(text.contains("secrets_paths"), "{text}");

    // And above all: the session continues, the next call succeeds normally.
    let allowed = responses.get(&3).expect("response to the README");
    assert_eq!(allowed["result"]["content"][0]["text"], "ok");
    assert!(allowed["result"].get("isError").is_none());
}

#[test]
fn a_secret_in_the_arguments_is_blocked_without_being_copied() {
    let d = Daemon::start("m1-secret", POLICY);
    let secret = "AKIAIOSFODNN7EXAMPLE";

    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"http_post\",\"arguments\":{{\"body\":\"{secret}\"}}}}}}\n"
    );
    let out = d.session(&input);
    let denied = by_id(&out).remove(&2).expect("response");

    assert_eq!(denied["result"]["isError"], true);
    let text = denied["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.contains("AKIAIO"), "the prefix must be shown: {text}");
    assert!(
        !text.contains(secret),
        "the secret must never be copied through: {text}"
    );
}

#[test]
fn ordinary_traffic_crosses_the_daemon_untroubled() {
    let d = Daemon::start("m1-ordinary", POLICY);

    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"text\":\"hello\"}}}}}}\n"
    );
    let out = d.session(&input);
    let r = by_id(&out);

    assert_eq!(r.len(), 3, "every response must come back: {out}");
    for id in [1, 2, 3] {
        assert!(
            r[&id]["result"].get("isError").is_none(),
            "id {id} wrongly blocked: {out}"
        );
    }
}

// --- Degraded mode ---

#[test]
fn with_no_daemon_the_shim_relays_anyway() {
    // The availability rule of §4. If closing the app paralysed the MCP
    // servers, mcpwall would be uninstalled within the hour.
    let dir = workdir("m1-no-daemon");
    let absent = dir.join("nonexistent.sock");

    let mut child = Command::new(mcpwall())
        .args(["--db".as_ref(), dir.join("j.db").as_os_str()])
        .arg("wrap")
        .args(["--socket".as_ref(), absent.as_os_str()])
        .arg("--")
        .arg(server("normal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim");

    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(
            format!(
                "{INIT}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/Users/x/.env\"}}}}}}\n"
            )
            .as_bytes(),
        );
    }
    let out = child.wait_with_output().expect("wait");
    let text = String::from_utf8_lossy(&out.stdout);
    let r = by_id(&text);

    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        r.len(),
        2,
        "traffic must go through without a daemon: {text}"
    );
    assert!(
        r[&2]["result"].get("isError").is_none(),
        "with no daemon, nothing may be blocked: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_daemon_dying_mid_session_does_not_break_it() {
    let mut d = Daemon::start("m1-dead", POLICY);

    // A first session confirms that blocking works.
    let blocked = d.session(&format!(
        "{INIT}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/x/.env\"}}}}}}\n"
    ));
    assert_eq!(by_id(&blocked)[&2]["result"]["isError"], true);

    // The daemon vanishes — update, app closed, crash.
    let _ = d.child.kill();
    let _ = d.child.wait();

    let out = d.session(&format!(
        "{INIT}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/x/.env\"}}}}}}\n"
    ));
    let r = by_id(&out);
    assert_eq!(r.len(), 2, "the session must stay usable: {out}");
    assert!(
        r[&2]["result"].get("isError").is_none(),
        "fail-open expected: {out}"
    );
}

// --- Version handshake ---

#[test]
fn a_shim_of_an_incompatible_version_goes_fail_open() {
    // The case of the MCP client left open across an update. We simulate an old
    // shim by talking to the socket directly.
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let d = Daemon::start("m1-version", POLICY);

    let stream = UnixStream::connect(&d.socket).expect("connect");
    let mut write = stream.try_clone().expect("clone");
    let mut lines = BufReader::new(stream).lines();

    // Deliberately wrong version.
    writeln!(write, r#"{{"mcpwall_ipc": 99, "build": "old"}}"#).expect("hello");

    let reply = lines.next().expect("response").expect("line");
    let hello: serde_json::Value = serde_json::from_str(&reply).expect("json");
    assert_eq!(hello["mcpwall_ipc"], 2, "the daemon announces its version");

    // The daemon closes the connection rather than risk a misread verdict: a
    // misunderstood verdict is either a phantom block or a hole in the
    // firewall.
    writeln!(
        write,
        r#"{{"type":"decide","method":"tools/call","frame":"{{}}","scope_key":"x","scope_source":"cwd","scope_paths":[],"server":null,"session_id":0}}"#
    )
    .ok();
    // What must hold is that **no verdict comes back** — not that the read ends
    // in any one particular way. The two differ by platform: having closed its
    // end, the daemon leaves macOS to report a clean EOF, while Linux answers
    // the write to a closed socket with an RST and the next read fails with
    // ECONNRESET. Demanding `None` made this test assert an accident of the
    // host rather than the property it exists for — and it went unnoticed
    // because the whole file was not running.
    match lines.next() {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(line)) => {
            panic!("a verdict was issued after an incompatible handshake: {line}")
        }
    }
}

#[test]
fn a_compatible_handshake_is_accepted() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let d = Daemon::start("m1-handshake", POLICY);

    let stream = UnixStream::connect(&d.socket).expect("connect");
    let mut write = stream.try_clone().expect("clone");
    let mut lines = BufReader::new(stream).lines();

    writeln!(write, r#"{{"mcpwall_ipc": 2, "build": "test"}}"#).expect("hello");
    let _ = lines.next().expect("daemon hello");

    let frame = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/p/.env" } }
    })
    .to_string();
    let req = serde_json::json!({
        "type": "decide",
        "method": "tools/call",
        "frame": frame,
        "scope_key": "project:/p",
        "scope_source": "injected",
        "scope_paths": ["/p"],
        "server": null,
        "session_id": 1,
    });
    writeln!(write, "{req}").expect("request");

    let reply = lines.next().expect("verdict").expect("line");
    let v: serde_json::Value = serde_json::from_str(&reply).expect("json");
    assert_eq!(v["type"], "verdict", "the daemon tags its messages");
    assert_eq!(v["outcome"], "deny");
    assert_eq!(v["rule"], "secrets_paths");
    // Rank 1 provenance: `forever` can be offered.
    assert_eq!(v["forever_allowed"], true);
}

#[test]
fn forever_is_refused_on_weak_provenance() {
    // The scope security guard, seen from the protocol: it is the daemon that
    // computes `forever_allowed`, so the UI need not redo the reasoning — and
    // cannot get it wrong by redoing it.
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let d = Daemon::start("m1-forever", POLICY);

    let stream = UnixStream::connect(&d.socket).expect("connect");
    let mut write = stream.try_clone().expect("clone");
    let mut lines = BufReader::new(stream).lines();
    writeln!(write, r#"{{"mcpwall_ipc": 2, "build": "test"}}"#).expect("hello");
    let _ = lines.next();

    for (source, expected) in [
        ("injected", true),
        ("roots", true),
        ("cwd", false),
        ("unknown", false),
    ] {
        let req = serde_json::json!({
            "type": "decide",
            "method": "tools/call",
            "frame": r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#,
            "scope_key": "project:/p",
            "scope_source": source,
            "scope_paths": ["/p"],
            "server": null,
            "session_id": 1,
        });
        writeln!(write, "{req}").expect("request");
        let reply = lines.next().expect("verdict").expect("line");
        let v: serde_json::Value = serde_json::from_str(&reply).expect("json");
        assert_eq!(v["forever_allowed"], expected, "provenance {source}");
    }
}
