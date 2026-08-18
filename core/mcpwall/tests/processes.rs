//! Process lifecycle, against real binaries that misbehave on purpose.
//!
//! The defects this module targets — orphans, deadlocks, badly closed
//! descriptors, lost exit codes — are precisely the ones no mocked test will
//! ever see. Here we start real binaries and make them misbehave.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The shim binary.
fn mcpwall() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcpwall"))
}

/// A fake server.
///
/// Located through the constant Cargo defines for each binary of this package,
/// not by guessing a sibling of the shim: that guess silently produced a path
/// to a binary nothing had built, and every test in this file failed for a
/// reason that had nothing to do with the product.
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

fn db_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mcpwall-test-{tag}-{}-{}.db",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

/// Drives a complete session and returns (output, exit code).
fn session(server_name: &str, input: &str, tag: &str) -> (String, i32) {
    let db = db_path(tag);
    let mut child = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .arg("--")
        .arg(server(server_name))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("starting the shim");

    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(input.as_bytes());
        // Closing stdin is the normal shutdown signal of a stdio MCP session.
    }

    let out = child.wait_with_output().expect("waiting for the shim");
    let _ = std::fs::remove_file(&db);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"T","version":"1"}}}"#;

// --- Nominal session ---

#[test]
fn a_complete_session_against_a_normal_server() {
    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\"}}}}\n"
    );
    let (out, code) = session("normal", &input, "normal");

    assert_eq!(code, 0, "the upstream exit code must be propagated");
    assert!(out.contains("\"protocolVersion\":\"2025-11-25\""), "{out}");
    assert!(out.contains("\"name\":\"normal\""), "{out}");
    assert_eq!(out.lines().count(), 3, "one response per request: {out}");
}

// --- Upstream failure modes ---

#[test]
fn a_silent_upstream_does_not_hang_the_shim() {
    let start = Instant::now();
    let (out, code) = session("silent", &format!("{INIT}\n"), "silent");

    assert!(
        start.elapsed() < Duration::from_secs(10),
        "the shim hung for {:?}",
        start.elapsed()
    );
    assert!(out.is_empty(), "nothing may be invented: {out}");
    assert_eq!(code, 0);
}

#[test]
fn an_upstream_dying_mid_message_makes_the_shim_exit() {
    let start = Instant::now();
    let (out, code) = session("dies_midmessage", &format!("{INIT}\n"), "dies");

    assert!(
        start.elapsed() < Duration::from_secs(10),
        "the shim waited for a frame that would never come"
    );
    assert_eq!(code, 3, "the upstream exit code must be propagated");
    // The partial frame is relayed, with its delimiter appended: losing the last
    // message would be worse than forwarding it incomplete.
    assert!(out.contains("resu"), "partial frame expected: {out:?}");
    assert!(out.ends_with('\n'), "delimiter missing: {out:?}");
}

#[test]
fn an_eight_megabyte_response_does_not_deadlock() {
    let start = Instant::now();
    let (out, code) = session("huge", &format!("{INIT}\n"), "huge");

    assert!(
        start.elapsed() < Duration::from_secs(30),
        "probable deadlock: {:?}",
        start.elapsed()
    );
    assert_eq!(code, 0);
    assert!(
        out.len() > 8 * 1024 * 1024,
        "payload truncated: {} bytes",
        out.len()
    );
    assert!(out.ends_with("}\n"));
}

#[test]
fn an_upstream_violating_the_spec_does_not_break_the_relay() {
    let (out, code) = session("malformed", &format!("{INIT}\n"), "malformed");

    assert_eq!(code, 0);
    // Blank lines absorbed, invalid JSON relayed verbatim, CRLF preserved,
    // final unterminated frame completed.
    assert!(out.contains("this is not json"), "{out:?}");
    assert!(out.contains("\"id\":1"), "{out:?}");
    assert!(out.contains("\"id\":2"), "{out:?}");
    assert!(!out.starts_with('\n'), "blank lines not absorbed: {out:?}");
    assert!(out.ends_with('\n'));
}

// --- The orphan case ---

#[test]
fn no_process_survives_the_shim_shutting_down() {
    // The most visible failure mode in real use: thirty ghost `node` processes
    // after a day's work, with mcpwall as the obvious culprit. The server used
    // here deliberately ignores SIGTERM, which forces the shim to escalate.
    let db = db_path("orphan");
    let mut shim = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .arg("--")
        .arg(server("ignores_sigterm"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("starting the shim");

    let shim_pid = shim.id();

    // Wait for the grandchild to exist.
    let child_pid = wait_for(Duration::from_secs(5), || {
        children_of(shim_pid).first().copied()
    })
    .expect("the upstream server never started");

    assert!(alive(child_pid), "the upstream should be running");

    // We kill the shim the way a closing client would.
    signal(shim_pid, nix::sys::signal::Signal::SIGTERM);

    let _ = shim.wait();

    // The upstream ignores SIGTERM; without escalation it would survive. We
    // give the shim its grace window, then check.
    let dead = wait_for(Duration::from_secs(20), || {
        (!alive(child_pid)).then_some(())
    });

    if dead.is_none() {
        // Do not leave anything behind after a failing test.
        signal(child_pid, nix::sys::signal::Signal::SIGKILL);
    }
    let _ = std::fs::remove_file(&db);

    assert!(
        dead.is_some(),
        "the upstream server (pid {child_pid}) survived the shim shutting down"
    );
}

#[test]
fn closing_stdin_stops_the_upstream() {
    // The normal shutdown path of the stdio MCP spec: close stdin, the upstream
    // exits.
    let db = db_path("stdin-close");
    let mut shim = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .arg("--")
        .arg(server("normal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("starting the shim");

    let shim_pid = shim.id();
    let child_pid = wait_for(Duration::from_secs(5), || {
        children_of(shim_pid).first().copied()
    })
    .expect("upstream did not start");

    drop(shim.stdin.take());

    let start = Instant::now();
    let _ = shim.wait();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "the shim did not exit after stdin was closed"
    );

    let dead = wait_for(Duration::from_secs(10), || {
        (!alive(child_pid)).then_some(())
    });
    let _ = std::fs::remove_file(&db);
    assert!(dead.is_some(), "the upstream survived stdin being closed");
}

// --- Journal ---

#[test]
fn the_journal_records_every_call() {
    // M0 exit criterion: "find every call again in the journal".
    let db = db_path("journal");
    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\"}}}}\n"
    );

    let mut child = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .arg("--")
        .arg(server("normal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim");
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(input.as_bytes());
    }
    let _ = child.wait_with_output();

    let out = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .args(["log", "-n", "50", "--json"])
        .output()
        .expect("log");
    let text = String::from_utf8_lossy(&out.stdout);

    let lines: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    let methods: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.get("method")?.as_str())
        .collect();
    assert!(methods.contains(&"initialize"), "{methods:?}");
    assert!(methods.contains(&"tools/list"), "{methods:?}");
    assert!(methods.contains(&"tools/call"), "{methods:?}");

    // The upstream's three responses are there too.
    let responses = lines
        .iter()
        .filter(|l| l["direction"] == "to_client")
        .count();
    assert_eq!(responses, 3, "responses missing: {text}");

    // Capturing `initialize` filled in the server.
    assert!(
        lines.iter().any(|l| l["server"] == "normal"),
        "serverInfo not captured: {text}"
    );

    // The scope is resolved and its provenance stored.
    let source = lines[0]["scope_source"].as_str().unwrap_or("");
    assert!(
        ["injected", "roots", "cwd"].contains(&source),
        "unexpected provenance: {source}"
    );

    let stats = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .args(["log", "--stats"])
        .output()
        .expect("stats");
    let stats = String::from_utf8_lossy(&stats.stdout);
    assert!(stats.contains("sessions        1"), "{stats}");
    assert!(stats.contains("blocked         0"), "{stats}");

    let _ = std::fs::remove_file(&db);
}

#[test]
fn the_injected_project_beats_the_cwd() {
    // Link 1 of the provenance chain: `--project`, written by `mcpwall init`.
    // It must win, and it must unlock the `forever` scope.
    let db = db_path("project");
    let project = std::env::temp_dir();

    let mut child = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .args(["--project".as_ref(), project.as_os_str()])
        .arg("--")
        .arg(server("normal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim");
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(format!("{INIT}\n").as_bytes());
    }
    let _ = child.wait_with_output();

    let out = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .args(["log", "-n", "10", "--json"])
        .output()
        .expect("log");
    let text = String::from_utf8_lossy(&out.stdout);
    let first: serde_json::Value = text
        .lines()
        .next()
        .and_then(|l| serde_json::from_str(l).ok())
        .expect("at least one line");

    assert_eq!(first["scope_source"], "injected", "{text}");
    let _ = std::fs::remove_file(&db);
}

// --- Process helpers ---

fn signal(pid: u32, sig: nix::sys::signal::Signal) {
    if let Ok(pid) = i32::try_from(pid) {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig);
    }
}

/// Does the process still exist?
///
/// `kill(pid, 0)` only tests. A zombie still answers present, hence filtering
/// on the state reported by `ps`.
fn alive(pid: u32) -> bool {
    let Ok(out) = Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output()
    else {
        return false;
    };
    let state = String::from_utf8_lossy(&out.stdout);
    let state = state.trim();
    !state.is_empty() && !state.starts_with('Z')
}

fn children_of(pid: u32) -> Vec<u32> {
    let Ok(out) = Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .output()
    else {
        return Vec::new();
    };
    BufReader::new(out.stdout.as_slice())
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

fn wait_for<T>(limit: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    f()
}
