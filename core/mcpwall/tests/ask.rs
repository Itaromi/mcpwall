//! Confirmation flow tests.
//!
//! This is the machinery the app's decision panel drives. The cases that matter
//! are not "the user clicks allow" — they are what happens when they do not
//! click, when the interface dies, or when it asks for more than the scope's
//! provenance permits.

use std::io::{BufRead, BufReader, Lines, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn mcpwall() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcpwall"))
}

/// A short directory: `sun_path` is only 104 bytes on macOS.
fn workdir(tag: &str) -> PathBuf {
    let d = PathBuf::from(format!("/tmp/mwa-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("directory");
    d
}

const POLICY: &str = r#"
default: allow
ask_timeout_seconds: 3
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env"]
    action: ask
    severity: high
    message: "access to a secrets file"
overrides: []
"#;

struct Harness {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
}

/// A connection to the daemon, post-handshake.
struct Conn {
    write: UnixStream,
    lines: Lines<BufReader<UnixStream>>,
}

impl Conn {
    fn send(&mut self, v: Value) {
        writeln!(self.write, "{v}").expect("send");
        self.write.flush().ok();
    }

    fn recv(&mut self) -> Option<Value> {
        let line = self.lines.next()?.ok()?;
        serde_json::from_str(&line).ok()
    }
}

impl Harness {
    fn start(tag: &str, policy: &str) -> Self {
        let dir = workdir(tag);
        let socket = dir.join("d.sock");
        let policy_path = dir.join("policy.yaml");
        std::fs::write(&policy_path, policy).expect("policy");

        let child = Command::new(mcpwall())
            .args(["--db".as_ref(), dir.join("j.db").as_os_str()])
            .arg("daemon")
            .args(["--socket".as_ref(), socket.as_os_str()])
            .args(["--policy".as_ref(), policy_path.as_os_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("daemon");

        let start = Instant::now();
        while !socket.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(socket.exists(), "socket not created");

        Self { child, socket, dir }
    }

    fn connect(&self) -> Conn {
        let stream = UnixStream::connect(&self.socket).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let write = stream.try_clone().expect("clone");
        let mut lines = BufReader::new(stream).lines();

        writeln!(
            &write as &UnixStream,
            r#"{{"mcpwall_ipc": 2, "build": "test"}}"#
        )
        .expect("hello");
        let hello = lines.next().expect("daemon hello").expect("line");
        let v: Value = serde_json::from_str(&hello).expect("json");
        assert_eq!(v["mcpwall_ipc"], 2);

        Conn { write, lines }
    }

    /// An interface connection, subscribed to prompts.
    fn ui(&self) -> Conn {
        let mut c = self.connect();
        c.send(json!({"type": "subscribe"}));
        // Let the daemon register the subscription before a shim asks:
        // otherwise we are testing a race, not the behaviour.
        std::thread::sleep(Duration::from_millis(150));
        c
    }

    fn decide_request(scope_source: &str) -> Value {
        let frame = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/p/.env" } }
        })
        .to_string();
        json!({
            "type": "decide",
            "method": "tools/call",
            "frame": frame,
            "scope_key": "project:/p",
            "scope_source": scope_source,
            "scope_paths": ["/p"],
            "server": "srv",
            "session_id": 1,
        })
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// --- The nominal path ---

#[test]
fn a_prompt_reaches_the_interface_with_enough_to_decide_on() {
    let h = Harness::start("prompt", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));

    let prompt = ui.recv().expect("prompt");
    assert_eq!(prompt["type"], "prompt");

    // Everything needed to decide without looking elsewhere. If the user has to
    // open the journal to understand, they will click "allow" instead.
    assert_eq!(prompt["tool"], "read_file");
    assert_eq!(prompt["server"], "srv");
    assert_eq!(prompt["rule"], "secrets_paths");
    assert_eq!(prompt["severity"], "high");
    assert_eq!(prompt["scope_key"], "project:/p");
    assert!(
        prompt["preview"].as_str().unwrap_or("").contains(".env"),
        "the excerpt must show the argument: {prompt}"
    );
    assert_eq!(prompt["forever_allowed"], true);
    assert_eq!(prompt["timeout_seconds"], 3);

    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "once"
    }));

    let verdict = shim.recv().expect("verdict");
    assert_eq!(verdict["type"], "verdict");
    assert_eq!(verdict["outcome"], "allow");
}

#[test]
fn a_refusal_from_the_user_blocks() {
    let h = Harness::start("refusal", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("demande");

    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": false,
        "until": "once"
    }));

    let verdict = shim.recv().expect("verdict");
    assert_eq!(verdict["outcome"], "deny");
    assert!(
        verdict["message"]
            .as_str()
            .unwrap_or("")
            .contains("denied by the user"),
        "{verdict}"
    );
}

// --- When nobody answers ---

#[test]
fn with_no_interface_a_prompt_is_refused_and_says_so() {
    // No UI subscribed: nobody can confirm. We refuse rather than allow
    // silently, but the agent must understand why — otherwise it concludes the
    // tool is broken and retries in a loop.
    let h = Harness::start("no-ui", POLICY);
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let verdict = shim.recv().expect("verdict");

    assert_eq!(verdict["outcome"], "deny");
    let msg = verdict["message"].as_str().unwrap_or("");
    assert!(msg.contains("no interface"), "{msg}");
}

#[test]
fn an_unanswered_prompt_expires_into_a_refusal() {
    let h = Harness::start("timeout", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    let start = Instant::now();
    shim.send(Harness::decide_request("injected"));

    let prompt = ui.recv().expect("prompt");
    assert_eq!(prompt["type"], "prompt");

    // We do not answer. `ask_timeout_seconds: 3`.
    let verdict = shim.recv().expect("verdict");
    assert_eq!(verdict["outcome"], "deny");
    assert!(
        verdict["message"]
            .as_str()
            .unwrap_or("")
            .contains("timed out"),
        "{verdict}"
    );

    let d = start.elapsed();
    assert!(d >= Duration::from_secs(3), "expired too early: {d:?}");
    assert!(d < Duration::from_secs(15), "expired too late: {d:?}");
}

#[test]
fn an_expired_prompt_is_withdrawn_from_the_interface() {
    // Without this withdrawal, the panel would stay up with buttons that no
    // longer do anything — and the user would believe they had decided.
    let h = Harness::start("withdraw", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("prompt");
    let id = prompt["prompt_id"].clone();

    let withdraw = ui.recv().expect("withdrawal");
    assert_eq!(withdraw["type"], "withdraw");
    assert_eq!(withdraw["prompt_id"], id);

    let _ = shim.recv();
}

#[test]
fn a_late_answer_is_ignored_without_damage() {
    let h = Harness::start("late", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("prompt");
    let _ = ui.recv(); // the withdrawal
    let _ = shim.recv(); // the refusal by expiry

    // The user clicks after the fact. Nothing may break, and above all the
    // decision must not be recorded for later.
    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "session"
    }));

    shim.send(Harness::decide_request("injected"));
    let prompt2 = ui.recv().expect("a fresh prompt must be raised");
    assert_eq!(prompt2["type"], "prompt");
}

// --- Scopes ---

#[test]
fn a_session_decision_avoids_asking_again() {
    let h = Harness::start("session", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("prompt");
    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "session"
    }));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "allow");

    // Second identical call: allowed without asking again.
    shim.send(Harness::decide_request("injected"));
    let verdict = shim.recv().expect("verdict");
    assert_eq!(verdict["outcome"], "allow");
    assert_eq!(verdict["rule"], "override");
}

#[test]
fn a_once_decision_makes_us_ask_again() {
    // `once` applies to this call only. Confusing it with `session` would
    // silently grant more than the user ticked.
    let h = Harness::start("once", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let p1 = ui.recv().expect("prompt");
    ui.send(json!({"type":"answer","prompt_id":p1["prompt_id"],"allow":true,"until":"once"}));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "allow");

    shim.send(Harness::decide_request("injected"));
    let p2 = ui.recv().expect("a second prompt is expected");
    assert_eq!(p2["type"], "prompt");
    ui.send(json!({"type":"answer","prompt_id":p2["prompt_id"],"allow":false,"until":"once"}));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "deny");
}

#[test]
fn forever_is_persisted_into_the_policy() {
    let h = Harness::start("forever", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("prompt");
    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "forever"
    }));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "allow");

    // The write is asynchronous with respect to the verdict.
    std::thread::sleep(Duration::from_millis(300));
    let yaml = std::fs::read_to_string(h.dir.join("policy.yaml")).expect("policy");

    assert!(
        yaml.contains("project:/p"),
        "override not persisted: {yaml}"
    );
    assert!(yaml.contains("read_file"), "{yaml}");
    assert!(yaml.contains("until: forever"), "{yaml}");
    // The user's comments survive: we append, we do not rewrite.
    assert!(
        yaml.contains("ask_timeout_seconds: 3"),
        "the file was rewritten instead of appended to: {yaml}"
    );
}

#[test]
fn forever_is_downgraded_on_an_untrusted_scope() {
    // The central check: the interface is a client, not an authority. If the
    // scope's provenance does not permit `forever`, the daemon downgrades even
    // when the UI asked for it — otherwise a permanent permission granted on a
    // cwd would leak into other projects.
    let h = Harness::start("downgrade", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("cwd"));
    let prompt = ui.recv().expect("prompt");
    assert_eq!(
        prompt["forever_allowed"], false,
        "the UI must not offer `forever` here"
    );

    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "forever"
    }));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "allow");

    std::thread::sleep(Duration::from_millis(300));
    let yaml = std::fs::read_to_string(h.dir.join("policy.yaml")).expect("policy");
    assert!(
        !yaml.contains("project:/p"),
        "a permanent decision was written for an untrusted scope: {yaml}"
    );
}

// --- State for the popover ---

#[test]
fn the_interface_can_ask_for_the_state() {
    let h = Harness::start("status", POLICY);
    let mut ui = h.ui();

    ui.send(json!({"type": "status"}));
    let st = ui.recv().expect("state");

    assert_eq!(st["type"], "status");
    assert_eq!(st["ui_connected"], true);
    assert!(
        st["policy_path"]
            .as_str()
            .unwrap_or("")
            .ends_with("policy.yaml")
    );
}

#[test]
fn a_disconnected_interface_does_not_stall_the_shims() {
    // The app can be closed at any moment. Prompts revert to explained
    // refusals, but nothing may be left hanging.
    let h = Harness::start("ui-dead", POLICY);
    {
        let _ui = h.ui();
    } // the UI disconnects here
    std::thread::sleep(Duration::from_millis(200));

    let mut shim = h.connect();
    let start = Instant::now();
    shim.send(Harness::decide_request("injected"));
    let verdict = shim.recv().expect("verdict");

    assert_eq!(verdict["outcome"], "deny");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "the shim waited on an absent UI: {:?}",
        start.elapsed()
    );
}

// --- The shim's timeout ---

#[test]
fn the_shim_waits_until_the_user_has_answered() {
    // The most dangerous defect found in M2, and invisible for as long as the
    // interface did not exist: the shim gave up after 5 seconds on its own
    // socket timeout while the daemon was still waiting for the click. And
    // giving up **lets the call through** — so every `ask` rule decayed into
    // `allow` as soon as the person thought for more than five seconds, which
    // is the normal case when reading a prompt.
    //
    // The daemon announces its timeout in the hello; the shim derives its own.
    let policy = POLICY.replace("ask_timeout_seconds: 3", "ask_timeout_seconds: 30");
    let h = Harness::start("shim-waits", &policy);
    let mut ui = h.ui();

    // The real shim, not a simulation: its client is what is under test.
    let mut shim = Command::new(mcpwall())
        .args(["--db".as_ref(), h.dir.join("j.db").as_os_str()])
        .arg("wrap")
        .args(["--socket".as_ref(), h.socket.as_os_str()])
        .arg("--")
        .arg({
            let mut p = mcpwall();
            p.pop();
            p.push("normal");
            p
        })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim");

    let input = format!(
        "{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"T","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/p/.env"}}}"#
    );
    if let Some(mut si) = shim.stdin.take() {
        let _ = si.write_all(input.as_bytes());
    }

    let prompt = ui.recv().expect("prompt");
    assert_eq!(prompt["type"], "prompt");

    // The user takes their time — well past the 5 seconds of the old hard-coded
    // timeout.
    std::thread::sleep(Duration::from_secs(8));
    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": false,
        "until": "once"
    }));

    let out = shim.wait_with_output().expect("waiting for the shim");
    let text = String::from_utf8_lossy(&out.stdout);
    let responses: std::collections::BTreeMap<i64, Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| Some((v.get("id")?.as_i64()?, v)))
        .collect();

    let denied = responses.get(&2).expect("response to the call");
    assert_eq!(
        denied["result"]["isError"], true,
        "the user's late refusal must be honoured, not bypassed by the shim \
         giving up: {text}"
    );
    assert!(
        denied["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("denied by the user"),
        "{text}"
    );
}
