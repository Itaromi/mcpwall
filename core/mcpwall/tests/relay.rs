//! Relay tests: what crosses the shim, and what it must never change.
//!
//! Everything runs on in-memory buffers: no processes, no SQLite. What these
//! tests check above all is that no inspection anomaly interrupts traffic.

use std::sync::{Arc, Mutex};

use mcpwall::protocol::frame::SplitterStats;
use mcpwall::protocol::mcp::{
    AllowAll, CallContext, DecisionError, DecisionPoint, Disposition, Verdict,
};
use mcpwall::transport::stdio::{Anomaly, Direction, FrameEvent, Observer, Pump};
use tokio::sync::mpsc;

// --- Test harness ---

/// Record of a frame seen by the observer.
struct Seen {
    #[allow(dead_code)]
    direction: Direction,
    #[allow(dead_code)]
    disposition: Disposition,
    method: Option<String>,
    #[allow(dead_code)]
    denied: bool,
}

#[derive(Default)]
struct Recorder {
    frames: Mutex<Vec<Seen>>,
    anomalies: Mutex<Vec<String>>,
    eof: Mutex<Vec<(Direction, SplitterStats)>>,
}

impl Observer for Recorder {
    fn on_frame(&self, e: &FrameEvent<'_>) {
        let denied = matches!(e.verdict, Some(Verdict::Deny { .. }));
        if let Ok(mut g) = self.frames.lock() {
            g.push(Seen {
                direction: e.direction,
                disposition: e.disposition,
                method: e.method.map(str::to_owned),
                denied,
            });
        }
    }

    fn on_anomaly(&self, a: &Anomaly) {
        if let Ok(mut g) = self.anomalies.lock() {
            g.push(format!("{a:?}"));
        }
    }

    fn on_eof(&self, d: Direction, s: SplitterStats) {
        if let Ok(mut g) = self.eof.lock() {
            g.push((d, s));
        }
    }
}

impl Recorder {
    fn methods(&self) -> Vec<String> {
        self.frames
            .lock()
            .map(|g| g.iter().filter_map(|f| f.method.clone()).collect())
            .unwrap_or_default()
    }

    fn count(&self) -> usize {
        self.frames.lock().map(|g| g.len()).unwrap_or(0)
    }

    fn anomalies(&self) -> Vec<String> {
        self.anomalies.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

/// Blocks everything that reaches the decision point.
struct DenyAll;

impl DecisionPoint for DenyAll {
    fn decide(&self, _ctx: &CallContext<'_>) -> Result<Verdict, DecisionError> {
        Ok(Verdict::Deny {
            rule: "test_rule".into(),
            message: "tainted local data in outbound argument".into(),
        })
    }
}

/// A broken decision point. Simulates an unreachable daemon.
struct Broken {
    fail_closed: bool,
}

impl DecisionPoint for Broken {
    fn decide(&self, _ctx: &CallContext<'_>) -> Result<Verdict, DecisionError> {
        Err(DecisionError {
            reason: "daemon unreachable".into(),
            fail_closed: self.fail_closed,
        })
    }
}

fn pump(direction: Direction, obs: Arc<Recorder>, dp: Arc<dyn DecisionPoint>) -> Pump {
    Pump {
        direction,
        max_frame_bytes: 1024,
        observer: obs,
        decision: dp,
        denied_tx: None,
    }
}

/// Relays `input` and returns what came out on the upstream side.
async fn relay(direction: Direction, input: &[u8], obs: Arc<Recorder>) -> Vec<u8> {
    let mut out = Vec::new();
    pump(direction, obs, Arc::new(AllowAll))
        .run(input, &mut out, None)
        .await
        .expect("the relay must not fail");
    out
}

// --- Transparency ---

#[tokio::test]
async fn the_relay_is_transparent() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
    let obs = Arc::new(Recorder::default());
    let out = relay(Direction::ToServer, input, obs.clone()).await;

    assert_eq!(out, input, "byte for byte");
    assert_eq!(obs.count(), 2);
    assert_eq!(obs.methods(), vec!["tools/call"]);
}

#[tokio::test]
async fn upstream_crlf_is_preserved() {
    // We do not normalise what we do not understand: the peer gets its bytes.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n";
    let obs = Arc::new(Recorder::default());
    assert_eq!(relay(Direction::ToClient, input, obs).await, input);
}

#[tokio::test]
async fn a_multi_megabyte_payload() {
    let big = "z".repeat(4 * 1024 * 1024);
    let input = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"t\":\"{big}\"}}}}\n");

    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();
    Pump {
        direction: Direction::ToClient,
        max_frame_bytes: 32 * 1024 * 1024,
        observer: obs.clone(),
        decision: Arc::new(AllowAll),
        denied_tx: None,
    }
    .run(input.as_bytes(), &mut out, None)
    .await
    .expect("relay");

    assert_eq!(out, input.as_bytes());
    assert_eq!(obs.count(), 1);
}

#[tokio::test]
async fn a_final_frame_without_a_delimiter_gets_one() {
    // Otherwise the peer waits forever for the rest of a complete message.
    let obs = Arc::new(Recorder::default());
    let out = relay(
        Direction::ToClient,
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
        obs.clone(),
    )
    .await;

    assert!(out.ends_with(b"}\n"));
    assert_eq!(obs.count(), 1);
    assert!(
        obs.anomalies().iter().any(|a| a.contains("Unterminated")),
        "the anomaly must be reported: {:?}",
        obs.anomalies()
    );
}

// --- No anomaly interrupts traffic ---

#[tokio::test]
async fn an_oversized_frame_is_dropped_but_the_stream_continues() {
    let mut input = vec![b'x'; 4096];
    input.push(b'\n');
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n");

    let obs = Arc::new(Recorder::default());
    let out = relay(Direction::ToServer, &input, obs.clone()).await;

    assert_eq!(
        out, b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        "the discarded bytes must not reach the upstream, what follows must"
    );
    assert!(obs.anomalies().iter().any(|a| a.contains("Oversize")));
    assert_eq!(obs.methods(), vec!["tools/list"]);
}

#[tokio::test]
async fn malformed_json_is_relayed_anyway() {
    // It is not the shim's place to decide a message is invalid: it is the
    // upstream server's job to answer with its error. We journal and pass on.
    let input = b"not json at all\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    let obs = Arc::new(Recorder::default());
    assert_eq!(relay(Direction::ToServer, input, obs.clone()).await, input);
    assert_eq!(obs.count(), 2);
}

#[tokio::test]
async fn upstream_blank_lines_are_absorbed() {
    let input = b"\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    let obs = Arc::new(Recorder::default());
    let out = relay(Direction::ToClient, input, obs.clone()).await;
    assert_eq!(out, b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    assert_eq!(obs.count(), 1);
}

#[tokio::test]
async fn frames_broken_into_small_chunks() {
    // The relay must be insensitive to how reads are split, like the splitter
    // it uses.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";

    let obs = Arc::new(Recorder::default());
    let (mut client, mut server) = tokio::io::duplex(8);
    let mut out = Vec::new();

    let feeder = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        for chunk in input.chunks(3) {
            let _ = client.write_all(chunk).await;
        }
        let _ = client.shutdown().await;
    });

    pump(Direction::ToServer, obs.clone(), Arc::new(AllowAll))
        .run(&mut server, &mut out, None)
        .await
        .expect("relay");
    let _ = feeder.await;

    assert_eq!(out, input);
    assert_eq!(obs.methods(), vec!["tools/call", "tools/list"]);
}

// --- Decision point ---

#[tokio::test]
async fn m0_blocks_nothing() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n";
    let obs = Arc::new(Recorder::default());
    assert_eq!(relay(Direction::ToServer, input, obs).await, input);
}

#[tokio::test]
async fn only_the_upward_direction_consults_the_decision_point() {
    // A response coming down must never be submitted for a verdict.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n";
    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();

    pump(Direction::ToClient, obs.clone(), Arc::new(DenyAll))
        .run(&input[..], &mut out, None)
        .await
        .expect("relay");

    assert_eq!(out, input, "DenyAll must not apply on the way down");
}

#[tokio::test]
async fn initialize_cannot_be_blocked() {
    // The structural guard seen end to end: even with a decision point that
    // refuses everything, `initialize` goes through. Blocking it would kill the
    // session.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n";
    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();

    pump(Direction::ToServer, obs.clone(), Arc::new(DenyAll))
        .run(&input[..], &mut out, None)
        .await
        .expect("relay");

    assert_eq!(out, input, "initialize must reach the upstream");
}

#[tokio::test]
async fn a_deny_does_not_go_up_and_answers_the_client() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/call\",\
                  \"params\":{\"name\":\"http_post\"}}\n";

    let (tx, mut rx) = mpsc::unbounded_channel();
    let obs = Arc::new(Recorder::default());
    let mut upstream = Vec::new();

    Pump {
        direction: Direction::ToServer,
        max_frame_bytes: 1024,
        observer: obs.clone(),
        decision: Arc::new(DenyAll),
        denied_tx: Some(tx),
    }
    .run(&input[..], &mut upstream, None)
    .await
    .expect("relay");

    assert!(
        upstream.is_empty(),
        "the frame must never reach the upstream"
    );

    let payload = rx.recv().await.expect("a block response is expected");
    let v: serde_json::Value = serde_json::from_slice(payload.trim_ascii_end()).expect("json");

    // Shape from §5: a valid result, not a protocol error.
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 42, "the id must be that of the blocked request");
    assert_eq!(v["result"]["isError"], true);
    assert!(v.get("error").is_none(), "never a JSON-RPC error");

    let text = v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.starts_with("blocked by mcpwall:"), "{text}");
    assert!(text.contains("rule: test_rule"), "{text}");
    assert!(payload.ends_with(b"\n"), "a frame ready to write");
}

#[tokio::test]
async fn a_blocked_notification_produces_no_response() {
    // No id, so nothing is waiting for a response. We drop it and note it.
    let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{}}\n";

    let (tx, mut rx) = mpsc::unbounded_channel();
    let obs = Arc::new(Recorder::default());
    let mut upstream = Vec::new();

    Pump {
        direction: Direction::ToServer,
        max_frame_bytes: 1024,
        observer: obs.clone(),
        decision: Arc::new(DenyAll),
        denied_tx: Some(tx),
    }
    .run(&input[..], &mut upstream, None)
    .await
    .expect("relay");

    assert!(upstream.is_empty());
    assert!(rx.try_recv().is_err(), "no response may be manufactured");
    assert!(
        obs.anomalies()
            .iter()
            .any(|a| a.contains("DeniedWithoutId")),
        "{:?}",
        obs.anomalies()
    );
}

// --- Return path ---

#[tokio::test]
async fn block_responses_leave_through_the_downward_pump() {
    // The block is decided on the way up but the response comes back down:
    // without this return path, the client would wait forever.
    let (tx, rx) = mpsc::unbounded_channel();
    tx.send(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"isError\":true}}\n".to_vec())
        .expect("send");
    drop(tx);

    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();
    let upstream = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";

    pump(Direction::ToClient, obs.clone(), Arc::new(AllowAll))
        .run(&upstream[..], &mut out, Some(rx))
        .await
        .expect("relay");

    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("\"id\":7"),
        "the injected frame is missing: {text}"
    );
    assert!(
        text.contains("\"id\":1"),
        "the upstream traffic is missing: {text}"
    );
}

// --- Counters ---

#[tokio::test]
async fn the_counters_are_reported_at_end_of_stream() {
    let input = b"\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n";
    let obs = Arc::new(Recorder::default());
    relay(Direction::ToClient, input, obs.clone()).await;

    let eof = obs.eof.lock().expect("lock");
    let (direction, stats) = eof.first().expect("one eof expected");
    assert_eq!(*direction, Direction::ToClient);
    assert_eq!(stats.frames, 1);
    assert_eq!(stats.empty_skipped, 1);
    assert_eq!(stats.crlf, 1);
}

// --- Decision point failure ---

#[tokio::test]
async fn a_broken_decision_point_lets_traffic_through() {
    // The availability rule of §4 applied to our own code: if the daemon is
    // down, we do not break the agent's session.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n";
    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();

    pump(
        Direction::ToServer,
        obs.clone(),
        Arc::new(Broken { fail_closed: false }),
    )
    .run(&input[..], &mut out, None)
    .await
    .expect("relay");

    assert_eq!(out, input, "traffic must go through despite the failure");
    assert!(
        obs.anomalies()
            .iter()
            .any(|a| a.contains("DecisionUnavailable")),
        "the incident must be reported: {:?}",
        obs.anomalies()
    );
}

#[tokio::test]
async fn fail_closed_blocks_when_the_policy_asks_for_it() {
    // A user who explicitly asked for fail_closed gets a block, not a silent
    // pass-through.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{}}\n";
    let (tx, mut rx) = mpsc::unbounded_channel();
    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();

    Pump {
        direction: Direction::ToServer,
        max_frame_bytes: 1024,
        observer: obs.clone(),
        decision: Arc::new(Broken { fail_closed: true }),
        denied_tx: Some(tx),
    }
    .run(&input[..], &mut out, None)
    .await
    .expect("relay");

    assert!(out.is_empty(), "nothing may reach the upstream");
    let payload = rx.recv().await.expect("a block response is expected");
    let v: serde_json::Value = serde_json::from_slice(payload.trim_ascii_end()).expect("json");
    assert_eq!(v["result"]["isError"], true);
    assert!(
        v["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("fail_closed")
    );
}
