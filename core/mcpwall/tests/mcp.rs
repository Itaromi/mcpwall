//! MCP semantics tests.
//!
//! Two obsessions: the method scan must never pick the wrong key, and
//! `initialize` must never be blockable.

use mcpwall::mcp::{
    AllowAll, CallContext, ClientHello, DecisionPoint, Disposition, METHOD_SCAN_WINDOW, MethodScan,
    ServerHello, classify, disposition, parse_client_hello, parse_server_hello, scan_method,
};

fn found(frame: &[u8]) -> (String, bool) {
    match scan_method(frame) {
        MethodScan::Found { method, full_scan } => (method, full_scan),
        other => panic!("expected a method, got {other:?}"),
    }
}

// --- Method scan: nominal cases ---

#[test]
fn method_at_the_head_of_the_frame() {
    let (m, full) = found(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#);
    assert_eq!(m, "tools/call");
    assert!(!full, "must fit inside the window");
}

#[test]
fn notification_without_an_id() {
    let (m, _) = found(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert_eq!(m, "notifications/initialized");
}

#[test]
fn response_without_a_method() {
    let frame = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;
    assert_eq!(scan_method(frame), MethodScan::NoMethod);
    assert_eq!(classify(&MethodScan::NoMethod), Disposition::Passthrough);
}

#[test]
fn whitespace_around_the_colon() {
    let (m, _) = found(br#"{ "method" : "tools/call" , "id" : 1 }"#);
    assert_eq!(m, "tools/call");
}

// --- Method scan: the traps ---

#[test]
fn nested_method_key_ignored() {
    // A naive substring search would return "x". Depth tracking requires
    // `method` to be a key of the root object.
    let (m, _) = found(br#"{"params":{"method":"x"},"method":"tools/call","id":1}"#);
    assert_eq!(m, "tools/call");
}

#[test]
fn method_as_a_value_and_not_a_key() {
    // Here "method" appears as the *value* of "kind". It must not be taken.
    let (m, _) = found(br#"{"kind":"method","method":"resources/read","id":1}"#);
    assert_eq!(m, "resources/read");
}

#[test]
fn method_only_as_a_value_yields_nothing() {
    assert_eq!(
        scan_method(br#"{"kind":"method","id":1,"result":{}}"#),
        MethodScan::NoMethod
    );
}

#[test]
fn a_brace_inside_a_string_does_not_skew_the_depth() {
    let (m, _) = found(br#"{"id":"a{b}c","method":"tools/call"}"#);
    assert_eq!(m, "tools/call");
}

// --- Escaping one's way out of classification ---

#[test]
fn an_escaped_quote_before_method_does_not_hide_the_method() {
    // The trap: a scan that bails on the first `\` would classify this as
    // Unparsable, hence Observe, hence outside the decision point. A
    // well-chosen `id` would be enough to bypass the policy.
    let (m, _) = found(br#"{"id":"a\"b","method":"tools/call"}"#);
    assert_eq!(m, "tools/call");
    assert_eq!(
        classify(&scan_method(br#"{"id":"a\"b","method":"tools/call"}"#)),
        Disposition::Decide
    );
}

#[test]
fn an_escaped_backslash_does_not_skew_the_depth() {
    let (m, _) = found(br#"{"id":"a\\","method":"resources/read"}"#);
    assert_eq!(m, "resources/read");
}

#[test]
fn a_fake_escaped_method_inside_a_value_does_not_fool_us() {
    // `"method"` appears, escaped, inside a string value.
    let (m, _) = found(br#"{"id":"x \"method\":\"evil\" y","method":"tools/call"}"#);
    assert_eq!(m, "tools/call");
}

#[test]
fn a_method_containing_an_escape_is_kept_out_of_the_decision_point() {
    // We do not decode escapes; we therefore refuse to conclude rather than
    // guess. Observe, never Decide.
    let scan = scan_method(br#"{"method":"tools\/call","id":1}"#);
    assert_eq!(scan, MethodScan::Unparsable);
    assert_eq!(classify(&scan), Disposition::Observe);
}

#[test]
fn a_non_textual_method_is_unparsable() {
    assert_eq!(
        scan_method(br#"{"method":42,"id":1}"#),
        MethodScan::Unparsable
    );
}

#[test]
fn a_truncated_frame_is_unparsable_not_nomethod() {
    // Silence is forbidden: a cut frame must not pass itself off as a
    // legitimate response with no method.
    assert_eq!(
        scan_method(br#"{"jsonrpc":"2.0","id":1,"meth"#),
        MethodScan::Unparsable
    );
    assert_eq!(
        scan_method(br#"{"method":"tools/ca"#),
        MethodScan::Unparsable
    );
}

#[test]
fn a_batch_array_yields_no_method() {
    // Batching was removed from the spec as of 2025-06-18; we do not handle it
    // here, we merely refuse to extract a method from it.
    assert_eq!(
        scan_method(br#"[{"method":"tools/call","id":1}]"#),
        MethodScan::NoMethod
    );
}

// --- The out-of-window fallback ---

#[test]
fn method_pushed_out_of_the_window_by_a_long_id() {
    let id = "z".repeat(METHOD_SCAN_WINDOW * 2);
    let frame = format!(r#"{{"jsonrpc":"2.0","id":"{id}","method":"tools/call"}}"#);

    let (m, full) = found(frame.as_bytes());
    assert_eq!(m, "tools/call");
    assert!(full, "the fallback to a full pass must be reported");
}

#[test]
fn method_pushed_out_by_params_serialised_first() {
    let blob = "a".repeat(METHOD_SCAN_WINDOW * 4);
    let frame = format!(r#"{{"params":{{"text":"{blob}"}},"method":"resources/read","id":1}}"#);

    let (m, full) = found(frame.as_bytes());
    assert_eq!(m, "resources/read");
    assert!(full);
}

#[test]
fn a_large_frame_with_no_method_stays_nomethod() {
    let blob = "b".repeat(METHOD_SCAN_WINDOW * 4);
    let frame = format!(r#"{{"id":1,"result":{{"text":"{blob}"}}}}"#);
    assert_eq!(scan_method(frame.as_bytes()), MethodScan::NoMethod);
}

// --- Classification ---

#[test]
fn the_decide_set() {
    for m in [
        "tools/call",
        "resources/read",
        "sampling/createMessage",
        "elicitation/create",
    ] {
        assert_eq!(disposition(m), Disposition::Decide, "{m}");
    }
}

#[test]
fn initialize_is_never_decidable() {
    // The guard that matters. Blocking `initialize` protects nothing and kills
    // the whole session. This test exists so that a future move of
    // `initialize` into the DECIDE set breaks CI rather than people's sessions.
    for m in ["initialize", "notifications/initialized"] {
        assert_eq!(disposition(m), Disposition::Observe, "{m}");
        assert_ne!(disposition(m), Disposition::Decide);
    }
}

#[test]
fn roots_traffic_is_observed() {
    // These two feed and invalidate link 2 of the scope. Leaving them on
    // passthrough would miss root changes mid-session.
    for m in ["roots/list", "notifications/roots/list_changed"] {
        assert_eq!(disposition(m), Disposition::Observe, "{m}");
    }
}

#[test]
fn an_unknown_method_falls_through() {
    assert_eq!(disposition("completion/complete"), Disposition::Passthrough);
    assert_eq!(disposition("ping"), Disposition::Passthrough);
}

#[test]
fn unparsable_falls_back_to_observe_never_to_decide() {
    let d = classify(&MethodScan::Unparsable);
    assert_eq!(d, Disposition::Observe);
    assert_ne!(d, Disposition::Decide);
}

#[test]
fn end_to_end_classification() {
    let frame = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
    assert_eq!(classify(&scan_method(frame)), Disposition::Decide);
}

// --- Decision point ---

#[test]
fn m0_allows_everything() {
    let ctx = CallContext {
        method: "tools/call",
        frame: b"{}",
    };
    assert_eq!(
        AllowAll.decide(&ctx).expect("AllowAll cannot fail"),
        mcpwall::mcp::Verdict::Allow
    );
}

// --- Capturing initialize ---

#[test]
fn capturing_the_client_hello() {
    // Shape taken from the 2025-11-25 spec, basic/lifecycle.
    let frame = br#"{
      "jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{
        "protocolVersion":"2025-11-25",
        "capabilities":{"roots":{"listChanged":true},"sampling":{}},
        "clientInfo":{"name":"ExampleClient","title":"Example","version":"1.0.0"}
      }
    }"#;

    assert_eq!(
        parse_client_hello(frame).unwrap(),
        ClientHello {
            requested_protocol_version: Some("2025-11-25".into()),
            client_name: Some("ExampleClient".into()),
            client_version: Some("1.0.0".into()),
            supports_roots: true,
            roots_list_changed: true,
        }
    );
}

#[test]
fn a_client_without_the_roots_capability() {
    let frame = br#"{"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2025-11-25","capabilities":{},
      "clientInfo":{"name":"C","version":"1"}}}"#;
    let hello = parse_client_hello(frame).unwrap();
    assert!(!hello.supports_roots, "scope link 2 unavailable");
    assert!(!hello.roots_list_changed);
}

#[test]
fn capturing_the_server_hello() {
    let frame = br#"{
      "jsonrpc":"2.0","id":1,
      "result":{
        "protocolVersion":"2025-11-25",
        "capabilities":{"tools":{"listChanged":true},"resources":{},"logging":{}},
        "serverInfo":{"name":"ExampleServer","version":"1.0.0"},
        "instructions":"..."
      }
    }"#;

    assert_eq!(
        parse_server_hello(frame).unwrap(),
        ServerHello {
            protocol_version: Some("2025-11-25".into()),
            server_name: Some("ExampleServer".into()),
            server_version: Some("1.0.0".into()),
            capabilities: vec!["logging".into(), "resources".into(), "tools".into()],
        }
    );
}

#[test]
fn the_negotiated_version_comes_from_the_server_response() {
    // The server does not support what the client asked for and answers with
    // another version. That is the one we store.
    let req = br#"{"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2025-11-25","capabilities":{},
      "clientInfo":{"name":"C","version":"1"}}}"#;
    let resp = br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",
      "capabilities":{},"serverInfo":{"name":"S","version":"1"}}}"#;

    assert_eq!(
        parse_client_hello(req).unwrap().requested_protocol_version,
        Some("2025-11-25".into())
    );
    assert_eq!(
        parse_server_hello(resp).unwrap().protocol_version,
        Some("2025-06-18".into())
    );
}

#[test]
fn a_server_error_is_not_a_hello() {
    let frame = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,
      "message":"Unsupported protocol version"}}"#;
    assert!(parse_server_hello(frame).is_none());
}

#[test]
fn a_hello_over_invalid_json_does_not_panic() {
    assert!(parse_client_hello(b"{ not json").is_none());
    assert!(parse_server_hello(b"").is_none());
}
