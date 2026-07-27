//! Policy engine tests.
//!
//! The obsession here is the **false positive**: a rule that interrupts
//! wrongly trains the user to click "allow" without reading, which negates the
//! entire product. Almost as many tests check that a rule does *not* fire as
//! check that it does.

use std::path::PathBuf;

use mcpwall::policy::{Action, DEFAULT_POLICY_YAML, Finding, Policy, request_from_frame};
use mcpwall::scope::{Scope, ScopeSource};

fn scope(paths: &[&str]) -> Scope {
    Scope::new(
        ScopeSource::Injected,
        paths.iter().map(PathBuf::from).collect::<Vec<_>>(),
    )
}

/// Evaluates a `tools/call` against a policy.
fn eval(
    policy: &Policy,
    tool: &str,
    args: serde_json::Value,
    sc: &Scope,
) -> mcpwall::policy::Decision {
    let frame = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": tool, "arguments": args }
    })
    .to_string();

    let mut buf = String::new();
    let key = sc.key();
    let mut req = request_from_frame("tools/call", frame.as_bytes(), sc, &mut buf);
    req.scope_key = &key;
    policy.evaluate(&req)
}

/// Writes a policy into a directory of the caller's own and loads it.
///
/// One directory per test, not one for all: the tests run in parallel, and a
/// file truncated by a concurrent write used to read back as "allow
/// everything" — a green test for the wrong reason.
fn policy_from(tag: &str, yaml: &str) -> Policy {
    let dir = std::env::temp_dir().join(format!("mcpwall-pol-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("directory");
    let path = dir.join("policy.yaml");
    std::fs::write(&path, yaml).expect("write");
    Policy::load(&path).expect("load")
}

fn default_policy(tag: &str) -> Policy {
    let file = Policy::parse(DEFAULT_POLICY_YAML).expect("default policy must be valid");
    assert_eq!(file.default, Action::Allow);
    // We go through the same path as production.
    policy_from(tag, DEFAULT_POLICY_YAML)
}

// --- The default policy is valid and unobtrusive ---

#[test]
fn the_default_policy_parses() {
    let f = Policy::parse(DEFAULT_POLICY_YAML).expect("must parse");
    assert_eq!(f.default, Action::Allow);
    assert!(!f.fail_closed, "fail_closed must stay false by default");
    assert_eq!(f.ask_timeout_seconds, 60);
    assert!(f.rules.len() >= 4);
}

#[test]
fn at_rest_the_default_policy_asks_nothing() {
    // The anti-alert-fatigue test. Ordinary traffic must produce no
    // interruption at all.
    let p = default_policy("at_rest_the_default_policy_asks_nothing");
    let sc = scope(&["/Users/x/project"]);

    for (tool, args) in [
        (
            "read_file",
            serde_json::json!({"path": "/Users/x/project/src/main.rs"}),
        ),
        (
            "list_directory",
            serde_json::json!({"path": "/Users/x/project"}),
        ),
        ("search", serde_json::json!({"query": "fn main"})),
        ("git_status", serde_json::json!({})),
        (
            "write_file",
            serde_json::json!({"path": "/Users/x/project/out.txt", "content": "hello"}),
        ),
    ] {
        let d = eval(&p, tool, args, &sc);
        assert_eq!(d.action, Action::Allow, "{tool} must not interrupt");
    }
}

// --- Secret paths ---

#[test]
fn reading_a_dotenv_fires() {
    let p = default_policy("reading_a_dotenv_fires");
    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/Users/x/project/.env"}),
        &scope(&["/Users/x/project"]),
    );
    assert_eq!(d.action, Action::Ask);
    assert_eq!(d.rule.as_deref(), Some("secrets_paths"));
}

#[test]
fn ssh_keys_fire() {
    let p = default_policy("ssh_keys_fire");
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    for path in [
        format!("{home}/.ssh/id_rsa"),
        format!("{home}/.aws/credentials"),
    ] {
        let d = eval(
            &p,
            "read_file",
            serde_json::json!({ "path": path }),
            &scope(&["/Users/x/project"]),
        );
        assert_eq!(d.action, Action::Ask, "{path}");
    }
}

#[test]
fn a_file_named_environment_does_not_fire() {
    // `**/.env` must not catch `environment.ts` or `.envrc`.
    let p = default_policy("a_file_named_environment_does_not_fire");
    for path in [
        "/Users/x/project/src/environment.ts",
        "/Users/x/project/env.example",
        "/Users/x/project/docs/environment.md",
    ] {
        let d = eval(
            &p,
            "read_file",
            serde_json::json!({ "path": path }),
            &scope(&["/Users/x/project"]),
        );
        assert_eq!(d.action, Action::Allow, "false positive on {path}");
    }
}

// --- Secret detection ---

#[test]
fn an_aws_key_in_the_arguments_fires() {
    let p = default_policy("an_aws_key_in_the_arguments_fires");
    let d = eval(
        &p,
        "http_post",
        serde_json::json!({"body": "AKIAIOSFODNN7EXAMPLE"}),
        &scope(&["/Users/x/project"]),
    );
    assert_eq!(d.action, Action::Ask);
    assert_eq!(d.rule.as_deref(), Some("secret_pattern"));
}

#[test]
fn the_journal_never_receives_the_secret_value() {
    // Project convention: we store the kind and a truncated prefix, never the
    // value. An audit journal that copies secrets makes leaks worse, it does
    // not protect against them.
    let p = default_policy("the_journal_never_receives_the_secret_value");
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let d = eval(
        &p,
        "http_post",
        serde_json::json!({ "body": secret }),
        &scope(&["/Users/x/project"]),
    );

    let message = d.agent_message();
    assert!(
        !message.contains(secret),
        "secret copied through: {message}"
    );
    assert!(message.contains("AKIAIO"), "prefix expected: {message}");

    match d.findings.first() {
        Some(Finding::Secret { kind, prefix }) => {
            assert_eq!(*kind, "AWS access key");
            assert_eq!(prefix.len(), 6);
            assert!(!secret.ends_with(prefix.as_str()) || prefix.len() < secret.len());
        }
        other => panic!("expected a finding, got {other:?}"),
    }
}

#[test]
fn the_secret_detectors_are_stingy() {
    // Every pattern is a potential source of false positives. These values look
    // like secrets without being any.
    let p = default_policy("the_secret_detectors_are_stingy");
    for value in [
        "AKIA",                 // too short
        "akiaiosfodnn7example", // lowercase
        "sk-",                  // too short
        "ghp_short",            // too short
        "some prose mentioning sk- and tokens",
    ] {
        let d = eval(
            &p,
            "http_post",
            serde_json::json!({ "body": value }),
            &scope(&["/Users/x/project"]),
        );
        assert_eq!(d.action, Action::Allow, "false positive on {value:?}");
    }
}

#[test]
fn a_private_key_is_recognised() {
    let p = default_policy("a_private_key_is_recognised");
    let d = eval(
        &p,
        "http_post",
        serde_json::json!({"body": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"}),
        &scope(&["/Users/x/project"]),
    );
    assert_eq!(d.action, Action::Ask);
}

// --- Leaving the project ---

#[test]
fn a_write_outside_the_project_fires() {
    let p = default_policy("a_write_outside_the_project_fires");
    let d = eval(
        &p,
        "write_file",
        serde_json::json!({"path": "/etc/hosts", "content": "x"}),
        &scope(&["/Users/x/project"]),
    );
    assert_eq!(d.action, Action::Ask);
    assert_eq!(d.rule.as_deref(), Some("outside_project_write"));
}

#[test]
fn a_read_outside_the_project_does_not_fire() {
    // The rule targets writes. Reading system documentation is unremarkable.
    let p = default_policy("a_read_outside_the_project_does_not_fire");
    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/usr/share/doc/readme"}),
        &scope(&["/Users/x/project"]),
    );
    assert_eq!(d.action, Action::Allow);
}

#[test]
fn an_unknown_scope_never_fires_the_outside_project_rule() {
    // Without knowing where the project is, we cannot say we are leaving it.
    // Pretending otherwise would fire the rule on all of Claude Desktop's
    // traffic, whose cwd bears no relation to a project.
    let p = default_policy("an_unknown_scope_never_fires_the_outside_project_rule");
    let d = eval(
        &p,
        "write_file",
        serde_json::json!({"path": "/etc/hosts", "content": "x"}),
        &Scope::unknown(),
    );
    assert_eq!(d.action, Action::Allow);
}

// --- Inert M3 rules ---

#[test]
fn the_taint_rules_do_not_fire_yet() {
    // `taint_exfil` and `tool_description_drift` are present in the file but
    // inert as long as M3 does not exist. An inert, visible rule beats an
    // absent rule we would forget to write — but above all it must not block
    // by accident.
    let p = default_policy("the_taint_rules_do_not_fire_yet");
    let d = eval(
        &p,
        "http_post",
        serde_json::json!({"body": "some arbitrary data"}),
        &scope(&["/Users/x/project"]),
    );
    assert_eq!(d.action, Action::Allow);
    assert_ne!(d.rule.as_deref(), Some("taint_exfil"));
}

// --- File robustness ---

#[test]
fn an_empty_condition_matches_nothing() {
    // Without this guard, a typo in a condition name would produce a rule with
    // no conditions, and therefore block all traffic.
    let yaml = r#"
default: allow
rules:
  - id: empty
    when: {}
    action: deny
"#;
    let file = Policy::parse(yaml).expect("parse");
    assert_eq!(file.rules.len(), 1);

    let p = policy_from("an_empty_condition_matches_nothing", yaml);

    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/x"}),
        &scope(&["/x"]),
    );
    assert_eq!(d.action, Action::Allow, "an empty rule must block nothing");
}

#[test]
fn an_empty_policy_is_refused() {
    // Found via a test that turned flaky: since every field has a default, an
    // empty file deserialised into `default: allow` with no rules at all. A
    // truncated `policy.yaml` — full disk, interrupted editor, partial write —
    // would therefore have disabled the firewall without a word.
    for empty in ["", "   ", "\n\n", "\t\n  "] {
        assert!(
            Policy::parse(empty).is_err(),
            "an empty policy must never mean 'allow everything': {empty:?}"
        );
    }
}

#[test]
fn a_truncated_policy_leaves_the_previous_one_active() {
    // The hot-reload corollary: if the file is emptied during a session, we
    // carry on with what we had rather than throwing the doors open.
    let dir = std::env::temp_dir().join(format!("mcpwall-tronq-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("directory");
    let path = dir.join("policy.yaml");

    std::fs::write(&path, "default: deny\nrules: []\n").expect("write");
    let mut p = Policy::load(&path).expect("load");
    assert_eq!(p.default_action(), Action::Deny);

    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&path, "").expect("truncate");

    assert!(!p.reload_if_changed());
    assert_eq!(
        p.default_action(),
        Action::Deny,
        "an emptied file must not disable filtering"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_field_is_refused() {
    // Better to refuse the file than to silently ignore a rule the user
    // believes is active.
    let yaml = r#"
default: allow
rules:
  - id: typo
    when:
      arg_path_matchez: ["**/.env"]
    action: deny
"#;
    assert!(Policy::parse(yaml).is_err());
}

#[test]
fn the_first_matching_rule_wins() {
    let yaml = r#"
default: allow
rules:
  - id: first
    when:
      tool_matches: ["read_*"]
    action: allow
  - id: second
    when:
      arg_path_matches: ["**/.env"]
    action: deny
"#;
    let p = policy_from("the_first_matching_rule_wins", yaml);

    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/x/.env"}),
        &scope(&["/x"]),
    );
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.rule.as_deref(), Some("first"));
}

// --- Overrides ---

#[test]
fn an_override_takes_precedence_over_the_rules() {
    let yaml = r#"
default: allow
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env"]
    action: deny
overrides:
  - scope: "project:/Users/x/project"
    tool: "read_file"
    action: allow
    until: forever
"#;
    let p = policy_from("an_override_takes_precedence_over_the_rules", yaml);

    let sc = scope(&["/Users/x/project"]);
    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/Users/x/project/.env"}),
        &sc,
    );
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.rule.as_deref(), Some("override"));
}

#[test]
fn an_override_does_not_leak_into_another_project() {
    // The check that the whole provenance chain exists to guarantee.
    let yaml = r#"
default: allow
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env"]
    action: deny
overrides:
  - scope: "project:/Users/x/project-a"
    tool: "read_file"
    action: allow
    until: forever
"#;
    let p = policy_from("an_override_does_not_leak_into_another_project", yaml);

    let other = scope(&["/Users/x/project-b"]);
    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/Users/x/project-b/.env"}),
        &other,
    );
    assert_eq!(
        d.action,
        Action::Deny,
        "the override leaked into another project"
    );
}

// --- Hot reloading ---

#[test]
fn the_policy_reloads_when_the_file_changes() {
    let dir = std::env::temp_dir().join(format!("mcpwall-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("p.yaml");

    std::fs::write(&path, "default: allow\nrules: []\n").expect("write");
    let mut p = Policy::load(&path).expect("load");
    assert_eq!(p.default_action(), Action::Allow);

    // mtime granularity forces us to wait a little.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&path, "default: deny\nrules: []\n").expect("rewrite");

    assert!(p.reload_if_changed());
    assert_eq!(p.default_action(), Action::Deny);
}

#[test]
fn an_invalid_policy_leaves_the_previous_one_active() {
    // A half-edited file must neither throw the firewall wide open nor slam it
    // shut in the middle of a working session.
    let dir = std::env::temp_dir().join(format!("mcpwall-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("p.yaml");

    std::fs::write(&path, "default: deny\nrules: []\n").expect("write");
    let mut p = Policy::load(&path).expect("load");
    assert_eq!(p.default_action(), Action::Deny);

    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&path, "default: [this is not valid\n").expect("rewrite");

    assert!(
        !p.reload_if_changed(),
        "an invalid file must not be adopted"
    );
    assert_eq!(
        p.default_action(),
        Action::Deny,
        "the previous policy must remain"
    );
}
