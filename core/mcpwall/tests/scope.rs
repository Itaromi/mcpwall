//! Scope resolution tests.
//!
//! The test that matters is [`forever_refused_on_weak_provenance`]: it is what
//! stops a permanent permission from leaking from one project to another.

use mcpwall::scope::{Scope, ScopeResolver, ScopeSource, canonicalize_for_scope, parse_root_uri};
use std::path::PathBuf;

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

// --- Precedence chain ---

#[test]
fn injected_beats_everything() {
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/tmp/elsewhere"));
    r.observe_roots([p("/home/u/roots")]);
    r.set_injected(p("/home/u/myrepo"));

    let s = r.resolve();
    assert_eq!(s.source(), ScopeSource::Injected);
    assert_eq!(s.paths(), [p("/home/u/myrepo")]);
}

#[test]
fn roots_beats_cwd() {
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/tmp/elsewhere"));
    r.observe_roots([p("/home/u/project")]);

    let s = r.resolve();
    assert_eq!(s.source(), ScopeSource::Roots);
    assert_eq!(s.paths(), [p("/home/u/project")]);
}

#[test]
fn cwd_as_a_last_resort() {
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/home/u/somewhere"));
    assert_eq!(r.resolve().source(), ScopeSource::Cwd);
}

#[test]
fn no_signal_yields_unknown_not_a_guess() {
    let s = ScopeResolver::new().resolve();
    assert_eq!(s.source(), ScopeSource::Unknown);
    assert!(s.paths().is_empty());
    assert_eq!(s.key(), "unknown");
}

#[test]
fn the_scope_may_rise_during_a_session() {
    // Server configured globally in ~/.claude.json: `init` could not write a
    // --project there. We start on cwd, then an upstream server asks for
    // roots/list and we rise to link 2.
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/home/u/somewhere"));

    let before = r.resolve();
    assert_eq!(before.source(), ScopeSource::Cwd);
    assert!(!before.allows_forever());

    r.observe_roots([p("/home/u/real-project")]);

    let after = r.resolve();
    assert_eq!(after.source(), ScopeSource::Roots);
    assert!(after.allows_forever());
    assert!(
        after.source().rank() < before.source().rank(),
        "provenance must rise, never fall"
    );
}

#[test]
fn list_changed_replaces_instead_of_merging() {
    // Merging would make the scope cover directories the client no longer
    // exposes.
    let mut r = ScopeResolver::new();
    r.observe_roots([p("/a"), p("/b")]);
    r.observe_roots([p("/c")]);
    assert_eq!(r.resolve().paths(), [p("/c")]);
}

#[test]
fn empty_roots_do_not_mask_the_cwd() {
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/home/u/project"));
    r.observe_roots(Vec::new());
    assert_eq!(r.resolve().source(), ScopeSource::Cwd);
}

// --- The `forever` guard ---

#[test]
fn forever_refused_on_weak_provenance() {
    // The central security check: under cwd or unknown, the meaning of the path
    // depends on the client, so `forever` would leak into other projects.
    assert!(!Scope::new(ScopeSource::Cwd, [p("/x")]).allows_forever());
    assert!(!Scope::unknown().allows_forever());

    assert!(Scope::new(ScopeSource::Injected, [p("/x")]).allows_forever());
    assert!(Scope::new(ScopeSource::Roots, [p("/x")]).allows_forever());
}

#[test]
fn precedence_order_is_stable() {
    assert!(ScopeSource::Injected.rank() < ScopeSource::Roots.rank());
    assert!(ScopeSource::Roots.rank() < ScopeSource::Cwd.rank());
    assert!(ScopeSource::Cwd.rank() < ScopeSource::Unknown.rank());
}

#[test]
fn provenance_labels_are_persisted() {
    // These strings go into the database. Changing them without a migration
    // breaks existing overrides.
    assert_eq!(ScopeSource::Injected.as_str(), "injected");
    assert_eq!(ScopeSource::Roots.as_str(), "roots");
    assert_eq!(ScopeSource::Cwd.as_str(), "cwd");
    assert_eq!(ScopeSource::Unknown.as_str(), "unknown");
}

// --- Set normalisation ---

#[test]
fn roots_are_sorted_and_deduplicated() {
    // roots is a set: arrival order must not change the key.
    let a = Scope::new(ScopeSource::Roots, [p("/b"), p("/a"), p("/b")]);
    let b = Scope::new(ScopeSource::Roots, [p("/a"), p("/b")]);
    assert_eq!(a.key(), b.key());
    assert_eq!(a.paths(), [p("/a"), p("/b")]);
}

#[test]
fn readable_key_for_a_single_root() {
    let s = Scope::new(ScopeSource::Injected, [p("/Users/marc/myrepo")]);
    assert_eq!(s.key(), "project:/Users/marc/myrepo");
}

#[test]
fn monorepo_with_several_roots() {
    let s = Scope::new(
        ScopeSource::Roots,
        [p("/repos/frontend"), p("/repos/backend")],
    );
    assert_eq!(s.paths().len(), 2);
    assert_eq!(s.display(), "/repos/backend, /repos/frontend");
    assert_ne!(
        s.key(),
        Scope::new(ScopeSource::Roots, [p("/repos/backend")]).key(),
        "a subset must not collide with the whole set"
    );
}

#[test]
fn provenance_is_absent_from_the_key() {
    // A session that rises from cwd to roots must land on the same rules, not
    // create a parallel set of them.
    let cwd = Scope::new(ScopeSource::Cwd, [p("/home/u/project")]);
    let roots = Scope::new(ScopeSource::Roots, [p("/home/u/project")]);
    assert_eq!(cwd.key(), roots.key());
    assert_ne!(cwd.allows_forever(), roots.allows_forever());
}

#[test]
fn provenance_with_no_path_falls_back_to_unknown() {
    let s = Scope::new(ScopeSource::Injected, Vec::new());
    assert_eq!(s.source(), ScopeSource::Unknown);
    assert!(!s.allows_forever());
}

// --- Root URIs ---

#[test]
fn nominal_file_uri() {
    // The exact form from the spec, client/roots.
    assert_eq!(
        parse_root_uri("file:///home/user/projects/myproject"),
        Some(p("/home/user/projects/myproject"))
    );
}

#[test]
fn uri_with_encoded_spaces() {
    assert_eq!(
        parse_root_uri("file:///Users/marc/My%20Project"),
        Some(p("/Users/marc/My Project"))
    );
}

#[test]
fn utf8_encoded_uri() {
    assert_eq!(
        parse_root_uri("file:///Users/marc/caf%C3%A9"),
        Some(p("/Users/marc/café"))
    );
}

#[test]
fn scheme_is_case_insensitive() {
    assert_eq!(parse_root_uri("FILE:///a/b"), Some(p("/a/b")));
}

#[test]
fn localhost_authority_accepted() {
    assert_eq!(parse_root_uri("file://localhost/a/b"), Some(p("/a/b")));
}

#[test]
fn remote_host_refused() {
    // A root on another machine is not a local path and must not become a
    // permission key.
    assert_eq!(parse_root_uri("file://elsewhere.example/a/b"), None);
}

#[test]
fn non_file_schemes_refused() {
    for uri in [
        "https://example.com/a",
        "git+ssh://host/repo",
        "s3://bucket/key",
        "/not/a/uri",
        "",
    ] {
        assert_eq!(parse_root_uri(uri), None, "{uri}");
    }
}

#[test]
fn trailing_slash_is_normalised() {
    // Otherwise the same root yields two scope keys depending on the client.
    assert_eq!(
        parse_root_uri("file:///home/u/project/"),
        parse_root_uri("file:///home/u/project")
    );
    assert_eq!(parse_root_uri("file:///"), Some(p("/")));
}

#[test]
fn malformed_encoding_refused() {
    for uri in ["file:///a/%zz", "file:///a/%2", "file:///a/%"] {
        assert_eq!(parse_root_uri(uri), None, "{uri}");
    }
}

#[test]
fn encoded_null_byte_refused() {
    assert_eq!(parse_root_uri("file:///a/%00/b"), None);
}

#[test]
fn query_and_fragment_ignored() {
    assert_eq!(parse_root_uri("file:///a/b?x=1"), Some(p("/a/b")));
    assert_eq!(parse_root_uri("file:///a/b#frag"), Some(p("/a/b")));
}

// --- Canonicalisation ---

#[test]
fn canonicalisation_resolves_symlinks() {
    // On macOS /tmp is a link to /private/tmp. Without canonicalisation, scope
    // keys do not match from one session to the next.
    let tmp = p("/tmp");
    if tmp.exists() {
        let canon = canonicalize_for_scope(&tmp);
        assert!(canon.is_absolute());
        assert_eq!(
            canon,
            canonicalize_for_scope(&p("/tmp/../tmp")),
            "two spellings of the same directory must yield the same key"
        );
    }
}

#[test]
fn canonicalising_a_nonexistent_path_does_not_panic() {
    // Degrading the grouping is acceptable; breaking the agent's session is
    // not.
    let absent = p("/this/path/does/not/exist/i/hope");
    assert_eq!(canonicalize_for_scope(&absent), absent);
}
