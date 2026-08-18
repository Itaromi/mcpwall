# Contributing to mcpwall

We welcome contributions from the community and look forward to working with you
to improve this project.

Before anything else, one sentence that governs every decision in this codebase:

> **mcpwall sits on the hot path of somebody's working agent.**

A bug here does not produce a stack trace in a log nobody reads. It produces an
agent that stops working mid-task, or — worse, because it is silent — a firewall
that has stopped filtering while still looking installed. Both cost more than
the feature that caused them was worth.

Most of what follows is a consequence of that sentence.

## How to contribute

**1. Fork the repository.** Start by forking
[Itaromi/mcpwall](https://github.com/Itaromi/mcpwall) to your own GitHub
account.

**2. Clone your fork** (replace `<YOUR_USERNAME>` with your GitHub username):

```sh
git clone https://github.com/<YOUR_USERNAME>/mcpwall.git
cd mcpwall
```

**3. Create a branch:**

```sh
git checkout -b feat/your-feature-name
```

or

```sh
git checkout -b fix/your-bug-fix-name
```

**4. Make your changes.** If they touch the MCP specification, Claude Code
hooks, or the format of client configuration files, read
[Check the documentation first](#check-the-documentation-before-you-write)
before you start — those formats change, and writing them from memory produces
something that looks right and silently does nothing.

**5. Test your changes:**

```sh
cargo test                                          # 228 tests, fake servers included
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --release --test bench -- --nocapture     # latency, 5 ms p99 threshold

cd app && swift build                               # the macOS application
```

The Rust toolchain is pinned in `rust-toolchain.toml`; nothing else is needed.
The core has no system dependency, and the app builds with the Command Line
Tools alone — a *universal* app build needs Xcode, and the script degrades to
the native architecture with a warning.

A green run on macOS is not evidence on its own. See
[Platform traps](#platform-traps).

**6. Commit your changes.** Write a message that explains *why* — this
repository's history is documentation, and the format matters here more than it
does in most projects. See [Commit messages](#commit-messages).

```sh
git add .
git commit
```

**7. Push your branch:**

```sh
git push origin feat/your-feature-name
```

**8. Open a pull request** against `main` on
[Itaromi/mcpwall](https://github.com/Itaromi/mcpwall).

## Pull request guidelines

- **One feature or fix per pull request.** If a change needs another change
  first, stack them: branch B targets branch A, not `main`. Each diff then
  stands on its own and can be reviewed without the others.
- **Never delete a base branch while a PR still targets it.** GitHub closes the
  dependent PR, and getting it back means restoring the branch by hand.
- **Clear title and description.** Say what was wrong and why the fix has the
  shape it does.
- **Include tests.** Real ones — see [Tests](#tests) for what that means here.
- **CI must be green on macOS *and* Linux.** `clippy -D warnings` and
  `cargo fmt --check` are part of it. The product is macOS, but the core is
  meant to stay portable.
- **Keep your pull request up to date** if changes are requested.
- **If you found something out of scope on the way, say so in the PR** rather
  than fixing it quietly. Half the defects worth reporting in this project were
  found while looking for something else.
- **Report coverage honestly.** If your change leaves a case unhandled, name it —
  in the README table, in `init`'s output, wherever a user would otherwise
  conclude from an absence that they are protected. A user who believes a server
  is behind the firewall when it is not is worse off than a user with no
  firewall at all.

## Issues

- **Bug reports.** Open an issue with a clear description and steps to
  reproduce. For anything that got past mcpwall, the three useful facts are:
  **the call that went through**, **the policy in force**, and **which transport
  it used** (stdio, HTTP, or the Claude Code hook).
- **Feature requests.** Describe the feature and what it would let someone do.
  Check [SPEC.md §2](SPEC.md) first — some things are non-goals on purpose
  (multi-user, OAuth, RBAC, LLM analysis of calls, Windows in v1), and saying no
  to those is a design decision rather than a backlog item.
- **Priority.** Bug fixes take priority over feature requests. Anything that
  makes mcpwall *silently stop filtering* takes priority over everything.

## Finding your way around

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the map: where each layer lives,
what a tool call meets on its way through, and which file enforces which
invariant. Read it before your first change and you will not have to guess.

## Start by reading SPEC.md

[SPEC.md](SPEC.md) is the reference document, not an artefact of the past. Its
**decision log** records why each choice was made, including the choices that
were wrong the first time and what the failure looked like.

If you are about to ask "why on earth is it done that way", the answer is
probably there — and if it is not, that is a gap worth reporting on its own.

## Invariants you must not break

These are not style preferences. Each one is a class of bug that has already
happened or would be invisible if it did, and most are guarded by a test that
will fail CI.

**`initialize` is never submitted to the decision point.** Blocking it protects
nothing and kills the entire session. `initialize_is_never_decidable` in
`tests/mcp.rs` breaks the build if anyone moves it out of OBSERVE.

**No `unwrap()` on the shim's path.** A panic in the shim is a broken agent
session, and the user will blame their MCP server, not us.

**`#![forbid(unsafe_code)]` in the core.** It is at the top of `lib.rs`. Leave it
there.

**If the daemon is unreachable, traffic goes through.** This is the availability
rule of SPEC §4 and it is a product decision, not a security oversight: if
closing the app breaks every one of the user's MCP servers, mcpwall is
uninstalled within the hour. A `fail_closed` mode exists in configuration and is
not the default.

*The one exception is the HTTP proxy*, and it is unavoidable rather than chosen:
the client has been pointed at its URL, so there is nothing left to fail open to.
That is stated in the README and in `init`'s own output rather than left to be
discovered.

**A false positive costs more than a false negative.** A rule that interrupts
wrongly teaches the user to click "allow" without reading, which negates the
entire product. When adding a detector or a rule, set the threshold high and say
in a comment what you traded away.

**Never journal the value of a secret.** Store the kind and a truncated prefix.
The taint store holds 64-bit fingerprints and nothing else — it can say *this
went out*, and it must never be able to give back *what*.

**Any label persisted to the database is a contract.** `ScopeSource::as_str`,
rule identifiers, the tool-description digest. Changing what goes into one
changes every stored row at once, which the user experiences as every tool on
their machine drifting on the same day. That needs a migration, not an edit.

## Check the documentation before you write

SPEC §13, and it has already paid for itself twice.

Before implementing anything that touches **the MCP specification**, **Claude
Code hooks**, or **the format of client configuration files**: read the current
documentation online. These formats change. The hook contract changed shape
(`hookSpecificOutput`, nested matcher groups) between the spec being written and
the hook being built, and writing it from memory would have produced something
that looked right and silently did nothing.

## Tests

The suite starts **real processes** on purpose. The defects it targets —
orphans, deadlocks under back-pressure, badly closed descriptors, lost exit
codes, a user who takes eight seconds to answer a prompt — are precisely the
ones no mocked test will ever see.

The fake MCP servers live in `core/mcpwall/testservers/` and are declared as
`[[bin]]` targets of the `mcpwall` package:

| Server | What it is for |
| --- | --- |
| `normal` | behaves correctly |
| `silent` | never writes anything |
| `huge` | answers with 8 MB — back-pressure must not deadlock |
| `malformed` | blank lines, invalid JSON, CRLF, an unterminated final frame |
| `dies_midmessage` | disappears mid-frame |
| `ignores_sigterm` | must be escalated to SIGKILL, or it becomes an orphan |
| `leaky` | hands back the file it is asked to read, so taint has something to catch |
| `rugpull` | changes its tool descriptions between two `tools/list` calls |
| `httpmcp` | a streamable HTTP server, written on raw TCP |

**Adding one:** put the source in `testservers/`, add a `[[bin]]` entry in
`core/mcpwall/Cargo.toml`, and reach it from a test with
`env!("CARGO_BIN_EXE_<name>")` — never by deriving a path next to the shim. That
derivation is exactly how fifteen tests silently stopped running once, while the
suites that need no subprocess stayed green and hid it.

`httpmcp` is deliberately written on raw TCP rather than on the proxy's own HTTP
stack. The tests check exact bytes, and a fake server sharing the library would
agree with the proxy about all of them — including where both are wrong.

**A test that cannot fail is not a test.** When you add one for a rule, make sure
no *other* rule could produce the same verdict. The end-to-end taint test runs
against a policy containing the taint rule and nothing else, precisely so that
it cannot pass by way of path or pattern matching, and would fail if taint
tracking were deleted outright.

The modules `frame`, `mcp`, `scope`, `taint` and `drift` are **I/O-free on
purpose**: they stay fuzzable without a runtime, and time is a parameter rather
than a clock read. Keep them that way.

## Platform traps

A green `cargo test` on macOS is not evidence.

- **Socket teardown is reported differently.** After the peer closes, macOS
  gives a clean EOF; Linux answers a write to a closed socket with an RST, so
  the next read fails with `ECONNRESET`. Assert the property — *no verdict came
  back* — never one particular way the connection ended.
- **`sockaddr_un.sun_path` is 104 bytes on macOS**, 108 on Linux. CI's temporary
  directory is long enough to blow past it; tests use short `/tmp` paths for a
  reason.
- **Load changes what a test proves.** `a_late_answer_is_ignored_without_damage`
  waited for a prompt to expire with `let _ = ui.recv()`, which swallowed the
  case where the expiry had not happened yet. The test then answered a *live*
  prompt, the daemon rightly honoured it, and the assertion failed three lines
  later for a reason nowhere near its cause — only ever under parallel load. If
  a test depends on something having already happened, **assert that it did**
  rather than reading past it.

## Commit messages

This repository's history is documentation. A reader six months from now should
be able to understand a change from its message alone, without the diff.

Say **what was wrong**, **why it mattered**, and **why the fix has the shape it
does**. Where a choice had defensible alternatives, name them and say what you
traded. `git log` is where the reasoning that did not fit in a comment lives.

Not this:

```
fix taint bug
```

But this:

```
Taint: name the origin in the refusal

The daemon matched an outbound argument against the taint store, recovered
the label of the read it came from — and then dropped it. The panel showed
"tainted local data" and nothing else.

That is the difference between a refusal a user can act on and one they can
only dismiss: told the payload was read from ~/project/.env, they know
whether they are looking at an injection or at their own deliberate call.
```

Length is not the point; a one-line change can deserve one line. Explaining
*why* is the point.

## Translations

The documentation is available in English and French:
[README.md](README.md) and [README.fr.md](README.fr.md).

To contribute another language:

1. **Copy `README.md`** to `README.<code>.md`, using the ISO 639-1 code
   (`README.de.md`, `README.es.md`, …).
2. **Translate it rather than transliterating it.** A word-for-word calque of
   English prose reads like a machine, and the point of this document is to be
   read by someone deciding whether to trust the tool.
3. **Add your language to the header line** of every existing README, so the
   versions all point at each other.
4. **Leave the code, the log output and the policy examples in English.** They
   are what the program actually prints; translating them would send a reader
   looking for a string that does not exist.
5. Open a pull request following the guidelines above.

Incomplete translations will not be merged: a half-translated page is worse
than one honest link to the English original.

## Reporting a security issue

If you have found a way past mcpwall, please open an issue. This is a local,
single-user tool with no deployed service behind it, so there is no embargo to
respect, and a public description helps whoever reads the rules next.

## Licence

MIT. By contributing, you agree that your contribution is licensed under it.

## Contributors

<a href="https://github.com/Itaromi/mcpwall/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Itaromi/mcpwall" />
</a>
