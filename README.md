# mcpwall

**"My client already asks me for permission, why would I need this?"**
Because your client's permissions are at the tool level and disappear under
auto-accept. mcpwall filters at the level of **argument contents**, keeps an
**audit trail across sessions**, and covers **third-party servers you already
approved**, once and for all.

A local application firewall for coding agents. Little Snitch, but for AI agent
tool calls.

---

## The problem

You run your agent in auto-accept. A GitHub issue, a web page or an email
contains a prompt injection. The agent reads a local secret, then tries to send
it to a network tool. All your client sees is a sequence of already-authorised
tool calls.

mcpwall sits between MCP clients and MCP servers, journals all JSON-RPC traffic,
and blocks according to a local policy.

## Coverage — what mcpwall sees, and what it does not

Being honest about coverage is a credibility argument.

| | Covered |
| --- | --- |
| MCP servers over stdio | yes |
| MCP servers over streamable HTTP | planned (M3) |
| Claude Code built-in tools (`Read`, `Edit`, `Bash`, `WebFetch`) | yes — `PreToolUse` / `PostToolUse` hooks |
| Codex built-in tools | **no** — its security model goes through the sandbox |
| Cursor | MCP traffic only |

An MCP proxy only sees MCP traffic. For Claude Code, the built-in tools are most
of the attack surface: covering them is the hook's job, not the proxy's.
`mcpwall init` installs it, and it answers to the same daemon, the same
`policy.yaml` and the same journal — so `Bash` reading your `.env` and then
`WebFetch` sending it out is blocked without an MCP server being involved at any
point.

## Status

Milestones M0, M1 and M2 are done: stdio relay, journal, policy daemon,
`init`/`restore`, and the macOS application — menu bar, decision panel, journal
window, graphical install.

**There is no distributable build yet.** The `.dmg` is neither signed nor
notarised, so Gatekeeper forces a right click → Open. Sparkle is not wired up.
See [SPEC.md](SPEC.md) §10 for what remains, and for the architecture and the
decisions taken with their reasons.

## Build and try it

```sh
# The application, with the core embedded
./scripts/build-app.sh
open build/mcpwall.app
```

The app starts the daemon, creates the symlink to the binary, and offers to
install itself into your MCP clients on first launch — showing the diff of what
will change, before writing anything.

From the command line alone, with no interface:

```sh
cargo build --release

# 1. the daemon, which writes a default policy on first launch
./target/release/mcpwall daemon &

# 2. see what init would do to your configurations — nothing is written without --apply
./target/release/mcpwall init

# 3. apply it, then restart your MCP clients
./target/release/mcpwall init --apply

# 4. watch the traffic go by
./target/release/mcpwall log --follow
./target/release/mcpwall log --stats
```

`mcpwall restore` puts every configuration back from the backups.

The policy lives in `~/.mcpwall/policy.yaml` and hot-reloads. By default it lets
everything through except access to secret paths and credentials spotted in
arguments.

Without the application, an `ask` rule **blocks** instead of asking: there is
nobody there to confirm. The message returned to the agent says so explicitly.

## Principles

- **Local-first.** No telemetry, no account, no outbound request other than the
  update check.
- **Deterministic.** No LLM analysis of calls. The policy is a readable file.
- **Available by default.** If the daemon is unreachable, traffic goes through.
  Breaking every one of the user's MCP servers because an app was closed is a
  defect, not a security posture.
- **Unobtrusive.** Only high-confidence rules interrupt. Alert fatigue is what
  kills this kind of tool.

## Development

```sh
cargo test                                    # 216 tests, fake servers included
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --release --test bench -- --nocapture   # latency, 5 ms p99 threshold

cd app && swift build                         # the application
```

The app's universal build requires Xcode; with the Command Line Tools alone,
`scripts/build-app.sh` degrades to the native architecture and warns you. CI
checks that the published binaries really are universal.

## Licence

MIT.
