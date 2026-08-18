# The map

Where things are, and why they are there. [SPEC.md](../SPEC.md) says what the
product must do and records the decisions; this file says where to put your
hands.

If you are reading the code for the first time, follow one tool call from end to
end. That path is the spine of the whole tree.

## Following one tool call

```
        ┌── the client sends ──────────────────────────────────────┐
        │                                                          │
 transport/stdio.rs      the relay: read bytes, never rewrite them
 transport/session.rs    the upstream process, and its death
        │
 protocol/frame.rs       split the stream into frames
 protocol/mcp.rs         which method is this? OBSERVE, DECIDE, or through?
        │
        ├── OBSERVE ──▶ journalled, never blockable. `initialize` lives here.
        │
        └── DECIDE
              │
 ipc/client.rs           hold the frame, ask for a verdict over the socket
              │
 daemon/mod.rs           accept, handshake, route
 daemon/decide.rs        taint? drift? an override already granted? ask the user?
 daemon/policy/          the rules, and what fired
              │
              ▼
        allow ──▶ the frame continues to the upstream
        deny  ──▶ transport/stdio.rs writes a valid result with `isError: true`
```

`transport/observer.rs` sits alongside the whole path, copying what happened
into `journal/`.

## The layers

### `protocol/` — what a frame *is*

**I/O-free, on purpose.** No socket, no file, no clock: time arrives as a
parameter. That is what keeps these modules fuzzable without a runtime
(SPEC §11), and what lets the trickiest logic in the product be tested without
starting anything.

| | |
| --- | --- |
| `frame.rs` | splitting a stream into frames, a 32 MB ceiling, resynchronisation after a server that violates the spec |
| `mcp.rs` | identifying the method, the OBSERVE/DECIDE split, the decision point trait, the shape of a block |
| `scope.rs` | which project a session belongs to — the provenance chain of §6bis |
| `taint.rs` | fingerprinting what a read returned, and recognising it later |
| `drift.rs` | hashing what a tool says about itself, for the rug-pull |

**Nothing here decides.** It classifies, fingerprints and describes.

### `transport/` — how bytes arrive

The two transports are not symmetrical, and the asymmetry is the single most
important thing to understand before touching this directory.

`stdio.rs` is a relay inside a process **the client started**, with mcpwall as
the server's command. If mcpwall were missing the server would simply run:
interposing costs nothing, and the availability rule of §4 follows for free.

`http.rs` cannot work that way. The client opens a socket to a URL, so the only
way in is to *be* the URL — a loopback proxy the configuration points at. While
it is stopped, the servers behind it are unreachable. There is no failing open,
because there is nothing left to fail open to.

`session.rs` owns the upstream process for stdio: fork, signals, EOF, exit code,
and the SIGTERM→SIGKILL escalation that stops thirty orphans accumulating over a
day. `observer.rs` binds either transport to the journal.

### `ipc/` — asking for a verdict

`mod.rs` is the wire: newline-delimited JSON over a Unix socket, with a version
handshake, because a client left open across an update runs an old shim against
a fresh daemon.

`client.rs` is the **shim's client of the daemon** — not an MCP client. It is
where mcpwall can break a session for a reason that is none of the user's
business, so the availability rule applies most literally here. It runs on a
system thread rather than a tokio task, and the reason is in the module doc:
a synchronous verdict called from an async pump would otherwise block the very
task meant to produce it.

### `daemon/` — the authority

One per machine. `mod.rs` accepts connections and routes messages; `decide.rs`
produces verdicts and raises confirmation prompts; `policy/` is the engine.

| | |
| --- | --- |
| `policy/model.rs` | the shape of `policy.yaml`. Deserialisation only |
| `policy/request.rs` | pulling paths and values out of a frame, once, so every rule judges the same extraction |
| `policy/findings.rs` | the detectors — **the one place that sees credentials in the clear** |
| `policy/mod.rs` | the engine: first matching rule, in file order |

### `journal/` — the audit trail

Two paths, and the split is load-bearing. Volume entries take a bounded channel
and are dropped when it is full, because slowing the relay costs more than
losing one line in a thousand allowed calls. Decisions take an unbounded channel
and are never dropped: an audit tool that loses the event justifying its
existence has no reason to exist.

`query.rs` opens read-only connections, deliberately separate from the writer
task: the UI polls them frequently and must never get in the way of a shim's
writes.

### The rest

| | |
| --- | --- |
| `hook.rs` | Claude Code's built-in tools, which never reach an MCP server. The blind spot of §7 |
| `setup/` | `init` and `restore` — the diff before the write, and the backup behind it |
| `cli/` | one module per subcommand, each owning its own arguments |
| `main.rs` | fourteen lines. Parse and dispatch |

## Tests

`core/mcpwall/tests/`, one file per concern. The ones that start real processes
are named for what they exercise, not for when they were written.

| | |
| --- | --- |
| `frame · mcp · scope · taint · drift · policy` | the pure layers, no subprocess |
| `relay.rs` | what crosses the shim, and what it must never change |
| `processes.rs` | orphans, deadlocks, an upstream that dies mid-frame |
| `blocking.rs` | a rule blocks without breaking the session |
| `ask.rs` | the confirmation flow, expiry, late answers |
| `exfil.rs` | **the attack the product exists for**, end to end |
| `hook.rs` | the same attack through built-ins alone, with no MCP call |
| `drift.rs` | the rug-pull, against a server that changes its story |
| `http.rs` | the proxy: byte passthrough, SSE, loopback enforcement |
| `setup.rs` | onboarding — what is preserved as much as what changes |
| `bench.rs` | passthrough latency, with a failing threshold |

The fake servers live in `core/mcpwall/testservers/` and are `[[bin]]` targets
of the `mcpwall` package, reached through `CARGO_BIN_EXE_<name>`. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for why that matters.

## Where the invariants live

| Invariant | Enforced in |
| --- | --- |
| `initialize` is never decidable | `protocol/mcp.rs`, guarded by `initialize_is_never_decidable` |
| No daemon means traffic passes | `ipc/client.rs`, `transport/stdio.rs` |
| Bytes are relayed, never reformatted | `transport/stdio.rs`, `transport/http.rs` |
| A secret's value never reaches the journal | `daemon/policy/findings.rs` |
| Fingerprints, never content, cross the socket | `protocol/taint.rs`, `ipc/mod.rs` |
| Persisted labels are contracts | `protocol/scope.rs`, `protocol/drift.rs`, `journal/schema.rs` |
| No `unsafe` | `lib.rs`, `#![forbid(unsafe_code)]` |

## The app

`app/Sources/mcpwall/` — SwiftUI and AppKit, macOS 14+, no Dock icon.

It **does not reimplement the daemon**. It supervises `mcpwall daemon` and
`mcpwall proxy` as child processes, with exponential backoff, and talks to the
daemon over the same socket everything else uses. One source of truth for the
policy and the taint state, and the core stays portable beyond macOS.
