# mcpwall — project specification

Reference document. Updated as decisions are made. Sections marked
**[revised]** have changed since the initial brief; the decision log at the end
of the document says why.

Last updated: 2026-07-27.

---

## 1. What we are building

A local application firewall for coding agents. It sits between MCP clients
(Claude Code, Cursor, Codex) and MCP servers, journals all JSON-RPC traffic, and
blocks dangerous calls according to a local policy.

Reference analogy: **Little Snitch, but for AI agent tool calls.**

The central use case to keep in mind at all times: a user runs their agent in
auto-accept mode; some external content (GitHub issue, web page, email) contains
a prompt injection; the agent reads a local secret and then tries to send it to
a network tool. mcpwall must spot that and interrupt.

## 2. Non-goals (to be refused explicitly if the conversation drifts)

- No multi-user, no OAuth, no RBAC, no Kubernetes deployment. The enterprise
  market is already taken (Lunar MCPX, MCPProxy, ContextForge). We build the
  single-machine, local-first, interactive product.
- No telemetry, no analytics, no user account, no outbound network request other
  than the Sparkle update check.
- No LLM analysis of calls. Everything is deterministic and readable.
- No Windows support in v1.

## 3. Stack

- **Core (shim + daemon)**: Rust. **A single binary**, static, with no runtime
  dependency. Crates: `tokio`, `serde_json`, `rusqlite`, `clap`, `tracing`,
  `memchr`. Rationale: the shim is on the hot path of every tool call, and the
  core must stay portable to Linux for later.
- **UI**: SwiftUI + AppKit, macOS 14+. An `LSUIElement` application (no Dock
  icon).
- **IPC**: Unix socket, newline-delimited JSON, under `~/.mcpwall/`.
- **Storage**: SQLite (`~/.mcpwall/journal.db`), WAL enabled,
  `synchronous = NORMAL`.

One repository, two top-level directories: `core/` (Rust) and `app/` (Swift).

Toolchain pinned in `rust-toolchain.toml`. Edition 2024.

## 4. Architecture **[revised]**

```
MCP client  <--stdio/http-->  mcpwall shim  <--stdio/http-->  upstream MCP server
                                   |
                            Unix socket (verdict)
                                   |
                          mcpwall daemon
                          (policy, taint, journal)
                                   |
                        +----------+----------+
                   menu bar app             SQLite journal
```

- One shim process per MCP server (started by the client, not by us).
- **A single** daemon for the whole machine, started by `mcpwall daemon`.
- There is **no** separate `mcpwalld` binary. One binary with subcommands: a
  single artefact to embed in `Contents/Resources/`, a single symlink, and above
  all no possible version drift between shim and daemon. On startup, the daemon
  rewrites `argv[0]` to `mcpwall-daemon` so it stays readable in Activity
  Monitor.
- The SwiftUI app **does not reimplement** the daemon: it starts and supervises
  `mcpwall daemon` as a child process. One source of truth for the policy and
  the taint state, and Linux portability stays intact.
- The shim is deliberately dumb: parse, relay, ask for a verdict, apply it. All
  the logic lives in the daemon.

### IPC version handshake

The single binary does not guarantee that the running process is the one the
config points at: a shim started by a client left open from before an update is
an old binary facing a fresh daemon.

First message on the socket:

```json
{"mcpwall_ipc": 1, "build": "<git sha>"}
```

Incompatibility → the shim goes **fail-open** and writes a visible warning.

### Availability rule (critical)

If the daemon is unreachable (app closed, crash), the shim **lets traffic
through** and writes to a catch-up log file. A `fail_closed: true` mode exists in
configuration but is not the default. Reason: if closing the app breaks every one
of the user's MCP servers, the product is uninstalled within the hour.

Allowed passthrough latency budget: **< 5 ms p99**. To be measured, not assumed.

### The journal: two paths **[revised]**

Not all events are worth the same.

- **volume** — allowed calls. Bounded channel (4096 to start with, to be
  measured), dropped on saturation, loss counter exposed.
- **decisions** — `deny`, `ask`, description drift, taint alert. Rare by nature.
  **Guaranteed write**, even at the cost of briefly blocking the relay. An audit
  tool that loses the very event justifying its existence has no reason to exist.

Pressure is reduced at the source rather than managed at saturation: WAL,
`synchronous = NORMAL` (not `FULL`), and batching in the writer task by
transactions of N entries or 200 ms, whichever comes first. Drops must stay
theoretical; the counter is a bug signal, not normal behaviour.

The counter is visible: `mcpwall log --stats` in M0, a badge in the UI in M2.
"47 entries lost today" is information the user is entitled to have.

## 5. Protocol **[revised]**

MCP carries JSON-RPC 2.0. Current spec revision: **`2025-11-25`**.

**JSON-RPC batching was removed** as of revision `2025-06-18` (breaking change
no. 1, PR #416). One frame = one message. A frame starting with `[` is a
violation to journal, not a case to support.

Two transports to handle:

- **stdio**: `\n`-delimited JSON on the child process's stdin/stdout. The shim
  forks the upstream server and relays. The upstream's `stderr` is relayed
  as-is. The spec mandates UTF-8 and forbids embedded newlines; real servers
  sometimes violate both, and the splitter must resynchronise without crashing.
- **Streamable HTTP**: POST + SSE response. To be implemented in M3 only.

### Byte passthrough

We **never** re-emit reformatted JSON. Two reasons: it would break any upstream
sensitive to exact bytes, and over HTTP it would invalidate `Content-Length`. The
relay copies the original bytes; a copy of the frame goes to the journal.

### Two sets, not one

The intercepted set is split, and the separation is structural so that a future
contributor cannot undo it by accident.

| Set | Methods | Handling |
| --- | --- | --- |
| **DECIDE** | `tools/call`, `resources/read`, `sampling/createMessage`, `elicitation/create` | full policy evaluation, allow/deny/ask verdict |
| **OBSERVE** | `initialize`, `notifications/initialized`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`, `prompts/get`, `roots/list`, `notifications/roots/list_changed` | enriched journalling, **never blockable** |
| passthrough | everything else | immediate relay, brief journalling |

**`initialize` is never submitted to the decision point.** Blocking it protects
nothing and breaks the whole session. A test (`initialize_is_never_decidable`)
breaks CI if anyone moves it into DECIDE.

`tools/list` is additionally subject to SHA-256 hashing of the descriptions, for
rug-pull detection (M3).

### Identifying the method

A cheap scan over the first `METHOD_SCAN_WINDOW` (200) bytes, **with an explicit
fallback** to a full pass. An exhausted window can never produce "no method": a
long textual `id`, or a serialiser placing `params` before `method`, is enough to
push the key out of the window, and that is ordinary traffic.

The scan is not a substring search but a state machine tracking brace depth:
`method` is only taken as a key of the **root object**. Without that,
`{"params":{"method":"x"},"method":"tools/call"}` would extract `x`.

Escapes are traversed correctly. A scan that bails on the first `\` classifies
the frame as `Unparsable`, hence OBSERVE, hence outside the decision point — a
`tools/call` whose `id` contains `\"` would then bypass the entire policy.

Frame not understood → OBSERVE. Never DECIDE, never silently passthrough.

### What we capture at `initialize`

On the **client request** side: the requested `protocolVersion`,
`clientInfo.name` and `.version`, the presence of `capabilities.roots` and its
`listChanged`.

On the **server response** side: `serverInfo.name` and `.version`, the keys of
`capabilities`, and above all `protocolVersion` — **it is the server's response
that carries the negotiated version**, not the client's request. That is the
field we store.

⚠️ **`initialize` contains no path and no cwd.** See §6bis.

### Points to investigate before M1

- **`elicitation` has two sub-capabilities**, `form` and `url`. The `url` one —
  making the user open a URL — is a far more direct phishing vector than the
  form. The distinction is made on the contents of `params`, so in the policy
  engine, not in the method classification.
- **The `tasks` capability** (new in `2025-11-25`): augmented requests including
  `tools/call`, `sampling/createMessage`, `elicitation/create`. If a `tools/call`
  can be deferred into a task, the result does not come back through the flow
  assumed here. To be read before writing the policy engine.

### The shape of a block

Never close the connection, never return a JSON-RPC protocol error. Return a
valid `result` with `isError: true` and text content of the form:

```
blocked by mcpwall: tainted local data in outbound argument (rule: taint_exfil)
```

The agent must read it as an ordinary tool failure, adapt, and carry on.

## 6. Policy engine

File `~/.mcpwall/policy.yaml`, hot-reloaded.

```yaml
default: allow          # allow | ask | deny
fail_closed: false
ask_timeout_seconds: 60 # expiry -> deny

rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env", "~/.ssh/**", "~/.aws/**", "**/id_rsa"]
    action: ask
    severity: high

  - id: outside_project_write
    when:
      tool_matches: ["*write*", "*edit*", "*delete*"]
      path_outside_cwd: true
    action: ask

  - id: taint_exfil
    when:
      arg_contains_tainted: true
      tool_is_outbound: true
    action: deny
    severity: critical

  - id: secret_pattern
    when:
      arg_matches_secret: true   # AWS keys, ghp_, sk-, BEGIN PRIVATE KEY
    action: ask

  - id: tool_description_changed
    when: { tool_description_drift: true }
    action: ask

overrides:                 # written by the UI, not by a human
  - scope: project:/Users/marc/myrepo
    tool: postgres.query
    action: allow
    until: session         # once | session | forever
```

Verdicts: `allow`, `deny`, `ask`. Scopes: `once`, `session`, `forever`.

## 6bis. Scope provenance **[new]**

Per-project scoping is not a display convenience, it is a security control: if
the scope is wrong, an "always allow for this project" leaks into another
project.

`initialize` does not carry the cwd. Two candidate sources fail, but not on the
same cases — hence a precedence chain.

| Rank | Source | Why / limitation |
| --- | --- | --- |
| 1 | `--project <path>` injected by `mcpwall init` | At the moment `init` rewrites `~/myrepo/.mcp.json`, it knows which project this is. Deterministic, protocol-independent, identical across clients. Passed as an **argument**, not an environment variable: args are preserved verbatim, env is sometimes filtered. |
| 2 | `roots` observed passively | Semantically correct, but an optional capability and a server→client request: the shim is not given it, it happens to see it, and only if an upstream server thinks to ask. |
| 3 | inherited cwd, **canonicalised** | Correct from Claude Code, unrelated to any project from Claude Desktop. Canonicalisation is mandatory (`/tmp` → `/private/tmp` on macOS), otherwise the keys do not match from one session to the next. |
| 4 | `unknown` | An explicit sentinel. We never guess. |

The case that forces this structure: a server configured globally in
`~/.claude.json` is used from ten different projects. `init` cannot write a
`--project` there; that server will drop to rank 2 or 3.

**Consequences, all mandatory:**

- The **scope source is stored** with every journal entry and every override.
- **`forever` is only offered by the UI when the provenance is rank 1 or 2.**
  Under `cwd` or `unknown`, only `once` and `session` are offered.
- `roots` is a **set**, not a path: sort, deduplicate, and key on the complete
  set — a monorepo may legitimately expose several.
- `notifications/roots/list_changed` **replaces** the set, it does not merge into
  it.
- The scope may **rise** in trustworthiness during a session. Each journal entry
  freezes the provenance of the moment; we do not rewrite the past.
- **Provenance does not go into the scope key.** A session that rises from `cwd`
  to `roots` on the same path lands on the same overrides instead of creating an
  invisible parallel set. Provenance controls the writing of a permission, not
  the reading of it.
- A root whose URI is not understood (non-`file` scheme, remote host, malformed
  encoding) is **ignored** — the chain drops down a link. A root we do not
  understand never becomes a permission key.

### Taint tracking

This is the differentiating feature, not to be cut down.

1. Every response to a local read (`resources/read`, a tool whose name matches
   `*read*`/`*file*`/`*exec*`) is split into shingles (word n-grams, n=8),
   hashed, and stored in memory with a 10-minute TTL along with their origin
   (path, timestamp).
2. Before any call to a tool considered outbound (configurable list: names
   matching `*post*`, `*send*`, `*create*`, `*fetch*`, `*http*`, or a server
   declared `outbound: true`), we hash the arguments and look for an overlap.
3. Overlap above a threshold → `taint_exfil` rule.

v1 may be approximate. A false negative is acceptable, a noisy false positive is
not: set the threshold high.

## 7. The blind spot to cover

An MCP proxy only sees MCP traffic. Claude Code's built-in tools (`Read`, `Edit`,
`Bash`, `WebFetch`) do **not** go through MCP — and they are most of the attack
surface. A Claude Code `PreToolUse` hook must be wired to the same daemon, with
the same policy and the same journal.

**Check the current Claude Code hooks documentation before implementing**: the
stdin input schema and the output permission-decision format change.

Codex has no clean equivalent (its security model goes through the sandbox): we
cover MCP only, and we write that down in the README in black and white. Being
honest about coverage is a credibility argument, not a weakness.

## 8. Onboarding — this is where the product is won or lost

The `mcpwall init` command (and its equivalent in the UI on first launch):

1. Discovers the existing configurations: `~/.claude.json`, the `.mcp.json` of
   the current project and of recent projects, `~/.codex/config.toml`,
   `~/.cursor/mcp.json`.
2. Backs up each file as `.bak.<timestamp>`.
3. Rewrites each server entry to wrap the original command in the shim, keeping
   `env`, `args` and everything else identical, and injecting `--project` when
   the rewritten file belongs to an identifiable project (§6bis rank 1).
4. Installs the Claude Code hook.
5. Shows a diff before writing anything.

`mcpwall restore` puts everything back from the backups, with one command.

The binary is embedded in the app's `Contents/Resources/`, and on first launch
the app creates a stable symlink at `~/.mcpwall/bin/mcpwall`. Configurations
point at that link, never at the bundle path — otherwise moving the app breaks
everything.

**Success criterion: zero terminal required.**

## 9. macOS UI

- `NSStatusItem` with an SF Symbol as a template image (automatic light/dark
  inversion). Grey at rest, a numbered badge when there have been blocks today.
- Left click: an `NSPopover` with counters (calls / blocked / active servers,
  plus the lost journal entry counter), the last 10 entries, "Block everything"
  and "Journal" buttons, settings.
  "Journal" navigates **inside the popover** to a compact two-line-per-entry
  list. Checking what just went past is the common case, and sending the user
  to a 900-point window for it is friction. The window stays one click away
  from that page, for what 320 points cannot do: filtering and export.
  A click anywhere else closes the popover, including in another application.
- Right click (and control-click): a plain `NSMenu` — Journal, Policy, reinstall,
  and **Quit mcpwall with its ⌘Q**. A menu, not a second popover: it is what
  macOS users expect from a status item, it is keyboard navigable, and quitting
  is the one thing someone must never have to hunt for.
- **Decision prompt**: definitely not an `NSPopover` (it closes on focus loss and
  does not show above a full-screen terminal). Use an `NSPanel` with
  `level = .statusBar`, a `collectionBehavior` including `.canJoinAllSpaces` and
  `.fullScreenAuxiliary`, and `becomesKeyOnlyIfNeeded = true`.
  The panel displays: tool, server, argument excerpt, the rule that fired, the
  taint origin where applicable, the project **and its provenance**, and three
  buttons (Block / Allow once / Always allow).
  The "Always allow" button is hidden when the scope provenance is rank 3 or 4.
- Journal window: a timeline filterable by project, server, verdict; expandable
  JSON detail; JSONL export.

Unobtrusive by default: at rest, mcpwall asks nothing. Only high-confidence rules
raise an `ask`. Alert fatigue is what kills this kind of tool.

## 10. Milestones

Work milestone by milestone. Do not start the next one until the previous one
runs on a real machine.

**M0 — observation only** *(done)*
`mcpwall wrap -- <command>` over stdio, transparent relay, SQLite journal,
`mcpwall log --tail`, `mcpwall log --stats`. No blocking, no UI.
Criterion: wrap a real filesystem server in Claude Code, run a complete session
without breaking anything, and find every call again in the journal.

- [x] `frame.rs` — splitting, 32 MB ceiling, resynchronisation
- [x] `mcp.rs` — method scan, OBSERVE/DECIDE, decision point, `initialize` capture
- [x] `scope.rs` — provenance chain, scope key, root URIs
- [x] `wrap.rs` — relay pumps, return path for blocks
- [x] `session.rs` — upstream fork, signals, EOF, exit code
- [x] SQLite journal, two paths
- [x] CLI `wrap` / `log --tail` / `log --stats`
- [x] fake MCP servers + integration tests against real processes
- [x] latency benchmark in CI

Latency measured in `--release`: **p99 3.4 µs** on a short frame, 6.1 µs when the
method is pushed out of the window, 70 µs on a 100 KB frame. Budget 5 ms.

**M1 — daemon + policy** *(done)*
Daemon with a Unix socket and a version handshake, `policy.yaml`, allow/deny/ask
verdicts (`ask` automatically answers `deny` while waiting for the UI), clean
blocking via `isError`, `mcpwall init` and `restore`.
Criterion: a rule blocks a `.env` read without breaking the agent's session.

- [x] `ipc.rs` — protocol + version handshake
- [x] `daemon.rs` — Unix socket, one per machine, socket at 0600
- [x] `client.rs` — `DecisionPoint` over the socket, fail-open by default
- [x] `policy.rs` — `policy.yaml`, hot reload, secret detection
- [x] `setup.rs` — `init` with diff and backups, `restore`

**M2 — macOS app** *(done, except signing)*
Menu bar, popover, decision panel, journal window, graphical onboarding,
supervision of `mcpwall daemon`, symlink, signed and notarised `.dmg`, Sparkle.
Criterion: a complete install from a `.dmg` on a clean machine, with no terminal.

- [x] confirmation flow in the core: the daemon can ask, not only refuse
- [x] `NSStatusItem` + popover, numbered badge only when there have been blocks
- [x] decision panel as an `NSPanel` (see §9), automatic withdrawal on expiry
- [x] filterable Journal window, JSONL export
- [x] graphical onboarding with a diff before writing and one-click restore
- [x] supervision of `mcpwall daemon` as a child process, with exponential backoff
- [x] symlink remade on every launch
- [x] bundle and `.dmg` assembled without Xcode (`scripts/build-app.sh`)
- [ ] **signing and notarisation** — script written (`scripts/sign-app.sh`) but
      **never run**: no "Developer ID" identity available. To be treated as
      untested until somebody has run it.
- [ ] **Sparkle** — not integrated. `SUFeedURL` is left empty in the
      `Info.plist`: a dead URL would raise an update error on every launch. To be
      wired up once a feed exists, with an EdDSA key pair.

The exit criterion is therefore **not met**: without notarisation, Gatekeeper
forces a right click → Open, which is exactly the friction §8 forbids.

**M3 — depth**

- [x] taint tracking — fingerprints, store, `taint_exfil` rule, origin named in
      the refusal, and the complete attack of §11 asserted end to end
- [x] Claude Code hook — `PreToolUse` decides, `PostToolUse` feeds the taint
      store, `init` installs both. Verified against the current documented
      contract (`hookSpecificOutput`, nested matcher groups), not from memory
- [ ] tool description drift detection
- [ ] streamable HTTP transport
- [x] JSONL export (delivered in M2 with the journal window)

## 11. Tests

- Fake MCP servers in Rust for the integration tests: a normal one, a slow one,
  one that returns malformed JSON, one that mutates its tool descriptions between
  two `tools/list` calls.
- Fuzzing tests on the frame parser: messages cut in half, unicode, multi-megabyte
  payloads. The `frame`, `mcp` and `scope` modules are I/O-free precisely so they
  stay fuzzable without a runtime.
- Latency benchmark in CI, with a failure threshold.
- An integration scenario reproducing the complete attack: reading a `.env` then
  attempting to send it via an outbound tool, with an assertion on the block.

## 12. Conventions

- Rust: `#![forbid(unsafe_code)]` in the core. `clippy -D warnings` in CI.
- No `unwrap()` on the shim's path. A shim panic = a broken agent session.
- Structured logging via `tracing`. The journal must never contain the value of a
  detected secret: we store the kind and a truncated prefix.
- MIT licence. No GPL — it slows enterprise adoption, which is the natural exit
  trajectory.
- Any label persisted to the database (`ScopeSource::as_str`, rule identifiers) is
  a contract: changing it requires a migration.
- README: the first three lines must answer "my client already asks me for
  permission, why would I need this?". Answer: the client's permissions are at
  the tool level and disappear under auto-accept; mcpwall filters at the level of
  argument contents, keeps an audit trail across sessions, and covers
  already-approved third-party servers once and for all.

## 13. Working instructions

- Before implementing anything touching the MCP spec, Claude Code hooks, or the
  format of client configuration files: check the current documentation online.
  These formats have changed recently and will change again.
- Do not write more than two files without stopping to show and run.
- If an architectural decision has several defensible options, lay them out with
  their costs instead of choosing silently.

---

## Decision log

**2026-07-27 — Single binary.** `mcpwalld` dropped in favour of `mcpwall
daemon`. Reason: shim/daemon version drift is a real class of bug, and the single
symlink simplifies onboarding. Offset by an IPC version handshake, because a
client left open can run an old shim against a fresh daemon.

**2026-07-27 — The app supervises the daemon, it does not reimplement it.** One
source of truth for policy and taint; Linux portability stays intact.

**2026-07-27 — Two-path journal.** `deny`s and alerts are never dropped: that is
the line the user will export into a security ticket.

**2026-07-27 — Byte passthrough, but a decision point present from M0.** Writing
M0 as "I copy and I parse elsewhere" would have made M1 a rewrite.

**2026-07-27 — JSON-RPC batching: confirmed removed** (`2025-06-18`, PR #416).
Assumption checked online, not recalled from memory.

**2026-07-27 — `initialize` does not carry the cwd.** Verified against the
`basic/lifecycle` spec: `params` contains `protocolVersion`, `capabilities`,
`clientInfo`, and `clientInfo` has no path field. The initial brief's per-project
scoping rested on a field that does not exist. Hence the provenance chain of
§6bis.

**2026-07-27 — `forever` conditioned on provenance.** One line of code, an entire
class of silent security bugs avoided.

**2026-07-27 — Provenance does not go into the scope key.** The alternative would
produce the absurd behaviour where the user allows something, a server asks for
`roots/list`, and their authorisation disappears.

**2026-07-27 — OBSERVE and DECIDE separated structurally.** `initialize` in
OBSERVE, locked down by a test. Blocking it protects nothing and kills the whole
session.

**2026-07-27 — Escapes traversed in the method scan.** The first version gave up
on the first `\`; an `id` containing `\"` was then enough to take a `tools/call`
out of the decision point. A one-byte policy bypass.

**2026-07-27 — `Oversize` resynchronises, it does not kill the connection.** The
splitter reports and carries on; deciding whether it is fatal belongs to the
transport layer. It is the same mechanism that absorbs a server violating the
newline rule.

**2026-07-27 — The frame ceiling only applied when there was no delimiter.** An
oversized frame arriving from a single `read()` therefore slipped through: the
effective value of the ceiling depended on how reads were split. Found by an
invariant test replayed across several chunk sizes, not by a case test.

**2026-07-27 — The decision point is fallible.** `DecisionPoint::decide` returns
a `Result`. Without it, a socket client could only report "daemon unreachable" by
lying `Allow` or by panicking. Any `Err` becomes a journalled `Allow`, except
under explicit `fail_closed`.

**2026-07-27 — The daemon client lives on a system thread, not on the executor.**
Holding a frame back requires a synchronous verdict, called from an async pump.
If the socket I/O shared the executor, waiting for the verdict would block the
very task meant to produce it — a guaranteed deadlock on a single-threaded
runtime.

**2026-07-27 — An empty policy is refused.** Since every field has a default, an
empty file deserialised into `default: allow` with no rules at all: a truncated
`policy.yaml` silently disabled the firewall. Discovered because a test sharing a
temporary directory turned flaky.

**2026-07-27 — `init` only injects `--project` where the project is known.**
Under `projects.<dir>` in `~/.claude.json` and in a `.mcp.json`, yes. At the root
of a global file, no: that server is used from ten projects, and inventing a
project for it would lie about the provenance — and so wrongly unlock `forever`.

**2026-07-27 — The daemon computes `forever_allowed` and passes it along.** The
UI does not have to redo the reasoning about provenance, and therefore cannot get
it wrong by redoing it.

**2026-07-27 — IPC protocol raised to version 2.** The confirmation flow changes
the shape of the messages, now tagged by a `type` field. Nothing being published,
nobody suffers for it — and it is the mechanism that will protect later updates.

**2026-07-27 — The UI is a client, not an authority.** The daemon downgrades a
`forever` scope requested on a weak-provenance scope, even if the interface sent
it. A compromised or buggy interface must not be able to grant more than the
provenance permits.

**2026-07-27 — The shim derives its timeout from the one the daemon announces.**
The gravest defect of M2, and invisible for as long as the interface did not
exist: the shim gave up after a 5 s socket timeout while the daemon was still
waiting for the click. And **giving up lets the call through** — so every `ask`
rule decayed into `allow` as soon as the person thought for more than five
seconds. The daemon's `Hello` now carries `ask_timeout_seconds`.

**2026-07-27 — `FileHandle` replaced by system calls on the Swift side.** Its
write blocked forever on a Unix socket: forty bytes that never left, with no
error and no trace. `FileHandle` is designed for files and pipes.

**2026-07-27 — The subscription is written on the handshake path.** Routing it
through the write queue lost it, and the app ran without ever receiving a
prompt — the daemon then refused every `ask`, explaining that no interface was
there.

**2026-07-27 — The popover is sized by SwiftUI, not by a hard-coded
`contentSize`.** `NSHostingController` only publishes a `preferredContentSize`
when given `sizingOptions`. Without it the value stays zero, NSPopover does its
geometry against the 420-point `contentSize` that had been set by hand, and the
bubble ends up anchored for a frame its ~210 points of content never fill —
visibly detached from the menu bar icon. The same fix makes the popover grow
correctly as the prompt list fills up.

**2026-07-27 — The journal opens inside the popover.** Glancing at what just
went past is the common case; the 900-point window was friction for it. The
in-popover list is deliberately not the window's `Table` — six columns do not
fit in 320 points, and a popover you scroll sideways is worse than none. The
window keeps what a narrow column genuinely cannot do: filtering and JSONL
export. Reading is now off the main thread, because spawning `mcpwall log` on it
stuttered the popover's opening animation — precisely when the user is looking.

**2026-07-27 — Dismissing the popover needs a global monitor, and the toggle
needs a guard.** Two separate defects behind one symptom. `.transient` only
reacts to clicks inside our own application; mcpwall is an accessory app, so the
click that should dismiss the bubble almost always lands in another one, where
AppKit never tells the popover. Hence an `NSEvent` global monitor on mouse-down
(mouse events need no accessibility permission, unlike keyboard ones). And
because a transient popover dismisses itself on the mouse *down* that reaches the
status item while the button's action arrives on the mouse *up*, the click meant
to close the bubble found `isShown == false` and reopened it — so an open that
lands within 200 ms of a close is ignored.

**2026-07-27 — The right click is a menu, not a second popover.** For a handful
of one-shot commands, `NSMenu` is what macOS users expect from a status item, it
is keyboard navigable, and it carries the ⌘Q. Control-click routes to the same
place: without it the menu is unreachable for anyone who has not enabled
secondary click. `statusItem.menu` is set and cleared around `performClick`
rather than using `NSMenu.popUp`, because that is what highlights the icon while
the menu is up — leaving it set would make the left click show the menu for ever.

**2026-07-27 — The bundle is assembled by hand, with no Xcode project.** Builds
identically in CI and on a machine that has only the Command Line Tools. The
universal build does require Xcode, however: the script degrades to the native
architecture with a warning, and CI checks that the published binaries really are
universal.
