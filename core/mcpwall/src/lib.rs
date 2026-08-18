#![forbid(unsafe_code)]

//! mcpwall — a local application firewall for coding agents.
//!
//! The layers, in the order a tool call meets them:
//!
//! 1. [`transport`] — bytes arrive over stdio or streamable HTTP.
//! 2. [`protocol`] — the frame is split, its method identified, its disposition
//!    decided: OBSERVE, DECIDE, or straight through. I/O-free, so fuzzable.
//! 3. [`ipc`] — a DECIDE frame is held while a verdict is asked for, over a Unix
//!    socket.
//! 4. [`daemon`] — the single authority on the machine. Policy, taint store,
//!    description drift, confirmation prompts.
//! 5. [`journal`] — what happened, on disk, across sessions.
//!
//! [`hook`] covers the same ground for Claude Code's built-in tools, which never
//! reach an MCP server at all. [`setup`] is `init` and `restore`.
//!
//! See `docs/ARCHITECTURE.md` for the map, and `SPEC.md` for why.

pub mod daemon;
pub mod hook;
pub mod ipc;
pub mod journal;
pub mod protocol;
pub mod setup;
pub mod transport;
