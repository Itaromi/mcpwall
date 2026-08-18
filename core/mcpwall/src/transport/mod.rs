//! How bytes reach us, and how they leave.
//!
//! MCP defines two transports and they are not symmetrical in what they cost us.
//!
//! - [`stdio`] is a relay inside a process **the client started**, with mcpwall
//!   as the server's command. If mcpwall were missing the server would simply
//!   run: interposing is free, and the availability rule of §4 follows.
//! - [`http`] cannot work that way. The client opens a socket to a URL, so the
//!   only way in is to *be* the URL — a local proxy the configuration points at.
//!   While it is stopped, the servers behind it are unreachable.
//!
//! [`session`] owns the upstream process for stdio; [`observer`] is what binds
//! either transport to the journal.

pub mod http;
pub mod observer;
pub mod session;
pub mod stdio;
