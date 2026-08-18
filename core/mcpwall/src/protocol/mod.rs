//! What an MCP frame *is*, and what it means.
//!
//! Everything in here is **I/O-free on purpose**. No socket, no file, no clock:
//! time arrives as a parameter rather than being read. That is what keeps these
//! modules fuzzable without a runtime (spec §11), and what lets the trickiest
//! logic in the product — the method scan, the provenance chain, the taint
//! algebra — be tested without starting anything.
//!
//! Nothing here decides. It classifies, fingerprints and describes; the verdict
//! belongs to [`crate::daemon`].

pub mod drift;
pub mod frame;
pub mod mcp;
pub mod scope;
pub mod taint;
