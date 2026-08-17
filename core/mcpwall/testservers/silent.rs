//! A server that never writes anything.
//!
//! Checks that the shim neither hangs nor invents traffic.

#[path = "support.rs"]
mod support;

fn main() {
    while support::read_line().is_some() {}
    // Exits when stdin closes, having written nothing.
}
