//! A server that never writes anything.
//!
//! Checks that the shim neither hangs nor invents traffic.

fn main() {
    while testservers::read_line().is_some() {}
    // Exits when stdin closes, having written nothing.
}
