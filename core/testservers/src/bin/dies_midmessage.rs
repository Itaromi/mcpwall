//! Serveur qui meurt au milieu d'un message.
//!
//! Le cas où l'amont écrit un début de frame puis disparaît : le shim doit
//! sortir proprement, pas attendre la fin d'une frame qui ne viendra jamais.

use std::io::Write;

fn main() {
    let _ = testservers::read_line();
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"resu");
    let _ = out.flush();
    std::process::exit(3);
}
