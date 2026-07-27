//! Serveur qui viole la spec de plusieurs façons à la fois.
//!
//! Lignes vides, JSON invalide, terminateurs CRLF, et une dernière frame sans
//! délimiteur. Rien de tout ça ne doit interrompre le relais.

use std::io::Write;

fn main() {
    let _ = testservers::read_line();
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "\n\n");
    let _ = writeln!(out, "ceci n'est pas du json");
    let _ = write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{}}}}\r\n");
    let _ = write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}");
    let _ = out.flush();
}
