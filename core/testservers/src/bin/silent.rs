//! Serveur qui n'écrit jamais rien.
//!
//! Vérifie que le shim ne reste pas suspendu et n'invente pas de trafic.

fn main() {
    while testservers::read_line().is_some() {}
    // Sort à la fermeture de stdin, sans avoir rien écrit.
}
