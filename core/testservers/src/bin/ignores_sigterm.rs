//! Serveur qui ignore SIGTERM.
//!
//! Sans escalade en SIGKILL, c'est exactement l'orphelin qu'on cherche à
//! éviter : trente processus fantômes après une journée de travail.

fn main() {
    // SIG_IGN sur SIGTERM et SIGINT via la commande `trap` du shell serait plus
    // simple, mais on veut un vrai binaire pour tester le chemin réel.
    unsafe {
        libc_signal(15, 1); // SIGTERM -> SIG_IGN
        libc_signal(2, 1); // SIGINT  -> SIG_IGN
    }
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

unsafe extern "C" {
    #[link_name = "signal"]
    fn libc_signal(sig: i32, handler: usize) -> usize;
}
