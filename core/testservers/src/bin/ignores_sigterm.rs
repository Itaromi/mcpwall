//! A server that ignores SIGTERM.
//!
//! Without escalation to SIGKILL this is exactly the orphan we are trying to
//! avoid: thirty ghost processes after a day's work.

fn main() {
    // SIG_IGN on SIGTERM and SIGINT via the shell's `trap` builtin would be
    // simpler, but we want a real binary so the real path gets tested.
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
