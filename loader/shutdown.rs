use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use log::{info, warn};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;

/// Coordinates shutdown between the main thread, the signal handler and the
/// stats thread: a flag that can only flip to "stopped", plus a condvar so
/// blocked threads wake up immediately when that happens.
pub struct Shutdown {
    running: AtomicBool,
    lock: Mutex<()>,
    wakeup: Condvar,
}

impl Shutdown {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(true),
            lock: Mutex::new(()),
            wakeup: Condvar::new(),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Flips to "stopped" (idempotent) and wakes every waiting thread.
    pub fn trigger(&self) {
        if self.running.swap(false, Ordering::SeqCst) {
            info!("Shutting down...");
        }
        // taking the lock orders this notify after any in-progress
        // is_running check, so no waiter can miss the wakeup
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.wakeup.notify_all();
    }

    /// Blocks until [`Shutdown::trigger`] is called.
    pub fn wait(&self) {
        let mut guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        while self.is_running() {
            guard = self
                .wakeup
                .wait(guard)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Sleeps for at most `timeout` (woken early by [`Shutdown::trigger`])
    /// and returns whether the process is still running afterwards.
    pub fn sleep(&self, timeout: Duration) -> bool {
        let guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.is_running() {
            return false;
        }
        drop(
            self.wakeup
                .wait_timeout(guard, timeout)
                .unwrap_or_else(PoisonError::into_inner),
        );
        self.is_running()
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawns a thread that triggers `shutdown` on the first termination signal.
pub fn trigger_on_termination_signal(shutdown: Arc<Shutdown>) {
    let mut signals = Signals::new(TERM_SIGNALS).expect("Couldn't register signals");
    thread::spawn(move || {
        if let Some(signal) = signals.forever().next() {
            warn!("Received termination signal: {signal}");
            shutdown.trigger();
        }
    });
}
