//! A cancellable-sleep shutdown signal, replacing Go's
//! `signal.NotifyContext` + `<-ctx.Done()` pattern. Every per-transport
//! ticker loop and the watchdog heartbeat loop hold a clone of this and call
//! `wait(interval)` instead of a plain `thread::sleep`: it returns early,
//! immediately, the moment `trigger()` is called from the signal-handling
//! thread (`bin/nixnetd.rs`), exactly like a `<-ctx.Done()` case winning a
//! `select`.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct Shutdown {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl Shutdown {
    pub fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// Marks shutdown as requested and wakes every waiter. Idempotent.
    pub fn trigger(&self) {
        let (lock, cvar) = &*self.inner;
        let mut done = lock.lock().unwrap();
        *done = true;
        cvar.notify_all();
    }

    pub fn is_set(&self) -> bool {
        let (lock, _) = &*self.inner;
        *lock.lock().unwrap()
    }

    /// Sleeps for up to `dur`, waking early if `trigger()` is called.
    /// Returns `true` if shutdown was (or became) set, `false` if the full
    /// duration elapsed with no shutdown requested.
    pub fn wait(&self, dur: Duration) -> bool {
        let (lock, cvar) = &*self.inner;
        let done = lock.lock().unwrap();
        if *done {
            return true;
        }
        let (done, result) = cvar.wait_timeout(done, dur).unwrap();
        *done || !result.timed_out()
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}
