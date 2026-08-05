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
    ///
    /// The FLAG decides, never the wakeup. A condvar may return without
    /// anyone having notified it (`futex_wait` is documented as spuriously
    /// wakeable, and Rust's futex `Condvar` reports any non-ETIMEDOUT
    /// return as a wake), so reading "we woke early" as "shutdown was
    /// requested" hands every caller a shutdown that nobody asked for.
    /// Every caller treats that as authoritative and exits its loop:
    /// `run_transport` would silently stop probing its transport for the
    /// rest of the process lifetime -- frozen at `up` in status.json, still
    /// winning its group, its lastKnownGood bound never evaluated again --
    /// the zero-transport loop in `Engine::run` would end `main` with a
    /// success exit from a resident daemon, and the watchdog heartbeat
    /// would stop feeding systemd. `wait_timeout_while` re-checks the
    /// predicate on every wake and re-arms with the time remaining, so this
    /// can only return on `*done` or on a genuinely elapsed `dur`. It also
    /// checks before sleeping, which subsumes the fast path this used to
    /// need.
    pub fn wait(&self, dur: Duration) -> bool {
        let (lock, cvar) = &*self.inner;
        let done = lock.lock().unwrap();
        let (done, _timeout) = cvar.wait_timeout_while(done, dur, |done| !*done).unwrap();
        *done
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A wake that is not a `trigger()` is not a shutdown. Simulated with
    /// the notify a spurious futex wake is indistinguishable from -- the
    /// flag stays false, so the only correct answer is "keep sleeping".
    /// Reported as shutdown, this silently retires a probe thread for the
    /// rest of the daemon's life, and its transport then stays `up` in
    /// status.json forever because nothing ever evaluates it again.
    #[test]
    fn a_wakeup_without_a_trigger_is_not_a_shutdown() {
        let sd = Shutdown::new();
        let noisy = sd.clone();
        let stop = Arc::new(Mutex::new(false));
        let stop_writer = Arc::clone(&stop);
        // Notifies throughout the wait, so the waiter cannot miss them by
        // being late to the condvar.
        let waker = std::thread::spawn(move || {
            while !*stop_writer.lock().unwrap() {
                let (lock, cvar) = &*noisy.inner;
                let _guard = lock.lock().unwrap();
                cvar.notify_all();
                drop(_guard);
                std::thread::sleep(Duration::from_millis(2));
            }
        });

        let dur = Duration::from_millis(250);
        let start = Instant::now();
        let woke = sd.wait(dur);
        let elapsed = start.elapsed();
        *stop.lock().unwrap() = true;
        waker.join().unwrap();

        assert!(!woke, "a stray wakeup was reported as a shutdown request");
        assert!(
            elapsed >= dur,
            "the sleep was cut short by a stray wakeup: {elapsed:?} < {dur:?}"
        );
    }

    /// The other direction, so "always return false" cannot pass the test
    /// above: a real `trigger()` returns immediately and truthfully.
    #[test]
    fn a_trigger_wakes_the_waiter_immediately() {
        let sd = Shutdown::new();
        let trigger = sd.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            trigger.trigger();
        });

        let start = Instant::now();
        assert!(sd.wait(Duration::from_secs(30)), "trigger was not observed");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the waiter slept out its full duration instead of waking on the trigger"
        );
        // Already-set is answered without sleeping at all.
        let start = Instant::now();
        assert!(sd.wait(Duration::from_secs(30)));
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
