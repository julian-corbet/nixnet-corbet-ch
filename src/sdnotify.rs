//! Implements the systemd `sd_notify(3)` protocol without a dependency on
//! libsystemd -- it's a trivial datagram write, and pulling in a C library
//! dependency (or even a dedicated crate) would undermine the "single
//! static-ish, minimal-footprint artifact" goal this port exists for in
//! the first place -- a 20-line hand-roll is exactly as good here as a
//! crate would be.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

/// Sends a state string (e.g. `"READY=1"`, `"WATCHDOG=1"`) to
/// `$NOTIFY_SOCKET`. A silent no-op when `NOTIFY_SOCKET` is unset (not
/// running under systemd -- e.g. local development), matching
/// `sd_notify`'s own documented behavior.
pub fn notify(state: &str) -> io::Result<()> {
    notify_to(std::env::var("NOTIFY_SOCKET").ok().as_deref(), state)
}

/// Pure core of [`notify`], taking the socket path explicitly instead of
/// reading the environment -- lets tests exercise the logic without
/// mutating process-global state (env vars are shared across the whole
/// test-binary process, and the default test harness runs tests
/// concurrently in threads, so env-var-mutating tests race each other).
fn notify_to(socket_path: Option<&str>, state: &str) -> io::Result<()> {
    let socket_path = match socket_path {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(()),
    };

    // Linux abstract-namespace sockets are spelled with a leading '@' in
    // the environment variable but a leading NUL on the wire.
    let sock = UnixDatagram::unbound()?;
    if let Some(rest) = socket_path.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        let addr = SocketAddr::from_abstract_name(rest.as_bytes())?;
        sock.send_to_addr(state.as_bytes(), &addr)?;
    } else {
        sock.send_to(state.as_bytes(), socket_path)?;
    }
    Ok(())
}

/// Returns how often `notify("WATCHDOG=1")` should be called to
/// comfortably stay inside systemd's `WatchdogSec` (half of
/// `WATCHDOG_USEC`, the conventional safety margin), or `None` if the unit
/// has no watchdog configured (`WATCHDOG_USEC` unset -- again, a plain
/// no-op, not an error).
pub fn watchdog_interval() -> Option<Duration> {
    parse_watchdog_usec(std::env::var("WATCHDOG_USEC").ok().as_deref())
}

/// Pure core of [`watchdog_interval`] -- see [`notify_to`] for why this is
/// split out (env-var-mutating tests race each other under the default
/// concurrent test harness; a pure function sidesteps that entirely).
fn parse_watchdog_usec(usec_str: Option<&str>) -> Option<Duration> {
    let usec_str = usec_str?;
    if usec_str.is_empty() {
        return None;
    }
    let usec: i64 = usec_str.parse().ok()?;
    if usec <= 0 {
        return None;
    }
    Some(Duration::from_micros(usec as u64) / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_is_a_silent_noop_without_notify_socket() {
        assert!(notify_to(None, "READY=1").is_ok());
    }

    #[test]
    fn watchdog_interval_is_none_when_unset() {
        assert_eq!(parse_watchdog_usec(None), None);
    }

    #[test]
    fn watchdog_interval_is_half_of_watchdog_usec() {
        assert_eq!(
            parse_watchdog_usec(Some("20000000")),
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn watchdog_interval_is_none_for_zero_or_negative_or_unparsable() {
        for v in ["0", "-5", "not-a-number", ""] {
            assert_eq!(parse_watchdog_usec(Some(v)), None, "value {:?}", v);
        }
    }

    #[test]
    fn notify_writes_state_verbatim_to_unixgram_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).unwrap();

        notify_to(Some(sock_path.to_str().unwrap()), "READY=1").unwrap();

        let mut buf = [0u8; 64];
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (n, _) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
    }
}
