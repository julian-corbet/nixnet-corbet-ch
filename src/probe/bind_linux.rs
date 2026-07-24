//! `SO_BINDTODEVICE` -- binding a socket to a specific network interface
//! (a Linux-only socket option) so a probe genuinely exercises the named
//! NIC's route rather than whatever the kernel's default route selection
//! would otherwise pick. Matters specifically for uplink health-checking on
//! multi-homed hosts (wired/wireless/cellular): an unbound probe could
//! succeed via the wrong interface and mask that the "real" one is dead.
//!
//! This is the one piece the port spec calls out as highest-risk to get
//! subtly wrong. The Go original needs two different call shapes for this
//! (`net.Dialer.Control`'s pre-connect raw-fd callback for TCP/HTTP, vs
//! `*net.IPConn.SyscallConn()`'s post-open raw-fd callback for the ICMP raw
//! socket) because the two paths obtain a raw fd at different points in
//! their respective APIs. `socket2::Socket` gives direct access to the fd
//! throughout its lifetime, so both cases collapse to the same one
//! function here: bind the device before `connect()`/`send_to()` in both
//! callers (`tcp.rs` binds before `connect_timeout`; `icmp.rs` binds
//! before the first `send_to`), which is functionally identical to the Go
//! original's "before connect(2) happens" / "against an already-open
//! socket" split -- SO_BINDTODEVICE is idempotent-safe to apply any time
//! before the socket is used for I/O, on both a not-yet-connected TCP
//! socket and a connectionless raw socket.

use std::io;

use socket2::Socket;

/// Applies `SO_BINDTODEVICE` to `socket`, restricting it to `iface`.
/// Requires `CAP_NET_RAW` at runtime, exactly as the Go original --
/// granted via `modules/core.nix`'s `AmbientCapabilities` wiring whenever
/// `config.NeedsNetRaw()` is true, unaffected by this port.
pub fn bind_to_device(socket: &Socket, iface: &str) -> io::Result<()> {
    socket.bind_device(Some(iface.as_bytes()))
}
