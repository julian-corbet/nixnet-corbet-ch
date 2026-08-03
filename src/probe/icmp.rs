//! Privileged raw ICMPv4 echo probe. Requires `CAP_NET_RAW`, which
//! `modules/core.nix` grants via `AmbientCapabilities` whenever any
//! transport uses `method = "icmp"` or `bindToInterface = true`
//! (`config::Config::needs_net_raw`), unaffected by this port.
//!
//! ICMPv4 echo request/reply wire encode/decode is hand-rolled here
//! (~10 bytes of header) rather than pulled in as a dependency -- the Go
//! original's own comment frames `golang.org/x/net/icmp` as "small,
//! well-tested enough to vendor rather than hand-write," which applies
//! just as well to writing it directly in ~40 lines of Rust instead of
//! adding a crate for it.
//!
//! Linux `SOCK_RAW`+`IPPROTO_ICMP` sockets deliver the IPv4 header
//! prepended to every received datagram (standard, long-documented raw
//! socket behavior -- see `man 7 raw` and every reference raw-ping
//! implementation); the header's IHL field gives its length, which is
//! stripped before parsing the ICMP message proper.

use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::config::Transport;

use super::{bind_linux::bind_to_device, ProbeError, ProbeResult};

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// Type, code, checksum, identifier, sequence -- the fixed prefix every
/// ICMPv4 message carries, and the whole of an echo header.
const ICMP_HEADER_LEN: usize = 8;

pub fn run(t: &Transport, timeout: Duration) -> Result<ProbeResult, ProbeError> {
    let target = t.effective_target();
    if target.is_empty() {
        return Err(ProbeError::new("icmp probe: no target/address configured"));
    }

    let dst: Ipv4Addr = match resolve_ipv4(target) {
        Ok(a) => a,
        Err(e) => {
            return Ok(ProbeResult {
                healthy: false,
                detail: format!("resolve: {}", e),
                ..Default::default()
            })
        }
    };

    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(e) => {
            return Ok(ProbeResult {
                healthy: false,
                detail: format!("listen (need CAP_NET_RAW): {}", e),
                ..Default::default()
            })
        }
    };

    if t.probe.bind_to_interface && !t.interface.is_empty() {
        if let Err(e) = bind_to_device(&socket, &t.interface) {
            return Ok(ProbeResult {
                healthy: false,
                detail: format!("bind to {}: {}", t.interface, e),
                ..Default::default()
            });
        }
    }

    let (id, seq) = next_echo_identity();
    let packet = build_echo_request(id, seq, b"nixnet");

    // One deadline for the whole probe, taken before the request goes out,
    // so `probe.timeoutMs` bounds the probe rather than each individual
    // recv. `SO_RCVTIMEO` on its own cannot do that: it restarts on every
    // call, so a target emitting a steady stream of ICMP -- every datagram
    // of which has to be read past now that replies are matched -- could
    // hold this thread indefinitely without any single recv ever timing
    // out, and the transport's tick along with it.
    let start = Instant::now();

    let dst_addr = SockAddr::from(SocketAddrV4::new(dst, 0));
    if let Err(e) = socket.send_to(&packet, &dst_addr) {
        return Ok(ProbeResult {
            healthy: false,
            detail: format!("write: {}", e),
            ..Default::default()
        });
    }

    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let remaining = match remaining_budget(timeout, start.elapsed()) {
            Some(r) => r,
            None => {
                return Ok(ProbeResult {
                    healthy: false,
                    detail: format!("no reply within {}ms", timeout.as_millis()),
                    ..Default::default()
                })
            }
        };
        if let Err(e) = socket.set_read_timeout(Some(remaining)) {
            return Ok(ProbeResult {
                healthy: false,
                detail: format!("set read timeout: {}", e),
                ..Default::default()
            });
        }

        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                return Ok(ProbeResult {
                    healthy: false,
                    detail: format!("no reply: {}", e),
                    ..Default::default()
                })
            }
        };
        let from_ip = from.as_socket_ipv4().map(|a| *a.ip());
        if from_ip != Some(dst) {
            continue; // stray reply from a different host; keep waiting for ours
        }
        // SAFETY: recv_from initialized exactly the first `n` bytes.
        let received: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if is_our_echo_reply(received, id, seq) {
            return Ok(ProbeResult {
                healthy: true,
                detail: "icmp echo reply".to_string(),
                ..Default::default()
            });
        }
        // Somebody else's echo reply, or an ICMP error about somebody
        // else's traffic. Keep reading -- bounded by the deadline above.
    }
}

/// Mints the `(identifier, sequence)` pair for one probe.
///
/// The identifier separates this process from every other pinger on the
/// box, and the sequence separates this probe from every other probe in
/// this process: two transports pointed at the same target run on their
/// own threads and would otherwise be indistinguishable to each other.
/// The identifier still mixes in the wall clock because a PID is reused
/// after a restart, and a reply to the *previous* nixnetd's outstanding
/// request could still be in flight when the new one starts probing.
fn next_echo_identity() -> (u16, u16) {
    static SEQ: AtomicU16 = AtomicU16::new(0);
    let nanos = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        & 0xffff) as u16;
    let id = nanos ^ (std::process::id() as u16);
    (id, SEQ.fetch_add(1, Ordering::Relaxed))
}

/// The remaining slice of a probe's whole-probe budget: `total` minus how
/// long the probe has already been running. `None` means the budget is
/// spent and the caller must stop, not issue another recv.
///
/// Anything under a microsecond counts as spent: `SO_RCVTIMEO` is a
/// `timeval`, so a sub-microsecond `Duration` truncates to `{0, 0}` --
/// byte-identical to the value that means "no timeout at all", which
/// would park the probe thread forever at the very moment its budget ran
/// out. That same truncation is why a transport configured with
/// `timeoutMs = 0` now fails closed immediately instead of blocking.
fn remaining_budget(total: Duration, elapsed: Duration) -> Option<Duration> {
    let left = total.checked_sub(elapsed)?;
    if left < Duration::from_micros(1) {
        return None;
    }
    Some(left)
}

fn resolve_ipv4(target: &str) -> std::io::Result<Ipv4Addr> {
    if let Ok(addr) = target.parse::<Ipv4Addr>() {
        return Ok(addr);
    }
    (target, 0u16)
        .to_socket_addrs()?
        .find_map(|a| match a {
            std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
            _ => None,
        })
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no IPv4 address found"))
}

/// Strips the IPv4 header (length given by the IHL field in the first
/// byte) and returns the ICMP message proper, if `data` is long enough to
/// contain a whole ICMP header.
fn icmp_message(data: &[u8]) -> Option<&[u8]> {
    let ihl = (data.first()? & 0x0f) as usize * 4;
    let icmp = data.get(ihl..)?;
    if icmp.len() < ICMP_HEADER_LEN {
        return None;
    }
    Some(icmp)
}

/// Whether `data` -- one datagram exactly as a raw ICMPv4 socket delivers
/// it, IPv4 header included -- is the reply to the echo request this probe
/// sent, keyed on the `(identifier, sequence)` pair it minted.
///
/// This check is what makes the answer the probe's own. A `SOCK_RAW`
/// socket is not a connection: the kernel copies every ICMP datagram it
/// receives to every raw ICMP socket on the box, so an unrelated `ping`
/// someone left running, or another nixnet transport health-checking the
/// same target over a different interface, produces echo replies that
/// land here too. Accepting those would report a transport as healthy on
/// the strength of traffic that never traversed it -- precisely the
/// failure the failover logic exists to catch.
fn is_our_echo_reply(data: &[u8], id: u16, seq: u16) -> bool {
    let icmp = match icmp_message(data) {
        Some(m) => m,
        None => return false,
    };
    icmp[0] == ICMP_ECHO_REPLY
        && icmp[1] == 0
        && u16::from_be_bytes([icmp[4], icmp[5]]) == id
        && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
}

fn build_echo_request(id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.push(ICMP_ECHO_REQUEST);
    buf.push(0); // code
    buf.push(0); // checksum hi (placeholder)
    buf.push(0); // checksum lo (placeholder)
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(data);
    let sum = internet_checksum(&buf);
    buf[2] = (sum >> 8) as u8;
    buf[3] = (sum & 0xff) as u8;
    buf
}

/// RFC 1071 Internet checksum.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_checksum_is_internally_consistent() {
        let pkt = build_echo_request(0x1234, 1, b"nixnet");
        // Checksumming the whole message (with the checksum field as
        // transmitted) must fold to exactly zero -- the standard
        // Internet-checksum self-verification property.
        assert_eq!(internet_checksum(&pkt), 0);
    }

    /// Builds a datagram shaped like what a raw ICMPv4 socket hands back:
    /// an IPv4 header of `ihl` 32-bit words, then the ICMP message.
    fn raw_datagram(ihl_words: u8, ty: u8, code: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut pkt = vec![0x40 | ihl_words]; // version 4 + IHL
        pkt.extend(std::iter::repeat_n(0u8, ihl_words as usize * 4 - 1));
        pkt.push(ty);
        pkt.push(code);
        pkt.extend_from_slice(&[0, 0]); // checksum, not re-verified on receipt
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(b"nixnet");
        pkt
    }

    #[test]
    fn echo_reply_is_accepted_only_for_our_own_identifier_and_sequence() {
        let (id, seq) = (0x1234u16, 7u16);

        assert!(
            is_our_echo_reply(&raw_datagram(5, ICMP_ECHO_REPLY, 0, id, seq), id, seq),
            "our own echo reply must be accepted"
        );

        // Everything below is what a SOCK_RAW socket also delivers: some
        // other process's ping to the same host, and a second nixnet
        // transport's probe of it. Neither says anything about this
        // transport's path, so neither may be counted as a reply.
        assert!(
            !is_our_echo_reply(
                &raw_datagram(5, ICMP_ECHO_REPLY, 0, id ^ 0xffff, seq),
                id,
                seq
            ),
            "a stray ping's echo reply (foreign identifier) must be rejected"
        );
        assert!(
            !is_our_echo_reply(
                &raw_datagram(5, ICMP_ECHO_REPLY, 0, id, seq.wrapping_add(1)),
                id,
                seq
            ),
            "another probe of ours (different sequence) must be rejected"
        );
        assert!(
            !is_our_echo_reply(&raw_datagram(5, ICMP_ECHO_REQUEST, 0, id, seq), id, seq),
            "an echo *request* must not be mistaken for a reply"
        );
        assert!(
            !is_our_echo_reply(&raw_datagram(5, 3, 1, id, seq), id, seq),
            "a destination-unreachable message must be rejected"
        );
    }

    #[test]
    fn echo_reply_matching_locates_the_icmp_header_by_ihl() {
        let (id, seq) = (0xbeefu16, 3u16);
        // IHL=6: 24 bytes of IPv4 header (options present). Reading the
        // identifier at a fixed offset would land in the options here.
        assert!(is_our_echo_reply(
            &raw_datagram(6, ICMP_ECHO_REPLY, 0, id, seq),
            id,
            seq
        ));

        // Truncated below a full ICMP header: nothing to match against.
        let mut short = raw_datagram(5, ICMP_ECHO_REPLY, 0, id, seq);
        short.truncate(20 + ICMP_HEADER_LEN - 1);
        assert!(!is_our_echo_reply(&short, id, seq));
        assert!(!is_our_echo_reply(&[], id, seq));
    }

    #[test]
    fn each_probe_gets_its_own_sequence_number() {
        let (_, first) = next_echo_identity();
        let (_, second) = next_echo_identity();
        assert_ne!(
            first, second,
            "two probes must be distinguishable from each other's replies"
        );
    }

    #[test]
    fn recv_budget_shrinks_by_time_already_spent() {
        let total = Duration::from_millis(800);
        // The point of the whole-probe deadline: the second recv may only
        // block for what the first one left over, never a fresh 800ms.
        assert_eq!(
            remaining_budget(total, Duration::ZERO),
            Some(Duration::from_millis(800))
        );
        assert_eq!(
            remaining_budget(total, Duration::from_millis(500)),
            Some(Duration::from_millis(300))
        );
        assert_eq!(
            remaining_budget(total, Duration::from_millis(799)),
            Some(Duration::from_millis(1))
        );
    }

    #[test]
    fn recv_budget_is_gone_once_the_deadline_passes() {
        let total = Duration::from_millis(800);
        assert_eq!(remaining_budget(total, total), None);
        // Overshoot must not wrap around into a fresh budget.
        assert_eq!(remaining_budget(total, Duration::from_secs(9)), None);
        // Sub-microsecond leftovers truncate to a `{0, 0}` timeval, which
        // means "block forever" -- they must be spent, not passed on.
        assert_eq!(
            remaining_budget(
                total,
                Duration::from_millis(800) - Duration::from_nanos(999)
            ),
            None
        );
        // A transport configured with timeoutMs = 0 has no budget at all.
        assert_eq!(remaining_budget(Duration::ZERO, Duration::ZERO), None);
    }
}
