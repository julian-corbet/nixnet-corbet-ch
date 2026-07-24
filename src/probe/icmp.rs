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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::config::Transport;

use super::{bind_linux::bind_to_device, ProbeError, ProbeResult};

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

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

    if let Err(e) = socket.set_read_timeout(Some(timeout)) {
        return Ok(ProbeResult {
            healthy: false,
            detail: format!("set read timeout: {}", e),
            ..Default::default()
        });
    }

    let id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        & 0xffff) as u16;
    let packet = build_echo_request(id, 1, b"nixnet");

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
        match parse_icmpv4(received) {
            Some((ty, _code)) if ty == ICMP_ECHO_REPLY => {
                return Ok(ProbeResult {
                    healthy: true,
                    detail: "icmp echo reply".to_string(),
                    ..Default::default()
                })
            }
            _ => continue,
        }
    }
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
/// byte) and returns the ICMP message's `(type, code)`, if `data` is long
/// enough to contain one.
fn parse_icmpv4(data: &[u8]) -> Option<(u8, u8)> {
    if data.is_empty() {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    let icmp = data.get(ihl..)?;
    if icmp.len() < 2 {
        return None;
    }
    Some((icmp[0], icmp[1]))
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

    #[test]
    fn parse_icmpv4_strips_ip_header_by_ihl() {
        let mut ip_and_icmp = vec![0x45u8]; // version 4, IHL=5 (20 bytes)
        ip_and_icmp.extend(std::iter::repeat_n(0u8, 19)); // rest of IP header
        ip_and_icmp.push(0); // ICMP type 0 = echo reply
        ip_and_icmp.push(0); // code
        ip_and_icmp.extend_from_slice(&[0, 0, 0, 0]); // checksum + rest

        let (ty, code) = parse_icmpv4(&ip_and_icmp).unwrap();
        assert_eq!(ty, ICMP_ECHO_REPLY);
        assert_eq!(code, 0);
    }
}
