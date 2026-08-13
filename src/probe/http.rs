//! Plain-HTTP GET probe. Hand-rolled (no HTTP client crate) to keep the
//! dependency/footprint minimal on an e2-micro-class target: the request
//! this method ever needs to build is exactly one line plus a `Host`
//! header, and all that's read back is a status line.
//!
//! `https://` targets are a known, narrow gap in this build (no TLS
//! client wired up -- flagged for Julian rather than silently
//! mishandled): they fail closed with a clear, non-fatal `Detail`
//! explaining why, exactly like any other probe failure -- never a panic,
//! never a hard daemon error. `method = "tcp"`/`"icmp"` or an `exec` probe
//! that shells out to `curl`/`curl --cacert` remain the two ways to
//! health-check an HTTPS endpoint today.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Transport;

use super::{bind_linux::bind_to_device, ProbeError, ProbeResult};

pub fn run(t: &Transport, timeout: Duration) -> Result<ProbeResult, ProbeError> {
    let target = t.effective_target();
    if target.is_empty() {
        return Err(ProbeError::new("http probe: no target/address configured"));
    }

    if let Some(rest) = target.strip_prefix("https://") {
        let (host, _) = split_host_path(rest);
        return Ok(ProbeResult {
            healthy: false,
            detail: format!(
                "http probe: {} uses https://, which this build's plain-HTTP prober does not support (no TLS client wired up) -- use method=tcp/icmp for reachability, or method=exec with a script that curls it",
                host
            ),
            ..Default::default()
        });
    }

    let req = plain_request(target, t.probe.port, &t.probe.path);

    let started = Instant::now();
    let addresses = match (req.connect_host.as_str(), req.connect_port)
        .to_socket_addrs()
        .map(|iter| iter.collect::<Vec<_>>())
    {
        Ok(addresses) if !addresses.is_empty() => addresses,
        Ok(_) => {
            return Ok(ProbeResult {
                healthy: false,
                detail: "no addresses found".to_string(),
                ..Default::default()
            })
        }
        Err(e) => {
            return Ok(ProbeResult {
                healthy: false,
                detail: e.to_string(),
                ..Default::default()
            })
        }
    };

    let mut last_error = "probe deadline exhausted during name resolution".to_string();
    for addr in addresses {
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
            Ok(socket) => socket,
            Err(e) => {
                last_error = e.to_string();
                continue;
            }
        };
        if t.probe.bind_to_interface && !t.interface.is_empty() {
            if let Err(e) = bind_to_device(&socket, &t.interface) {
                last_error = e.to_string();
                continue;
            }
        }
        if let Err(e) = socket.connect_timeout(&addr.into(), remaining) {
            last_error = format!("{addr}: {e}");
            continue;
        }
        let mut stream: TcpStream = socket.into();
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(remaining));
        let _ = stream.set_write_timeout(Some(remaining));

        return match do_get(&mut stream, &req.header_host, &req.path) {
            Ok(code) => Ok(ProbeResult {
                healthy: code < 400,
                detail: format!("http status {} ({addr})", code),
                ..Default::default()
            }),
            Err(e) => Ok(ProbeResult {
                healthy: false,
                detail: format!("{addr}: {e}"),
                ..Default::default()
            }),
        };
    }

    Ok(ProbeResult {
        healthy: false,
        detail: last_error,
        ..Default::default()
    })
}

fn split_host_path(rest: &str) -> (String, String) {
    match rest.find('/') {
        Some(idx) => (rest[..idx].to_string(), rest[idx..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    }
}

/// Everything a plain-HTTP GET needs, derived from the transport config
/// before any socket is touched. Split out of `run` so the whole
/// target-shaped surface -- scheme or not, IPv6 literal or not, the
/// `probe.port` fallback -- is table-testable without a network.
#[derive(Debug, PartialEq)]
struct Request {
    /// Value for the `Host:` header.
    header_host: String,
    /// Host as the resolver has to see it, which is not always what the
    /// header says -- see `Authority::header_host`.
    connect_host: String,
    connect_port: u16,
    path: String,
}

/// An authority (`host`, `host:port`, `[v6]`, `[v6]:port`, or a bare IPv6
/// literal) taken apart.
#[derive(Debug)]
struct Authority {
    /// Brackets stripped; a zone id, if the operator wrote one, is left on
    /// for getaddrinfo(3), which is what actually understands it.
    host: String,
    /// The port the authority itself named. `None` is not "port 80": it is
    /// also what lets `probe.port` still fill the port in, and what keeps a
    /// redundant `:80` out of the `Host:` header.
    port: Option<u16>,
    /// `host` is an IPv6 literal, so the header has to bracket it again.
    ipv6_literal: bool,
}

impl Authority {
    /// The `Host:` header value. RFC 7230 §5.4 defers to the URI authority
    /// grammar, which brackets an IPv6 literal -- `Host: [2001:db8::1]:8080`
    /// -- so the brackets that had to come off for `ToSocketAddrs` (which
    /// resolves neither `[2001:db8::1]` nor a bracketed `host` part) go
    /// back on here. The two consumers genuinely disagree about brackets;
    /// that disagreement is why host and port are parsed once, centrally,
    /// instead of at each use.
    fn header_host(&self) -> String {
        match (self.ipv6_literal, self.port) {
            (true, Some(p)) => format!("[{}]:{}", self.host, p),
            (true, None) => format!("[{}]", self.host),
            (false, Some(p)) => format!("{}:{}", self.host, p),
            (false, None) => self.host.clone(),
        }
    }
}

/// Splits an HTTP authority into host and port.
///
/// A bare IPv6 literal is why this cannot be the `rsplit_once(':')` it once
/// was: the address's own separators are not a port delimiter, so
/// `2001:db8::1` has to survive the split untouched rather than arrive at
/// the resolver as host `2001:db8:` on port 1. Anything that is neither
/// bracketed nor an IPv6 literal is split exactly as before, including
/// malformed input such as `host:notaport`, which stays one opaque host so
/// that the resolver -- not this function -- is what reports it.
fn split_authority(authority: &str) -> Authority {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((literal, after)) = rest.split_once(']') {
            return Authority {
                host: literal.to_string(),
                port: after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()),
                ipv6_literal: true,
            };
        }
        // Unterminated '[': no grammar accepts this, so fall through to the
        // opaque-host path rather than invent a reading of it.
    } else if let Some((head, tail)) = authority.rsplit_once(':') {
        if head.contains(':') {
            // Two or more colons means an IPv6 literal, and an unbracketed
            // one cannot carry a port at all -- there would be no way to
            // tell that port from another group of the address.
            return Authority {
                host: authority.to_string(),
                port: None,
                ipv6_literal: true,
            };
        }
        if let Ok(port) = tail.parse::<u16>() {
            return Authority {
                host: head.to_string(),
                port: Some(port),
                ipv6_literal: false,
            };
        }
    }

    Authority {
        host: authority.to_string(),
        port: None,
        ipv6_literal: false,
    }
}

/// Derives the request from a transport's `probe.target`/`probe.port`/
/// `probe.path`. `target` never carries an `https://` scheme here -- `run`
/// answers those before it gets this far.
fn plain_request(target: &str, probe_port: i64, probe_path: &str) -> Request {
    let (auth, path) = match target.strip_prefix("http://") {
        // An explicit URL is self-contained: its authority names the port
        // (or leaves it at 80) and it carries its own path, so probe.port
        // and probe.path stay out of this branch entirely.
        Some(rest) => {
            let (authority, path) = split_host_path(rest);
            (split_authority(&authority), path)
        }
        None => {
            // No scheme: build "http://" + host[:port] + path exactly like
            // the Go original -- note probe.port defaults to 22 generically
            // (shared with the tcp method's default), so an http probe left
            // at its defaults connects to :22, not :80, unless the operator
            // sets probe.port explicitly. Port 80 is left implicit so a
            // bare host keeps a bare `Host:` header.
            //
            // The condition is "the target named no port of its own", which
            // used to be spelled `!host.contains(':')` -- true of every
            // bare IPv6 literal, which is how an IPv6-only host ended up
            // probed on :80 no matter what probe.port said.
            let mut auth = split_authority(target);
            if auth.port.is_none() && probe_port != 0 && probe_port != 80 {
                // Out of u16 range is unreachable through the Nix module
                // (`types.port`); a hand-written config.json that manages it
                // falls back to the implicit 80 instead of mangling the
                // number into the hostname the way the old format! did.
                auth.port = u16::try_from(probe_port).ok();
            }
            let path = if probe_path.is_empty() {
                "/".to_string()
            } else {
                probe_path.to_string()
            };
            (auth, path)
        }
    };

    Request {
        header_host: auth.header_host(),
        connect_port: auth.port.unwrap_or(80),
        connect_host: auth.host,
        path,
    }
}

fn do_get(stream: &mut TcpStream, header_host: &str, path: &str) -> std::io::Result<u16> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: nixnetd\r\n\r\n",
        path, header_host
    );
    stream.write_all(req.as_bytes())?;

    // Only the status line matters -- read until we see one, discarding
    // everything else, up to a small bound (mirrors the Go original's
    // `io.LimitReader(resp.Body, 4096)` discard).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        if buf.windows(2).any(|w| w == b"\r\n") || buf.len() >= 4096 {
            break;
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let code_str = parts.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed http status line: {:?}", status_line),
        )
    })?;
    code_str.parse::<u16>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed http status code: {:?}", code_str),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_authority_understands_every_host_form() {
        // (authority, host for the resolver, port it named, `Host:` header)
        let cases: &[(&str, &str, Option<u16>, &str)] = &[
            ("192.0.2.10", "192.0.2.10", None, "192.0.2.10"),
            (
                "192.0.2.10:8080",
                "192.0.2.10",
                Some(8080),
                "192.0.2.10:8080",
            ),
            (
                "host.example.com",
                "host.example.com",
                None,
                "host.example.com",
            ),
            (
                "host.example.com:8443",
                "host.example.com",
                Some(8443),
                "host.example.com:8443",
            ),
            // A bare literal must not be split at its own colons, and comes
            // back bracketed for the header.
            ("2001:db8::1", "2001:db8::1", None, "[2001:db8::1]"),
            ("::1", "::1", None, "[::1]"),
            ("[2001:db8::1]", "2001:db8::1", None, "[2001:db8::1]"),
            (
                "[2001:db8::1]:8080",
                "2001:db8::1",
                Some(8080),
                "[2001:db8::1]:8080",
            ),
            // Only the brackets are the resolver's problem; a zone id is
            // getaddrinfo's business and passes through untouched.
            ("fe80::1%eth0", "fe80::1%eth0", None, "[fe80::1%eth0]"),
            (
                "[fe80::1%eth0]:8080",
                "fe80::1%eth0",
                Some(8080),
                "[fe80::1%eth0]:8080",
            ),
            // Malformed input stays opaque, exactly as the old split left
            // it, so the resolver is what reports it.
            (
                "host.example.com:notaport",
                "host.example.com:notaport",
                None,
                "host.example.com:notaport",
            ),
            ("[2001:db8::1", "[2001:db8::1", None, "[2001:db8::1"),
        ];
        for (authority, host, port, header) in cases {
            let got = split_authority(authority);
            assert_eq!(&got.host, host, "connect host of {:?}", authority);
            assert_eq!(&got.port, port, "port of {:?}", authority);
            assert_eq!(
                &got.header_host(),
                header,
                "Host: header of {:?}",
                authority
            );
        }
    }

    #[test]
    fn plain_request_derives_header_and_connect_target() {
        // (target, probe.port, probe.path) -> (Host:, connect host, connect
        // port, request path)
        let cases: &[(&str, i64, &str, &str, &str, u16, &str)] = &[
            // Scheme-less: probe.port supplies the port, probe.path the path.
            (
                "192.0.2.10",
                8080,
                "/healthz",
                "192.0.2.10:8080",
                "192.0.2.10",
                8080,
                "/healthz",
            ),
            ("192.0.2.10", 80, "", "192.0.2.10", "192.0.2.10", 80, "/"),
            (
                "host.example.com",
                22,
                "/",
                "host.example.com:22",
                "host.example.com",
                22,
                "/",
            ),
            // A port in the target itself wins over probe.port.
            (
                "192.0.2.10:9000",
                8080,
                "/h",
                "192.0.2.10:9000",
                "192.0.2.10",
                9000,
                "/h",
            ),
            // The IPv6-only host: bracketed header, bare connect target, and
            // probe.port applies because the literal named no port.
            (
                "2001:db8::1",
                8080,
                "/healthz",
                "[2001:db8::1]:8080",
                "2001:db8::1",
                8080,
                "/healthz",
            ),
            (
                "[2001:db8::1]:8080",
                22,
                "/healthz",
                "[2001:db8::1]:8080",
                "2001:db8::1",
                8080,
                "/healthz",
            ),
            (
                "2001:db8::1",
                80,
                "/",
                "[2001:db8::1]",
                "2001:db8::1",
                80,
                "/",
            ),
            // An http:// URL is self-contained: probe.port/probe.path ignored.
            (
                "http://host.example.com/status",
                8080,
                "/ignored",
                "host.example.com",
                "host.example.com",
                80,
                "/status",
            ),
            (
                "http://192.0.2.10:8080/status",
                22,
                "/ignored",
                "192.0.2.10:8080",
                "192.0.2.10",
                8080,
                "/status",
            ),
            (
                "http://[2001:db8::1]:8080/status",
                22,
                "/ignored",
                "[2001:db8::1]:8080",
                "2001:db8::1",
                8080,
                "/status",
            ),
            (
                "http://[2001:db8::1]/status",
                22,
                "/ignored",
                "[2001:db8::1]",
                "2001:db8::1",
                80,
                "/status",
            ),
        ];
        for (target, probe_port, probe_path, header, connect_host, connect_port, path) in cases {
            assert_eq!(
                plain_request(target, *probe_port, probe_path),
                Request {
                    header_host: header.to_string(),
                    connect_host: connect_host.to_string(),
                    connect_port: *connect_port,
                    path: path.to_string(),
                },
                "plain_request({:?}, {}, {:?})",
                target,
                probe_port,
                probe_path
            );
        }
    }
}
