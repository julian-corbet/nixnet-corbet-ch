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
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Transport;

use super::{bind_linux::bind_to_device, ProbeError, ProbeResult};

pub fn run(t: &Transport, timeout: Duration) -> Result<ProbeResult, ProbeError> {
    let target = t.effective_target();
    if target.is_empty() {
        return Err(ProbeError::new("http probe: no target/address configured"));
    }

    let (header_host, path) = if let Some(rest) = target.strip_prefix("https://") {
        let (host, _) = split_host_path(rest);
        return Ok(ProbeResult {
            healthy: false,
            detail: format!(
                "http probe: {} uses https://, which this build's plain-HTTP prober does not support (no TLS client wired up) -- use method=tcp/icmp for reachability, or method=exec with a script that curls it",
                host
            ),
            ..Default::default()
        });
    } else if let Some(rest) = target.strip_prefix("http://") {
        split_host_path(rest)
    } else {
        // No scheme: build "http://" + host[:port] + path exactly like
        // the Go original -- note probe.port defaults to 22 generically
        // (shared with the tcp method's default), so an http probe left
        // at its defaults connects to :22, not :80, unless the operator
        // sets probe.port explicitly. Only append the port when it's set
        // and isn't already 80 (the implicit default for a bare host).
        let mut host = target.to_string();
        if t.probe.port != 0 && t.probe.port != 80 && !host.contains(':') {
            host = format!("{}:{}", host, t.probe.port);
        }
        let path = if t.probe.path.is_empty() {
            "/".to_string()
        } else {
            t.probe.path.clone()
        };
        (host, path)
    };

    let (connect_host, connect_port) = match header_host.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(p) => (h.to_string(), p),
            Err(_) => (header_host.clone(), 80),
        },
        None => (header_host.clone(), 80),
    };

    let addr = match (connect_host.as_str(), connect_port)
        .to_socket_addrs()
        .and_then(|mut it| {
            it.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses found")
            })
        }) {
        Ok(a) => a,
        Err(e) => {
            return Ok(ProbeResult {
                healthy: false,
                detail: e.to_string(),
                ..Default::default()
            })
        }
    };

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) => {
            return Ok(ProbeResult {
                healthy: false,
                detail: e.to_string(),
                ..Default::default()
            })
        }
    };
    if t.probe.bind_to_interface && !t.interface.is_empty() {
        if let Err(e) = bind_to_device(&socket, &t.interface) {
            return Ok(ProbeResult {
                healthy: false,
                detail: e.to_string(),
                ..Default::default()
            });
        }
    }
    if let Err(e) = socket.connect_timeout(&addr.into(), timeout) {
        return Ok(ProbeResult {
            healthy: false,
            detail: e.to_string(),
            ..Default::default()
        });
    }
    let mut stream: TcpStream = socket.into();
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    match do_get(&mut stream, &header_host, &path) {
        Ok(code) => Ok(ProbeResult {
            healthy: code < 400,
            detail: format!("http status {}", code),
            ..Default::default()
        }),
        Err(e) => Ok(ProbeResult {
            healthy: false,
            detail: e.to_string(),
            ..Default::default()
        }),
    }
}

fn split_host_path(rest: &str) -> (String, String) {
    match rest.find('/') {
        Some(idx) => (rest[..idx].to_string(), rest[idx..].to_string()),
        None => (rest.to_string(), "/".to_string()),
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
