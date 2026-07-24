use std::net::ToSocketAddrs;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Transport;

use super::{bind_linux::bind_to_device, ProbeError, ProbeResult};

pub fn run(t: &Transport, timeout: Duration) -> Result<ProbeResult, ProbeError> {
    let target = t.effective_target();
    if target.is_empty() {
        return Err(ProbeError::new("tcp probe: no target/address configured"));
    }
    let port = if t.probe.port == 0 { 22 } else { t.probe.port };

    let addr = match (target, port as u16).to_socket_addrs().and_then(|mut it| {
        it.next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses found"))
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

    match socket.connect_timeout(&addr.into(), timeout) {
        Ok(()) => Ok(ProbeResult {
            healthy: true,
            detail: "tcp connect ok".to_string(),
            ..Default::default()
        }),
        Err(e) => Ok(ProbeResult {
            healthy: false,
            detail: e.to_string(),
            ..Default::default()
        }),
    }
}
