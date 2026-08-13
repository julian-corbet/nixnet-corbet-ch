use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Transport;

use super::{bind_linux::bind_to_device, ProbeError, ProbeResult};

pub fn run(t: &Transport, timeout: Duration) -> Result<ProbeResult, ProbeError> {
    let target = t.effective_target();
    if target.is_empty() {
        return Err(ProbeError::new("tcp probe: no target/address configured"));
    }
    let port = if t.probe.port == 0 { 22 } else { t.probe.port };

    let started = Instant::now();
    let addresses = match (target, port as u16)
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

        match socket.connect_timeout(&addr.into(), remaining) {
            Ok(()) => {
                return Ok(ProbeResult {
                    healthy: true,
                    detail: format!("tcp connect ok ({addr})"),
                    ..Default::default()
                })
            }
            Err(e) => last_error = format!("{addr}: {e}"),
        }
    }

    Ok(ProbeResult {
        healthy: false,
        detail: last_error,
        ..Default::default()
    })
}
