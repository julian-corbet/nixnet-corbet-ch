//! Implements the provider exec-probe contract (`docs/providers.md`):
//! exit code 0 = healthy, non-zero = unhealthy (the only guaranteed
//! signal); an optional single line of JSON on stdout
//! (`{"address":...,"healthy":...,"detail":...}`) may additionally
//! override the address and surface free-text detail. `healthy` in the
//! JSON is informational only -- the exit code always wins.
//!
//! `probe.exec` is a full command line, not a bare path -- tokenized here
//! and exec'd directly, never through a shell, so a provider script never
//! gains an implicit dependency on `/bin/sh` existing on `PATH`.

use std::time::Duration;

use serde::Deserialize;

use crate::config::Transport;
use crate::subprocess;

use super::{first_non_empty_line, tokenize, ProbeError, ProbeResult};

#[derive(Deserialize)]
struct ExecEnvelope {
    address: Option<String>,
    // Deliberately never consulted -- the process exit code is always
    // authoritative. Kept only so an envelope that sets it still
    // deserializes instead of erroring on an unknown field.
    #[allow(dead_code)]
    healthy: Option<bool>,
    detail: Option<String>,
}

pub fn run(t: &Transport, timeout: Duration) -> Result<ProbeResult, ProbeError> {
    let argv =
        tokenize(&t.probe.exec).map_err(|e| ProbeError::new(format!("exec probe: {}", e)))?;
    if argv.is_empty() {
        return Err(ProbeError::new("exec probe: probe.exec is empty"));
    }

    let arg_refs: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    let output = match subprocess::run(&argv[0], &arg_refs, timeout) {
        Ok(output) => output,
        Err(e) => {
            // Couldn't even start the process (bad binary, etc.) --
            // unhealthy, not a hard daemon error, so one bad provider
            // script can't take down the whole tick loop.
            return Ok(ProbeResult {
                healthy: false,
                detail: e.to_string(),
                ..Default::default()
            });
        }
    };
    let healthy = !output.timed_out && output.status.success();

    let mut res = ProbeResult {
        healthy,
        ..Default::default()
    };
    let line = first_non_empty_line(&output.stdout);
    if !line.is_empty() {
        match serde_json::from_str::<ExecEnvelope>(&line) {
            Ok(envelope) => {
                res.address = envelope.address.unwrap_or_default();
                res.detail = envelope.detail.unwrap_or_default();
            }
            Err(e) => {
                res.detail = format!(
                    "exec probe: stdout was not the one-line JSON envelope: {}",
                    e
                );
            }
        }
    }
    if res.detail.is_empty() {
        res.detail = if healthy {
            "exec exit 0".to_string()
        } else {
            "exec exit non-zero".to_string()
        };
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        res.detail.push_str(": stderr: ");
        res.detail.push_str(stderr);
    }
    if output.truncated {
        res.detail.push_str(" (probe output truncated at 64 KiB)");
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Probe, Transport};
    use std::time::Instant;

    fn exec_transport(command: &str) -> Transport {
        Transport {
            probe: Probe {
                method: "exec".into(),
                exec: command.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn timeout_kills_descendants_that_inherited_the_output_pipes() {
        let transport = exec_transport("/bin/sh -c 'sleep 30 & wait'");
        let start = Instant::now();
        let result = run(&transport, Duration::from_millis(50)).unwrap();

        assert!(!result.healthy);
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "reader join remained blocked after the direct child timed out"
        );
    }

    #[test]
    fn successful_parent_does_not_leave_readers_waiting_on_a_daemonized_child() {
        let transport = exec_transport("/bin/sh -c 'sleep 30 &'");
        let start = Instant::now();
        let result = run(&transport, Duration::from_secs(3)).unwrap();

        assert!(result.healthy, "{}", result.detail);
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "reader join waited for a descendant after its parent succeeded"
        );
    }

    #[test]
    fn output_is_bounded_and_stderr_remains_diagnostic() {
        let transport =
            exec_transport("/bin/sh -c 'printf problem >&2; yes x | head -c 70000; exit 1'");
        let result = run(&transport, Duration::from_secs(3)).unwrap();

        assert!(!result.healthy);
        assert!(result.detail.contains("problem"), "{}", result.detail);
        assert!(result.detail.contains("truncated"), "{}", result.detail);
    }
}
