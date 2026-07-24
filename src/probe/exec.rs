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

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::config::Transport;

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

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    // stderr is discarded entirely -- never logged, never surfaced
    // anywhere, matching the Go original's `cmd.Output()` (stdout-only).
    cmd.stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
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

    // Drain stdout concurrently with waiting, exactly like Go's
    // `cmd.Output()` does internally -- otherwise a script that writes
    // more than one pipe buffer's worth of stdout before exiting could
    // deadlock the poll loop below.
    let mut stdout_pipe = child.stdout.take();
    let reader = stdout_pipe.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // A hung script gets killed on timeout -- this is
                    // then just a plain (signal-)non-zero exit below, not
                    // a hard error, matching `exec.CommandContext`'s
                    // context-cancellation behavior in the Go original.
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10).min(timeout));
            }
            Err(_) => break None,
        }
    };

    let stdout_buf = reader.and_then(|h| h.join().ok()).unwrap_or_default();
    let healthy = matches!(status, Some(s) if s.success());

    let mut res = ProbeResult {
        healthy,
        ..Default::default()
    };
    let line = first_non_empty_line(&stdout_buf);
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
    Ok(res)
}
