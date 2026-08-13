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
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::config::Transport;

use super::{first_non_empty_line, tokenize, ProbeError, ProbeResult};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

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
    cmd.stderr(Stdio::piped());
    // Give the probe its own process group. Killing only the direct child
    // leaves descendants alive with inherited stdout/stderr pipe handles;
    // joining the reader then blocks forever even though the timeout fired.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }

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

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let process_group = child.id() as i32;
    if stdout
        .as_ref()
        .is_some_and(|pipe| set_nonblocking(pipe).is_err())
        || stderr
            .as_ref()
            .is_some_and(|pipe| set_nonblocking(pipe).is_err())
    {
        kill_process_group(process_group);
        let _ = child.wait();
        return Ok(ProbeResult {
            healthy: false,
            detail: "exec probe: could not make output pipes non-blocking".to_string(),
            ..Default::default()
        });
    }

    let mut stdout_buf = BoundedOutput::default();
    let mut stderr_buf = BoundedOutput::default();
    let start = Instant::now();
    let status = loop {
        drain(&mut stdout, &mut stdout_buf);
        drain(&mut stderr, &mut stderr_buf);
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // A hung script gets killed on timeout -- this is
                    // then just a plain (signal-)non-zero exit below, not
                    // a hard error, matching `exec.CommandContext`'s
                    // context-cancellation behavior in the Go original.
                    // Negative pid means the whole process group. The
                    // direct child is included, as are provider helpers
                    // that inherited the output pipes.
                    kill_process_group(process_group);
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10).min(timeout));
            }
            Err(_) => {
                kill_process_group(process_group);
                let _ = child.wait();
                break None;
            }
        }
    };

    // Even a successfully-reaped direct child may have daemonized a
    // descendant which still owns our output pipes. A probe command and
    // everything it starts have the same lifetime; reap the group before
    // the final non-blocking drain so success cannot hang either.
    kill_process_group(process_group);
    drain(&mut stdout, &mut stdout_buf);
    drain(&mut stderr, &mut stderr_buf);
    let healthy = matches!(status, Some(s) if s.success());

    let mut res = ProbeResult {
        healthy,
        ..Default::default()
    };
    let line = first_non_empty_line(&stdout_buf.bytes);
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
    let stderr = String::from_utf8_lossy(&stderr_buf.bytes);
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        res.detail.push_str(": stderr: ");
        res.detail.push_str(stderr);
    }
    if stdout_buf.truncated || stderr_buf.truncated {
        res.detail.push_str(" (probe output truncated at 64 KiB)");
    }
    Ok(res)
}

#[derive(Default)]
struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn set_nonblocking(pipe: &impl AsRawFd) -> std::io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fcntl only observes/updates flags on this valid owned fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the fd remains valid for the duration of the call.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn drain<R: Read>(pipe: &mut Option<R>, output: &mut BoundedOutput) {
    let Some(reader) = pipe.as_mut() else {
        return;
    };
    let mut chunk = [0_u8; 8192];
    let mut close = false;
    // Bound work per pass so a command that writes forever cannot prevent
    // the outer loop from checking its deadline.
    for _ in 0..32 {
        let count = match reader.read(&mut chunk) {
            Ok(0) => {
                close = true;
                break;
            }
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                close = true;
                break;
            }
        };
        let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.bytes.len());
        if remaining > 0 {
            output
                .bytes
                .extend_from_slice(&chunk[..count.min(remaining)]);
        }
        output.truncated |= count > remaining;
    }
    if close {
        *pipe = None;
    }
}

fn kill_process_group(process_group: i32) {
    // SAFETY: the child created this process group with setsid(); a
    // negative pid targets that group and can never target this daemon.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Probe, Transport};

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
