//! Bounded execution for the daemon's external helpers.
//!
//! Every child gets its own process group, bounded stdout/stderr pipes, a
//! wall-clock deadline, and an unconditional reap. Killing only the direct
//! child is insufficient: a helper can leave descendants holding the output
//! pipes open, turning a nominal timeout into another indefinite wait.

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

pub(crate) struct BoundedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub truncated: bool,
}

pub(crate) fn run(command: &str, args: &[&str], timeout: Duration) -> io::Result<BoundedOutput> {
    let mut cmd = Command::new(command);
    cmd.args(args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // SAFETY: pre_exec runs in the child immediately before exec. setsid
    // creates a process group whose id is the child's pid, so a later
    // negative-pid kill can never target nixnetd itself.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }

    let mut child = cmd.spawn()?;
    let process_group = child.id() as i32;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    if let Some(pipe) = stdout.as_ref() {
        if let Err(error) = set_nonblocking(pipe) {
            kill_process_group(process_group);
            let _ = child.wait();
            return Err(error);
        }
    }
    if let Some(pipe) = stderr.as_ref() {
        if let Err(error) = set_nonblocking(pipe) {
            kill_process_group(process_group);
            let _ = child.wait();
            return Err(error);
        }
    }

    let mut stdout_buf = Captured::default();
    let mut stderr_buf = Captured::default();
    let started = Instant::now();
    let (status, timed_out) = loop {
        drain(&mut stdout, &mut stdout_buf);
        drain(&mut stderr, &mut stderr_buf);
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if started.elapsed() >= timeout => {
                kill_process_group(process_group);
                break (child.wait()?, true);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10).min(timeout)),
            Err(error) => {
                kill_process_group(process_group);
                let _ = child.wait();
                return Err(error);
            }
        }
    };

    // A successful direct child may have daemonized a descendant that still
    // owns one of our pipes. The command and everything it starts share one
    // lifetime; close the group before the final non-blocking drain.
    kill_process_group(process_group);
    drain(&mut stdout, &mut stdout_buf);
    drain(&mut stderr, &mut stderr_buf);

    Ok(BoundedOutput {
        status,
        stdout: stdout_buf.bytes,
        stderr: stderr_buf.bytes,
        timed_out,
        truncated: stdout_buf.truncated || stderr_buf.truncated,
    })
}

#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

fn set_nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fcntl only observes or updates flags on this valid owned fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the fd remains valid for this call.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain<R: Read>(pipe: &mut Option<R>, output: &mut Captured) {
    let Some(reader) = pipe.as_mut() else {
        return;
    };
    let mut chunk = [0_u8; 8192];
    let mut close = false;
    // Bound each pass so a child writing forever cannot starve the deadline.
    for _ in 0..32 {
        let count = match reader.read(&mut chunk) {
            Ok(0) => {
                close = true;
                break;
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
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
    // SAFETY: the child created this process group with setsid(); a negative
    // pid targets that group and cannot target this daemon.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
}
