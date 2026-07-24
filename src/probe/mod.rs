//! Implements the four probe methods a transport can use: `tcp`, `http`,
//! `icmp`, and `exec`.

mod bind_linux;
mod exec;
mod http;
mod icmp;
mod tcp;

use std::fmt;
use std::time::Duration;

use crate::config::Transport;

/// What a single probe run produced.
#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    pub healthy: bool,
    /// If non-empty, overrides the transport's configured address for this
    /// tick -- the entire dynamic-address mechanism. Only ever set by the
    /// exec method.
    pub address: String,
    pub detail: String,
}

/// A probe could not even be attempted (misconfigured method, empty
/// exec line, etc.) -- distinct from an unhealthy *result*, which is a
/// normal `ProbeResult { healthy: false, .. }`.
#[derive(Debug)]
pub struct ProbeError(pub String);

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ProbeError {}

impl ProbeError {
    fn new(msg: impl Into<String>) -> Self {
        ProbeError(msg.into())
    }
}

/// Dispatches to the method-specific prober. `timeout` is this transport's
/// `probe.timeoutMs`, applied uniformly by each prober so a hung dial
/// can't outlive the tick (the Go original derives a `context.Context`
/// deadline once, centrally, in `probe.Run`; each prober here is simply
/// handed the already-resolved `Duration` instead).
pub fn run(t: &Transport) -> Result<ProbeResult, ProbeError> {
    let timeout = Duration::from_millis(t.probe.timeout_ms.max(0) as u64);
    match t.probe.method.as_str() {
        "tcp" => tcp::run(t, timeout),
        "http" => http::run(t, timeout),
        "icmp" => icmp::run(t, timeout),
        "exec" => exec::run(t, timeout),
        other => Err(ProbeError::new(format!(
            "unknown probe method \"{}\"",
            other
        ))),
    }
}

/// Minimal shell-word splitting (whitespace-separated, single/double
/// quotes respected, no globbing/expansion/escapes beyond that). Nix store
/// paths never contain literal spaces, so this only ever needs to split
/// `"<path> arg1 arg2 ..."`.
fn tokenize(s: &str) -> Result<Vec<String>, ProbeError> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;

    for c in s.chars() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                cur.push(c);
            }
        } else if in_double {
            if c == '"' {
                in_double = false;
            } else {
                cur.push(c);
            }
        } else if c == '\'' {
            in_single = true;
        } else if c == '"' {
            in_double = true;
        } else if c == ' ' || c == '\t' {
            // Matches Go's flush(): only emit a token if something was
            // actually accumulated -- an entirely-empty quoted argument
            // (e.g. `''`) is silently dropped, not preserved as `""`.
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if in_single || in_double {
        return Err(ProbeError::new(format!(
            "unterminated quote in exec command line \"{}\"",
            s
        )));
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    Ok(tokens)
}

/// Returns the first non-empty, trimmed line of `b` -- skips blank lines,
/// ignores everything after the first non-empty line (including trailing
/// garbage).
fn first_non_empty_line(b: &[u8]) -> String {
    let text = String::from_utf8_lossy(b);
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_matches_go_test_cases() {
        let cases: &[(&str, &[&str])] = &[
            ("/bin/foo", &["/bin/foo"]),
            ("/bin/foo bar baz", &["/bin/foo", "bar", "baz"]),
            ("/bin/foo 'has space'", &["/bin/foo", "has space"]),
            ("/bin/foo \"has space\"", &["/bin/foo", "has space"]),
            ("  /bin/foo   bar  ", &["/bin/foo", "bar"]),
            (
                "/nix/store/xxxx-nixnet-netbird-address-probe-host-b/bin/nixnet-netbird-address-probe-host-b",
                &["/nix/store/xxxx-nixnet-netbird-address-probe-host-b/bin/nixnet-netbird-address-probe-host-b"],
            ),
        ];
        for (input, want) in cases {
            let got = tokenize(input).unwrap();
            assert_eq!(&got, want, "tokenize({:?})", input);
        }

        assert!(tokenize("/bin/foo \"unterminated").is_err());
    }

    #[test]
    fn first_non_empty_line_matches_go_test_cases() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"\n\n\n", ""),
            (
                br#"{"address":"203.0.113.20"}"#,
                r#"{"address":"203.0.113.20"}"#,
            ),
            (
                b"\n  \n{\"healthy\":true}\ntrailing garbage\n",
                r#"{"healthy":true}"#,
            ),
        ];
        for (input, want) in cases {
            assert_eq!(&first_non_empty_line(input), want, "input {:?}", input);
        }
    }
}
