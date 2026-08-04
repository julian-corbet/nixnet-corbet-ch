//! Managed `/etc/hosts` block for peers. Content outside the BEGIN/END
//! markers ("the static prefix") is never touched by the daemon -- it is
//! seeded once, at boot/switch, by the NixOS activation script
//! (`modules/core.nix`), from the user's own `networking.hosts` /
//! `extraHosts` plus best-effort last-known-good winners.

use std::io;
use std::path::{Path, PathBuf};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const BEGIN_MARKER: &str = "# BEGIN nixnet";
const END_MARKER: &str = "# END nixnet";

/// One resolved hostname -> address mapping for the managed block.
#[derive(Debug, Clone)]
pub struct Entry {
    pub address: String,
    /// All names for this address, e.g. a peer's `hostnames` list.
    pub hostnames: Vec<String>,
    /// STALE-1: RFC3339 instant of the last successful probe that
    /// confirmed this address, rendered as a comment line above the entry.
    /// `None` only when nothing ever confirmed it (state restored from a
    /// nixnet that predates the timestamp) -- an absent claim, never a
    /// fabricated one.
    pub confirmed_at: Option<String>,
}

/// Owns atomic rewrites of the managed hosts file.
pub struct HostsPublisher {
    path: PathBuf,
    static_prefix: String,
}

impl HostsPublisher {
    /// Loads the current static prefix from whatever already exists at
    /// `path` (normally written moments earlier by the activation script).
    /// If `path` doesn't exist yet, or has no marker block, its entire
    /// existing content -- or nothing at all -- becomes the static prefix;
    /// this is what makes running `nixnetd` directly against a
    /// hand-written hosts file (no Nix activation script involved) a safe,
    /// supported thing to do.
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let prefix = match std::fs::read_to_string(&path) {
            Ok(data) => split_static(&data).0,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            path,
            static_prefix: prefix,
        })
    }

    /// Rewrites the whole hosts file: static prefix, unchanged, plus a
    /// freshly rendered marker block for `entries`. Entries are sorted by
    /// address for deterministic, diff-friendly output across ticks.
    ///
    /// STALE-1: each entry is preceded by a comment line carrying when it
    /// was last confirmed, and the block by one carrying when it was
    /// written. Whole-line comments rather than trailing ones on purpose --
    /// glibc's hosts parser truncates at `#` anywhere in a line, but
    /// systemd-resolved's does not consistently, and a trailing comment
    /// there would register as a bogus extra hostname on every reload.
    /// A leading `#` is unambiguous to every reader of this format.
    pub fn publish(&self, entries: &[Entry]) -> io::Result<()> {
        let mut sorted: Vec<&Entry> = entries.iter().collect();
        sorted.sort_by(|a, b| a.address.cmp(&b.address));

        let written_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();

        let mut out = String::new();
        out.push_str(&self.static_prefix);
        out.push_str(BEGIN_MARKER);
        out.push('\n');
        out.push_str(&format!("# nixnet written={}\n", written_at));
        for e in sorted {
            if let Some(confirmed) = &e.confirmed_at {
                out.push_str(&format!(
                    "# nixnet {} confirmed={}\n",
                    e.address, confirmed
                ));
            }
            out.push_str(&e.address);
            out.push('\t');
            out.push_str(&e.hostnames.join(" "));
            out.push('\n');
        }
        out.push_str(END_MARKER);
        out.push('\n');

        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        crate::atomic::write_with_chmod(dir, &self.path, out.as_bytes(), ".hosts.tmp-", 0o644)
    }
}

/// Returns the content strictly before the BEGIN marker line (trailing
/// blank lines trimmed). If no BEGIN marker is present, the whole input is
/// treated as static content. Second return value mirrors the Go
/// original's `hadMarkers` (unused by callers here, kept for parity with
/// `splitStatic`'s documented signature).
fn split_static(content: &str) -> (String, bool) {
    match content.find(BEGIN_MARKER) {
        Some(idx) => (format!("{}\n", content[..idx].trim_end_matches('\n')), true),
        None => (format!("{}\n", content.trim_end_matches('\n')), false),
    }
}

/// Reads `# nixnet <address> confirmed=<rfc3339>` back into its two parts.
/// Anything else -- including the `# nixnet written=` header and a comment
/// a human added by hand -- is not one of these and yields `None`.
fn parse_confirmed_comment(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("# nixnet ")?;
    let (address, tail) = rest.split_once(' ')?;
    let ts = tail.strip_prefix("confirmed=")?;
    if address.is_empty() || ts.is_empty() {
        return None;
    }
    Some((address.to_string(), ts.to_string()))
}

/// The documented inverse of `split_static`: parses whatever's inside the
/// marker block back into `Entry`s. Not used by the daemon itself; kept
/// (and covered by the same tests) for anything that wants to
/// programmatically re-derive the marker-delimited entries `nixnetd` last
/// published -- e.g. a future `nixnetctl` subcommand.
#[allow(dead_code)]
pub fn parse_nix_hosts(content: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut in_block = false;
    // The `# nixnet <address> confirmed=<rfc3339>` line most recently seen,
    // which `publish` emits directly above the entry it describes.
    let mut pending_confirmed: Option<(String, String)> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == BEGIN_MARKER {
            in_block = true;
        } else if trimmed == END_MARKER {
            in_block = false;
        } else if in_block {
            // The block carries STALE-1's freshness metadata as comment
            // lines (see `publish`). Parsing one as an entry would yield an
            // "address" of `#` with the metadata as its hostnames -- a
            // plausible-looking record of something that does not exist.
            // Recognised rather than merely skipped, so this stays a real
            // inverse of `publish` instead of one that silently drops the
            // half a consumer would compute an age from.
            if trimmed.starts_with('#') {
                pending_confirmed = parse_confirmed_comment(trimmed);
                continue;
            }
            let mut fields = line.split_whitespace();
            if let Some(address) = fields.next() {
                let hostnames: Vec<String> = fields.map(|s| s.to_string()).collect();
                if !hostnames.is_empty() {
                    entries.push(Entry {
                        address: address.to_string(),
                        hostnames,
                        confirmed_at: pending_confirmed
                            .take()
                            .filter(|(addr, _)| addr == address)
                            .map(|(_, ts)| ts),
                    });
                }
            }
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_static_no_marker_keeps_whole_file() {
        let (prefix, had) = split_static("127.0.0.1 localhost\n::1 localhost\n");
        assert_eq!(prefix, "127.0.0.1 localhost\n::1 localhost\n");
        assert!(!had);
    }

    #[test]
    fn split_static_keeps_only_content_before_marker() {
        let content =
            "static line 1\nstatic line 2\n\n\n# BEGIN nixnet\n1.2.3.4\tfoo\n# END nixnet\n";
        let (prefix, had) = split_static(content);
        assert_eq!(prefix, "static line 1\nstatic line 2\n");
        assert!(had);
    }

    #[test]
    fn publish_sorts_by_address_and_writes_marker_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "# static\n").unwrap();

        let hp = HostsPublisher::new(&path).unwrap();
        hp.publish(&[
            Entry {
                address: "10.0.0.2".into(),
                hostnames: vec!["b".into()],
                confirmed_at: None,
            },
            Entry {
                address: "10.0.0.1".into(),
                hostnames: vec!["a".into(), "a.example.com".into()],
                confirmed_at: Some("2026-08-04T10:00:00Z".into()),
            },
        ])
        .unwrap();

        let got = std::fs::read_to_string(&path).unwrap();
        // The `written=` line is the one part that cannot be compared
        // literally -- it is the current instant by definition. Asserted
        // for shape below instead, and dropped here so the rest stays an
        // exact comparison rather than a set of `contains` checks that
        // would pass against a block with extra junk in it.
        let lines: Vec<&str> = got.lines().collect();
        assert!(
            lines[2].starts_with("# nixnet written="),
            "block does not carry its write time (STALE-1):\n{got}"
        );
        let without_written: String = lines
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 2)
            .map(|(_, l)| format!("{l}\n"))
            .collect();
        let expected = "# static\n\
                        # BEGIN nixnet\n\
                        # nixnet 10.0.0.1 confirmed=2026-08-04T10:00:00Z\n\
                        10.0.0.1\ta a.example.com\n\
                        10.0.0.2\tb\n\
                        # END nixnet\n";
        assert_eq!(without_written, expected);

        // Permissions must be 0644 (world-readable), unlike state/status.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn parse_nix_hosts_is_the_inverse_of_publish() {
        let content = "static\n# BEGIN nixnet\n10.0.0.1\ta b\n10.0.0.2\tc\n# END nixnet\n";
        let entries = parse_nix_hosts(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].address, "10.0.0.1");
        assert_eq!(entries[0].hostnames, vec!["a", "b"]);
        assert_eq!(entries[1].address, "10.0.0.2");
        assert_eq!(entries[1].hostnames, vec!["c"]);
    }

    /// STALE-1's metadata must round-trip, and -- more importantly -- must
    /// never be mistaken for an entry. Parsed as one, `# nixnet 10.0.0.1
    /// confirmed=...` becomes a host named `10.0.0.1` at address `#`: a
    /// plausible-looking record of something that does not exist.
    #[test]
    fn parse_nix_hosts_reads_freshness_comments_without_inventing_entries() {
        let content = "static\n\
                       # BEGIN nixnet\n\
                       # nixnet written=2026-08-04T10:00:01Z\n\
                       # nixnet 10.0.0.1 confirmed=2026-08-04T10:00:00Z\n\
                       10.0.0.1\ta b\n\
                       10.0.0.2\tc\n\
                       # END nixnet\n";
        let entries = parse_nix_hosts(content);
        assert_eq!(entries.len(), 2, "comment lines were parsed as entries");
        assert_eq!(entries[0].address, "10.0.0.1");
        assert_eq!(
            entries[0].confirmed_at.as_deref(),
            Some("2026-08-04T10:00:00Z")
        );
        // The second entry has no comment of its own, and must NOT inherit
        // the first one's -- an age attached to the wrong address is worse
        // than no age at all.
        assert_eq!(entries[1].address, "10.0.0.2");
        assert_eq!(entries[1].confirmed_at, None);
    }

    #[test]
    fn new_hosts_publisher_on_missing_file_has_empty_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let hp = HostsPublisher::new(&path).unwrap();
        assert_eq!(hp.static_prefix, "");
    }
}
