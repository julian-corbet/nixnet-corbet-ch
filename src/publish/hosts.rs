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
    /// The static prefix as it looked when the daemon started, used ONLY
    /// when the file has since vanished. Every ordinary publication reads
    /// the prefix back off disk instead: TF-2 turned publication into a
    /// per-tick operation, and a snapshot replayed every few seconds
    /// deletes anything a human or another tool appended within one tick
    /// of them writing it.
    static_prefix: String,
}

impl HostsPublisher {
    /// Loads the static prefix from whatever already exists at `path`
    /// (normally written moments earlier by the activation script). If
    /// `path` doesn't exist yet, or has no marker block, its entire
    /// existing content -- or nothing at all -- becomes the static prefix;
    /// this is what makes running `nixnetd` directly against a
    /// hand-written hosts file (no Nix activation script involved) a safe,
    /// supported thing to do.
    ///
    /// The value read here is a FALLBACK for a file that later disappears:
    /// `publish` re-reads the prefix off the live file every time, so
    /// nothing written outside the markers after this point is lost.
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
    /// Returns whether the file was actually written.
    ///
    /// TF-2: called on every reconcile tick, not only when a winner
    /// changes, and therefore a NO-OP whenever the live file already says
    /// this. `/etc/hosts` is watched -- systemd-resolved reloads it,
    /// nss caches invalidate on it -- so rewriting it every few seconds to
    /// restate the same three lines is not free, and "the file changed" has
    /// to keep meaning something.
    ///
    /// STALE-1: each entry is preceded by a comment line carrying when it
    /// was last confirmed, and the block by one carrying when it was
    /// written. Whole-line comments rather than trailing ones on purpose --
    /// glibc's hosts parser truncates at `#` anywhere in a line, but
    /// systemd-resolved's does not consistently, and a trailing comment
    /// there would register as a bogus extra hostname on every reload.
    /// A leading `#` is unambiguous to every reader of this format.
    pub fn publish(&self, entries: &[Entry]) -> io::Result<bool> {
        let current = match std::fs::read_to_string(&self.path) {
            Ok(c) => Some(c),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };

        // The prefix comes off the LIVE file, so an entry a human or
        // another tool put outside the markers survives (PUB-1) instead of
        // being deleted by the next tick's replay of a start-time snapshot.
        let prefix = match &current {
            Some(c) => split_static(c).0,
            None => self.static_prefix.clone(),
        };

        let mut sorted: Vec<&Entry> = entries.iter().collect();
        sorted.sort_by(|a, b| a.address.cmp(&b.address));

        let written_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();

        let mut out = String::new();
        out.push_str(&prefix);
        out.push_str(BEGIN_MARKER);
        out.push('\n');
        out.push_str(&format!("# nixnet written={}\n", written_at));
        for e in sorted {
            if let Some(confirmed) = &e.confirmed_at {
                out.push_str(&format!("# nixnet {} confirmed={}\n", e.address, confirmed));
            }
            out.push_str(&e.address);
            out.push('\t');
            out.push_str(&e.hostnames.join(" "));
            out.push('\n');
        }
        out.push_str(END_MARKER);
        out.push('\n');

        if let Some(c) = &current {
            if same_but_for_freshness(c, &out) {
                return Ok(false);
            }
        }

        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        crate::atomic::write_with_chmod(dir, &self.path, out.as_bytes(), ".hosts.tmp-", 0o644)?;
        Ok(true)
    }
}

/// Compares two renderings of the file while ignoring nixnet's own
/// freshness comments -- the `# nixnet written=` header and the
/// `# nixnet <address> confirmed=` lines.
///
/// They are ignored because they change on EVERY tick a probe succeeds, so
/// comparing them would make "has anything changed?" answer yes forever
/// and rewrite `/etc/hosts` every few seconds -- exactly the churn TF-2
/// refuses. STATE THE COST HONESTLY: the timestamps in the file are
/// therefore those of the last write, not of the last probe, so a consumer
/// reading only `/etc/hosts` under-reads the freshness of an entry that has
/// been confirmed steadily since. The exact per-tick answer STALE-1 asks
/// for is published in `status.json`, which is rewritten every tick on a
/// tmpfs where churn costs nothing.
fn same_but_for_freshness(a: &str, b: &str) -> bool {
    let significant = |s: &str| -> Vec<String> {
        s.lines()
            .filter(|l| !l.trim_start().starts_with("# nixnet "))
            .map(str::to_string)
            .collect()
    };
    significant(a) == significant(b)
}

/// Returns the content strictly before the BEGIN marker line (trailing
/// blank lines trimmed). If no BEGIN marker is present, the whole input is
/// treated as static content. Second return value mirrors the Go
/// original's `hadMarkers` (unused by callers here, kept for parity with
/// `splitStatic`'s documented signature).
fn split_static(content: &str) -> (String, bool) {
    let (raw, had_markers) = match content.find(BEGIN_MARKER) {
        Some(idx) => (&content[..idx], true),
        None => (content, false),
    };
    let trimmed = raw.trim_end_matches('\n');
    // An EMPTY prefix renders as nothing, not as a blank line. It matters
    // because TF-2 decides whether to write by comparing this rendering
    // against the live file: a prefix that gains a newline when it is read
    // back off a file it just wrote is a difference that never converges,
    // so the daemon would rewrite the hosts file on every single tick while
    // reporting that it had reconciled.
    if trimmed.is_empty() {
        (String::new(), had_markers)
    } else {
        (format!("{}\n", trimmed), had_markers)
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

    /// TF-2, at the file layer: publication moved onto every reconcile
    /// tick, so a publication of unchanged entries must not touch the
    /// file. Asserted on the INODE, not on the bytes: the write is
    /// tmpfile-plus-rename, so a rewrite always lands on a new inode even
    /// when the content happens to match -- and it is the rename, not the
    /// content, that wakes every watcher of `/etc/hosts`.
    #[test]
    fn republishing_identical_entries_does_not_touch_the_file() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "# static\n").unwrap();
        let hp = HostsPublisher::new(&path).unwrap();

        let entries = |confirmed: &str| {
            vec![Entry {
                address: "10.0.0.1".into(),
                hostnames: vec!["a".into()],
                confirmed_at: Some(confirmed.into()),
            }]
        };

        assert!(
            hp.publish(&entries("2026-08-04T10:00:00Z")).unwrap(),
            "the first publication wrote nothing"
        );
        let first = std::fs::metadata(&path).unwrap().ino();

        // A later tick: same winner, same address -- only the freshness
        // stamp has moved on, which is what happens on every single tick a
        // probe succeeds.
        assert!(
            !hp.publish(&entries("2026-08-04T10:00:03Z")).unwrap(),
            "an unchanged block was rewritten"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            first,
            "the file was replaced despite publishing the same entries -- at \
             a 3-second tick that is a rename of /etc/hosts ~29,000 times a day"
        );

        // ...and the other direction, so "never writes" cannot pass this.
        assert!(
            hp.publish(&[Entry {
                address: "10.0.0.9".into(),
                hostnames: vec!["a".into()],
                confirmed_at: None,
            }])
            .unwrap(),
            "a changed address did not reach the file"
        );
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), first);
        assert!(std::fs::read_to_string(&path).unwrap().contains("10.0.0.9"));
    }

    /// PUB-1's foreign-entry half, which per-tick publication would
    /// otherwise turn from a slow leak into an immediate one: a line added
    /// outside the markers after the daemon started must survive -- and,
    /// because it is not a change to anything nixnet publishes, must not
    /// even cause a rewrite.
    #[test]
    fn a_line_added_outside_the_markers_survives_the_next_publication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "# static\n").unwrap();
        let hp = HostsPublisher::new(&path).unwrap();

        let entries = [Entry {
            address: "10.0.0.1".into(),
            hostnames: vec!["a".into()],
            confirmed_at: None,
        }];
        hp.publish(&entries).unwrap();

        let published = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            published.replace("# static\n", "# static\n192.0.2.7\tforeign\n"),
        )
        .unwrap();

        assert!(
            !hp.publish(&entries).unwrap(),
            "adding a foreign entry provoked a rewrite of the managed block"
        );
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("192.0.2.7\tforeign"),
            "an entry written outside nixnet's markers was deleted:\n{after}"
        );
        assert!(
            after.contains("10.0.0.1\ta"),
            "the managed block was lost:\n{after}"
        );
    }

    #[test]
    fn new_hosts_publisher_on_missing_file_has_empty_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let hp = HostsPublisher::new(&path).unwrap();
        assert_eq!(hp.static_prefix, "");
    }
}
