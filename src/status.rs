//! Renders `/run/nixnet/status.json` -- the live health snapshot
//! `nixnetctl` reads. There is no control socket; reading the file directly
//! is sufficient and keeps the daemon's listening surface at zero sockets.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Named distinctly from `config::Transport` -- same name collision exists
/// across the two Go packages (`status.Transport` / `config.Transport`),
/// kept apart here to avoid any ambiguity a `use` of both modules could
/// otherwise introduce.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusTransport {
    /// "up" | "down" | "unknown"
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub winner: String,
    /// When this winner was SELECTED.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub since: String,
    /// STALE-1: when a successful probe last CONFIRMED the published
    /// value. Distinct from `since` (selection) and from the snapshot's
    /// `generatedAt` (the write): a reader needs the confirmation time to
    /// compute an age, and a value with no age is indistinguishable from a
    /// current one -- which is how an address dead for eleven days kept
    /// being served as if it were fine.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_confirmed_at: String,
    /// The last error while applying this group's published state. For
    /// uplinks this is a route-metric publication failure; peer publication
    /// errors are shared across the hosts file and live on the snapshot.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_publish_error: String,
    pub degraded: bool,
    pub transports: HashMap<String, StatusTransport>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    /// The managed hosts file is one shared artifact for every peer group,
    /// so a failure to write it is a snapshot-wide error rather than an
    /// error attributable to whichever peer's tick discovered it.
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "lastHostsPublishError"
    )]
    pub last_hosts_publish_error: String,
    pub peers: HashMap<String, Group>,
    pub uplinks: HashMap<String, Group>,
}

/// Atomically publishes `snap` to `path` -- the same "write .tmp, fsync,
/// rename()" discipline as the hosts file, since `status.json` is read by
/// `nixnetctl` at arbitrary times and must never be observed half-written.
/// Unlike the hosts file, no explicit chmod is applied here (inherits the
/// temp file's default permissions) -- matching the Go original's
/// asymmetry exactly, not "fixing" it to be consistent.
pub fn write(path: &Path, mut snap: Snapshot) -> io::Result<()> {
    snap.generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();

    let mut data = serde_json::to_vec_pretty(&snap)?;
    data.push(b'\n');

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    crate::atomic::write_no_chmod(dir, path, &data, ".status.json.tmp-")
}

/// Loads a previously-written status.json -- used by `nixnetctl`.
pub fn read(path: &Path) -> io::Result<Snapshot> {
    let data = std::fs::read(path)?;
    serde_json::from_slice(&data).map_err(io::Error::from)
}
