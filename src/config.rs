//! Loads nixnet's runtime configuration from a JSON file (normally
//! `/etc/nixnet/config.json`, rendered from Nix at build/activation time --
//! see `modules/core.nix`). `nixnetd` itself is entirely Nix-unaware: it
//! only ever reads this JSON file and never has any dependency on Nix, so
//! the same binary works from a Nix-rendered config, a hand-written one, or
//! a system-manager render.
//!
//! Field names and JSON shape are pinned byte-for-byte against
//! `testdata/nix-rendered-example.json`, the actual `nix eval`-captured
//! fixture this port's regression test (`tests/config_test.rs`) reuses.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Deserializer};

/// `onAllDown` values, peers only.
pub const ON_ALL_DOWN_LAST_KNOWN_GOOD: &str = "lastKnownGood";
pub const ON_ALL_DOWN_UNPUBLISH: &str = "unpublish";

/// Nix renders every `nullOr types.str` option as an explicit JSON `null`
/// when unset. Go's `encoding/json` leaves a plain (non-pointer) `string`
/// field at its zero value (`""`) when the JSON value is `null` -- this
/// deserializer reproduces that exact behavior for the handful of fields
/// that are `nullOr types.str` on the Nix side (address, interface, target,
/// providerId, exec) instead of requiring `Option<String>` everywhere and
/// pushing `.unwrap_or_default()` out to every call site, matching how the
/// Go struct fields are plain `string` throughout.
fn null_as_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

/// Probe is the shared health-check descriptor attached to every transport.
/// Field names and defaults mirror the `probe` submodule in
/// `modules/core.nix`'s `transportType` exactly.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Probe {
    pub method: String,
    #[serde(deserialize_with = "null_as_empty_string")]
    pub target: String,
    pub port: i64,
    pub path: String,
    pub bind_to_interface: bool,
    pub interval_ms: i64,
    pub timeout_ms: i64,
    pub up_threshold: i64,
    pub down_threshold: i64,
    /// A full command line (`"<absolute-nix-store-path> arg1 arg2 ..."`),
    /// not a bare path -- see `docs/providers.md`'s "Deviation: probe.exec
    /// is a command line, not a bare path" for why this departs from a
    /// literal `types.path`. Tokenized and exec'd directly (never via a
    /// shell) by `crate::probe`.
    #[serde(deserialize_with = "null_as_empty_string")]
    pub exec: String,
}

impl Probe {
    /// Fills in the handful of fields a hand-written config.json is
    /// allowed to omit. `def` is the already-defaulted
    /// `daemon.defaultProbe`, mirroring the Nix side's default chain
    /// field-for-field.
    fn apply_defaults(&mut self, def: &DefaultProbe) {
        if self.method.is_empty() {
            self.method = "tcp".to_string();
        }
        if self.port == 0 {
            self.port = 22;
        }
        if self.path.is_empty() {
            self.path = "/".to_string();
        }
        if self.interval_ms == 0 {
            self.interval_ms = def.interval_ms;
        }
        if self.timeout_ms == 0 {
            self.timeout_ms = def.timeout_ms;
        }
        if self.up_threshold == 0 {
            self.up_threshold = def.up_threshold;
        }
        if self.down_threshold == 0 {
            self.down_threshold = def.down_threshold;
        }
    }
}

/// Transport is the one candidate-transport abstraction shared verbatim by
/// peers and uplinks.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Transport {
    #[serde(deserialize_with = "null_as_empty_string")]
    pub address: String,
    #[serde(deserialize_with = "null_as_empty_string")]
    pub interface: String,
    pub priority: i64,
    #[serde(deserialize_with = "null_as_empty_string")]
    pub provider_id: String,
    pub probe: Probe,
}

impl Transport {
    /// What should actually be dialed/pinged/exec'd for this transport:
    /// `probe.target` if set, else `address`. A Nix-rendered config already
    /// resolves this (`transportType` sets `probe.target = mkDefault
    /// address`); this is the hand-written-JSON fallback.
    pub fn effective_target(&self) -> &str {
        if !self.probe.target.is_empty() {
            &self.probe.target
        } else {
            &self.address
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Hysteresis {
    pub min_hold_ms: i64,
}

impl Hysteresis {
    fn apply_default(&mut self, def: i64) {
        if self.min_hold_ms == 0 {
            self.min_hold_ms = def;
        }
    }
}

/// STALE-2's bound, per peer. Absent/`null` means unbounded -- the
/// eleven-day leak this option exists to close, kept as the DEFAULT only
/// because no measurement justifies a number and inventing one would be
/// worse than making the operator choose. `modules/core.nix` warns at eval
/// time when it is left unset, so nobody arrives here by accident.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LastKnownGood {
    /// How long a last-known-good address may keep being published after
    /// the last successful probe that confirmed it. `None` == forever.
    pub max_age_sec: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Peer {
    pub hostnames: Vec<String>,
    pub transports: Vec<Transport>,
    pub hysteresis: Hysteresis,
    pub on_all_down: String,
    pub last_known_good: LastKnownGood,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UplinkPublish {
    pub route_metric: bool,
    pub metric_base: i64,
    pub metric_step: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Uplink {
    pub transports: Vec<Transport>,
    pub hysteresis: Hysteresis,
    pub publish: UplinkPublish,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DefaultProbe {
    pub interval_ms: i64,
    pub timeout_ms: i64,
    pub up_threshold: i64,
    pub down_threshold: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Daemon {
    pub state_dir: String,
    pub runtime_dir: String,
    pub hosts_file: String,
    /// Absolute path to the `ip` binary used for uplink route-metric
    /// publish. Falls back to `"ip"` (PATH lookup) for the hand-written
    /// config / non-Nix case.
    pub ip_path: String,
    pub default_probe: DefaultProbe,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub daemon: Daemon,
    pub peers: HashMap<String, Peer>,
    pub uplinks: HashMap<String, Uplink>,
}

#[derive(Debug)]
pub enum ConfigError {
    Read(String, std::io::Error),
    Parse(String, serde_json::Error),
    Validate(String, String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read(path, e) => write!(f, "reading config {}: {}", path, e),
            ConfigError::Parse(path, e) => write!(f, "parsing config {}: {}", path, e),
            ConfigError::Validate(path, e) => write!(f, "validating config {}: {}", path, e),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Reads and validates a config.json from `path`.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let display = path.display().to_string();
    let data = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(display.clone(), e))?;
    let mut cfg: Config =
        serde_json::from_str(&data).map_err(|e| ConfigError::Parse(display.clone(), e))?;
    cfg.apply_defaults();
    cfg.validate()
        .map_err(|e| ConfigError::Validate(display.clone(), e))?;
    Ok(cfg)
}

impl Config {
    fn apply_defaults(&mut self) {
        if self.daemon.state_dir.is_empty() {
            self.daemon.state_dir = "/var/lib/nixnet".to_string();
        }
        if self.daemon.runtime_dir.is_empty() {
            self.daemon.runtime_dir = "nixnet".to_string();
        }
        if self.daemon.hosts_file.is_empty() {
            self.daemon.hosts_file = "/run/nixnet/hosts".to_string();
        }
        if self.daemon.ip_path.is_empty() {
            self.daemon.ip_path = "ip".to_string();
        }
        if self.daemon.default_probe.interval_ms == 0 {
            self.daemon.default_probe.interval_ms = 3000;
        }
        if self.daemon.default_probe.timeout_ms == 0 {
            self.daemon.default_probe.timeout_ms = 800;
        }
        if self.daemon.default_probe.up_threshold == 0 {
            self.daemon.default_probe.up_threshold = 2;
        }
        if self.daemon.default_probe.down_threshold == 0 {
            self.daemon.default_probe.down_threshold = 3;
        }

        let default_probe = self.daemon.default_probe.clone();
        for peer in self.peers.values_mut() {
            if peer.on_all_down.is_empty() {
                peer.on_all_down = ON_ALL_DOWN_LAST_KNOWN_GOOD.to_string();
            }
            peer.hysteresis.apply_default(10_000);
            for t in peer.transports.iter_mut() {
                t.probe.apply_defaults(&default_probe);
                // peer transports only: target falls back to the
                // transport's own address if still empty.
                if t.probe.target.is_empty() {
                    t.probe.target = t.address.clone();
                }
            }
        }

        for uplink in self.uplinks.values_mut() {
            uplink.hysteresis.apply_default(15_000);
            if uplink.publish.metric_base == 0 {
                uplink.publish.metric_base = 100;
            }
            if uplink.publish.metric_step == 0 {
                uplink.publish.metric_step = 10;
            }
            for t in uplink.transports.iter_mut() {
                t.probe.apply_defaults(&default_probe);
            }
        }
    }

    /// Re-checks the build-time assertions `modules/core.nix` already
    /// enforces at eval time. Re-checking here is what makes the
    /// "hand-written config.json" adoption path actually safe to use
    /// standalone, rather than silently trusting Nix to have been the one
    /// who wrote the file.
    fn validate(&self) -> Result<(), String> {
        let mut seen_hostnames: HashMap<String, String> = HashMap::new();
        // Sort peer names for deterministic error messages -- Go's map
        // iteration is randomized, so this is a small, harmless
        // improvement over the source, not a behavior a test depends on.
        let mut peer_names: Vec<&String> = self.peers.keys().collect();
        peer_names.sort();
        for name in peer_names {
            let p = &self.peers[name];
            if p.hostnames.is_empty() {
                return Err(format!("peer \"{}\": hostnames must not be empty", name));
            }
            for h in &p.hostnames {
                if let Some(owner) = seen_hostnames.get(h) {
                    return Err(format!(
                        "hostname \"{}\" claimed by both peer \"{}\" and peer \"{}\"",
                        h, owner, name
                    ));
                }
                seen_hostnames.insert(h.clone(), name.clone());
            }
            for (i, t) in p.transports.iter().enumerate() {
                validate_probe(&t.probe)
                    .map_err(|e| format!("peer \"{}\" transport[{}]: {}", name, i, e))?;
            }
            if p.on_all_down != ON_ALL_DOWN_LAST_KNOWN_GOOD
                && p.on_all_down != ON_ALL_DOWN_UNPUBLISH
            {
                return Err(format!(
                    "peer \"{}\": onAllDown must be \"{}\" or \"{}\", got \"{}\"",
                    name, ON_ALL_DOWN_LAST_KNOWN_GOOD, ON_ALL_DOWN_UNPUBLISH, p.on_all_down
                ));
            }
            // A zero or negative bound is not "expire immediately" -- that
            // is what `onAllDown = "unpublish"` is for, and reading it as
            // such here would silently turn a typo into a policy change on
            // the one path whose whole job is to keep a name resolving.
            // The Nix type (`ints.positive`) already rejects it; this is
            // the same check for the hand-written-config.json path.
            if let Some(v) = p.last_known_good.max_age_sec {
                if v <= 0 {
                    return Err(format!(
                        "peer \"{}\": lastKnownGood.maxAgeSec must be positive (got {}); \
                         use onAllDown = \"{}\" to withdraw immediately",
                        name, v, ON_ALL_DOWN_UNPUBLISH
                    ));
                }
            }
        }

        let mut uplink_names: Vec<&String> = self.uplinks.keys().collect();
        uplink_names.sort();
        for name in uplink_names {
            let u = &self.uplinks[name];
            for (i, t) in u.transports.iter().enumerate() {
                if t.interface.is_empty() {
                    return Err(format!(
                        "uplink \"{}\" transport[{}]: interface is required",
                        name, i
                    ));
                }
                validate_probe(&t.probe)
                    .map_err(|e| format!("uplink \"{}\" transport[{}]: {}", name, i, e))?;
                if t.probe.method != "exec" && t.probe.target.is_empty() {
                    return Err(format!(
                        "uplink \"{}\" transport[{}]: probe.target is required (address has no default here)",
                        name, i
                    ));
                }
            }
        }
        Ok(())
    }

    /// Reports whether any uplink group needs `CAP_NET_ADMIN` to
    /// reprioritize route metrics.
    pub fn needs_net_admin(&self) -> bool {
        self.uplinks.values().any(|u| u.publish.route_metric)
    }

    /// Reports whether any transport needs `CAP_NET_RAW` for ICMP or
    /// `SO_BINDTODEVICE` probing.
    pub fn needs_net_raw(&self) -> bool {
        let transport_needs = |t: &Transport| t.probe.method == "icmp" || t.probe.bind_to_interface;
        if self
            .peers
            .values()
            .any(|p| p.transports.iter().any(transport_needs))
        {
            return true;
        }
        self.uplinks
            .values()
            .any(|u| u.transports.iter().any(transport_needs))
    }
}

fn validate_probe(p: &Probe) -> Result<(), String> {
    match p.method.as_str() {
        "tcp" | "icmp" | "http" | "exec" => {}
        other => {
            return Err(format!(
                "probe.method \"{}\" is not one of tcp|icmp|http|exec",
                other
            ))
        }
    }
    if p.method == "exec" && p.exec.is_empty() {
        return Err("probe.method=exec requires probe.exec".to_string());
    }
    Ok(())
}
