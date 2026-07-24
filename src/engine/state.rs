//! Mirrors `<stateDir>/state.json` -- the hysteresis counters and last
//! winners that let a killed/restarted daemon reconverge with no special
//! recovery code path. Loading this at startup is what makes that true:
//! without it, a restart would forget every transport's history and start
//! every state machine over at Unknown, needlessly re-running the up/down
//! thresholds it had already satisfied a moment before.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{EngineState, Group, TransportState};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct PersistedTransport {
    state: String,
    consecutive_success: i64,
    consecutive_failure: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct PersistedGroup {
    winner: i64, // -1 == none
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    winner_since: Option<OffsetDateTime>,
    degraded: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_published_address: String,
    transports: Vec<PersistedTransport>,
}

impl Default for PersistedGroup {
    fn default() -> Self {
        Self {
            winner: -1,
            winner_since: None,
            degraded: false,
            last_published_address: String::new(),
            transports: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct PersistedState {
    peers: HashMap<String, PersistedGroup>,
    uplinks: HashMap<String, PersistedGroup>,
}

/// Not a pinned wire format (unlike config.json) -- state.json is only
/// ever written and read by this same daemon, so an RFC3339 round trip
/// (rather than Go's byte-identical `time.Time` JSON encoding) is
/// sufficient.
mod rfc3339_opt {
    use super::{OffsetDateTime, Rfc3339};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(t) => {
                let formatted = t.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
                s.serialize_str(&formatted)
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) if !s.is_empty() => OffsetDateTime::parse(&s, &Rfc3339)
                .map(Some)
                .map_err(serde::de::Error::custom),
            _ => Ok(None),
        }
    }
}

impl super::Engine {
    /// Best-effort by design: a missing or corrupt state.json (first boot
    /// ever, or a manually-cleared state dir) just means every group
    /// starts fresh at Unknown/no-winner -- never a fatal error.
    pub(super) fn load_state(path: &Path, state: &mut EngineState) {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let ps: PersistedState = match serde_json::from_slice(&data) {
            Ok(p) => p,
            Err(e) => {
                crate::logf!("state: ignoring unreadable {}: {}", path.display(), e);
                return;
            }
        };
        restore(&mut state.peers, &ps.peers);
        restore(&mut state.uplinks, &ps.uplinks);
    }

    /// Writes the full state atomically. Callers must hold the lock.
    pub(super) fn save_state_locked(&self, state: &EngineState) {
        let ps = PersistedState {
            peers: dump(&state.peers),
            uplinks: dump(&state.uplinks),
        };

        let mut data = match serde_json::to_vec_pretty(&ps) {
            Ok(d) => d,
            Err(e) => {
                crate::logf!("state: marshal failed: {}", e);
                return;
            }
        };
        data.push(b'\n');

        let dir = self.state_path.parent().unwrap_or_else(|| Path::new("."));
        if let Err(e) =
            crate::atomic::write_no_chmod(dir, &self.state_path, &data, ".state.json.tmp-")
        {
            crate::logf!("state: {}", e);
        }
    }
}

fn restore(groups: &mut HashMap<String, Group>, saved: &HashMap<String, PersistedGroup>) {
    for (name, g) in groups.iter_mut() {
        let pg = match saved.get(name) {
            Some(pg) => pg,
            None => continue,
        };
        g.winner = if pg.winner >= 0 && (pg.winner as usize) < g.transports.len() {
            Some(pg.winner as usize)
        } else {
            None // transports list shrank across a config change, or there was never a winner
        };
        g.winner_since = pg.winner_since;
        g.degraded = pg.degraded;
        g.last_published_addr = pg.last_published_address.clone();
        for (i, pt) in pg.transports.iter().enumerate() {
            if i >= g.transports.len() {
                break;
            }
            let tr = &mut g.transports[i];
            tr.state = match pt.state.as_str() {
                "up" => TransportState::Up,
                "down" => TransportState::Down,
                _ => TransportState::Unknown,
            };
            tr.consecutive_success = pt.consecutive_success;
            tr.consecutive_failure = pt.consecutive_failure;
            tr.current_address = pt.address.clone();
        }
    }
}

fn dump(groups: &HashMap<String, Group>) -> HashMap<String, PersistedGroup> {
    let mut out = HashMap::new();
    for (name, g) in groups {
        let mut pg = PersistedGroup {
            winner: g.winner.map(|w| w as i64).unwrap_or(-1),
            winner_since: g.winner_since,
            degraded: g.degraded,
            last_published_address: g.last_published_addr.clone(),
            transports: Vec::with_capacity(g.transports.len()),
        };
        for tr in &g.transports {
            pg.transports.push(PersistedTransport {
                state: tr.state.as_str().to_string(),
                consecutive_success: tr.consecutive_success,
                consecutive_failure: tr.consecutive_failure,
                address: tr.current_address.clone(),
            });
        }
        out.insert(name.clone(), pg);
    }
    out
}
