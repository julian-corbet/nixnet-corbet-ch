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

use super::{EngineState, Group, GroupKind, TransportState};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct PersistedTransport {
    /// Stable transport identity. State files written before this field
    /// intentionally cold-start rather than guessing by list position.
    id: String,
    state: String,
    consecutive_success: i64,
    consecutive_failure: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    last_success_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct PersistedGroup {
    #[serde(skip_serializing_if = "String::is_empty")]
    winner_id: String,
    /// Accepted only so an old state file remains parseable. It is never
    /// used for restore: list position is not identity.
    #[serde(rename = "winner", skip_serializing)]
    _legacy_winner: i64,
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    winner_since: Option<OffsetDateTime>,
    /// STALE-2: when a successful probe last confirmed
    /// `last_published_address`. Persisted because the whole point of the
    /// bound is that it survives a restart -- an age that resets to zero
    /// whenever the process does is not a bound, it is a restart counter.
    /// Also read by the boot-time hosts seed in `modules/core.nix`, which
    /// publishes from this same file before the daemon exists.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    confirmed_at: Option<OffsetDateTime>,
    degraded: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_published_address: String,
    transports: Vec<PersistedTransport>,
}

impl Default for PersistedGroup {
    fn default() -> Self {
        Self {
            winner_id: String::new(),
            _legacy_winner: -1,
            winner_since: None,
            confirmed_at: None,
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
    /// Best-effort by design: a missing, unreadable or corrupt state.json
    /// is a logged COLD START, never an error and never a crash loop. This
    /// is the layer that makes the host reachable at all -- a daemon that
    /// refuses to run because a cache file is malformed takes the machine
    /// off the network to protect the accuracy of an optimisation, and
    /// under `Restart=always` it does so once a second until
    /// `start-limit-hit`. Every group simply starts fresh at
    /// Unknown/no-winner, which costs one probe interval and cannot be
    /// wrong.
    pub(super) fn load_state(path: &Path, state: &mut EngineState) {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            // A first-ever boot is silent: NotFound is the expected state
            // of a host that has never run this daemon, not an incident.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                crate::logf!(
                    "state: COLD START -- cannot read {}: {} (every group starts at unknown)",
                    path.display(),
                    e
                );
                return;
            }
        };
        let ps: PersistedState = match serde_json::from_slice(&data) {
            Ok(p) => p,
            Err(e) => {
                crate::logf!(
                    "state: COLD START -- {} is unparseable: {} (every group starts at unknown)",
                    path.display(),
                    e
                );
                return;
            }
        };
        restore(&mut state.peers, &ps.peers);
        restore(&mut state.uplinks, &ps.uplinks);
    }

    /// Writes the full state atomically. Callers must hold the lock.
    pub(super) fn save_state_locked(&self, state: &EngineState) {
        if let Some(data) = serialized_state(state) {
            let _ = self.write_state_data(&data);
        }
    }

    /// Runtime persistence path: snapshot under the state mutex, then fsync
    /// and rename with no engine-state lock held. `last_state_write` is
    /// also the writer lock, preventing an older concurrent snapshot from
    /// landing after a newer one without delaying route/hosts publication.
    pub(super) fn save_state(&self, force: bool) {
        let mut last = self.last_state_write.lock().unwrap();
        if !force && last.is_some_and(|time| time.elapsed() < std::time::Duration::from_secs(15)) {
            return;
        }
        let data = {
            let state = self.state.lock().unwrap();
            serialized_state(&state)
        };
        if let Some(data) = data {
            if self.write_state_data(&data) {
                *last = Some(std::time::Instant::now());
            }
        }
    }

    fn write_state_data(&self, data: &[u8]) -> bool {
        let dir = self.state_path.parent().unwrap_or_else(|| Path::new("."));
        if let Err(e) =
            crate::atomic::write_no_chmod(dir, &self.state_path, data, ".state.json.tmp-")
        {
            crate::logf!("state: {}", e);
            return false;
        }
        true
    }
}

fn serialized_state(state: &EngineState) -> Option<Vec<u8>> {
    let ps = PersistedState {
        peers: dump(&state.peers),
        uplinks: dump(&state.uplinks),
    };

    let mut data = match serde_json::to_vec_pretty(&ps) {
        Ok(d) => d,
        Err(e) => {
            crate::logf!("state: marshal failed: {}", e);
            return None;
        }
    };
    data.push(b'\n');
    Some(data)
}

fn restore(groups: &mut HashMap<String, Group>, saved: &HashMap<String, PersistedGroup>) {
    let now = OffsetDateTime::now_utc();
    for (name, g) in groups.iter_mut() {
        let pg = match saved.get(name) {
            Some(pg) => pg,
            None => continue,
        };
        g.winner = if pg.winner_id.is_empty() {
            None
        } else {
            g.transports.iter().position(|tr| tr.key == pg.winner_id)
        };
        g.winner_since = pg.winner_since;
        g.last_confirmed_at = pg.confirmed_at;
        g.degraded = pg.degraded;
        g.last_published_addr = pg.last_published_address.clone();
        expire_restored_last_known_good(name, g, now);
        let saved_by_id: HashMap<&str, &PersistedTransport> = pg
            .transports
            .iter()
            .filter(|tr| !tr.id.is_empty())
            .map(|tr| (tr.id.as_str(), tr))
            .collect();
        let mut winner_static_address_changed = false;
        for (i, tr) in g.transports.iter_mut().enumerate() {
            let Some(pt) = saved_by_id.get(tr.key.as_str()).copied() else {
                continue;
            };
            tr.state = match pt.state.as_str() {
                "up" => TransportState::Up,
                "down" => TransportState::Down,
                _ => TransportState::Unknown,
            };
            tr.consecutive_success = pt.consecutive_success;
            tr.consecutive_failure = pt.consecutive_failure;
            tr.last_success_at = pt.last_success_at;

            // A configured address is the declaration, not a cache hint.
            // Restoring an old effective address over it made an edited
            // static peer keep publishing its previous address after a
            // restart. Dynamic exec transports deliberately leave
            // `spec.address` empty, so their last discovered address still
            // restores from state while their provider is unavailable.
            if tr.spec.address.is_empty() {
                tr.current_address = pt.address.clone();
            } else {
                // Older state files did not persist `address`. An empty
                // cache therefore says "unknown", not "different"; it
                // cannot invalidate a valid last-known-good static peer.
                let changed = !pt.address.is_empty() && tr.spec.address != pt.address;
                tr.current_address = tr.spec.address.clone();
                if changed {
                    tr.state = TransportState::Unknown;
                    tr.consecutive_success = 0;
                    tr.consecutive_failure = 0;
                    tr.detail.clear();
                    winner_static_address_changed |= g.winner == Some(i);
                }
            }
        }

        // The old format named its winner and transports by list position.
        // Reusing that evidence after a reorder is worse than a cold start:
        // it can immediately publish the wrong address or promote the wrong
        // uplink. A missing current winner therefore invalidates the group
        // publication, while individually matched transports may still keep
        // their own counters.
        if g.winner.is_none() && !g.last_published_addr.is_empty() {
            g.winner_since = None;
            g.last_published_addr.clear();
            g.last_confirmed_at = None;
            g.degraded = true;
        }

        if winner_static_address_changed {
            // The persisted winner and confirmation were evidence about
            // the OLD endpoint. Publish neither the old address nor a new
            // one that has not yet passed a probe; the next probe chooses
            // and publishes the declared address normally.
            g.winner = None;
            g.winner_since = None;
            g.last_published_addr.clear();
            g.last_confirmed_at = None;
            g.degraded = true;
        }
    }
}

/// STALE-2, the half everyone forgets: the age bound applies to state
/// RESTORED FROM DISK, not only to time that elapsed while this process
/// was running. Without this, `run()`'s startup re-assert reads the last
/// winner straight back out of state.json and republishes it, so every
/// restart launders a stale entry into a fresh-looking one and the live
/// bound is decorative -- which is precisely how one address stayed
/// published for eleven days across every restart that might have cleared
/// it.
///
/// Deliberately independent of the persisted `degraded` flag: an entry
/// confirmed a month ago is too old whether or not the daemon had noticed
/// it was failing before it stopped. The machine being powered off is not
/// evidence that the peer was fine.
fn expire_restored_last_known_good(name: &str, g: &mut Group, now: OffsetDateTime) {
    if g.kind != GroupKind::Peer
        || g.on_all_down != crate::config::ON_ALL_DOWN_LAST_KNOWN_GOOD
        || g.last_published_addr.is_empty()
    {
        return;
    }
    let verdict = super::staleness(g.max_age_sec, g.last_confirmed_at, now);
    if verdict == super::Staleness::Fresh {
        return;
    }
    crate::logf!(
        "group=peer={} lastKnownGood WITHDRAWN on restore addr={} age={} bound={}s: \
         restarting does not make an unconfirmed address current",
        name,
        g.last_published_addr,
        super::staleness_age_label(verdict),
        g.max_age_sec.unwrap_or_default()
    );
    g.last_published_addr.clear();
    g.winner = None;
}

fn dump(groups: &HashMap<String, Group>) -> HashMap<String, PersistedGroup> {
    let mut out = HashMap::new();
    for (name, g) in groups {
        let mut pg = PersistedGroup {
            winner_id: g
                .winner
                .map(|w| g.transports[w].key.clone())
                .unwrap_or_default(),
            _legacy_winner: -1,
            winner_since: g.winner_since,
            confirmed_at: g.last_confirmed_at,
            degraded: g.degraded,
            last_published_address: g.last_published_addr.clone(),
            transports: Vec::with_capacity(g.transports.len()),
        };
        for tr in &g.transports {
            pg.transports.push(PersistedTransport {
                id: tr.key.clone(),
                state: tr.state.as_str().to_string(),
                consecutive_success: tr.consecutive_success,
                consecutive_failure: tr.consecutive_failure,
                address: tr.current_address.clone(),
                last_success_at: tr.last_success_at,
            });
        }
        out.insert(name.clone(), pg);
    }
    out
}

#[cfg(test)]
mod tests {
    //! STALE-2's restore-from-disk half, tested beside the code that
    //! implements it. This is the path the production defect lived in: the
    //! running daemon's bound can be perfect and still be decorative if a
    //! restart reads the entry straight back out of this file, which is
    //! how one address stayed published for eleven days across every
    //! restart that might have cleared it. A green live-path test while
    //! this path is broken is the exact shape of that bug.

    use std::collections::HashMap;

    use time::format_description::well_known::Rfc3339;

    use super::super::tests::{add_transport, ago, new_peer_group, new_test_engine};
    use super::super::{Engine, EngineState, Group, GroupKind};
    use crate::config;
    use crate::publish::{HostsPublisher, RoutePublisher};

    /// Writes a state.json BY HAND rather than round-tripping through
    /// `save_state_locked`: this pins the ON-DISK format, so renaming
    /// `confirmedAt` shows up here as a failing restore instead of as a
    /// silently unbounded entry in production. `consecutiveFailure` is the
    /// real incident's count, not decoration -- it is what a peer that has
    /// been unreachable for eleven days actually looks like on disk.
    fn write_state_json(
        path: &std::path::Path,
        addr: &str,
        confirmed_at: Option<&str>,
        degraded: bool,
    ) {
        let confirmed = match confirmed_at {
            Some(ts) => format!(",\n        \"confirmedAt\": \"{ts}\""),
            None => String::new(),
        };
        let transport_confirmed = match confirmed_at {
            Some(ts) => format!(", \"lastSuccessAt\": \"{ts}\""),
            None => String::new(),
        };
        std::fs::write(
            path,
            format!(
                r#"{{
  "peers": {{
    "host-b": {{
      "winnerId": "{addr}",
      "degraded": {degraded},
      "lastPublishedAddress": "{addr}"{confirmed},
      "transports": [ {{ "id": "{addr}", "state": "down", "consecutiveSuccess": 0, "consecutiveFailure": 48000{transport_confirmed} }} ]
    }}
  }},
  "uplinks": {{}}
}}
"#
            ),
        )
        .unwrap();
    }

    fn rfc3339_ago(secs: i64) -> String {
        ago(secs).format(&Rfc3339).unwrap()
    }

    /// Startup, as `Engine::new` performs it: build the configured groups,
    /// then load whatever the last run left behind. Returns the restored
    /// peer group AND a live Engine over it, because "was it dropped from
    /// state" and "did it reach the hosts file" are different claims and
    /// only the second is what a consumer experiences.
    fn restart_with_state(
        max_age_sec: Option<i64>,
        confirmed_at: Option<&str>,
        degraded: bool,
    ) -> (Engine, tempfile::TempDir) {
        let (eng, dir) = new_test_engine();
        write_state_json(&eng.state_path, "192.0.2.10", confirmed_at, degraded);

        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        g.max_age_sec = max_age_sec;
        let winner = add_transport(&mut g, 10, "192.0.2.10");
        g.winner = Some(winner);
        let mut state = EngineState {
            peers: HashMap::from([("host-b".to_string(), g)]),
            uplinks: HashMap::new(),
            ..Default::default()
        };
        Engine::load_state(&eng.state_path, &mut state);
        *eng.state.lock().unwrap() = state;
        (eng, dir)
    }

    fn restored_peer(eng: &Engine) -> Group {
        let mut state = eng.state.lock().unwrap();
        state.peers.remove("host-b").expect("peer group exists")
    }

    /// Runs the startup re-assert and returns what actually landed in the
    /// hosts file.
    fn published_after_startup(eng: &Engine, dir: &tempfile::TempDir) -> String {
        eng.publish_restored_peers();
        std::fs::read_to_string(dir.path().join("hosts")).unwrap_or_default()
    }

    /// THE part everyone forgets, and the reason this behaviour exists.
    /// Without an age check on this path the startup re-assert reads the
    /// last winner back out of state.json and republishes it, so every
    /// restart launders a stale entry into a fresh-looking one and the
    /// live bound expires nothing that a reboot cannot undo.
    #[test]
    fn restore_drops_a_last_known_good_older_than_the_bound() {
        let (eng, dir) = restart_with_state(Some(60), Some(&rfc3339_ago(11 * 24 * 3600)), true);

        let published = published_after_startup(&eng, &dir);
        assert!(
            !published.contains("192.0.2.10"),
            "a restart re-published an eleven-day-old address:\n{published}"
        );

        let g = restored_peer(&eng);
        assert_eq!(
            g.last_published_addr, "",
            "a restart resurrected an eleven-day-old address"
        );
        assert_eq!(g.winner, None, "the winner pointer resurrects it too");
    }

    /// The direction that stops all of this from being satisfied by a
    /// restore that simply drops everything. A restart during a brief
    /// outage must not cost the last-known-good that the policy exists to
    /// provide -- so the entry survives AND is published again.
    #[test]
    fn restore_keeps_a_last_known_good_inside_the_bound() {
        let (eng, dir) = restart_with_state(Some(3600), Some(&rfc3339_ago(30)), true);

        let published = published_after_startup(&eng, &dir);
        assert!(
            published.contains("192.0.2.10"),
            "a restart inside the bound lost the last-known-good it exists \
             to preserve:\n{published}"
        );

        let g = restored_peer(&eng);
        assert_eq!(g.last_published_addr, "192.0.2.10");
        assert_eq!(g.winner, Some(0));
        assert!(
            g.last_confirmed_at.is_some(),
            "the confirmation time itself must survive the restart, or the \
             next tick's age is computed from nothing and the entry expires \
             for the wrong reason"
        );
    }

    /// Expiry on restore does not consult the persisted `degraded` flag,
    /// and this is the pair of tests that pins it. `degraded = true` is
    /// the daemon having noticed the peer was failing before it stopped.
    #[test]
    fn restore_expires_an_old_entry_that_was_persisted_degraded() {
        let (eng, _dir) = restart_with_state(Some(60), Some(&rfc3339_ago(11 * 24 * 3600)), true);
        assert_eq!(restored_peer(&eng).last_published_addr, "");
    }

    /// ...and `degraded = false` is a daemon that was killed, or a machine
    /// powered off, while the peer still looked healthy. Being switched
    /// off for a month is not evidence that the peer was fine for that
    /// month, so the same age applies: an entry nothing has confirmed
    /// since is expired whichever way the flag was left.
    #[test]
    fn restore_expires_an_old_entry_that_was_persisted_healthy() {
        let (eng, dir) = restart_with_state(Some(60), Some(&rfc3339_ago(30 * 24 * 3600)), false);

        let published = published_after_startup(&eng, &dir);
        assert!(
            !published.contains("192.0.2.10"),
            "a month-old address was re-published because the last run \
             happened not to have marked it degraded yet:\n{published}"
        );
        assert_eq!(restored_peer(&eng).last_published_addr, "");
    }

    /// The genuinely ambiguous case, DECIDED: a bound is declared, but the
    /// state file records no confirmation time at all (written by a nixnet
    /// that predates the field). It is dropped rather than trusted --
    /// an entry that cannot be shown to be inside its bound is not inside
    /// it, and the cost of being wrong here is one probe interval of a
    /// name not resolving, versus eleven days of a wrong address resolving
    /// for the other reading. Only peers that declared a bound are
    /// affected, which is what keeps an upgrade from flushing a fleet.
    #[test]
    fn restore_drops_a_bounded_entry_with_no_confirmation_rather_than_trusting_it() {
        let (eng, _dir) = restart_with_state(Some(60), None, true);
        assert_eq!(restored_peer(&eng).last_published_addr, "");
    }

    /// The default is unbounded, and it must stay that way on this path
    /// too: taking a bound by default would change every existing
    /// deployment's behaviour at once, on the layer that decides whether a
    /// host can be reached at all.
    #[test]
    fn restore_keeps_an_unbounded_entry_however_old() {
        let (eng, dir) = restart_with_state(None, Some(&rfc3339_ago(11 * 24 * 3600)), true);

        let published = published_after_startup(&eng, &dir);
        assert!(
            published.contains("192.0.2.10"),
            "an entry with no declared bound was dropped on restore:\n{published}"
        );
        assert_eq!(restored_peer(&eng).last_published_addr, "192.0.2.10");
    }

    /// The confirmation time has to round-trip, or the bound restarts its
    /// clock on every save -- an entry that is always "just confirmed" is
    /// an entry with no bound at all. Asserts the FIELD NAME on disk too,
    /// because the boot-time hosts seed in `modules/core.nix` reads this
    /// same file with jq and cannot be type-checked against it.
    #[test]
    fn save_records_the_confirmation_time_and_load_reads_it_back() {
        let (eng, dir) = new_test_engine();
        let confirmed = ago(120);
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        g.last_published_addr = "192.0.2.10".into();
        g.last_confirmed_at = Some(confirmed);
        let winner = add_transport(&mut g, 10, "192.0.2.10");
        g.winner = Some(winner);
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

        {
            let state = eng.state.lock().unwrap();
            eng.save_state_locked(&state);
        }
        let on_disk = std::fs::read_to_string(dir.path().join("state.json")).unwrap();
        assert!(
            on_disk.contains("confirmedAt"),
            "state.json carries no confirmation time; the boot seed in \
             modules/core.nix reads this exact field name:\n{on_disk}"
        );

        let mut fresh_group = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        add_transport(&mut fresh_group, 10, "192.0.2.10");
        let mut fresh = EngineState {
            peers: HashMap::from([("host-b".to_string(), fresh_group)]),
            uplinks: HashMap::new(),
            ..Default::default()
        };
        Engine::load_state(&dir.path().join("state.json"), &mut fresh);
        assert_eq!(
            fresh.peers["host-b"]
                .last_confirmed_at
                .unwrap()
                .unix_timestamp(),
            confirmed.unix_timestamp(),
            "confirmation time did not survive a save/load round trip"
        );
    }

    #[test]
    fn restore_matches_transports_and_winner_by_stable_identity() {
        let (eng, dir) = new_test_engine();
        let mut original = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let lan = add_transport(&mut original, 10, "192.0.2.10");
        let overlay = add_transport(&mut original, 20, "100.64.0.10");
        original.transports[lan].state = super::TransportState::Down;
        original.transports[lan].consecutive_failure = 7;
        original.transports[overlay].state = super::TransportState::Up;
        original.transports[overlay].consecutive_success = 11;
        original.winner = Some(overlay);
        original.last_published_addr = "100.64.0.10".into();
        original.last_confirmed_at = Some(ago(5));
        eng.state
            .lock()
            .unwrap()
            .peers
            .insert("host-b".into(), original);
        {
            let state = eng.state.lock().unwrap();
            eng.save_state_locked(&state);
        }

        let mut reordered = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let overlay_now_first = add_transport(&mut reordered, 20, "100.64.0.10");
        let lan_now_second = add_transport(&mut reordered, 10, "192.0.2.10");
        let mut fresh = EngineState {
            peers: HashMap::from([("host-b".into(), reordered)]),
            uplinks: HashMap::new(),
            ..Default::default()
        };
        Engine::load_state(&dir.path().join("state.json"), &mut fresh);

        let restored = &fresh.peers["host-b"];
        assert_eq!(restored.winner, Some(overlay_now_first));
        assert_eq!(
            restored.transports[overlay_now_first].state,
            super::TransportState::Up
        );
        assert_eq!(
            restored.transports[overlay_now_first].consecutive_success,
            11
        );
        assert_eq!(
            restored.transports[lan_now_second].state,
            super::TransportState::Down
        );
        assert_eq!(restored.transports[lan_now_second].consecutive_failure, 7);
    }

    #[test]
    fn legacy_position_only_state_cold_starts_instead_of_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(
            &path,
            r#"{"peers":{"host-b":{"winner":0,"degraded":false,
              "lastPublishedAddress":"192.0.2.10",
              "transports":[{"state":"up","address":"192.0.2.10"}]}},"uplinks":{}}"#,
        )
        .unwrap();
        let mut group = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        add_transport(&mut group, 10, "192.0.2.10");
        let mut state = EngineState {
            peers: HashMap::from([("host-b".into(), group)]),
            uplinks: HashMap::new(),
            ..Default::default()
        };

        Engine::load_state(&path, &mut state);
        let restored = &state.peers["host-b"];
        assert_eq!(restored.winner, None);
        assert_eq!(restored.last_published_addr, "");
        assert_eq!(restored.transports[0].state, super::TransportState::Unknown);
    }

    #[test]
    fn steady_confirmation_ticks_are_checkpointed_not_fsynced_every_tick() {
        let (eng, dir) = new_test_engine();
        let mut group = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let winner = add_transport(&mut group, 10, "192.0.2.10");
        group.winner = Some(winner);
        group.last_published_addr = "192.0.2.10".into();
        group.last_confirmed_at = Some(ago(10));
        eng.state
            .lock()
            .unwrap()
            .peers
            .insert("host-b".into(), group);

        eng.save_state(false);
        let path = dir.path().join("state.json");
        let first = std::fs::read(&path).unwrap();
        eng.state
            .lock()
            .unwrap()
            .peers
            .get_mut("host-b")
            .unwrap()
            .last_confirmed_at = Some(OffsetDateTime::now_utc());
        eng.save_state(false);
        assert_eq!(std::fs::read(&path).unwrap(), first);

        eng.save_state(true);
        assert_ne!(std::fs::read(&path).unwrap(), first);
    }

    /// A corrupt state file is a logged COLD START, never an error and
    /// never a crash loop: this is the layer that makes the host reachable
    /// at all, and under `Restart=always` a refusal to start is a machine
    /// that never comes back.
    #[test]
    fn a_corrupt_state_file_is_a_cold_start_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, "{ this is not json at all ][").unwrap();

        let mut state = EngineState {
            peers: HashMap::from([(
                "host-b".to_string(),
                new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD),
            )]),
            uplinks: HashMap::new(),
            ..Default::default()
        };
        Engine::load_state(&path, &mut state);

        let g = &state.peers["host-b"];
        assert_eq!(g.winner, None);
        assert_eq!(g.last_published_addr, "");
        assert_eq!(g.last_confirmed_at, None);
    }

    /// An uplink group has no retained name to expire, and must never
    /// acquire one by accident: `expire_restored_last_known_good` keys on
    /// `GroupKind::Peer`, and this is what would catch that key being
    /// dropped in a refactor.
    #[test]
    fn restore_leaves_uplink_groups_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(
            &path,
            r#"{"peers":{},"uplinks":{"internet":{"winnerId":"192.0.2.10","degraded":true,
               "lastPublishedAddress":"192.0.2.10",
               "confirmedAt":"2000-01-01T00:00:00Z",
               "transports":[{"id":"192.0.2.10","state":"down"}]}}}"#,
        )
        .unwrap();

        let mut g = new_peer_group("internet", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        g.kind = GroupKind::Uplink;
        g.max_age_sec = Some(60);
        add_transport(&mut g, 10, "192.0.2.10");
        let mut state = EngineState {
            peers: HashMap::new(),
            uplinks: HashMap::from([("internet".to_string(), g)]),
            ..Default::default()
        };
        Engine::load_state(&path, &mut state);

        assert_eq!(
            state.uplinks["internet"].last_published_addr, "192.0.2.10",
            "the peer-only staleness bound reached into an uplink group"
        );
    }

    /// A static Nix address is a declaration. A prior state file may carry
    /// an old dynamic or static value, but it is never permitted to win
    /// over an address the operator changed in the current configuration.
    #[test]
    fn restore_drops_health_for_a_changed_static_winner_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(
            &path,
            r#"{"peers":{"host-b":{"winnerId":"192.0.2.10","winnerSince":"2026-08-05T08:00:00Z",
               "confirmedAt":"2026-08-05T08:00:00Z","degraded":false,
               "lastPublishedAddress":"192.0.2.10",
               "transports":[{"id":"192.0.2.10","state":"up","consecutiveSuccess":7,"address":"192.0.2.10"}]}},"uplinks":{}}"#,
        )
        .unwrap();

        let mut group = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let transport = add_transport(&mut group, 10, "192.0.2.99");
        let mut state = EngineState {
            peers: HashMap::from([("host-b".to_string(), group)]),
            uplinks: HashMap::new(),
            ..Default::default()
        };
        Engine::load_state(&path, &mut state);

        let group = &state.peers["host-b"];
        let restored = &group.transports[transport];
        assert_eq!(restored.current_address, "192.0.2.99");
        assert_eq!(restored.state, super::TransportState::Unknown);
        assert_eq!(restored.consecutive_success, 0);
        assert_eq!(restored.consecutive_failure, 0);
        assert_eq!(group.winner, None);
        assert_eq!(group.last_published_addr, "");
        assert_eq!(group.last_confirmed_at, None);
        assert!(group.degraded, "the changed address awaits a fresh probe");
    }

    /// The static-address rule has a necessary boundary: an exec transport
    /// declares no address precisely because its provider discovers one at
    /// runtime, so its cached address remains useful across a restart.
    #[test]
    fn restore_keeps_a_dynamic_transport_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(
            &path,
            r#"{"peers":{"host-b":{"winnerId":"test-dynamic","degraded":false,
               "lastPublishedAddress":"100.64.42.10",
               "transports":[{"id":"test-dynamic","state":"up","consecutiveSuccess":7,"address":"100.64.42.10"}]}},"uplinks":{}}"#,
        )
        .unwrap();

        let mut group = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let transport = add_transport(&mut group, 10, "");
        let mut state = EngineState {
            peers: HashMap::from([("host-b".to_string(), group)]),
            uplinks: HashMap::new(),
            ..Default::default()
        };
        Engine::load_state(&path, &mut state);

        let group = &state.peers["host-b"];
        let restored = &group.transports[transport];
        assert_eq!(restored.current_address, "100.64.42.10");
        assert_eq!(restored.state, super::TransportState::Up);
        assert_eq!(group.winner, Some(0));
        assert_eq!(group.last_published_addr, "100.64.42.10");
        assert!(!group.degraded);
    }

    /// Guards the one construction the tests above all rely on: the engine
    /// used by `restart_with_state` really does publish through a real
    /// `HostsPublisher` and a `RoutePublisher` that touches nothing. If
    /// this ever stops being true, every "not published" assertion above
    /// becomes vacuous.
    #[test]
    fn the_test_engine_publishes_through_a_real_hosts_file() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let eng = Engine {
            hosts: HostsPublisher::new(&hosts_path).unwrap(),
            routes: RoutePublisher {
                ip_path: "/bin/true".to_string(),
            },
            status_path: dir.path().join("status.json"),
            state_path: dir.path().join("state.json"),
            status_ttl: std::time::Duration::from_secs(30),
            state: std::sync::Mutex::new(EngineState::default()),
            io_lock: std::sync::Mutex::new(()),
            last_state_write: std::sync::Mutex::new(None),
            last_status_write: std::sync::Mutex::new(None),
            initialized: std::sync::atomic::AtomicBool::new(false),
        };
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        g.last_published_addr = "192.0.2.10".into();
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

        eng.publish_restored_peers();
        assert!(std::fs::read_to_string(&hosts_path)
            .unwrap()
            .contains("192.0.2.10"));
    }
}
