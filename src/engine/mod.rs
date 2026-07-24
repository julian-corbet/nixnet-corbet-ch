//! Implements nixnet's per-transport health state machine and per-group
//! winner selection. One OS thread per transport, its own ticker (a
//! slow/hung probe never delays another); all shared runtime state behind
//! one [`Mutex`] (this workload ticks in seconds, not microseconds -- one
//! coarse lock is simpler than per-transport locks and costs nothing
//! observable here), matching the Go original's single `sync.Mutex`
//! guarding both the peers and uplinks maps.
//!
//! One structural difference from the Go original is worth calling out:
//! Go's per-transport goroutine closes over a `*transportRuntime` pointer
//! directly and mutates it in place (still serialized by the shared
//! mutex). Rust's ownership rules don't allow a thread to hold a live
//! reference into a [`Mutex`]-guarded structure across its entire
//! lifetime, so each thread instead captures a small `(GroupKind, group
//! name, transport index)` key and re-locks/re-looks-up the transport
//! each tick -- functionally identical, just addressed by key instead of
//! by pointer.

mod state;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::{self, Config};
use crate::logf;
use crate::probe;
use crate::publish::{self, HostsPublisher, RoutePublisher};
use crate::shutdown::Shutdown;
use crate::status;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GroupKind {
    Peer,
    Uplink,
}

impl GroupKind {
    fn label(self) -> &'static str {
        match self {
            GroupKind::Peer => "peer",
            GroupKind::Uplink => "uplink",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TransportState {
    Unknown,
    Up,
    Down,
}

impl TransportState {
    fn as_str(self) -> &'static str {
        match self {
            TransportState::Unknown => "unknown",
            TransportState::Up => "up",
            TransportState::Down => "down",
        }
    }
}

struct TransportRuntime {
    spec: config::Transport,
    /// Human-readable id for logs/status, e.g. "peer/host-b#0(lan)".
    id: String,

    state: TransportState,
    consecutive_success: i64,
    consecutive_failure: i64,
    current_address: String,
    detail: String,
}

struct Group {
    kind: GroupKind,

    // Peers only.
    hostnames: Vec<String>,
    on_all_down: String,
    // Uplinks only.
    route_metric: bool,
    metric_base: i64,
    metric_step: i64,

    min_hold_ms: i64,
    transports: Vec<TransportRuntime>,

    winner: Option<usize>, // None == no winner (mirrors the Go original's winner == -1)
    winner_since: Option<OffsetDateTime>,
    degraded: bool,
    /// Peers only: what's currently actually in the managed hosts block
    /// for this peer ("" == not published).
    last_published_addr: String,
}

struct EngineState {
    peers: HashMap<String, Group>,
    uplinks: HashMap<String, Group>,
}

impl EngineState {
    fn group(&self, kind: GroupKind, name: &str) -> &Group {
        match kind {
            GroupKind::Peer => &self.peers[name],
            GroupKind::Uplink => &self.uplinks[name],
        }
    }

    fn group_mut(&mut self, kind: GroupKind, name: &str) -> &mut Group {
        match kind {
            GroupKind::Peer => self.peers.get_mut(name).expect("peer group exists"),
            GroupKind::Uplink => self.uplinks.get_mut(name).expect("uplink group exists"),
        }
    }
}

/// Ties the config, in-memory health table, and publish backends
/// together.
pub struct Engine {
    hosts: HostsPublisher,
    routes: RoutePublisher,

    status_path: PathBuf,
    state_path: PathBuf,

    state: Mutex<EngineState>,
}

/// One currently-healthy candidate, ordered by priority within
/// `reconcile_locked`.
struct Candidate {
    idx: usize,
    priority: i64,
}

impl Engine {
    /// Builds an Engine from `cfg`. Transport threads are not started
    /// until [`Engine::run`].
    pub fn new(
        cfg: Config,
        hosts: HostsPublisher,
        routes: RoutePublisher,
        status_path: PathBuf,
        state_path: PathBuf,
    ) -> Self {
        let mut peers = HashMap::new();
        for (name, p) in cfg.peers {
            let mut transports = Vec::with_capacity(p.transports.len());
            for (i, t) in p.transports.into_iter().enumerate() {
                let id = transport_id(GroupKind::Peer, &name, i, &t);
                transports.push(TransportRuntime {
                    spec: t,
                    id,
                    state: TransportState::Unknown,
                    consecutive_success: 0,
                    consecutive_failure: 0,
                    current_address: String::new(),
                    detail: String::new(),
                });
            }
            peers.insert(
                name,
                Group {
                    kind: GroupKind::Peer,
                    hostnames: p.hostnames,
                    on_all_down: p.on_all_down,
                    route_metric: false,
                    metric_base: 0,
                    metric_step: 0,
                    min_hold_ms: p.hysteresis.min_hold_ms,
                    transports,
                    winner: None,
                    winner_since: None,
                    degraded: false,
                    last_published_addr: String::new(),
                },
            );
        }

        let mut uplinks = HashMap::new();
        for (name, u) in cfg.uplinks {
            let mut transports = Vec::with_capacity(u.transports.len());
            for (i, t) in u.transports.into_iter().enumerate() {
                let id = transport_id(GroupKind::Uplink, &name, i, &t);
                transports.push(TransportRuntime {
                    spec: t,
                    id,
                    state: TransportState::Unknown,
                    consecutive_success: 0,
                    consecutive_failure: 0,
                    current_address: String::new(),
                    detail: String::new(),
                });
            }
            uplinks.insert(
                name,
                Group {
                    kind: GroupKind::Uplink,
                    hostnames: Vec::new(),
                    on_all_down: String::new(),
                    route_metric: u.publish.route_metric,
                    metric_base: u.publish.metric_base,
                    metric_step: u.publish.metric_step,
                    min_hold_ms: u.hysteresis.min_hold_ms,
                    transports,
                    winner: None,
                    winner_since: None,
                    degraded: false,
                    last_published_addr: String::new(),
                },
            );
        }

        let mut state = EngineState { peers, uplinks };
        Self::load_state(&state_path, &mut state);

        Self {
            hosts,
            routes,
            status_path,
            state_path,
            state: Mutex::new(state),
        }
    }

    pub fn peer_count(&self) -> usize {
        self.state.lock().unwrap().peers.len()
    }

    pub fn uplink_count(&self) -> usize {
        self.state.lock().unwrap().uplinks.len()
    }

    /// Starts one thread per transport and blocks until every one of them
    /// observes `shutdown`. Probe/publish errors are logged and reflected
    /// in status.json, never fatal to the daemon itself -- a single bad
    /// transport must never take the whole daemon down.
    pub fn run(self: Arc<Self>, shutdown: Shutdown) {
        let keys = self.transport_keys();
        let mut handles = Vec::with_capacity(keys.len());
        for key in keys {
            let eng = Arc::clone(&self);
            let sd = shutdown.clone();
            handles.push(std::thread::spawn(move || eng.run_transport(key, sd)));
        }

        // Publish an initial status snapshot immediately, so nixnetctl has
        // something sane to read even before the first probe tick
        // completes.
        self.write_status();

        for h in handles {
            let _ = h.join();
        }
    }

    fn transport_keys(&self) -> Vec<(GroupKind, String, usize)> {
        let state = self.state.lock().unwrap();
        let mut keys = Vec::new();
        for (name, g) in state.peers.iter() {
            for i in 0..g.transports.len() {
                keys.push((GroupKind::Peer, name.clone(), i));
            }
        }
        for (name, g) in state.uplinks.iter() {
            for i in 0..g.transports.len() {
                keys.push((GroupKind::Uplink, name.clone(), i));
            }
        }
        keys
    }

    fn run_transport(&self, key: (GroupKind, String, usize), shutdown: Shutdown) {
        let (kind, name, idx) = key;
        let interval_ms = {
            let state = self.state.lock().unwrap();
            state.group(kind, &name).transports[idx]
                .spec
                .probe
                .interval_ms
        };
        let interval = if interval_ms <= 0 {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(interval_ms as u64)
        };

        loop {
            self.probe_once(kind, &name, idx);
            if shutdown.wait(interval) {
                return;
            }
        }
    }

    fn probe_once(&self, kind: GroupKind, name: &str, idx: usize) {
        let (spec, tr_id) = {
            let state = self.state.lock().unwrap();
            let tr = &state.group(kind, name).transports[idx];
            (tr.spec.clone(), tr.id.clone())
        };

        let res = match probe::run(&spec) {
            Ok(r) => r,
            Err(e) => {
                logf!("transport={} probe misconfigured: {}", tr_id, e);
                probe::ProbeResult {
                    healthy: false,
                    detail: e.to_string(),
                    ..Default::default()
                }
            }
        };

        let mut state = self.state.lock().unwrap();
        let (old_state, new_state, transition_count, tr_detail);
        {
            let g = state.group_mut(kind, name);
            let tr = &mut g.transports[idx];
            old_state = tr.state;
            if res.healthy {
                tr.consecutive_failure = 0;
                tr.consecutive_success += 1;
                if tr.state != TransportState::Up
                    && tr.consecutive_success >= threshold(tr.spec.probe.up_threshold, 2)
                {
                    tr.state = TransportState::Up;
                }
            } else {
                tr.consecutive_success = 0;
                tr.consecutive_failure += 1;
                if tr.state != TransportState::Down
                    && tr.consecutive_failure >= threshold(tr.spec.probe.down_threshold, 3)
                {
                    tr.state = TransportState::Down;
                }
            }
            if !res.address.is_empty() {
                tr.current_address = res.address.clone();
            } else if tr.current_address.is_empty() {
                tr.current_address = tr.spec.address.clone();
            }
            tr.detail = res.detail.clone();
            new_state = tr.state;
            transition_count = if new_state != old_state {
                match new_state {
                    TransportState::Up => tr.consecutive_success,
                    TransportState::Down => tr.consecutive_failure,
                    TransportState::Unknown => 0,
                }
            } else {
                0
            };
            tr_detail = tr.detail.clone();
        }

        self.reconcile_locked(&mut state, kind, name);
        self.save_state_locked(&state);
        drop(state);

        if new_state != old_state {
            logf!(
                "transport={} state={}->{} after={} detail={:?}",
                tr_id,
                old_state.as_str(),
                new_state.as_str(),
                transition_count,
                tr_detail
            );
        }

        self.write_status();
    }

    /// Implements winner-selection: among currently-healthy candidates,
    /// lowest priority number wins, damped by `minHoldMs` unless the
    /// current winner itself just went unhealthy. Also covers the
    /// documented extension beyond a literal reading of that rule:
    /// republishing when the current winner's own dynamically-discovered
    /// address changes, even with no winner-index change at all (a
    /// provider re-enrolling with a new overlay IP, e.g.). Callers must
    /// hold the lock (pass the already-locked `state`).
    fn reconcile_locked(&self, state: &mut EngineState, kind: GroupKind, name: &str) {
        let now = OffsetDateTime::now_utc();
        let group_label = format!("{}={}", kind.label(), name);

        enum Action {
            None,
            PublishPeers,
            PublishUplink(Vec<publish::RankedInterface>, bool, i64, i64),
        }

        let action = {
            let g = state.group_mut(kind, name);

            let mut candidates: Vec<Candidate> = g
                .transports
                .iter()
                .enumerate()
                .filter(|(_, tr)| tr.state == TransportState::Up)
                .map(|(i, tr)| Candidate {
                    idx: i,
                    priority: tr.spec.priority,
                })
                .collect();
            candidates.sort_by_key(|c| c.priority);

            if candidates.is_empty() {
                let was_degraded = g.degraded;
                g.degraded = true;
                if !was_degraded {
                    logf!("group={} DEGRADED: all transports down", group_label);
                }
                if kind == GroupKind::Peer
                    && g.on_all_down == config::ON_ALL_DOWN_UNPUBLISH
                    && g.winner.is_some()
                {
                    g.winner = None;
                    g.last_published_addr.clear();
                    Action::PublishPeers
                } else {
                    // uplinks, and lastKnownGood peers: leave the last
                    // winner/route exactly as it was -- deliberately no
                    // publish at all.
                    Action::None
                }
            } else {
                if g.degraded {
                    g.degraded = false;
                    logf!(
                        "group={} RECOVERED: at least one transport is up again",
                        group_label
                    );
                }

                let best_priority = candidates[0].priority;
                let mut new_winner = candidates[0].idx;
                if let Some(w) = g.winner {
                    if candidates
                        .iter()
                        .any(|c| c.priority == best_priority && c.idx == w)
                    {
                        new_winner = w; // ties: keep the current winner if it's among them
                    }
                }

                let mut winner_changed = Some(new_winner) != g.winner;

                if winner_changed {
                    if let Some(w) = g.winner {
                        if g.transports[w].state == TransportState::Up {
                            // The current winner is still healthy -- this
                            // is "a strictly better option appeared," not
                            // a failover. Damp it via minHold, unless the
                            // hold window has already elapsed. Never
                            // applied when the current winner just went
                            // Down (that branch has state != Up, so this
                            // whole condition is false and we switch
                            // immediately).
                            let min_hold = time::Duration::milliseconds(g.min_hold_ms.max(0));
                            let since = g.winner_since.unwrap_or(now);
                            if now - since < min_hold {
                                winner_changed = false;
                                new_winner = w;
                            }
                        }
                    }
                }

                let mut address_drift = false;
                if !winner_changed && g.winner.is_some() && kind == GroupKind::Peer {
                    let addr = &g.transports[new_winner].current_address;
                    if !addr.is_empty() && *addr != g.last_published_addr {
                        address_drift = true;
                    }
                }

                if !winner_changed && !address_drift {
                    Action::None
                } else {
                    if winner_changed {
                        g.winner = Some(new_winner);
                        g.winner_since = Some(now);
                        logf!(
                            "group={} winner-change new={}",
                            group_label,
                            g.transports[new_winner].id
                        );
                    }

                    match kind {
                        GroupKind::Peer => {
                            g.last_published_addr =
                                g.transports[new_winner].current_address.clone();
                            Action::PublishPeers
                        }
                        GroupKind::Uplink => {
                            let w = g.winner.expect("winner just set above");
                            let mut ranked = Vec::with_capacity(candidates.len());
                            ranked.push(publish::RankedInterface {
                                interface: g.transports[w].spec.interface.clone(),
                            });
                            for c in &candidates {
                                if c.idx == w {
                                    continue;
                                }
                                ranked.push(publish::RankedInterface {
                                    interface: g.transports[c.idx].spec.interface.clone(),
                                });
                            }
                            Action::PublishUplink(
                                ranked,
                                g.route_metric,
                                g.metric_base,
                                g.metric_step,
                            )
                        }
                    }
                }
            }
        };

        match action {
            Action::None => {}
            Action::PublishPeers => self.publish_peers_locked(state),
            Action::PublishUplink(ranked, route_metric, metric_base, metric_step) => {
                if !route_metric {
                    return;
                }
                if let Err(e) = self.routes.apply(&ranked, metric_base, metric_step) {
                    logf!("publish routes for group={}: {}", group_label, e);
                }
            }
        }
    }

    /// Rewrites the whole managed hosts block from every peer group's
    /// current `last_published_addr` (not just the group that just
    /// changed) -- the publish backend is a single shared file, so any
    /// change requires re-rendering the entire block. Callers must hold
    /// the lock.
    fn publish_peers_locked(&self, state: &EngineState) {
        let mut entries = Vec::new();
        for g in state.peers.values() {
            if g.last_published_addr.is_empty() {
                continue;
            }
            entries.push(publish::Entry {
                address: g.last_published_addr.clone(),
                hostnames: g.hostnames.clone(),
            });
        }
        if let Err(e) = self.hosts.publish(&entries) {
            logf!("publish hosts: {}", e);
        }
    }

    /// Renders `/run/nixnet/status.json` -- every tick, regardless of
    /// whether anything changed.
    fn write_status(&self) {
        let snap = {
            let state = self.state.lock().unwrap();
            let mut peers = HashMap::new();
            let mut uplinks = HashMap::new();
            for (name, g) in &state.peers {
                peers.insert(name.clone(), render_group(g));
            }
            for (name, g) in &state.uplinks {
                uplinks.insert(name.clone(), render_group(g));
            }
            status::Snapshot {
                generated_at: String::new(),
                peers,
                uplinks,
            }
        };

        if let Err(e) = status::write(&self.status_path, snap) {
            logf!("write status: {}", e);
        }
    }
}

fn render_group(g: &Group) -> status::Group {
    let mut sg = status::Group {
        winner: String::new(),
        since: String::new(),
        degraded: g.degraded,
        transports: HashMap::new(),
    };
    if let Some(w) = g.winner {
        sg.winner = winner_label(g, w);
        if let Some(since) = g.winner_since {
            sg.since = since.format(&Rfc3339).unwrap_or_default();
        }
    }
    for tr in &g.transports {
        sg.transports.insert(
            tr.id.clone(),
            status::StatusTransport {
                state: tr.state.as_str().to_string(),
                detail: tr.detail.clone(),
            },
        );
    }
    sg
}

fn winner_label(g: &Group, winner: usize) -> String {
    if winner >= g.transports.len() {
        return String::new();
    }
    match g.kind {
        GroupKind::Peer => g.last_published_addr.clone(),
        GroupKind::Uplink => g.transports[winner].spec.interface.clone(),
    }
}

fn threshold(v: i64, def: i64) -> i64 {
    if v <= 0 {
        def
    } else {
        v
    }
}

/// Derives a stable, readable log/status identifier. Transport identity
/// itself is the list position (index) -- reordering a transports list in
/// Nix is equivalent to removing and re-adding entries.
fn transport_id(kind: GroupKind, group_name: &str, idx: usize, t: &config::Transport) -> String {
    let label = if !t.provider_id.is_empty() {
        t.provider_id.as_str()
    } else if !t.interface.is_empty() {
        t.interface.as_str()
    } else if !t.address.is_empty() {
        t.address.as_str()
    } else {
        "?"
    };
    format!("{}/{}#{}({})", kind.label(), group_name, idx, label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::{HostsPublisher, RoutePublisher};

    fn new_test_engine() -> (Engine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let hosts = HostsPublisher::new(dir.path().join("hosts")).unwrap();
        // Never actually mutate routing in a test.
        let routes = RoutePublisher {
            ip_path: "/bin/true".to_string(),
        };
        let eng = Engine {
            hosts,
            routes,
            status_path: dir.path().join("status.json"),
            state_path: dir.path().join("state.json"),
            state: Mutex::new(EngineState {
                peers: HashMap::new(),
                uplinks: HashMap::new(),
            }),
        };
        (eng, dir)
    }

    fn new_peer_group(name: &str, min_hold_ms: i64, on_all_down: &str) -> Group {
        Group {
            kind: GroupKind::Peer,
            hostnames: vec![name.to_string()],
            on_all_down: on_all_down.to_string(),
            route_metric: false,
            metric_base: 0,
            metric_step: 0,
            min_hold_ms,
            transports: Vec::new(),
            winner: None,
            winner_since: None,
            degraded: false,
            last_published_addr: String::new(),
        }
    }

    /// Mirrors the real invariant `probe_once` maintains: every
    /// transport's `current_address` is populated before
    /// `reconcile_locked` ever looks at it (falling back to
    /// `spec.address` when a probe result carries no dynamic override).
    /// Returns the transport's index within `g.transports` -- tests that
    /// specifically exercise a *changing* dynamic address mutate
    /// `transports[idx].current_address` directly afterward.
    fn add_transport(g: &mut Group, priority: i64, address: &str) -> usize {
        g.transports.push(TransportRuntime {
            spec: config::Transport {
                priority,
                address: address.to_string(),
                ..Default::default()
            },
            id: address.to_string(),
            state: TransportState::Unknown,
            consecutive_success: 0,
            consecutive_failure: 0,
            current_address: address.to_string(),
            detail: String::new(),
        });
        g.transports.len() - 1
    }

    /// Exercises the core winner-selection rule: among currently-healthy
    /// candidates, lowest priority number wins.
    #[test]
    fn reconcile_picks_lowest_priority_healthy() {
        let (eng, _dir) = new_test_engine();
        // min_hold_ms = 0: this test is about priority selection, not
        // damping (that's hysteresis_damps_better_option's job) -- with a
        // non-zero hold, "a better option appearing while the winner is
        // still healthy" is correctly damped, which would make this
        // test's second assertion fail for the *right* reason but the
        // *wrong* test.
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let low_prio = add_transport(&mut g, 10, "192.0.2.10"); // more preferred (lower number)
        let high_prio = add_transport(&mut g, 50, "192.0.2.20"); // less preferred
        {
            let mut state = eng.state.lock().unwrap();
            state.peers.insert("host-b".to_string(), g);
        }

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[high_prio].state =
                TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        {
            let state = eng.state.lock().unwrap();
            let g = state.group(GroupKind::Peer, "host-b");
            assert_eq!(
                g.winner,
                Some(high_prio),
                "the only healthy transport should win"
            );
            assert_eq!(g.last_published_addr, "192.0.2.20");
        }

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[low_prio].state =
                TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        {
            let state = eng.state.lock().unwrap();
            let g = state.group(GroupKind::Peer, "host-b");
            assert_eq!(
                g.winner,
                Some(low_prio),
                "lower priority number should win once healthy"
            );
        }
    }

    /// Exercises minHold damping: a strictly-better (lower priority
    /// number) option becoming healthy while the CURRENT winner is still
    /// healthy must NOT switch the winner until `min_hold_ms` has elapsed
    /// since `winner_since`.
    #[test]
    fn reconcile_hysteresis_damps_better_option() {
        let (eng, _dir) = new_test_engine();
        let mut g = new_peer_group("host-b", 10_000, config::ON_ALL_DOWN_LAST_KNOWN_GOOD); // 10s hold
        let worse = add_transport(&mut g, 50, "192.0.2.20");
        let better = add_transport(&mut g, 10, "192.0.2.10");
        {
            let mut state = eng.state.lock().unwrap();
            state.peers.insert("host-b".to_string(), g);
        }

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[worse].state = TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        assert_eq!(
            eng.state
                .lock()
                .unwrap()
                .group(GroupKind::Peer, "host-b")
                .winner,
            Some(worse),
            "worse should win before better appears"
        );

        // Better option appears immediately after -- still well inside
        // the 10s hold window, so it must NOT take over yet.
        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[better].state =
                TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        assert_eq!(
            eng.state
                .lock()
                .unwrap()
                .group(GroupKind::Peer, "host-b")
                .winner,
            Some(worse),
            "damped: hold window not elapsed"
        );

        // Simulate the hold window having elapsed.
        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").winner_since =
                Some(OffsetDateTime::now_utc() - time::Duration::seconds(11));
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        assert_eq!(
            eng.state
                .lock()
                .unwrap()
                .group(GroupKind::Peer, "host-b")
                .winner,
            Some(better),
            "better should win once the hold window elapses"
        );
    }

    /// Exercises the explicit carve-out: minHold is never applied when the
    /// CURRENT winner itself just went Down -- a dead winner is never held
    /// onto to satisfy a hold timer, even a second after it became the
    /// winner.
    #[test]
    fn reconcile_dead_winner_switches_immediately() {
        let (eng, _dir) = new_test_engine();
        let mut g = new_peer_group("host-b", 10_000, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let primary = add_transport(&mut g, 10, "192.0.2.10");
        let fallback = add_transport(&mut g, 50, "192.0.2.20");
        {
            let mut state = eng.state.lock().unwrap();
            state.peers.insert("host-b".to_string(), g);
        }

        {
            let mut state = eng.state.lock().unwrap();
            let grp = state.group_mut(GroupKind::Peer, "host-b");
            grp.transports[primary].state = TransportState::Up;
            grp.transports[fallback].state = TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        let winner_since = {
            let state = eng.state.lock().unwrap();
            let g = state.group(GroupKind::Peer, "host-b");
            assert_eq!(g.winner, Some(primary));
            g.winner_since.unwrap()
        };

        // primary dies a moment later -- well inside what would otherwise
        // be the 10s hold window.
        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[primary].state =
                TransportState::Down;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        let state = eng.state.lock().unwrap();
        let g = state.group(GroupKind::Peer, "host-b");
        assert_eq!(
            g.winner,
            Some(fallback),
            "a dead winner must switch immediately, no hold"
        );
        assert!(
            g.winner_since.unwrap() > winner_since,
            "winner_since did not advance on failover"
        );
    }

    /// Exercises the `onAllDown = "lastKnownGood"` branch: when every
    /// transport is down, the group is marked degraded but the
    /// previously-published address is left alone (no unpublish).
    #[test]
    fn reconcile_on_all_down_last_known_good() {
        let (eng, _dir) = new_test_engine();
        let mut g = new_peer_group("host-b", 10_000, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let only = add_transport(&mut g, 10, "192.0.2.10");
        {
            let mut state = eng.state.lock().unwrap();
            state.peers.insert("host-b".to_string(), g);
        }

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[only].state = TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        assert!(
            !eng.state
                .lock()
                .unwrap()
                .group(GroupKind::Peer, "host-b")
                .degraded
        );

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[only].state =
                TransportState::Down;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        let state = eng.state.lock().unwrap();
        let g = state.group(GroupKind::Peer, "host-b");
        assert!(
            g.degraded,
            "degraded should be true after all transports went down"
        );
        assert_eq!(
            g.last_published_addr, "192.0.2.10",
            "lastKnownGood must not clear the published address"
        );
        assert_eq!(
            g.winner,
            Some(only),
            "lastKnownGood leaves the winner pointer alone"
        );
    }

    /// Exercises the other `onAllDown` branch: with `"unpublish"`, the
    /// entry is actually cleared once every transport is down.
    #[test]
    fn reconcile_on_all_down_unpublish() {
        let (eng, _dir) = new_test_engine();
        let mut g = new_peer_group("host-b", 10_000, config::ON_ALL_DOWN_UNPUBLISH);
        let only = add_transport(&mut g, 10, "192.0.2.10");
        {
            let mut state = eng.state.lock().unwrap();
            state.peers.insert("host-b".to_string(), g);
        }

        {
            let mut state = eng.state.lock().unwrap();
            let grp = state.group_mut(GroupKind::Peer, "host-b");
            grp.transports[only].state = TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
            state.group_mut(GroupKind::Peer, "host-b").transports[only].state =
                TransportState::Down;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        let state = eng.state.lock().unwrap();
        let g = state.group(GroupKind::Peer, "host-b");
        assert_eq!(g.last_published_addr, "", "unpublish must clear it");
        assert_eq!(g.winner, None, "unpublish clears the winner too");
    }

    /// Covers the documented extension beyond a literal winner-index-only
    /// republish rule: a provider's exec probe changing the WINNING
    /// transport's own address, with no winner-index change at all, must
    /// still update `last_published_addr`.
    #[test]
    fn reconcile_address_drift_republishes_without_winner_change() {
        let (eng, _dir) = new_test_engine();
        let mut g = new_peer_group("host-b", 10_000, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let idx = add_transport(&mut g, 10, "203.0.113.5");
        g.transports[idx].spec.provider_id = "netbird".to_string();
        {
            let mut state = eng.state.lock().unwrap();
            state.peers.insert("host-b".to_string(), g);
        }

        {
            let mut state = eng.state.lock().unwrap();
            let grp = state.group_mut(GroupKind::Peer, "host-b");
            grp.transports[idx].state = TransportState::Up;
            grp.transports[idx].current_address = "203.0.113.5".to_string();
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        let winner_before = {
            let state = eng.state.lock().unwrap();
            let g = state.group(GroupKind::Peer, "host-b");
            assert_eq!(g.last_published_addr, "203.0.113.5");
            g.winner
        };

        // The provider re-enrolls and gets handed a new overlay IP. State
        // stays Up throughout -- no transition, no winner-index change.
        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[idx].current_address =
                "203.0.113.99".to_string();
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        let state = eng.state.lock().unwrap();
        let g = state.group(GroupKind::Peer, "host-b");
        assert_eq!(
            g.winner, winner_before,
            "winner index shouldn't change -- same transport"
        );
        assert_eq!(
            g.last_published_addr, "203.0.113.99",
            "address drift on the unchanged winner must still republish"
        );
    }
}
