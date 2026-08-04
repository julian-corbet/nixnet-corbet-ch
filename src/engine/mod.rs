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
    /// Peers only, STALE-2: how long `on_all_down == "lastKnownGood"` may
    /// keep publishing an address no probe can confirm any more. `None` ==
    /// unbounded, which is the defect the bound exists to close.
    max_age_sec: Option<i64>,
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
    /// STALE-1/STALE-2: when the published value was last CONFIRMED by a
    /// successful probe -- not when it was last written. Survives restarts
    /// (state.json), because the age of an entry does not reset just
    /// because the process holding it did. `None` == never confirmed by
    /// this daemon.
    last_confirmed_at: Option<OffsetDateTime>,
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

/// STALE-2's verdict on one retained last-known-good entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Staleness {
    /// Keep publishing: inside the bound, or no bound was declared.
    Fresh,
    /// Withdraw. Carries the age, for the ONE log line the withdrawal
    /// emits -- an operator reading it needs to know how long the address
    /// had been unconfirmable, not merely that it was.
    Expired(time::Duration),
    /// Withdraw, age unknown: a bound is declared, but nothing recorded
    /// when this entry was last confirmed (state.json written by a nixnet
    /// that predates the timestamp). An entry that cannot be shown to be
    /// inside its bound is not inside it -- and the recovery from being
    /// wrong here costs one probe interval, while the recovery from the
    /// other reading cost eleven days.
    ExpiredUnknownAge,
}

/// The single age judgement behind STALE-2, deliberately a free function
/// over three values rather than a method on `Group`: the live path
/// (`reconcile_locked`) and the restore-from-disk path (`state::restore`)
/// must reach the SAME verdict from the same inputs, and two copies of
/// this arithmetic is exactly how the production defect survived. The
/// running daemon had no bound at all, restore-at-start had no age check
/// either, so every restart laundered an eleven-day-old address into a
/// fresh-looking one and nothing anywhere ever said "too old".
fn staleness(
    max_age_sec: Option<i64>,
    confirmed_at: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Staleness {
    let bound = match max_age_sec {
        Some(v) if v > 0 => time::Duration::seconds(v),
        // No bound (or a nonsensical one that config validation already
        // rejects on both the Nix and the JSON path): unbounded, the
        // behaviour this option exists to let an operator opt out of.
        _ => return Staleness::Fresh,
    };
    let confirmed_at = match confirmed_at {
        Some(t) => t,
        None => return Staleness::ExpiredUnknownAge,
    };
    let age = now - confirmed_at;
    // A negative age is a clock that moved backwards (NTP step, a VM
    // restored from a snapshot), never evidence of staleness -- so it
    // reads as fresh and the next successful probe re-stamps it. Treating
    // it as expired would let one clock correction withdraw every name on
    // the host at once, which is the outage this daemon exists to avoid.
    if age > bound {
        Staleness::Expired(age)
    } else {
        Staleness::Fresh
    }
}

/// Renders a `Staleness` age for the withdrawal log line. Kept beside
/// `staleness` so the "unknown" wording is chosen once, not per call site.
///
/// Sub-second precision, because whole seconds print the boundary case as
/// `age=20s bound=20s` -- a line that reads as though the daemon withdrew
/// an entry it had just declared fresh, and that is the ONE line an
/// operator ever sees about this event.
fn staleness_age_label(s: Staleness) -> String {
    match s {
        Staleness::Expired(age) => format!("{:.1}s", age.as_seconds_f64()),
        Staleness::ExpiredUnknownAge => "unknown (state predates confirmedAt)".to_string(),
        Staleness::Fresh => String::new(),
    }
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
                    max_age_sec: p.last_known_good.max_age_sec,
                    route_metric: false,
                    metric_base: 0,
                    metric_step: 0,
                    min_hold_ms: p.hysteresis.min_hold_ms,
                    transports,
                    winner: None,
                    winner_since: None,
                    degraded: false,
                    last_published_addr: String::new(),
                    last_confirmed_at: None,
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
                    // Uplinks publish a route metric, not a name. There is
                    // no retained value for a bound to expire.
                    max_age_sec: None,
                    route_metric: u.publish.route_metric,
                    metric_base: u.publish.metric_base,
                    metric_step: u.publish.metric_step,
                    min_hold_ms: u.hysteresis.min_hold_ms,
                    transports,
                    winner: None,
                    winner_since: None,
                    degraded: false,
                    last_published_addr: String::new(),
                    last_confirmed_at: None,
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

        // ...and re-assert the hosts block from the winners restored out
        // of state.json, for the same reason: until this call existed,
        // NOTHING was published until some group's winner actually
        // CHANGED. A restart on a settled fleet changes no winner, so the
        // activation script's boot seed -- which keys each entry by the
        // peer's Nix ATTRIBUTE NAME, not its configured `hostnames` list
        // -- stayed in /etc/hosts indefinitely, and every alias a peer
        // declared beyond its attribute name was simply absent. Observed
        // in production: `getent hosts <alias>` returned NXDOMAIN on a
        // host whose nixnetd had been up, healthy, and reporting correct
        // winners for hours.
        self.publish_restored_peers();

        // A host with zero peer groups and zero uplink groups configured
        // (nixnet enabled ahead of any real config -- a legitimate,
        // expected state per this daemon's own "resident, ready for
        // whatever this host resolves outbound in the future" design) has
        // no transports to spawn, so `handles` is empty here. Without this
        // guard the join loop below is a no-op and `run` (and therefore
        // `main`) returns immediately -- a resident daemon silently
        // exiting 0 in under a second. Under the unit's Restart=always
        // policy that means an instant crash-loop into start-limit-hit.
        // Block on the same shutdown signal every transport ticker already
        // uses, so the daemon behaves identically to the N>0 case: it
        // stays up, and a future config push (through a config reload,
        // once that lands) or SIGTERM/SIGINT ends it the normal way.
        if handles.is_empty() {
            while !shutdown.wait(Duration::from_secs(3600)) {}
            return;
        }

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
                } else if kind == GroupKind::Peer
                    && g.on_all_down == config::ON_ALL_DOWN_LAST_KNOWN_GOOD
                    && !g.last_published_addr.is_empty()
                {
                    // STALE-2. A lastKnownGood peer with something still
                    // published: keep publishing it only while it is
                    // inside its declared bound. The policy is named
                    // explicitly rather than reached by elimination, so
                    // this stays symmetric with the restore-from-disk
                    // check in `state::expire_restored_last_known_good`
                    // -- the two must agree about WHICH peers they apply
                    // to as much as about the age.
                    match staleness(g.max_age_sec, g.last_confirmed_at, now) {
                        Staleness::Fresh => Action::None,
                        expired => {
                            // Withdrawn, not marked: a hosts file cannot
                            // express "probably wrong", so an address that
                            // has failed every probe for longer than the
                            // operator declared tolerable is removed
                            // rather than annotated. The subject stays
                            // degraded -- this is not a recovery.
                            //
                            // Logged exactly ONCE, which the emptied
                            // `last_published_addr` guarantees structurally
                            // (this branch needs a non-empty one): at a
                            // 3-second tick, a line per tick would be
                            // ~29,000 lines a day describing a single
                            // event, which is its own outage.
                            logf!(
                                "group={} lastKnownGood WITHDRAWN addr={} age={} bound={}s: \
                                 no probe has confirmed this address since",
                                group_label,
                                g.last_published_addr,
                                staleness_age_label(expired),
                                g.max_age_sec.unwrap_or_default()
                            );
                            g.winner = None;
                            g.last_published_addr.clear();
                            Action::PublishPeers
                        }
                    }
                } else {
                    // uplinks, and lastKnownGood peers with nothing
                    // published to expire: leave the last winner/route
                    // exactly as it was -- deliberately no publish at all.
                    Action::None
                }
            } else {
                // Everything published for this group from here on is
                // backed by a transport that just probed successfully:
                // whichever candidate wins below is Up by construction.
                // This stamp is what STALE-1 publishes and what STALE-2
                // measures the age against, so it is set on the tick the
                // confirmation happened, not on the tick something changed.
                g.last_confirmed_at = Some(now);

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

    /// Publishes the peer block once at startup, from the winners
    /// `state.json` restored, so a restart re-asserts what this daemon
    /// had already selected instead of leaving the activation script's
    /// boot seed in place until the next winner change.
    ///
    /// Deliberately a no-op when nothing was restored (a first-ever
    /// start, or a wiped stateDir): every group's `last_published_addr`
    /// is empty then, so publishing would render an EMPTY managed block
    /// -- actively worse than the seed it would overwrite, since the seed
    /// is the only last-known-good content that exists at that point. The
    /// first real probe tick publishes as it always did.
    fn publish_restored_peers(&self) {
        let state = self.state.lock().unwrap();
        if state
            .peers
            .values()
            .all(|g| g.last_published_addr.is_empty())
        {
            return;
        }
        self.publish_peers_locked(&state);
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
                // STALE-1: the published artifact carries when it was last
                // confirmed, so a consumer can compute its age without
                // knowing this daemon's probe cadence -- and without
                // reading status.json, which most consumers of /etc/hosts
                // will never do.
                confirmed_at: g
                    .last_confirmed_at
                    .and_then(|t| t.format(&Rfc3339).ok()),
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
        // STALE-1: `since` is when this winner was SELECTED, which is not
        // when it was last confirmed -- a winner selected an hour ago and
        // failing for the last ten minutes has both, and only the second
        // one tells a reader whether the value can still be trusted.
        last_confirmed_at: g
            .last_confirmed_at
            .and_then(|t| t.format(&Rfc3339).ok())
            .unwrap_or_default(),
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

    pub(super) fn new_test_engine() -> (Engine, tempfile::TempDir) {
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

    /// `max_age_sec` is None here -- the unbounded default -- so every
    /// pre-STALE-2 test keeps exercising exactly what it did before.
    /// Tests about the bound set `g.max_age_sec` themselves.
    pub(super) fn new_peer_group(name: &str, min_hold_ms: i64, on_all_down: &str) -> Group {
        Group {
            kind: GroupKind::Peer,
            hostnames: vec![name.to_string()],
            on_all_down: on_all_down.to_string(),
            max_age_sec: None,
            route_metric: false,
            metric_base: 0,
            metric_step: 0,
            min_hold_ms,
            transports: Vec::new(),
            winner: None,
            winner_since: None,
            degraded: false,
            last_published_addr: String::new(),
            last_confirmed_at: None,
        }
    }

    /// Mirrors the real invariant `probe_once` maintains: every
    /// transport's `current_address` is populated before
    /// `reconcile_locked` ever looks at it (falling back to
    /// `spec.address` when a probe result carries no dynamic override).
    /// Returns the transport's index within `g.transports` -- tests that
    /// specifically exercise a *changing* dynamic address mutate
    /// `transports[idx].current_address` directly afterward.
    pub(super) fn add_transport(g: &mut Group, priority: i64, address: &str) -> usize {
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

    /// Regression test for the 2026-07-25 production incident: a host
    /// with zero peer groups and zero uplink groups configured (nixnet
    /// enabled ahead of any real config being pushed -- a legitimate,
    /// expected state) has no transports to spawn, so `run()`'s terminal
    /// `for h in handles { h.join(); }` loop was a silent no-op and the
    /// resident daemon exited cleanly in well under a second instead of
    /// staying up. Under the unit's `Restart=always` that produced an
    /// instant crash-loop into `start-limit-hit`. `run()` must now block
    /// on `shutdown` in the zero-transport case exactly like the N>0
    /// case does, and return only once `trigger()` is called.
    #[test]
    fn run_blocks_on_shutdown_with_zero_transports() {
        let (eng, _dir) = new_test_engine();
        let eng = Arc::new(eng);
        let shutdown = Shutdown::new();

        let eng2 = Arc::clone(&eng);
        let sd2 = shutdown.clone();
        let handle = std::thread::spawn(move || eng2.run(sd2));

        // Give run() a moment to reach the (now-blocking) zero-transports
        // guard. If the bug regresses, run() returns almost instantly and
        // this assertion is what actually catches it -- without it, the
        // later join() below would "pass" even on the old, broken
        // behavior, since triggering shutdown on an already-exited thread
        // is harmless.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !handle.is_finished(),
            "run() returned before shutdown was triggered -- the \
             zero-transport case is falling through instead of blocking \
             (regression of the 2026-07-25 fix)"
        );

        shutdown.trigger();
        handle.join().expect("run() thread panicked");
    }

    /// Regression test for the 2026-08-03 production incident: `run()`
    /// published nothing at startup, so a restart on a settled fleet --
    /// where by definition no winner CHANGES -- left the activation
    /// script's boot seed sitting in `/etc/hosts` indefinitely. That seed
    /// keys each entry by the peer's Nix ATTRIBUTE NAME, so every further
    /// name in its `hostnames` list was simply absent, and
    /// `getent hosts <alias>` returned NXDOMAIN against a daemon that was
    /// up, healthy, and reporting the correct winner the whole time.
    ///
    /// Uses a group with zero transports deliberately: that spawns no
    /// probe threads (so `run()` blocks on shutdown instead of doing real
    /// network I/O) while still exercising the real `run()` path, which
    /// is where the bug was -- never in `publish_peers_locked`, which
    /// always worked whenever something actually called it.
    #[test]
    fn startup_publishes_restored_winners_without_a_winner_change() {
        let (eng, dir) = new_test_engine();
        let hosts_path = dir.path().join("hosts");

        // Exactly what state.json's restore() reinstates on a restart:
        // the winner this daemon had already selected, plus every
        // hostname its config declares for that peer.
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        g.hostnames = vec!["host-b".to_string(), "host-b.alias".to_string()];
        g.last_published_addr = "192.0.2.10".to_string();
        {
            let mut state = eng.state.lock().unwrap();
            state.peers.insert("host-b".to_string(), g);
        }

        let eng = Arc::new(eng);
        let shutdown = Shutdown::new();
        let eng2 = Arc::clone(&eng);
        let sd2 = shutdown.clone();
        let handle = std::thread::spawn(move || eng2.run(sd2));

        std::thread::sleep(Duration::from_millis(200));
        let published = std::fs::read_to_string(&hosts_path).unwrap_or_default();

        shutdown.trigger();
        handle.join().expect("run() thread panicked");

        assert!(
            published.contains("192.0.2.10\thost-b host-b.alias"),
            "startup did not re-assert the restored winner with its full \
             hostnames list -- published block was:\n{published}"
        );
    }

    /// The other direction, and the reason the startup publish is
    /// conditional rather than unconditional: a first-ever start (nothing
    /// to restore) must NOT publish, because rendering an empty managed
    /// block would overwrite the activation script's seed -- the only
    /// last-known-good content in the file before the first probe tick
    /// completes. Publishing nothing is strictly better than publishing
    /// emptiness.
    #[test]
    fn startup_publish_skipped_when_nothing_was_restored() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let seed = "# BEGIN nixnet\n192.0.2.10\thost-b\n# END nixnet\n";
        std::fs::write(&hosts_path, seed).unwrap();

        let eng = Engine {
            hosts: HostsPublisher::new(&hosts_path).unwrap(),
            routes: RoutePublisher {
                ip_path: "/bin/true".to_string(),
            },
            status_path: dir.path().join("status.json"),
            state_path: dir.path().join("state.json"),
            state: Mutex::new(EngineState {
                peers: HashMap::new(),
                uplinks: HashMap::new(),
            }),
        };
        // A configured peer whose winner was never established, i.e. no
        // state.json existed to restore a `last_published_addr` from.
        let g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        eng.state
            .lock()
            .unwrap()
            .peers
            .insert("host-b".to_string(), g);

        eng.publish_restored_peers();

        assert_eq!(
            std::fs::read_to_string(&hosts_path).unwrap(),
            seed,
            "a start with nothing restored overwrote the activation seed \
             with an empty managed block"
        );
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

    // ------------------------------------------------------------------
    // STALE-2, the arithmetic and the LIVE path. The restore-from-disk
    // path -- the half the production defect actually lived in -- is
    // tested beside the code that implements it, in `state.rs`. It reuses
    // the `pub(super)` helpers below rather than owning a second copy of
    // them, so a group built for a live-path test and one built for a
    // restore test cannot drift into being different things.
    // ------------------------------------------------------------------

    pub(super) fn ago(secs: i64) -> OffsetDateTime {
        OffsetDateTime::now_utc() - time::Duration::seconds(secs)
    }

    /// The unbounded case is the DEFAULT, so this is the arm most
    /// configurations take: no bound declared, nothing ever expires. It is
    /// tested not because it is good but because changing it silently
    /// would change every existing deployment's behaviour at once.
    #[test]
    fn staleness_without_a_bound_never_expires() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            staleness(None, Some(now - time::Duration::days(11)), now),
            Staleness::Fresh
        );
        assert_eq!(staleness(None, None, now), Staleness::Fresh);
    }

    #[test]
    fn staleness_inside_the_bound_is_fresh() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            staleness(Some(60), Some(now - time::Duration::seconds(59)), now),
            Staleness::Fresh
        );
    }

    /// The boundary itself. `age == bound` is INSIDE: a bound of 60s means
    /// "may be published for 60 seconds", and expiring at exactly 60 would
    /// make the last second of every declared window a lie.
    #[test]
    fn staleness_exactly_at_the_bound_is_still_fresh() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            staleness(Some(60), Some(now - time::Duration::seconds(60)), now),
            Staleness::Fresh
        );
        assert!(matches!(
            staleness(Some(60), Some(now - time::Duration::seconds(61)), now),
            Staleness::Expired(_)
        ));
    }

    #[test]
    fn staleness_past_the_bound_reports_the_age() {
        let now = OffsetDateTime::now_utc();
        match staleness(Some(60), Some(now - time::Duration::seconds(3600)), now) {
            Staleness::Expired(age) => assert_eq!(age.whole_seconds(), 3600),
            other => panic!("expected Expired with an age, got {other:?}"),
        }
    }

    /// A bounded entry whose confirmation time was never recorded --
    /// state.json written by a nixnet that predates the timestamp. It
    /// cannot be shown to be inside its bound, so it is not.
    #[test]
    fn staleness_with_a_bound_but_no_confirmation_expires() {
        assert_eq!(
            staleness(Some(60), None, OffsetDateTime::now_utc()),
            Staleness::ExpiredUnknownAge
        );
    }

    /// A clock that moved backwards (NTP step, a VM restored from a
    /// snapshot) makes every confirmation look like it happened in the
    /// future. That is not evidence of staleness, and reading it as such
    /// would withdraw every name on the host at once -- the exact outage
    /// this daemon exists to prevent, caused by the fix for a different
    /// one.
    #[test]
    fn staleness_survives_a_clock_that_moved_backwards() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            staleness(Some(60), Some(now + time::Duration::hours(2)), now),
            Staleness::Fresh
        );
    }

    /// THE behaviour, on the live path: a peer down continuously for
    /// longer than its bound is REMOVED from the published block -- not
    /// annotated, not marked, removed. A hosts file cannot express
    /// "probably wrong".
    #[test]
    fn reconcile_withdraws_last_known_good_past_the_bound() {
        let (eng, dir) = new_test_engine();
        let hosts_path = dir.path().join("hosts");
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        g.max_age_sec = Some(60);
        let only = add_transport(&mut g, 10, "192.0.2.10");
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[only].state = TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        assert!(
            std::fs::read_to_string(&hosts_path)
                .unwrap()
                .contains("192.0.2.10"),
            "a healthy peer was never published in the first place"
        );

        // Everything goes down, and stays down past the bound.
        {
            let mut state = eng.state.lock().unwrap();
            let grp = state.group_mut(GroupKind::Peer, "host-b");
            grp.transports[only].state = TransportState::Down;
            grp.last_confirmed_at = Some(ago(3600));
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        let published = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(
            !published.contains("192.0.2.10"),
            "an address unconfirmed for an hour, under a 60s bound, is still \
             being published:\n{published}"
        );

        let state = eng.state.lock().unwrap();
        let g = state.group(GroupKind::Peer, "host-b");
        assert_eq!(g.last_published_addr, "", "withdrawal must clear the entry");
        assert_eq!(g.winner, None);
        assert!(
            g.degraded,
            "withdrawing is not recovering -- the subject stays red"
        );
    }

    /// The direction that stops the fix from being `unpublish` wearing a
    /// different name. Inside the bound, a failing peer STILL resolves --
    /// that is what lastKnownGood is for, and an implementation that
    /// withdrew immediately would satisfy every other assertion here.
    #[test]
    fn reconcile_keeps_last_known_good_inside_the_bound() {
        let (eng, dir) = new_test_engine();
        let hosts_path = dir.path().join("hosts");
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        g.max_age_sec = Some(3600);
        let only = add_transport(&mut g, 10, "192.0.2.10");
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[only].state = TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        {
            let mut state = eng.state.lock().unwrap();
            let grp = state.group_mut(GroupKind::Peer, "host-b");
            grp.transports[only].state = TransportState::Down;
            grp.last_confirmed_at = Some(ago(30)); // well inside 3600
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        assert!(
            std::fs::read_to_string(&hosts_path)
                .unwrap()
                .contains("192.0.2.10"),
            "a failing peer inside its bound stopped resolving -- that is \
             `unpublish`, not a bounded lastKnownGood"
        );
        let state = eng.state.lock().unwrap();
        assert!(
            state.group(GroupKind::Peer, "host-b").degraded,
            "still publishing is not still healthy"
        );
    }

    /// A bound expires an entry; it does not blacklist an address. Trading
    /// a stale answer for a permanently missing one is not an improvement.
    #[test]
    fn a_withdrawn_peer_is_published_again_when_it_comes_back() {
        let (eng, dir) = new_test_engine();
        let hosts_path = dir.path().join("hosts");
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        g.max_age_sec = Some(60);
        g.last_published_addr = "192.0.2.10".into();
        g.last_confirmed_at = Some(ago(3600));
        let only = add_transport(&mut g, 10, "192.0.2.10");
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

        {
            let mut state = eng.state.lock().unwrap();
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        assert!(!std::fs::read_to_string(&hosts_path)
            .unwrap()
            .contains("192.0.2.10"));

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[only].state = TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        assert!(
            std::fs::read_to_string(&hosts_path)
                .unwrap()
                .contains("192.0.2.10"),
            "a recovered peer was not re-published: the bound blacklisted \
             the address instead of expiring the entry"
        );
        let state = eng.state.lock().unwrap();
        let g = state.group(GroupKind::Peer, "host-b");
        assert!(!g.degraded);
        assert!(
            g.last_confirmed_at.unwrap() > ago(5),
            "recovery did not re-stamp the confirmation time"
        );
    }

    /// `unpublish` peers must not acquire a second, subtly different
    /// withdrawal path: they already clear on the first all-down tick, and
    /// the STALE-2 branch must never be the thing that does it for them.
    #[test]
    fn the_bound_does_not_apply_to_unpublish_peers() {
        let (eng, _dir) = new_test_engine();
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_UNPUBLISH);
        g.max_age_sec = Some(60);
        let only = add_transport(&mut g, 10, "192.0.2.10");
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

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
        assert_eq!(state.group(GroupKind::Peer, "host-b").last_published_addr, "");
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
