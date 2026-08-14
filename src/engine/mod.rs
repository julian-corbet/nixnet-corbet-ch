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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

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
    /// Stable persisted identity. List position is presentation only.
    key: String,

    state: TransportState,
    consecutive_success: i64,
    consecutive_failure: i64,
    current_address: String,
    detail: String,
    /// Successful observation backing this transport's effective address.
    last_success_at: Option<OffsetDateTime>,
    /// Monotonic worker progress used by the systemd watchdog.
    probe_started_at: Option<Instant>,
    next_probe_due: Option<Instant>,
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
    /// Uplinks only: the last route-publish failure already reported for
    /// this group, so a persistent one is logged once instead of once per
    /// tick. See `log_publish_error`.
    last_publish_error: String,
}

#[derive(Default)]
struct EngineState {
    peers: HashMap<String, Group>,
    uplinks: HashMap<String, Group>,
    /// The last hosts-publish failure already reported. Per ENGINE, not
    /// per group: the hosts file is one shared artifact that every peer
    /// group renders into, so a failure to write it is one event no matter
    /// which group's tick discovered it.
    last_hosts_error: String,
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
    status_ttl: Duration,

    state: Mutex<EngineState>,
    /// Serializes external publication without serializing probe state
    /// updates behind the external I/O itself.
    io_lock: Mutex<()>,
    last_state_write: Mutex<Option<Instant>>,
    last_status_write: Mutex<Option<Instant>>,
    initialized: AtomicBool,
}

/// One currently-healthy candidate, ordered by priority within
/// `reconcile_locked`.
struct Candidate {
    idx: usize,
    priority: i64,
}

enum Action {
    None,
    /// Re-render the managed hosts block. `passive` marks a tick that
    /// changed nothing in nixnet's own state, where an empty block must not
    /// overwrite the activation seed.
    PublishPeers {
        passive: bool,
    },
    PublishUplink(Vec<publish::RankedInterface>, i64, i64),
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
        let status_ttl = status_ttl(&cfg);
        let mut peers = HashMap::new();
        for (name, p) in cfg.peers {
            let mut transports = Vec::with_capacity(p.transports.len());
            for (i, t) in p.transports.into_iter().enumerate() {
                let id = transport_id(GroupKind::Peer, &name, i, &t);
                transports.push(TransportRuntime {
                    key: t.id.clone(),
                    spec: t,
                    id,
                    state: TransportState::Unknown,
                    consecutive_success: 0,
                    consecutive_failure: 0,
                    current_address: String::new(),
                    detail: String::new(),
                    last_success_at: None,
                    probe_started_at: None,
                    next_probe_due: None,
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
                    last_publish_error: String::new(),
                },
            );
        }

        let mut uplinks = HashMap::new();
        for (name, u) in cfg.uplinks {
            let mut transports = Vec::with_capacity(u.transports.len());
            for (i, t) in u.transports.into_iter().enumerate() {
                let id = transport_id(GroupKind::Uplink, &name, i, &t);
                transports.push(TransportRuntime {
                    key: t.id.clone(),
                    spec: t,
                    id,
                    state: TransportState::Unknown,
                    consecutive_success: 0,
                    consecutive_failure: 0,
                    current_address: String::new(),
                    detail: String::new(),
                    last_success_at: None,
                    probe_started_at: None,
                    next_probe_due: None,
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
                    last_publish_error: String::new(),
                },
            );
        }

        let mut state = EngineState {
            peers,
            uplinks,
            ..Default::default()
        };
        Self::load_state(&state_path, &mut state);

        Self {
            hosts,
            routes,
            status_path,
            state_path,
            status_ttl,
            state: Mutex::new(state),
            io_lock: Mutex::new(()),
            last_state_write: Mutex::new(None),
            last_status_write: Mutex::new(None),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn peer_count(&self) -> usize {
        self.state.lock().unwrap().peers.len()
    }

    pub fn uplink_count(&self) -> usize {
        self.state.lock().unwrap().uplinks.len()
    }

    /// Starts one thread per transport and blocks until shutdown.
    pub fn run(self: Arc<Self>, shutdown: Shutdown) {
        self.run_with_ready(shutdown, || {});
    }

    /// Calls `ready` only after workers exist and restored publications
    /// have been attempted. This is the only honest `READY=1` boundary.
    pub fn run_with_ready<F>(self: Arc<Self>, shutdown: Shutdown, ready: F)
    where
        F: FnOnce(),
    {
        let keys = self.transport_keys();
        let mut handles = Vec::with_capacity(keys.len());
        {
            let mut state = self.state.lock().unwrap();
            let now = Instant::now();
            for (kind, name, idx) in &keys {
                state.group_mut(*kind, name).transports[*idx].next_probe_due = Some(now);
            }
        }
        // Re-assert the hosts block from the winners restored out
        // of state.json, for the same reason: until this call existed,
        // NOTHING was published until some group's winner actually
        // CHANGED. A restart on a settled fleet changes no winner, so the
        // activation script's boot seed -- which keys each entry by the
        // peer's Nix ATTRIBUTE NAME, not its configured `hostnames` list
        // -- stayed in /etc/hosts indefinitely, and every alias a peer
        // declared beyond its attribute name was simply absent. Observed
        // in production: `getent hosts <alias>` returned NXDOMAIN on a
        // host whose nixnetd had been up, healthy, and reporting correct
        // winners for hours. The uplink half is the same claim about the
        // routing table: a DHCP client that renewed while this process was
        // down has already put the metric back where nixnet does not want
        // it. Workers start only after these publications, so a first probe
        // cannot race a restored-state publication.
        self.publish_restored_peers();
        self.publish_restored_uplinks();

        // Publish an initial status snapshot after startup I/O, so any
        // publication error is visible before READY=1 rather than being
        // hidden until a later probe tick.
        self.write_status(true);

        for key in keys {
            let eng = Arc::clone(&self);
            let sd = shutdown.clone();
            handles.push(std::thread::spawn(move || eng.run_transport(key, sd)));
        }
        self.initialized.store(true, Ordering::Release);
        ready();

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
            self.initialized.store(false, Ordering::Release);
            return;
        }

        while !shutdown.is_set() {
            if handles.iter().any(|h| h.is_finished()) {
                logf!(
                    "engine: a transport worker exited unexpectedly; terminating so systemd can restart the complete supervisor"
                );
                self.initialized.store(false, Ordering::Release);
                shutdown.trigger();
                break;
            }
            if shutdown.wait(Duration::from_millis(250)) {
                break;
            }
        }

        for h in handles {
            if h.join().is_err() {
                logf!("engine: transport worker panicked");
            }
        }
        self.initialized.store(false, Ordering::Release);
    }

    /// True only while the real engine is making bounded progress. A
    /// wedged state lock, stuck probe/publisher, or retired worker stops
    /// the heartbeat instead of being hidden by an independent timer.
    pub fn watchdog_healthy(&self, stall_limit: Duration) -> bool {
        if !self.initialized.load(Ordering::Acquire) {
            return false;
        }
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => return false,
        };
        let now = Instant::now();
        state
            .peers
            .values()
            .chain(state.uplinks.values())
            .flat_map(|g| g.transports.iter())
            .all(|tr| match tr.probe_started_at {
                Some(started) => now.saturating_duration_since(started) <= stall_limit,
                None => tr
                    .next_probe_due
                    .and_then(|due| due.checked_add(stall_limit))
                    .is_some_and(|deadline| now <= deadline),
            })
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

        let mut next = Instant::now();
        loop {
            let now = Instant::now();
            if now < next && shutdown.wait(next.duration_since(now)) {
                return;
            }
            {
                let mut state = self.state.lock().unwrap();
                let tr = &mut state.group_mut(kind, &name).transports[idx];
                tr.probe_started_at = Some(Instant::now());
                tr.next_probe_due = None;
            }
            self.probe_once(kind, &name, idx);
            next = next.checked_add(interval).unwrap_or_else(Instant::now);
            let now = Instant::now();
            if next < now {
                // Keep a start-to-start cadence, coalescing missed ticks so
                // a slow probe neither stretches every future threshold nor
                // creates a catch-up storm.
                next = now;
            }
            {
                let mut state = self.state.lock().unwrap();
                let tr = &mut state.group_mut(kind, &name).transports[idx];
                tr.probe_started_at = None;
                tr.next_probe_due = Some(next);
            }
        }
    }

    fn probe_once(&self, kind: GroupKind, name: &str, idx: usize) {
        let (spec, tr_id) = {
            let state = self.state.lock().unwrap();
            let tr = &state.group(kind, name).transports[idx];
            (tr.spec.clone(), tr.id.clone())
        };

        let mut res = match probe::run(&spec) {
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
        if res.healthy
            && !res.address.is_empty()
            && res.address.parse::<std::net::IpAddr>().is_err()
        {
            res.healthy = false;
            res.detail = format!(
                "exec probe returned invalid address {:?}; expected an IPv4 or IPv6 literal",
                res.address
            );
            res.address.clear();
        }

        let observed_at = OffsetDateTime::now_utc();
        let mut state = self.state.lock().unwrap();
        let (old_state, new_state, transition_count, tr_detail, address_changed);
        {
            let g = state.group_mut(kind, name);
            let tr = &mut g.transports[idx];
            old_state = tr.state;
            if res.healthy {
                tr.consecutive_failure = 0;
                let up_threshold = threshold(tr.spec.probe.up_threshold, 2);
                tr.consecutive_success = tr.consecutive_success.saturating_add(1).min(up_threshold);
                if tr.state != TransportState::Up && tr.consecutive_success >= up_threshold {
                    tr.state = TransportState::Up;
                }
                tr.last_success_at = Some(observed_at);
            } else {
                tr.consecutive_success = 0;
                let down_threshold = threshold(tr.spec.probe.down_threshold, 3);
                tr.consecutive_failure =
                    tr.consecutive_failure.saturating_add(1).min(down_threshold);
                if tr.state != TransportState::Down && tr.consecutive_failure >= down_threshold {
                    tr.state = TransportState::Down;
                }
            }
            // Only a healthy provider result may commit a newly-discovered
            // address. Otherwise down-threshold hysteresis can publish an
            // address that has never passed a probe.
            let old_address = tr.current_address.clone();
            if res.healthy && !res.address.is_empty() {
                tr.current_address = res.address.clone();
            } else if tr.current_address.is_empty() {
                tr.current_address = tr.spec.address.clone();
            }
            address_changed = tr.current_address != old_address;
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

        drop(state);

        let publication_changed = self.reconcile(kind, name);
        self.save_state(new_state != old_state || address_changed || publication_changed);

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

        self.write_status(new_state != old_state || publication_changed);
    }

    /// Implements winner-selection: among currently-healthy candidates,
    /// lowest priority number wins, damped by `minHoldMs` unless the
    /// current winner itself just went unhealthy. Also covers the
    /// documented extension beyond a literal reading of that rule:
    /// republishing when the current winner's own dynamically-discovered
    /// address changes, even with no winner-index change at all (a
    /// provider re-enrolling with a new overlay IP, e.g.). Callers must
    /// hold the lock (pass the already-locked `state`).
    ///
    /// TF-2: EVERY tick ends in a publication attempt, whether or not
    /// anything about this group changed. The publish backends compare
    /// what they would write against what is live and write only on a
    /// difference, so a settled group costs one file read or one route
    /// read-back and nothing else. Publication used to be emitted inside
    /// the winner-change branch alone, which made it fiction on any host
    /// whose winner never changes: a single-uplink host declared metric
    /// 600, ran on DHCP's metric 100, and logged not one publish line in
    /// the deployment's entire history. Publication is reconciliation
    /// against observed reality, and a transition-driven publisher is
    /// correct exactly until something else changes the world behind its
    /// back -- which is always.
    fn decide_action_locked(&self, state: &mut EngineState, kind: GroupKind, name: &str) -> Action {
        let now = OffsetDateTime::now_utc();
        let group_label = format!("{}={}", kind.label(), name);

        // The uplink half of TF-2, in one place: the ranking a group
        // publishes does not depend on whether anything changed this tick,
        // only on who the winner is -- so the "nothing changed" and "winner
        // changed" arms below hand back the identical action.
        let uplink_action = |g: &Group| -> Action {
            let ranked = uplink_ranking(g);
            if ranked.is_empty() {
                // No winner yet (nothing probed successfully since boot,
                // and nothing restored), route publication turned off, or
                // no interface named: nixnet has no opinion to assert.
                Action::None
            } else {
                Action::PublishUplink(ranked, g.metric_base, g.metric_step)
            }
        };

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
                    // Not passive: withdrawing the last entry on the host
                    // legitimately renders an empty block, and must.
                    Action::PublishPeers { passive: false }
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
                        // Still inside the bound: keep publishing it, and
                        // keep asserting it (TF-2) -- a retained
                        // last-known-good is exactly the entry most likely
                        // to be quietly dropped by something else, since
                        // nothing about it changes to trigger a rewrite.
                        Staleness::Fresh => Action::PublishPeers { passive: true },
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
                            Action::PublishPeers { passive: false }
                        }
                    }
                } else if kind == GroupKind::Uplink {
                    // Every uplink transport is down. The winner pointer is
                    // deliberately left where it was -- nixnet has no
                    // better candidate to name, and withdrawing the
                    // ranking would hand the choice back to whatever
                    // metrics DHCP happens to have installed. It is still
                    // re-asserted (TF-2): the published intent has not
                    // changed just because every probe is failing.
                    uplink_action(g)
                } else {
                    // lastKnownGood peers with nothing published to expire.
                    Action::PublishPeers { passive: true }
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

                // Freshness belongs to the selected transport's last
                // successful observation. A failed winner tick, or another
                // transport's successful tick, must not refresh it.
                g.last_confirmed_at = g.transports[new_winner].last_success_at;

                if !winner_changed && !address_drift {
                    // The settled case, and the one the old code treated as
                    // "nothing to do" -- which is how a host published
                    // nothing for its entire uptime. Nothing about the
                    // GROUP changed; the world outside it may have.
                    match kind {
                        GroupKind::Peer => Action::PublishPeers { passive: true },
                        GroupKind::Uplink => uplink_action(g),
                    }
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
                            Action::PublishPeers { passive: false }
                        }
                        GroupKind::Uplink => uplink_action(g),
                    }
                }
            }
        };

        action
    }

    #[cfg(test)]
    fn apply_action_locked(
        &self,
        state: &mut EngineState,
        kind: GroupKind,
        name: &str,
        action: Action,
    ) {
        let group_label = format!("{}={}", kind.label(), name);
        match action {
            Action::None => {}
            Action::PublishPeers { passive } => {
                // A passive tick must never render an EMPTY managed block:
                // before the first winner is established, the activation
                // script's boot seed is the only last-known-good content
                // that exists, and overwriting it with emptiness is
                // strictly worse than leaving it alone. A withdrawal
                // (`passive == false`) does exactly that on purpose.
                if passive && nothing_to_publish(state) {
                    return;
                }
                self.publish_peers_locked(state);
            }
            Action::PublishUplink(ranked, metric_base, metric_step) => {
                let out = self.routes.apply(&ranked, metric_base, metric_step);
                // One line per route actually moved -- and, because the
                // publisher writes only on a difference, no line at all
                // when the live table already agreed. This is TF-2's
                // "logging the re-assert": on a settled host it is silent
                // for months and then says exactly what changed the table
                // back.
                for c in &out.changes {
                    logf!(
                        "group={} route re-assert dev={} metric={}->{}",
                        group_label,
                        c.interface,
                        c.from_metric,
                        c.to_metric
                    );
                }
                let what = format!("publish routes for group={}", group_label);
                let g = state.group_mut(kind, name);
                log_publish_error(
                    &mut g.last_publish_error,
                    &what,
                    out.error.map(|e| e.to_string()),
                );
            }
        }
    }

    /// Reconciles one group while keeping every filesystem operation and
    /// route command outside the engine-state mutex. Other probe workers
    /// can therefore record failures and make watchdog progress even when
    /// an external publisher is slow. `io_lock` preserves publication
    /// ordering across those workers.
    fn reconcile(&self, kind: GroupKind, name: &str) -> bool {
        let _io = self.io_lock.lock().unwrap();
        let (action, entries, peer_set_empty, state_changed) = {
            let mut state = self.state.lock().unwrap();
            let group = state.group(kind, name);
            let before = (
                group.winner,
                group.degraded,
                group.last_published_addr.clone(),
            );
            let action = self.decide_action_locked(&mut state, kind, name);
            let group = state.group(kind, name);
            let after = (
                group.winner,
                group.degraded,
                group.last_published_addr.clone(),
            );
            let entries = if matches!(&action, Action::PublishPeers { .. }) {
                peer_entries(&state)
            } else {
                Vec::new()
            };
            let empty = nothing_to_publish(&state);
            (action, entries, empty, before != after)
        };

        let mut changed = state_changed;
        let group_label = format!("{}={}", kind.label(), name);
        match action {
            Action::None => {}
            Action::PublishPeers { passive } => {
                if passive && peer_set_empty {
                    return state_changed;
                }
                let result = self.hosts.publish(&entries);
                if let Ok(true) = result {
                    logf!(
                        "hosts re-assert: wrote {} entries -- the live file did not match what this daemon publishes",
                        entries.len()
                    );
                }
                let mut state = self.state.lock().unwrap();
                let old_error = state.last_hosts_error.clone();
                log_publish_error(
                    &mut state.last_hosts_error,
                    "publish hosts",
                    result.err().map(|e| e.to_string()),
                );
                changed |= old_error != state.last_hosts_error;
            }
            Action::PublishUplink(ranked, metric_base, metric_step) => {
                let out = self.routes.apply(&ranked, metric_base, metric_step);
                for change in &out.changes {
                    logf!(
                        "group={} route re-assert dev={} metric={}->{}",
                        group_label,
                        change.interface,
                        change.from_metric,
                        change.to_metric
                    );
                }
                let what = format!("publish routes for group={}", group_label);
                let mut state = self.state.lock().unwrap();
                let group = state.group_mut(kind, name);
                let old_error = group.last_publish_error.clone();
                log_publish_error(
                    &mut group.last_publish_error,
                    &what,
                    out.error.map(|e| e.to_string()),
                );
                changed |= old_error != group.last_publish_error;
            }
        }
        changed
    }

    /// Test/startup compatibility wrapper. Runtime probe ticks use
    /// [`Engine::reconcile`], which releases the state lock before I/O.
    #[cfg(test)]
    fn reconcile_locked(&self, state: &mut EngineState, kind: GroupKind, name: &str) {
        let action = self.decide_action_locked(state, kind, name);
        self.apply_action_locked(state, kind, name, action);
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
        let mut state = self.state.lock().unwrap();
        if nothing_to_publish(&state) {
            return;
        }
        self.publish_peers_locked(&mut state);
    }

    /// The uplink counterpart, for the same reason: the winner restored
    /// from `state.json` is what this host had already decided, and the
    /// routing table it is decided about belongs to the kernel, not to
    /// this process -- a DHCP client that renewed while the daemon was
    /// down has already rewritten the metric back. Doing it here rather
    /// than waiting for the first probe tick closes a window of one probe
    /// interval on every restart.
    ///
    /// Deliberately a no-op when nothing was restored: `uplink_ranking`
    /// yields nothing without a winner, and nixnet never invents a
    /// ranking it has not measured.
    fn publish_restored_uplinks(&self) {
        let mut state = self.state.lock().unwrap();
        let names: Vec<String> = state.uplinks.keys().cloned().collect();
        for name in names {
            let (ranked, metric_base, metric_step) = {
                let g = &state.uplinks[&name];
                (uplink_ranking(g), g.metric_base, g.metric_step)
            };
            if ranked.is_empty() {
                continue;
            }
            let out = self.routes.apply(&ranked, metric_base, metric_step);
            for c in &out.changes {
                logf!(
                    "group=uplink={} route re-assert dev={} metric={}->{} (restart)",
                    name,
                    c.interface,
                    c.from_metric,
                    c.to_metric
                );
            }
            let what = format!("publish routes for group=uplink={}", name);
            let g = state.uplinks.get_mut(&name).expect("uplink group exists");
            log_publish_error(
                &mut g.last_publish_error,
                &what,
                out.error.map(|e| e.to_string()),
            );
        }
    }

    /// Rewrites the whole managed hosts block from every peer group's
    /// current `last_published_addr` (not just the group that just
    /// changed) -- the publish backend is a single shared file, so any
    /// change requires re-rendering the entire block. Callers must hold
    /// the lock.
    ///
    /// TF-2: called on every peer tick, and the backend writes only when
    /// the rendered block differs from the live file, so the ordinary
    /// outcome is one read and nothing else.
    fn publish_peers_locked(&self, state: &mut EngineState) {
        let entries = peer_entries(state);
        let result = self.hosts.publish(&entries);
        if let Ok(true) = result {
            logf!(
                "hosts re-assert: wrote {} entries -- the live file did not \
                 match what this daemon publishes",
                entries.len()
            );
        }
        log_publish_error(
            &mut state.last_hosts_error,
            "publish hosts",
            result.err().map(|e| e.to_string()),
        );
    }

    /// Renders `/run/nixnet/status.json`. Transitions are immediate; steady
    /// ticks are coalesced to at most one filesystem transaction per
    /// second when multiple transport workers complete together.
    fn write_status(&self, force: bool) {
        // This guard is also the status writer lock. Keep it across the
        // atomic rename so two workers cannot land snapshots out of order.
        let mut last = self.last_status_write.lock().unwrap();
        if !force && last.is_some_and(|time| time.elapsed() < Duration::from_secs(1)) {
            return;
        }
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
                valid_until: String::new(),
                last_hosts_publish_error: state.last_hosts_error.clone(),
                peers,
                uplinks,
            }
        };

        if let Err(e) = status::write(&self.status_path, snap, self.status_ttl) {
            logf!("write status: {}", e);
        } else {
            *last = Some(Instant::now());
        }
    }
}

fn status_ttl(cfg: &Config) -> Duration {
    let longest_ms = cfg
        .peers
        .values()
        .flat_map(|group| group.transports.iter())
        .chain(
            cfg.uplinks
                .values()
                .flat_map(|group| group.transports.iter()),
        )
        .map(|transport| {
            transport
                .probe
                .interval_ms
                .saturating_add(transport.probe.timeout_ms)
        })
        .max()
        .unwrap_or(0)
        .saturating_add(5_000)
        .max(15_000);
    Duration::from_millis(longest_ms as u64)
}

fn peer_entries(state: &EngineState) -> Vec<publish::Entry> {
    state
        .peers
        .values()
        .filter(|group| !group.last_published_addr.is_empty())
        .map(|group| publish::Entry {
            address: group.last_published_addr.clone(),
            hostnames: group.hostnames.clone(),
            // STALE-1: consumers can compute age without knowing the probe
            // cadence or reading status.json.
            confirmed_at: group
                .last_confirmed_at
                .and_then(|time| time.format(&Rfc3339).ok()),
        })
        .collect()
}

/// True when no peer group has anything to publish -- a first-ever start,
/// or a wiped stateDir. Rendering the managed block then would write an
/// EMPTY one over the activation script's boot seed, which is the only
/// last-known-good content in the file at that point.
fn nothing_to_publish(state: &EngineState) -> bool {
    state
        .peers
        .values()
        .all(|g| g.last_published_addr.is_empty())
}

/// The full published ranking for an uplink group: the winner first, then
/// every OTHER transport of the same subject -- healthy ones in priority
/// order, then the rest. `apply` turns the position into a metric, so the
/// position IS the published preference.
///
/// TF-3: the losers are in this list, and that is the whole point. A
/// ranking of healthy candidates only leaves the transport that just
/// FAILED sitting on the metric it won with, so the ex-winner and the new
/// winner both end up at `metricBase` -- two equal-cost defaults, between
/// which the kernel picks whichever it likes, possibly the dead one.
/// Demoting the loser is not a detail of metric failover; it is the
/// entirety of it.
///
/// Health outranks priority for the non-winners on purpose: the metric
/// order is the order the kernel falls back through if nixnet's own winner
/// stops working before the next probe notices, so a DOWN transport must
/// never sit ahead of a healthy one, however preferred it is on paper.
fn uplink_ranking(g: &Group) -> Vec<publish::RankedInterface> {
    let winner = match g.winner {
        Some(w) if g.route_metric && w < g.transports.len() => w,
        _ => return Vec::new(),
    };

    let mut order: Vec<usize> = (0..g.transports.len()).filter(|&i| i != winner).collect();
    order.sort_by_key(|&i| {
        let tr = &g.transports[i];
        (tr.state != TransportState::Up, tr.spec.priority, i)
    });
    order.insert(0, winner);

    let mut ranked = Vec::with_capacity(order.len());
    let mut seen: Vec<&str> = Vec::with_capacity(order.len());
    for i in order {
        let tr = &g.transports[i];
        // An uplink transport with no interface cannot have a route
        // reprioritized (config validation rejects one, so this is the
        // hand-written-JSON path), and two transports sharing ONE
        // interface -- two probe targets over the same link -- would
        // otherwise be handed two different metrics for the same route and
        // fight over it, every tick, forever. The better-ranked one wins.
        if tr.spec.interface.is_empty() || seen.contains(&tr.spec.interface.as_str()) {
            continue;
        }
        seen.push(&tr.spec.interface);
        ranked.push(publish::RankedInterface {
            interface: tr.spec.interface.clone(),
            healthy: tr.state == TransportState::Up,
        });
    }
    ranked
}

/// Logs a publish failure only when it is not the one already reported,
/// and logs the recovery when it clears.
///
/// TF-2 made publication a per-tick operation, so a failure that persists
/// -- a read-only `/etc`, an interface that stays gone -- would otherwise
/// emit one identical line every tick: ~29,000 lines a day describing a
/// single event, which is its own outage, and the same arithmetic that
/// makes the STALE-2 withdrawal log exactly once.
fn log_publish_error(reported: &mut String, what: &str, err: Option<String>) {
    match err {
        Some(e) => {
            if *reported != e {
                logf!("{}: {}", what, e);
                *reported = e;
            }
        }
        None => {
            if !reported.is_empty() {
                logf!("{}: recovered", what);
                reported.clear();
            }
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
        last_publish_error: g.last_publish_error.clone(),
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

/// Derives a readable log/status label. Persisted identity is the separate
/// `TransportRuntime::key`; the index here is only useful to locate the
/// declaration a human is looking at.
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
    // The recording stand-in `ip`, shared with the publisher's own tests so
    // "the engine called it" and "it emitted the right thing" stay claims
    // about one program.
    use crate::publish::route::tests as route_fakes;

    pub(super) fn new_test_engine() -> (Engine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let hosts = HostsPublisher::new(dir.path().join("hosts")).unwrap();
        // Never actually mutate routing in a test.
        let routes = RoutePublisher::new("/bin/true");
        let eng = Engine {
            hosts,
            routes,
            status_path: dir.path().join("status.json"),
            state_path: dir.path().join("state.json"),
            status_ttl: Duration::from_secs(30),
            state: Mutex::new(EngineState::default()),
            io_lock: Mutex::new(()),
            last_state_write: Mutex::new(None),
            last_status_write: Mutex::new(None),
            initialized: AtomicBool::new(false),
        };
        (eng, dir)
    }

    /// The same engine, but pointed at the recording stand-in `ip` instead
    /// of `/bin/true`: every route command the engine issues (and, more to
    /// the point of TF-2, every one it does NOT issue) is readable from
    /// `dir/argv.log` afterwards.
    fn new_routing_engine() -> (Engine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let eng = Engine {
            hosts: HostsPublisher::new(dir.path().join("hosts")).unwrap(),
            routes: RoutePublisher::new(route_fakes::fake_ip(dir.path())),
            status_path: dir.path().join("status.json"),
            state_path: dir.path().join("state.json"),
            status_ttl: Duration::from_secs(30),
            state: Mutex::new(EngineState::default()),
            io_lock: Mutex::new(()),
            last_state_write: Mutex::new(None),
            last_status_write: Mutex::new(None),
            initialized: AtomicBool::new(false),
        };
        (eng, dir)
    }

    /// An uplink group as a settled host has it: a winner already selected
    /// (restored from state.json across the last restart, or chosen hours
    /// ago), every transport healthy, nothing about to change.
    fn settled_uplink(eng: &Engine, name: &str, ifaces: &[(&str, i64)], winner: usize) {
        let mut g = new_uplink_group(10_000, 100, 50);
        for (iface, priority) in ifaces {
            let idx = add_uplink_transport(&mut g, *priority, iface);
            g.transports[idx].state = TransportState::Up;
        }
        g.winner = Some(winner);
        g.winner_since = Some(OffsetDateTime::now_utc());
        eng.state.lock().unwrap().uplinks.insert(name.into(), g);
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
            last_publish_error: String::new(),
        }
    }

    /// An uplink group the way `Engine::new` builds one, with route-metric
    /// publication on -- the configuration the whole of TF-2/TF-3 is
    /// about.
    pub(super) fn new_uplink_group(min_hold_ms: i64, metric_base: i64, metric_step: i64) -> Group {
        Group {
            kind: GroupKind::Uplink,
            hostnames: Vec::new(),
            on_all_down: String::new(),
            max_age_sec: None,
            route_metric: true,
            metric_base,
            metric_step,
            min_hold_ms,
            transports: Vec::new(),
            winner: None,
            winner_since: None,
            degraded: false,
            last_published_addr: String::new(),
            last_confirmed_at: None,
            last_publish_error: String::new(),
        }
    }

    /// Adds an uplink transport, which is addressed by INTERFACE rather
    /// than by address -- that is the whole difference between a group
    /// that publishes a name and one that publishes a route metric.
    pub(super) fn add_uplink_transport(g: &mut Group, priority: i64, interface: &str) -> usize {
        g.transports.push(TransportRuntime {
            spec: config::Transport {
                id: interface.to_string(),
                priority,
                interface: interface.to_string(),
                ..Default::default()
            },
            id: interface.to_string(),
            key: interface.to_string(),
            state: TransportState::Unknown,
            consecutive_success: 0,
            consecutive_failure: 0,
            current_address: String::new(),
            detail: String::new(),
            last_success_at: Some(OffsetDateTime::now_utc()),
            probe_started_at: None,
            next_probe_due: None,
        });
        g.transports.len() - 1
    }

    /// Mirrors the real invariant `probe_once` maintains: every
    /// transport's `current_address` is populated before
    /// `reconcile_locked` ever looks at it (falling back to
    /// `spec.address` when a probe result carries no dynamic override).
    /// Returns the transport's index within `g.transports` -- tests that
    /// specifically exercise a *changing* dynamic address mutate
    /// `transports[idx].current_address` directly afterward.
    pub(super) fn add_transport(g: &mut Group, priority: i64, address: &str) -> usize {
        let key = if address.is_empty() {
            "test-dynamic".to_string()
        } else {
            address.to_string()
        };
        g.transports.push(TransportRuntime {
            spec: config::Transport {
                id: key.clone(),
                priority,
                address: address.to_string(),
                ..Default::default()
            },
            id: key.clone(),
            key,
            state: TransportState::Unknown,
            consecutive_success: 0,
            consecutive_failure: 0,
            current_address: address.to_string(),
            detail: String::new(),
            last_success_at: Some(OffsetDateTime::now_utc()),
            probe_started_at: None,
            next_probe_due: None,
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

    #[test]
    fn readiness_means_the_supervisor_watchdog_is_live() {
        let (eng, _dir) = new_test_engine();
        let eng = Arc::new(eng);
        let shutdown = Shutdown::new();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runner = Arc::clone(&eng);
        let runner_shutdown = shutdown.clone();
        let handle = std::thread::spawn(move || {
            runner.run_with_ready(runner_shutdown, || ready_tx.send(()).unwrap())
        });

        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(eng.watchdog_healthy(Duration::from_secs(10)));

        shutdown.trigger();
        handle.join().unwrap();
        assert!(!eng.watchdog_healthy(Duration::from_secs(10)));
    }

    #[test]
    fn a_stuck_transport_makes_the_watchdog_withhold_heartbeats() {
        let (eng, _dir) = new_test_engine();
        let mut group = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let transport = add_transport(&mut group, 10, "192.0.2.10");
        group.transports[transport].probe_started_at =
            Instant::now().checked_sub(Duration::from_secs(30));
        eng.state
            .lock()
            .unwrap()
            .peers
            .insert("host-b".into(), group);
        eng.initialized.store(true, Ordering::Release);

        assert!(!eng.watchdog_healthy(Duration::from_secs(10)));
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
            routes: RoutePublisher::new("/bin/true"),
            status_path: dir.path().join("status.json"),
            state_path: dir.path().join("state.json"),
            status_ttl: Duration::from_secs(30),
            state: Mutex::new(EngineState::default()),
            io_lock: Mutex::new(()),
            last_state_write: Mutex::new(None),
            last_status_write: Mutex::new(None),
            initialized: AtomicBool::new(false),
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
    // TF-2: publication happens on reconcile, not only on winner change.
    //
    // The defect these cover is not hypothetical and not partial: the route
    // publisher had never run, on any host, in the entire life of the
    // deployment. It was emitted from inside the winner-change branch
    // alone, and a single-uplink host has no winner change after the first
    // one -- which, restored from state.json, never happens again either.
    // So the host declared metricBase 600, ran on DHCP's metric 100, and
    // logged not one publish line, while every test in this file passed.
    // A test that merely EXERCISES the publisher proves nothing about
    // that; these assert on which ticks it is reached.
    // ------------------------------------------------------------------

    /// THE production case. One uplink, winner already established, no
    /// winner change now or ever again -- and the live route is still on
    /// the metric DHCP gave it. Against the old code this asserts nothing
    /// happening at all: no `ip` invocation of any kind.
    #[test]
    fn a_settled_single_uplink_host_still_publishes_its_metric() {
        let (eng, dir) = new_routing_engine();
        // The live route is the one DHCP installed, at DHCP's metric --
        // which is what every host in the deployment was actually running
        // on while its config declared something else entirely.
        route_fakes::canned_route(
            dir.path(),
            "wan0",
            r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wan0","protocol":"dhcp","metric":600,"flags":[]}]"#,
        );
        settled_uplink(&eng, "internet", &[("wan0", 10)], 0);

        {
            let mut state = eng.state.lock().unwrap();
            eng.reconcile_locked(&mut state, GroupKind::Uplink, "internet");
        }

        assert_eq!(
            route_fakes::published_metrics(dir.path()),
            vec![("wan0".to_string(), 100)],
            "a host whose winner never changes published nothing -- which is \
             the entire defect: the declared metric is fiction and the live \
             route keeps whatever DHCP set"
        );
    }

    /// ...and the reason the metric above is 100 rather than the canned
    /// 600: TF-2's "Not:" clause. A reconcile that finds the live table
    /// already saying what nixnet publishes must issue NO route command --
    /// otherwise the fix trades a silent no-op for two route-table
    /// transactions per interface per tick, forever.
    #[test]
    fn an_uplink_reconcile_against_an_agreeing_table_writes_nothing() {
        let (eng, dir) = new_routing_engine();
        route_fakes::canned_route(
            dir.path(),
            "wan0",
            r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wan0","metric":100,"flags":[]}]"#,
        );
        settled_uplink(&eng, "internet", &[("wan0", 10)], 0);

        for _ in 0..3 {
            let mut state = eng.state.lock().unwrap();
            eng.reconcile_locked(&mut state, GroupKind::Uplink, "internet");
        }

        assert!(
            !route_fakes::invocations(dir.path()).is_empty(),
            "the live table was never even read, so nothing was reconciled"
        );
        assert_eq!(
            route_fakes::writes(dir.path()),
            Vec::<Vec<String>>::new(),
            "an unchanged uplink rewrote the routing table anyway"
        );
    }

    // ------------------------------------------------------------------
    // TF-3: the loser is demoted in the same operation that promotes the
    // winner.
    // ------------------------------------------------------------------

    /// A real failover between two uplinks. The old publisher re-metricked
    /// only the candidates it could verify as Up, so the interface that had
    /// just FAILED kept the metric it won with: both defaults ended at
    /// metricBase, tied, and the kernel picked between two equal-cost
    /// routes -- possibly the dead one.
    #[test]
    fn a_winner_change_leaves_no_two_transports_sharing_a_metric() {
        let (eng, dir) = new_routing_engine();
        // The table as the previous publication left it: wired0 won at
        // 100, wireless0 sat one step behind at 150.
        route_fakes::canned_route(
            dir.path(),
            "wired0",
            r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wired0","metric":100,"flags":[]}]"#,
        );
        route_fakes::canned_route(
            dir.path(),
            "wireless0",
            r#"[{"dst":"default","gateway":"192.0.2.129","dev":"wireless0","metric":150,"flags":[]}]"#,
        );
        settled_uplink(&eng, "internet", &[("wired0", 10), ("wireless0", 50)], 0);

        // The wire is cut.
        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Uplink, "internet").transports[0].state =
                TransportState::Down;
            eng.reconcile_locked(&mut state, GroupKind::Uplink, "internet");
        }

        assert_eq!(
            eng.state
                .lock()
                .unwrap()
                .group(GroupKind::Uplink, "internet")
                .winner,
            Some(1),
            "the dead transport is still the winner"
        );

        let metrics = route_fakes::published_metrics(dir.path());
        let winner = metrics
            .iter()
            .find(|(dev, _)| dev == "wireless0")
            .unwrap_or_else(|| panic!("the new winner was never published: {metrics:?}"))
            .1;
        let loser = metrics
            .iter()
            .find(|(dev, _)| dev == "wired0")
            .unwrap_or_else(|| {
                panic!(
                    "the transport that just failed was never demoted, so it \
                     still holds the metric it won with: {metrics:?}"
                )
            })
            .1;
        assert!(
            winner < loser,
            "the new winner is not strictly cheaper than the ex-winner \
             ({winner} vs {loser}) -- the kernel is choosing between two \
             defaults on its own"
        );

        let mut seen: Vec<i64> = metrics.iter().map(|(_, m)| *m).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            before,
            "two transports share a metric: {metrics:?}"
        );
    }

    /// TF-3's boundary, which is as load-bearing as the demotion itself:
    /// nixnet does NOT delete the loser's route. Deleting a default that a
    /// foreign DHCP client installed puts the host one lease renewal away
    /// from a fight nixnet loses -- and, in the meantime, with no route at
    /// all over an interface that may be the only one that comes back.
    #[test]
    fn the_demoted_loser_keeps_a_default_route() {
        let (eng, dir) = new_routing_engine();
        route_fakes::canned_route(
            dir.path(),
            "wired0",
            r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wired0","metric":100,"flags":[]}]"#,
        );
        route_fakes::canned_route(
            dir.path(),
            "wireless0",
            r#"[{"dst":"default","gateway":"192.0.2.129","dev":"wireless0","metric":150,"flags":[]}]"#,
        );
        settled_uplink(&eng, "internet", &[("wired0", 10), ("wireless0", 50)], 0);

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Uplink, "internet").transports[0].state =
                TransportState::Down;
            eng.reconcile_locked(&mut state, GroupKind::Uplink, "internet");
        }

        // Replay the recorded commands against the interface's route set:
        // `replace` installs at a metric, `del` removes the one at that
        // metric. What survives is what the kernel would be left holding.
        let mut wired0: Vec<i64> = vec![100];
        for a in route_fakes::writes(dir.path()) {
            if a.iter().any(|x| x == "wired0") {
                let metric: i64 = a.last().unwrap().parse().unwrap();
                match a[1].as_str() {
                    "replace" => {
                        if !wired0.contains(&metric) {
                            wired0.push(metric)
                        }
                    }
                    "del" => wired0.retain(|m| *m != metric),
                    other => panic!("unexpected route verb {other}: {a:?}"),
                }
            }
        }
        assert_eq!(
            wired0,
            vec![150],
            "the loser's default route did not end up demoted-and-intact -- \
             an empty set here means nixnet deleted a route a DHCP client \
             owns"
        );
    }

    /// Health outranks declared priority for the non-winners. The metric
    /// order IS the order the kernel falls back through when nixnet's
    /// winner stops working before the next probe notices, so a DOWN
    /// transport must never sit ahead of a healthy one, however preferred
    /// it is on paper.
    #[test]
    fn a_down_transport_ranks_behind_every_healthy_one() {
        let mut g = new_uplink_group(0, 100, 50);
        let dead_but_preferred = add_uplink_transport(&mut g, 10, "wired0");
        let healthy_fallback = add_uplink_transport(&mut g, 50, "wireless0");
        let healthy_winner = add_uplink_transport(&mut g, 20, "wwan0");
        g.transports[dead_but_preferred].state = TransportState::Down;
        g.transports[healthy_fallback].state = TransportState::Up;
        g.transports[healthy_winner].state = TransportState::Up;
        g.winner = Some(healthy_winner);

        let ranked: Vec<String> = uplink_ranking(&g)
            .iter()
            .map(|r| r.interface.clone())
            .collect();
        assert_eq!(ranked, vec!["wwan0", "wireless0", "wired0"]);
    }

    /// Two transports over ONE interface -- two probe targets across the
    /// same link -- share one default route. Handing each its own metric
    /// would have them rewrite that single route twice per tick, forever.
    #[test]
    fn two_transports_on_one_interface_are_published_once() {
        let mut g = new_uplink_group(0, 100, 50);
        for _ in 0..2 {
            let i = add_uplink_transport(&mut g, 10, "wan0");
            g.transports[i].state = TransportState::Up;
        }
        g.winner = Some(0);

        assert_eq!(uplink_ranking(&g).len(), 1);
    }

    /// Route publication is opt-out per uplink, and staying out means
    /// staying out: nothing is read, nothing is written.
    #[test]
    fn an_uplink_with_route_metric_off_publishes_nothing() {
        let (eng, dir) = new_routing_engine();
        settled_uplink(&eng, "internet", &[("wan0", 10)], 0);
        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Uplink, "internet").route_metric = false;
            eng.reconcile_locked(&mut state, GroupKind::Uplink, "internet");
        }
        assert_eq!(
            route_fakes::invocations(dir.path()),
            Vec::<Vec<String>>::new()
        );
    }

    // ------------------------------------------------------------------
    // TF-2, the peer half: the same rule about the hosts file.
    // ------------------------------------------------------------------

    /// Something else emptied the managed block -- an activation, an
    /// editor, a package's post-install script. With publication driven by
    /// winner changes alone, a settled host never noticed: the names stayed
    /// NXDOMAIN until something unrelated changed a winner.
    #[test]
    fn a_hosts_block_emptied_behind_the_daemon_is_restored_on_the_next_tick() {
        let (eng, dir) = new_test_engine();
        let hosts_path = dir.path().join("hosts");
        let mut g = new_peer_group("host-b", 10_000, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let only = add_transport(&mut g, 10, "192.0.2.10");
        g.winner = Some(only);
        g.winner_since = Some(OffsetDateTime::now_utc());
        g.last_published_addr = "192.0.2.10".to_string();
        g.transports[only].state = TransportState::Up;
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

        std::fs::write(&hosts_path, "# BEGIN nixnet\n# END nixnet\n").unwrap();

        {
            let mut state = eng.state.lock().unwrap();
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        let published = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(
            published.contains("192.0.2.10\thost-b"),
            "the daemon's own published entry stayed missing through a \
             reconcile, because no winner happened to change:\n{published}"
        );
    }

    /// The other half of the same rule. A tick that changes nothing must
    /// not touch the file -- asserted on the INODE, because publication is
    /// tmpfile-plus-rename and it is the rename, not the content, that
    /// wakes every watcher of `/etc/hosts`. The per-entry freshness
    /// comment moves on every tick, so a naive byte comparison would
    /// rewrite the file forever.
    #[test]
    fn a_peer_reconcile_that_changes_nothing_does_not_rewrite_the_file() {
        use std::os::unix::fs::MetadataExt;
        let (eng, dir) = new_test_engine();
        let hosts_path = dir.path().join("hosts");
        let mut g = new_peer_group("host-b", 10_000, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let only = add_transport(&mut g, 10, "192.0.2.10");
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

        {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").transports[only].state = TransportState::Up;
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }
        let after_first = std::fs::metadata(&hosts_path).unwrap().ino();

        for _ in 0..3 {
            let mut state = eng.state.lock().unwrap();
            state.group_mut(GroupKind::Peer, "host-b").last_confirmed_at = Some(ago(1));
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        assert_eq!(
            std::fs::metadata(&hosts_path).unwrap().ino(),
            after_first,
            "a settled peer rewrote /etc/hosts on every tick"
        );
    }

    /// The guard that stops per-tick publication from destroying the boot
    /// seed: before any winner exists, the activation script's seed is the
    /// only last-known-good content in the file, and a passive tick must
    /// never render an EMPTY managed block over it.
    #[test]
    fn a_passive_tick_never_writes_an_empty_block_over_the_seed() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let seed = "# BEGIN nixnet\n192.0.2.10\thost-b\n# END nixnet\n";
        std::fs::write(&hosts_path, seed).unwrap();
        let eng = Engine {
            hosts: HostsPublisher::new(&hosts_path).unwrap(),
            routes: RoutePublisher::new("/bin/true"),
            status_path: dir.path().join("status.json"),
            state_path: dir.path().join("state.json"),
            status_ttl: Duration::from_secs(30),
            state: Mutex::new(EngineState::default()),
            io_lock: Mutex::new(()),
            last_state_write: Mutex::new(None),
            last_status_write: Mutex::new(None),
            initialized: AtomicBool::new(false),
        };
        let mut g = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        add_transport(&mut g, 10, "192.0.2.10"); // still Unknown: nothing has probed yet
        eng.state.lock().unwrap().peers.insert("host-b".into(), g);

        {
            let mut state = eng.state.lock().unwrap();
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        assert_eq!(
            std::fs::read_to_string(&hosts_path).unwrap(),
            seed,
            "a tick before the first winner overwrote the boot seed with an \
             empty block"
        );
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

    #[test]
    fn another_transports_tick_does_not_refresh_the_winners_evidence() {
        let (eng, _dir) = new_test_engine();
        let mut group = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let winner = add_transport(&mut group, 10, "192.0.2.10");
        let other = add_transport(&mut group, 20, "192.0.2.20");
        group.transports[winner].state = TransportState::Up;
        group.transports[other].state = TransportState::Up;
        group.transports[winner].last_success_at = Some(ago(3600));
        group.transports[other].last_success_at = Some(OffsetDateTime::now_utc());
        group.winner = Some(winner);
        group.winner_since = Some(ago(3600));
        group.last_published_addr = "192.0.2.10".into();
        group.last_confirmed_at = Some(ago(3600));
        eng.state
            .lock()
            .unwrap()
            .peers
            .insert("host-b".into(), group);

        {
            let mut state = eng.state.lock().unwrap();
            eng.reconcile_locked(&mut state, GroupKind::Peer, "host-b");
        }

        let state = eng.state.lock().unwrap();
        let confirmed = state.peers["host-b"].last_confirmed_at.unwrap();
        assert!(
            confirmed < ago(3500),
            "a different transport laundered the stale winner into a fresh publication"
        );
    }

    #[test]
    fn a_failing_exec_probe_cannot_replace_the_published_address() {
        use std::os::unix::fs::PermissionsExt;

        let (eng, dir) = new_test_engine();
        let script = dir.path().join("failing-provider");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '%s\\n' '{\"address\":\"203.0.113.99\"}'\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut group = new_peer_group("host-b", 0, config::ON_ALL_DOWN_LAST_KNOWN_GOOD);
        let transport = add_transport(&mut group, 10, "192.0.2.10");
        group.transports[transport].state = TransportState::Up;
        group.transports[transport].spec.probe.method = "exec".into();
        group.transports[transport].spec.probe.exec = script.display().to_string();
        group.transports[transport].spec.probe.timeout_ms = 1000;
        group.transports[transport].spec.probe.down_threshold = 3;
        group.winner = Some(transport);
        group.last_published_addr = "192.0.2.10".into();
        eng.state
            .lock()
            .unwrap()
            .peers
            .insert("host-b".into(), group);

        eng.probe_once(GroupKind::Peer, "host-b", transport);

        let state = eng.state.lock().unwrap();
        let group = &state.peers["host-b"];
        assert_eq!(group.transports[transport].current_address, "192.0.2.10");
        assert_eq!(group.last_published_addr, "192.0.2.10");
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
        assert_eq!(
            state.group(GroupKind::Peer, "host-b").last_published_addr,
            ""
        );
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

    /// A transport can probe healthy while its publication backend is
    /// broken. The status document must carry that distinction; otherwise
    /// `nixnetctl` calls a route or hosts decision healthy even though the
    /// kernel/file never received it.
    #[test]
    fn status_exposes_hosts_and_uplink_publication_failures() {
        let (eng, dir) = new_test_engine();
        let mut uplink = new_uplink_group(10_000, 100, 50);
        uplink.last_publish_error = "ip route replace: permission denied".to_string();

        {
            let mut state = eng.state.lock().unwrap();
            state.last_hosts_error = "read-only file system".to_string();
            state.uplinks.insert("internet".to_string(), uplink);
        }

        eng.write_status(true);
        let snapshot = status::read(&dir.path().join("status.json")).unwrap();
        assert_eq!(
            snapshot.last_hosts_publish_error, "read-only file system",
            "a shared hosts-file error disappeared from status.json"
        );
        assert_eq!(
            snapshot.uplinks["internet"].last_publish_error, "ip route replace: permission denied",
            "a route publication error disappeared from status.json"
        );
    }
}
