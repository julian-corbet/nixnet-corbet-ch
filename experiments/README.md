# Experiments

Throwaway trials: spikes, one-off scripts, measurements not yet worth
writing up properly. Nothing here is guaranteed to work, be maintained, or
survive the next cleanup pass. If something in here turns out to matter,
distill the actual finding into [`../studies/`](../studies/README.md) and
let the experiment stay disposable (or delete it).

This is also the open-questions ledger for nixnet's own judgment calls —
every entry below corresponds to a default or design choice that's
reasoned, not measured. Results feed back into `modules/core.nix`'s
defaults or `docs/providers.md`'s deviation notes as they close.

All open; nothing has been run yet (fresh scaffold, no real fleet has run
this code).

## 001 — is 3000ms the right default probe interval?

**Question:** `nixnet.daemon.defaultProbe.intervalMs` defaults to
3000. Is that actually a good default for the two motivating scenarios —
a laptop roaming between WiFi networks (uplinks) and a server occasionally
losing its overlay VPN (peers) — or too slow/too chatty for either?

**Hypothesis:** 3s is a reasonable middle ground (design.md §12 already
frames sub-second failover as an explicit non-goal), but a laptop's
WiFi-roam or sleep/wake transition is a fundamentally different failure
shape (near-instant interface flap) than a server's overlay VPN drifting
(gradual, minutes-scale) — one fixed default for both may be leaving
something on the table in one direction or the other.

**Method sketch:** instrument `nixnetd` to log probe-to-detection latency
against a real WiFi-roam event (e.g. `NetworkManager` reassociating) and
compare against the same instrumentation on an overlay-VPN kill/restore
cycle. No fleet host runs nixnet yet, so this can't be done for real until
one does.

**Status:** open.

## 002 — is `minHoldMs` (10s peers / 15s uplinks) the right hysteresis floor?

**Question:** are the peer/uplink `hysteresis.minHoldMs` defaults tuned
against anything, or just picked to "feel" damped enough?

**Hypothesis:** picked, not measured — design.md doesn't cite a source for
either number. A principled alternative worth testing: derive the floor
from the *other* thresholds already in play (e.g.
`downThreshold * intervalMs`, so the hold window scales with how long it
already takes to detect a failure in the first place) rather than a fixed
constant that's right for the default cadence and wrong for anyone who
overrides `intervalMs`.

**Method sketch:** a synthetic flapping transport (alternates healthy/dead
on a controlled cadence) against both a fixed-constant and a
derived-from-thresholds `minHoldMs`, comparing route/hosts-file churn
count over a fixed test window.

**Status:** open.

## 003 — privileged raw ICMP vs unprivileged `ping_group_range` SOCK_DGRAM

**Question:** `src/probe/icmp.rs`'s ICMP prober uses privileged raw
sockets (`Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))`,
needs `CAP_NET_RAW`) per design.md §1's "capability-gated, only when
needed" story. Linux also supports unprivileged `SOCK_DGRAM` ICMP (via
`net.ipv4.ping_group_range`), which a plain `Type::DGRAM` +
`Protocol::ICMPV4` socket also supports. Would defaulting to that — where
the sysctl happens to already permit it — let more peers-plus-ICMP
installs stay in the zero-capability common case design.md §8 wants?

**Hypothesis:** unlikely to be a clean win — `ping_group_range` is a
host-wide sysctl nixnet doesn't control and can't assume is set, and
falling back between the two modes per-host adds real complexity for a
capability grant that's already automatic and narrow. Worth a real
comparison before ruling it out, though.

**Status:** open.

## 004 — `SO_BINDTODEVICE` cost/behavior on a real WiFi/cellular pair

**Question:** design.md §1 justifies `probe.bindToInterface` +
`SO_BINDTODEVICE` as necessary because "an un-bound probe... can succeed
via whichever default route the kernel currently prefers." True in
principle — never verified against a real dual-uplink laptop with actual
WiFi + cellular interfaces, where NetworkManager's own routing-policy
rules might already interact with `SO_BINDTODEVICE` in a way worth
knowing about before this ships anywhere real.

**Status:** open.

## 005 — one coarse `Mutex` vs per-transport locks, at scale

**Question:** `src/engine/mod.rs` uses a single `Engine.state: Mutex<..>`
guarding all group/transport state (see the module doc comment's
reasoning: this workload ticks in seconds, a handful of transports, one
lock is simpler and costs nothing observable). At what transport count
does that stop being true — does a large fleet (dozens of peers, each
with several transports) start to see probe-tick jitter from lock
contention against `publish_peers_locked`'s file I/O?

**Method sketch:** a synthetic config with O(100) transports, instrumented
tick-to-tick jitter measurement, before deciding whether per-group (not
necessarily per-transport) locking is warranted.

**Status:** open.

## 006 — `netbird status --json` field paths are unverified against a real install

**Question:** `modules/netbird-provider.nix`'s address-probe, drift-check,
and reprovision scripts all parse `netbird status --json` with `jq`
expressions like `.managementState.url // .management.url` and
`.peers[].fqdn // .peers[].hostName` — written defensively (trying a
couple of plausible field-name variants) from the CLI's documented
behavior, not from a captured real payload, since no fleet host in this
project's development environment runs NetBird.

**Hypothesis:** the overall drift-detection *logic* (config.json
presence/validity, management-URL mismatch, NeedsLogin, interface
absence) is sound regardless of exact field names, but the specific `jq`
paths may need a one-time correction against a real `netbird status
--json` payload before first real deployment.

**Status:** open — flagged explicitly rather than silently assumed
correct; see also `docs/providers.md`'s deviation notes for what's a
verified interpretation of design.md versus what's a filled-in gap.

## 007 — NetworkManager metric-assignment churn, in practice

**Question:** design.md §5.2 already documents the *possibility* of
nixnet's `ip route replace ... metric` fighting NetworkManager's own
automatic metric assignment on link-up/DHCP-renewal, as an accepted,
un-fully-solved rough edge. How often does this actually produce visible
journal churn on a real dual-uplink machine, and is it bad enough in
practice to warrant `NetworkManager.conf`'s
`ipv4.route-metric`/`ipv6.route-metric` being set to a fixed value as a
documented companion recommendation (not a nixnet feature — just
guidance) wherever nixnet manages uplink metrics?

**Status:** open.
