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

nixnet runs in production, so these are no longer blocked on "nobody has
deployed this" — they are blocked on someone doing the measurement.
Entries marked **closed** below were settled against a real deployment;
the rest are still open, and each says what specifically it needs.

## 001 — is 3000ms the right default probe interval?

**Question:** `nixnet.daemon.defaultProbe.intervalMs` defaults to
3000. Is that actually a good default for the two motivating scenarios —
a laptop roaming between WiFi networks (uplinks) and a server occasionally
losing its overlay VPN (peers) — or too slow/too chatty for either?

**Hypothesis:** 3s is a reasonable middle ground (the README's
[Non-goals (v1)](../README.md#non-goals-v1) already frames sub-second
failover as an explicit non-goal), but a laptop's
WiFi-roam or sleep/wake transition is a fundamentally different failure
shape (near-instant interface flap) than a server's overlay VPN drifting
(gradual, minutes-scale) — one fixed default for both may be leaving
something on the table in one direction or the other.

**Method sketch:** instrument `nixnetd` to log probe-to-detection latency
against a real WiFi-roam event (e.g. `NetworkManager` reassociating) and
compare against the same instrumentation on an overlay-VPN kill/restore
cycle. Both failure shapes now occur on hosts actually running nixnet —
the instrumentation is what's missing, not the deployment.

**Status:** open.

## 002 — is `minHoldMs` (10s peers / 15s uplinks) the right hysteresis floor?

**Question:** are the peer/uplink `hysteresis.minHoldMs` defaults tuned
against anything, or just picked to "feel" damped enough?

**Hypothesis:** picked, not measured — no measurement backs
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
needs `CAP_NET_RAW`) — capability-gated, so the grant only happens when
some transport actually uses ICMP or `bindToInterface`. Linux also
supports unprivileged `SOCK_DGRAM` ICMP (via
`net.ipv4.ping_group_range`), which a plain `Type::DGRAM` +
`Protocol::ICMPV4` socket also supports. Would defaulting to that — where
the sysctl happens to already permit it — let more peers-plus-ICMP
installs stay in the zero-capability common case the README's
[Security](../README.md#security) section describes?

**Hypothesis:** unlikely to be a clean win — `ping_group_range` is a
host-wide sysctl nixnet doesn't control and can't assume is set, and
falling back between the two modes per-host adds real complexity for a
capability grant that's already automatic and narrow. Worth a real
comparison before ruling it out, though.

**Status:** open.

## 004 — `SO_BINDTODEVICE` cost/behavior on a real WiFi/cellular pair

**Question:** `src/probe/bind_linux.rs`'s module doc justifies
`probe.bindToInterface` + `SO_BINDTODEVICE` as necessary because "an
unbound probe could succeed via the wrong interface and mask that the
'real' one is dead." True in principle — never verified against a real
dual-uplink laptop with actual
WiFi + cellular interfaces, where NetworkManager's own routing-policy
rules might already interact with `SO_BINDTODEVICE` in a way worth
knowing about before this ships anywhere real.

**Status:** open.

## 005 — one coarse `Mutex` vs per-transport locks, at scale

**Question:** `src/engine/mod.rs` uses a single `Engine.state: Mutex<..>`
guarding all group/transport state (see the module doc comment's
reasoning: this workload ticks in seconds, a handful of transports, one
lock is simpler and costs nothing observable). At what transport count
does that stop being true — does many hosts (dozens of peers, each
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
behavior, not from a captured real payload.

**Hypothesis:** the overall drift-detection *logic* (config.json
presence/validity, management-URL mismatch, NeedsLogin, interface
absence) is sound regardless of exact field names, but the specific `jq`
paths may need a one-time correction against a real `netbird status
--json` payload before first real deployment.

**Status: closed.** The hypothesis held: the drift-detection logic was
sound and the `jq` paths needed exactly the one-time correction this
entry predicted. Corrected against a real `netbird status --json` payload
from NetBird v0.74.3 — the address probe now queries the control socket
rather than reading `config.json` directly, and the identity-health check
matches that version's actual schema. See the `netbird-provider` commits
that landed those two fixes.

## 007 — NetworkManager metric-assignment churn, in practice

**Question:** nixnet's `ip route replace ... metric` can fight
NetworkManager's own automatic metric assignment on link-up/DHCP-renewal,
an accepted, un-fully-solved rough edge. How often does this actually
produce visible
journal churn on a real dual-uplink machine, and is it bad enough in
practice to warrant `NetworkManager.conf`'s
`ipv4.route-metric`/`ipv6.route-metric` being set to a fixed value as a
documented companion recommendation (not a nixnet feature — just
guidance) wherever nixnet manages uplink metrics?

**Status:** open.

## 008 — NetBird REST API `/policies` and `/routes` field paths are unverified against a real account

**Question:** `modules/netbird-access-model.nix`'s audit script parses
`GET /policies` (`.rules[0].sources`/`.destinations`/`.bidirectional`)
and `GET /routes` (`.network`/`.groups`) with `jq` expressions written
from NetBird's documented REST API shape — same caveat as #006, but for
the HTTP API instead of the CLI's `--json` output. #006 closing does not
close this one: `netbirdGroupReconcile`'s `/groups` calls run against a
real account daily, but `netbirdAccessModel`'s `/policies` and `/routes`
audit is the one module in this repo nothing enables yet, so precisely
these two field-path sets remain unexercised.

**Hypothesis:** the one-rule-per-policy assumption matches this
project's own usage pattern (a named policy = one directional edge —
`internal-mesh`, `internal-to-external`, one `grant-<device>-<nibble>`
per grant) and the field names are the documented ones, but neither has
been checked against a captured real payload.

**Status:** open — flagged explicitly (see the module's own header)
rather than silently assumed correct. A field-path miss degrades to
"can't confirm this one, logged and skipped," never a false
DIVERGENCE report, so the failure mode is annoying, not misleading.
