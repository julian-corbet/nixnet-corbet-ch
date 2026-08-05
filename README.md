# nixnet

A small, resident, provider-agnostic failover daemon plus a NixOS (and
`system-manager`) module surface. It solves one problem, in one generic
shape, twice:

- **"Which address currently reaches peer X?"** — a named remote host may
  be reachable over several transports (a LAN address, an overlay-VPN
  address, ...); nixnet picks the best currently-healthy one and publishes
  it so `ssh host-b`, `mount host-b:/export`, and everything else that
  already resolves hostnames just work, with zero per-application
  mesh-awareness.
- **"Which local uplink should carry egress traffic right now?"** — a
  machine with several local network interfaces (wired, WiFi, cellular)
  should keep using the best currently-healthy one, with a flapping or
  fragile one automatically deprioritized.

Both are the same abstraction — *N candidate transports, priority-ordered,
individually health-checked, hysteresis-damped, one deterministic winner
published on change* — walked by the same engine. Only the **publish
backend** differs (an `/etc/hosts` entry for peers; a kernel route metric
for uplinks).

Providers plug into this engine by contributing ordinary list entries into
one shared schema, optionally backed by a tiny, stable **exec contract**
(a script, JSON-on-stdout, an exit code) for transports whose address or
health can't be known at Nix-eval time. Core never has provider-specific
code in it — see [`docs/providers.md`](docs/providers.md) for the full
contract, and `modules/netbird-provider.nix` for a complete, real,
non-stub example.

`netbird-provider` ships first-party in this same repo: it wraps upstream
`services.netbird` (never reimplementing NetBird's own install/config
management) and adds the concrete, non-interactive fix for the failure
class that motivated this project — local NetBird identity state going
empty or stale, and the daemon silently falling back to a default
management endpoint. It detects that drift precisely (including "looks
connected but enrolled against the wrong server") and re-enrolls
headlessly from a setup-key secret, failing loudly, never silently, when
it can't.

## Quickstart

```nix
{
  inputs.nixnet.url = "github:julian-corbet/nixnet-corbet-ch";
}
# host configuration.nix:
imports = [ inputs.nixnet.nixosModules.default ];

nixnet.enable = true;

# ── Remote peer: LAN-preferred, overlay-fallback ──
nixnet.peers."host-b" = {
  hostnames = [ "host-b" ];
  transports = [
    {
      address  = "192.0.2.20";      # TEST-NET-1 placeholder LAN address
      priority = 10;                # lower wins when healthy
      probe = { method = "tcp"; port = 22; intervalMs = 2000; timeoutMs = 800;
                upThreshold = 2; downThreshold = 3; };
    }
    # The overlay transport is NOT hand-written here -- netbird-provider
    # (below) contributes it automatically into this same transports list.
  ];
  hysteresis.minHoldMs = 10000;
  onAllDown = "lastKnownGood";
  lastKnownGood.maxAgeSec = 900;  # stop publishing an address no probe has
                                  # confirmed for 15 min; null warns and
                                  # keeps publishing it forever
};

# ── Local dual-uplink: wired-preferred, wireless/cellular fallback ──
nixnet.uplinks."internet" = {
  transports = [
    { interface = "wired0";    priority = 10;
      probe = { method = "tcp"; target = "192.0.2.53"; port = 443;
                intervalMs = 3000; upThreshold = 3; downThreshold = 5; }; }
    { interface = "wireless0"; priority = 50;
      probe = { method = "icmp"; target = "192.0.2.53"; bindToInterface = true;
                intervalMs = 3000; upThreshold = 3; downThreshold = 5; }; }
    { interface = "cellular0"; priority = 90;
      probe = { method = "icmp"; target = "192.0.2.53"; bindToInterface = true;
                intervalMs = 5000; timeoutMs = 1500; upThreshold = 3; downThreshold = 5; }; }
  ];
  hysteresis.minHoldMs = 15000;
  publish = { routeMetric = true; metricBase = 100; metricStep = 50; };
};

# ── netbird-provider: contributes host-b's overlay transport automatically ──
nixnet.netbird = {
  enable        = true;
  managementUrl = "https://mesh.example.com";
  setupKeyFile  = config.sops.secrets."nixnet-netbird-setup-key".path;
  peers."host-b" = { priority = 50; };   # overlay address discovered dynamically

  reprovision = {
    enable = true;
    checkIntervalSec = 60;
    minReprovisionIntervalSec = 300;
    driftFailureThreshold = 3;
  };
};

# Consumers just use it, with zero mesh-awareness:
#   ssh host-b
#   mount host-b:/export /mnt
```

`imports = [ inputs.nixnet.nixosModules.netbird-provider ];` alongside
`.default` to pull in the provider.

## How it fits together

```
nixnet.peers / uplinks
            |
            v
 /etc/nixnet/config.json          (rendered once, at build time)
            |
            v
      +------------+
      |  nixnetd   |   one probe thread + ticker per transport
      +-----+------+
            |
   every tick: does what is
   live differ from what is
   published? (TF-2)
       /            \
      v              v
+-----------+  +---------------------------+
| /etc/hosts|  | ip route replace default  |
| (managed  |  | dev IFACE metric N        |
|  block)   |  +---------------------------+
+-----------+
      |
      v
ssh, mount, curl, browsers --
every ordinary NSS files-then-dns lookup
```

`nixnetd` is entirely Nix-unaware — it only ever reads
`/etc/nixnet/config.json` and writes JSON/text elsewhere
(`/var/lib/nixnet-hosts/hosts`, `/run/nixnet/status.json`,
`/var/lib/nixnet/state.json`). The same binary works unmodified from a
Nix-rendered config, a hand-written one, or a `system-manager` render.
`status.json` reports the last hosts-file publication error globally and the
last route-metric publication error for each uplink, so a healthy probe does
not mask a publisher that failed to apply its decision.

## Beyond peer/uplink: resident-daemon watchdogs

nixnet's charter is broader than "peer address failover" + "uplink
egress selection" — those are the two shapes that fit `nixnetd`'s own
probe-and-publish engine, but the underlying idea is simpler and wider:
**any declaratively-managed network connection that can fail and needs
non-interactive recovery belongs in nixnet's namespace.** `netbird-provider`
already does two things: it contributes NetBird's overlay address as a
peer transport (the engine-shaped half), *and* it runs an independent
drift-check/reprovision loop that catches "looks connected, isn't
actually" and non-interactively re-enrolls (a daemon-health-watchdog
half that has nothing to do with the engine at all).

`cloudflared-provider` is the second half on its own, applied to a daemon
that structurally can't be a peer transport: a Cloudflare Tunnel client
is inbound-only (it *receives* public traffic; it never helps this host
*reach* a peer), so it has no address to contribute. What it shares with
NetBird is the failure mode — a wedged QUIC/HTTP2 edge connection that
`Restart=on-failure` never sees, because the process never actually
dies. `cloudflared-provider` probes cloudflared's own `/ready` health
endpoint on a timer and restarts the tunnel service non-interactively
past a drift threshold, same hysteresis-then-act shape as
`netbird-provider`'s reprovisioning, no peer/uplink engine involved.

```nix
imports = [ inputs.nixnet.nixosModules.cloudflared-provider ]; # core.nix NOT required

nixnet.cloudflared = {
  enable = true;
  tunnelUnit = "cloudflared-tunnel-00000000-0000-0000-0000-000000000000"; # bare unit name, no ".service"
};
```

See `modules/cloudflared-provider.nix`'s own header comment for the full
design note, and expect more providers in this second, non-transport
shape over time as more "this can fail and should heal itself"
candidates show up.

## Owning the networking mechanism itself

Everything above *observes* or *fails over between* connections someone
else brought up. This repo also ships the modules that bring the
connections up in the first place — the overlay network, the group
membership that governs it, the multi-peer gateway that gives services
their own identities on it, and the public ingress in front of them. None
of these contribute a peer/uplink transport and none require
`nixosModules.core`.

- **`nixnet.overlay`** (`modules/overlay.nix`) — turn this host into a
  NetBird overlay client, optionally the account's routing peer
  (`advertiseRoutes`), with an external-device confinement rule
  (`confineExternalRanges`/`confineExternalAllow`) closing the blanket
  forward-accept hole a routing peer otherwise leaves open. Distinct from
  `nixnet.netbird` (above): that module is about REACHING a specific peer
  through the failover engine; this one is about THIS host's own overlay
  membership. A host commonly runs both.

  Its packet-path rules live in an nftables table this module **owns**
  (`inet nixnet-overlay`), applied by its own unit — not in
  `networking.firewall.extraCommands`. That matters for more than tidiness:
  `extraCommands` is honoured by the iptables backend alone, so on an
  nftables-backed firewall it is an eval error and on a host with
  `networking.firewall.enable = false` it is discarded **with no error at
  all**. A deny rule that can silently not exist is not a deny rule. Because
  nftables lets several tables hook the same point and runs them all, this
  table coexists with the nixpkgs firewall (either backend), a third-party
  nftables ruleset, and NetBird's own tables, without any of them knowing it
  is there. `nixnet.overlay.ruleset` is the rendered text, read-only, so you
  can `nix eval` exactly what a host will load before it loads it.

  Confinement is per address family and `confineExternalRanges` is a list:
  a confined v4 source range cannot match v6 packets, so confining an
  advertised v6 prefix takes its own v6 entry. Declaring one without the
  other is an assertion error rather than a quietly unreachable rule — and
  IPv6 forwarding is only enabled when a v6 prefix is actually advertised,
  since turning on a forwarding plane this module writes no rules for is
  worse than leaving it off.
- **`nixnet.meshGateway`** (`modules/mesh-gateway.nix`) — one process
  holding N self-hosted-NetBird identities (an embed client per configured
  peer), L4-forwarding each to a real backend. Gives a service (or a
  client-less machine) its own overlay address without running its own
  NetBird client. Owns the systemd/config-rendering mechanism only —
  `package` is a required option: bring your own build of a program that
  reads the rendered JSON and speaks NetBird's embed-client library (see
  the module's own header for why the binary itself is out of scope here).
- **`nixnet.netbirdGroupReconcile`** (`modules/netbird-group-reconcile.nix`)
  — keeps NetBird peer→group membership in sync with a declared IP-octet
  addressing scheme, on a timer, so a group→group ACL grant picks up a
  peer that enrolls later. Membership-only: never creates/deletes groups
  or policies. `bands`/`catchAllGroup` are **live NetBird object names** —
  see the module's own header warning before wiring this in.
- **`nixnet.netbirdAccessModel`** (`modules/netbird-access-model.nix`) —
  declares the SHAPE of a NetBird account's access control (which groups
  exist, which directional policies connect them, which groups receive
  which routes) as an option surface with assertions, plus a read-only
  timer that audits the live account against it. Never creates, renames,
  or deletes anything account-side — same boundary as
  `netbirdGroupReconcile` above, which it wires into (one host's
  `internalGroup` feeds `netbirdGroupReconcile.catchAllGroup` as a
  default, so a group is named exactly once when both are enabled). See
  the module's own header for the rename-in-place warning and the
  operator runbook below for the exact ordered steps of a live rename.
- **`nixnet.ingress`** (`modules/ingress.nix`) — provisions a Cloudflare
  Tunnel (public hostname → local service ingress) plus an optional
  host-side DNS reconciler. Companion to `nixnet.cloudflared` (the
  watchdog, above), not a replacement — point the watchdog's `tunnelUnit`
  at `"cloudflared-tunnel-${config.nixnet.ingress.tunnelId}"` to watch the
  tunnel this module provisions.
- **`nixnet.bpftune`** (`modules/bpftune.nix`) — an explicit opt-in to
  NixOS's upstream `services.bpftune` daemon. It is a runtime transport
  policy writer, not a baseline package: use it only on a host that owns its
  kernel and networking policy. Foreign system-manager hosts can select their
  native package through `nixnet.backend.bpftune` instead.
- **`nixnet.wireguard`** (`modules/wireguard.nix`) — an authenticated,
  private dual-stack transit. It transports private IPv4 and IPv6 addresses
  over WireGuard; only a declared hub listener opens a public UDP port, and
  forwarding is limited to the tunnel's own authenticated interface pair.
- **`lib.svcProxyConfig`** (`lib/svc-proxy-config.nix`) — not a module, a
  pure function: turns a service registry into a split-horizon in-cluster
  nginx config + CoreDNS zone, so an in-cluster caller of `<svc>.<zone>`
  gets the same HTTPS experience as an overlay or public-tunnel caller.
  Called from a consumer's own flake `outputs` or host config, same as
  `nixpkgs.lib` itself.

These six modules are NixOS-only for now — each uses at least one
primitive (`boot.kernel.sysctl`, `networking.firewall.extraCommands`, or
upstream `services.cloudflared`) outside `system-manager`'s smaller option
surface (see the `system-manager` section below for that boundary).
`netbirdAccessModel` itself only touches `systemd.services`/`.timers`
(so it *could* run on `system-manager`), but it's listed here because it
has no purpose without the overlay/reconcile mechanism the rest of this
section brings up.

### Renaming a live group or policy — the operator runbook

`nixnet.netbirdAccessModel` and `nixnet.netbirdGroupReconcile` both
declare **names**; neither ever calls a rename endpoint (see each
module's own header). Renaming a group or policy that real policies
already reference is safe, but only IN PLACE (same object `id`, new
`name` field) — never "create a new one and delete the old one" (a new
object gets a new `id`, orphaning every policy/route still pointing at
the old one). Ordered steps, using a `workers → internal` /
`workers-mesh → internal-mesh` / `workers-to-external →
internal-to-external` rename as a worked, illustrative example (substitute your own real
group/policy names):

1. **Account-side, first:** `PUT` each object's existing `id` with only
   its `name` field changed — the group, then each policy. This is
   non-disruptive at every step: every rule/route still resolves the
   same `id`, so mid-rename traffic behavior does not change at all.
2. **Then** flip the Nix declaration — `groups.internal` (was
   `groups.workers`), `policies.internal-mesh.{from,to}` /
   `policies.internal-to-external.{from,to}` referencing `"internal"`,
   and `nixnet.netbirdAccessModel.internalGroup = "internal"` — to match.
   Set `renamedFrom` on the renamed group/policy entries to their old
   name for one deploy cycle, so the audit (if `audit.enable`) can
   confirm the old name is actually gone live, then remove `renamedFrom`.
3. **If `nixnet.netbirdGroupReconcile` is also enabled**, its `bands`/
   `catchAllGroup` must reference the SAME new names — flipping step 2
   already does this for `catchAllGroup` if it was relying on
   `netbirdAccessModel`'s default; a `bands` entry naming the group
   explicitly needs its own edit.

**What breaks if this runs out of order:**

- **Flipping the Nix declaration BEFORE the account-side rename (step 2
  before step 1)** is *safe*, just inert: `netbirdGroupReconcile` looks
  up a group's `id` by matching its CURRENT live `name` — if nothing
  live is yet named `"internal"`, it logs `WARN: managed group
  'internal' absent` every tick and changes nothing (by design — it
  never creates a group). `netbirdAccessModel`'s own assertions still
  pass (they only check the declaration is internally consistent, never
  reach the account), and its audit (if enabled) reports every renamed
  group/policy as "declared, not found live by name" until step 1 lands.
  Nothing is torn down; the mesh keeps working on the OLD names the
  whole time.
- **Doing the account-side rename as "create new + delete old" instead
  of a `name`-only `PUT`** is the genuinely dangerous order this whole
  model exists to catch: the new group gets a new `id`, so every
  existing policy/route rule still lists the OLD (now-deleted) group's
  `id` — NetBird drops those rule entries to a dangling reference, and
  the flow that policy was supposed to allow silently stops being
  allowed (or, for a route, stops being distributed) with no error
  raised anywhere. This is exactly "a policy referencing a group that
  does not exist" — always rename in place.

## The firewall — one owner, derived rules

`nixnet.firewall` (`modules/firewall.nix`, generator in `lib/ruleset.nix`)
renders and applies this host's nftables ruleset: a default-deny input
chain, an optional forward chain, no egress filtering. It is imported by
`modules/core.nix` rather than offered as a separate module, and that is
the whole design.

**Why it lives here.** It used to be its own repo. A firewall repo cannot
know how the host gets its address, so a default-drop input chain dropped
the DHCP RENEW leg on a DHCP-addressed edge host. The initial DISCOVER
goes out over AF_PACKET and never traverses netfilter, so the box came up
addressed and looked healthy; the lease expired ~21h later and the host
went dark with symptoms naming DNS, the metadata service and the overlay —
everything except the firewall, because the change and the outage were
most of a day apart. The missing rule is one line and nobody forgot it:
the repo that rendered the ruleset had no way to see the fact that
motivates it.

So rules **derive from declared facts**, and each derived rule names its
fact in the ruleset itself:

- **DHCP client accepts** ← `nixnet.interfaces.<i>.addressing.v4 = "dhcp"`
  (or `.v6`). A statically-addressed host does not carry them; a
  SLAAC-addressed one gets no DHCPv6 accept either, because router
  advertisements are ICMPv6, which the preamble already accepts. The
  declaration also says *which* interface renews, so the accept is scoped
  to it. Client direction only — accepting `dport 67` would quietly make
  every DHCP-addressed host reachable as a DHCP *server*.
- **Overlay confinement CIDRs** ← the octet band already declared in
  `nixnet.netbirdGroupReconcile.bands`, plus
  `nixnet.firewall.overlayConfinement.network` (the overlay's own /24 —
  address space, not a boundary). The confined band defaults to
  `excludeFromCatchAll.forBand`, the one the account already treats as
  least-trust. The band is computed into exact CIDRs (an unaligned band
  `3-9` renders `.3/32, .4/30, .8/31`, never a prefix that swallows
  addresses nobody put in it) and published into
  `nixnet.overlay.confineExternalRanges` as a default. Hand-writing the
  same boundary twice is how the two quietly stop matching, and the
  direction that fails is silent: a prefix narrower than the band leaves
  the peers outside it unconfined with every rule still present.
- **Forward accepts for the routed overlay path** ←
  `nixnet.overlay.advertiseRoutes`. Every base chain at a hook sees the
  packet and **any** chain's drop is final, so a drop-policy forward chain
  in nixnet's table overrides the accepts the overlay module's own table
  (and NetBird) rely on. On a routing peer those accepts are derived
  rather than remembered.

**What fails at evaluation, on the build host:**

- a default-deny ruleset with neither `management.interfaces` nor
  `trustedInterfaces` — the config that builds, activates, reports
  success and strands a machine reachable only over the interface nobody
  named;
- an interface named in any rule that is not in `nixnet.interfaces` (a
  misspelled interface matches nothing and fails **open**, silently, with
  the rule still sitting there looking correct);
- an interface whose `addressing` leaves a family unset — `unmanaged` is a
  real answer and a different one from silence;
- `forward.rules` without `forward.enable`, and a rule with neither
  `ports` nor `portRanges`;
- `nixnet.firewall.table` colliding with the table `nixnet.overlay`
  renders into (both replace their table with `add; delete; define`, so
  the one that applies second deletes the other's chains — leaving either
  no input policy or no overlay confinement, both units green);
- `nixnet.overlay.confineExternalRanges` not covering the derived band;
- `networking.firewall`/`networking.nftables` left enabled alongside this
  one — two default-drop input chains at one hook intersect rather than
  combine, and neither configuration looks wrong on its own.

**Guards that are not negotiable:**

- **Never `flush ruleset`.** The ruleset replaces exactly one table with
  `add; delete; define`, and turning the module off deletes that one table
  and nothing else. This is also why the module owns its apply unit
  instead of handing the text to `networking.nftables`: that module
  defaults `flushRuleset` to true whenever it is given a raw ruleset and
  concatenates the `flush ruleset` into the same transaction, which would
  wipe k3s, docker, podman, libvirt and nixnet's own overlay table off the
  host on every apply.
- **Management interfaces first**, before the host's own rules and not
  overridable by them.
- **A failed apply is not a host with no firewall.** The apply unit runs
  under `set -eu` with no `|| true` anywhere, so the loader's exit status
  *is* the signal; the load is one `nft -f` transaction, so a failure
  leaves the previous ruleset byte-identical; and a *finished* apply with
  nixnet's table absent exits non-zero rather than reporting success — the
  state a production host was found in, from a serial console, with
  nothing on the host saying so. The unit deliberately has **no
  `ExecStop`**: a changed ruleset makes the switch stop-and-start it, and
  a teardown-on-stop would delete the firewall *before* trying to load its
  replacement, turning a bad ruleset into an open host.
- **Dead-man switch** (`autoRevert`, on by default): snapshot our table,
  arm a timer, restore unless `nixnet-firewall-confirm` runs. It arms on a
  ruleset **change**, never on a boot — arming every boot meant the timer
  fired on every headless boot, nobody typed the confirmation, and the
  revert (with no prior table to restore) deleted the firewall outright.
- **Silent drops** for traffic that is dropped anyway: on the host this
  generalises, 66% of kernel log lines were the firewall logging ordinary
  LAN broadcast housekeeping — the noise that hid a real WireGuard drop.

**Two tables, one host.** On a routing peer nixnet writes two nftables
tables: this one (host policy) and `nixnet.overlay`'s (the overlay
mechanism's confinement and source-NAT). That remains two writers — the
firewall derives the confinement and asserts the two agree, it does not
render the overlay's rules into its own table. The overlay's table name is
read out of the text that module will actually load, not hardcoded, so
renaming it there cannot silently stop the collision check from matching.

**Both planes, one text, one unit.** `nixnet.firewall.ruleset` is
read-only and rendered even when `enable` is false, so `nix eval` shows
exactly what a host would load before it loads it. It is written to the
store and copied to `/etc/nftables/nixnet.nft` for reading, and
`nixnet-firewall.service` — same name on NixOS and on `system-manager` —
loads the **store path**, so the unit's own text moves whenever a rule
does. That is the only diff either delivery engine acts on:
`system-manager` restarts a unit when the unit's store path changes and
has no "a file this unit reads changed" notion at all, and it has no
`networking.nftables` either (its `networking.firewall` is a mock that
accepts the whole NixOS schema, warns, and touches nothing — for a
firewall, silent success is the worst failure mode there is).

`nixnet.firewall.enable = false` does not mean *absent*: the unit still
runs, and its job becomes asserting nixnet's table is gone, so a
generation that turns the firewall off cannot leave the previous one's
rules in the kernel. On NixOS, `networking.firewall.enable = false` is
required and asserted.

```nix
networking.firewall.enable = false;   # nixnet owns the input chain now

nixnet.interfaces = {
  wt0.addressing  = { v4 = "static"; v6 = "none"; };  # overlay tunnel
  eth0.addressing = { v4 = "dhcp";   v6 = "slaac"; }; # DHCP: earns the renewal accepts
};

nixnet.firewall = {
  enable = true;
  management.interfaces = [ "wt0" ];   # the way back in, never removable
  allow = [
    { protocol = "tcp"; ports = [ 80 443 ]; comment = "public web"; }
    { protocol = "udp"; portRanges = [{ from = 49160; to = 49360; }];
      sourcesV4 = [ "192.0.2.0/24" ]; comment = "turn relay"; }
  ];
  silentDrops = [ { match = "udp dport 5355"; comment = "LLMNR"; } ];
};
```

`experiments/render-check.nix` is the eval-time check for all of it —
real NixOS evaluations, both directions on every derivation (a
declared-DHCP host **gets** the accepts, a static host **does not**) and
every refusal asserted by the message it must produce, not just by a
count:

```
nix-instantiate --eval --strict experiments/render-check.nix -A ok
```

## Options reference

`nixnet.*` (`modules/core.nix`):

- `enable` — turn the engine on.
- `package` — the `nixnetd`/`nixnetctl` build; override only to pin/patch.
- `daemon.stateDir` (default `/var/lib/nixnet`), `daemon.runtimeDir`
  (default `nixnet`, under `/run`), `daemon.hostsFile` (default
  `/var/lib/nixnet-hosts/hosts` — under `/var/lib`, not `runtimeDir`:
  `/run` is a fresh, empty tmpfs on every boot, so a symlink chain ending
  there can never resolve before something has (re)created it *this
  specific boot* — see the `system-manager` note below. A sibling of
  `stateDir` rather than nested under it, so the file `/etc/hosts`
  resolves to stays clear of whatever systemd does to `StateDirectory=`;
  it must be readable by every process on the box, which is the entire
  point of `/etc/hosts`).
- `daemon.defaultProbe.{intervalMs,timeoutMs,upThreshold,downThreshold}` —
  the single source of truth every transport's own `probe.*` field falls
  back to when not set explicitly (defaults `3000`/`800`/`2`/`3` — ◐
  reasoned, not measured across real hosts yet; see
  `experiments/README.md` #001).
- `peers.<name>.hostnames` — names to publish (e.g. `[ "host-b" ]`).
- `peers.<name>.transports` — list of the shared transport type (below).
- `peers.<name>.hysteresis.minHoldMs` (default `10000` — ◐, see
  `experiments/README.md` #002).
- `peers.<name>.onAllDown` — `"lastKnownGood"` (default; keep the last
  address published, mark degraded) or `"unpublish"` (remove the entry,
  let NSS fall through to DNS).
- `peers.<name>.lastKnownGood.maxAgeSec` (default `null` = unbounded, and
  it **warns at eval time**) — how long `"lastKnownGood"` may keep
  publishing an address after the last successful probe that confirmed it.
  Past that age the entry is *removed* from the hosts file and the peer
  stays degraded; the moment a transport comes back it is published again.
  The bound applies to state restored from disk at startup and to the
  boot-time hosts seed, not only to time elapsed while the daemon ran — a
  restart must not launder an old entry into a fresh-looking one. Unbounded
  is not a trade-off but a leak: measured on a real estate, one peer stayed
  published for eleven days across ~48,000 consecutive probe failures,
  degraded in `status.json` and resolving perfectly for everyone who simply
  asked the resolver. The default stays `null` because nothing measured
  justifies a number — the tolerance belongs to whatever consumes the name
  (see `BEHAVIORS.md` `STALE-2` and open question #2).
- `uplinks.<name>.transports` — list of the shared transport type; every
  entry **must** set `interface`.
- `uplinks.<name>.hysteresis.minHoldMs` (default `15000` — ◐, same open
  question as peers').
- `uplinks.<name>.publish.routeMetric` (default `true`),
  `.metricBase` (default `100`), `.metricStep` (default `10`).
- `interfaces.<name>.addressing.v4` / `.v6` (default `null` on both) — how
  this interface gets its address: `static`, `dhcp`, `slaac` (v6 only),
  `none`, `unmanaged`. Declared in `modules/firewall.nix`, which extends
  this same submodule, because it is the fact the DHCP client accepts
  derive from (see [The firewall](#the-firewall--one-owner-derived-rules)).
  `null` means *nobody said*, deliberately not the same state as
  `unmanaged` (*somebody said this is not nixnet's*). nixnet never
  configures addressing — it records how addressing happens so everything
  downstream derives from it.
- `interfaces.<name>.mac` (default `null`), `.addresses` (an attrset keyed
  by role, e.g. `{ lan = "192.0.2.10"; }`, default `{ }`) — a FACT table
  of this host's own NICs, independent of `peers`/`uplinks` (which pick a
  winner among candidate transports at runtime) and of `enable` (these
  entries, and their own `assertions`, apply even with the daemon off).
  This is the table a domain like `nixhost` mirrors defensively
  (`config.nixnet.interfaces or { }`) rather than hand-declaring its own
  copy — see `interfaceType`'s comment in `modules/core.nix` for the
  fact/policy line drawn against `transportType.address` and
  `netbird-provider`'s `staticOverlayAddress`.

The shared **transport** type (`peers.<name>.transports[]` and
`uplinks.<name>.transports[]` both use this):

- `address` — a concrete reachable address (peers: required unless a
  provider's exec probe supplies one dynamically; uplinks: usually left
  null).
- `interface` — local egress interface (required for uplinks; optional
  for peers, to pin a probe to a NIC).
- `priority` — lower number wins, among currently-healthy candidates.
- `providerId` — observability tag only (e.g. `"netbird"`); never read by
  engine logic.
- `probe.method` — `"tcp"` (default), `"icmp"`, `"http"`, or `"exec"`.
- `probe.target` — what's actually probed; defaults to `address` (peers).
  Required for uplinks (no default there — enforced by an assertion, not
  the type system, since both groups share this one submodule).
- `probe.port` (default `22`), `probe.path` (default `"/"`, http only).
- `probe.bindToInterface` — `SO_BINDTODEVICE` to `interface`, so a health
  result genuinely reflects that NIC. Requires `CAP_NET_RAW`, granted
  automatically whenever any transport needs it (see Security below).
- `probe.intervalMs`/`timeoutMs`/`upThreshold`/`downThreshold` — each
  defaults to the matching `daemon.defaultProbe.*` value.
- `probe.exec` — required when `method = "exec"`. A **full command line**
  (not a bare path — see `docs/providers.md`'s deviation note), argv[0]
  already an absolute Nix store path. Run with no shell involved, every
  tick, per the [provider contract](docs/providers.md).

`nixnet.firewall.*` (`modules/firewall.nix`) — see
[The firewall](#the-firewall--one-owner-derived-rules) for the failures
each of these exists to prevent:

- `enable` — render and apply the ruleset. Off by default, and off means
  the table is asserted **absent** rather than unmentioned: the apply unit
  exists either way (one oneshot per boot), so no host carries a previous
  generation's rules. The assertions below only apply when it is on.
- `table` (default `"nixnet"`) — the one `inet` table this module owns.
  Never flushed, never shared; asserted not to collide with the table
  `nixnet.overlay` renders into.
- `management.interfaces` (default `[ ]`) — interfaces that ALWAYS keep
  the management port open, emitted before the host's own rules and not
  overridable by them. `management.port` (default `22`),
  `management.rateLimitNew` (default `null`; an nftables `limit rate`
  expression such as `"6/minute"`, which replaces the unconditional accept
  with a rate-limited accept plus an explicit drop).
- `trustedInterfaces` (default `[ ]`) — accept ALL inbound traffic on
  these. A much bigger grant than `management.interfaces`, which opens
  exactly one port.
- `allow` — accept rules: `protocol` (`tcp`/`udp`), `ports`, `portRanges`
  (`{ from; to; }`, mixes freely with `ports` in one nftables set),
  `sourcesV4`/`sourcesV6` (empty means ANY — a real choice, not a default
  to reach for), `interface`, `comment` (rendered into the ruleset, which
  is what a future reader debugs from).
- `silentDrops` — `{ match; comment; }` pairs dropped without logging.
- `forward.enable` (default `false`) / `forward.rules` — a forward chain,
  off by default because any base chain's drop is final across all tables.
  On a routing peer the overlay path is accepted automatically.
- `overlayConfinement.network` (default `null`) — the overlay's own /24;
  set it to derive `nixnet.overlay.confineExternalRanges` from the
  declared octet band. `overlayConfinement.band` (default: the band in
  `excludeFromCatchAll.forBand`), `overlayConfinement.ranges` (read-only,
  the derived CIDRs — `nix eval` it).
- `autoRevert.enable` (default `true`) / `.seconds` (default `120`) — the
  dead-man switch, armed on a ruleset change and disarmed by running
  `nixnet-firewall-confirm`.
- `ruleset` — read-only, the exact text both planes apply.

`nixnet.netbird.*` (`modules/netbird-provider.nix`) — see
[Quickstart](#quickstart) for a worked example and the module's own
header comment for the full drift-detection and reprovisioning design:

- `enable`, `managementUrl`, `setupKeyFile` (a reusable, non-interactive
  NetBird setup key — sops/agenix-provided, root-readable),
  `hostnameOverride` (defaults to `networking.hostName`).
- `peers.<name>.priority`, `.staticOverlayAddress` (leave null to discover
  dynamically), `.probe.port` (default `22`).
- `reprovision.enable` (default `true`),
  `.checkIntervalSec` (default `60`, periodic safety net),
  `.minReprovisionIntervalSec` (default `300`, rate limit between actual
  `netbird up` attempts), `.driftFailureThreshold` (default `3`,
  consecutive drift-shaped exec-probe failures before the reactive
  trigger fires), `.connectTimeoutSec` (default `30`).

Every `peers.<name>` referenced under `nixnet.netbird.peers`
must already exist under `nixnet.peers.<name>` (with its own
`hostnames`) — the provider only ever *adds* one more transport to that
peer's list.

`nixnet.overlay.*` (`modules/overlay.nix`):

- `enable`, `managementUrl`, `hostname`, `setupKeyFile` — same shape as
  `nixnet.netbird`'s equivalents, no defaults (environment-specific).
- `advertiseRoutes` (default `[ ]`) — LAN CIDRs this peer routes into the
  overlay; non-empty turns on kernel forwarding + source-NAT for the
  reverse direction.
- `confineExternalRanges`/`confineExternalAllow` (default `[ ]`/`[ ]`) —
  restrict an untrusted overlay band to only the LAN hosts it's allowed to
  reach, everything else dropped.
- `overlayInterface` (default `"wt0"`, upstream's default tunnel
  interface name).

`nixnet.meshGateway.*` (`modules/mesh-gateway.nix`):

- `enable`, `package` (required — see the module's own header),
  `managementUrl`, `apiUrl`, `ageKeyFile`, `setupKeySecret`,
  `apiTokenSecret` — all environment-specific, no defaults.
- `setupKeyRuntimeFile`/`apiTokenRuntimeFile` (defaults under
  `/run/secrets/nixnet-mesh-gateway-*`) — where the unsealed secrets land.
- `stateDir` (default `/var/lib/nixnet-mesh-gateway`).
- `peers.<name>.ip`, `.forwards[].{proto,listenPort,dial}` — one entry per
  overlay identity this gateway holds; `privateKeyFile` is computed
  internally (`<stateDir>/<name>/private.key`), never set by hand.

`nixnet.netbirdGroupReconcile.*` (`modules/netbird-group-reconcile.nix`):

- `enable`, `apiUrl` (no default), `tokenFile` (defaults to
  `nixnet.meshGateway.apiTokenRuntimeFile`'s own default — the two modules
  share one token when both are enabled).
- `bands[].{min,max,name}` (default `[ ]`) — octet ranges mapped to a
  **live NetBird group name** each.
- `catchAllGroup` (required whenever `bands` is non-empty) — the group
  every reconciled peer joins, except a band named in
  `excludeFromCatchAll.forBand` (default `null` — every band's members
  also join the catch-all).
- `onBootSec` (default `5min`), `interval` (default `10min`).

`nixnet.netbirdAccessModel.*` (`modules/netbird-access-model.nix`):

- `enable`, `internalGroup` (required — must be a key of `groups`; the
  group meaning "every one of our own peers").
- `groups.<name>.description` (required), `.renamedFrom` (default
  `null` — set for one deploy cycle while a rename is in flight; see the
  runbook above).
- `policies.<name>.from`/`.to` (both must be keys of `groups`),
  `.bidirectional` (default `false`), `.enabled` (default `true` —
  audited but a mismatch is informational-only, see the option's own
  description), `.renamedFrom` (default `null`), `.description` (default
  `""`).
- `routes.<name>.network` (the CIDR the audit matches a live route by —
  two declared routes must not share one), `.distributeTo` (group names,
  each must be a key of `groups`), `.description` (default `""`).
- `audit.enable`, `.apiUrl` (no default), `.tokenFile` (defaults to
  `nixnet.meshGateway.apiTokenRuntimeFile`'s own default — shared token
  with the sibling modules), `.onBootSec` (default `5min`), `.interval`
  (default `15min`).
- Assertions: `internalGroup` must be a declared group; every
  policy/route group reference must be declared; no two routes may share
  a `network`; when `nixnet.netbirdGroupReconcile` is also enabled, every
  one of its `bands[].name` must be a declared group. Wiring:
  `nixnet.netbirdGroupReconcile.catchAllGroup` defaults to
  `internalGroup` whenever both modules are enabled.

`nixnet.ingress.*` (`modules/ingress.nix`):

- `enable`, `tunnelId` (required), `credentialsFile` (default
  `/run/secrets/cloudflared-credentials.json`).
- `ingress[].{hostname,service,path}` (default `[ ]`) — this module
  appends the `http_status:404` catch-all itself.
- `edgeIpVersion` (default `"auto"`), `transportProtocol` (default
  `"auto"`).
- `dnsReconcile.enable`, `.apiTokenFile` (default
  `/run/secrets/cloudflared-cf-api-token`), `.zone` (required),
  `.onCalendar` (default `*:0/15`), `.mgmtRecords` (attrset of
  hostname → internal IP, UPSERTed as proxied=false A-records).

`lib.svcProxyConfig` (`lib/svc-proxy-config.nix`) — a function, not a
module option tree; called as
`inputs.nixnet.lib.svcProxyConfig { inherit lib services machines zone proxyClusterIP l4ClusterIpPrefix; }`.
See the file's own header for the full `services.<name>` input shape and
the HTTP-vs-L4-direct split it renders.

## Non-NixOS hosts (via `system-manager`)

`nixosModules.core`/`.netbird-provider` need a real NixOS host. For a
non-NixOS Linux box applying config with
[numtide/system-manager](https://github.com/numtide/system-manager)
instead, import `systemManagerModules.core`/`.netbird-provider` instead —
same file, same schema:

```nix
{
  inputs.nixnet.url = "github:julian-corbet/nixnet-corbet-ch";
}
imports = [ inputs.nixnet.systemManagerModules.core ];
nixnet.enable = true;
# ... same options as above
```

nixnet only ever touches `environment.etc`, `systemd.services`/`timers`/
`path` units, and a rendered JSON config — none of the primitives
`system-manager` categorically can't reach (no `boot.kernel.sysctl`, no
kernel command-line parameters). `modules/core.nix` sets
`environment.etc.hosts.replaceExisting = true` itself on the
`system-manager` backend (real NixOS has no such option — it always
reconciles `/etc` from scratch on activation instead), so a target whose
`/etc/hosts` already exists as a real, hand-edited file is adopted
correctly with no action needed from a consumer.

### Native packages on system-manager hosts

`systemManagerModules.backend` is a separate, opt-in package catalogue for
hosts whose native distribution owns network services. It publishes the
official-repository and AUR names as `nixnet.backend.archPackages` and
`nixnet.backend.aurPackages`; it never installs packages or writes a second
service unit. Wire those lists to the host's package reconciler, then select
only mechanisms the host actually owns:

```nix
{ config, ... }:
{
  imports = [ inputs.nixnet.systemManagerModules.backend ];

  nixnet.backend = {
    enable = true;
    netbird.enable = true;
    networkManager.enable = true;
    bluez.enable = true;
  };

  nixarch.packages.pacman = config.nixnet.backend.archPackages;
  nixarch.packages.aur = config.nixnet.backend.aurPackages;
}
```

The base `bluez` selection includes `bluez` and `bluez-utils`. `bluez.obex`
and `bluez.hid2hci` are independent opt-ins for OBEX transfers and Bluetooth
HID adapter conversion. The NixOS overlay and ingress modules already own
their respective NixOS package/service paths; they do not use this native
package output.

## Security

`nixnetd` runs as a dedicated `nixnetd` system user — never `root`, and
deliberately **not** `DynamicUser`: the daemon has to own the hosts file
it atomically renames over, and a per-boot-random dynamic UID owns
neither that file nor its directory, so every publish fails with `EPERM`
(POSIX restricts `rename(2)` over an existing file to its owner, the
directory's owner, or a privileged process). It runs with
`NoNewPrivileges`, `ProtectSystem = "strict"`, and
`RuntimeDirectory`/`StateDirectory` scoped to exactly `/run/nixnet` and
`/var/lib/nixnet`. It is granted
`CAP_NET_ADMIN` only if some uplink has `publish.routeMetric = true`
(the common case), and `CAP_NET_RAW` only if some transport uses
`probe.method = "icmp"` or `probe.bindToInterface = true`. A peers-only
install using TCP/HTTP probes gets **no** elevated capabilities at all.

`nixnet-netbird-reprovision.service` runs as root (required to drive
`netbird up`/`down` and read the setup-key secret) but is a narrowly
scoped, rate-limited, `flock`-guarded oneshot — never a resident
privileged process.

## Building from source

The daemon (`nixnetd`, `nixnetctl`) is a real, working Rust
implementation — a single crate with two `[[bin]]` targets over a shared
library (`src/lib.rs`): the winner-selection/hysteresis engine
(`src/engine`), all four probe methods (`src/probe`), both publish
backends (`src/publish`), and the `sd_notify` watchdog integration
(`src/sdnotify`) are complete, not stubs.

```
cargo build --release   # or: nix build .#nixnet
cargo test               # or: nix build .#nixnet (runs the same suite in-derivation)
```

`Cargo.lock` is committed, so both build paths work fully offline — `nix
build` uses `rustPlatform.buildRustPackage`'s `cargoLock.lockFile`
against the committed lockfile rather than a separate vendor hash to keep
in sync.

## Status

**Running in production**, across several hosts and both backends (NixOS
and `system-manager`). The engine, both publish backends, and the netbird
reference provider are complete implementations rather than stubs, and
the networking-ownership modules above manage a real overlay, a real
mesh gateway and real public ingress day to day.

That deployment is also where the sharpest bugs have come from — the ones
no amount of eval-time checking finds, because they are facts about a
running kernel and a running systemd rather than about what Nix evaluates
to. Four, so far: the daemon's own process identity versus the hosts
file it must rename over; a secret-unseal that raced the mount holding
its key and hard-failed the mesh gateway until a human intervened; a
restart publishing nothing at all, because publishing was wired only to
*winner changes* and a settled fleet has none; and the uplink half of
that same defect, where the route publisher had never once run on any
host — a single-uplink host has no winner change, so a declared metric
sat next to a live route the daemon had never touched. Each landed with
a regression check — a unit test or an eval-time assertion — next to the
fix.

Calibrate accordingly before adopting:

- Values marked ◐ above are **reasoned, not measured**.
  `experiments/README.md` is the open ledger of exactly which ones still
  need real numbers behind them.
- The **peer/`/etc/hosts` half is far better exercised than the
  uplink/route-metric half**, which has had comparatively little real
  exposure. Treat uplink failover as the less-proven surface.
- Places where the code fills a gap the option surface didn't pin down
  are documented explicitly in
  [`docs/providers.md`](docs/providers.md#documented-deviations-and-judgment-calls)
  rather than left implicit.

## Non-goals (v1)

- Sub-second failover latency (bounded by `probe.intervalMs`, default 3s).
- Full ownership of the kernel routing table for uplinks (metric
  reprioritization of existing routes only).
- Any DNS-protocol behavior — nixnet never listens on a network port for
  peer publishing.
- Automatic server-side pruning of stale duplicate NetBird peers after a
  full local-identity reprovision (a full state wipe forces a *new*
  WireGuard identity; the reprovisioned peer re-registers as "same name,
  new key," and a stale duplicate may need manual server-side pruning).

## Related projects

nixnet is one of several small, independently-usable open-source projects
sharing a common design system:
[nixram](https://github.com/julian-corbet/nixram-corbet-ch) (RAM-pressure
tuning by declared level),
[nixarch](https://github.com/julian-corbet/nixarch-corbet-ch) (declarative
Arch/CachyOS), [nixvps](https://github.com/julian-corbet/nixvps-corbet-ch)
(tiny sub-1GB NixOS VPS profiles),
[nixremote](https://github.com/julian-corbet/nixremote-corbet-ch)
(cross-machine native Wayland app forwarding), and
[nixsh](https://github.com/julian-corbet/nixsh-corbet-ch) (the
safe-adoption pattern for declarative shell config, across fish, bash and zsh). nixnet's own
niche is purely transport failover — usable alongside any of them, or
standalone.

## License

MIT.
