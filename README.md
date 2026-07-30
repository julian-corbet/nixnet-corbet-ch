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
      |  nixnetd   |   one probe goroutine + ticker per transport
      +-----+------+
            |
      winner changes?
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
  (`confineExternalRange`/`confineExternalAllow`) closing the blanket
  forward-accept hole a routing peer otherwise leaves open. Distinct from
  `nixnet.netbird` (above): that module is about REACHING a specific peer
  through the failover engine; this one is about THIS host's own overlay
  membership. A host commonly runs both.
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
- **`lib.svcProxyConfig`** (`lib/svc-proxy-config.nix`) — not a module, a
  pure function: turns a service registry into a split-horizon in-cluster
  nginx config + CoreDNS zone, so an in-cluster caller of `<svc>.<zone>`
  gets the same HTTPS experience as an overlay or public-tunnel caller.
  Called from a consumer's own flake `outputs` or host config, same as
  `nixpkgs.lib` itself.

These five modules are NixOS-only for now — each uses at least one
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

## Options reference

`nixnet.*` (`modules/core.nix`):

- `enable` — turn the engine on.
- `package` — the `nixnetd`/`nixnetctl` build; override only to pin/patch.
- `daemon.stateDir` (default `/var/lib/nixnet`), `daemon.runtimeDir`
  (default `nixnet`, under `/run`), `daemon.hostsFile` (default
  `/var/lib/nixnet-hosts/hosts` — under `/var/lib`, not `runtimeDir`:
  `/run` is a fresh, empty tmpfs on every boot, so a symlink chain ending
  there can never resolve before something has (re)created it *this
  specific boot* — see the `system-manager` note below. Deliberately a
  sibling of `stateDir`, not nested under it: `nixnetd` runs with
  `DynamicUser=true`, which relocates `stateDir` under the shared,
  `0700 root:root` `/var/lib/private/` parent — anything nested there
  becomes unreadable to every other process on the box, defeating the
  whole point of `/etc/hosts`).
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
- `uplinks.<name>.transports` — list of the shared transport type; every
  entry **must** set `interface`.
- `uplinks.<name>.hysteresis.minHoldMs` (default `15000` — ◐, same open
  question as peers').
- `uplinks.<name>.publish.routeMetric` (default `true`),
  `.metricBase` (default `100`), `.metricStep` (default `10`).
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

`nixnet.netbird.*` (`modules/netbird-provider.nix`) — see
[Quickstart](#quickstart) for a worked example and
[`docs/providers.md`](docs/providers.md) §7 for the full drift-detection
and reprovisioning design:

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
- `confineExternalRange`/`confineExternalAllow` (default `null`/`[ ]`) —
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

## Security

`nixnetd` runs as `DynamicUser`, `NoNewPrivileges`,
`ProtectSystem = "strict"`, with `RuntimeDirectory`/`StateDirectory`
scoped to exactly `/run/nixnet` and `/var/lib/nixnet`. It is granted
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

Fresh project: the engine, both publish backends, and the netbird
reference provider are implemented for real per the v1 design document,
but nothing here has run across real hosts yet. A handful of places
where the code necessarily fills a gap or extends the letter of the
design document are documented explicitly in
[`docs/providers.md`](docs/providers.md#deviations-from-the-v1-design-document)
rather than left implicit. Values marked ◐ above are reasoned, not
measured; `experiments/README.md` tracks what still needs measuring
against a real deployment.

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
