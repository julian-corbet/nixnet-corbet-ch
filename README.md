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

services.nixnet.enable = true;

# ── Remote peer: LAN-preferred, overlay-fallback ──
services.nixnet.peers."host-b" = {
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
services.nixnet.uplinks."internet" = {
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
services.nixnet.netbird = {
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
services.nixnet.peers / uplinks
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
(`/run/nixnet/hosts`, `/run/nixnet/status.json`,
`/var/lib/nixnet/state.json`). The same binary works unmodified from a
Nix-rendered config, a hand-written one, or a `system-manager` render.

## Options reference

`services.nixnet.*` (`modules/core.nix`):

- `enable` — turn the engine on.
- `package` — the `nixnetd`/`nixnetctl` build; override only to pin/patch.
- `daemon.stateDir` (default `/var/lib/nixnet`), `daemon.runtimeDir`
  (default `nixnet`, under `/run`), `daemon.hostsFile` (default
  `/run/nixnet/hosts`).
- `daemon.defaultProbe.{intervalMs,timeoutMs,upThreshold,downThreshold}` —
  the single source of truth every transport's own `probe.*` field falls
  back to when not set explicitly (defaults `3000`/`800`/`2`/`3` — ◐
  reasoned, not measured against a real fleet yet; see
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

`services.nixnet.netbird.*` (`modules/netbird-provider.nix`) — see
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

Every `peers.<name>` referenced under `services.nixnet.netbird.peers`
must already exist under `services.nixnet.peers.<name>` (with its own
`hostnames`) — the provider only ever *adds* one more transport to that
peer's list.

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
services.nixnet.enable = true;
# ... same options as above
```

nixnet only ever touches `environment.etc`, `systemd.services`/`timers`/
`path` units, and a rendered JSON config — none of the primitives
`system-manager` categorically can't reach (no `boot.kernel.sysctl`, no
kernel command-line parameters). The one adoption trap worth knowing (not
novel to nixnet): if a target's `/etc/hosts` already exists as a real file
rather than a fresh path, `environment.etc.hosts.replaceExisting = true`
must be set explicitly — omitting it is a silent no-op on `system-manager`,
not an error.

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

The daemon (`cmd/nixnetd`, `cmd/nixnetctl`) is a real, working Go
implementation — the winner-selection/hysteresis engine
(`internal/engine`), all four probe methods
(`internal/probe`), both publish backends
(`internal/publish`), and the `sd_notify` watchdog integration
(`internal/sdnotify`) are complete, not stubs.

```
go build ./...      # or: nix build .#nixnet
```

`vendor/` is committed (see `go.mod`/`go.sum`), so both build paths work
fully offline — `nix build` uses `vendorHash = null` against the
committed vendor directory rather than a network-fetch FOD hash.

## Status

Fresh project: the engine, both publish backends, and the netbird
reference provider are implemented for real per the v1 design document,
but nothing here has run against a real fleet yet. A handful of places
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
[nixfish](https://github.com/julian-corbet/nixfish-corbet-ch) (the
safe-adoption pattern for declarative fish shell config). nixnet's own
niche is purely transport failover — usable alongside any of them, or
standalone.

## License

MIT.
