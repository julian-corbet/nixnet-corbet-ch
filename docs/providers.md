# The provider contract

A **provider** is an ordinary NixOS (or system-manager) module that makes a
new transport source available to nixnet. Core has no registry, no
plugin-loading mechanism, and no provider-specific code — a provider
"registers" purely by contributing standard Nix option values into
`services.nixnet.peers.<name>.transports` and/or
`services.nixnet.uplinks.<name>.transports`.

`netbird-provider` (shipped in this same repo, `modules/netbird-provider.nix`)
is the reference implementation. If you're writing a new provider — a
`tailscale-provider`, a `zerotier-provider`, anything else — read
`modules/netbird-provider.nix` alongside this document; it's real, complete
code, not a stub.

## 1. What a provider MUST do

1. **Namespace its own options** under `services.nixnet.<providerName>.*`
   (mirroring the `services.prometheus.exporters.<name>` convention — one
   dedicated options namespace per provider, one segment under
   `services.nixnet`, not a nested `providers.` level).
2. **Contribute only into `services.nixnet.peers.<name>.transports`
   and/or `services.nixnet.uplinks.<name>.transports`**, via ordinary
   list concatenation (`services.nixnet.peers = lib.mkMerge [ ... ]`, or
   building the transport list programmatically from the provider's own
   smaller option table and merging it in — see
   `modules/netbird-provider.nix`'s `services.nixnet.peers = mkMerge
   (mapAttrsToList ...)`). A provider module must never touch
   `services.nixnet.daemon.*`, never write to `/run/nixnet/*` directly, and
   never assume anything about how core probes or publishes — it only ever
   contributes *candidates*. (See §4 below for the one narrow, documented
   exception this repo's own reference provider needed.)
3. **Never reimplement functionality the underlying tool already
   provides.** If the provider wraps another NixOS module (e.g.
   `services.netbird`), it must set that module's own options and consume
   its outputs — not reinvent installation/config management for that
   tool.

## 2. What a provider MAY do

- **Exec probe** — set a contributed transport's `probe.method = "exec"`
  and `probe.exec = <command line>`. Each probe tick, `nixnetd` runs it
  and applies exactly this contract:
  - **Exit code 0 = healthy, non-zero = unhealthy.** This is the only
    signal core is *guaranteed* to use — a provider that just wants a
    richer health check than plain TCP/ICMP/HTTP (e.g. "does the tunnel
    software's own control channel agree this peer is connected?") needs
    nothing more than this.
  - **Optionally**, the script may print exactly one line of JSON to
    stdout:
    ```json
    {"address": "203.0.113.20", "healthy": true, "detail": "p2p, netbird v0.7x"}
    ```
    `healthy` is informational only when present (exit code remains
    authoritative); `address`, if present, **overrides the transport's
    static `address` for this tick** — this is the entire "dynamic address
    source" mechanism. `detail` is free text surfaced in `nixnetctl
    status` and nowhere else. Core parses **only these three well-defined
    fields** and nothing else — it never attempts to understand a
    provider's own status format.
  - This is intentionally the *only* interface a provider needs for both
    "richer health" and "dynamic addressing." There is no separate push
    API, no control socket, no RPC.
- **Register independent systemd units** for self-healing its own
  transport source (e.g. a reprovisioning timer). Core never orchestrates
  this and never knows it exists — it only ever sees whatever ends up (or
  doesn't) in `transports` as a result. A provider that wants *core* to
  react faster to a persistent failure than the next scheduled self-heal
  attempt can use the **trigger-file pattern**: have its exec-probe script
  `touch` a file under `/run/nixnet/reprovision/<providerName>` when it
  detects a drift-shaped (not just reachability) failure, and ship its own
  root-owned `systemd.path` unit watching that path to start its
  reprovisioning oneshot. This gives fast reactive recovery without ever
  granting the (unprivileged) exec-probe process itself any
  `systemctl`/root capability.

## 3. What a provider MUST NOT do

- Touch core's daemon code, core's publish logic, or any other provider's
  namespace.
- Assume a specific probe cadence, retry count, or hysteresis value —
  these are the consumer's (core's) configuration, not the provider's to
  set defaults for beyond what it contributes per-transport.
- Silently no-op on a failure it could instead report. `netbird-provider`'s
  reprovisioning oneshot is written specifically to never do this: a
  missing setup-key secret is a distinctly-tagged, non-zero exit
  (`NIXNET_NETBIRD_REPROVISION_FAILED reason=no-setup-key`), not a quiet
  `exit 0` that leaves the daemon stuck with nobody notified.

## 4. Minimal example (for a hypothetical `tailscale-provider`)

```nix
services.nixnet.tailscale-provider.enable = mkEnableOption "...";
services.nixnet.tailscale-provider.authKeyFile = mkOption { type = types.path; };
services.nixnet.tailscale-provider.peers.<name> = mkOption {
  type = types.submodule { options = {
    priority = mkOption { type = types.int; };
  };};
};

# internally:
services.nixnet.peers = lib.mkMerge (lib.mapAttrsToList (peerName: peerCfg: {
  ${peerName}.transports = [{
    priority = peerCfg.priority;
    providerId = "tailscale";
    probe.method = "exec";
    probe.exec = "${pkgs.writeShellApplication {
      name = "tailscale-probe-${peerName}";
      runtimeInputs = [ pkgs.tailscale pkgs.jq ];
      text = ''
        status=$(tailscale status --json)
        # ... extract address + connected state for ${peerName}, echo {"address":...,"healthy":...}
      '';
    }}/bin/tailscale-probe-${peerName}";
  }];
}) cfg.tailscale-provider.peers);
```

No daemon code changes, no core-repo changes — this is the complete shape
a new provider PR needs to fill in. `modules/netbird-provider.nix` is the same
shape at full scale (real drift detection, real reprovisioning, real
exec-probe scripts) if you want a worked example past "minimal."

---

## Deviations from the v1 design document

This section exists because the code doesn't match the design document
line-for-line in a few places. Each entry below explains what changed, in
which file, and why — so a reviewer (or a future contributor extending
this) doesn't have to reverse-engineer the reasoning from a diff.

### Deviation: `probe.exec` is a command line, not a bare `types.path`

The design document's §3.1 pseudocode types `probe.exec` as
`types.nullOr types.path` — but its own §7.2 usage example immediately
assigns `probe.exec = "${nixnetNetbirdAddressProbe} ${name}";`, which is a
**full command line** (a store path followed by a space and an argument),
not a bare path. `types.path` cannot represent that. `modules/core.nix`
types `probe.exec` as `types.nullOr types.str` instead, documented
throughout as "a full command line, argv[0] already an absolute Nix store
path." `src/probe/exec.rs`'s `run` tokenizes that string with a
small quote-aware word-splitter and execs `argv[0]` directly — **never**
through `/bin/sh** — which is actually a *stricter* reading of the design's
own "no PATH dependency, one narrow well-tested exec" goal (§1's rationale
table) than shelling out via `sh -c` would have been.

### Deviation: address-drift republish, beyond a literal reading of §4.2

Design document §4.2's winner-selection pseudocode returns early — no
publish call at all — whenever the winner index hasn't changed:

> `if newWinner == currentWinner: return   # no-op; nothing is republished`

Taken completely literally, this would mean: if a provider's exec probe
changes the **winning** transport's own dynamically-discovered address
(exactly the netbird-provider scenario — a peer re-enrolls and gets a new
overlay IP, but is still the highest-priority *healthy* transport before
and after), nothing ever gets republished, because the winner *index*
never moved. That would silently defeat the entire "dynamic address
source" mechanism §6.2 describes as the reason the exec-probe JSON
envelope's `address` field exists at all.

`src/engine/mod.rs`'s `reconcile_locked` additionally republishes
whenever the current winner's effective address differs from what was
last actually published — winner-index unchanged or not. This is a
narrow, additive extension: it changes *when* a publish happens, never
*which* transport wins or how hysteresis/minHold is computed, so it
doesn't touch any of the properties §1's rationale table argues for.

### Deviation: transport identity is list position, not a name field

The design document's `transportType` (§3.1) has no name/id field on a
transport — only the observability-only `providerId`. But §4.1's own
pseudocode log line format (`"transport=%s state=%s->Up after=%d" %
(id, ...)`) and §5.3's `status.json` shape (a `transports` object keyed by
some string) both assume transports have string identities somewhere.

`src/engine/mod.rs` resolves this gap by using each transport's
position in its `transports` list as its stable identity for
`state.json` persistence, and derives a readable label
(`peer/host-b#0(lan)`) from `providerId`/`interface`/`address` (whichever
is set) purely for logs and `status.json` keys. The practical consequence:
**reordering a `transports` list in Nix is equivalent to removing and
re-adding every entry after the change point** — their persisted
hysteresis counters reset. This is called out here rather than left to be
discovered the hard way.

### Deviation: `nixnetd`'s `SupplementaryGroups` set by netbird-provider

`docs/providers.md` §3 says a provider must never touch
`services.nixnet.daemon.*`. `modules/netbird-provider.nix` sets
`systemd.services.nixnetd.serviceConfig.SupplementaryGroups = [ "netbird" ];`
when enabled — which is **not** the same boundary: `services.nixnet.daemon.*`
is nixnet's own Nix *option surface* (cadence, paths, thresholds — the
things §6.1.2 actually says a provider must leave alone); `systemd.services.nixnetd`
is the raw NixOS systemd-unit option any two unrelated modules can
jointly extend, the same way, say, a hardening module and a logging
module might both add settings to the same third-party unit. It's needed
because `netbird-provider`'s exec-probe script runs as a child process of
`nixnetd`'s own unprivileged (`DynamicUser`) process, and `netbird status`
needs group-level read access to NetBird's control socket that a bare
dynamic UID doesn't have. This is scoped as narrowly as possible (one
group membership, only when `netbird-provider` is actually enabled) and
documented at the point it's set, in `modules/netbird-provider.nix`.

### Clarification (not a deviation): `daemon.defaultProbe` is load-bearing

Design document §3.1's `probe` submodule hardcodes its own field defaults
(3000/800/2/3) directly; §3.2 separately declares
`services.nixnet.daemon.defaultProbe` with the *same* numbers, but never
actually wires the two together — read completely literally,
`daemon.defaultProbe` would be a dead option nobody consults.
`modules/core.nix`'s `probeType` submodule instead sets each field's
default to `cfg.daemon.defaultProbe.<field>`, and
`src/config.rs`'s hand-written-JSON fallback path mirrors the
same chain (`Probe::apply_defaults` takes the resolved `daemon.defaultProbe`
as a parameter). This makes `daemon.defaultProbe` an actually-functional
single point of control, matching what the option's existence otherwise
implies it should do.
