# modules/core.nix
#
# nixnet's whole generic engine: services.nixnet.peers.<name> and
# services.nixnet.uplinks.<name>, sharing one transport submodule type and
# rendered into one config.json for nixnetd (design.md §3). This file is
# shared verbatim between nixosModules.core and systemManagerModules.core
# (flake.nix) — see §9 for why that's safe: nixnet only ever touches
# environment.etc, systemd.services/timers/paths, and a rendered JSON file,
# none of which system-manager categorically can't reach.
#
# Providers (netbird-provider.nix and friends) never import this file
# directly — they contribute into services.nixnet.peers/uplinks the same
# way a consumer's own machine config does, via ordinary Nix option
# merging. Core has no provider registry and no provider-specific code;
# see docs/providers.md.

{ lib, config, pkgs, ... }:

with lib;

let
  cfg = config.services.nixnet;

  # ---------------------------------------------------------------------
  # Shared transport submodule (design.md §3.1) — reused verbatim by both
  # peers.<name>.transports and uplinks.<name>.transports. One type, one
  # engine code path; see the design rationale table in design.md §1 for
  # why this is "one schema, two readable tables" rather than one table
  # with a `kind` discriminator.
  # ---------------------------------------------------------------------
  probeType = types.submodule {
    options = {
      method = mkOption {
        type = types.enum [ "tcp" "icmp" "http" "exec" ];
        default = "tcp";
        description = "How this transport is health-checked each tick.";
      };

      target = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          What to actually probe. For peer transports this defaults to the
          sibling `address` option (see the submodule's own `config` block
          below) — you only need to set it explicitly if it differs from
          `address` (e.g. probing a management port on a different IP than
          the one that gets published). For uplink transports there is no
          such default: `address` is usually left null there, so
          `target` (or `probe.method = "exec"`, which doesn't need one) is
          required — enforced by `assertions` below, not by the type
          system, since both groups share this one submodule.
        '';
      };

      port = mkOption {
        type = types.nullOr types.port;
        default = 22;
        description = "tcp method only.";
      };

      path = mkOption {
        type = types.str;
        default = "/";
        description = "http method only.";
      };

      bindToInterface = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Bind the probe socket to the transport's `interface` via
          SO_BINDTODEVICE, so the health result genuinely reflects that
          NIC rather than whatever route the kernel would otherwise pick.
          Requires CAP_NET_RAW; the module grants it automatically (see
          `needsNetRaw` below) whenever any transport sets this or uses
          `method = "icmp"`.
        '';
      };

      intervalMs = mkOption {
        type = types.ints.positive;
        default = cfg.daemon.defaultProbe.intervalMs;
      };
      timeoutMs = mkOption {
        type = types.ints.positive;
        default = cfg.daemon.defaultProbe.timeoutMs;
      };
      upThreshold = mkOption {
        type = types.ints.positive;
        default = cfg.daemon.defaultProbe.upThreshold;
      };
      downThreshold = mkOption {
        type = types.ints.positive;
        default = cfg.daemon.defaultProbe.downThreshold;
      };

      exec = mkOption {
        # DEVIATION from the design document's literal `types.path`
        # typing (§3.1): the design doc's own netbird-provider example
        # (§7.2) assigns `probe.exec = "${script} ${peerName}"` — a full
        # command line (program + argument), not a bare path, which
        # `types.path` cannot represent (it would either fail to coerce
        # or silently only keep the first word, neither of which is what
        # the example clearly intends). Typed `types.str` here instead,
        # documented as "a full command line" throughout, and see
        # nixnetd's internal/probe package for the corresponding
        # no-shell, word-split exec — this preserves the "no PATH
        # dependency, one narrow well-tested exec" property system-manager
        # hosts need just as much as `types.path` would have.
        type = types.nullOr types.str;
        default = null;
        description = ''
          Required when method = "exec". A full command line, already
          resolved to an absolute Nix store path for argv[0] (e.g. a
          `pkgs.writeShellApplication` result concatenated with a space
          and an argument). Run each tick with no shell involved — see
          docs/providers.md §6.2.
        '';
      };
    };
  };

  transportType = types.submodule ({ config, ... }: {
    options = {
      address = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          A concrete reachable address for this transport. Peer
          transports: required unless supplied dynamically by a
          provider's exec probe (§6.2's `address` envelope field). Uplink
          transports: usually left null — `probe.target` (reached via
          `interface`) is what's actually probed there.
        '';
      };

      interface = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Local egress interface this transport is bound to. Required for
          uplink transports (this is *what* is being selected between —
          enforced by `assertions` below). Optional for peer transports,
          to pin a probe to a specific NIC.
        '';
      };

      priority = mkOption {
        type = types.int;
        description = "Lower number = more preferred, among currently-healthy candidates.";
      };

      providerId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Observability tag only, e.g. \"netbird\". Never read by core logic.";
      };

      probe = mkOption {
        type = probeType;
        default = { };
      };
    };

    # target defaults to address, for every transport (peer or uplink
    # alike — this submodule is shared, see design.md §1's schema-shape
    # rationale). For uplinks, address is normally null, so this default
    # just leaves target null too, same as if there were no default at
    # all; the assertion in the parent module is what actually enforces
    # "required for uplinks."
    config = {
      probe.target = mkDefault config.address;
    };
  });

  hysteresisType = types.submodule {
    options.minHoldMs = mkOption {
      type = types.ints.positive;
      default = 10000;
      description = ''
        Once the group's winner changes, no further winner change is
        applied until minHoldMs has elapsed — UNLESS the current winner
        itself has just gone unhealthy (a dead winner is never held onto
        to satisfy a hold timer).
      '';
    };
  };

  peerType = types.submodule {
    options = {
      hostnames = mkOption {
        type = types.listOf types.str;
        description = ''Names to publish, e.g. [ "host-b" "host-b.mesh.example.com" ].'';
      };
      transports = mkOption {
        type = types.listOf transportType;
        default = [ ];
      };
      hysteresis = mkOption {
        type = hysteresisType;
        default = { };
      };
      onAllDown = mkOption {
        type = types.enum [ "lastKnownGood" "unpublish" ];
        default = "lastKnownGood";
        description = ''
          lastKnownGood: keep publishing the last address that was ever up
          (good for retry-tolerant protocols like a soft-mounted NFS
          share); the group is marked degraded in status.json + the
          journal. unpublish: remove the managed entry entirely so NSS
          falls through to the next source (typically DNS).
        '';
      };
    };
  };

  uplinkType = types.submodule {
    options = {
      transports = mkOption {
        type = types.listOf transportType;
        default = [ ];
      };
      hysteresis = mkOption {
        type = hysteresisType;
        default = { minHoldMs = 15000; };
      };
      publish = {
        routeMetric = mkOption { type = types.bool; default = true; };
        metricBase = mkOption {
          type = types.int;
          default = 100;
          description = "Metric assigned to the current winner.";
        };
        metricStep = mkOption {
          type = types.int;
          default = 10;
          description = "Metric spacing applied to non-winners, in priority order.";
        };
      };
    };
  };

  # ---------------------------------------------------------------------
  # Capability computation (design.md §8): a peers-only install with only
  # TCP/HTTP probes gets no elevated capabilities at all.
  # ---------------------------------------------------------------------
  allTransports =
    (concatMap (p: p.transports) (attrValues cfg.peers))
    ++ (concatMap (u: u.transports) (attrValues cfg.uplinks));

  needsNetAdmin = any (u: u.publish.routeMetric) (attrValues cfg.uplinks);
  needsNetRaw = any (t: t.probe.method == "icmp" || t.probe.bindToInterface) allTransports;

  # ---------------------------------------------------------------------
  # config.json rendering (design.md §3.3) — the *only* interface between
  # Nix and nixnetd. nixnetd never reads anything else Nix-shaped.
  # ---------------------------------------------------------------------
  renderedConfig = {
    daemon = {
      inherit (cfg.daemon) stateDir runtimeDir;
      hostsFile = cfg.daemon.hostsFile;
      ipPath = "${pkgs.iproute2}/bin/ip";
      defaultProbe = cfg.daemon.defaultProbe;
    };
    peers = mapAttrs
      (_: p: {
        inherit (p) hostnames transports onAllDown;
        hysteresis = p.hysteresis;
      })
      cfg.peers;
    uplinks = mapAttrs
      (_: u: {
        inherit (u) transports publish;
        hysteresis = u.hysteresis;
      })
      cfg.uplinks;
  };

  configJsonFile = pkgs.writeText "nixnet-config.json" (builtins.toJSON renderedConfig);

  # ---------------------------------------------------------------------
  # nixnet package: nixnetd + nixnetctl. Defined once in ../package.nix,
  # shared with flake.nix's own `packages` output, so there's exactly one
  # buildGoModule call in the whole repo.
  # ---------------------------------------------------------------------
  nixnetPackage = pkgs.callPackage ../package.nix { };

  # ---------------------------------------------------------------------
  # Boot-time hosts seeding (design.md §5.1): synchronous, so
  # /run/nixnet/hosts is NEVER dangling even before nixnetd's first tick.
  # Runs as an activation script, not inside the daemon.
  # ---------------------------------------------------------------------
  extraHostsLines = concatStringsSep "\n" (
    mapAttrsToList (address: names: "${address}\t${concatStringsSep " " (if isList names then names else [ names ])}")
      config.networking.hosts
  );

  seedHostsScript = pkgs.writeShellScript "nixnet-seed-hosts" ''
    set -euo pipefail
    runtime_dir="/run/${cfg.daemon.runtimeDir}"
    mkdir -p "$runtime_dir"
    hosts_dir=$(dirname "${cfg.daemon.hostsFile}")
    mkdir -p "$hosts_dir"

    tmp=$(mktemp "${cfg.daemon.hostsFile}.seed.XXXXXX")
    trap 'rm -f "$tmp"' EXIT

    {
      echo "127.0.0.1 localhost"
      echo "::1 localhost"
      ${optionalString (extraHostsLines != "") ''
        cat <<'NIXNET_EXTRA_HOSTS_EOF'
        ${extraHostsLines}
        NIXNET_EXTRA_HOSTS_EOF
      ''}
      echo "# BEGIN nixnet"
      # Best-effort: seed from the last-known-good winners in
      # state.json, if a previous boot left one. Never fatal if missing,
      # unreadable, or jq isn't happy with it — the daemon's first probe
      # tick (within one intervalMs of startup) will correct/populate
      # this regardless.
      if [ -r "${cfg.daemon.stateDir}/state.json" ]; then
        ${pkgs.jq}/bin/jq -r '
          .peers // {} | to_entries[] |
          select(.value.lastPublishedAddress != null and .value.lastPublishedAddress != "") |
          .value.lastPublishedAddress as $addr | .key as $name | "\($addr)\t\($name)"
        ' "${cfg.daemon.stateDir}/state.json" 2>/dev/null || true
      fi
      echo "# END nixnet"
    } > "$tmp"

    mv -f "$tmp" "${cfg.daemon.hostsFile}"
    chmod 0644 "${cfg.daemon.hostsFile}"
  '';

in
{
  options.services.nixnet = {
    enable = mkEnableOption "nixnet transport failover (peer + uplink health-checked publish)";

    package = mkOption {
      type = types.package;
      default = nixnetPackage;
      description = "The nixnetd + nixnetctl package. Override only to pin/patch a build.";
    };

    daemon = {
      stateDir = mkOption { type = types.path; default = "/var/lib/nixnet"; };
      runtimeDir = mkOption { type = types.str; default = "nixnet"; description = "Under /run."; };
      hostsFile = mkOption { type = types.path; default = "/run/nixnet/hosts"; };

      defaultProbe = {
        intervalMs = mkOption { type = types.ints.positive; default = 3000; };
        timeoutMs = mkOption { type = types.ints.positive; default = 800; };
        upThreshold = mkOption { type = types.ints.positive; default = 2; };
        downThreshold = mkOption { type = types.ints.positive; default = 3; };
      };
    };

    peers = mkOption {
      type = types.attrsOf peerType;
      default = { };
      description = "Remote hosts reachable over one or more transports, published into /etc/hosts.";
    };

    uplinks = mkOption {
      type = types.attrsOf uplinkType;
      default = { };
      description = "Local egress choices (wired/wireless/cellular/...), published as route metrics.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion =
          let allNames = concatMap (p: p.hostnames) (attrValues cfg.peers);
          in length allNames == length (unique allNames);
        message = ''
          services.nixnet.peers.*.hostnames has a duplicate entry across
          two different peers. Silently colliding entries in a shared
          namespace like /etc/hosts is exactly the kind of failure nixnet
          exists to prevent, not reproduce -- rename one of them.
        '';
      }
      {
        assertion = hasPrefix "/var/lib/" (toString cfg.daemon.stateDir);
        message = ''
          services.nixnet.daemon.stateDir (${toString cfg.daemon.stateDir}) must
          live under /var/lib/ -- the systemd unit uses StateDirectory=,
          which systemd only ever creates under /var/lib/ and which is
          what gives the DynamicUser nixnetd runs as correct ownership of
          it. A path elsewhere would silently keep the *directory name*
          but not actually point at the location you configured.
        '';
      }
    ] ++ (flatten (mapAttrsToList
      (name: u: imap0
        (i: t: {
          assertion = t.interface != null;
          message = "services.nixnet.uplinks.${name}.transports[${toString i}]: interface is required for uplink transports.";
        })
        u.transports)
      cfg.uplinks))
    ++ (flatten (mapAttrsToList
      (name: u: imap0
        (i: t: {
          assertion = t.probe.method == "exec" || t.probe.target != null;
          message = "services.nixnet.uplinks.${name}.transports[${toString i}]: probe.target (or probe.method = \"exec\") is required -- address has no default for uplinks.";
        })
        u.transports)
      cfg.uplinks))
    ++ (flatten (mapAttrsToList
      (peerOrUplinkName: g: imap0
        (i: t: {
          assertion = t.probe.method != "exec" || t.probe.exec != null;
          message = "${peerOrUplinkName}.transports[${toString i}]: probe.method = \"exec\" requires probe.exec.";
        })
        g.transports)
      (cfg.peers // cfg.uplinks)));

    environment.etc."nixnet/config.json".source = configJsonFile;

    # Same pattern nixpkgs's own systemd-resolved module uses for
    # /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf: point a
    # normally store-symlinked /etc file at a runtime-writable path
    # instead. Loudly documented here, not a silent takeover.
    environment.etc.hosts = mkForce { source = cfg.daemon.hostsFile; };

    system.activationScripts.nixnetSeedHosts = {
      text = "${seedHostsScript}";
      deps = [ ];
    };

    systemd.services.nixnetd = {
      description = "nixnet transport failover daemon";
      # No explicit ordering against the hosts-seeding activation script:
      # system.activationScripts already runs synchronously, to
      # completion, before systemd starts any unit on a fresh boot; on a
      # `nixos-rebuild switch` (not a fresh boot) activation runs
      # synchronously too, ahead of restarting changed units -- there is
      # no systemd unit to order against, activation isn't one.
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/nixnetd -config /etc/nixnet/config.json";
        DynamicUser = true;
        RuntimeDirectory = cfg.daemon.runtimeDir;
        StateDirectory = baseNameOf (toString cfg.daemon.stateDir);
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/run/${cfg.daemon.runtimeDir}" cfg.daemon.stateDir ];
        AmbientCapabilities =
          (optional needsNetAdmin "CAP_NET_ADMIN")
          ++ (optional needsNetRaw "CAP_NET_RAW");
        Restart = "always";
        RestartSec = 1;
        WatchdogSec = 10; # heartbeat interval is WATCHDOG_USEC/2, see internal/sdnotify
        NotifyAccess = "main";
        Type = "notify";
      };
    };
  };
}
