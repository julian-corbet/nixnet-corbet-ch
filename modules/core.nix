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

{ lib, config, pkgs, options, ... }:

with lib;

let
  cfg = config.services.nixnet;

  # ---------------------------------------------------------------------
  # system-manager backend detection (design.md §9). system-manager exposes
  # no `networking.hosts` at all and only a fixed `system.activationScripts.
  # users` stub (not an extensible attrsOf), so both the /etc/hosts merge
  # below and the activation-script seeding mechanism need a system-manager
  # code path. Detected via system-manager's OWN `system-manager.*` option
  # namespace (e.g. `system-manager.allowAnyDistro`), which exists only
  # under system-manager and never under real NixOS -- cheaper and more
  # robust than trying to introspect whether `system.activationScripts` is
  # of an extensible type.
  # ---------------------------------------------------------------------
  isSystemManager = options ? system-manager;

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
  # rustPlatform.buildRustPackage call in the whole repo.
  # ---------------------------------------------------------------------
  nixnetPackage = pkgs.callPackage ../package.nix { };

  # ---------------------------------------------------------------------
  # Boot-time hosts seeding (design.md §5.1): synchronous, so
  # cfg.daemon.hostsFile is NEVER dangling even before nixnetd's first
  # tick. Runs as an activation script on NixOS; system-manager has no
  # `networking.hosts` to merge in at all, so this is simply empty there
  # (see the systemd-oneshot seeding path AND the preActivationAssertions
  # hook below for that backend instead).
  # ---------------------------------------------------------------------
  extraHostsLines = concatStringsSep "\n" (
    mapAttrsToList (address: names: "${address}\t${concatStringsSep " " (if isList names then names else [ names ])}")
      (if isSystemManager then { } else config.networking.hosts)
  );

  seedHostsScript = pkgs.writeShellScript "nixnet-seed-hosts" ''
    set -euo pipefail
    runtime_dir="/run/${cfg.daemon.runtimeDir}"
    mkdir -p "$runtime_dir"
    hosts_dir=$(dirname "${cfg.daemon.hostsFile}")
    mkdir -p "$hosts_dir"
    # hostsFile deliberately lives outside nixnetd's DynamicUser StateDirectory
    # (see the option's own doc comment) specifically so it stays reachable by
    # every other reader on the box. nixnetd itself writes here as an
    # unprivileged, per-boot-random DynamicUser UID with no fixed group to
    # grant ownership through, so the directory has to be sticky+world-
    # writable (mode 1777, same model as /tmp) for nixnetd's own atomic
    # write-tmp-then-rename to succeed -- there is exactly one writer
    # (nixnetd) in practice, and the content itself (hostname -> address
    # mappings) is no more sensitive than what's already public via DNS.
    chmod 1777 "$hosts_dir"

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
      hostsFile = mkOption {
        type = types.path;
        # NOT "${cfg.daemon.stateDir}/hosts" -- found 2026-07-25 in production:
        # nixnetd runs with DynamicUser=true, so systemd relocates its
        # StateDirectory to /var/lib/private/nixnet (a symlinked-from
        # /var/lib/nixnet convenience path) and, crucially, makes the shared
        # /var/lib/private/ PARENT directory 0700 root:root -- a hardcoded
        # systemd isolation boundary with no per-service override. Any file
        # nixnetd writes under stateDir inherits that same unreachability for
        # every OTHER process on the box, including systemd-resolved and
        # every plain NSS "files" lookup -- exactly the readers /etc/hosts
        # exists to serve. A sibling directory outside stateDir (still under
        # /var/lib, so the persistence argument below still holds) sidesteps
        # the private-parent entirely.
        default = "/var/lib/nixnet-hosts/hosts";
        description = ''
          Where nixnetd actually keeps /etc/hosts's live content --
          environment.etc.hosts.source points here (see the comment on
          that option below). Deliberately under /var/lib (persists across
          reboots), but deliberately NOT nested under stateDir -- see the
          comment on the default above for why. /run is ruled out for the
          same reason it always was: a fresh, empty tmpfs on every single
          boot, so a symlink chain ending there can never resolve until
          something has run *this specific boot* to (re)create it -- and
          on the system-manager backend specifically, nothing has, at the
          point system-manager-engine resolves this symlink (see
          design.md §9 / §5.1). Living under /var/lib instead means that
          once this file exists for the first time ever on a given host,
          it never goes missing again across any future boot or
          redeploy, which is what actually makes the system-manager
          `preActivationAssertions` guarantee below sufficient in
          practice, not just on paper.
        '';
      };

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

  config = mkIf cfg.enable ({
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
      {
        assertion = !(hasPrefix ("${toString cfg.daemon.stateDir}/") (toString cfg.daemon.hostsFile));
        message = ''
          services.nixnet.daemon.hostsFile (${toString cfg.daemon.hostsFile}) must NOT
          live under services.nixnet.daemon.stateDir (${toString cfg.daemon.stateDir}).
          Found in production 2026-07-25: nixnetd's StateDirectory= is silently
          relocated by systemd (DynamicUser=true) to /var/lib/private/<name>,
          and the shared /var/lib/private/ parent is 0700 root:root with no
          per-service override -- anything nested under stateDir inherits that
          same unreachability for every other reader on the box, including
          /etc/hosts's whole reason to exist. hostsFile has its own sibling
          directory (see its option default) precisely to avoid this.
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
    #
    # mkForce replaces the WHOLE attrset (not just `source`), so any
    # option this feature needs MUST be set HERE, in this same literal --
    # a sibling module contributing e.g. `environment.etc.hosts.
    # replaceExisting = true` separately gets silently discarded back to
    # its default by this mkForce, not merged (verified via
    # lib.evalModules: a consumer override there evaluates to the
    # default regardless). `replaceExisting` only exists as an option on
    # the system-manager backend (real NixOS's environment.etc has no
    # such field -- it always reconciles /etc from scratch on activation
    # instead, so there's nothing to set there); system-manager needs it
    # unconditionally true for this entry specifically, because /etc/hosts
    # already exists, unmanaged, on essentially every real distro
    # system-manager bolts onto -- without it, system-manager just warns
    # and leaves the pre-existing file alone, silently no-op'ing this
    # entire feature.
    environment.etc.hosts = mkForce ({
      source = cfg.daemon.hostsFile;
    } // optionalAttrs isSystemManager {
      replaceExisting = true;
    });

    # system-manager: no `system.activationScripts.<name>` at all (only a
    # fixed, non-extensible `.users` stub -- see options.services.nixnet's
    # `isSystemManager` note above), so the same seeding logic runs as an
    # ordinary oneshot unit instead, ordered before nixnetd via the
    # `before`/`wants` wiring nixnetd itself carries below (added
    # unconditionally -- a harmless dangling unit reference on NixOS, where
    # this service doesn't exist and the activation script above already
    # covers it).
    systemd.services.nixnet-seed-hosts = mkIf isSystemManager {
      description = "Seed cfg.daemon.hostsFile before nixnetd's first tick (system-manager backend)";
      before = [ "nixnetd.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${seedHostsScript}";
      };
    };

    systemd.services.nixnetd = {
      description = "nixnet transport failover daemon";
      # On NixOS, no explicit ordering against the hosts-seeding activation
      # script is needed (see the comment on system.activationScripts
      # above -- activation isn't a systemd unit, it already completes
      # first). On system-manager, nixnet-seed-hosts.service above needs
      # explicit ordering, which these two lines provide; referencing a
      # unit that doesn't exist (the NixOS case) is a harmless no-op.
      after = [ "network.target" "nixnet-seed-hosts.service" ];
      wants = [ "nixnet-seed-hosts.service" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/nixnetd -config /etc/nixnet/config.json";
        DynamicUser = true;
        RuntimeDirectory = cfg.daemon.runtimeDir;
        StateDirectory = baseNameOf (toString cfg.daemon.stateDir);
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/run/${cfg.daemon.runtimeDir}" cfg.daemon.stateDir (dirOf cfg.daemon.hostsFile) ];
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
  }
  # NixOS only: an activation script (design.md §5.1) -- runs synchronously,
  # to completion, before systemd starts any unit on a fresh boot; on a
  # `nixos-rebuild switch` (not a fresh boot) activation runs synchronously
  # too, ahead of restarting changed units. Merged in via `//` (a plain Nix
  # conditional on the ATTRSET ITSELF), not `mkIf` wrapping the value --
  # system-manager's `system.activationScripts` is a fixed-field submodule
  # (only `.users`/`.setupSecrets`/`.generate-age-key` are declared there,
  # not an extensible `attrsOf`), so an `mkIf false { nixnetSeedHosts = ...;
  # }` assigned to it STILL throws "option does not exist" -- the module
  # system's submodule merge walks a definition's structural KEYS to check
  # them against declared options independent of the mkIf condition's truth
  # value. `optionalAttrs` avoids this because when its condition is false
  # the `system` key is simply ABSENT from this module's contributed
  # attrset entirely, so there is no definition to check in the first
  # place. (Verified empirically against a real system-manager consumer
  # target -- an `mkIf isSystemManager`-wrapped version of this same block
  # still failed eval with exactly that error.)
  // (optionalAttrs (!isSystemManager) {
    system.activationScripts.nixnetSeedHosts = {
      text = "${seedHostsScript}";
      deps = [ ];
    };
  })
  # system-manager only: the actual fix for the etc-activation ordering bug
  # (design.md §9). system-manager-engine's activate() runs, in order: (1)
  # preActivationAssertions, (2) etc-file activation, (3) systemd-tmpfiles
  # --create (i.e. systemd.tmpfiles.rules), (4) systemd services -- so both
  # nixnet-seed-hosts.service (a systemd service, step 4) AND a
  # systemd.tmpfiles.rules entry (step 3) run strictly AFTER step 2, too
  # late to help environment.etc.hosts's own resolution at step 2 (verified
  # by reading system-manager-engine's own source, crates/system-manager-
  # engine/src/activate.rs and .../activate/etc_files.rs: it resolves every
  # symlink-mode /etc entry via `fs::canonicalize`, which errors on a
  # dangling target, and -- critically -- ONE such error there aborts
  # collection of the ENTIRE etc file list, so nothing under /etc gets
  # activated at all that run, not just this one entry).
  #
  # `system-manager.preActivationAssertions.<name>.script` is the one hook
  # that genuinely runs BEFORE step 2 (it's step 0, gating whether
  # activation proceeds past its own success/failure at all) -- despite the
  # "assertions" name, its `script` is just an arbitrary shell string run
  # for effect, so it's used here to guarantee cfg.daemon.hostsFile exists
  # as a real file (reusing seedHostsScript itself, so it's the SAME
  # real/best-effort-last-known-good content nixnet-seed-hosts.service
  # produces, not a bare placeholder) before system-manager-engine ever
  # tries to canonicalize environment.etc.hosts's symlink chain. Combined
  # with hostsFile now living under stateDir (/var/lib, survives reboots --
  # see the option's own doc comment) rather than runtimeDir (/run, wiped
  # every boot), this only needs to actually fire on the very first
  # activation ever performed for a given host; every activation after
  # that, the file this script would create already exists from either a
  # previous run of this same script or from nixnetd's own last session.
  #
  # Uses the SAME `optionalAttrs isSystemManager` (not `mkIf`) pattern as
  # the NixOS-only activationScripts block above, for the identical reason:
  # `system-manager.preActivationAssertions` is an option namespace that
  # simply doesn't exist under real NixOS at all, and assigning into an
  # undeclared option path throws regardless of any mkIf wrapping.
  // (optionalAttrs isSystemManager {
    system-manager.preActivationAssertions.nixnetSeedHosts = {
      enable = true;
      script = "${seedHostsScript}";
    };

    # /etc/hosts management is silently useless if the host's own NSS
    # config never actually reaches "files" for hostname lookups. Modern
    # systemd-resolved defaults ship `hosts: resolve [!UNAVAIL=return]
    # files ... dns` -- the [!UNAVAIL=return] means ANY answer from
    # resolve (a successful DNS hit, NOT just success-or-fail) short-
    # circuits NSS before "files" is ever consulted. On a split-horizon
    # setup where DNS already answers a peer's hostname (e.g. via a VPN
    # mesh's own DNS), nixnetd's carefully-computed winner in /etc/hosts
    # is written correctly and then never read -- discovered exactly this
    # way against a real deploy (DNS returned a mesh peer's overlay
    # address for a hostname nixnetd had already resolved to the healthy
    # LAN address). Rather than rewrite a file nixnet doesn't own, fail
    # loudly at activation time with the fix, instead of a confusing
    # mount/connect timeout discovered later -- same "enforce at
    # declaration, not detection after the fact" principle as nixnas's
    # persist-enforce.
    system-manager.preActivationAssertions.nixnetNsswitchOrder = {
      enable = true;
      script = pkgs.writeShellScript "nixnet-nsswitch-check" ''
        set -euo pipefail
        line="$(grep '^hosts:' /etc/nsswitch.conf || true)"
        if [ -z "$line" ]; then
          exit 0   # no hosts: line at all -- not nixnet's problem to diagnose
        fi
        files_pos=$(echo "$line" | grep -bo '\bfiles\b' | head -1 | cut -d: -f1 || echo "")
        resolve_pos=$(echo "$line" | grep -bo '\bresolve\b' | head -1 | cut -d: -f1 || echo "")
        dns_pos=$(echo "$line" | grep -bo '\bdns\b' | head -1 | cut -d: -f1 || echo "")
        shortcircuit_pos="$resolve_pos"
        if [ -z "$shortcircuit_pos" ]; then shortcircuit_pos="$dns_pos"; fi
        if [ -n "$files_pos" ] && [ -n "$shortcircuit_pos" ] && [ "$files_pos" -lt "$shortcircuit_pos" ]; then
          exit 0   # files comes first -- nixnet's /etc/hosts entries are reachable
        fi
        echo "nixnet: /etc/nsswitch.conf's 'hosts:' line does not reach 'files' before" >&2
        echo "  'resolve'/'dns' (found: $line)." >&2
        echo "  nixnetd writes /etc/hosts correctly, but nothing will ever read it --" >&2
        echo "  DNS answers first and NSS short-circuits on [!UNAVAIL=return]." >&2
        echo "  Fix: put 'files' before 'resolve'/'dns' in that line, e.g.:" >&2
        echo "    hosts: files mymachines resolve [!UNAVAIL=return] dns" >&2
        exit 1
      '';
    };
  }));
}
