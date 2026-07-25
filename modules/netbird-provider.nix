# modules/netbird-provider.nix
#
# The first-party reference provider (design.md §7). Wraps upstream
# `services.netbird` — never reimplements NetBird's own install/config
# management — and adds exactly three things on top: a dynamic
# address+health source per configured peer (via the exec-probe contract,
# docs/providers.md §6.2), a precise drift detector, and non-interactive
# headless reprovisioning from a setup-key secret.
#
# This is the concrete fix for the incident that motivated nixnet: local
# NetBird identity state going empty/stale and the daemon silently falling
# back to a default management endpoint. See §7.4 "the concrete incident
# fix" for the exact drift definition this module checks.
#
# Like modules/core.nix, this file is shared verbatim between
# nixosModules.netbird-provider and systemManagerModules.netbird-provider.

{ lib, config, pkgs, ... }:

with lib;

let
  cfg = config.services.nixnet.netbird;

  peerType = types.submodule {
    options = {
      priority = mkOption {
        type = types.int;
        description = "Priority of this peer's netbird-supplied transport, same scale as any other transport's priority.";
      };
      staticOverlayAddress = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Set only if this peer's overlay IP is fixed/known in advance;
          otherwise left null and discovered dynamically each tick via
          `netbird status --json`.
        '';
      };
      probe.port = mkOption {
        type = types.port;
        default = 22;
      };
    };
  };

  hostname = if cfg.hostnameOverride != null then cfg.hostnameOverride else config.networking.hostName;

  # One address+health-probe script PER configured peer, values baked in at
  # eval time (mirrors the tailscale-provider example in docs/providers.md
  # §6.4) — simpler than threading per-peer config through CLI args at run
  # time, and keeps every argv[0] a single self-contained store path with
  # no runtime lookup of "which peer am I" needed.
  #
  # Uses pkgs.writeShellApplication so every tool used (netbird, jq,
  # coreutils) is resolved to an absolute store path baked into the
  # wrapper's own PATH — never the caller's ambient PATH. This is the
  # concrete system-manager-portability technique design.md's Go/PATH
  # rationale (§1) calls for: nixnetd's own exec never depends on host
  # PATH, and neither does the script it execs.
  mkAddressProbe = peerName: peerCfg:
    pkgs.writeShellApplication {
      name = "nixnet-netbird-address-probe-${peerName}";
      runtimeInputs = [ pkgs.netbird pkgs.jq ];
      text = ''
        set -euo pipefail

        drift_state_dir="/run/nixnet/reprovision"
        drift_count_file="$drift_state_dir/.netbird-drift-count-${peerName}"
        trigger_file="$drift_state_dir/netbird"
        mkdir -p "$drift_state_dir"

        fail_drift_shaped() {
          # A drift-shaped signal (identity/state problem), as opposed to
          # a plain reachability failure -- see design.md §7.4's
          # distinction. Counts consecutive occurrences and only touches
          # the reactive trigger file after
          # driftFailureThreshold in a row, its own small hysteresis to
          # avoid false positives during normal daemon startup.
          count=0
          [ -r "$drift_count_file" ] && count=$(cat "$drift_count_file")
          count=$((count + 1))
          echo "$count" > "$drift_count_file"
          if [ "$count" -ge ${toString cfg.reprovision.driftFailureThreshold} ]; then
            touch "$trigger_file"
          fi
          echo '{"healthy":false,"detail":"drift-shaped failure (netbird identity/state), count='"$count"'"}'
          exit 1
        }

        ok_reachable() {
          rm -f "$drift_count_file"
        }

        if [ ! -s /var/lib/netbird/config.json ]; then
          fail_drift_shaped
        fi
        if ! ${pkgs.jq}/bin/jq -e . /var/lib/netbird/config.json >/dev/null 2>&1; then
          fail_drift_shaped
        fi

        status_json=$(netbird status --json 2>/dev/null || echo '{}')

        ${identityHealthCheckBash "${pkgs.jq}/bin/jq" cfg.managementUrl}
        if [ "$mgmt_healthy" = "no" ]; then
          # Identity/management-channel problem: enrolled against the wrong
          # endpoint, or the management connection is down. Every OTHER
          # signal on such a daemon can still look healthy -- this is
          # exactly what drift detection exists to catch.
          fail_drift_shaped
        fi

        if ! ip link show netbird0 >/dev/null 2>&1 && ! ip link show wt0 >/dev/null 2>&1; then
          fail_drift_shaped
        fi

        # Identity/state looks sound. Now find this specific peer's
        # connection entry -- a plain network partition here (peer just
        # unreachable, identity intact) is NOT drift, and must fall
        # through to ordinary priority failover with no identity action.
        ok_reachable

        peer_entry=$(echo "$status_json" | ${pkgs.jq}/bin/jq -c --arg name "${peerName}" \
          '(.peers.details // [])[] | select(.fqdn == $name or .hostName == $name or (.fqdn | tostring | startswith($name)))' 2>/dev/null | head -n1 || true)

        connected="false"
        discovered_addr=""
        if [ -n "$peer_entry" ]; then
          connected=$(echo "$peer_entry" | ${pkgs.jq}/bin/jq -r '(.status == "Connected") or (.connStatus == "Connected") // false')
          discovered_addr=$(echo "$peer_entry" | ${pkgs.jq}/bin/jq -r '.ip // .netbirdIp // empty' 2>/dev/null || true)
        fi

        ${optionalString (peerCfg.staticOverlayAddress != null) ''
          discovered_addr="${peerCfg.staticOverlayAddress}"
        ''}

        if [ "$connected" = "true" ] && [ -n "$discovered_addr" ]; then
          echo "{\"address\":\"$discovered_addr\",\"healthy\":true,\"detail\":\"netbird p2p/relay connected\"}"
          exit 0
        fi

        echo "{\"healthy\":false,\"detail\":\"netbird peer not Connected (reachability, not identity -- no reprovision)\"}"
        exit 1
      '';
    };

  # Shared identity/management-health check, used identically by the
  # exec-probe, drift-check, and reprovision scripts below -- factored out
  # 2026-07-25 after the same check was found duplicated AND independently
  # buggy in three separate places. Sets $mgmt_url/$mgmt_connected/
  # $mgmt_healthy ("yes"/"no") in the caller's shell; the caller decides
  # what "not healthy" means in its own context (probe failure vs
  # drift-check log line vs reprovision precondition).
  #
  # netbird v0.74.3's `status --json` has NO `.managementState` object and
  # NO `.needsLogin` field at all -- confirmed directly against a live
  # daemon. The real fields are `.management.url` (which ALWAYS carries an
  # explicit port, e.g. "https://host:443", even when the configured
  # managementUrl has none -- the naive exact-string comparison this
  # replaced produced a false "drift-shaped failure" on a genuinely healthy,
  # correctly-enrolled connection) and `.management.connected` (boolean).
  identityHealthCheckBash = jqBin: expectedUrl: ''
    mgmt_url=$(echo "$status_json" | ${jqBin} -r '.management.url // empty' 2>/dev/null || true)
    mgmt_url_no_port="''${mgmt_url%:*}"
    mgmt_connected=$(echo "$status_json" | ${jqBin} -r '.management.connected // false' 2>/dev/null || echo false)
    mgmt_healthy=yes
    if [ -n "$mgmt_url" ] && [ "$mgmt_url_no_port" != "${expectedUrl}" ]; then
      mgmt_healthy=no
    fi
    if [ "$mgmt_connected" != "true" ]; then
      mgmt_healthy=no
    fi
  '';

  driftCheckScript = pkgs.writeShellApplication {
    name = "nixnet-netbird-drift-check";
    runtimeInputs = [ pkgs.netbird pkgs.jq pkgs.iproute2 ];
    text = ''
      set -euo pipefail
      trigger_dir="/run/nixnet/reprovision"
      mkdir -p "$trigger_dir"

      drift=0

      if [ ! -s /var/lib/netbird/config.json ]; then
        echo "nixnet-netbird-drift-check: config.json missing or empty"
        drift=1
      elif ! jq -e . /var/lib/netbird/config.json >/dev/null 2>&1; then
        echo "nixnet-netbird-drift-check: config.json is not valid JSON"
        drift=1
      fi

      if [ "$drift" -eq 0 ]; then
        status_json=$(netbird status --json 2>/dev/null || echo '{}')
        ${identityHealthCheckBash "jq" cfg.managementUrl}
        if [ "$mgmt_healthy" = "no" ]; then
          echo "nixnet-netbird-drift-check: management URL mismatch or management channel disconnected (url=$mgmt_url, expected ${cfg.managementUrl})"
          drift=1
        fi
        if ! ip link show netbird0 >/dev/null 2>&1 && ! ip link show wt0 >/dev/null 2>&1; then
          echo "nixnet-netbird-drift-check: mesh network interface absent"
          drift=1
        fi
      fi

      if [ "$drift" -eq 1 ]; then
        # Periodic safety net: a single bad reading is enough to trigger
        # here (it already only runs every checkIntervalSec, unlike the
        # reactive exec-probe path which needs driftFailureThreshold
        # consecutive failures because it runs on the much faster probe
        # cadence).
        touch "$trigger_dir/netbird"
        echo "nixnet-netbird-drift-check: drift detected, touched $trigger_dir/netbird"
      else
        echo "nixnet-netbird-drift-check: no drift detected"
      fi
    '';
  };

  reprovisionScript = pkgs.writeShellApplication {
    name = "nixnet-netbird-reprovision";
    runtimeInputs = [ pkgs.netbird pkgs.jq pkgs.util-linux pkgs.coreutils ];
    text = ''
      set -euo pipefail

      state_dir="/var/lib/nixnet"
      mkdir -p "$state_dir"
      lock_file="$state_dir/.netbird-reprovision.lock"
      last_attempt_file="$state_dir/.netbird-reprovision-last-attempt"
      status_file="/run/nixnet/netbird-provider-status.json"
      mkdir -p "$(dirname "$status_file")"

      exec 9>"$lock_file"
      if ! flock -n 9; then
        echo "NIXNET_NETBIRD_REPROVISION_SKIPPED reason=already-running"
        exit 0
      fi

      now=$(date +%s)
      last=0
      [ -r "$last_attempt_file" ] && last=$(cat "$last_attempt_file")
      elapsed=$((now - last))
      if [ "$elapsed" -lt ${toString cfg.reprovision.minReprovisionIntervalSec} ]; then
        echo "NIXNET_NETBIRD_REPROVISION_SKIPPED reason=rate-limited elapsed=''${elapsed}s min=${toString cfg.reprovision.minReprovisionIntervalSec}s"
        exit 0
      fi

      # Re-confirm drift is still present before acting on what may be a
      # stale trigger.
      drift_still_present=0
      if [ ! -s /var/lib/netbird/config.json ]; then
        drift_still_present=1
      elif ! jq -e . /var/lib/netbird/config.json >/dev/null 2>&1; then
        drift_still_present=1
      else
        status_json=$(netbird status --json 2>/dev/null || echo '{}')
        ${identityHealthCheckBash "jq" cfg.managementUrl}
        if [ "$mgmt_healthy" = "no" ]; then
          drift_still_present=1
        fi
      fi
      if [ "$drift_still_present" -eq 0 ]; then
        echo "NIXNET_NETBIRD_REPROVISION_SKIPPED reason=drift-already-resolved"
        rm -f /run/nixnet/reprovision/netbird
        exit 0
      fi

      echo "$now" > "$last_attempt_file"

      if [ ! -r "${cfg.setupKeyFile}" ]; then
        echo "NIXNET_NETBIRD_REPROVISION_FAILED reason=no-setup-key path=${cfg.setupKeyFile}" >&2
        echo '{"result":"failed","reason":"no-setup-key"}' > "$status_file"
        exit 1
      fi
      setup_key=$(cat "${cfg.setupKeyFile}")

      netbird down || true

      if ! netbird up --management-url "${cfg.managementUrl}" \
                       --setup-key "$setup_key" \
                       --hostname "${hostname}"; then
        echo "NIXNET_NETBIRD_REPROVISION_FAILED reason=netbird-up-failed" >&2
        echo '{"result":"failed","reason":"netbird-up-failed"}' > "$status_file"
        exit 1
      fi

      deadline=$((now + ${toString cfg.reprovision.connectTimeoutSec}))
      connected="false"
      while [ "$(date +%s)" -lt "$deadline" ]; do
        st=$(netbird status --json 2>/dev/null || echo '{}')
        mgmt_connected=$(echo "$st" | jq -r '.management.connected // false')
        if [ "$mgmt_connected" = "true" ] && { ip link show netbird0 >/dev/null 2>&1 || ip link show wt0 >/dev/null 2>&1; }; then
          connected="true"
          break
        fi
        sleep 1
      done

      rm -f /run/nixnet/reprovision/netbird

      if [ "$connected" = "true" ]; then
        echo "NIXNET_NETBIRD_REPROVISION_SUCCEEDED"
        printf '{"result":"succeeded","at":"%s"}\n' "$(date -Iseconds)" > "$status_file"
        exit 0
      else
        echo "NIXNET_NETBIRD_REPROVISION_FAILED reason=timeout-waiting-for-connected" >&2
        echo '{"result":"failed","reason":"timeout-waiting-for-connected"}' > "$status_file"
        exit 1
      fi
    '';
  };

in
{
  options.services.nixnet.netbird = {
    enable = mkEnableOption "NetBird transport provider for nixnet";

    managementUrl = mkOption {
      type = types.str;
      example = "https://mesh.example.com";
      description = "The NetBird management server URL this fleet enrolls against.";
    };

    setupKeyFile = mkOption {
      type = types.path;
      description = ''
        Path to a file containing a reusable, non-interactive NetBird
        setup key. sops/agenix-provided, root-readable. This is what
        makes reprovisioning scriptable at all -- interactive SSO/browser
        login is never invoked.
      '';
    };

    hostnameOverride = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Defaults to config.networking.hostName.";
    };

    peers = mkOption {
      type = types.attrsOf peerType;
      default = { };
      description = ''
        Which services.nixnet.peers.<name> entries netbird-provider
        should contribute an overlay transport into. The name here MUST
        match an existing services.nixnet.peers.<name> (declared by you,
        with its own `hostnames` and any other transports) -- this
        provider only ever ADDS one more transport to that peer's list,
        via ordinary Nix list-option merging (docs/providers.md §6.1.2).
      '';
    };

    reprovision = {
      enable = mkOption { type = types.bool; default = true; };
      checkIntervalSec = mkOption {
        type = types.ints.positive;
        default = 60;
        description = "Periodic safety-net cadence.";
      };
      minReprovisionIntervalSec = mkOption {
        type = types.ints.positive;
        default = 300;
        description = "Rate limit between actual `netbird up` attempts.";
      };
      driftFailureThreshold = mkOption {
        type = types.ints.positive;
        default = 3;
        description = "Consecutive drift-shaped exec-probe failures before the reactive trigger fires.";
      };
      connectTimeoutSec = mkOption {
        type = types.ints.positive;
        default = 30;
        description = "Bound for post-enroll poll of `netbird status`.";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = all (name: hasAttr name config.services.nixnet.peers) (attrNames cfg.peers);
        message = ''
          services.nixnet.netbird.peers has an entry whose name doesn't
          match any services.nixnet.peers.<name> -- declare the peer
          itself first (hostnames, any other transports), then let
          netbird-provider contribute its overlay transport into it.
        '';
      }
    ];

    # Wraps upstream services.netbird -- never reimplements NetBird's own
    # install/config management (docs/providers.md §6.1.3).
    services.netbird.enable = true;

    # nixnetd's unit hard-requires SupplementaryGroups = [ "netbird" ]
    # (see the systemd.services.nixnetd extension further down) so the
    # exec-probe script above -- run as a child of nixnetd's own
    # unprivileged process -- can reach NetBird's control socket. That
    # group is NOT guaranteed to exist just because services.netbird.
    # enable = true: upstream's netbird.nix only provisions a matching
    # users.groups.<name> for a `hardened = true` client (AmbientCapabilities
    # + DynamicUser-alike sandboxing), and `services.netbird.enable = true`
    # here only sets up its backward-compat "default" client with
    # `hardened = mkDefault false` -- i.e. a root-run daemon, no group at
    # all, by default. Relying on that group having been provisioned as a
    # side effect elsewhere is exactly the kind of assumption that leaves
    # nixnetd crash-looping (systemd exit 216/GROUP, "Failed to determine
    # supplementary groups") on any host where netbird just runs as root.
    # Declare it ourselves instead, so the dependency is guaranteed rather
    # than accidentally-sometimes-true. Safe even when services.netbird
    # DOES also provision it (e.g. a consumer sets `hardened = true`):
    # both contribute the same all-defaults `{ }` definition, and NixOS
    # merges two such definitions for the same group with no conflict.
    users.groups.netbird = { };

    # Contribute one exec-probe transport per configured peer, via
    # ordinary list-option merging into the SAME
    # services.nixnet.peers.<name>.transports list the consumer's own
    # machine config (and any other provider) also contributes into.
    # netbird-provider never touches services.nixnet.daemon.* and never
    # writes to /run/nixnet/* directly (docs/providers.md §6.1.2).
    services.nixnet.peers = mkMerge (mapAttrsToList
      (peerName: peerCfg: {
        ${peerName}.transports = [{
          priority = peerCfg.priority;
          providerId = "netbird";
          probe = {
            method = "exec";
            port = peerCfg.probe.port;
            exec = "${mkAddressProbe peerName peerCfg}/bin/nixnet-netbird-address-probe-${peerName}";
          };
        }];
      })
      cfg.peers);

    # This unit is owned by core (systemd.services.nixnetd, defined in
    # core.nix) -- adding a SupplementaryGroups entry to it here is NOT
    # netbird-provider reaching into services.nixnet.daemon.* (the
    # contract's actual boundary, docs/providers.md §6.1.2); it's an
    # ordinary cross-module systemd.services.* extension, the same
    # mechanism any two unrelated NixOS modules can use to jointly shape a
    # third unit. It's needed because the exec-probe script above runs as
    # a child of nixnetd's own (unprivileged, DynamicUser) process, and
    # `netbird status` needs group-level access to NetBird's control
    # socket. See docs/providers.md's "Deviation: nixnetd
    # SupplementaryGroups" note.
    systemd.services.nixnetd.serviceConfig.SupplementaryGroups = mkIf config.services.nixnet.enable [ "netbird" ];

    systemd.timers.nixnet-netbird-drift-check = mkIf cfg.reprovision.enable {
      description = "Periodic safety-net for nixnet's netbird drift detector";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitActiveSec = "${toString cfg.reprovision.checkIntervalSec}s";
        Unit = "nixnet-netbird-drift-check.service";
      };
    };

    systemd.services.nixnet-netbird-drift-check = mkIf cfg.reprovision.enable {
      description = "nixnet netbird drift detector (periodic safety net)";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${driftCheckScript}/bin/nixnet-netbird-drift-check";
        # Root: needs to read /var/lib/netbird/config.json (root-only) and
        # run `netbird status` at full privilege, matching design.md §7.3's
        # documented privilege level.
      };
    };

    # Reactive path: the address-probe script (run as a child of the
    # unprivileged nixnetd) touches /run/nixnet/reprovision/netbird on
    # driftFailureThreshold consecutive drift-shaped failures. This
    # root-owned path unit is what turns that file-touch into fast
    # reactive recovery, without ever granting the unprivileged probe
    # process itself any systemctl/root capability (design.md §7.4).
    systemd.paths.nixnet-netbird-reprovision-trigger = mkIf cfg.reprovision.enable {
      description = "Watch for nixnet netbird reprovision triggers";
      wantedBy = [ "multi-user.target" ];
      pathConfig = {
        PathExists = "/run/nixnet/reprovision/netbird";
        Unit = "nixnet-netbird-reprovision.service";
      };
    };

    systemd.services.nixnet-netbird-reprovision = mkIf cfg.reprovision.enable {
      description = "nixnet netbird non-interactive reprovisioning";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${reprovisionScript}/bin/nixnet-netbird-reprovision";
        # Root: required to drive `netbird up`/`down` and read the
        # setup-key secret (design.md §8) -- narrowly-scoped, rate-limited
        # oneshot, never a resident privileged process.
      };
    };

    systemd.tmpfiles.rules = [
      "d /run/nixnet/reprovision 0750 root root -"
    ];
  };
}
