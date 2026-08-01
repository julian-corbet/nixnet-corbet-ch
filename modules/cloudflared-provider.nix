# modules/cloudflared-provider.nix
#
# nixnet's charter is broader than "peer address failover" + "uplink
# egress selection" (the two patterns docs/providers.md and the README
# describe as one shared abstraction): ANY declaratively-managed network
# connection that can fail and need non-interactive recovery belongs in
# nixnet's namespace. cloudflared (a Cloudflare Tunnel client) is the
# first example that doesn't fit the peer/transport shape at all -- it's
# inbound-only (it RECEIVES public traffic; it never helps THIS host
# reach a peer), so it can't contribute a `nixnet.peers.<name>`
# transport the way netbird-provider does. What it shares with
# netbird-provider is the OTHER half of that module: a resident daemon
# whose failure mode is "looks alive, isn't actually working" (a wedged
# QUIC/HTTP2 edge connection, not a process crash -- `Restart=on-failure`
# never fires for this), caught by periodic health probing and fixed by
# a non-interactive restart. This module is exactly netbird-provider's
# drift-check/reprovision half, reapplied to cloudflared's own health
# signal, with no transport-contribution half at all.
#
# Health signal: cloudflared's own `--metrics`/`TUNNEL_METRICS` HTTP
# endpoint's `/ready` route (upstream-documented, not a private
# behavior) -- `{"status":200,"readyConnections":N,"connectorId":"..."}`.
# This module pins that endpoint to a known address on `cfg.tunnelUnit`
# (merging one more key into its `environment` attrset -- the exact same
# mechanism the caller's own cloudflared wrapper already uses for
# TUNNEL_EDGE_IP_VERSION/TUNNEL_TRANSPORT_PROTOCOL) so the watchdog
# always knows where to probe, rather than reading cloudflared's own
# random default port off the network at runtime.
{ config, lib, pkgs, ... }:
let
  cfg = config.nixnet.cloudflared;

  driftCheckScript = pkgs.writeShellApplication {
    name = "nixnet-cloudflared-drift-check";
    runtimeInputs = [ pkgs.curl pkgs.jq pkgs.systemd pkgs.coreutils pkgs.gawk ];
    text = ''
      set -euo pipefail

      state_dir="/run/nixnet/reprovision"
      drift_count_file="$state_dir/.cloudflared-drift-count"
      last_restart_file="/var/lib/nixnet-cloudflared/.last-restart"
      mkdir -p "$state_dir" "$(dirname "$last_restart_file")"

      ready_json=$(curl -fsS --max-time 5 "http://${cfg.metricsAddr}/ready" 2>/dev/null || echo '{}')

      drift=0
      if [ "$ready_json" = "{}" ] || ! echo "$ready_json" | jq -e . >/dev/null 2>&1; then
        echo "nixnet-cloudflared-drift-check: metrics endpoint (${cfg.metricsAddr}) not responding -- tunnel daemon down or wedged"
        drift=1
      else
        ready_connections=$(echo "$ready_json" | jq -r '.readyConnections // 0')
        if [ "$ready_connections" -lt 1 ]; then
          echo "nixnet-cloudflared-drift-check: readyConnections=$ready_connections -- no live edge connections (daemon running, tunnel not actually serving)"
          drift=1
        fi
      fi

      if [ "$drift" -eq 0 ]; then
        rm -f "$drift_count_file"
        echo "nixnet-cloudflared-drift-check: healthy"
        exit 0
      fi

      # A freshly-(re)started cloudflared genuinely needs a few seconds to
      # reach the edge -- on a slow boot (network-online.target delayed) or
      # right after an unrelated switch-triggered restart, that legitimate
      # startup window looks identical to real drift. Give it the same
      # grace period the threshold itself represents (checkIntervalSec *
      # driftFailureThreshold) before counting a failure at all, rather
      # than risk restarting a daemon that was already about to succeed.
      active_since_us=$(systemctl show ${lib.escapeShellArg cfg.tunnelUnit} -p ActiveEnterTimestampMonotonic --value 2>/dev/null || echo 0)
      now_us=$(awk '{ printf "%d", $1 * 1000000 }' /proc/uptime)
      age_sec=$(( (now_us - active_since_us) / 1000000 ))
      if [ "$age_sec" -lt ${toString (cfg.checkIntervalSec * cfg.driftFailureThreshold)} ]; then
        echo "nixnet-cloudflared-drift-check: drift-shaped reading but ${cfg.tunnelUnit} only active ''${age_sec}s -- within startup grace, not counting"
        exit 0
      fi

      count=0
      [ -r "$drift_count_file" ] && count=$(cat "$drift_count_file")
      count=$((count + 1))
      echo "$count" > "$drift_count_file"

      if [ "$count" -lt ${toString cfg.driftFailureThreshold} ]; then
        echo "nixnet-cloudflared-drift-check: drift-shaped failure, count=$count (threshold ${toString cfg.driftFailureThreshold})"
        exit 0
      fi

      now=$(date +%s)
      last=0
      [ -r "$last_restart_file" ] && last=$(cat "$last_restart_file")
      elapsed=$((now - last))
      if [ "$elapsed" -lt ${toString cfg.minRestartIntervalSec} ]; then
        echo "nixnet-cloudflared-drift-check: threshold reached but rate-limited (last restart ''${elapsed}s ago, min ${toString cfg.minRestartIntervalSec}s) -- waiting"
        exit 0
      fi

      echo "$now" > "$last_restart_file"
      echo "NIXNET_CLOUDFLARED_RESTART count=$count reason=drift-threshold-reached unit=${cfg.tunnelUnit}"
      systemctl restart ${lib.escapeShellArg cfg.tunnelUnit}
      rm -f "$drift_count_file"
    '';
  };
in
{
  options.nixnet.cloudflared = {
    enable = lib.mkEnableOption "cloudflared tunnel health watchdog (nixnet's drift-check/reprovision pattern, applied to a resident daemon instead of a peer transport)";

    tunnelUnit = lib.mkOption {
      type = lib.types.str;
      example = "cloudflared-tunnel-00000000-0000-0000-0000-000000000000";
      description = ''
        The `services.cloudflared`-managed systemd unit this watchdog
        probes and, on persistent drift, restarts -- the BARE unit name,
        with no trailing `.service` (this module uses it as a
        `systemd.services.<name>` attribute key, which NixOS itself
        appends `.service` to; passing it pre-suffixed here would
        silently produce a second, bogus `<name>.service.service` unit
        instead of extending the real one). Wraps upstream -- never
        reimplements cloudflared's own tunnel/config management, same
        boundary netbird-provider draws around `services.netbird`.
      '';
    };

    metricsAddr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:20241";
      description = ''
        `host:port` for cloudflared's own `--metrics` HTTP endpoint. This
        module sets `TUNNEL_METRICS` to this value on `cfg.tunnelUnit`
        automatically (merged into its `environment` attrset) -- no
        separate wiring needed on the cloudflared side. Left at
        cloudflared's own conventional default first-choice port.
      '';
    };

    checkIntervalSec = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = "How often the health probe runs.";
    };

    driftFailureThreshold = lib.mkOption {
      type = lib.types.ints.positive;
      default = 3;
      description = "Consecutive drift-shaped probe failures before a restart fires -- hysteresis against a single transient blip.";
    };

    minRestartIntervalSec = lib.mkOption {
      type = lib.types.ints.positive;
      default = 300;
      description = "Rate limit between actual restarts, so a persistently-down edge (e.g. a real Cloudflare-side outage) doesn't thrash the service.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # The exact regression this module already shipped once (caught in
        # build-verification, not by this assertion): a pre-suffixed
        # tunnelUnit silently creates a second, bogus
        # "<name>.service.service" unit that gets TUNNEL_METRICS instead of
        # the real one -- which then leaves the REAL tunnel's /ready
        # endpoint permanently unreachable, so this watchdog would restart
        # a healthy, public-serving tunnel every minRestartIntervalSec
        # forever. Strictly worse than not running this module at all, so
        # it's worth a hard eval-time guard, not just a doc comment.
        assertion = !(lib.hasSuffix ".service" cfg.tunnelUnit) && !(lib.hasInfix "/" cfg.tunnelUnit);
        message = ''
          nixnet.cloudflared.tunnelUnit ("${cfg.tunnelUnit}") must
          be the BARE systemd unit name, with no ".service" suffix and no
          "/" -- see this option's own description for why a pre-suffixed
          value is actively dangerous here, not just redundant.
        '';
      }
    ];

    systemd.services.${cfg.tunnelUnit}.environment.TUNNEL_METRICS = cfg.metricsAddr;

    systemd.timers.nixnet-cloudflared-drift-check = {
      description = "Periodic health probe for nixnet's cloudflared watchdog";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitActiveSec = "${toString cfg.checkIntervalSec}s";
        Unit = "nixnet-cloudflared-drift-check.service";
      };
    };

    systemd.services.nixnet-cloudflared-drift-check = {
      description = "nixnet cloudflared drift detector + non-interactive restart";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${driftCheckScript}/bin/nixnet-cloudflared-drift-check";
        # Root: needs `systemctl restart` on cfg.tunnelUnit. Narrowly-scoped,
        # rate-limited oneshot, never a resident privileged process --
        # same privilege shape as netbird-provider's reprovision unit.
      };
    };

    systemd.tmpfiles.rules = [
      # Same path netbird-provider's own tmpfiles rule declares -- a plain
      # duplicate list entry across modules is harmless (systemd-tmpfiles
      # is idempotent), and cloudflared-provider must not assume
      # netbird-provider (or even nixnet.core) is enabled on the
      # same host, so it declares this independently rather than relying
      # on another module having already done so.
      "d /run/nixnet/reprovision 0750 root root -"
      # Deliberately NOT /var/lib/nixnet: that path is nixnetd's own
      # `StateDirectory=nixnet` (core.nix), owned by its own fixed user --
      # this module must work with or without core.nix enabled at all, and
      # even when both are enabled, two independent systemd mechanisms
      # (StateDirectory= vs a plain tmpfiles `d` rule) fighting over the
      # same top-level directory's ownership across reboots is exactly the
      # kind of footgun worth a few extra bytes to avoid.
      "d /var/lib/nixnet-cloudflared 0750 root root -"
    ];
  };
}
