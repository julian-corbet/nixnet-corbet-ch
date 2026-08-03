# modules/overlay.nix
#
# nixnet.overlay — turn THIS host into a self-hosted NetBird overlay client,
# optionally the network's ONE routing peer (advertising a LAN so
# client-less devices on it become reachable from the overlay without their
# own NetBird install).
#
# Distinct from `netbird-provider.nix` (`nixnet.netbird`): that module
# contributes a PEER TRANSPORT into nixnet's own peer/uplink failover engine
# (core.nix) for a peer this host wants to REACH. This module is the other
# half of the same underlying tool — making THIS host a NetBird peer at
# all, and (optionally) the gateway other LAN devices are reached through.
# A host commonly wants both: enrolled via `nixnet.overlay`, then a specific
# remote peer's health/reprovisioning handled via `nixnet.netbird`.
#
# Wraps upstream `services.netbird` — never reimplements NetBird's own
# install/config management, the same boundary every provider in this repo
# draws (docs/providers.md's "What a provider MUST do" section).
{ config, lib, pkgs, ... }:

let
  cfg = config.nixnet.overlay;
in
{
  options.nixnet.overlay = {
    enable = lib.mkEnableOption "NetBird overlay client on this host";

    managementUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://netbird.example.com";
      description = "Self-hosted NetBird management URL.";
    };

    hostname = lib.mkOption {
      type = lib.types.str;
      description = "NetBird peer name (the identity this host enrolls under).";
      example = "host-b";
    };

    setupKeyFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to a file containing a NetBird setup key (reusable). Used once
        for headless enrollment; after that the stored config carries the
        peer.
      '';
      example = "/run/secrets/netbird-setup-key";
    };

    advertiseRoutes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "192.0.2.0/24" ]; # TEST-NET-1 placeholder LAN CIDR
      description = ''
        LAN CIDRs this peer makes reachable from the overlay (routing
        peer). The route object itself is created account-side via the
        NetBird API and bound to this peer; here we only enable the kernel
        forwarding it needs.
      '';
    };

    confineExternalRange = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "198.51.100.0/28"; # TEST-NET-2 placeholder overlay CIDR
      description = ''
        Overlay CIDR of UNTRUSTED external devices (a least-trust group).
        On the routing peer, traffic from these source IPs to the LAN is
        DROPPED except the hosts in `confineExternalAllow`. Closes the
        blanket `-i <overlay-if> -j ACCEPT` forward hole a routing peer
        otherwise leaves: route DISTRIBUTION only constrains an honest
        client — a compromised guest can add its own route to the LAN CIDR
        and reach the whole LAN otherwise. The rule sits in the raw
        PREROUTING chain, which runs before FORWARD in either iptables
        layer, so it can't be reordered under NetBird's own dynamic rules.
      '';
    };

    confineExternalAllow = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "192.0.2.125" "192.0.2.126" ];
      description = "LAN hosts the confined external range MAY still reach. Everything else on the LAN is dropped for that range.";
    };

    overlayInterface = lib.mkOption {
      type = lib.types.str;
      default = "wt0";
      description = "The NetBird tunnel interface name on this host (upstream default is wt0; a `hardened = true` client uses a different name).";
    };
  };

  config = lib.mkIf cfg.enable {
    services.netbird.enable = true;

    # A routing peer must forward between the overlay interface and the LAN bridge.
    boot.kernel.sysctl = lib.mkIf (cfg.advertiseRoutes != [ ]) {
      "net.ipv4.ip_forward" = lib.mkDefault 1;
      "net.ipv6.conf.all.forwarding" = lib.mkDefault 1;
    };

    # ── LAN → overlay egress SOURCE-NAT ──────────────────────────────────
    # advertiseRoutes gives the OVERLAY reach INTO the LAN (overlay peer →
    # LAN device). The REVERSE — a client-less LAN device reaching OUT to
    # an overlay peer by routing through this peer — needs one thing
    # NetBird does NOT add: a source-NAT, so the overlay sees the traffic
    # as THIS peer (which is a real, enrolled peer) and the reply routes
    # back. FORWARDING itself is already permitted — NetBird, as a routing
    # peer, blanket-accepts inbound-from-overlay in the FORWARD chain — so
    # no explicit forward rule is needed for reachability. That blanket
    # accept is also why untrusted externals need confineExternalRange
    # above (a source-scoped raw-PREROUTING DROP, layer-agnostic). Gated
    # on advertiseRoutes so only a routing peer carries it; idempotent -C
    # guard.
    networking.firewall.extraCommands = lib.mkIf (cfg.advertiseRoutes != [ ]) (
      lib.concatMapStringsSep "\n" (cidr: ''
        iptables -t nat -C POSTROUTING -s ${cidr} -o ${cfg.overlayInterface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${cidr} -o ${cfg.overlayInterface} -j MASQUERADE
      '') cfg.advertiseRoutes
      + lib.optionalString (cfg.confineExternalRange != null) ''
        # External-device LAN confinement (raw PREROUTING, pre-FORWARD in any layer):
        # source ${cfg.confineExternalRange} may reach ONLY confineExternalAllow on the
        # LAN; every other advertised-CIDR destination is DROPPED. Overlay→overlay
        # traffic falls through (policy layer governs it). Idempotent; cleaned in
        # stopCommands.
        iptables -t raw -N NIXNET-EXT-CONFINE 2>/dev/null || true
        iptables -t raw -F NIXNET-EXT-CONFINE
        ${lib.concatMapStringsSep "\n        " (h: "iptables -t raw -A NIXNET-EXT-CONFINE -d ${h}/32 -j RETURN") cfg.confineExternalAllow}
        ${lib.concatMapStringsSep "\n        " (cidr: "iptables -t raw -A NIXNET-EXT-CONFINE -d ${cidr} -j DROP") cfg.advertiseRoutes}
        iptables -t raw -C PREROUTING -i ${cfg.overlayInterface} -s ${cfg.confineExternalRange} -j NIXNET-EXT-CONFINE 2>/dev/null || iptables -t raw -I PREROUTING -i ${cfg.overlayInterface} -s ${cfg.confineExternalRange} -j NIXNET-EXT-CONFINE
      ''
    );
    networking.firewall.extraStopCommands = lib.mkIf (cfg.advertiseRoutes != [ ]) (
      lib.concatMapStringsSep "\n" (cidr: ''
        iptables -t nat -D POSTROUTING -s ${cidr} -o ${cfg.overlayInterface} -j MASQUERADE 2>/dev/null || true
      '') cfg.advertiseRoutes
      + lib.optionalString (cfg.confineExternalRange != null) ''
        iptables -t raw -D PREROUTING -i ${cfg.overlayInterface} -s ${cfg.confineExternalRange} -j NIXNET-EXT-CONFINE 2>/dev/null || true
        iptables -t raw -F NIXNET-EXT-CONFINE 2>/dev/null || true
        iptables -t raw -X NIXNET-EXT-CONFINE 2>/dev/null || true
      ''
    );

    # ── Headless enrollment ──────────────────────────────────────────────
    # One-shot: bring the client up with the setup key if not already
    # joined. Idempotent — skips when Management is already Connected.
    # Ordered after the netbird daemon + network so `netbird up` can reach
    # the management server. Note: `nixnet.netbird`'s own reprovisioning
    # (netbird-provider.nix) is a stricter, LOUDLY-failing alternative to
    # this same job for a host that also wants active drift detection —
    # this oneshot only runs at unit start and silently no-ops (`exit 0`)
    # when no setup key is present, so a host relying on it ALONE for
    # recovery gets no signal when enrollment never happened.
    systemd.services.nixnet-overlay-enroll = {
      description = "Enroll ${cfg.hostname} into NetBird (${cfg.managementUrl})";
      after = [ "netbird.service" "network-online.target" ];
      wants = [ "netbird.service" "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.netbird pkgs.coreutils ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        Restart = lib.mkDefault "on-failure";
        RestartSec = lib.mkDefault "10s";
      };
      script = ''
        set -euo pipefail
        # Wait for the daemon socket.
        for i in {1..30}; do
          if netbird status >/dev/null 2>&1; then break; fi
          sleep 1
        done
        if netbird status 2>/dev/null | grep -q "Management: Connected"; then
          echo "already enrolled and connected"
          exit 0
        fi
        if [ ! -r "${cfg.setupKeyFile}" ]; then
          echo "no setup key at ${cfg.setupKeyFile}; daemon is up — enroll once with:"
          echo "  netbird up --management-url ${cfg.managementUrl} --setup-key <key> --hostname ${cfg.hostname}"
          exit 0
        fi
        netbird up \
          --management-url "${cfg.managementUrl}" \
          --setup-key "$(cat ${cfg.setupKeyFile})" \
          --hostname "${cfg.hostname}"
      '';
    };
  };
}
