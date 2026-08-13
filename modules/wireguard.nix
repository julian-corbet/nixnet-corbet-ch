# nixnet.wireguard -- a small, authenticated dual-stack private transit.
#
# The module deliberately routes private IPv4 and IPv6 over WireGuard instead
# of translating either address family. A WireGuard peer is the security
# boundary; only an explicitly declared listener opens a public UDP port.
{ config, lib, options, pkgs, ... }:

let
  cfg = config.nixnet.wireguard;
  tooling = import ../lib/tooling.nix { inherit lib; };
  backend = tooling.backendOf options;
  isNixos = backend == "nixos";
  q = lib.escapeShellArg;
  serviceName = "nixnet-wireguard-${cfg.interface}";
  runtimeDir = "/run/nixnet-wireguard";
  configPath = "${runtimeDir}/${cfg.interface}.conf";
  secretFiles = [ cfg.privateKeyFile ]
    ++ lib.filter (path: path != null) (map (peer: peer.presharedKeyFile) (lib.attrValues cfg.peers));

  peerText = peer: ''
    [Peer]
    PublicKey = ${peer.publicKey}
    ${lib.optionalString (peer.presharedKeyFile != null) "PresharedKey = $(cat ${q peer.presharedKeyFile})\n"}AllowedIPs = ${lib.concatStringsSep ", " peer.allowedIPs}
    ${lib.optionalString (peer.endpoint != null) "Endpoint = ${peer.endpoint}\n"}${lib.optionalString (peer.persistentKeepalive != null) "PersistentKeepalive = ${toString peer.persistentKeepalive}\n"}
  '';

  setup = pkgs.writeShellApplication {
    name = serviceName;
    runtimeInputs = [ pkgs.coreutils pkgs.iproute2 pkgs.wireguard-tools ];
    text = ''
      set -euo pipefail
      umask 077

      test -s ${q cfg.privateKeyFile}
      ${lib.concatMapStringsSep "\n" (path: "test -s ${q path}")
        (lib.filter (path: path != cfg.privateKeyFile) secretFiles)}
      install -d -m 0700 ${q runtimeDir}
      config=${q configPath}

      cleanup_partial() {
        if ip link show dev ${q cfg.interface} >/dev/null 2>&1; then
          wg-quick down "$config" >/dev/null 2>&1 \
            || ip link delete dev ${q cfg.interface} >/dev/null 2>&1 \
            || true
        fi
        rm -f "$config"
      }
      trap cleanup_partial ERR

      cat > "$config" <<EOF
      [Interface]
      PrivateKey = $(cat ${q cfg.privateKeyFile})
      Address = ${lib.concatStringsSep ", " cfg.addresses}
      ${lib.optionalString (cfg.listenPort != null) "ListenPort = ${toString cfg.listenPort}\n"}${lib.optionalString (cfg.mtu != null) "MTU = ${toString cfg.mtu}\n"}
      ${lib.concatMapStringsSep "\n" peerText (lib.attrValues cfg.peers)}
      EOF

      # Parse the complete generated file before making the first netlink change. `up` can still
      # fail on live-state conflicts, so the ERR trap above removes any partial interface too.
      wg-quick strip "$config" >/dev/null
      wg-quick up "$config"
      trap - ERR
    '';
  };

  teardown = pkgs.writeShellApplication {
    name = "${serviceName}-teardown";
    runtimeInputs = [ pkgs.coreutils pkgs.iproute2 pkgs.wireguard-tools ];
    text = ''
      config=${q configPath}
      if test -e "$config"; then
        wg-quick down "$config"
        rm -f "$config"
      fi
    '';
  };

  peerType = lib.types.submodule {
    options = {
      publicKey = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9+/]{43}=";
        description = "WireGuard public key for this peer.";
      };
      presharedKeyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Optional runtime file containing the peer's WireGuard preshared key.";
      };
      endpoint = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "[2001:db8::1]:51821";
        description = "Public WireGuard endpoint. Null accepts an endpoint learned from this peer.";
      };
      persistentKeepalive = lib.mkOption {
        type = lib.types.nullOr (lib.types.ints.between 1 65535);
        default = null;
        description = "Optional WireGuard keepalive interval in seconds for a peer behind NAT.";
      };
      allowedIPs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Private prefixes this peer may source and receive through this tunnel.";
      };
    };
  };
in
{
  imports = [ ./core.nix ];

  options.nixnet.wireguard = {
    enable = lib.mkEnableOption "an authenticated WireGuard private transit";

    interface = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9_=+.-]{1,15}";
      default = "wg-nixnet";
      description = "Name of the WireGuard interface owned by NixNet.";
    };

    addresses = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "10.254.42.48/24" "fd42:254:42::48/64" ];
      description = "Private IPv4 and IPv6 addresses assigned to this peer.";
    };

    privateKeyFile = lib.mkOption {
      type = lib.types.str;
      description = "Runtime-only file containing this peer's WireGuard private key.";
    };

    secretUnits = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Units that must successfully provision privateKeyFile and any peer preshared keys before this tunnel starts.";
    };

    listenPort = lib.mkOption {
      type = lib.types.nullOr lib.types.port;
      default = null;
      description = "UDP port to listen on. Null leaves this peer outbound-only.";
    };

    mtu = lib.mkOption {
      type = lib.types.nullOr (lib.types.ints.between 576 65535);
      default = null;
      description = "Optional WireGuard interface MTU. Null delegates MTU selection to wg-quick.";
    };

    peers = lib.mkOption {
      type = lib.types.attrsOf peerType;
      default = { };
      description = "Named WireGuard peers. Every peer must declare non-empty AllowedIPs.";
    };

    openFirewall = lib.mkEnableOption "the configured listenPort in nixnet.firewall";

    forwarding.enable = lib.mkEnableOption ''
      forwarding only between this tunnel's authenticated peers. NixOS-only:
      it enables IP forwarding and adds the exact interface pair to NixNet's
      default-drop forward chain.
    '';
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.addresses != [ ];
          message = "nixnet.wireguard: enable requires at least one private interface address.";
        }
        {
          assertion = cfg.peers != { };
          message = "nixnet.wireguard: enable requires at least one peer.";
        }
        {
          assertion = lib.all (peer: peer.allowedIPs != [ ]) (lib.attrValues cfg.peers);
          message = "nixnet.wireguard: every peer requires at least one AllowedIPs prefix.";
        }
        {
          assertion = !cfg.openFirewall || cfg.listenPort != null;
          message = "nixnet.wireguard: openFirewall requires listenPort.";
        }
        {
          assertion = !cfg.openFirewall || config.nixnet.firewall.enable;
          message = "nixnet.wireguard: openFirewall requires nixnet.firewall.enable.";
        }
        {
          assertion = !cfg.forwarding.enable || isNixos;
          message = "nixnet.wireguard: forwarding is NixOS-only; system-manager peers are clients, not transit gateways.";
        }
      ];

      nixnet.interfaces.${cfg.interface}.addressing = {
        v4 = "unmanaged";
        v6 = "unmanaged";
      };

      environment.systemPackages = [ pkgs.wireguard-tools ];

      systemd.services.${serviceName} = {
        description = "nixnet: WireGuard private transit ${cfg.interface}";
        wantedBy = [ "multi-user.target" ];
        # A failed secret producer must not cancel this start permanently.
        # The setup script validates every secret itself and retries, so a
        # late producer recovers without an operator re-starting the unit.
        wants = [ "network-online.target" ] ++ cfg.secretUnits;
        after = [ "network-online.target" ] ++ cfg.secretUnits;
        unitConfig = {
          RequiresMountsFor = secretFiles;
          StartLimitIntervalSec = 300;
          StartLimitBurst = 5;
        };
        path = [ pkgs.coreutils pkgs.iproute2 pkgs.wireguard-tools ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          RuntimeDirectory = "nixnet-wireguard";
          RuntimeDirectoryMode = "0700";
          UMask = "0077";
          CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
          AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
          ExecStart = "${setup}/bin/${serviceName}";
          ExecStop = "${teardown}/bin/${serviceName}-teardown";
          Restart = "on-failure";
          RestartSec = "30s";
          TimeoutStartSec = "2min";
        };
      };
    }

    (lib.mkIf cfg.openFirewall {
      nixnet.firewall.allow = [ {
        protocol = "udp";
        ports = [ cfg.listenPort ];
        comment = "nixnet WireGuard private transit endpoint";
      } ];
    })

    (lib.mkIf cfg.forwarding.enable {
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv6.conf.all.forwarding" = 1;
      };
      nixnet.firewall.forward = {
        enable = true;
        trustedInterfacePairs = [ {
          ingress = cfg.interface;
          egress = cfg.interface;
        } ];
      };
    })
  ]);
}
