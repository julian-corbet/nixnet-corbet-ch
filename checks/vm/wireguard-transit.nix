# checks/vm/wireguard-transit.nix — WG-1, WG-2.
#
# Three real kernels prove the intended shape: one public listener on the hub,
# two outbound peers, and IPv4 plus IPv6 packets forwarded only back into the
# authenticated WireGuard interface. The keys are disposable test fixtures.
{ pkgs }:

let
  hub = {
    private = "oKtYQEG//QNyp/Q5iWxEaekzUj3SokQd37Zx9TDN4WI=";
    public = "fy4IU+ftDoRrl3qBdP/oCBesnJvikzzE2Pl63ezPFBg=";
  };
  left = {
    private = "yAOEtupYmQKUpxuQw2uuPVYN4AHbuiLFYbnoRGD/wl8=";
    public = "EAeLINHF0iu3LakRgQwNsBbwI3JPlorLpVqff8LDRjg=";
  };
  right = {
    private = "cG5a9C166gLQrPqDhBR4tji2EKxeX6mzHSw8PvNl/FY=";
    public = "tsV58S7om/cjbEz09+F0wJwq0Msyaq8CmE9iMunUlQY=";
  };

  keyUnit = key: {
    systemd.services.test-wireguard-key = {
      description = "Write a disposable WireGuard test key";
      wantedBy = [ "multi-user.target" ];
      before = [ "nixnet-wireguard-wg-test.service" ];
      serviceConfig.Type = "oneshot";
      script = ''
        install -d -m 0700 /run/test-wireguard
        printf '%s\n' '${key.private}' > /run/test-wireguard/private-key
        chmod 0600 /run/test-wireguard/private-key
      '';
    };
  };
in
{
  name = "wireguard-transit";
  behaviours = [ "WG-1" "WG-2" ];
  requiresModules = [ "wireguard.nix" ];
  requiresOptions = [
    [ "nixnet" "wireguard" "enable" ]
    [ "nixnet" "wireguard" "privateKeyFile" ]
    [ "nixnet" "wireguard" "forwarding" "enable" ]
    [ "nixnet" "firewall" "forward" "trustedInterfacePairs" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-wireguard-transit";

    nodes = {
      hub = { ... }: {
        imports = [ modules.wireguard baseline (keyUnit hub) ];
        virtualisation.vlans = [ 1 ];
        nixnet.interfaces.eth1.addressing = { v4 = "static"; v6 = "none"; };
        nixnet.firewall = {
          enable = true;
          management.interfaces = [ "eth1" ];
          autoRevert.enable = false;
        };
        nixnet.wireguard = {
          enable = true;
          interface = "wg-test";
          addresses = [ "10.254.42.1/24" "fd42:254:42::1/64" ];
          privateKeyFile = "/run/test-wireguard/private-key";
          secretUnits = [ "test-wireguard-key.service" ];
          listenPort = 51821;
          openFirewall = true;
          forwarding.enable = true;
          peers = {
            left = {
              publicKey = left.public;
              allowedIPs = [ "10.254.42.6/32" "fd42:254:42::6/128" ];
            };
            right = {
              publicKey = right.public;
              allowedIPs = [ "10.254.42.48/32" "fd42:254:42::48/128" ];
            };
          };
        };
      };

      left = { ... }: {
        imports = [ modules.wireguard baseline (keyUnit left) ];
        virtualisation.vlans = [ 1 ];
        nixnet.wireguard = {
          enable = true;
          interface = "wg-test";
          addresses = [ "10.254.42.6/24" "fd42:254:42::6/64" ];
          privateKeyFile = "/run/test-wireguard/private-key";
          secretUnits = [ "test-wireguard-key.service" ];
          peers.hub = {
            publicKey = hub.public;
            endpoint = "hub:51821";
            persistentKeepalive = 5;
            allowedIPs = [ "10.254.42.0/24" "fd42:254:42::/64" ];
          };
        };
      };

      right = { ... }: {
        imports = [ modules.wireguard baseline (keyUnit right) ];
        virtualisation.vlans = [ 1 ];
        nixnet.wireguard = {
          enable = true;
          interface = "wg-test";
          addresses = [ "10.254.42.48/24" "fd42:254:42::48/64" ];
          privateKeyFile = "/run/test-wireguard/private-key";
          secretUnits = [ "test-wireguard-key.service" ];
          peers.hub = {
            publicKey = hub.public;
            endpoint = "hub:51821";
            persistentKeepalive = 5;
            allowedIPs = [ "10.254.42.0/24" "fd42:254:42::/64" ];
          };
        };
      };
    };

    testScript = ''
      for node in (hub, left, right):
          node.wait_for_unit("nixnet-wireguard-wg-test.service")
          node.succeed("wg show wg-test >/dev/null")

      # The public listener is the hub's one deliberate firewall aperture.
      firewall = hub.succeed("nft list table inet nixnet")
      assert "udp dport 51821 accept" in firewall, firewall
      assert 'iifname "wg-test" oifname "wg-test" accept' in firewall, firewall

      # Both paths cross the hub, so each successful echo proves forward and
      # reply forwarding through the tunnel rather than a direct peer route.
      left.succeed("ping -c 1 -W 5 10.254.42.48")
      left.succeed("ping -6 -c 1 -W 5 fd42:254:42::48")
      right.succeed("ping -c 1 -W 5 10.254.42.6")
      right.succeed("ping -6 -c 1 -W 5 fd42:254:42::6")

      for node in (hub, left, right):
          handshake = node.succeed("wg show wg-test latest-handshakes")
          assert any(int(line.split()[1]) > 0 for line in handshake.splitlines()), handshake
    '';
  };
}
