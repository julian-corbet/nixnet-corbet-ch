# checks/vm/wireless-power-policy.nix — RADIO-3.
#
# Three states, all read back from NetworkManager rather than from the script's own log:
#
#   1. on battery, Wi-Fi associated  -> the modem's radio is off, the Wi-Fi radio is on
#   2. on mains                      -> every declared radio is on again
#   3. nothing associated at all     -> every radio is on, whatever the policy says
#
# Each direction rules out a different broken implementation, which is why all three are here: a
# script that only ever powers things DOWN passes (1) and fails (2); one that only ever powers
# things UP passes (2) and fails (1); one that powers down "everything but the winner" without
# noticing there is no winner passes both and fails (3) — by taking the machine off the network,
# which is the outcome this entry exists to forbid.
#
# ── THE STATE IS PASSED IN, NOT SIMULATED ──────────────────────────────────────────────────────
# `nixnet-radio-power ac|battery` is the same entry point the boot unit, the NetworkManager
# dispatcher and the udev rule use; they call it with no argument and it reads
# /sys/class/power_supply itself. A VM has no power supply to fake, so the test supplies the state
# the way an operator would. What it does NOT fake is anything downstream: the winner is computed
# from real NetworkManager device state, and the switch is a real rfkill through NetworkManager.
#
# The radios are stood in by ordinary NetworkManager-managed interfaces — see
# checks/vm/wireless-outranks-modem.nix's header for why that is honest. The mechanism this test
# exercises is per-KIND (`nmcli radio wifi|wwan`), which is a NetworkManager property, not a
# property of any device: it is settable, readable and rfkill-backed with no radio hardware at all.
{ pkgs }:

{
  name = "wireless-power-policy";
  behaviours = [ "RADIO-3" ];
  requiresModules = [ "wireless.nix" ];
  requiresOptions = [
    [ "nixnet" "wireless" "enable" ]
    [ "nixnet" "wireless" "powerPolicy" "onBattery" ]
    [ "nixnet" "wireless" "powerPolicy" "onAc" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-wireless-power-policy";

    nodes.machine = { lib, ... }: {
      imports = [ modules.core modules.wireless baseline ];

      virtualisation.vlans = [ 1 2 ];
      networking.interfaces = lib.mkForce { eth1 = { }; eth2 = { }; };

      networking.networkmanager = {
        enable = true;
        settings.main.no-auto-default = "*";
        # Statically addressed on purpose: this test needs both devices to reach `connected` and
        # STAY there, and a DHCP lease is a second thing that can fail in a test about neither
        # addressing nor DHCP. Nothing here is nixnet's -- these are the connections a modem's own
        # provisioner or an operator would already have, which is exactly the position nixnet
        # ranks and powers from.
        ensureProfiles.profiles = {
          uplink-a = {
            connection = { id = "uplink-a"; type = "ethernet"; interface-name = "eth1"; autoconnect = true; };
            ipv4 = { method = "manual"; address1 = "10.99.1.2/24"; };
            ipv6.method = "ignore";
          };
          uplink-b = {
            connection = { id = "uplink-b"; type = "ethernet"; interface-name = "eth2"; autoconnect = true; };
            ipv4 = { method = "manual"; address1 = "10.99.2.2/24"; };
            ipv6.method = "ignore";
          };
        };
      };

      nixnet.interfaces = {
        eth1.addressing = { v4 = "none"; v6 = "none"; };
        eth2.addressing = { v4 = "none"; v6 = "none"; };
      };

      nixnet.wireless = {
        enable = true;
        radios = {
          wifi0 = { interface = "eth1"; kind = "wifi"; priority = 10; };
          modem = { interface = "eth2"; kind = "wwan"; priority = 50; };
        };
        powerPolicy = {
          onBattery = "preferredOnly";
          onAc = "all";
        };
      };
    };

    testScript = ''
      machine.wait_for_unit("NetworkManager.service")

      def radio(kind):
          return machine.succeed(f"nmcli radio {kind}").strip()

      def connected(device):
          return machine.succeed(
              "nmcli -t -f DEVICE,STATE device"
          ).find(f"{device}:connected") >= 0

      # The boot unit ran, and exited zero: the policy is applied without anyone asking, which is
      # the only way it gets applied on a headless host.
      status = machine.succeed(
          "systemctl show -p ExecMainStatus --value nixnet-radio-power.service"
      ).strip()
      assert status == "0", f"the boot-time power policy unit exited {status}"

      # Both radios up to begin with, and the winner really is associated -- otherwise case 1
      # below would be measuring case 3.
      machine.succeed("nmcli radio wifi on")
      machine.succeed("nmcli radio wwan on")
      machine.wait_until_succeeds("nmcli -t -f DEVICE,STATE device | grep -qx 'eth1:connected'", timeout=120)
      machine.wait_until_succeeds("nmcli -t -f DEVICE,STATE device | grep -qx 'eth2:connected'", timeout=120)

      # ── 1. on battery, with a winner ─────────────────────────────────────────────────────────
      machine.succeed("nixnet-radio-power battery")
      assert radio("wifi") == "enabled", "the winning radio was powered down on battery"
      assert radio("wwan") == "disabled", (
          "the losing radio stayed powered on battery, which is the power this policy exists to "
          "stop spending"
      )
      assert connected("eth1"), "powering the loser down took the winner's connection with it"

      # ── 2. on mains ──────────────────────────────────────────────────────────────────────────
      machine.succeed("nixnet-radio-power ac")
      assert radio("wifi") == "enabled", "a radio is down on mains under policy 'all'"
      assert radio("wwan") == "enabled", "a radio is down on mains under policy 'all'"

      # ── 3. nothing associated ────────────────────────────────────────────────────────────────
      # The state a policy must not act on. With no winner there is nothing to prefer, and
      # "power down everything except the winner" would power down everything.
      machine.succeed("nmcli device disconnect eth1")
      machine.succeed("nmcli device disconnect eth2")
      machine.wait_until_fails("nmcli -t -f DEVICE,STATE device | grep -qx 'eth1:connected'")
      machine.wait_until_fails("nmcli -t -f DEVICE,STATE device | grep -qx 'eth2:connected'")

      machine.succeed("nixnet-radio-power battery")
      assert radio("wifi") == "enabled", (
          "every radio was powered down on a host with nothing associated -- there is now no way "
          "back onto a network, which is not a power saving"
      )
      assert radio("wwan") == "enabled", (
          "every radio was powered down on a host with nothing associated -- there is now no way "
          "back onto a network, which is not a power saving"
      )
    '';
  };
}
