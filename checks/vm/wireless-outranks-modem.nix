# checks/vm/wireless-outranks-modem.nix — RADIO-2.
#
# What "Wi-Fi outranks the modem" IS, at the layer it is decidable: two default routes on one host,
# and which of them the kernel picks. So this test builds exactly that — two NetworkManager-managed
# uplinks, each ranked by nixnet — and reads the answer off `ip route`, not off a rendered file.
#
# ── THE CONTROL IS THE POINT ───────────────────────────────────────────────────────────────────
# A second, identical node runs WITHOUT nixnet.wireless. Without it this test would only prove that
# some numbers are the numbers we wrote down; with it, it proves the module changed the outcome —
# and it corrected this file's own first premise. Measured: NetworkManager does NOT leave two wired
# uplinks tied. It assigns 100 and 101, breaking the tie by device enumeration order, which means
# an undeclared host does have a preferred uplink — chosen by how the kernel found the hardware.
# That is the thing a declaration replaces.
#
# ── WHAT IS STOOD IN FOR, AND WHY THAT IS HONEST ───────────────────────────────────────────────
# Neither radio is real hardware here: both are ordinary NetworkManager-managed interfaces, one
# DECLARED as the Wi-Fi radio and one as the WWAN radio. That is deliberate, and it is not a
# simplification of the mechanism under test — the ranking nixnet writes is a per-DEVICE route
# metric derived from the radio's priority, which is device-type agnostic by construction. It has
# to be: a modem's own connection is ModemManager's to create, so the only way nixnet can rank one
# at all is a rule that applies to a connection it did not write. That is what this test exercises.
# Real association over a real radio is checks/vm/wireless-association.nix's job, and the per-KIND
# power switch — the one place the kind genuinely matters — is checks/vm/wireless-power-policy.nix.
{ pkgs }:

let
  # An uplink each: vlan 1 stands in for the Wi-Fi network, vlan 2 for the cellular one. The
  # router serves both, so both legs get a real DHCP lease with a real default route.
  keaSubnet = vlan: {
    id = vlan;
    subnet = "192.168.${toString vlan}.0/24";
    pools = [{ pool = "192.168.${toString vlan}.100 - 192.168.${toString vlan}.150"; }];
    option-data = [{ name = "routers"; data = "192.168.${toString vlan}.1"; }];
  };

  # NetworkManager owns both uplinks, so the test driver's own static addressing on them is
  # cleared: two configurators on one interface is a fight with no winner and no error message.
  # Same `mkForce` nixpkgs' own NetworkManager tests use.
  client = { lib, ... }: {
    virtualisation.vlans = [ 1 2 ];
    networking.interfaces = lib.mkForce { eth1 = { }; eth2 = { }; };
    networking.networkmanager = {
      enable = true;
      # eth0 is the test VM's own QEMU user-mode NIC, and NetworkManager will happily DHCP a THIRD
      # default route onto it at metric 100 -- which outranks both uplinks under test and makes
      # every routing assertion below about the wrong interface. Measured, not anticipated: the
      # first run of this test reported {'eth0': 100, 'eth1': 110, 'eth2': 150}.
      unmanaged = [ "interface-name:eth0" ];
    };
  };
in
{
  name = "wireless-outranks-modem";
  behaviours = [ "RADIO-2" ];
  requiresModules = [ "wireless.nix" ];
  requiresOptions = [
    [ "nixnet" "wireless" "enable" ]
    [ "nixnet" "wireless" "radios" "priority" ]
    [ "nixnet" "wireless" "metricBase" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-wireless-outranks-modem";

    nodes = {
      router = { lib, ... }: {
        imports = [ baseline ];
        virtualisation.vlans = [ 1 2 ];
        networking.interfaces = {
          eth1.ipv4.addresses = lib.mkForce [{ address = "192.168.1.1"; prefixLength = 24; }];
          eth2.ipv4.addresses = lib.mkForce [{ address = "192.168.2.1"; prefixLength = 24; }];
        };
        services.kea.dhcp4 = {
          enable = true;
          settings = {
            interfaces-config.interfaces = [ "eth1" "eth2" ];
            lease-database = { type = "memfile"; persist = false; };
            valid-lifetime = 600;
            subnet4 = [ (keaSubnet 1) (keaSubnet 2) ];
          };
        };
      };

      laptop = { ... }: {
        imports = [ modules.core modules.wireless baseline client ];

        nixnet.interfaces = {
          eth1.addressing = { v4 = "dhcp"; v6 = "none"; };
          eth2.addressing = { v4 = "dhcp"; v6 = "none"; };
        };

        nixnet.wireless = {
          enable = true;
          radios = {
            wifi0 = { interface = "eth1"; kind = "wifi"; priority = 10; };
            modem = { interface = "eth2"; kind = "wwan"; priority = 50; };
          };
          # Not this test's subject, and pinned so nothing gets powered down mid-measurement.
          powerPolicy = { onBattery = "all"; onAc = "all"; };
        };
      };

      # The same machine, minus the declaration.
      control = { ... }: {
        imports = [ baseline client ];
      };
    };

    testScript = ''
      import json

      start_all()
      router.wait_for_unit("kea-dhcp4-server.service")

      def defaults(machine):
          """Every default route the kernel holds, as {interface: metric}."""
          out = machine.succeed("ip -4 -j route show default")
          return {r["dev"]: r.get("metric", 0) for r in json.loads(out)}

      for machine in (laptop, control):
          machine.wait_for_unit("NetworkManager.service")
          machine.wait_until_succeeds(
              "ip -4 -j route show default | grep -q eth1 && "
              "ip -4 -j route show default | grep -q eth2",
              timeout=120,
          )

      # ── The declared host ────────────────────────────────────────────────────────────────────
      metrics = defaults(laptop)
      assert set(metrics) == {"eth1", "eth2"}, f"expected one default per uplink, got {metrics}"

      # metricBase (100) + the radio's own priority. Derived from the number the operator declared,
      # not from a rank among whatever else happens to be configured.
      assert metrics["eth1"] == 110, f"the Wi-Fi radio's route metric is {metrics['eth1']}, not 110"
      assert metrics["eth2"] == 150, f"the modem's route metric is {metrics['eth2']}, not 150"
      assert metrics["eth1"] < metrics["eth2"], (
          f"the modem outranks Wi-Fi: {metrics}"
      )
      assert len(set(metrics.values())) == 2, (
          f"two default routes share a metric, which is the tie TF-3 exists to prevent: {metrics}"
      )

      # And the consequence, from the kernel rather than from the metric: a new connection leaves
      # over the Wi-Fi radio.
      chosen = laptop.succeed("ip -4 -j route get 198.51.100.1")
      assert json.loads(chosen)[0]["dev"] == "eth1", (
          f"the kernel routes new traffic over the wrong uplink:\n{chosen}"
      )

      # ── The control: what happens when nobody declares the ranking ───────────────────────────
      # MEASURED, and not what this test first assumed. NetworkManager does not leave two wired
      # uplinks at one metric: it hands out 100 and 101 — its own default, plus a per-device
      # increment to break the tie itself. So the failure here is subtler than two equal-cost
      # defaults, and worse in one respect: the host DOES prefer one uplink, by device enumeration
      # order, which is a fact about how the kernel found the hardware and not about anything an
      # operator said. Re-enumerate the devices — a different boot, a replaced adapter, a modem
      # that appears late — and the preference moves, silently.
      #
      # So what the control proves is that the numbers on the declared node came from the
      # declaration: they are not NetworkManager's, and the separation NetworkManager produces on
      # its own is a tie-break (1) rather than a ranking (40).
      control_metrics = defaults(control)
      assert control_metrics != metrics, (
          "the declared node has exactly the metrics NetworkManager assigns without this module, "
          f"so nothing above measures the declaration: {control_metrics}"
      )
      assert set(control_metrics.values()) != {110, 150}, (
          f"the control node has nixnet's metrics without nixnet: {control_metrics}"
      )
      control_spread = max(control_metrics.values()) - min(control_metrics.values())
      declared_spread = metrics["eth2"] - metrics["eth1"]
      assert control_spread < declared_spread, (
          f"NetworkManager's own separation ({control_spread}) is no longer distinguishable from a "
          f"declared ranking ({declared_spread}): {control_metrics}"
      )
    '';
  };
}
