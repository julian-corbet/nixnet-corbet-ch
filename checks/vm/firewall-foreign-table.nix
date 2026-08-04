# checks/vm/firewall-foreign-table.nix — FW-2.
#
# `flush ruleset` on re-apply deletes every other table on the host: k3s,
# docker, podman and libvirt all write chains through iptables-nft, and the
# outage that follows reads as an application fault, not as a firewall change.
# The rule is therefore absolute -- nixnet replaces exactly one table, by name,
# and every other table is byte-identical afterwards.
#
# Three moments, because the risk is different at each: the first apply, a
# RE-apply (where the tempting `flush ruleset` lives), and REMOVAL (where a
# careless teardown is just as destructive as a careless apply, and where
# nobody looks because the change was "turning something off").
#
# The foreign table carries no counters on purpose. `nft list table` prints
# counter values, so a table with counters can never be compared byte-for-byte
# against itself, and the test would have to weaken to a substring check.

{ pkgs }:

{
  name = "firewall-foreign-table";
  behaviours = [ "FW-2" ];
  requiresModules = [ "firewall.nix" ];
  requiresOptions = [
    [ "nixnet" "firewall" "enable" ]
    [ "nixnet" "firewall" "table" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-firewall-foreign-table";

    nodes.machine = { lib, ... }: {
      imports = [ modules.core modules.firewall baseline ];
      virtualisation.vlans = [ 1 ];

      nixnet.interfaces.eth1.addressing = { v4 = "static"; v6 = "none"; };
      nixnet.firewall = {
        enable = true;
        management.interfaces = [ "eth1" ];
        autoRevert.enable = false;
      };

      # Stands in for docker/k3s/libvirt/the overlay client: someone else's
      # table, at someone else's hook, that nixnet never asked about.
      environment.etc."foreign.nft".text = ''
        table inet foreignexample {
          chain forward {
            type filter hook forward priority filter + 5; policy accept;
            ip saddr 203.0.113.0/24 drop
          }
          chain input {
            type filter hook input priority filter + 5; policy accept;
            tcp dport 9999 accept
          }
        }
      '';

      # mkForce, not a plain `false`: a specialisation inherits the parent
      # configuration, so this is a redefinition of an option the parent already
      # set to `true` and merges as a conflict rather than as an override.
      specialisation.off.configuration = {
        nixnet.firewall.enable = lib.mkForce false;
      };
    };

    testScript = ''
      machine.wait_for_unit("nixnet-firewall.service")
      machine.wait_for_unit("multi-user.target")

      machine.succeed("nft -f /etc/foreign.nft")
      before = machine.succeed("nft list table inet foreignexample")
      assert "203.0.113.0/24" in before, "the foreign table did not load; nothing below is measurable"

      # ── re-apply ───────────────────────────────────────────────────────
      machine.succeed("systemctl restart nixnet-firewall.service")
      machine.wait_for_unit("nixnet-firewall.service")
      machine.succeed("nft list table inet nixnet >/dev/null")

      after_reapply = machine.succeed("nft list table inet foreignexample")
      assert after_reapply == before, (
          "re-applying nixnet's ruleset modified a table it does not own:\n"
          f"--- before ---\n{before}\n--- after ---\n{after_reapply}"
      )

      # ── removal ────────────────────────────────────────────────────────
      # Turning the firewall OFF must delete nixnet's table and nothing else.
      machine.succeed("/run/current-system/specialisation/off/bin/switch-to-configuration test")
      machine.fail("nft list table inet nixnet")

      after_removal = machine.succeed("nft list table inet foreignexample")
      assert after_removal == before, (
          "removing nixnet's ruleset destroyed a table it does not own:\n"
          f"--- before ---\n{before}\n--- after ---\n{after_removal}"
      )
    '';
  };
}
