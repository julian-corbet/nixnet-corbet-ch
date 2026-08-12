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
  requiresModules = [ "firewall.nix" "overlay.nix" ];
  requiresOptions = [
    [ "nixnet" "firewall" "enable" ]
    [ "nixnet" "firewall" "table" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }:
    let
      # Same boundary as the production failure: after the systemd initrd has
      # loaded its declared modules, forbid every later module load.  This node
      # imports overlay.nix without firewall.nix so it proves the overlay owns
      # its own prerequisites instead of accidentally borrowing them.
      lockModuleLoading = {
        boot.initrd.systemd.enable = true;
        systemd.services.nixnet-test-lock-module-loading = {
          description = "nixnet test: forbid module loading after the initrd";
          wantedBy = [ "sysinit.target" ];
          before = [ "sysinit.target" "nixnet-overlay-firewall.service" ];
          after = [ "systemd-modules-load.service" ];
          unitConfig.DefaultDependencies = false;
          serviceConfig.Type = "oneshot";
          script = ''
            echo 1 > /proc/sys/kernel/modules_disabled
          '';
        };
      };
    in
    {
      name = "nixnet-firewall-foreign-table";

      nodes = {
        machine = { lib, ... }: {
          imports = [ modules.core modules.firewall modules.overlay baseline ];
          virtualisation.vlans = [ 1 ];

          nixnet.interfaces.eth1.addressing = { v4 = "static"; v6 = "none"; };
          nixnet.firewall = {
            enable = true;
            management.interfaces = [ "eth1" ];
            autoRevert.enable = false;
          };

          nixnet.overlay = {
            enable = true;
            managementUrl = "https://mesh.example.com";
            hostname = "router";
            setupKeyFile = "/run/secrets/nixnet-overlay-key";
            advertiseRoutes = [ "192.0.2.0/24" ];
          };

          # This test exercises the packet-path table, not NetBird enrollment.
          # Do not let an intentionally absent setup key or a client daemon add
          # an unrelated failure to the node.
          systemd.services.netbird.wantedBy = lib.mkForce [ ];
          systemd.services.nixnet-overlay-enroll.wantedBy = lib.mkForce [ ];

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
          # configuration, so this redefinition would otherwise be a conflict.
          specialisation.off.configuration = {
            nixnet.firewall.enable = lib.mkForce false;
          };

          specialisation.overlayoff.configuration = {
            nixnet.overlay.enable = lib.mkForce false;
          };

          # A string is intentionally used for CIDRs at the public option
          # surface, so nft is the final parser.  Switching to this generation
          # exercises a failed replacement of the active oneshot.
          specialisation.overlaybroken.configuration = {
            nixnet.overlay.advertiseRoutes = lib.mkForce [ "not-a-prefix" ];
          };
        };

        overlaylocked = { lib, ... }: {
          imports = [ modules.overlay baseline lockModuleLoading ];
          virtualisation.vlans = [ 1 ];
          nixnet.overlay = {
            enable = true;
            managementUrl = "https://mesh.example.com";
            hostname = "module-locked-router";
            setupKeyFile = "/run/secrets/nixnet-overlay-key";
            advertiseRoutes = [ "192.0.2.0/24" ];
          };
          systemd.services.netbird.wantedBy = lib.mkForce [ ];
          systemd.services.nixnet-overlay-enroll.wantedBy = lib.mkForce [ ];
        };
      };

      testScript = ''
        machine.wait_for_unit("nixnet-firewall.service")
        machine.wait_for_unit("nixnet-overlay-firewall.service")
        machine.wait_for_unit("multi-user.target")

        # A failed specialisation switch still advances /run/current-system to
        # the failed specialisation, whose closure intentionally does not nest
        # its siblings.  Resolve every test target from the parent up front.
        broken_system = machine.succeed(
            "readlink -f /run/current-system/specialisation/overlaybroken"
        ).strip()
        overlayoff_system = machine.succeed(
            "readlink -f /run/current-system/specialisation/overlayoff"
        ).strip()
        off_system = machine.succeed(
            "readlink -f /run/current-system/specialisation/off"
        ).strip()

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

        # A changed overlay unit must preserve the previous table until the new
        # atomic nft transaction succeeds.  Deleting it from ExecStop creates a
        # fail-open window and turns a failed apply into a permanent loss of
        # confinement/NAT.
        overlay_before = machine.succeed("nft list table inet nixnet-overlay")
        machine.fail(
            f"{broken_system}/bin/switch-to-configuration test"
        )
        machine.succeed("systemctl is-failed nixnet-overlay-firewall.service")
        overlay_after = machine.succeed("nft list table inet nixnet-overlay")
        assert overlay_after == overlay_before, (
            "a failed overlay re-apply removed or changed the previous packet-path table:\n"
            f"--- before ---\n{overlay_before}\n--- after ---\n{overlay_after}"
        )

        # Disabling the overlay is an explicit desired state, not the side
        # effect of stopping an old unit.  Its teardown generation removes only
        # the table it owns.
        machine.succeed(f"{overlayoff_system}/bin/switch-to-configuration test")
        machine.fail("nft list table inet nixnet-overlay")
        assert machine.succeed("nft list table inet foreignexample") == before

        # ── removal ────────────────────────────────────────────────────────
        # Turning the firewall OFF must delete nixnet's table and nothing else.
        machine.succeed(f"{off_system}/bin/switch-to-configuration test")
        machine.fail("nft list table inet nixnet")

        after_removal = machine.succeed("nft list table inet foreignexample")
        assert after_removal == before, (
            "removing nixnet's ruleset destroyed a table it does not own:\n"
            f"--- before ---\n{before}\n--- after ---\n{after_removal}"
        )

        # Finally prove overlay.nix itself owns every module it needs at the
        # systemd-initrd boundary; firewall.nix is intentionally absent here.
        overlaylocked.wait_for_unit("multi-user.target")
        overlaylocked.succeed("test $(cat /proc/sys/kernel/modules_disabled) -eq 1")
        overlaylocked.succeed("systemctl is-active --quiet nixnet-overlay-firewall.service")
        overlaylocked.succeed("nft list table inet nixnet-overlay")
        for module in (
            "af_packet", "nfnetlink", "nf_conntrack", "nf_tables", "nf_nat",
            "nft_chain_nat", "nft_masq", "tun"
        ):
            overlaylocked.succeed(f"test -d /sys/module/{module}")
      '';
    };
}
