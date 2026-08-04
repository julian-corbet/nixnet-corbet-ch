# checks/vm/firewall-reconcile.nix — FW-4.
#
# The premise this test asserts BEFORE it asserts anything else: the apply unit
# is a `Type=oneshot` with `RemainAfterExit`, so `systemctl is-active` answers
# "did this run once, successfully" and NOT "is the firewall in force". Delete
# the table underneath it and the unit stays green. That is not a hypothetical --
# it was measured on a public production host, which sat with no packet filter at
# all while everything systemd could be asked reported success.
#
# So the reconcile loop has to detect three DIFFERENT shapes of the same outcome,
# and the test exercises each, because a check that only looks for the table
# misses two of them:
#
#   1. the table is deleted      -- `nft flush ruleset`, a CNI reset, a hand-run command
#   2. the table is emptied      -- `nft flush table`, table still there, no rules in it
#   3. the table is FOREIGN      -- present, populated, but from another generation
#
# And one shape it must NOT repair: the auto-revert dead-man switch fired for this
# exact ruleset. Repairing there reloads the rules that just locked an operator
# out, once per interval, forever. That case has to fail loudly instead.

{ pkgs }:

{
  name = "firewall-reconcile";
  behaviours = [ "FW-4" ];
  requiresModules = [ "firewall.nix" ];
  requiresOptions = [
    [ "nixnet" "firewall" "enable" ]
    [ "nixnet" "firewall" "reconcile" "enable" ]
    [ "nixnet" "firewall" "reconcile" "intervalSec" ]
    [ "nixnet" "firewall" "metricsFile" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-firewall-reconcile";

    nodes.machine = { ... }: {
      imports = [ modules.core modules.firewall baseline ];
      virtualisation.vlans = [ 1 ];

      nixnet.interfaces.eth1.addressing = { v4 = "static"; v6 = "none"; };
      nixnet.firewall = {
        enable = true;
        management.interfaces = [ "eth1" ];
        # ON, because this test needs `applied-hash` to exist: it is the same value
        # revertScript writes into `reverted-hash`, and the stand-down case below
        # simulates a fired revert by copying it rather than by inventing a hash.
        autoRevert.enable = true;
        reconcile = {
          enable = true;
          # Long, deliberately. Every repair below is triggered by starting the unit
          # by hand, so the test measures the LOGIC rather than racing a timer. That
          # the timer exists and is armed is asserted separately.
          intervalSec = 3600;
        };
        allow = [
          {
            protocol = "tcp";
            ports = [ 8080 ];
            comment = "a rule to look for after a repair";
          }
        ];
      };
    };

    testScript = ''
      machine.wait_for_unit("nixnet-firewall.service")
      machine.wait_for_unit("multi-user.target")

      state = "/var/lib/nixnet-firewall"

      def enforced():
          out = machine.succeed(f"grep '^nixnet_firewall_enforced ' {state}/metrics.prom")
          return out.split()[1].strip()

      def repairs():
          out = machine.succeed(f"grep '^nixnet_firewall_repairs_total ' {state}/metrics.prom")
          return int(out.split()[1].strip())

      # The timer must be armed without anyone having started it -- unlike the revert
      # timer, which is armed only by a real ruleset change.
      machine.succeed("systemctl is-active nixnet-firewall-reconcile.timer")

      machine.succeed("nft list table inet nixnet >/dev/null")
      assert enforced() == "1", "a freshly applied firewall does not report itself enforced"
      assert repairs() == 0, "nothing has been repaired yet"

      # ── 1. the table is deleted ─────────────────────────────────────────
      machine.succeed("nft delete table inet nixnet")
      machine.fail("nft list table inet nixnet")

      # THE premise. If this assertion ever fails, the reconcile loop is redundant
      # and this whole test can go -- but it does not fail, and that is the point.
      machine.succeed("systemctl is-active nixnet-firewall.service")
      machine.succeed("systemctl is-failed nixnet-firewall.service || true")
      status = machine.succeed("systemctl show -p ActiveState --value nixnet-firewall.service").strip()
      assert status == "active", (
          f"expected the apply unit to still report active over a deleted table, got {status!r}"
      )

      machine.succeed("systemctl start nixnet-firewall-reconcile.service")
      machine.succeed("nft list table inet nixnet >/dev/null")
      out = machine.succeed("nft list table inet nixnet")
      assert "8080" in out, f"the repaired table is missing the host's own rules:\n{out}"
      assert repairs() == 1, f"the repair was not counted: {repairs()}"
      assert enforced() == "1", "repaired, but not reporting itself enforced"

      # ── 2. the table is emptied, not deleted ────────────────────────────
      # `nft flush table` leaves the table and takes the chains. A presence check
      # passes here and the host has no rules at all.
      machine.succeed("nft flush table inet nixnet")
      machine.succeed("nft list table inet nixnet >/dev/null")
      chains = machine.succeed("nft list table inet nixnet")
      assert "8080" not in chains, "flush did not empty the table; case 2 is not being tested"

      machine.succeed("systemctl start nixnet-firewall-reconcile.service")
      out = machine.succeed("nft list table inet nixnet")
      assert "8080" in out, f"an emptied table was not repaired:\n{out}"
      assert repairs() == 2, f"the second repair was not counted: {repairs()}"

      # ── 3. the table is present, populated, and FOREIGN ─────────────────
      # What a rollback to a generation with different rules leaves behind: a
      # perfectly good nixnet table that is not the one this generation renders.
      machine.succeed(
          "nft -f - <<'EOF'\n"
          "table inet nixnet\n"
          "delete table inet nixnet\n"
          "table inet nixnet {\n"
          "  chain input {\n"
          "    type filter hook input priority filter; policy drop;\n"
          "    ct state established,related accept\n"
          "    tcp dport 22 accept\n"
          "  }\n"
          "}\n"
          "EOF"
      )
      foreign = machine.succeed("nft list table inet nixnet")
      assert "8080" not in foreign, "the foreign ruleset was not loaded; case 3 is not being tested"

      machine.succeed("systemctl start nixnet-firewall-reconcile.service")
      out = machine.succeed("nft list table inet nixnet")
      assert "8080" in out, f"a foreign generation was not replaced:\n{out}"
      assert repairs() == 3, f"the third repair was not counted: {repairs()}"

      # ── 4. the one case it must NOT repair ──────────────────────────────
      # The dead-man switch fired for THIS ruleset. `reverted-hash` carries exactly
      # what revertScript writes: the hash already recorded in `applied-hash`.
      machine.succeed(f"cp {state}/applied-hash {state}/reverted-hash")
      machine.succeed("nft delete table inet nixnet")

      machine.fail("systemctl start nixnet-firewall-reconcile.service")
      machine.fail("nft list table inet nixnet")
      assert repairs() == 3, "reconcile repaired a ruleset the dead-man switch deliberately replaced"
      assert enforced() == "0", "a host running rules nixnet did not choose still reports enforced=1"

      # NOT `log` -- that name is the driver's own logger object in this scope.
      journal = machine.succeed("journalctl -u nixnet-firewall-reconcile.service --no-pager")
      assert "NOT repairing" in journal, f"the refusal was not stated in the journal:\n{journal}"

      # ── and the way back out ────────────────────────────────────────────
      # Confirming after the window closed is a real operator action: it means "put
      # it back". The next reconcile must then repair rather than refuse.
      machine.succeed("nixnet-firewall-confirm")
      machine.succeed("systemctl start nixnet-firewall-reconcile.service")
      out = machine.succeed("nft list table inet nixnet")
      assert "8080" in out, f"confirming did not re-enable repair:\n{out}"
      assert enforced() == "1", "back in force, but not reporting it"
    '';
  };
}
