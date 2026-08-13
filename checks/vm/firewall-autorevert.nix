# checks/vm/firewall-autorevert.nix — FW-5.
#
# The dead-man switch is the one part of this module that can, by design, take a firewall away. So
# the question is not only "does it fire when it should" but "what is it allowed to leave behind",
# and the second one has a production answer: on 2026-08-04 it left corbet-eu-vultr — a public host
# and the overlay control plane — with no packet filter at all.
#
# The sequence, because "arm only on a change" was already implemented and did not prevent it:
# a host's FIRST nixnet ruleset is by definition a change, so the switch armed. Its snapshot was of
# an empty kernel, so the restore file said `add table; delete table`. Nobody typed
# nixnet-firewall-confirm, because it was an unattended deploy and there is no human in that loop.
# The timer fired and did exactly what it was told.
#
# Hence two halves, and they pull in opposite directions:
#
#   1. a first apply must NOT arm — there is nothing to revert TO, and "no firewall" is not a
#      recovery from a bad ruleset;
#   2. a CHANGED ruleset over an existing one MUST still arm and MUST still revert, because that is
#      the lockout the switch exists for.
#
# Plus the handover to FW-4: after a revert, the reconcile loop must stand down rather than reload
# the ruleset that was just undone.

{ pkgs }:

{
  name = "firewall-autorevert";
  behaviours = [ "FW-5" ];
  requiresModules = [ "firewall.nix" ];
  requiresOptions = [
    [ "nixnet" "firewall" "enable" ]
    [ "nixnet" "firewall" "autoRevert" "enable" ]
    [ "nixnet" "firewall" "autoRevert" "seconds" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-firewall-autorevert";

    nodes.machine = { lib, ... }: {
      imports = [ modules.core modules.firewall baseline ];
      virtualisation.vlans = [ 1 ];

      nixnet.interfaces.eth1.addressing = { v4 = "static"; v6 = "none"; };
      nixnet.firewall = {
        enable = true;
        management.interfaces = [ "eth1" ];
        autoRevert = {
          enable = true;
          # Short enough to observe, long enough that a slow VM boot does not race it.
          seconds = 5;
        };
        # Long, so the FW-4 loop cannot repair anything behind this test's back; the one reconcile
        # run below is started by hand.
        reconcile.intervalSec = 3600;
      };

      # A CHANGED ruleset over a working one — the case that must still arm.
      specialisation.changed.configuration = {
        nixnet.firewall.allow = lib.mkForce [
          {
            protocol = "tcp";
            ports = [ 9090 ];
            comment = "the rule whose disappearance proves the revert ran";
          }
        ];
      };

    };

    testScript = ''
      state = "/var/lib/nixnet-firewall"

      machine.wait_for_unit("nixnet-firewall.service")
      machine.wait_for_unit("multi-user.target")
      machine.succeed("nft list table inet nixnet >/dev/null")

      # ── 1. a first apply must not arm ───────────────────────────────────
      # There was no table before this one, so the only thing a revert could do is delete it.
      machine.fail("systemctl is-active nixnet-firewall-revert.timer")
      machine.fail(f"test -e {state}/pending.nft")
      machine.fail(f"test -e {state}/pending-hash")

      journal = machine.succeed("journalctl -u nixnet-firewall.service --no-pager")
      assert "no previous ruleset to restore" in journal, (
          f"the refusal to arm was not stated in the journal:\n{journal}"
      )

      # And it is still there well after the window would have expired. This is the assertion the
      # production incident would have failed.
      machine.sleep(10)
      machine.succeed("nft list table inet nixnet >/dev/null")
      out = machine.succeed(f"grep '^nixnet_firewall_enforced ' {state}/metrics.prom")
      assert out.split()[1].strip() == "1", "the firewall went away during the window that never armed"

      # ── 2. a changed ruleset over a working one must arm, and must revert ──
      machine.succeed("/run/current-system/specialisation/changed/bin/switch-to-configuration test")

      out = machine.succeed("nft list table inet nixnet")
      assert "9090" in out, f"the changed ruleset did not load:\n{out}"
      machine.succeed(f"test -s {state}/pending.nft")
      machine.succeed(f"test -s {state}/pending-hash")
      machine.succeed("systemctl is-active nixnet-firewall-revert.timer")

      # Restarting the apply unit is not confirmation and must not discard the rollback snapshot.
      machine.succeed("systemctl restart nixnet-firewall.service")
      machine.succeed(f"test -s {state}/pending.nft")
      machine.succeed("systemctl is-active nixnet-firewall-revert.timer")

      # Nobody confirms — the unattended case.
      machine.sleep(12)
      out = machine.succeed("nft list table inet nixnet")
      assert "9090" not in out, (
          f"the confirmation window expired and the ruleset was NOT reverted:\n{out}"
      )
      # Reverted TO something, not into nothing: the previous ruleset is what came back.
      assert "hook input" in out, f"the revert left no input chain at all:\n{out}"
      machine.succeed(f"test -s {state}/reverted-hash")
      machine.fail(f"test -e {state}/applied-hash")

      # ── 3. the handover to every automatic owner ────────────────────────
      # The reconcile loop must not undo the revert. It goes red instead.
      machine.fail("systemctl start nixnet-firewall-reconcile.service")
      out = machine.succeed("nft list table inet nixnet")
      assert "9090" not in out, f"reconcile reloaded the ruleset the dead-man switch undid:\n{out}"

      # Nor may a service restart or reboot re-apply it. This was a separate path from reconcile:
      # the old apply script unconditionally loaded first and cleared the revert marker afterwards.
      machine.fail("systemctl restart nixnet-firewall.service")
      out = machine.succeed("nft list table inet nixnet")
      assert "9090" not in out, f"service restart re-applied the deliberately reverted ruleset:\n{out}"
    '';
  };
}
