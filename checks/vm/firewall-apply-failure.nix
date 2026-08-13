# checks/vm/firewall-apply-failure.nix — FW-3.
#
# The load-bearing entry of BEHAVIORS.md, and the one currently false in
# production: the ruleset is rendered as text and handed to a loader whose
# result is swallowed, so a host that fails to load its firewall runs with NO
# packet filter and says nothing. That state was discovered from a serial
# console, not from anything the host emitted.
#
# An unapplied firewall must be indistinguishable from a crashed one. Three
# separate observable claims, all asserted here on machine state rather than on
# log text:
#
#   * the apply unit is `failed` -- not active, not "activating", not exited 0;
#   * the load is ONE transaction, so a failed apply leaves the PREVIOUS
#     ruleset in force, byte-identical;
#   * a boot that never had a previous ruleset ends with no nixnet table AND a
#     failed unit AND a degraded system -- never a quiet green machine with an
#     open filter.
#
# `silentDrops.*.match` is the injection point because it is the one option
# that carries a raw nftables matcher, i.e. the realistic way a ruleset that
# builds fine fails to load. Making the failure come from a declared option
# rather than from a patched-in broken file is deliberate: the test exercises
# the same path an operator's typo takes.
#
# FW-3's "Not" is asserted too. On failure nixnet must NOT install a panic
# default-drop ruleset -- on a host reachable only over the network that turns
# a firewall bug into a lost machine -- so the peer node must still reach the
# machine after the failed apply.

{ pkgs }:

let
  # Loads on no kernel: `prot0col` is not a match. Passes every Nix type check,
  # which is exactly the class of failure this behaviour is about.
  unloadable = [{
    match = "ip prot0col 6";
    comment = "deliberately unloadable -- FW-3 fixture";
  }];

  firewalled = {
    nixnet.interfaces.eth1.addressing = { v4 = "static"; v6 = "none"; };
    nixnet.firewall = {
      enable = true;
      management.interfaces = [ "eth1" ];
      # autoRevert would restore a snapshot mid-test and confuse the question
      # being asked here; FW-5 is a separate behaviour with its own window.
      autoRevert.enable = false;
    };
  };

  # Reproduce the systemd-initrd boundary that exposed the production boot
  # failure.  The initrd's module-load service remains active across
  # switch-root, so stage 2 does not get a second chance to load modules.
  # Locking module loading before sysinit.target makes that boundary
  # deterministic in the VM: anything the firewall needs must already have
  # been loaded by the initrd.
  lockModuleLoading = {
    boot.initrd.systemd.enable = true;
    systemd.services.nixnet-test-lock-module-loading = {
      description = "nixnet test: forbid module loading after the initrd";
      wantedBy = [ "sysinit.target" ];
      before = [ "sysinit.target" "nixnet-firewall.service" ];
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
  name = "firewall-apply-failure";
  behaviours = [ "FW-3" ];
  requiresModules = [ "firewall.nix" ];
  requiresOptions = [
    [ "nixnet" "firewall" "enable" ]
    [ "nixnet" "firewall" "silentDrops" ]
    [ "nixnet" "firewall" "autoRevert" "enable" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-firewall-apply-failure";

    nodes = {
      # Boots healthy, then switches to a generation whose ruleset cannot load.
      machine = { ... }: {
        imports = [ modules.core modules.firewall baseline firewalled ];
        virtualisation.vlans = [ 1 ];
        specialisation.broken.configuration = {
          nixnet.firewall.silentDrops = unloadable;
        };
      };

      # Boots straight into the unloadable ruleset: the no-previous-state case,
      # where "the table is absent" is the only thing left to notice.
      bootbroken = { ... }: {
        imports = [ modules.core modules.firewall baseline firewalled ];
        virtualisation.vlans = [ 1 ];
        nixnet.firewall.silentDrops = unloadable;
      };

      # A healthy boot with post-initrd module loading forbidden.  This is the
      # case a syntax-only failure fixture cannot cover: the nftables socket,
      # conntrack expressions, rate limiter and AF_PACKET must all exist before
      # nixnet runs, without demand-loading hiding an incomplete module.
      modulelocked = { ... }: {
        imports = [ modules.core modules.firewall baseline firewalled lockModuleLoading ];
        nixnet.firewall.management.rateLimitNew = "6/minute";
      };

      # `enable = false` still owns removal of a table left by an earlier
      # generation.  On a clean boot absence is already proven and that
      # teardown must not degrade the host even after module loading is locked.
      disabledlocked = { ... }: {
        imports = [ modules.core modules.firewall baseline lockModuleLoading ];
      };

      # A second machine, because FW-3's "Not" is about reachability and
      # reachability is only decidable from somewhere else.
      peer = { ... }: {
        imports = [ baseline ];
        virtualisation.vlans = [ 1 ];
      };
    };

    testScript = ''
      start_all()
      machine.wait_for_unit("nixnet-firewall.service")
      machine.wait_for_unit("multi-user.target")

      # The healthy baseline this test measures the failure against.
      good = machine.succeed("nft list table inet nixnet")
      applied_before = machine.succeed("cat /var/lib/nixnet-firewall/applied-hash").strip()
      assert "policy drop" in good, "the healthy generation is not default-deny; nothing below means anything"
      peer.wait_for_unit("multi-user.target")
      peer.succeed(f"ping -c 2 -W 5 {machine.name}")

      # ── the failed apply ────────────────────────────────────────────────
      machine.fail("/run/current-system/specialisation/broken/bin/switch-to-configuration test")

      state = machine.succeed(
          "systemctl show -p ActiveState -p Result --value nixnet-firewall.service"
      ).split()
      assert state[0] == "failed", f"apply unit did not fail visibly: ActiveState={state[0]}"
      assert state[1] != "success", "apply unit reported Result=success on a ruleset that cannot load"

      # One transaction: the previous ruleset is still in force, unchanged.
      after = machine.succeed("nft list table inet nixnet")
      assert after == good, (
          "a failed apply changed the live ruleset -- the load is not one transaction:\n"
          f"--- before ---\n{good}\n--- after ---\n{after}"
      )
      applied_after = machine.succeed("cat /var/lib/nixnet-firewall/applied-hash").strip()
      assert applied_after == applied_before, (
          "a failed load advanced applied-hash, so a retry would mistake the broken generation for an unchanged one"
      )

      # FW-3's "Not": no panic default-drop. The host stays reachable.
      peer.succeed(f"ping -c 2 -W 5 {machine.name}")

      # ── the same failure with nothing to fall back to ──────────────────
      bootbroken.wait_for_unit("multi-user.target")
      # The unit must have RUN and FAILED. `is-failed` is the observable; a unit
      # that is merely inactive would mean nothing ever tried.
      bootbroken.succeed("systemctl is-failed nixnet-firewall.service")
      bootbroken.fail("nft list table inet nixnet")
      # ...and the machine must not present itself as healthy while unfirewalled.
      status = bootbroken.succeed("systemctl is-system-running || true").strip()
      assert status in ("degraded", "maintenance"), (
          f"a host with no firewall and a failed apply reports itself as '{status}'"
      )

      # ── the systemd-initrd module boundary ──────────────────────────────
      modulelocked.wait_for_unit("multi-user.target")
      modulelocked.succeed("test $(cat /proc/sys/kernel/modules_disabled) -eq 1")
      modulelocked.succeed("systemctl is-active --quiet nixnet-firewall.service")
      modulelocked.succeed("nft list table inet nixnet")
      for module in (
          "af_packet", "nfnetlink", "nf_conntrack", "nf_tables", "nft_ct", "nft_limit"
      ):
          modulelocked.succeed(f"test -d /sys/module/{module}")

      disabledlocked.wait_for_unit("multi-user.target")
      disabledlocked.succeed("test $(cat /proc/sys/kernel/modules_disabled) -eq 1")
      disabledlocked.succeed("systemctl is-active --quiet nixnet-firewall.service")
      disabledlocked.fail("nft list table inet nixnet")
    '';
  };
}
