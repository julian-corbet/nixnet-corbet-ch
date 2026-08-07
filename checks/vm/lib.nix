# checks/vm/lib.nix — the VM-test harness itself.
#
# Every sharp bug in this repo's history reached production because nothing ever
# booted a machine and looked at it. The eval checks next door read rendered
# option VALUES; that is a different question from "does the machine still have
# an address 40 seconds later", and no amount of string comparison answers it.
# So: nixpkgs' own `testers.runNixOSTest`, real kernels, real nftables, real
# DHCP, and assertions on machine state -- `ip addr`, `nft list table`, the
# published file, `systemctl is-failed` -- never on log strings.
#
# THE ONE KIND OF EVIDENCE THAT IS NOT A BOOTED MACHINE. Some behaviours in the
# contract are REFUSALS -- `FW-1`, `RADIO-4`, `RADIO-6`: a configuration that must
# fail on the build host rather than render. A refusal's whole point is that no
# machine ever boots, so a VM test is the wrong instrument, and until now the only
# way to record that was a waiver in ../coverage.nix. A waiver says "nothing proves
# this"; for a refusal that is simply false -- an evaluation either fails with the
# named message or it does not, which is as decidable from outside as any packet
# counter. So a spec may declare `refusals` instead of (or alongside) `test`, and
# gets a check of the same name either way. Both directions are still required: a
# refusal case names the message it expects, and every refusal set carries at least
# one control config that must evaluate CLEAN, or "refuses everything" would pass.
#
# The one piece of machinery here worth explaining is the RUNNABILITY GATE.
# These tests are written against the rebuild's target contract (BEHAVIORS.md),
# and parts of that contract do not exist in modules/ yet. A test written
# against an option that does not exist yet must FAIL, by name, saying exactly
# what is missing -- never disappear from the check set, and never pass. A
# vacuous test is worse than no test: it converts an unknown into a false
# assurance. So each test declares what it needs, and a test whose needs are
# unmet becomes a derivation that fails with the unmet need printed.

{ pkgs, nixpkgs, moduleDir }:

let
  lib = pkgs.lib;

  modulePath = f: moduleDir + "/${f}";

  # ---------------------------------------------------------------------
  # Option-surface probe. `hasOptionPath` answers "does this module set
  # declare nixnet.firewall.enable?" without evaluating a whole machine, and
  # descends THROUGH submodules: `nixnet.interfaces` is an attrsOf submodule,
  # so `addressing.v4` lives behind `type.getSubOptions`, not behind a plain
  # attribute. Naming a path that stops short of a real option (a submodule
  # attribute that happens to exist) is caught too -- the final node must
  # itself be an option.
  # ---------------------------------------------------------------------
  probeOptions = mods:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      system = pkgs.stdenv.hostPlatform.system;
      modules = mods ++ [{
        boot.loader.grub.enable = false;
        fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
        system.stateVersion = "25.05";
      }];
    }).options;

  isOption = n: n ? _type && n._type == "option";

  hasOptionPath = opts: path:
    let
      step = node: seg:
        if node == null then null
        else
          let
            # An option node has no child attributes of its own; its children
            # live in its TYPE. getSubOptions is defined on every type (it
            # returns { } for a scalar), so this is safe on any node.
            children = if isOption node then node.type.getSubOptions "" else node;
          in
          if children ? ${seg} then children.${seg} else null;
      final = lib.foldl' step opts path;
    in
    final != null && isOption final;

  # A check that cannot run yet. Fails loudly and prints why. Deliberately not
  # a skip and deliberately not a `true`: the check set is the only mechanical
  # record of what this repo can and cannot prove about itself.
  unrunnable = name: reasons: pkgs.runCommand "nixnet-vm-${name}-UNRUNNABLE"
    { inherit name; reasonText = lib.concatMapStringsSep "\n" (r: "  - ${r}") reasons; }
    ''
      echo "nixnet VM check '$name' cannot run against modules/ as it stands:" >&2
      echo "$reasonText" >&2
      echo "" >&2
      echo "This test encodes a behaviour from BEHAVIORS.md that the modules do not" >&2
      echo "implement yet. It fails on purpose -- the test is the spec." >&2
      exit 1
    '';

  # ---------------------------------------------------------------------
  # Node baseline shared by every VM test.
  #
  # `networking.firewall.enable = false` is not tidiness. nixpkgs' firewall
  # module emits its own DHCP-client and ICMP accepts unconditionally, which
  # is precisely the derivation these tests exist to verify nixnet performs
  # itself -- leaving it on would make the DHCP test pass against a nixnet
  # ruleset containing no DHCP rule at all.
  # ---------------------------------------------------------------------
  nodeBaseline = {
    networking.firewall.enable = false;
    # Tests assert on `nft list table`, so the binary has to be on PATH inside
    # the machine, not just in the apply unit's own closure.
    environment.systemPackages = [ pkgs.nftables pkgs.jq ];
    # Test VMs boot from a store the driver shares; no bootloader involved.
    boot.loader.grub.enable = false;
    # The test instrumentation switches this off to save build time, and three
    # of these tests need it: ACTIVATION on a running machine is the exact
    # moment PUB-1's second writer runs and FW-3's bad ruleset is loaded, and
    # neither is reachable from a machine that can only ever boot.
    system.switch.enable = true;
  };

  # ---------------------------------------------------------------------
  # Refusal evidence: a configuration that must FAIL to evaluate, and the
  # message it must fail with.
  #
  # The minimal-but-complete NixOS baseline, identical in shape to the one
  # ../default.nix and experiments/render-check.nix use.
  # `networking.firewall.enable = false` because nixnet's own firewall
  # asserts against it, and several of these configs enable both.
  # ---------------------------------------------------------------------
  evalBaseline = {
    boot.loader.grub.enable = false;
    fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
    system.stateVersion = "25.05";
    networking.firewall.enable = false;
  };

  evalConfig = mods:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      system = pkgs.stdenv.hostPlatform.system;
      modules = mods ++ [ evalBaseline ];
    }).config;

  # Narrowed to nixnet's own, and `.message` is forced ONLY for assertions that
  # already failed -- Nix's `&&` is lazy, and an unrelated nixpkgs assertion's
  # message can throw against a baseline this bare (filesystems.nix's
  # topological sort on the fake root above is the known one).
  nixnetFailures = cfg:
    map (a: a.message)
      (lib.filter (a: !a.assertion && lib.hasInfix "nixnet" a.message) cfg.assertions);

  # case = { name; modules = [ ... ]; expect = "infix" | null; }
  # `expect = null` is a CONTROL: the same shape, correct, which must evaluate
  # with no nixnet assertion failing at all.
  runRefusal = case:
    let
      msgs = nixnetFailures (evalConfig case.modules);
      ok =
        if case.expect == null
        then msgs == [ ]
        else lib.any (m: lib.hasInfix case.expect m) msgs;
      detail =
        if case.expect == null
        then "expected a clean evaluation, got: ${builtins.toJSON msgs}"
        else "expected an assertion containing ${builtins.toJSON case.expect}, got: ${builtins.toJSON msgs}";
    in
    { inherit (case) name; inherit ok detail; };

  mkRefusals = name: cases:
    let
      results = map runRefusal cases;
      failures = builtins.filter (r: !r.ok) results;
      hasControl = lib.any (c: c.expect == null) cases;
    in
    assert lib.assertMsg hasControl
      "checks/vm: refusal set '${name}' has no control case (expect = null); a set that only ever refuses cannot tell a working module from a broken one";
    pkgs.runCommand "nixnet-refusal-${name}"
      {
        failed = lib.concatMapStringsSep "\n" (r: "  - ${r.name}: ${r.detail}") failures;
        total = toString (builtins.length results);
      }
      ''
        if [ -n "$failed" ]; then
          echo "nixnet refusal check '${name}' FAILED:" >&2
          echo "$failed" >&2
          exit 1
        fi
        echo "all $total refusal cases held"
        touch $out
      '';

  # ---------------------------------------------------------------------
  # mkTest: spec in, derivation out.
  #
  # spec = {
  #   name            = "kebab-case-slug";
  #   behaviours      = [ "OWN-1" ... ];   # ids from BEHAVIORS.md this proves
  #   requiresModules = [ "firewall.nix" ];
  #   requiresOptions = [ [ "nixnet" "firewall" "enable" ] ... ];
  #   test            = { modules, baseline }: <runNixOSTest argument>;
  #   refusals        = { modules, evalBaseline }: [ <case> ];
  # }
  #
  # A spec declaring both gets ONE derivation that depends on both, because a
  # behaviour id names one check: `RADIO-5` is a file mode on a booted machine
  # AND an evaluation that refuses a store path, and evidence for half of it is
  # not evidence.
  # ---------------------------------------------------------------------
  mkTest = spec:
    let
      needModules = spec.requiresModules or [ ];
      needOptions = spec.requiresOptions or [ ];

      missingModules = builtins.filter (f: !(builtins.pathExists (modulePath f))) needModules;

      # Only probed when every required module FILE exists -- otherwise the
      # eval-config call below would itself throw on a missing import, losing
      # the precise "modules/firewall.nix does not exist" message.
      probed =
        if missingModules != [ ] then null
        else probeOptions (map modulePath ([ "core.nix" ] ++ needModules));

      missingOptions =
        if probed == null then [ ]
        else builtins.filter (p: !(hasOptionPath probed p)) needOptions;

      reasons =
        (map (f: "modules/${f} does not exist") missingModules)
        ++ (map (p: "option `${lib.concatStringsSep "." p}` is not declared") missingOptions);

      modules = builtins.listToAttrs (map
        (f: { name = lib.removeSuffix ".nix" f; value = modulePath f; })
        ([ "core.nix" ] ++ needModules));

      vmDrv = pkgs.testers.runNixOSTest (spec.test { inherit modules; baseline = nodeBaseline; });
      refusalDrv = mkRefusals spec.name (spec.refusals { inherit modules evalBaseline; });
    in
    if reasons != [ ]
    then unrunnable spec.name reasons
    else if !(spec ? refusals) then vmDrv
    else if !(spec ? test) then refusalDrv
    else
    # Both kinds of evidence, one check. Named as env attrs so each is a real
    # build-time dependency: this derivation cannot exist unless both did.
      pkgs.runCommand "nixnet-vm-${spec.name}"
        { vm = vmDrv; refusals = refusalDrv; }
        ''
          echo "vm test:  $vm"
          echo "refusals: $refusals"
          touch $out
        '';

in
{
  inherit mkTest nodeBaseline modulePath hasOptionPath probeOptions unrunnable
    evalBaseline evalConfig nixnetFailures;
}
