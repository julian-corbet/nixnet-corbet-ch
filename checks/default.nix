# checks/default.nix
#
# EVAL-TIME tests for nixnet's core module (modules/core.nix). Real NixOS
# evaluation via nixpkgs' own eval-config.nix, not a bare `lib.evalModules`
# stub -- core.nix's fix here touches `users.users`/`users.groups` and
# `systemd.services.*.serviceConfig`, real option surface a hand-rolled
# stub would have to reimplement anyway. These check the module's
# rendered OUTPUT VALUES, never runtime behavior on a booted machine --
# whether a rename() actually succeeds under a given owner/sticky-bit
# combination is a fact about a live kernel, not about what Nix evaluates
# to, and is deliberately out of scope here. That fact was instead
# verified live, in both directions, against a real production host:
# pre-fix, nixnetd logged "publish hosts: Operation not permitted" on
# every winner-change (DynamicUser's per-boot UID owned neither the
# boot-seeded hostsFile nor its directory); post-fix, the same box
# published real winners into /etc/hosts successfully. See the fix
# commit for that reproduction.

{ pkgs, nixpkgs, nixnetModule, meshGatewayModule }:

let
  lib = pkgs.lib;

  # The minimal-but-complete NixOS baseline every evaluation below needs.
  baseline = {
    boot.loader.grub.enable = false;
    fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
    system.stateVersion = "25.05";
  };

  evalModules = mods:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      system = "x86_64-linux";
      modules = mods ++ [ baseline ];
    }).config;

  # Evaluate nixnet (always enabled, one minimal peer so
  # systemd.services.nixnetd actually renders) plus whatever `extraConfig`
  # a test needs, against a minimal-but-complete NixOS configuration.
  evalFor = extraConfig:
    evalModules [
      nixnetModule
      {
        nixnet.enable = true;
        nixnet.peers.example = {
          hostnames = [ "example" ];
          transports = [{
            address = "192.0.2.10";
            priority = 10;
            probe = { method = "tcp"; port = 22; };
          }];
        };
      }
      extraConfig
    ];

  # One test result. `detail` is only read when `ok == false` (in the
  # failure report below), but it's always a plain string here so
  # forcing it is never a surprise.
  check = name: ok: detail: { inherit name ok detail; };

  cfg = evalFor { };
  nixnetdService = cfg.systemd.services.nixnetd.serviceConfig;

  results = [
    # THE regression this file exists for. Pre-fix, `DynamicUser = true`
    # sat here and nixnetd's boot-time-seeded hostsFile could never be
    # renamed-over by its own per-boot-random UID -- unconditionally, not
    # intermittently (POSIX sticky-bit semantics: unlink/rename is
    # restricted to the file's owner, the directory's owner, or a
    # privileged process, and a non-root DynamicUser is never any of
    # those against a root-owned file). Post-fix: no DynamicUser, a fixed
    # User/Group instead. This check fails against the pre-fix module and
    # passes against the post-fix one -- verified both ways while writing
    # it, not just asserted after the fact.
    (check "nixnetd-fixed-user/no-dynamic-user"
      (!(nixnetdService ? DynamicUser) || nixnetdService.DynamicUser != true)
      "serviceConfig.DynamicUser: ${builtins.toJSON (nixnetdService.DynamicUser or null)}")

    (check "nixnetd-fixed-user/runs-as-nixnetd-user"
      ((nixnetdService.User or null) == "nixnetd")
      "serviceConfig.User: ${builtins.toJSON (nixnetdService.User or null)}")

    (check "nixnetd-fixed-user/runs-as-nixnetd-group"
      ((nixnetdService.Group or null) == "nixnetd")
      "serviceConfig.Group: ${builtins.toJSON (nixnetdService.Group or null)}")

    (check "nixnetd-fixed-user/user-declared"
      (cfg.users.users ? nixnetd)
      "users.users keys: ${builtins.toJSON (builtins.attrNames cfg.users.users)}")

    (check "nixnetd-fixed-user/group-declared"
      (cfg.users.groups ? nixnetd)
      "users.groups keys: ${builtins.toJSON (builtins.attrNames cfg.users.groups)}")

  ];

  # ---------------------------------------------------------------------
  # mesh-gateway: the 2026-08-03 overlay outage.
  #
  # A separate evaluation, because mesh-gateway is a standalone module
  # with its own required options and none of core.nix's fixture above
  # applies to it. Every value here is a placeholder -- these checks read
  # rendered unit WIRING (ordering edges, dependency strength, restart
  # policy), never anything that would need a real key, a real API, or a
  # real binary. `ageKeyFile`/`*Secret` are deliberately absolute string
  # paths rather than `./fixture` files: `types.path` accepts them
  # unchanged, so the rendered RequiresMountsFor= is a stable, assertable
  # literal instead of a store hash that changes on every edit.
  # ---------------------------------------------------------------------
  mgAgeKey = "/var/lib/example/age.key";
  mgSetupKey = "/var/lib/example/setupkey.enc";

  # A deliberately STORE-path secret, to pin the filtering direction below.
  mgStoreSecret = pkgs.writeText "nixnet-fake-sealed-secret" "not-a-real-secret";

  mgCfg = evalModules [
    meshGatewayModule
    {
      nixnet.meshGateway = {
        enable = true;
        package = pkgs.coreutils; # never executed at eval time
        managementUrl = "https://mesh.example.com";
        apiUrl = "https://mesh.example.com/api";
        ageKeyFile = mgAgeKey;
        setupKeySecret = mgSetupKey;
        # NOT a sibling of setupKeySecret by accident: this one is a store
        # path so the two apitoken/setupkey units together cover both sides
        # of the store-path filter in one evaluation.
        apiTokenSecret = mgStoreSecret;
      };
    }
  ];

  mgUnseal = mgCfg.systemd.services.nixnet-mesh-gateway-setupkey-unseal;
  mgGateway = mgCfg.systemd.services.nixnet-mesh-gateway;
  mgUnsealUnits = [
    "nixnet-mesh-gateway-setupkey-unseal.service"
    "nixnet-mesh-gateway-apitoken-unseal.service"
  ];

  meshGatewayResults = [
    # THE regression this block exists for. The unseal ran before the
    # filesystem holding its age key was mounted -- a 10-second loss --
    # and because a Type=oneshot failure latches, the overlay stayed down
    # until a human intervened. RequiresMountsFor= makes systemd derive
    # that ordering from the path itself, so no consumer has to name a
    # mount unit.
    (check "mesh-gateway/unseal-orders-after-age-key-mount"
      (lib.elem mgAgeKey (lib.toList (mgUnseal.unitConfig.RequiresMountsFor or [ ])))
      "unitConfig.RequiresMountsFor: ${builtins.toJSON (mgUnseal.unitConfig.RequiresMountsFor or null)}")

    (check "mesh-gateway/unseal-orders-after-secret-mount"
      (lib.elem mgSetupKey (lib.toList (mgUnseal.unitConfig.RequiresMountsFor or [ ])))
      "unitConfig.RequiresMountsFor: ${builtins.toJSON (mgUnseal.unitConfig.RequiresMountsFor or null)}")

    # Defence in depth: a transient unreadable secret must retry, not
    # latch. Type=oneshot rejects Restart=always/on-success, so on-failure
    # is both the correct and the only usable mode here.
    # The other direction of the same filter. A store path must NOT appear:
    # /nix/store is up before systemd starts anything, and `toString` on a
    # store path drops its string context, so letting one through would make
    # this unit's derivation reference it without declaring the dependency.
    (check "mesh-gateway/unseal-excludes-store-paths"
      (!(lib.any
        (lib.hasPrefix builtins.storeDir)
        (lib.toList (mgCfg.systemd.services.nixnet-mesh-gateway-apitoken-unseal.unitConfig.RequiresMountsFor or [ ]))))
      "apitoken unseal RequiresMountsFor: ${builtins.toJSON (mgCfg.systemd.services.nixnet-mesh-gateway-apitoken-unseal.unitConfig.RequiresMountsFor or null)}")

    # ...and the age key must still survive that filter on the very same unit,
    # so "exclude store paths" can never degrade into "exclude everything".
    (check "mesh-gateway/unseal-keeps-age-key-alongside-store-secret"
      (lib.elem mgAgeKey (lib.toList (mgCfg.systemd.services.nixnet-mesh-gateway-apitoken-unseal.unitConfig.RequiresMountsFor or [ ])))
      "apitoken unseal RequiresMountsFor: ${builtins.toJSON (mgCfg.systemd.services.nixnet-mesh-gateway-apitoken-unseal.unitConfig.RequiresMountsFor or null)}")

    (check "mesh-gateway/unseal-retries-on-failure"
      ((mgUnseal.serviceConfig.Restart or null) == "on-failure")
      "serviceConfig.Restart: ${builtins.toJSON (mgUnseal.serviceConfig.Restart or null)}")

    # The dependency-strength half of the same incident: with `requires`,
    # a failed unseal CANCELS the gateway's start job and nothing ever
    # re-queues it, so the unseal succeeding later fixes nothing. These
    # two checks are a matched pair -- the ordering edge must SURVIVE
    # while the hard requirement must be GONE. Dropping both would
    # "pass" the second check while silently making startup racy.
    (check "mesh-gateway/does-not-hard-require-unseals"
      (!(lib.any (u: lib.elem u (mgGateway.requires or [ ])) mgUnsealUnits))
      "requires: ${builtins.toJSON (mgGateway.requires or null)}")

    (check "mesh-gateway/still-orders-after-unseals"
      (lib.all (u: lib.elem u (mgGateway.after or [ ])) mgUnsealUnits)
      "after: ${builtins.toJSON (mgGateway.after or null)}")

    (check "mesh-gateway/still-wants-unseals"
      (lib.all (u: lib.elem u (mgGateway.wants or [ ])) mgUnsealUnits)
      "wants: ${builtins.toJSON (mgGateway.wants or null)}")
  ];

  # Source-text checks for the two assertions, rather than reading the
  # evaluated `config.assertions` list: that list is the FULL system's,
  # every module's, not just nixnet's -- forcing every entry's `.message`
  # (which `lib.any`/`hasInfix` needs to do) evaluates unrelated modules'
  # assertion strings too, and at least one of those (filesystems.nix's
  # topological-sort message, tripped by this file's own minimal fake
  # `fileSystems."/"`) throws on a stub this bare. Reading the module's
  # own source text sidesteps that class of fragility entirely and is
  # exactly as meaningful for what these two checks actually assert:
  # which literal assertions modules/core.nix's own code declares.
  coreSrc = builtins.readFile ../modules/core.nix;

  sourceResults = [
    # The obsolete "hostsFile must not live under stateDir" assertion
    # existed solely to guard against DynamicUser's own StateDirectory=
    # relocation to /var/lib/private/<name> (0700 root:root) -- that
    # relocation only ever happens under DynamicUser=true, so with it gone
    # the guard was dead code protecting against something that can no
    # longer happen. Confirms it was actually deleted, not just made
    # unreachable.
    (check "nixnetd-fixed-user/stale-relocation-assertion-removed"
      (!(lib.hasInfix "relocated by systemd (DynamicUser=true)" coreSrc))
      "found the retired assertion's own text still in modules/core.nix")

    # The still-valid assertion (stateDir must live under /var/lib/) must
    # survive the edit -- this fix touches the same `assertions` list, and
    # a careless removal of the WHOLE block instead of just the one stale
    # entry would silently drop a genuinely load-bearing check.
    (check "nixnetd-fixed-user/statedir-location-assertion-survives"
      (lib.hasInfix "live under /var/lib/" coreSrc)
      "did not find the surviving assertion's text in modules/core.nix")
  ];

  allResults = results ++ meshGatewayResults ++ sourceResults;

  failed = builtins.filter (r: !r.ok) allResults;

  report = lib.concatMapStringsSep "\n" (r: "  - ${r.name}: ${r.detail}") failed;
in
if failed != [ ]
then throw ''
  nixnet eval-checks FAILED (${toString (builtins.length failed)}/${toString (builtins.length allResults)}):
  ${report}
''
else {
  # Constructing this derivation depends on `passedCount`, which forces
  # `results` (and therefore every `check` assertion above) even if
  # nothing else ever reads the attribute -- so the checks really do run,
  # not just get defined.
  eval-checks = pkgs.runCommand "nixnet-eval-checks"
    { passedCount = toString (builtins.length allResults); }
    ''
      echo "all $passedCount nixnet eval checks passed"
      touch $out
    '';
}
