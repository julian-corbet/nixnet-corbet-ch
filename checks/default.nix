# checks/default.nix
#
# The checks output: EVAL-TIME assertions on rendered module values (this
# file) plus the VM tests in ./vm, which boot machines and assert on what
# the kernel actually did.
#
# The split is not arbitrary. Eval-time checks answer "what does this
# module render", and that is all they can answer -- a rendered-ruleset
# string comparison passes for a rule that loads and matches nothing, and
# a rendered unit passes for a daemon that cannot write the file it
# exists to write. Everything whose failure mode is "the machine is
# unreachable" belongs in ./vm, on a booted machine, asserted from a
# second one.
#
# The eval-time half below is real NixOS evaluation via nixpkgs' own
# eval-config.nix, not a bare `lib.evalModules` stub -- these checks touch
# `users.users`/`users.groups` and `systemd.services.*.serviceConfig`,
# real option surface a hand-rolled stub would have to reimplement anyway.

# `moduleDir` rather than one path per module: ./vm probes for modules that do
# not exist yet (the firewall fold-in) and must be able to say "modules/
# firewall.nix does not exist" instead of aborting evaluation of every other
# check on a missing import.
{ pkgs, nixpkgs, nixnetModule, meshGatewayModule, overlayModule, moduleDir }:

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

  # Use a nested state path in the main fixture so the ordinary service
  # checks and the path-preservation regression share one NixOS evaluation.
  cfg = evalFor {
    nixnet.daemon.stateDir = "/var/lib/nixnet/nested-state";
  };
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

    (check "nixnetd/state-directory-preserves-nested-path"
      ((nixnetdService.StateDirectory or null) == "nixnet/nested-state")
      "serviceConfig.StateDirectory: ${builtins.toJSON (nixnetdService.StateDirectory or null)}")

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

  # ---------------------------------------------------------------------
  # overlay: the confinement must not be silently droppable.
  #
  # These rules used to ride on networking.firewall.extraCommands, which the
  # iptables backend alone honours -- so on a host with the nixpkgs firewall
  # disabled (what every nftables-native firewall requires) a DENY rule
  # vanished with no error at all. The checks below pin the properties that
  # make that impossible now: an owned table, rendered per address family,
  # and no dependence on the firewall module's escape hatch.
  # ---------------------------------------------------------------------
  overlayCfg = evalModules [
    overlayModule
    (moduleDir + "/ingress.nix")
    (moduleDir + "/netbird-access-model.nix")
    {
      nixnet.overlay = {
        enable = true;
        managementUrl = "https://mesh.example.com";
        hostname = "router";
        setupKeyFile = "/run/secrets/nixnet-overlay-key";
        overlayInterface = "wt0";
        # Dual-stack on purpose: a v4-only fixture cannot catch a v6 rule
        # landing in a chain no v6 packet can reach, which is the exact
        # mistake the per-family split exists to prevent.
        advertiseRoutes = [ "192.0.2.0/24" "2001:db8:42::/64" ];
        confineExternalRanges = [ "198.51.100.192/26" "2001:db8:ff::/64" ];
        confineExternalAllow = [ "192.0.2.6" "2001:db8:42::6" ];
      };
      nixnet.netbirdAccessModel = {
        enable = true;
        internalGroup = "internal";
        groups.internal.description = "All internally managed peers.";
        audit.apiUrl = "https://mesh.example.com/api";
      };
      nixnet.ingress = {
        enable = true;
        tunnelId = "00000000-0000-0000-0000-000000000001";
        credentialsFile = "/run/secrets/cloudflared-credentials.json";
        edgeIpVersion = "6";
        transportProtocol = "http2";
        ingress = [{
          hostname = "app.example.com";
          path = "^/hook$";
          service = "http://127.0.0.1:8080";
        }];
        dnsReconcile = {
          enable = true;
          apiTokenFile = "/run/secrets/cloudflare-api-token";
          zone = "example.com";
        };
      };
    }
  ];

  overlayRules = overlayCfg.nixnet.overlay.ruleset;

  overlayResults = [
    # THE regression. If either of these strings ever comes back, a deny rule
    # is once again one `networking.firewall.enable = false` away from
    # silently not existing.
    # Asserted against the EVALUATED value, not the module's source text.
    # A source grep cannot tell a live `networking.firewall.extraCommands =`
    # from the prose explaining why this module stopped using one, so it
    # fails the moment the file documents its own history -- and the only
    # way to satisfy it becomes deleting the documentation. What actually
    # matters is that this module CONTRIBUTES nothing there, which is
    # exactly what the rendered config says.
    # Keyed on THIS module's own fingerprint rather than on the field being
    # empty: nixpkgs' firewall module contributes its own nat/forward
    # teardown helpers to extraCommands unconditionally, so "empty" is never
    # true and an emptiness check would fail against a perfectly correct
    # module. What must be absent is anything nixnet put there -- its chain
    # name, and the overlay interface its masquerade named.
    (check "overlay/contributes-no-firewall-extraCommands"
      (!(lib.hasInfix "NIXNET-EXT-CONFINE" overlayCfg.networking.firewall.extraCommands)
        && !(lib.hasInfix "wt0" overlayCfg.networking.firewall.extraCommands))
      "networking.firewall.extraCommands: ${builtins.toJSON overlayCfg.networking.firewall.extraCommands}")

    (check "overlay/contributes-no-firewall-extraStopCommands"
      (!(lib.hasInfix "NIXNET-EXT-CONFINE" overlayCfg.networking.firewall.extraStopCommands)
        && !(lib.hasInfix "wt0" overlayCfg.networking.firewall.extraStopCommands))
      "networking.firewall.extraStopCommands: ${builtins.toJSON overlayCfg.networking.firewall.extraStopCommands}")

    (check "overlay/owns-its-own-table"
      (lib.hasInfix "table inet nixnet-overlay {" overlayRules)
      "rendered ruleset:\n${overlayRules}")

    # Family separation, both directions. A v4 source range must jump to the
    # v4 chain and a v6 source range to the v6 chain -- crossing them yields
    # rules that read as coverage but can never match a packet.
    (check "overlay/v4-source-jumps-to-v4-chain"
      (lib.hasInfix "ip saddr 198.51.100.192/26 jump ext-confine-v4" overlayRules)
      "rendered ruleset:\n${overlayRules}")

    (check "overlay/v6-source-jumps-to-v6-chain"
      (lib.hasInfix "ip6 saddr 2001:db8:ff::/64 jump ext-confine-v6" overlayRules)
      "rendered ruleset:\n${overlayRules}")

    (check "overlay/v6-route-dropped-in-the-v6-chain-only"
      (let
        v6ChainBody = lib.last (lib.splitString "chain ext-confine-v6 {" overlayRules);
        v4ChainBody = lib.head (lib.splitString "chain ext-confine-v6 {" overlayRules);
      in
      lib.hasInfix "ip6 daddr 2001:db8:42::/64 drop" v6ChainBody
      && !(lib.hasInfix "ip6 daddr" v4ChainBody))
      "rendered ruleset:\n${overlayRules}")

    # The confinement has to run ahead of any filter-priority chain, or
    # NetBird's own dynamic accept could be evaluated first.
    (check "overlay/confinement-hooks-prerouting-at-raw-priority"
      (lib.hasInfix "type filter hook prerouting priority raw;" overlayRules)
      "rendered ruleset:\n${overlayRules}")

    # Masquerade is v4-only by design: NATing an advertised v6 prefix would
    # destroy the end-to-end addressing that is the reason to advertise it.
    (check "overlay/masquerades-v4-only"
      (lib.hasInfix "ip saddr 192.0.2.0/24 oifname \"wt0\" masquerade" overlayRules
        && !(lib.hasInfix "ip6 saddr 2001:db8:42::/64 oifname \"wt0\" masquerade" overlayRules))
      "rendered ruleset:\n${overlayRules}")

    # v6 forwarding must not be enabled unless a v6 prefix is actually
    # advertised -- turning on a forwarding plane this module writes no rules
    # for is strictly worse than leaving it off.
    (check "overlay/v6-forwarding-follows-a-v6-route"
      ((overlayCfg.boot.kernel.sysctl."net.ipv6.conf.all.forwarding" or null) == 1)
      "sysctl: ${builtins.toJSON overlayCfg.boot.kernel.sysctl}")

    (check "overlay/unit-survives-a-firewall-restart"
      (lib.elem "firewall.service"
        (overlayCfg.systemd.services.nixnet-overlay-firewall.partOf or [ ]))
      "partOf: ${builtins.toJSON (overlayCfg.systemd.services.nixnet-overlay-firewall.partOf or null)}")
  ];

  # A second evaluation proving the v6 forwarding sysctl is NOT set when only
  # v4 is advertised. Without this, the check above would pass just as happily
  # against a module that turned v6 forwarding on unconditionally.
  overlayV4OnlyCfg = evalModules [
    overlayModule
    (moduleDir + "/netbird-access-model.nix")
    (moduleDir + "/netbird-group-reconcile.nix")
    {
      nixnet.overlay = {
        enable = true;
        managementUrl = "https://mesh.example.com";
        hostname = "router";
        setupKeyFile = "/run/secrets/nixnet-overlay-key";
        advertiseRoutes = [ "192.0.2.0/24" ];
        confineExternalRanges = [ "198.51.100.192/26" ];
      };
      nixnet.netbirdAccessModel = {
        enable = true;
        internalGroup = "internal";
        groups.internal.description = "All internally managed peers.";
        audit.apiUrl = "https://mesh.example.com/api";
      };
      nixnet.netbirdGroupReconcile = {
        enable = true;
        apiUrl = "https://mesh.example.com/api";
      };
    }
  ];

  overlayV4OnlyResults = [
    (check "overlay/v4-only-does-not-enable-v6-forwarding"
      (!(overlayV4OnlyCfg.boot.kernel.sysctl ? "net.ipv6.conf.all.forwarding"))
      "sysctl: ${builtins.toJSON overlayV4OnlyCfg.boot.kernel.sysctl}")

    (check "overlay/v4-only-renders-no-v6-chain"
      (!(lib.hasInfix "ext-confine-v6" overlayV4OnlyCfg.nixnet.overlay.ruleset))
      "rendered ruleset:\n${overlayV4OnlyCfg.nixnet.overlay.ruleset}")
  ];

  # The access-model is exported as a standalone NixOS module. Its optional
  # integration with group reconciliation must not make that export depend on
  # importing the sibling module, while still supplying the shared default
  # when both are present.
  accessModelResults = [
    (check "netbird-access-model/imports-standalone"
      (!(overlayCfg.nixnet ? netbirdGroupReconcile)
        && overlayCfg.nixnet.netbirdAccessModel.internalGroup == "internal")
      "standalone module unexpectedly requires or defines nixnet.netbirdGroupReconcile")

    (check "netbird-access-model/defaults-reconciler-catch-all"
      (overlayV4OnlyCfg.nixnet.netbirdGroupReconcile.catchAllGroup == "internal")
      "catchAllGroup: ${builtins.toJSON overlayV4OnlyCfg.nixnet.netbirdGroupReconcile.catchAllGroup}")
  ];

  ingressTunnelId = "00000000-0000-0000-0000-000000000001";
  ingressTunnel = overlayCfg.services.cloudflared.tunnels.${ingressTunnelId};
  ingressResults = [
    (check "ingress/uses-native-edge-ip-option"
      (ingressTunnel.edgeIPVersion == "6")
      "edgeIPVersion: ${builtins.toJSON ingressTunnel.edgeIPVersion}")

    (check "ingress/uses-native-transport-option"
      (ingressTunnel.protocol == "http2")
      "protocol: ${builtins.toJSON ingressTunnel.protocol}")

    (check "ingress/dns-reconciler-waits-for-token-mount"
      (lib.elem "/run/secrets/cloudflare-api-token"
        (lib.toList (overlayCfg.systemd.services.nixnet-ingress-dns-reconcile.unitConfig.RequiresMountsFor or [ ])))
      "RequiresMountsFor: ${builtins.toJSON (overlayCfg.systemd.services.nixnet-ingress-dns-reconcile.unitConfig.RequiresMountsFor or null)}")
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

  # ---------------------------------------------------------------------
  # firewall: the whole eval-time suite for modules/firewall.nix, which
  # lives in experiments/render-check.nix and until now ran nowhere.
  #
  # That file is the ONLY test of the firewall's derivations and refusals
  # -- the DHCP accepts appearing when a host declares `addressing.v4 =
  # "dhcp"` AND being absent when it does not, the confinement CIDRs, the
  # anti-lockout refusal, the typo refusal, the two-tables collision -- and
  # it was reachable only by hand, from a command line in the README. CI
  # ran `nix flake check`, `nix flake check` never imported it, so every
  # one of those assertions was decoration. The three firewall behaviours
  # that DO have VM tests (FW-2, FW-3, OWN-1) cover none of the refusals,
  # because a refusal's whole point is that it happens on the build host
  # and no machine ever boots.
  #
  # Imported here rather than moved, to keep this the smallest change that
  # closes the gap; experiments/ describes itself as disposable, so the
  # file's real home is checks/, and moving it is a follow-up that must not
  # be the thing blocking these assertions from running.
  #
  # Every attribute it exposes is a boolean; `ok` is their conjunction and
  # is skipped here so a failure reports the individual claim by NAME
  # rather than as one opaque false.
  renderCheck = import ../experiments/render-check.nix {
    inherit nixpkgs;
    system = pkgs.stdenv.hostPlatform.system;
  };

  firewallResults = map
    (n: check "firewall/${n}" renderCheck.${n} "experiments/render-check.nix: ${n} is false")
    (builtins.filter (n: n != "ok") (builtins.attrNames renderCheck));

  allResults = results ++ meshGatewayResults ++ overlayResults ++ overlayV4OnlyResults
    ++ accessModelResults ++ ingressResults ++ sourceResults ++ firewallResults;

  failed = builtins.filter (r: !r.ok) allResults;

  report = lib.concatMapStringsSep "\n" (r: "  - ${r.name}: ${r.detail}") failed;

  # Constructing this derivation depends on `passedCount`, which forces
  # `results` (and therefore every `check` assertion above) even if
  # nothing else ever reads the attribute -- so the checks really do run,
  # not just get defined.
  #
  # The throw is scoped to THIS attribute, deliberately. It used to sit at
  # the file's top level, where one failing eval assertion aborted
  # evaluation of the whole checks output -- including the VM tests, which
  # then reported nothing at all about a machine that may well have been
  # fine. A failing check should cost you that check.
  evalChecks =
    if failed != [ ]
    then
      throw ''
        nixnet eval-checks FAILED (${toString (builtins.length failed)}/${toString (builtins.length allResults)}):
        ${report}
      ''
    else
      pkgs.runCommand "nixnet-eval-checks"
        { passedCount = toString (builtins.length allResults); }
        ''
          echo "all $passedCount nixnet eval checks passed"
          touch $out
        '';

  vm = import ./vm { inherit pkgs nixpkgs moduleDir; };
in
{
  eval-checks = evalChecks;

  # TEST-1: the id sets on both sides of the contract, compared. Fed the
  # behaviour ids the VM tests actually claim, so a test that is deleted or
  # renamed shows up here as an unwaived behaviour rather than as silence.
  behaviour-coverage = import ./coverage.nix {
    inherit pkgs;
    behaviorsFile = ../BEHAVIORS.md;
    inherit (vm) covered;
  };
}
// vm.checks
