# Eval check for nixnet's firewall: the rendered ruleset, the rules DERIVED from declared facts,
# and the assertions that must refuse a configuration rather than render it.
#
#   nix-instantiate --eval --strict experiments/render-check.nix -A ok
#   nix-instantiate --eval --strict experiments/render-check.nix          # every individual result
#
# Real NixOS evaluations (nixpkgs' own eval-config.nix), not a bare `lib.evalModules` stub — same
# reasoning as checks/default.nix: modules/firewall.nix touches `networking.nftables`,
# `systemd.services` and `environment.systemPackages`, real option surface a hand-rolled stub would
# have to reimplement anyway. It also means `networking.nftables.flushRuleset` below is the value
# nixpkgs' own module computes, not one this file asserts about itself.
#
# BOTH DIRECTIONS, everywhere. A firewall check that only proves rules appear is the dangerous half
# working and the safe half absent: a rule that must NOT be there when the fact is absent, and a
# configuration that must FAIL rather than build, are the assertions that actually matter here.
#
# Also imported by checks/default.nix, so these assertions run under `nix flake check` instead of
# only when someone remembers the command above. That import is a PURE evaluation, which is why
# neither `system` nor `lib` may come from `import nixpkgs { }` here: that path reads
# `builtins.currentSystem`, which does not exist in pure mode, and the whole file would fail to
# evaluate with an error naming impurity rather than a firewall rule. `nixpkgs/lib` needs no
# package set at all, and `system` is a parameter with an impure default that only the standalone
# command line above ever forces.
{ nixpkgs ? <nixpkgs>, system ? builtins.currentSystem }:
let
  lib = import (nixpkgs + "/lib");
  rs = import ../lib/ruleset.nix { inherit lib; };

  # The minimal-but-complete NixOS baseline every evaluation needs (same shape checks/default.nix
  # uses).
  baseline = {
    boot.loader.grub.enable = false;
    fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
    system.stateVersion = "25.05";
    # Not tidiness, and asserted by the module: nixpkgs' firewall is a second default-drop input
    # chain at the same hook, and it emits its own DHCP and ICMP accepts — which would make the
    # derivation under test here indistinguishable from a constant.
    networking.firewall.enable = false;
  };

  eval = extra: (import (nixpkgs + "/nixos/lib/eval-config.nix") {
    inherit system;
    modules = [ ../modules/core.nix baseline extra ];
  }).config;

  # Evaluating `assertions` is not enough — they are inert data until something checks them. This
  # mirrors what the module system does at build time, so a missing or renamed assertion actually
  # fails this check. Narrowed to nixnet's own: an unrelated nixpkgs assertion firing on the
  # baseline would otherwise be indistinguishable from the one under test.
  failed = cfg:
    map (a: a.message)
      (lib.filter (a: !a.assertion && lib.hasInfix "nixnet" a.message) cfg.assertions);

  # A refusal check that counts is a refusal check that can pass on the WRONG refusal. Each negative
  # case below therefore names the assertion it expects, by a phrase only that message carries.
  firesWith = cfg: infix:
    let msgs = failed cfg; in
    lib.length msgs == 1 && lib.hasInfix infix (lib.head msgs);

  # The management interface, declared as a fact on every host below: the overlay tunnel, static v4,
  # no v6. `unmanaged` would do as well — what matters is that SOMETHING was said.
  mgmtIface = { addressing = { v4 = "static"; v6 = "none"; }; };

  firewallBase = {
    enable = true;
    management.interfaces = [ "wt0" ];
    allow = [
      { protocol = "tcp"; ports = [ 22 ]; sourcesV4 = [ "198.51.100.0/24" ]; comment = "ssh from LAN"; }
      { protocol = "udp"; ports = [ 51820 ]; sourcesV4 = [ "198.51.100.0/24" ]; comment = "wireguard"; }
    ];
    silentDrops = [{ match = "udp dport 5355"; comment = "LLMNR"; }];
  };

  # ── DIRECTION 1: the host DECLARES DHCP addressing ────────────────────────────────────────────
  dhcpHost = eval {
    nixnet.interfaces = {
      wt0 = mgmtIface;
      eth0.addressing = { v4 = "dhcp"; v6 = "dhcp"; };
    };
    nixnet.firewall = firewallBase;
  };
  dhcpRules = dhcpHost.nixnet.firewall.ruleset;

  # ── DIRECTION 2: the same host, statically addressed ──────────────────────────────────────────
  staticHost = eval {
    nixnet.interfaces = {
      wt0 = mgmtIface;
      eth0.addressing = { v4 = "static"; v6 = "none"; };
    };
    nixnet.firewall = firewallBase;
  };
  staticRules = staticHost.nixnet.firewall.ruleset;

  # ── DIRECTION 3: SLAAC is not DHCPv6 ──────────────────────────────────────────────────────────
  # A v6 address configured by router advertisement needs no accept of its own: RAs are ICMPv6,
  # which the preamble accepts unconditionally. An accept here would be a rule with no fact behind
  # it, which is the habit this whole module exists to break.
  slaacHost = eval {
    nixnet.interfaces = {
      wt0 = mgmtIface;
      eth0.addressing = { v4 = "static"; v6 = "slaac"; };
    };
    nixnet.firewall = firewallBase;
  };
  slaacRules = slaacHost.nixnet.firewall.ruleset;

  # Strip comments before testing for destructive directives or absent rules. The module's own
  # header EXPLAINS that it never flushes and WHY the DHCP accepts exist, and a naive substring test
  # matched that prose — reporting a catastrophic operation that was not there, and a rule that was
  # only mentioned. Tests over generated code must read the code, not the commentary.
  codeOf = rules: lib.concatStringsSep "\n"
    (lib.filter (l: !(lib.hasPrefix "#" (lib.strings.trim l)))
      (lib.splitString "\n" rules));

  dhcpCode = codeOf dhcpRules;
  staticCode = codeOf staticRules;
  slaacCode = codeOf slaacRules;

  # The same host with the firewall turned off: the module still has to answer for the table.
  disabledHost = eval {
    nixnet.interfaces.wt0 = mgmtIface;
    nixnet.firewall.enable = false;
  };

  # nixpkgs' own firewall left on alongside this one.
  conflicting = eval {
    networking.firewall.enable = lib.mkForce true;
    nixnet.interfaces.wt0 = mgmtIface;
    nixnet.firewall = { enable = true; management.interfaces = [ "wt0" ]; };
  };

  # ── The refusals ──────────────────────────────────────────────────────────────────────────────
  lockout = eval {
    nixnet.interfaces.wt0 = mgmtIface;
    nixnet.firewall.enable = true; # no management interface, no trusted interface
  };

  typo = eval {
    nixnet.interfaces.wt0 = mgmtIface;
    nixnet.firewall = { enable = true; management.interfaces = [ "wt1" ]; };
  };

  unstatedAddressing = eval {
    nixnet.interfaces.wt0 = { }; # declared, but nobody said how it is addressed
    nixnet.firewall = { enable = true; management.interfaces = [ "wt0" ]; };
  };

  noPortsAtAll = eval {
    nixnet.interfaces.wt0 = mgmtIface;
    nixnet.firewall = {
      enable = true;
      management.interfaces = [ "wt0" ];
      allow = [{ comment = "forgot the ports"; }];
    };
  };

  # ── Rate-limited management ───────────────────────────────────────────────────────────────────
  # The unconditional accept must be GONE, replaced by a rate-limited accept plus an explicit drop
  # for anything over it. Both directions matter — a module that adds the rate-limit line but leaves
  # the old unconditional accept in place has shipped no protection at all.
  rateLimited = eval {
    nixnet.interfaces.enp1s0.addressing = { v4 = "dhcp"; v6 = "none"; };
    nixnet.firewall = {
      enable = true;
      management = { interfaces = [ "enp1s0" ]; rateLimitNew = "6/minute"; };
    };
  };
  rateLimitedRules = rateLimited.nixnet.firewall.ruleset;

  # ── Port ranges ───────────────────────────────────────────────────────────────────────────────
  ranged = eval {
    nixnet.interfaces.wt0 = mgmtIface;
    nixnet.firewall = {
      enable = true;
      management.interfaces = [ "wt0" ];
      allow = [
        { protocol = "udp"; portRanges = [{ from = 49160; to = 49360; }]; comment = "turn relay"; }
        { protocol = "tcp"; ports = [ 80 ]; portRanges = [{ from = 8000; to = 8010; }]; comment = "mixed"; }
      ];
    };
  };
  rangedRules = ranged.nixnet.firewall.ruleset;

  # ── The routing peer: two nixnet tables on one host ───────────────────────────────────────────
  # Everything the confinement derivation needs is already declared for other reasons: the octet
  # band that decides group membership, and which band is the least-trust one.
  routingPeer = extra: eval {
    imports = [
      ../modules/overlay.nix
      ../modules/netbird-group-reconcile.nix
      extra
      {
        nixnet.interfaces = {
          wt0 = mgmtIface;
          eth0.addressing = { v4 = "dhcp"; v6 = "none"; };
        };

        nixnet.overlay = {
          enable = true;
          managementUrl = "https://overlay.example.org";
          hostname = "host-a";
          setupKeyFile = "/run/secrets/nixnet-setup-key";
          advertiseRoutes = [ "192.0.2.0/24" ]; # TEST-NET-1 placeholder LAN
        };

        nixnet.netbirdGroupReconcile = {
          enable = true;
          apiUrl = "https://overlay.example.org/api";
          catchAllGroup = "internal";
          bands = [
            { min = 0; max = 15; name = "external"; }
            { min = 80; max = 95; name = "management"; }
          ];
          excludeFromCatchAll.forBand = "external";
        };

        nixnet.firewall = {
          enable = true;
          management.interfaces = [ "wt0" ];
          forward.enable = true;
          overlayConfinement.network = "198.51.100.0/24"; # TEST-NET-2 placeholder overlay space
        };
      }
    ];
  };

  peer = routingPeer { };
  peerRules = peer.nixnet.firewall.ruleset;

  # The operator overrides the derivation with a NARROWER range: .0/29 instead of the band's .0/28.
  # Nothing fails at runtime — the rules that exist are correct, and the peers in .8-.15 are simply
  # not confined.
  peerDisagreeing = routingPeer {
    nixnet.overlay.confineExternalRanges = lib.mkForce [ "198.51.100.0/29" ];
  };

  # Both modules replacing the SAME table: whichever applies second deletes the other's chains.
  peerTableCollision = routingPeer {
    nixnet.firewall.table = lib.mkForce "nixnet-overlay";
  };

  # The SAME collision with the firewall DISABLED — which is the MORE dangerous case, not the safe
  # one, and was unasserted while this check lived under `mkIf cfg.enable`. `nixnet-firewall.service`
  # exists in every generation on purpose (`enable = false` has to mean the table is GONE, not
  # unmentioned), and with the firewall off its ExecStart is the teardown:
  # `nft "add table inet <table>; delete table inet <table>"`. Point `table` at the overlay's name,
  # turn the firewall off, and that runs once per boot against the overlay's confinement and
  # source-NAT — deleting both, silently, with the unit green and nothing declarative left that
  # even mentions the table.
  peerTableCollisionDisabled = routingPeer {
    nixnet.firewall.enable = lib.mkForce false;
    nixnet.firewall.table = lib.mkForce "nixnet-overlay";
  };

in
rec {
  # ── DERIVED: the DHCP client accepts ─────────────────────────────────────────────────────────
  # THE regression this whole fold exists for. Present because the host declared DHCP addressing,
  # scoped to the interface that declared it.
  dhcpV4Accept = lib.hasInfix ''iifname "eth0" meta nfproto ipv4 udp sport 67 udp dport 68 accept'' dhcpCode;
  dhcpV6Accept = lib.hasInfix ''iifname "eth0" ip6 daddr fe80::/64 udp dport 546 accept'' dhcpCode;

  # THE OTHER DIRECTION, and the reason this is a derivation rather than a constant: a
  # statically-addressed host must not carry them at all.
  staticHostHasNoDhcpV4 = !(lib.hasInfix "udp dport 68 accept" staticCode);
  staticHostHasNoDhcpV6 = !(lib.hasInfix "udp dport 546 accept" staticCode);

  # SLAAC earns no DHCPv6 accept: router advertisements are ICMPv6, already accepted.
  slaacHasNoDhcpV6 = !(lib.hasInfix "udp dport 546 accept" slaacCode);
  slaacKeepsIcmpV6 = lib.hasInfix "meta l4proto ipv6-icmp accept" slaacCode;

  # Scoped to the interface that declares DHCP, never to the one that does not.
  dhcpScopedToDeclaringInterface = !(lib.hasInfix ''iifname "wt0" meta nfproto ipv4 udp sport 67'' dhcpCode);

  # THE NEGATIVE HALF, and the reason these are two rules rather than nixpkgs' port-pair set:
  # accepting dport 67 would make every DHCP-addressed host reachable as a DHCP SERVER.
  noDhcpServerAccept = !(lib.hasInfix "udp dport 67 accept" dhcpCode);

  # Ordering: the DHCP accepts precede the host's own rules, for the same reason conntrack does — a
  # host must not be able to shadow its own address renewal with a later rule.
  dhcpBeforeHostRules =
    (lib.stringLength (lib.head (lib.splitString "udp dport 68 accept" dhcpRules)))
    < (lib.stringLength (lib.head (lib.splitString "ssh from LAN" dhcpRules)));

  # ── DERIVED: the overlay confinement ─────────────────────────────────────────────────────────
  # The band [0,15] inside the declared /24 is exactly one prefix, and it is computed, not typed.
  confinementDerived = peer.nixnet.firewall.overlayConfinement.ranges == [ "198.51.100.0/28" ];
  # ...and it reaches the module that renders the confinement rules.
  confinementReachesOverlay = peer.nixnet.overlay.confineExternalRanges == [ "198.51.100.0/28" ];
  confinementInOverlayRuleset = lib.hasInfix "ip saddr 198.51.100.0/28 jump ext-confine-v4" peer.nixnet.overlay.ruleset;

  # The generator, directly: an unaligned band renders as several exact CIDRs rather than being
  # rounded out to a prefix that swallows addresses nobody put in that band.
  cidrExactUnaligned = rs.octetRangeToCidrs "198.51.100" 3 9 == [ "198.51.100.3/32" "198.51.100.4/30" "198.51.100.8/31" ];
  cidrWholeTwentyFour = rs.octetRangeToCidrs "198.51.100" 0 255 == [ "198.51.100.0/24" ];
  cidrSingleAddress = rs.octetRangeToCidrs "198.51.100" 7 7 == [ "198.51.100.7/32" ];

  # ── DERIVED: the routed overlay path ─────────────────────────────────────────────────────────
  # A drop-policy forward chain in nixnet's table overrides the accepts in every other table, so a
  # routing peer's own routed traffic dies unless this chain lets it through.
  forwardAcceptsOverlayIn = lib.hasInfix ''iifname "wt0" accept  # nixnet: routed overlay path'' peerRules;
  forwardAcceptsOverlayOut = lib.hasInfix ''oifname "wt0" accept  # nixnet: routed overlay path'' peerRules;
  # Not on a host that never asked for a forward chain.
  noForwardByDefault = !(lib.hasInfix "hook forward" dhcpRules);

  # ── TWO TABLES, ONE HOST ─────────────────────────────────────────────────────────────────────
  peerAgrees = (lib.length (failed peer)) == 0;
  disagreementFires = firesWith peerDisagreeing "does not contain every one of them";
  tableCollisionFires = firesWith peerTableCollision "deletes the other's chains";
  tableCollisionFiresWhenDisabled = firesWith peerTableCollisionDisabled "deletes the other's chains";

  # ── Ported guards ────────────────────────────────────────────────────────────────────────────
  # Management first, and not overridable by the host's own rules — ordering is the whole point.
  mgmtPresent = lib.hasInfix ''iifname "wt0" tcp dport 22 accept'' dhcpRules;
  mgmtBeforeHostRules =
    (lib.stringLength (lib.head (lib.splitString "nixnet: management" dhcpRules)))
    < (lib.stringLength (lib.head (lib.splitString "ssh from LAN" dhcpRules)));

  # Never flush: the single most destructive thing this module could do on a host running k3s — and
  # it has to hold in the DELIVERY too, not just in the text. nixpkgs' nftables module defaults
  # `flushRuleset` to true whenever a raw ruleset is set and concatenates that `flush ruleset` into
  # the same transaction, which would wipe every other table on the box, nixnet's own overlay table
  # included — so this module owns its apply unit instead of delegating to it.
  neverFlushesInText = !(lib.hasInfix "flush ruleset" dhcpCode);
  scopedDelete = lib.hasInfix "delete table inet nixnet" dhcpCode;
  doesNotDelegateToNftablesModule = dhcpHost.networking.nftables.enable == false;

  # One apply unit, named the same on both planes, and it must have NO ExecStop: a changed ruleset
  # makes the switch stop-and-start this unit, and an ExecStop that deleted the table would tear
  # the firewall down before trying to load the new one — so a ruleset that fails to load would
  # leave the host with nothing instead of with the ruleset it had.
  applyUnitExists = dhcpHost.systemd.services ? nixnet-firewall;
  applyUnitHasNoExecStop = !(dhcpHost.systemd.services.nixnet-firewall.serviceConfig ? ExecStop);
  # The unit's own text moves with the rules — the only diff either delivery engine acts on.
  applyKeyedToRuleset =
    dhcpHost.systemd.services.nixnet-firewall.serviceConfig.ExecStart
    != staticHost.systemd.services.nixnet-firewall.serviceConfig.ExecStart;
  # `enable = false` means the table is GONE, not unmentioned: the unit still exists and does the
  # opposite job, so a generation that turns the firewall off cannot leave the previous one's rules
  # loaded in the kernel.
  disabledHostStillTearsDown =
    (disabledHost.systemd.services ? nixnet-firewall)
    && disabledHost.systemd.services.nixnet-firewall.serviceConfig.ExecStart
    != dhcpHost.systemd.services.nixnet-firewall.serviceConfig.ExecStart;
  # Two default-drop input chains at one hook intersect rather than combine.
  nixpkgsFirewallConflictFires = firesWith conflicting "intersect rather than combine";

  # Default deny, conntrack first, loopback matched by name (no load-time ifindex dependency).
  policyDrop = lib.hasInfix "policy drop" dhcpRules;
  conntrackFirst = lib.hasInfix "ct state established,related accept" dhcpRules;
  loopbackByName = lib.hasInfix ''iifname "lo" accept'' dhcpCode;

  v4Matcher = lib.hasInfix "ip saddr 198.51.100.0/24 udp dport 51820 accept" dhcpRules;
  silentDrop = lib.hasInfix "udp dport 5355 drop" dhcpRules;

  # A lone range renders bare (no `{ }`), same as the single-port case; a discrete port plus a range
  # in one rule share ONE set rather than becoming two rule lines.
  bareRange = lib.hasInfix "udp dport 49160-49360 accept" rangedRules;
  mixedSet = lib.hasInfix "tcp dport { 80, 8000-8010 } accept" rangedRules;

  noUnconditionalAccept = !(lib.hasInfix ''iifname "enp1s0" tcp dport 22 accept  #'' rateLimitedRules);
  hasRateLimitAccept = lib.hasInfix ''ct state new limit rate 6/minute accept'' rateLimitedRules;
  hasRateLimitDrop = lib.hasInfix ''ct state new drop  # nixnet: management, rate-limit exceeded'' rateLimitedRules;

  # The dead-man switch is armed by the snapshot path, never by a target that fires on every boot —
  # which is what made the revert fire on every headless boot and delete the firewall outright.
  revertTimerNotWantedByTarget = (dhcpHost.systemd.timers.nixnet-firewall-revert.wantedBy or [ ]) == [ ];
  # The filter is in force before anything brings an interface up.
  applyBeforeNetworkPre = lib.elem "network-pre.target" dhcpHost.systemd.services.nixnet-firewall.before;

  # ── The refusals ─────────────────────────────────────────────────────────────────────────────
  # A config with no way back in must FAIL on the build host, not render and strand the machine.
  lockoutFires = firesWith lockout "no way back in";
  # An interface no host declared matches nothing and fails OPEN — so it never gets that far.
  typoFires = firesWith typo "not declared in `nixnet.interfaces`";
  # "Nobody said how this is addressed" is the state the DHCP outage was made of.
  unstatedAddressingFires = firesWith unstatedAddressing "whose addressing nobody stated";
  noPortsFires = firesWith noPortsAtAll "almost certainly a missing value";
  goodConfigPasses = (lib.length (failed dhcpHost)) == 0;
  staticConfigPasses = (lib.length (failed staticHost)) == 0;

  ok = dhcpV4Accept && dhcpV6Accept
    && staticHostHasNoDhcpV4 && staticHostHasNoDhcpV6
    && slaacHasNoDhcpV6 && slaacKeepsIcmpV6
    && dhcpScopedToDeclaringInterface && noDhcpServerAccept && dhcpBeforeHostRules
    && confinementDerived && confinementReachesOverlay && confinementInOverlayRuleset
    && cidrExactUnaligned && cidrWholeTwentyFour && cidrSingleAddress
    && forwardAcceptsOverlayIn && forwardAcceptsOverlayOut && noForwardByDefault
    && peerAgrees && disagreementFires && tableCollisionFires && tableCollisionFiresWhenDisabled
    && mgmtPresent && mgmtBeforeHostRules
    && neverFlushesInText && scopedDelete && doesNotDelegateToNftablesModule
    && applyUnitExists && applyUnitHasNoExecStop && applyKeyedToRuleset
    && disabledHostStillTearsDown && nixpkgsFirewallConflictFires
    && policyDrop && conntrackFirst && loopbackByName && v4Matcher && silentDrop
    && bareRange && mixedSet
    && noUnconditionalAccept && hasRateLimitAccept && hasRateLimitDrop
    && revertTimerNotWantedByTarget && applyBeforeNetworkPre
    && lockoutFires && typoFires && unstatedAddressingFires && noPortsFires
    && goodConfigPasses && staticConfigPasses;
}
