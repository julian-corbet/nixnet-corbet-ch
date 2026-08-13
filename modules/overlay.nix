# modules/overlay.nix
#
# nixnet.overlay — turn THIS host into a self-hosted NetBird overlay client,
# optionally the network's ONE routing peer (advertising a LAN so
# client-less devices on it become reachable from the overlay without their
# own NetBird install).
#
# Distinct from `netbird-provider.nix` (`nixnet.netbird`): that module
# contributes a PEER TRANSPORT into nixnet's own peer/uplink failover engine
# (core.nix) for a peer this host wants to REACH. This module is the other
# half of the same underlying tool — making THIS host a NetBird peer at
# all, and (optionally) the gateway other LAN devices are reached through.
# A host commonly wants both: enrolled via `nixnet.overlay`, then a specific
# remote peer's health/reprovisioning handled via `nixnet.netbird`.
#
# Wraps upstream `services.netbird` — never reimplements NetBird's own
# install/config management, the same boundary every provider in this repo
# draws (docs/providers.md's "What a provider MUST do" section).
{ config, lib, options, pkgs, ... }:

let
  cfg = config.nixnet.overlay;
  tl = import ../lib/tooling.nix { inherit lib; };
  q = lib.escapeShellArg;

  stripPort = url:
    let match = builtins.match "(.*):[0-9]+" url;
    in if match == null then url else builtins.head match;

  # This module writes an nftables table of its own (below), so it owes the host the same thing
  # modules/firewall.nix does: the means to READ that table. The failure is not hypothetical — a
  # production host was enforcing THIS module's `inet nixnet-overlay` table with no `nft` installed
  # anywhere on it. `applyScript` runs nft from a store path, so the table went up and stayed up
  # and nothing complained; the operator simply had no way to ask whether the confinement was
  # still there. lib/tooling.nix names the tool per backend, `null` included.
  tooling = tl.resolve { inherit pkgs options; names = cfg.tooling; };

  # An address family is decided per-entry rather than per-option, so one
  # `advertiseRoutes` list can carry both families and each rule lands in the
  # right half of a single `inet` table.
  isV6 = s: lib.hasInfix ":" s;
  v4Routes = lib.filter (c: !isV6 c) cfg.advertiseRoutes;
  v6Routes = lib.filter isV6 cfg.advertiseRoutes;

  # `confineExternalAllow` takes bare host addresses; nft wants a prefix
  # length on a set-free comparison to be unambiguous, and a bare address
  # compares fine, so pass it through untouched and only pick the matcher.
  daddr = a: if isV6 a then "ip6 daddr ${a}" else "ip daddr ${a}";
  saddr = a: if isV6 a then "ip6 saddr ${a}" else "ip saddr ${a}";

  tableName = "nixnet-overlay";

  # The table and the NetBird tunnel are kernel-backed parts of this module's
  # contract.  Loading these in both initrd and stage 2 matters on a systemd
  # initrd: its modules-load unit remains active across switch-root, so a
  # stage-2 declaration alone does not get another attempt before this unit
  # starts.  Keep the list unconditional because the disabled generation owns
  # teardown of a table left by the enabled generation.
  overlayKernelModules = [
    "af_packet"
    "nfnetlink"
    "nf_conntrack"
    "nf_tables"
    "nf_nat"
    "nft_chain_nat"
    "nft_masq"
    "tun"
  ];

  overlayRulesActive = cfg.enable && cfg.advertiseRoutes != [ ];

  indent = n: lib.concatMapStringsSep "\n" (l: "    ${l}") n;

  # Confinement is built PER ADDRESS FAMILY, and that is not cosmetic: a
  # confined v4 source range can only ever match v4 packets, so putting a v6
  # destination drop in the chain it jumps to yields a rule nothing can
  # reach. Mixing them reads like v6 is covered while leaving it wide open.
  # Each family gets its own chain holding only its own allowances and
  # drops, and each confined range jumps to the chain of its own family.
  confinedRanges = cfg.confineExternalRanges;
  confinedV4 = lib.filter (r: !isV6 r) confinedRanges;
  confinedV6 = lib.filter isV6 confinedRanges;

  confineChain = fam: allowed: routes: ''
  chain ext-confine-${fam} {
${indent (map (h: "${daddr h} return") allowed ++ map (c: "${daddr c} drop") routes)}
  }
'';

  v4Confine = lib.optionalString (confinedV4 != [ ])
    (confineChain "v4" (lib.filter (a: !isV6 a) cfg.confineExternalAllow) v4Routes);
  v6Confine = lib.optionalString (confinedV6 != [ ])
    (confineChain "v6" (lib.filter isV6 cfg.confineExternalAllow) v6Routes);

  confineJumps =
    map (r: "iifname \"${cfg.overlayInterface}\" ${saddr r} jump ext-confine-v4") confinedV4
    ++ map (r: "iifname \"${cfg.overlayInterface}\" ${saddr r} jump ext-confine-v6") confinedV6;

  confineRules = lib.optionalString (confinedRanges != [ ]) ''
${v4Confine}${v6Confine}
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
${indent confineJumps}
  }
'';

  # IPv4 only, deliberately. Masquerading IPv6 would break the end-to-end
  # addressing that is the entire reason to advertise a v6 prefix at all --
  # a v6 LAN reachable from the overlay wants its real source address, not
  # this peer's. If a v6 route is advertised it is confined by the same
  # table above and simply not source-NATed.
  snatRules = lib.optionalString (v4Routes != [ ]) ''
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
${indent (map (c: "ip saddr ${c} oifname \"${cfg.overlayInterface}\" masquerade") v4Routes)}
  }
'';

  ruleset = ''
table inet ${tableName} {
${confineRules}${snatRules}}
'';

  # The atomic replace idiom: declare the table (a no-op when it already
  # exists), delete it, then define it for real -- all inside ONE `nft -f`
  # transaction, so the ruleset is never observably half-applied and no
  # chain can outlive a rename. That last property is why this module no
  # longer needs teardown commands that mirror the setup commands by name:
  # the previous generation's chains are destroyed wholesale, whatever they
  # were called. Name-coupled teardown is what leaked an orphan chain the
  # last time one of these was renamed.
  applyScript = pkgs.writeShellApplication {
    name = "nixnet-overlay-firewall-apply";
    runtimeInputs = [ pkgs.nftables pkgs.iptables ];
    text = ''
      nft -f - <<'NFT_EOF'
      table inet ${tableName} {}
      delete table inet ${tableName}
      ${ruleset}
      NFT_EOF

      # One-time migration cleanup. Before this module owned its own table,
      # the confinement was an iptables chain installed through
      # networking.firewall.extraCommands. A host switching to this version
      # still has that chain and its jump sitting in raw PREROUTING, where
      # nothing declarative will ever remove them again -- extraStopCommands
      # only ran for the generation that declared them. Idempotent, and a
      # no-op on any host that never ran the older version.
      # The jump is deleted by rewriting whatever `-S` reports rather than by
      # reconstructing the rule from current config: the chain was installed
      # by an EARLIER generation, whose source range is not necessarily the
      # one configured now (and, after the option became a list, is not even
      # expressible as one value). Matching on the target name is what makes
      # this work regardless of what the old rule looked like -- and is
      # exactly the property whose absence let a renamed chain leak in the
      # first place.
      # `legacyChains` extends the same treatment to a chain some OTHER
      # config created and can no longer reach -- see that option's own
      # description for why an abandoned extraCommands chain is unremovable
      # by any later generation.
      # NOTE the ordering above: the nft table is applied BEFORE any of this
      # runs, so a failure in the cleanup below can never leave the host
      # without its confinement. That is deliberate -- the cleanup is
      # housekeeping for a chain that is already redundant, and must never
      # be able to take the actual rules down with it.
      if command -v iptables >/dev/null 2>&1; then
        cleanup_legacy_chain() {
          local chain="$1"
          # Collected into a variable with `|| true` rather than piped
          # straight into the loop: this script runs under `set -o pipefail`
          # (writeShellApplication), and grep exits 1 when a chain has no
          # jumps left -- which is the NORMAL steady state once a chain has
          # already been cleaned. Piping directly made the whole script exit
          # 1 on the second and every subsequent apply, so the unit failed
          # permanently the moment its own cleanup had succeeded once.
          jumps=$(iptables -t raw -S PREROUTING 2>/dev/null \
            | grep -- "-j $chain\$" \
            | sed 's/^-A /-D /' || true)
          if [ -n "$jumps" ]; then
            printf '%s\n' "$jumps" | while read -r rule; do
              # shellcheck disable=SC2086 # the rule is a pre-split argv line
              iptables -t raw $rule 2>/dev/null || true
            done
          fi
          iptables -t raw -F "$chain" 2>/dev/null || true
          iptables -t raw -X "$chain" 2>/dev/null || true
        }

        cleanup_legacy_chain NIXNET-EXT-CONFINE
        ${lib.concatMapStringsSep "\n" (chain: "cleanup_legacy_chain ${lib.escapeShellArg chain}") cfg.legacyChains}
      fi
    '';
  };

  teardownScript = pkgs.writeShellApplication {
    name = "nixnet-overlay-firewall-teardown";
    runtimeInputs = [ pkgs.nftables ];
    text = ''
      nft -f - <<'NFT_EOF'
      table inet ${tableName} {}
      delete table inet ${tableName}
      NFT_EOF
    '';
  };
in
{
  options.nixnet.overlay = {
    enable = lib.mkEnableOption "NetBird overlay client on this host";

    managementUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://netbird.example.com";
      description = "Self-hosted NetBird management URL.";
    };

    hostname = lib.mkOption {
      type = lib.types.str;
      description = "NetBird peer name (the identity this host enrolls under).";
      example = "host-b";
    };

    setupKeyFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to a file containing a NetBird setup key (reusable). Used once
        for headless enrollment; after that the stored config carries the
        peer.
      '';
      example = "/run/secrets/netbird-setup-key";
    };

    advertiseRoutes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "192.0.2.0/24" ]; # TEST-NET-1 placeholder LAN CIDR
      description = ''
        LAN CIDRs this peer makes reachable from the overlay (routing
        peer). The route object itself is created account-side via the
        NetBird API and bound to this peer; here we only enable the kernel
        forwarding it needs.
      '';
    };

    confineExternalRanges = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "198.51.100.0/28" ]; # TEST-NET-2 placeholder overlay CIDR
      description = ''
        Overlay CIDRs of UNTRUSTED external devices (a least-trust group).
        On the routing peer, traffic from these source ranges to the LAN is
        DROPPED except the hosts in `confineExternalAllow`. Closes the
        blanket accept-from-overlay forward hole a routing peer otherwise
        leaves: route DISTRIBUTION only constrains an honest client — a
        compromised guest can add its own route to the LAN CIDR and reach
        the whole LAN otherwise. The rules hook `prerouting` at `raw`
        priority in this module's own `inet` table, so they run ahead of any
        filter-priority chain and cannot be reordered under NetBird's own
        dynamic rules.

        A LIST, and per address family, because a confined v4 source range
        can only match v4 packets: confining an advertised v6 prefix takes
        its own v6 entry here. Listing only a v4 range while advertising a
        v6 prefix leaves that prefix reachable, so it is an assertion error
        rather than a silent hole.
      '';
    };

    confineExternalAllow = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "192.0.2.125" "192.0.2.126" ];
      description = "LAN hosts the confined external range MAY still reach. Everything else on the LAN is dropped for that range.";
    };

    legacyChains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "OLD-EXT-CONFINE" ];
      description = ''
        Names of iptables chains in the `raw` table left behind by a
        HAND-ROLLED confinement this module has replaced, to be removed on
        every apply.

        Exists because a chain installed through
        `networking.firewall.extraCommands` outlives the generation that
        declared it: teardown only runs for whichever generation is being
        stopped, so once a chain's declaration is gone, nothing declarative
        can ever remove it again and it sits in the ruleset forever.
        Naming it here removes it the declarative way, rather than leaving
        an operator to run `iptables -X` by hand on a live box.

        This module always cleans up its OWN former chain without being
        asked; this option is for a chain some other config created.
        Idempotent and safe to leave set permanently, though once you have
        confirmed the chain is gone it is just noise.
      '';
    };

    ruleset = lib.mkOption {
      type = lib.types.lines;
      readOnly = true;
      description = ''
        The exact nftables text this module will load, rendered from the
        options above. Read-only: set the options, not this.

        Exposed because a rule you cannot read before it is applied is a rule
        you are trusting blind — `nix eval` this on any host to see precisely
        what its overlay confinement and source-NAT amount to, without
        needing an `nft` binary on the box or a switch to have happened.
      '';
    };

    overlayInterface = lib.mkOption {
      type = lib.types.str;
      default = "wt0";
      description = "The NetBird tunnel interface name on this host (upstream default is wt0; a `hardened = true` client uses a different name).";
    };

    tooling = lib.mkOption {
      type = lib.types.listOf (lib.types.enum (lib.attrNames tl.tools));
      default = [ "nft" ];
      description = ''
        Tools for INSPECTING the nftables table this module installs, added to the host.

        The `ruleset` option above lets you read the rules from the BUILD host without an `nft`
        anywhere; this is the other half of that, on the machine actually enforcing them. Defaults
        to `[ "nft" ]` because a host that carries a confinement should be able to answer whether
        it still carries it — a production host enforcing this module's table had no `nft` at all,
        which nothing detects, because applying the table never needs one.

        Same option, same default and same per-backend resolution as `nixnet.firewall.tooling`;
        setting both on one host installs one copy. Set to `[ ]` to opt out where the distro
        already ships the tool. On nix-darwin there is no nftables at all (macOS filters with pf)
        and the selection is reported in `warnings` rather than silently installing nothing.
      '';
    };
  };

  config = lib.mkMerge [
    # Rendered unconditionally, OUTSIDE the enable gate, so a consumer can
    # inspect what enabling this would apply before committing to it.
    {
      nixnet.overlay.ruleset = ruleset;

      boot.initrd.kernelModules = overlayKernelModules;
      boot.kernelModules = overlayKernelModules;

      # This unit deliberately exists in disabled generations too.  A live
      # switch from enabled to disabled must actively remove the table left by
      # the old generation; merely omitting the unit leaves stale packet-path
      # policy behind.  Conversely, there is deliberately NO ExecStop: during
      # an enabled-to-enabled switch, stopping the old unit must preserve the
      # last known-good table until the new atomic nft transaction succeeds.
      systemd.services.nixnet-overlay-firewall = {
        description = "nixnet overlay packet-path rules (own nftables table: ${tableName})";
        after = [ "network-pre.target" "firewall.service" "nftables.service" ];
        wantedBy = [ "multi-user.target" ];
        # Anything that rebuilds the host ruleset can flush this table out from
        # under us -- nixpkgs' own nftables module defaults to `flush ruleset`
        # on every start, which takes every table on the box, not just its own.
        # partOf makes their restart restart us, so the rules come back instead
        # of silently staying gone. Only wired to units this host actually has:
        # a partOf on an absent unit would be dead weight.
        partOf = lib.optional config.networking.firewall.enable "firewall.service"
          ++ lib.optional config.networking.nftables.enable "nftables.service";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = lib.getExe (if overlayRulesActive then applyScript else teardownScript);
        };
      };
    }

    (lib.mkIf cfg.enable {
    services.netbird.enable = true;

    # The means to read the table this module is about to install. `environment.systemPackages` is
    # the same option name under NixOS and under system-manager (the latter buildEnv's it into
    # /run/system-manager/sw and prepends that to PATH), so no backend branch belongs here — the
    # part that varies per backend is the package name, and lib/tooling.nix holds it.
    environment.systemPackages = tooling.packages;

    warnings = lib.optional (tooling.unavailable != [ ])
      (tl.unavailableWarning {
        option = "nixnet.overlay.tooling";
        inherit (tooling) backend unavailable;
      });

    assertions = [
      # Both of these used to be silent no-ops: every firewall rule this
      # module writes is gated on advertiseRoutes, so a confinement declared
      # without one was simply never installed -- the most dangerous possible
      # failure for a rule whose entire job is to deny traffic.
      {
        assertion = cfg.confineExternalRanges == [ ] || cfg.advertiseRoutes != [ ];
        message = ''
          nixnet.overlay.confineExternalRanges is set but advertiseRoutes is empty.
          The confinement only has meaning on a routing peer -- with no advertised
          CIDR there is no LAN traffic to confine, and nothing would be installed.
          Either advertise the LAN this peer routes, or drop the confinement.
        '';
      }
      {
        assertion = cfg.confineExternalAllow == [ ] || cfg.confineExternalRanges != [ ];
        message = ''
          nixnet.overlay.confineExternalAllow lists hosts but confineExternalRanges
          is empty, so there is no confined range for them to be exceptions to.
          These allowances would have no effect.
        '';
      }
      # The half-configured case, and the reason this is an error rather than
      # a warning: a v4-only confinement alongside an advertised v6 prefix
      # reads as "the overlay is confined" while leaving the whole v6 LAN
      # reachable by every external device.
      {
        assertion = cfg.confineExternalRanges == [ ] || v6Routes == [ ] || confinedV6 != [ ];
        message = ''
          nixnet.overlay advertises the IPv6 prefix(es) ${lib.concatStringsSep ", " v6Routes}
          and declares a confinement, but confineExternalRanges contains no IPv6
          range. A v4 source range cannot match v6 packets, so those prefixes would
          be reachable by every external device the confinement is meant to fence
          off. Add the external band's IPv6 range, or stop advertising IPv6 here.
        '';
      }
      {
        assertion = cfg.confineExternalRanges == [ ] || v4Routes == [ ] || confinedV4 != [ ];
        message = ''
          nixnet.overlay advertises the IPv4 CIDR(s) ${lib.concatStringsSep ", " v4Routes}
          and declares a confinement, but confineExternalRanges contains no IPv4
          range, so nothing confines v4 traffic to them.
        '';
      }
    ];

    # A routing peer must forward between the overlay interface and the LAN.
    boot.kernel.sysctl = lib.mkMerge [
      (lib.mkIf (v4Routes != [ ]) { "net.ipv4.ip_forward" = lib.mkDefault 1; })
      # v6 forwarding is enabled ONLY when a v6 prefix is actually advertised.
      # It used to be turned on unconditionally alongside v4 while this module
      # wrote no v6 rules at all, which left a routing peer forwarding IPv6
      # both unconfined and un-NATed -- an open path around the very
      # confinement the v4 side was carefully building. Enabling a forwarding
      # plane you do not filter is strictly worse than not enabling it.
      (lib.mkIf (v6Routes != [ ]) { "net.ipv6.conf.all.forwarding" = lib.mkDefault 1; })
    ];

    # ── The overlay's own packet-path rules, in a table this module owns ──
    #
    # These are NOT host firewall policy (which ports are open, who may
    # administer this box) -- they are the routing-peer mechanism's own
    # requirements: source-NAT so a client-less LAN device can reach out
    # through this peer, and a confinement so an untrusted overlay band
    # cannot reach past the hosts it is allowed. They belong to whoever owns
    # the overlay, which is this module.
    #
    # They used to be installed through networking.firewall.extraCommands.
    # That coupled a mechanism to a policy module AND to one specific
    # backend: extraCommands is honoured only by the iptables backend, so on
    # a host whose firewall is nftables-backed it is an eval error, and on a
    # host with networking.firewall disabled entirely -- the configuration
    # every nftables-native firewall project requires -- these rules are
    # discarded with NO ERROR AT ALL. Silently losing a deny rule is the
    # worst failure mode available, and it was one `mkForce false` away on
    # any host that adopted such a firewall.
    #
    # An owned `inet` table sidesteps all of it. nftables lets several tables
    # hook the same point and runs them all, so this coexists with the
    # nixpkgs firewall (either backend), with a third-party nftables
    # ruleset, and with NetBird's own tables, without any of them needing to
    # know this exists. One `inet` table also covers v4 and v6 together,
    # which is what makes confining an advertised v6 prefix possible at all.
    # ── LAN → overlay egress SOURCE-NAT ──────────────────────────────────
    # advertiseRoutes gives the OVERLAY reach INTO the LAN (overlay peer →
    # LAN device). The REVERSE — a client-less LAN device reaching OUT to
    # an overlay peer by routing through this peer — needs one thing
    # NetBird does NOT add: a source-NAT, so the overlay sees the traffic
    # as THIS peer (which is a real, enrolled peer) and the reply routes
    # back. FORWARDING itself is already permitted — NetBird, as a routing
    # peer, blanket-accepts inbound-from-overlay in the FORWARD chain — so
    # no explicit forward rule is needed for reachability. That blanket
    # accept is also why untrusted externals need confineExternalRanges
    # above (a source-scoped raw-PREROUTING DROP, layer-agnostic). Gated
    # on advertiseRoutes so only a routing peer carries it; idempotent -C
    # guard.
    # ── Headless enrollment ──────────────────────────────────────────────
    # One-shot: reconnect an existing identity first, and use the setup key
    # only when that cannot recover. Skips when management is already connected
    # to the declared endpoint.
    # Ordered after the netbird daemon + network so `netbird up` can reach
    # the management server. Note: `nixnet.netbird`'s own reprovisioning
    # (netbird-provider.nix) is a stricter, LOUDLY-failing alternative to
    # this same job for a host that also wants active drift detection. This
    # oneshot only runs at unit start; failures are loud and retry every 30s.
    systemd.services.nixnet-overlay-enroll = {
      description = "Enroll ${cfg.hostname} into NetBird (${cfg.managementUrl})";
      after = [ "netbird.service" "network-online.target" ];
      wants = [ "netbird.service" "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.netbird pkgs.coreutils pkgs.jq ];
      unitConfig.StartLimitIntervalSec = 0;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        Restart = lib.mkDefault "on-failure";
        RestartSec = lib.mkDefault "30s";
        TimeoutStartSec = "3min";
      };
      script = ''
        set -euo pipefail

        connected_to_expected_management() {
          local status_json mgmt_url normalized
          status_json=$(netbird status --json 2>/dev/null || true)
          mgmt_url=$(jq -r '.management.url // empty' <<<"$status_json" 2>/dev/null || true)
          normalized="$mgmt_url"
          case "''${mgmt_url##*:}" in
            ""|*[!0-9]*) : ;;
            *) normalized="''${mgmt_url%:*}" ;;
          esac
          [ "$(jq -r '.management.connected // false' <<<"$status_json" 2>/dev/null || echo false)" = true ] \
            && { [ -z "$mgmt_url" ] || [ "$normalized" = ${q (stripPort cfg.managementUrl)} ]; }
        }

        wait_connected() {
          for i in {1..30}; do
            connected_to_expected_management && return 0
            sleep 1
          done
          return 1
        }

        # Wait for the daemon socket.
        for i in {1..30}; do
          if netbird status >/dev/null 2>&1; then break; fi
          sleep 1
        done
        if connected_to_expected_management; then
          echo "already enrolled and connected"
          exit 0
        fi

        # Preserve an existing peer identity whenever possible. Re-keying a
        # merely disconnected daemon can create a duplicate peer and orphan
        # routes attached to the original server-side identity.
        if timeout 30 netbird up --management-url ${q cfg.managementUrl} \
            && wait_connected; then
          echo "reconnected existing NetBird identity"
          exit 0
        fi

        if [ ! -r ${q cfg.setupKeyFile} ]; then
          echo "no readable setup key at ${cfg.setupKeyFile}; enrollment cannot proceed" >&2
          exit 1
        fi
        netbird down || true
        # `--setup-key-file`, never `--setup-key "$(cat ...)"`: the latter
        # hands a long-lived, reusable setup key to netbird as an argv
        # element, and /proc/<pid>/cmdline is world-readable on a default
        # Linux host (no hidepid=, no ProtectProc=) -- any local uid could
        # read it and enroll an arbitrary peer into the account. The flag
        # reads the same root-readable file checked just above.
        timeout 30 netbird up \
          --management-url ${q cfg.managementUrl} \
          --setup-key-file ${q cfg.setupKeyFile} \
          --hostname ${q cfg.hostname}
        wait_connected
      '';
    };
    })
  ];
}
