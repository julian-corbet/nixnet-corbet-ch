# modules/core.nix
#
# nixnet's whole generic engine: nixnet.peers.<name> and
# nixnet.uplinks.<name>, sharing one transport submodule type and
# rendered into one config.json for nixnetd. This file is
# shared verbatim between nixosModules.core and systemManagerModules.core
# (flake.nix) — see the README's "Non-NixOS hosts (via `system-manager`)"
# section for why that's safe: nixnet only ever touches
# environment.etc, systemd.services/timers/paths, and a rendered JSON file,
# none of which system-manager categorically can't reach.
#
# Providers (netbird-provider.nix and friends) never import this file
# directly — they contribute into nixnet.peers/uplinks the same
# way a consumer's own machine config does, via ordinary Nix option
# merging. Core has no provider registry and no provider-specific code;
# see docs/providers.md.

{ lib, config, pkgs, options, ... }:

with lib;

let
  cfg = config.nixnet;

  # ---------------------------------------------------------------------
  # system-manager backend detection (see the README's "Non-NixOS hosts
  # (via `system-manager`)" section). system-manager exposes
  # no `networking.hosts` at all and only a fixed `system.activationScripts.
  # users` stub (not an extensible attrsOf), so both the /etc/hosts merge
  # below and the activation-script seeding mechanism need a system-manager
  # code path. Detected via system-manager's OWN `system-manager.*` option
  # namespace (e.g. `system-manager.allowAnyDistro`), which exists only
  # under system-manager and never under real NixOS -- cheaper and more
  # robust than trying to introspect whether `system.activationScripts` is
  # of an extensible type.
  # ---------------------------------------------------------------------
  isSystemManager = options ? system-manager;

  # ---------------------------------------------------------------------
  # Shared transport submodule — reused verbatim by both
  # peers.<name>.transports and uplinks.<name>.transports. One type, one
  # engine code path: peers and uplinks stay two readable tables sharing
  # one schema, rather than one table with a `kind` discriminator.
  # ---------------------------------------------------------------------
  probeType = types.submodule {
    options = {
      method = mkOption {
        type = types.enum [ "tcp" "icmp" "http" "exec" ];
        default = "tcp";
        description = "How this transport is health-checked each tick.";
      };

      target = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          What to actually probe. For peer transports this defaults to the
          sibling `address` option (see the submodule's own `config` block
          below) — you only need to set it explicitly if it differs from
          `address` (e.g. probing a management port on a different IP than
          the one that gets published). For uplink transports there is no
          such default: `address` is usually left null there, so
          `target` (or `probe.method = "exec"`, which doesn't need one) is
          required — enforced by `assertions` below, not by the type
          system, since both groups share this one submodule.
        '';
      };

      port = mkOption {
        type = types.nullOr types.port;
        default = 22;
        description = "tcp method only.";
      };

      path = mkOption {
        type = types.str;
        default = "/";
        description = "http method only.";
      };

      bindToInterface = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Bind the probe socket to the transport's `interface` via
          SO_BINDTODEVICE, so the health result genuinely reflects that
          NIC rather than whatever route the kernel would otherwise pick.
          Requires CAP_NET_RAW; the module grants it automatically (see
          `needsNetRaw` below) whenever any transport sets this or uses
          `method = "icmp"`.
        '';
      };

      intervalMs = mkOption {
        type = types.ints.positive;
        default = cfg.daemon.defaultProbe.intervalMs;
      };
      timeoutMs = mkOption {
        type = types.ints.positive;
        default = cfg.daemon.defaultProbe.timeoutMs;
      };
      upThreshold = mkOption {
        type = types.ints.positive;
        default = cfg.daemon.defaultProbe.upThreshold;
      };
      downThreshold = mkOption {
        type = types.ints.positive;
        default = cfg.daemon.defaultProbe.downThreshold;
      };

      exec = mkOption {
        # NOT the more obvious `types.path`: the provider contract types
        # `probe.exec` as a command line (docs/providers.md's "What a
        # provider MAY do" section), e.g. `"${script} ${peerName}"` — a full
        # command line (program + argument), not a bare path, which
        # `types.path` cannot represent (it would either fail to coerce
        # or silently only keep the first word, neither of which is what
        # such an assignment intends). Typed `types.str` here instead,
        # documented as "a full command line" throughout, and see
        # nixnetd's `src/probe/exec.rs` for the corresponding
        # no-shell, word-split exec — this preserves the "no PATH
        # dependency, one narrow well-tested exec" property system-manager
        # hosts need just as much as `types.path` would have.
        type = types.nullOr types.str;
        default = null;
        description = ''
          Required when method = "exec". A full command line, already
          resolved to an absolute Nix store path for argv[0] (e.g. a
          `pkgs.writeShellApplication` result concatenated with a space
          and an argument). Run each tick with no shell involved — see
          docs/providers.md's "What a provider MAY do" section.
        '';
      };
    };
  };

  transportType = types.submodule ({ config, ... }: {
    options = {
      id = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Stable identity for persisted health state within this peer or
          uplink. List order is never identity. When null, nixnetd derives a
          deterministic ID from the path-defining fields (provider,
          interface, address and probe target/method). Set this explicitly
          when two transports intentionally have the same mechanism shape.
        '';
      };

      address = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          A concrete reachable address for this transport. Peer
          transports: required unless supplied dynamically by a
          provider's exec probe (the `address` field of its JSON envelope,
          see docs/providers.md). Uplink
          transports: usually left null — `probe.target` (reached via
          `interface`) is what's actually probed there.
        '';
      };

      interface = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Local egress interface this transport is bound to. Required for
          uplink transports (this is *what* is being selected between —
          enforced by `assertions` below). Optional for peer transports,
          to pin a probe to a specific NIC.
        '';
      };

      priority = mkOption {
        type = types.int;
        description = "Lower number = more preferred, among currently-healthy candidates.";
      };

      providerId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Observability tag only, e.g. \"netbird\". Never read by core logic.";
      };

      probe = mkOption {
        type = probeType;
        default = { };
      };
    };

    # target defaults to address, for every transport (peer or uplink
    # alike — this submodule is shared, see the shared-transport-submodule
    # comment above). For uplinks, address is normally null, so this default
    # just leaves target null too, same as if there were no default at
    # all; the assertion in the parent module is what actually enforces
    # "required for uplinks."
    config = {
      probe.target = mkDefault config.address;
    };
  });

  hysteresisType = types.submodule {
    options.minHoldMs = mkOption {
      type = types.ints.positive;
      default = 10000;
      description = ''
        Once the group's winner changes, no further winner change is
        applied until minHoldMs has elapsed — UNLESS the current winner
        itself has just gone unhealthy (a dead winner is never held onto
        to satisfy a hold timer).
      '';
    };
  };

  # STALE-2. `onAllDown = "lastKnownGood"` keeps publishing an address no
  # probe can confirm any more; without a bound it keeps publishing it
  # forever. Measured on a real estate: one peer published continuously for
  # eleven days across roughly 48,000 consecutive probe failures -- degraded
  # in status.json the whole time, and resolving perfectly for anyone who
  # just asked the resolver, which is everyone. That is not a trade-off
  # between a stale answer and no answer; it is an address that is simply
  # wrong being asserted as fact indefinitely.
  lastKnownGoodType = types.submodule {
    options.maxAgeSec = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      example = 900;
      description = ''
        How long a last-known-good address may keep being published after
        the last successful probe that confirmed it. Past this age the
        entry is REMOVED from the published hosts file (a hosts file
        cannot express "probably wrong", so the only honest alternative to
        a correct answer is no answer) and the peer stays degraded. The
        moment a transport comes back the address is published again --
        this bound expires an entry, it does not blacklist it.

        `null` (the default) means unbounded, which is the defect above.
        It is the default only because no measurement on this estate
        justifies any particular number, and inventing one would be worse
        than making the operator choose: the tolerance belongs to whatever
        consumes the name (a soft-mounted filesystem retries for minutes,
        a discovery path wants the failure immediately). Leaving it null
        warns at eval time, so the unbounded case is at least chosen out
        loud rather than inherited by accident.

        Applies to state restored from disk too, not only to time that
        elapsed while the daemon was running -- see nixnetd's own
        `engine::staleness`. A restart that laundered an old entry into a
        fresh-looking one is how the eleven days above survived every
        restart that might have cleared them.

        Has no effect when `onAllDown = "unpublish"`: nothing is retained
        there, so there is nothing to expire.
      '';
    };
  };

  peerType = types.submodule {
    options = {
      hostnames = mkOption {
        type = types.listOf types.str;
        description = ''Names to publish, e.g. [ "host-b" "host-b.mesh.example.com" ].'';
      };
      transports = mkOption {
        type = types.listOf transportType;
        default = [ ];
      };
      hysteresis = mkOption {
        type = hysteresisType;
        default = { };
      };
      onAllDown = mkOption {
        type = types.enum [ "lastKnownGood" "unpublish" ];
        default = "lastKnownGood";
        description = ''
          lastKnownGood: keep publishing the last address that was ever up
          (good for retry-tolerant protocols like a soft-mounted NFS
          share), bounded by `lastKnownGood.maxAgeSec`; the group is
          marked degraded in status.json + the journal. unpublish: remove
          the managed entry entirely so NSS falls through to the next
          source (typically DNS).
        '';
      };
      lastKnownGood = mkOption {
        type = lastKnownGoodType;
        default = { };
        description = "Bounds on how long the `onAllDown = \"lastKnownGood\"` policy may keep publishing an unconfirmable address.";
      };
    };
  };

  # ---------------------------------------------------------------------
  # nixnet.interfaces.<name>: the interface FACT table. Added so a host's
  # NICs are declared in exactly one place -- see this option's own
  # description (below, in options.nixnet) for the fact/policy line this
  # draws, and why it sits beside peers/uplinks despite sharing no engine
  # code with either. `interfaceType` intentionally has the SAME shape
  # (`mac`, `addresses` keyed by role) as nixhost's own hand-declared
  # `netInterfaceSubmodule` -- that shape is simply what an interface fact
  # table needs regardless of which repo states it, not a contortion of
  # nixnet's namespace to please a particular consumer. The namespace
  # PATH stays nixnet's own choice (`nixnet.interfaces`, not e.g.
  # `nixnet.resources.net` mirroring nixhost's tree shape) -- nixhost
  # adapts to the owner via its own defensive-read idiom
  # (`config.nixnet.interfaces or { }`), the owner never contorts itself
  # to shorten the consumer's path.
  # ---------------------------------------------------------------------
  interfaceType = types.submodule {
    options = {
      mac = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "aa:bb:cc:dd:ee:ff";
        description = ''
          This interface's hardware MAC, or `null` (the default) for an
          interface with no stable one worth recording -- an
          overlay-network (NetBird/WireGuard) interface's identity is its
          tunnel key, not a MAC, and forcing a value here would mean
          inventing one just to satisfy the type. Checked below
          (`assertions`) against a six-octet colon-separated hex shape
          whenever set, non-null: a malformed MAC is cheap to catch here
          and expensive to debug at whatever udev rule or device-plugin
          match eventually fails on it downstream.
        '';
      };

      addresses = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = { lan = "192.0.2.10"; overlay = "198.51.100.10"; };
        description = ''
          Every address this interface is DECLARED to answer to, keyed by
          role rather than a fixed column set -- one host's interface has
          one LAN address, another has a LAN address AND an overlay one
          simultaneously, a third has only a dynamic public address
          nothing here needs to name. Add a role by using it.

          This is inventory, not the failover engine's own runtime state,
          and that line is deliberate: an address belongs here only if
          it's known at Nix-eval time as part of this host's declared
          configuration (a static LAN IP, a DHCP reservation, a NetBird
          peer's overlay address pinned via `staticOverlayAddress` on
          THIS host's own enrollment) -- never a value nixnetd discovers
          or arbitrates between at runtime. The two nearest existing
          "address" concepts in this file are NOT the same axis and are
          deliberately left alone rather than folded in here:
            - `transportType.address` / `netbird-provider`'s
              `staticOverlayAddress` describe a REMOTE PEER's reachable
              address, used to pick a winner among competing transports.
              This table describes THIS HOST's own interfaces -- a peer's
              address is that peer's inventory, declared on that peer's
              own host, not a second copy of it here.
            - `uplinks.<name>.transports[].interface` is a bare string
              naming a local egress interface for routing purposes; it
              deliberately carries no attached MAC/address inventory, and
              this table doesn't force one on it either (no assertion
              requires an uplink's `interface` to have a matching entry
              here) -- coupling the two would make declaring an uplink
              transport silently REQUIRE also fully inventorying that
              NIC's addresses, which breaks the "each option group is
              independently usable" property every other part of this
              file preserves (a peers-only install needs no uplinks;
              an uplinks-only install shouldn't need to start
              inventorying interfaces it already names by string).
          Duplicate address values across two different interfaces on
          THIS table are asserted below as a hard error, the same
          "colliding entries in a shared namespace" reasoning
          `peers.*.hostnames`'s own assertion already applies -- a single
          host declaring the identical address on two different NICs is
          overwhelmingly a copy-paste mistake, not a real configuration
          (unlike a genuinely-shared VIP/anycast address, which spans
          *hosts*, not two NICs on the same one, and so never collides
          with this per-host check).
        '';
      };
    };
  };

  looksLikeMac = s: builtins.match "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}" s != null;

  malformedMacs = flatten (mapAttrsToList
    (name: i:
      optional (i.mac != null && !(looksLikeMac i.mac))
        "nixnet.interfaces.${name}.mac = \"${i.mac}\" is not six colon-separated hex octets (e.g. \"aa:bb:cc:dd:ee:ff\").")
    cfg.interfaces);

  # Every (interface, role, address) triple flattened into one list, so
  # duplicate detection below is a single group-by rather than an O(n^2)
  # pairwise comparison across interfaces.
  allInterfaceAddresses = flatten (mapAttrsToList
    (name: i: mapAttrsToList (role: addr: { inherit name role addr; }) i.addresses)
    cfg.interfaces);

  addressOccurrences = foldl'
    (acc: a: acc // { ${a.addr} = (acc.${a.addr} or [ ]) ++ [ "${a.name}.${a.role}" ]; })
    { }
    allInterfaceAddresses;

  duplicateInterfaceAddresses = filterAttrs (_: locs: length locs > 1) addressOccurrences;

  # Validation for `nixnet.interfaces` -- deliberately NOT nested inside
  # `mkIf cfg.enable` below (see where this list is spliced into `config`):
  # a host may declare its own interface inventory purely for a consumer
  # like nixhost to read, with `nixnet.enable = false` and no daemon
  # running at all. Gating these checks behind the daemon's own on/off
  # switch would mean a malformed MAC or a duplicated address on such a
  # host silently evaluates clean, only to surface however the consumer
  # downstream chokes on it instead.
  interfaceAssertions = [
    {
      assertion = malformedMacs == [ ];
      message = ''
        nixnet.interfaces has a malformed mac:
          ${concatStringsSep "\n          " malformedMacs}
        A MAC that doesn't type-check as six colon-separated hex octets
        is worth catching HERE, at eval time -- the alternative is
        whatever downstream consumer (a udev rule, a device-plugin match)
        discovers it first, with a much less specific error.
      '';
    }
    {
      assertion = duplicateInterfaceAddresses == { };
      message = ''
        nixnet.interfaces has the same address declared on more than one
        interface: ${concatStringsSep "; " (mapAttrsToList (addr: locs: "${addr} on ${concatStringsSep ", " locs}") duplicateInterfaceAddresses)}.
        Two different NICs on the SAME host answering to the identical
        address is overwhelmingly a copy-paste mistake, not a real
        configuration (a genuinely-shared address spans hosts, not two
        interfaces on one of them, and so never trips this check) --
        rename or remove one of the entries above.
      '';
    }
  ];

  uplinkType = types.submodule {
    options = {
      transports = mkOption {
        type = types.listOf transportType;
        default = [ ];
      };
      hysteresis = mkOption {
        type = hysteresisType;
        default = { minHoldMs = 15000; };
      };
      publish = {
        routeMetric = mkOption { type = types.bool; default = true; };
        metricBase = mkOption {
          type = types.ints.unsigned;
          default = 100;
          description = "Metric assigned to the current winner.";
        };
        metricStep = mkOption {
          type = types.ints.positive;
          default = 10;
          description = ''
            Metric spacing applied to non-winners, in rank order (healthy
            candidates by priority, then the rest).

            Positive, because the spacing is what makes the ranking a
            ranking: at zero every transport of the subject lands on
            `metricBase` -- N equal-cost default routes the kernel chooses
            between on its own -- and a negative step publishes the least
            preferred transport as the cheapest route.
          '';
        };
      };
    };
  };

  # ---------------------------------------------------------------------
  # Capability computation (see the README's "Security" section): a
  # peers-only install with only
  # TCP/HTTP probes gets no elevated capabilities at all.
  # ---------------------------------------------------------------------
  allTransports =
    (concatMap (p: p.transports) (attrValues cfg.peers))
    ++ (concatMap (u: u.transports) (attrValues cfg.uplinks));

  needsNetAdmin = any (u: u.publish.routeMetric) (attrValues cfg.uplinks);
  needsNetRaw = any (t: t.probe.method == "icmp" || t.probe.bindToInterface) allTransports;

  # ---------------------------------------------------------------------
  # STALE-2, eval half. `unpublish` peers are excluded on purpose: they
  # retain nothing, so there is nothing for a bound to expire and a warning
  # there would be pure noise -- and noise is how a warning that matters
  # stops being read.
  # ---------------------------------------------------------------------
  retainingPeers = filterAttrs (_: p: p.onAllDown == "lastKnownGood") cfg.peers;
  unboundedPeers = attrNames (filterAttrs (_: p: p.lastKnownGood.maxAgeSec == null) retainingPeers);

  # The same bounds, as data the boot seed's own age filter can read (see
  # seedHostsScript below). Only peers that both retain and declared a
  # bound appear; an absent key there means "unbounded", matching the
  # daemon's own reading of a null maxAgeSec.
  seedMaxAgeBounds = mapAttrs (_: p: p.lastKnownGood.maxAgeSec)
    (filterAttrs (_: p: p.lastKnownGood.maxAgeSec != null) retainingPeers);

  # ---------------------------------------------------------------------
  # config.json rendering — the *only* interface between
  # Nix and nixnetd. nixnetd never reads anything else Nix-shaped.
  # ---------------------------------------------------------------------
  renderedConfig = {
    daemon = {
      inherit (cfg.daemon) stateDir runtimeDir;
      hostsFile = cfg.daemon.hostsFile;
      ipPath = "${pkgs.iproute2}/bin/ip";
      defaultProbe = cfg.daemon.defaultProbe;
    };
    peers = mapAttrs
      (_: p: {
        inherit (p) hostnames transports onAllDown lastKnownGood;
        hysteresis = p.hysteresis;
      })
      cfg.peers;
    uplinks = mapAttrs
      (_: u: {
        inherit (u) transports publish;
        hysteresis = u.hysteresis;
      })
      cfg.uplinks;
  };

  configJsonFile = pkgs.writeText "nixnet-config.json" (builtins.toJSON renderedConfig);

  # ---------------------------------------------------------------------
  # nixnet package: nixnetd + nixnetctl. Defined once in ../package.nix,
  # shared with flake.nix's own `packages` output, so there's exactly one
  # rustPlatform.buildRustPackage call in the whole repo.
  # ---------------------------------------------------------------------
  nixnetPackage = pkgs.callPackage ../package.nix { };

  # ---------------------------------------------------------------------
  # Initial hosts seeding: synchronous, so cfg.daemon.hostsFile is NEVER
  # dangling even before nixnetd's first tick. Later activations refresh only
  # the declarative static prefix and preserve the daemon-owned marker block
  # byte-for-byte. Runs as an activation script on NixOS; system-manager has no
  # `networking.*` host options to merge in at all, so the prefix is just
  # the two localhost lines there (see the systemd-oneshot seeding path AND
  # the preActivationAssertions hook below for that backend instead).
  # ---------------------------------------------------------------------
  # The WHOLE static prefix nixpkgs would have written, not a re-derivation
  # of one slice of it. `environment.etc.hosts` is mkForce'd at the bottom of
  # this file to point at cfg.daemon.hostsFile, so whatever this seed does
  # not reproduce is simply GONE from /etc/hosts the moment nixnet.enable is
  # set -- silently, with no warning and no assertion. Rendering
  # `networking.hosts` alone dropped every other contributor to
  # `networking.hostFiles` (which nixpkgs defines as
  # `mkBefore [ localhostHosts stringHosts extraHosts ]`): the user's own
  # `networking.extraHosts`, and modules that append their own file --
  # stevenblack, nixos-containers, kubernetes/pki, and
  # google-compute-config, whose 169.254.169.254 metadata.google.internal
  # mapping `networking.timeServers` then depends on. Handing the whole list
  # to the same `pkgs.concatText` builder nixpkgs itself uses makes the
  # seeded prefix byte-identical to the /etc/hosts this host would have had
  # without nixnet -- which is exactly the contract src/publish/hosts.rs
  # already documents. Concatenating the built files also picks up
  # `networking.enableIPv6 = false` for free (nixpkgs guards its own `::1
  # localhost` line with it; a hardcoded one cannot).
  #
  # No recursion: `networking.hostFiles` is computed from
  # `networking.{hosts,extraHosts,enableIPv6}` and never reads
  # `environment.etc`. system-manager has none of those options, hence the
  # literal fallback there.
  staticPrefixFile =
    if isSystemManager
    then
      pkgs.writeText "nixnet-static-hosts" ''
        127.0.0.1 localhost
        ::1 localhost
      ''
    else pkgs.concatText "nixnet-static-hosts" config.networking.hostFiles;

  seedHostsScript = pkgs.writeShellScript "nixnet-seed-hosts" ''
    set -euo pipefail
    runtime_dir="/run/${cfg.daemon.runtimeDir}"
    mkdir -p "$runtime_dir"
    hosts_dir=$(dirname "${cfg.daemon.hostsFile}")
    mkdir -p "$hosts_dir"
    # hostsFile deliberately lives outside nixnetd's StateDirectory (see the
    # option's own doc comment) specifically so it stays reachable by every
    # other reader on the box. nixnetd is the sole writer, so the directory
    # and file are chowned to its own fixed user/group (nixnetd:nixnetd,
    # declared below) rather than left root-owned -- this script runs as
    # root (a NixOS activation script, or a system-manager oneshot/
    # preActivationAssertion), so it CAN hand ownership to nixnetd directly,
    # and a stable owner is what actually lets nixnetd's own atomic
    # write-tmp-then-rename succeed later (see git history for why the
    # previous approach here -- mode 1777 on the directory, reasoned as
    # "same model as /tmp" -- never worked: that model is backwards. /tmp's
    # sticky bit specifically PREVENTS a non-owner from renaming over
    # another user's file, even with the directory world-writable; it
    # can't grant the opposite of what it's for. A fixed owner is the only
    # way for the daemon to legitimately win that rename against a
    # root-owned file the seed step wrote first).
    #
    # Best-effort, not `|| exit`: on system-manager, this same script also
    # runs once as a `preActivationAssertions` hook (see below), ordered
    # BEFORE user creation -- at that specific early call the "nixnetd"
    # user may not exist yet, so `chown` can legitimately fail there. Never
    # fatal to this script's own job (guaranteeing the file exists, so a
    # `symlinkJoin`/etc-activation reading it never dangles) -- the LATER,
    # correctly-ordered call (the NixOS activation script proper, or
    # system-manager's nixnet-seed-hosts.service, both of which run after
    # users are created) re-chowns it correctly before nixnetd itself ever
    # starts.
    chown nixnetd:nixnetd "$hosts_dir" 2>/dev/null || true
    chmod 0755 "$hosts_dir"

    # `nixnetd` owns the marker block. Activation may need to refresh the
    # declarative static prefix when networking.hosts/hostFiles changed, but
    # it must not reconstruct that block from state.json: the daemon has the
    # authoritative aliases, winner addresses, and confirmation timestamps.
    # Preserve every byte from BEGIN onward (including a foreign suffix) and
    # avoid a replace altogether when the resulting file is unchanged.
    if [ -r "${cfg.daemon.hostsFile}" ] && ${pkgs.gawk}/bin/awk '
      $0 == "# BEGIN nixnet" { begin = 1 }
      begin && $0 == "# END nixnet" { end = 1; exit }
      END { exit !(begin && end) }
    ' "${cfg.daemon.hostsFile}"; then
      tmp=$(mktemp "${cfg.daemon.hostsFile}.seed.XXXXXX")
      trap 'rm -f "$tmp"' EXIT

      {
        cat ${staticPrefixFile}
        ${pkgs.gawk}/bin/awk '
          $0 == "# BEGIN nixnet" { copy = 1 }
          copy { print }
        ' "${cfg.daemon.hostsFile}"
      } > "$tmp"

      if ! ${pkgs.diffutils}/bin/cmp -s "$tmp" "${cfg.daemon.hostsFile}"; then
        mv -f "$tmp" "${cfg.daemon.hostsFile}"
      fi
      chmod 0644 "${cfg.daemon.hostsFile}"
      chown nixnetd:nixnetd "${cfg.daemon.hostsFile}" 2>/dev/null || true
      exit 0
    fi

    tmp=$(mktemp "${cfg.daemon.hostsFile}.seed.XXXXXX")
    trap 'rm -f "$tmp"' EXIT

    {
      cat ${staticPrefixFile}
      echo "# BEGIN nixnet"
      # Best-effort: seed from the last-known-good winners in
      # state.json, if a previous boot left one. Never fatal if missing,
      # unreadable, or jq isn't happy with it — the daemon's first probe
      # tick (within one intervalMs of startup) will correct/populate
      # this regardless.
      #
      # STALE-2 applies HERE too, and this is the copy of the rule that is
      # easiest to forget: this script publishes straight into the hosts
      # file, before nixnetd starts and independent of it. A bound that the
      # daemon honours and the boot seed does not is not a bound — every
      # boot would re-assert the very entry the daemon expired, and the
      # daemon would then leave it alone, because it publishes on CHANGE
      # and an expired entry it never restored is not a change it makes.
      # So the same age judgement runs here, from the same recorded
      # confirmedAt, against the same per-peer bound. A peer with no bound
      # (absent from $bounds) is unbounded, exactly as in the daemon; a
      # bounded peer whose state records no confirmedAt at all cannot be
      # shown to be inside its bound and is therefore dropped.
      #
      # The `|| true` swallows a jq failure on a corrupt state file, which
      # degrades to seeding NOTHING — the safe direction for a file whose
      # only other option is asserting an address nobody can vouch for.
      if [ -r "${cfg.daemon.stateDir}/state.json" ]; then
        ${pkgs.jq}/bin/jq -r --argjson bounds '${builtins.toJSON seedMaxAgeBounds}' '
          .peers // {} | to_entries[]
          | select(.value.lastPublishedAddress != null and .value.lastPublishedAddress != "")
          | select(
              ($bounds[.key] // null) as $bound
              | if $bound == null then true
                else
                  ((.value.confirmedAt // "")
                   | if . == "" then null else (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) end) as $c
                  | $c != null and (now - $c) <= $bound
                end
            )
          | "\(.value.lastPublishedAddress)\t\(.key)"
        ' "${cfg.daemon.stateDir}/state.json" 2>/dev/null || true
      fi
      echo "# END nixnet"
    } > "$tmp"

    mv -f "$tmp" "${cfg.daemon.hostsFile}"
    chmod 0644 "${cfg.daemon.hostsFile}"
    chown nixnetd:nixnetd "${cfg.daemon.hostsFile}" 2>/dev/null || true
  '';

in
{
  # The packet filter is part of this host's network reality, not a neighbouring concern, so it is
  # imported here rather than offered as an opt-in module: a firewall that could be left out is a
  # firewall that can be evaluated without the facts it derives from. It reads `nixnet.interfaces`
  # (declared below) and extends that same submodule with the per-family `addressing` fact -- the
  # fact whose absence, in a separate repo, cost a DHCP-addressed edge host most of a day.
  #
  # Until `nixnet.firewall.enable` this costs exactly one oneshot unit per boot, whose job while
  # disabled is to assert nixnet's nftables table is ABSENT -- so a host that turns the firewall
  # off is never left carrying the previous generation's rules in the kernel.
  imports = [ ./firewall.nix ];

  options.nixnet = {
    enable = mkEnableOption "nixnet transport failover (peer + uplink health-checked publish)";

    package = mkOption {
      type = types.package;
      default = nixnetPackage;
      description = "The nixnetd + nixnetctl package. Override only to pin/patch a build.";
    };

    daemon = {
      stateDir = mkOption { type = types.path; default = "/var/lib/nixnet"; };
      runtimeDir = mkOption { type = types.str; default = "nixnet"; description = "Under /run."; };
      hostsFile = mkOption {
        type = types.path;
        # NOT "${cfg.daemon.stateDir}/hosts" -- found 2026-07-25 in production (now historical:
        # nixnetd no longer runs with DynamicUser=true, see systemd.services.nixnetd below, so the
        # relocation this originally sidestepped can't happen anymore either). At the time,
        # DynamicUser=true made systemd relocate StateDirectory to /var/lib/private/nixnet (a
        # symlinked-from /var/lib/nixnet convenience path) with the shared /var/lib/private/
        # PARENT directory 0700 root:root -- a hardcoded systemd isolation boundary with no
        # per-service override. Any file nixnetd wrote under stateDir inherited that same
        # unreachability for every OTHER process on the box, including systemd-resolved and every
        # plain NSS "files" lookup -- exactly the readers /etc/hosts exists to serve. Kept as a
        # sibling directory outside stateDir regardless of the fix below: nothing needs it moved
        # back, and every consumer's rendered config.json already carries this exact path.
        default = "/var/lib/nixnet-hosts/hosts";
        description = ''
          Where nixnetd actually keeps /etc/hosts's live content --
          environment.etc.hosts.source points here (see the comment on
          that option below). Deliberately under /var/lib (persists across
          reboots), but deliberately NOT nested under stateDir -- see the
          comment on the default above for why. /run is ruled out for the
          same reason it always was: a fresh, empty tmpfs on every single
          boot, so a symlink chain ending there can never resolve until
          something has run *this specific boot* to (re)create it -- and
          on the system-manager backend specifically, nothing has, at the
          point system-manager-engine resolves this symlink (see the
          `system-manager.preActivationAssertions` block at the end of
          this file). Living under /var/lib instead means that
          once this file exists for the first time ever on a given host,
          it never goes missing again across any future boot or
          redeploy, which is what actually makes the system-manager
          `preActivationAssertions` guarantee below sufficient in
          practice, not just on paper.
        '';
      };

      defaultProbe = {
        intervalMs = mkOption { type = types.ints.positive; default = 3000; };
        timeoutMs = mkOption { type = types.ints.positive; default = 800; };
        upThreshold = mkOption { type = types.ints.positive; default = 2; };
        downThreshold = mkOption { type = types.ints.positive; default = 3; };
      };
    };

    peers = mkOption {
      type = types.attrsOf peerType;
      default = { };
      description = "Remote hosts reachable over one or more transports, published into /etc/hosts.";
    };

    uplinks = mkOption {
      type = types.attrsOf uplinkType;
      default = { };
      description = "Local egress choices (wired/wireless/cellular/...), published as route metrics.";
    };

    interfaces = mkOption {
      type = types.attrsOf interfaceType;
      default = { };
      example = literalExpression ''
        { lan0 = { mac = "aa:bb:cc:dd:ee:ff"; addresses.lan = "192.0.2.10"; }; }
      '';
      description = ''
        The network interfaces this host actually has, keyed by a short
        stable name -- a FACT table (this host's own MAC/address
        inventory), independent of `peers`/`uplinks` above (the engine
        that picks a winner AMONG candidate transports at runtime) and of
        any provider. Empty (the default) for a host where no interface
        is worth recording at this path. See `interfaceType`'s own
        comment (above, in this file's `let`) for the fact-vs-policy line
        drawn here and how this reconciles with `transportType.address`
        and `netbird-provider`'s `staticOverlayAddress` rather than
        duplicating either.

        This is the read a domain like nixhost mirrors defensively
        (`config.nixnet.interfaces or { }`) to make a host's NICs
        addressable at its own namespace path without a second,
        independently-maintained copy of this table existing there --
        the same one-way idiom nixhost's own `storage.disks` already
        applies to nixstorage.
      '';
    };
  };

  # `mkMerge` here, rather than folding `interfaceAssertions` into the
  # `mkIf cfg.enable` block below: those checks must fire whenever
  # `nixnet.interfaces` is populated, independent of whether the
  # peer/uplink daemon itself is enabled on this host (see
  # `interfaceAssertions`'s own comment, above in this file's `let`, for
  # why gating them on `cfg.enable` would leave a fact-table-only host
  # unchecked).
  config = mkMerge [
    { assertions = interfaceAssertions; }
    (mkIf cfg.enable ({
    assertions = [
      {
        assertion =
          let allNames = concatMap (p: p.hostnames) (attrValues cfg.peers);
          in length allNames == length (unique allNames);
        message = ''
          nixnet.peers.*.hostnames has a duplicate entry across
          two different peers. Silently colliding entries in a shared
          namespace like /etc/hosts is exactly the kind of failure nixnet
          exists to prevent, not reproduce -- rename one of them.
        '';
      }
      {
        assertion = hasPrefix "/var/lib/" (toString cfg.daemon.stateDir);
        message = ''
          nixnet.daemon.stateDir (${toString cfg.daemon.stateDir}) must
          live under /var/lib/ -- the systemd unit uses StateDirectory=,
          which systemd only ever creates under /var/lib/ and which is
          what gives the fixed user nixnetd runs as correct ownership of
          it. A path elsewhere would silently keep the *directory name*
          but not actually point at the location you configured.
        '';
      }
    ]
    ++ (flatten (mapAttrsToList
      (name: u: imap0
        (i: t: {
          assertion = t.interface != null;
          message = "nixnet.uplinks.${name}.transports[${toString i}]: interface is required for uplink transports.";
        })
        u.transports)
      cfg.uplinks))
    ++ (flatten (mapAttrsToList
      (name: u: imap0
        (i: t: {
          assertion = t.probe.method == "exec" || t.probe.target != null;
          message = "nixnet.uplinks.${name}.transports[${toString i}]: probe.target (or probe.method = \"exec\") is required -- address has no default for uplinks.";
        })
        u.transports)
      cfg.uplinks))
    ++ (flatten (mapAttrsToList
      (peerOrUplinkName: g: imap0
        (i: t: {
          assertion = t.probe.method != "exec" || t.probe.exec != null;
          message = "${peerOrUplinkName}.transports[${toString i}]: probe.method = \"exec\" requires probe.exec.";
        })
        g.transports)
      (cfg.peers // cfg.uplinks)));

    # STALE-2: a WARNING and not an assertion, deliberately. Refusing to
    # evaluate would make a bound mandatory, and no number is defensible
    # from here -- the tolerance belongs to whatever consumes the name. But
    # an unbounded last-known-good is a defect with a measured cost (eleven
    # days of a dead address resolving as fact, see lastKnownGoodType
    # above), so it has to be chosen out loud rather than inherited from a
    # default that reads as harmless.
    warnings = optional (unboundedPeers != [ ]) ''
      nixnet: ${concatStringsSep ", " (map (n: "nixnet.peers.${n}") unboundedPeers)}
      will keep publishing their last-known-good address forever once every
      transport is down -- lastKnownGood.maxAgeSec is null, so nothing ever
      expires the entry. A dead address that keeps resolving is worse than a
      name that stops resolving: the first is a falsehood consumers cannot
      detect, the second is a failure they can. Set
      lastKnownGood.maxAgeSec to however long that name's consumers can
      usefully retry, or onAllDown = "unpublish" to withdraw immediately.
    '';

    environment.etc."nixnet/config.json".source = configJsonFile;

    # Same pattern nixpkgs's own systemd-resolved module uses for
    # /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf: point a
    # normally store-symlinked /etc file at a runtime-writable path
    # instead. Loudly documented here, not a silent takeover.
    #
    # mkForce replaces the WHOLE attrset (not just `source`), so any
    # option this feature needs MUST be set HERE, in this same literal --
    # a sibling module contributing e.g. `environment.etc.hosts.
    # replaceExisting = true` separately gets silently discarded back to
    # its default by this mkForce, not merged (verified via
    # lib.evalModules: a consumer override there evaluates to the
    # default regardless). `replaceExisting` only exists as an option on
    # the system-manager backend (real NixOS's environment.etc has no
    # such field -- it always reconciles /etc from scratch on activation
    # instead, so there's nothing to set there); system-manager needs it
    # unconditionally true for this entry specifically, because /etc/hosts
    # already exists, unmanaged, on essentially every real distro
    # system-manager bolts onto -- without it, system-manager just warns
    # and leaves the pre-existing file alone, silently no-op'ing this
    # entire feature.
    environment.etc.hosts = mkForce ({
      source = cfg.daemon.hostsFile;
    } // optionalAttrs isSystemManager {
      replaceExisting = true;
    });

    # nixnetd's own fixed identity (replaces DynamicUser=true -- see
    # systemd.services.nixnetd's own comment below for why DynamicUser never
    # actually worked here). A plain system user/group: nixnetd owns
    # cfg.daemon.stateDir and the hostsFile sibling directory (both chowned
    # to it, see seedHostsScript above and StateDirectory= below), needs no
    # login shell and no home directory of its own.
    users.users.nixnetd = {
      isSystemUser = true;
      group = "nixnetd";
      description = "nixnet transport failover daemon";
    };
    users.groups.nixnetd = { };

    # system-manager: no `system.activationScripts.<name>` at all (only a
    # fixed, non-extensible `.users` stub -- see options.nixnet's
    # `isSystemManager` note above), so the same seeding logic runs as an
    # ordinary oneshot unit instead, ordered before nixnetd via the
    # `before`/`wants` wiring nixnetd itself carries below (added
    # unconditionally -- a harmless dangling unit reference on NixOS, where
    # this service doesn't exist and the activation script above already
    # covers it). Also ordered after userborn.service -- system-manager's own
    # user-creation step -- so "nixnetd" reliably exists by the time this
    # script's chown runs (see seedHostsScript's own comment on why an
    # earlier, unordered call is allowed to have that chown no-op instead).
    # Harmless on NixOS too: userborn.service doesn't exist there, so this
    # is the same kind of no-op dangling reference nixnetd's own `after`
    # below already relies on.
    systemd.services.nixnet-seed-hosts = mkIf isSystemManager {
      description = "Seed cfg.daemon.hostsFile before nixnetd's first tick (system-manager backend)";
      before = [ "nixnetd.service" ];
      after = [ "userborn.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${seedHostsScript}";
      };
    };

    systemd.services.nixnetd = {
      description = "nixnet transport failover daemon";
      # On NixOS, no explicit ordering against the hosts-seeding activation
      # script is needed (see the comment on system.activationScripts
      # above -- activation isn't a systemd unit, it already completes
      # first). On system-manager, nixnet-seed-hosts.service above needs
      # explicit ordering, which these two lines provide; referencing a
      # unit that doesn't exist (the NixOS case) is a harmless no-op.
      after = [ "network.target" "nixnet-seed-hosts.service" ];
      wants = [ "nixnet-seed-hosts.service" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/nixnetd -config /etc/nixnet/config.json";
        # NOT DynamicUser=true. Found live in production 2026-08-01: the
        # boot-time seed script (seedHostsScript above) runs as root and
        # creates hostsFile before nixnetd's first tick, every single boot.
        # A DynamicUser's UID is freshly allocated per boot and owns
        # neither that file nor its directory, so nixnetd's own atomic
        # write-tmp-then-rename (Rust: `NamedTempFile::persist`, a
        # rename(2)) hit EPERM on every single publish attempt --
        # unconditionally, not intermittently: POSIX's sticky-bit rule
        # (the directory was mode 1777) restricts unlink/rename to the
        # file's owner, the directory's owner, or a privileged process,
        # and a non-root DynamicUser is never any of those against a
        # root-owned file. This was reasoned as "same model as /tmp" when
        # written; that model is backwards -- /tmp's sticky bit exists
        # specifically to STOP a non-owner from doing exactly the rename
        # nixnetd needed to do. The daemon had never once successfully
        # published a winner since hostsFile was moved outside
        # StateDirectory (2026-07-25); only the boot-time seed's own
        # content (or nothing) was ever visible in /etc/hosts. A fixed
        # user closes this for good: nixnetd owns the file and directory
        # outright (chowned by the seed script, see above), so the rename
        # is always same-owner and sticky bit is a non-issue. See
        # ../checks/default.nix's "nixnetd-fixed-user" checks for the
        # regression test.
        User = "nixnetd";
        Group = "nixnetd";
        RuntimeDirectory = cfg.daemon.runtimeDir;
        StateDirectory = baseNameOf (toString cfg.daemon.stateDir);
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/run/${cfg.daemon.runtimeDir}" cfg.daemon.stateDir (dirOf cfg.daemon.hostsFile) ];
        AmbientCapabilities =
          (optional needsNetAdmin "CAP_NET_ADMIN")
          ++ (optional needsNetRaw "CAP_NET_RAW");
        Restart = "always";
        RestartSec = 1;
        WatchdogSec = 10; # heartbeat interval is WATCHDOG_USEC/2, see internal/sdnotify
        NotifyAccess = "main";
        Type = "notify";
      };
    };
  }
  # NixOS only: an activation script -- runs synchronously,
  # to completion, before systemd starts any unit on a fresh boot; on a
  # `nixos-rebuild switch` (not a fresh boot) activation runs synchronously
  # too, ahead of restarting changed units. Merged in via `//` (a plain Nix
  # conditional on the ATTRSET ITSELF), not `mkIf` wrapping the value --
  # system-manager's `system.activationScripts` is a fixed-field submodule
  # (only `.users`/`.setupSecrets`/`.generate-age-key` are declared there,
  # not an extensible `attrsOf`), so an `mkIf false { nixnetSeedHosts = ...;
  # }` assigned to it STILL throws "option does not exist" -- the module
  # system's submodule merge walks a definition's structural KEYS to check
  # them against declared options independent of the mkIf condition's truth
  # value. `optionalAttrs` avoids this because when its condition is false
  # the `system` key is simply ABSENT from this module's contributed
  # attrset entirely, so there is no definition to check in the first
  # place. (Verified empirically against a real system-manager consumer
  # target -- an `mkIf isSystemManager`-wrapped version of this same block
  # still failed eval with exactly that error.)
  // (optionalAttrs (!isSystemManager) {
    system.activationScripts.nixnetSeedHosts = {
      text = "${seedHostsScript}";
      deps = [ ];
    };
  })
  # system-manager only: the actual fix for the etc-activation ordering bug
  # (see the README's "Non-NixOS hosts (via `system-manager`)" section).
  # system-manager-engine's activate() runs, in order: (1)
  # preActivationAssertions, (2) etc-file activation, (3) systemd-tmpfiles
  # --create (i.e. systemd.tmpfiles.rules), (4) systemd services -- so both
  # nixnet-seed-hosts.service (a systemd service, step 4) AND a
  # systemd.tmpfiles.rules entry (step 3) run strictly AFTER step 2, too
  # late to help environment.etc.hosts's own resolution at step 2 (verified
  # by reading system-manager-engine's own source, crates/system-manager-
  # engine/src/activate.rs and .../activate/etc_files.rs: it resolves every
  # symlink-mode /etc entry via `fs::canonicalize`, which errors on a
  # dangling target, and -- critically -- ONE such error there aborts
  # collection of the ENTIRE etc file list, so nothing under /etc gets
  # activated at all that run, not just this one entry).
  #
  # `system-manager.preActivationAssertions.<name>.script` is the one hook
  # that genuinely runs BEFORE step 2 (it's step 0, gating whether
  # activation proceeds past its own success/failure at all) -- despite the
  # "assertions" name, its `script` is just an arbitrary shell string run
  # for effect, so it's used here to guarantee cfg.daemon.hostsFile exists
  # as a real file (reusing seedHostsScript itself, so it's the SAME
  # real/best-effort-last-known-good content nixnet-seed-hosts.service
  # produces, not a bare placeholder) before system-manager-engine ever
  # tries to canonicalize environment.etc.hosts's symlink chain. Combined
  # with hostsFile now living under stateDir (/var/lib, survives reboots --
  # see the option's own doc comment) rather than runtimeDir (/run, wiped
  # every boot), this only needs to actually fire on the very first
  # activation ever performed for a given host; every activation after
  # that, the file this script would create already exists from either a
  # previous run of this same script or from nixnetd's own last session.
  #
  # Uses the SAME `optionalAttrs isSystemManager` (not `mkIf`) pattern as
  # the NixOS-only activationScripts block above, for the identical reason:
  # `system-manager.preActivationAssertions` is an option namespace that
  # simply doesn't exist under real NixOS at all, and assigning into an
  # undeclared option path throws regardless of any mkIf wrapping.
  // (optionalAttrs isSystemManager {
    system-manager.preActivationAssertions.nixnetSeedHosts = {
      enable = true;
      script = "${seedHostsScript}";
    };

    # /etc/hosts management is silently useless if the host's own NSS
    # config never actually reaches "files" for hostname lookups. Modern
    # systemd-resolved defaults ship `hosts: resolve [!UNAVAIL=return]
    # files ... dns` -- the [!UNAVAIL=return] means ANY answer from
    # resolve (a successful DNS hit, NOT just success-or-fail) short-
    # circuits NSS before "files" is ever consulted. On a split-horizon
    # setup where DNS already answers a peer's hostname (e.g. via a VPN
    # mesh's own DNS), nixnetd's carefully-computed winner in /etc/hosts
    # is written correctly and then never read -- discovered exactly this
    # way against a real deploy (DNS returned a mesh peer's overlay
    # address for a hostname nixnetd had already resolved to the healthy
    # LAN address). Rather than rewrite a file nixnet doesn't own, fail
    # loudly at activation time with the fix, instead of a confusing
    # mount/connect timeout discovered later -- same "enforce at
    # declaration, not detection after the fact" principle as nixnas's
    # persist-enforce.
    system-manager.preActivationAssertions.nixnetNsswitchOrder = {
      enable = true;
      script = "${pkgs.writeShellScript "nixnet-nsswitch-check" ''
        set -euo pipefail
        line="$(grep '^hosts:' /etc/nsswitch.conf || true)"
        if [ -z "$line" ]; then
          exit 0   # no hosts: line at all -- not nixnet's problem to diagnose
        fi
        files_pos=$(echo "$line" | grep -bo '\bfiles\b' | head -1 | cut -d: -f1 || echo "")
        resolve_pos=$(echo "$line" | grep -bo '\bresolve\b' | head -1 | cut -d: -f1 || echo "")
        dns_pos=$(echo "$line" | grep -bo '\bdns\b' | head -1 | cut -d: -f1 || echo "")
        shortcircuit_pos="$resolve_pos"
        if [ -z "$shortcircuit_pos" ]; then shortcircuit_pos="$dns_pos"; fi
        if [ -n "$files_pos" ] && [ -n "$shortcircuit_pos" ] && [ "$files_pos" -lt "$shortcircuit_pos" ]; then
          exit 0   # files comes first -- nixnet's /etc/hosts entries are reachable
        fi
        echo "nixnet: /etc/nsswitch.conf's 'hosts:' line does not reach 'files' before" >&2
        echo "  'resolve'/'dns' (found: $line)." >&2
        echo "  nixnetd writes /etc/hosts correctly, but nothing will ever read it --" >&2
        echo "  DNS answers first and NSS short-circuits on [!UNAVAIL=return]." >&2
        echo "  Fix: put 'files' before 'resolve'/'dns' in that line, e.g.:" >&2
        echo "    hosts: files mymachines resolve [!UNAVAIL=return] dns" >&2
        exit 1
      ''}";
    };
  })))
  ];
}
