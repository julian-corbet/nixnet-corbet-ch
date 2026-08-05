# modules/firewall.nix
#
# nixnet.firewall — this host's packet filter, in the repo that owns the rest of the host's network
# reality. It lived in a repo of its own; this is it folded back in, and the fold is the point.
#
# WHY ONE OWNER. A firewall repo cannot know how the host gets its address. So its default-drop
# input chain dropped the DHCP RENEW leg on a DHCP-addressed edge host, the lease expired ~21h
# later, and the box went dark with symptoms naming DNS, the metadata service and the overlay —
# everything except the firewall, because the firewall change and the outage were most of a day
# apart. The rule that was missing is one line long and nobody forgot it: the repo that rendered
# the ruleset had no way to see the fact that motivates it.
#
# So rules here DERIVE from facts nixnet already holds, and every derivation names the fact:
#   - the DHCP client accepts exist because an interface DECLARES `addressing.v4/v6 = "dhcp"`
#     (`nixnet.interfaces.<i>`, this file extends that same fact table with the addressing field);
#     a statically-addressed host does not carry them, and the accept is scoped to the interface
#     that renews.
#   - the overlay confinement CIDRs are computed from the trust BAND the operator already declares
#     for group reconciliation, instead of being a second, hand-written statement of the same
#     boundary that can quietly stop matching it.
#   - a routing peer's forward accepts are computed from `nixnet.overlay.advertiseRoutes`.
#
# IMPORTED BY core.nix, not standalone: it reads `nixnet.interfaces`, which core declares. One
# import, one evaluation, one place where "this host is DHCP-addressed" and "this host drops
# unmatched input" meet.
{ lib, config, options, pkgs, ... }:

let
  cfg = config.nixnet.firewall;
  rs = import ../lib/ruleset.nix { inherit lib; };
  tl = import ../lib/tooling.nix { inherit lib; };

  # Same backend detection core.nix uses, for the same reason: system-manager has NO
  # `networking.nftables` at all (its whole networking surface is `networking.enableIPv6` and a
  # `networking.firewall` MOCK that accepts the full NixOS schema, warns, and touches nothing).
  # Detected through system-manager's own option namespace, which never exists under real NixOS —
  # now via lib/tooling.nix's `backendOf`, which is the same test generalised to all three
  # backends, so this module and the tooling catalogue can never disagree about which one it is on.
  isSystemManager = tl.backendOf options == "system-manager";

  # ── The tools this host needs to READ what this module makes it enforce ─────────────────────
  #
  # Motivated by a real failure, not by tidiness: a host was enforcing a nixnet-authored `inet`
  # table with no `nft` installed at all. Enforcement never needed it — `applyScript` loads the
  # ruleset from a store path — so nothing broke and nothing warned; only every attempt to LOOK at
  # the firewall did, and the workaround was to fetch nftables over a network the firewall is a
  # candidate cause of having lost. lib/tooling.nix owns the per-backend naming, including the
  # backend that has no answer.
  tooling = tl.resolve { inherit pkgs options; names = cfg.tooling; };

  # ── The facts, read from wherever nixnet already declares them ──────────────────────────────
  #
  # Sibling modules are read defensively (`or`), the same idiom netbird-access-model.nix uses:
  # `config.nixnet.overlay` does not exist as an option at all when that module was never
  # imported, and `or` catches the failure anywhere along the path. `config.nixnet.interfaces` is
  # NOT read that way — core.nix imports this file, so the fact table is always there, and a
  # defensive read would only hide a broken import.
  interfaces = config.nixnet.interfaces;

  overlayCfg = config.nixnet.overlay or {
    enable = false;
    advertiseRoutes = [ ];
    confineExternalRanges = [ ];
    overlayInterface = null;
    ruleset = "";
  };

  groupReconcileCfg = config.nixnet.netbirdGroupReconcile or {
    bands = [ ];
    excludeFromCatchAll.forBand = null;
  };

  # ── DERIVATION 1: DHCP client accepts ───────────────────────────────────────────────────────
  dhcpV4Interfaces = lib.attrNames (lib.filterAttrs (_: i: i.addressing.v4 == "dhcp") interfaces);
  dhcpV6Interfaces = lib.attrNames (lib.filterAttrs (_: i: i.addressing.v6 == "dhcp") interfaces);

  # ── DERIVATION 2: overlay confinement ranges ────────────────────────────────────────────────
  #
  # The operator declares the trust boundary ONCE, as an octet band, because that is the form
  # group membership is reconciled from (`nixnet.netbirdGroupReconcile.bands`: a peer whose overlay
  # address ends in that range lands in that group). The confinement then needs the same boundary
  # as a CIDR — and writing it out by hand is a second statement of one fact, which is a fact that
  # can disagree with itself. Here it is computed; the only thing declared additionally is the
  # overlay's own /24, which is address space, not a boundary.
  confinement = cfg.overlayConfinement;
  confinementActive = confinement.network != null;

  # The band scheme keys off the LAST octet, so the network it lives in has to be a /24. Anything
  # else means the two declarations are not describing the same address space at all.
  networkMatch =
    if confinement.network == null then null
    else builtins.match "([0-9]+\\.[0-9]+\\.[0-9]+)\\.0/24" confinement.network;
  networkBase = if networkMatch == null then null else lib.head networkMatch;

  # Defaults to the band already singled out as least-trust: `excludeFromCatchAll.forBand` is the
  # band whose members join ONLY their own group and never the catch-all — i.e. the one the account
  # already treats as external. Naming it a second time here is optional, not required.
  confinedBandName =
    if confinement.band != null then confinement.band
    else groupReconcileCfg.excludeFromCatchAll.forBand or null;

  confinedBands = lib.filter (b: b.name == confinedBandName) (groupReconcileCfg.bands or [ ]);

  derivedConfinementRanges =
    if !confinementActive || networkBase == null then [ ]
    else lib.concatMap (b: rs.octetRangeToCidrs networkBase b.min b.max) confinedBands;

  # ── DERIVATION 3: the routed overlay path ───────────────────────────────────────────────────
  # A routing peer forwards between the overlay interface and the LAN it advertises. Whether this
  # host is one is already declared: `nixnet.overlay.advertiseRoutes`.
  isRoutingPeer = (overlayCfg.enable or false) && (overlayCfg.advertiseRoutes or [ ]) != [ ];
  overlayInterface = overlayCfg.overlayInterface or null;

  routedOverlayForwardLines =
    lib.optionals (cfg.forward.enable && isRoutingPeer && overlayInterface != null)
      (rs.forwardInterfaceLines overlayInterface
        "routed overlay path, derived from nixnet.overlay.advertiseRoutes");

  trustedForwardLines = lib.optionals cfg.forward.enable (map
    (pair: "iifname \"${pair.ingress}\" oifname \"${pair.egress}\" accept  # nixnet: authenticated transit")
    cfg.forward.trustedInterfacePairs);

  # ── The other table ─────────────────────────────────────────────────────────────────────────
  #
  # nixnet.overlay writes an nftables table of its OWN (its confinement and source-NAT are the
  # overlay mechanism's requirements, not host policy), so on a routing peer two nixnet-authored
  # tables hook the same packet path. Its table name is read out of the text it will actually load
  # rather than hardcoded here, so renaming it there cannot silently stop this check from matching.
  overlayTableNames =
    let lines = lib.splitString "\n" (overlayCfg.ruleset or "");
    in map (l: lib.elemAt (lib.splitString " " (lib.strings.trim l)) 2)
      (lib.filter (l: lib.hasPrefix "table inet " (lib.strings.trim l)) lines);

  # ── Interfaces this firewall names ──────────────────────────────────────────────────────────
  # Including the DERIVED one: a rule that names an interface this host never declared fails open
  # exactly the same way whether a human typed the name or a derivation produced it.
  namedInterfaces = lib.unique (
    cfg.management.interfaces
    ++ cfg.trustedInterfaces
    ++ (lib.filter (i: i != null) (map (r: r.interface) (cfg.allow ++ cfg.forward.rules)))
    ++ lib.concatMap (pair: [ pair.ingress pair.egress ]) cfg.forward.trustedInterfacePairs
    ++ (lib.optional (routedOverlayForwardLines != [ ]) overlayInterface)
  );

  undeclaredInterfaces = lib.filter (n: !(interfaces ? ${n})) namedInterfaces;
  addressinglessInterfaces = lib.filter
    (n: (interfaces ? ${n})
      && (interfaces.${n}.addressing.v4 == null || interfaces.${n}.addressing.v6 == null))
    namedInterfaces;

  # ── Rendering ───────────────────────────────────────────────────────────────────────────────
  indent = n: lines:
    lib.concatStringsSep "\n"
      (map (l: if l == "" then "" else "${lib.strings.replicate n " "}${l}") lines);

  # max 0: a title longer than the rule width would otherwise make replicate throw on a negative
  # count — a crash in a comment renderer, which is a silly way to fail a firewall build.
  section = title: lines:
    let pad = lib.strings.replicate (lib.max 0 (68 - lib.stringLength title)) "-"; in
    lib.optionalString (lines != [ ])
      "\n    # -- ${title} ${pad}\n${indent 4 lines}\n";

  forwardChain = lib.optionalString cfg.forward.enable ''

      chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
    ${indent 4 (routedOverlayForwardLines ++ trustedForwardLines ++ lib.concatMap rs.ruleLines cfg.forward.rules)}
      }'';

  rulesetText = ''
    # Generated by nixnet's firewall module. Do not edit — edit the host's nixnet.firewall.* options.
    #
    # NOTE the add-then-delete-then-define idiom below. It replaces ONLY this table, atomically,
    # and never issues `flush ruleset`: other tables on this host belong to k3s, docker, podman,
    # libvirt (all of which write chains via iptables-nft) and to nixnet's own overlay module, and
    # flushing would delete them without a word. `add` first is what makes `delete` safe when the
    # table does not exist yet — deleting a missing table is an error that would abort the whole
    # transaction.
    table inet ${cfg.table}
    delete table inet ${cfg.table}

    table inet ${cfg.table} {
    ${indent 2 (rs.managementSetLines cfg)}
      chain input {
        type filter hook input priority filter; policy drop;

    ${indent 4 rs.preambleLines}
    ${section "DHCP client — derived from nixnet.interfaces.*.addressing" (rs.dhcpClientLines { v4Interfaces = dhcpV4Interfaces; v6Interfaces = dhcpV6Interfaces; })}${section "management — generated first, not overridable by host rules" (rs.managementLines cfg)}${section "trusted interfaces" (map (i: "iifname \"${i}\" accept  # nixnet: trusted interface") cfg.trustedInterfaces)}${section "silent drops (dropped anyway; kept out of the kernel log)" (rs.silentDropLines cfg.silentDrops)}${section "host rules" (lib.concatMap rs.ruleLines cfg.allow)}  }
    ${forwardChain}
      # No output chain: nixnet does not filter egress. A host that needs it should say so
      # explicitly rather than inherit it as a side effect of enabling a firewall.
    }
  '';

  rulesetHash = builtins.hashString "sha256" cfg.ruleset;

  # ── The generation marker ───────────────────────────────────────────────────────────────────
  #
  # One rule, in a regular chain with no hook that nothing jumps to — never traversed, zero datapath
  # cost — whose COMMENT carries this ruleset's hash. It answers the question the kernel otherwise
  # cannot be asked cheaply: "is the table currently loaded the one THIS generation renders?"
  #
  # Comparing text does not work. `nft list table` renders handles, expanded syntax and its own
  # formatting, so a byte-comparison against the source reports drift on every host every time; a
  # normalised comparison means re-implementing nft's printer and getting it wrong on the version
  # that adds a field. One rule with a known comment is checkable with one command.
  #
  # A RULE, not a chain name — and that distinction is load-bearing, found by the VM test rather
  # than by reasoning. `nft flush table` empties every chain's RULES and leaves the CHAINS in place,
  # so a marker encoded as a chain name survives the flush and reports a table that has been emptied
  # as healthy. The host would then be sitting behind an input chain with `policy drop` and no
  # accepts — every packet dropped — with the reconcile loop calling it fine.
  #
  # So it answers three failures with one check:
  #   * table deleted outright (`nft flush ruleset`, a CNI reset, a hand-run command)
  #   * table present but emptied (`nft flush table inet nixnet`)
  #   * table present from a DIFFERENT generation (an older ruleset reloaded, e.g. by a rollback)
  #
  # What it does NOT catch, stated rather than implied: the surgical removal of one rule from the
  # input chain leaves the marker intact. Detecting that needs a full content comparison, which is
  # the fragile thing above. Flush, delete and rollback are the shapes that actually happen.
  #
  # Hashed over `cfg.ruleset`, which does NOT contain the marker — the marker is appended when the
  # file is written. Hashing the file including its own hash would not converge.
  generationChain = "nixnet-generation";
  generationMark = "nixnet-generation=${rulesetHash}";

  markerText = ''

    # The generation marker — see modules/firewall.nix. Unhooked, unreachable from any base chain:
    # it is a fact about WHICH ruleset is loaded, not a rule about packets.
    table inet ${cfg.table} {
      chain ${generationChain} {
        counter comment "${generationMark}"
      }
    }
  '';

  # The one question every path here asks. `grep` rather than nft's exit status, because a chain
  # that exists and is empty exits 0 — which is exactly the emptied-table case.
  inForceFunc = ''
    nixnet_in_force() {
      ${pkgs.nftables}/bin/nft list chain inet ${cfg.table} ${generationChain} 2>/dev/null \
        | grep -q '${generationMark}'
    }
  '';

  # ── Dead-man switch ─────────────────────────────────────────────────────────────────────────
  stateDir = "/var/lib/nixnet-firewall";
  pendingFile = "${stateDir}/pending.nft";
  appliedHashFile = "${stateDir}/applied-hash";

  # Which ruleset the dead-man switch REPLACED, if it ever fired. This is the one thing that must
  # stop the reconcile loop from repairing: after a revert, the table deliberately does not match
  # this generation, and reloading it would put back the ruleset that just locked someone out —
  # every 60 seconds, forever. Two mechanisms with authority over the same table is exactly what
  # ISO-1 warns about; this file is where they agree on who wins.
  revertedHashFile = "${stateDir}/reverted-hash";
  repairCountFile = "${stateDir}/repairs";

  confirm = pkgs.writeShellApplication {
    name = "nixnet-firewall-confirm";
    runtimeInputs = [ pkgs.systemd ];
    text = ''
      # Disarm the revert timer. Run this once you have confirmed you still have a working
      # connection THROUGH the new ruleset — ideally from a SECOND session, not the one you already
      # had open, since an established connection survives rules that would refuse a new one.
      systemctl stop nixnet-firewall-revert.timer 2>/dev/null || true
      rm -f ${pendingFile}
      # Also clears a revert that already fired. Confirming AFTER the window closed is a real
      # operator action meaning "put it back and stop reverting" — the ruleset is fine, the human
      # was just slow. It re-enables the reconcile loop, which restores the ruleset on its next run.
      rm -f ${revertedHashFile}
      echo "nixnet: ruleset confirmed; auto-revert disarmed."
    '';
  };

  revertScript = pkgs.writeShellScript "nixnet-firewall-revert" ''
    if [ -f ${pendingFile} ]; then
      echo "nixnet: confirmation window expired — restoring the previous ruleset."
      # The exit status decides what happens next, so it is checked rather than assumed. A failed
      # restore that deleted the snapshot and told the reconcile loop to stand down would leave the
      # host running the suspect ruleset with BOTH safety nets retired and nothing left that could
      # put anything back.
      if ${pkgs.nftables}/bin/nft -f ${pendingFile}; then
        rm -f ${pendingFile}
        # Tell the reconcile loop to stand down for THIS ruleset. Without this it would find the
        # generation marker missing one interval later, conclude the firewall had been flushed by a
        # foreigner, and reload the very ruleset this revert just undid.
        printf %s "${rulesetHash}" > ${revertedHashFile}
      else
        echo "nixnet: restoring the previous ruleset FAILED — keeping the snapshot." >&2
        echo "nixnet: the host is running the unconfirmed ruleset; reconcile stays enabled." >&2
        exit 1
      fi
    fi
  '';

  # Snapshot OUR TABLE ONLY, never `nft list ruleset`. A full dump would restore every table on the
  # host — so a revert firing after docker, k3s or the overlay module legitimately changed their
  # own tables during the confirmation window would stomp those changes too. Same own-table
  # discipline the apply path enforces.
  #
  # One script for both planes, and it ARMS THE TIMER ITSELF rather than leaving that to whatever
  # wants the timer unit: arming is the thing that must happen only on a real change, so it belongs
  # next to the comparison that decides that.
  snapshotScript = pkgs.writeShellScript "nixnet-firewall-snapshot" ''
    mkdir -p ${stateDir}
    chmod 0700 ${stateDir}

    # ── ARM ONLY ON A REAL CHANGE ──────────────────────────────────────────────────────────────
    # The dead-man switch exists to protect the moment an operator applies a NEW ruleset and might
    # lock themselves out. A plain reboot is not that moment, and arming there is actively harmful:
    # the confirmation has to be typed by a human, nobody types it on a headless box, so the timer
    # fired on EVERY boot and the "revert" deleted the firewall outright (with no prior table, the
    # restore file is just `add table; delete table`). A CI-deployed host therefore spent every
    # boot running with no firewall at all, from ~`seconds` in until the next reboot. Found in
    # production; every unattended host on the default was exposed.
    #
    # Remote-lockout protection for an unattended deploy is the deploy layer's rollback, not this
    # timer's. This switch covers exactly what it can: a ruleset that differs from the last one
    # applied on this box.
    if [ -f ${appliedHashFile} ] && [ "$(cat ${appliedHashFile})" = "${rulesetHash}" ]; then
      rm -f ${pendingFile}
      echo "nixnet: ruleset unchanged since last apply — not arming auto-revert."
      exit 0
    fi

    # ── NEVER ARM WITH NOTHING TO RESTORE ──────────────────────────────────────────────────────
    # There is no prior table, so the only thing a revert could do is DELETE this one and leave the
    # host with no packet filter. That is not a recovery from a bad ruleset, it is a worse outcome
    # than the ruleset — and it is the failure that put corbet-eu-vultr, a public host and the
    # overlay control plane, on the open internet unfiltered on 2026-08-04.
    #
    # Read the sequence, because "arm only on a change" was already implemented and did not prevent
    # it: the first deploy of a nixnet ruleset to a host is BY DEFINITION a change, so the switch
    # armed. The snapshot it took was of an empty kernel, so the restore file said `add table;
    # delete table`. Nobody typed `nixnet-firewall-confirm`, because it was an unattended CI deploy
    # and there is no human in that loop. `seconds` later the timer fired and did exactly what it
    # was told. Green unit, no firewall, and every subsequent theory (the switch self-killing,
    # deploy-rs rolling back, a podman health check) was looking at a different part of the elephant.
    #
    # A first apply therefore gets NO dead-man switch. The protection an unattended first deploy
    # actually has is the deploy layer's own rollback, which reverts the whole generation rather
    # than one table — and if that fails too, a firewall that is merely WRONG still leaves a host in
    # a better state than a firewall that is ABSENT.
    if ! ${pkgs.nftables}/bin/nft list table inet ${cfg.table} >/dev/null 2>&1; then
      rm -f ${pendingFile}
      printf %s "${rulesetHash}" > ${appliedHashFile}
      echo "nixnet: no previous ruleset to restore — not arming auto-revert." >&2
      echo "nixnet: a revert here could only DELETE this host's firewall, which is not a recovery." >&2
      exit 0
    fi

    { echo "table inet ${cfg.table}"; echo "delete table inet ${cfg.table}"; \
      ${pkgs.nftables}/bin/nft list table inet ${cfg.table}; } > ${pendingFile}

    # Recorded BEFORE the countdown, not on confirmation. If the revert does fire, the next boot
    # must load this ruleset and LEAVE it alone rather than re-arming and re-reverting forever —
    # one unconfirmed window per change, not one per boot.
    printf %s "${rulesetHash}" > ${appliedHashFile}

    # --no-block: on the NixOS plane this runs from a unit ordered before nftables.service, and a
    # blocking start would have systemd waiting on a job we are ourselves in the middle of.
    ${pkgs.systemd}/bin/systemctl --no-block start nixnet-firewall-revert.timer
  '';

  # ── The apply path ──────────────────────────────────────────────────────────────────────────
  #
  # The ruleset goes into the store, and the apply unit names that store path. So the unit's own
  # text moves whenever a rule moves, which is the ONLY diff both delivery engines act on:
  # system-manager restarts a unit when the unit's store path changes and has no "a file this unit
  # reads changed" notion at all, and NixOS' switch compares unit files the same way. A unit
  # pointing at a fixed /etc path would sit inert with a changed ruleset until the next reboot.
  #
  # The marker chain is appended HERE rather than rendered into `cfg.ruleset`, for two reasons: the
  # hash it is named after is taken over `cfg.ruleset` (a ruleset containing its own hash cannot
  # converge), and `cfg.ruleset` is the readable statement of host policy — a bookkeeping chain in
  # it would read as a rule someone forgot to finish.
  rulesetFile = pkgs.writeText "nixnet-firewall.nft" (cfg.ruleset + markerText);

  # ── Observability ───────────────────────────────────────────────────────────────────────────
  #
  # Two numbers, written by every path that establishes the truth of them: whether the ruleset this
  # generation renders is the one actually loaded, and how many times something had to put it back.
  # A repair count that is not zero is not an error — it is the host saying something else on it
  # removes the firewall, which is a fact no green unit ever conveys.
  #
  # Written atomically (tmp + rename) because a Prometheus textfile collector reads this file on its
  # own schedule and a half-written one parses as a scrape error.
  metricsFunc =
    if cfg.metricsFile == null
    then "nixnet_write_metrics() { :; }\n"
    else ''
      nixnet_write_metrics() {
        _enforced="$1"
        _repairs=0
        if [ -f ${repairCountFile} ]; then _repairs="$(cat ${repairCountFile})"; fi
        mkdir -p "$(dirname ${cfg.metricsFile})"
        _tmp="${cfg.metricsFile}.$$.tmp"
        {
          echo "# HELP nixnet_firewall_enforced 1 when the loaded nftables table is the one this generation renders."
          echo "# TYPE nixnet_firewall_enforced gauge"
          echo "nixnet_firewall_enforced $_enforced"
          echo "# HELP nixnet_firewall_repairs_total Reloads by the reconcile loop after finding the ruleset absent or foreign."
          echo "# TYPE nixnet_firewall_repairs_total counter"
          echo "nixnet_firewall_repairs_total $_repairs"
          echo "# HELP nixnet_firewall_last_check_seconds Unix time of the last completed firewall check."
          echo "# TYPE nixnet_firewall_last_check_seconds gauge"
          echo "nixnet_firewall_last_check_seconds $(date +%s)"
        } > "$_tmp"
        chmod 0644 "$_tmp"
        mv -f "$_tmp" ${cfg.metricsFile}
      }
    '';

  # ── FW-4: the reconcile loop ────────────────────────────────────────────────────────────────
  #
  # Ordering this module's unit against the two other units this repo happens to know about covers
  # only hosts running exactly those two. A container CNI's reset path, an overlay client, a
  # rollback to a generation that had a different firewall, or a hand-run `nft flush ruleset`
  # removes the table with no error and nothing restores it until the next deploy. `RemainAfterExit`
  # then keeps `nixnet-firewall.service` reporting active/success over an empty kernel — measured in
  # production on a public host: the unit was green, the box had no packet filter at all, and the
  # only reason it was noticed was that someone went looking for something else.
  #
  # Deliberately NOT a re-run of `applyScript`: a repair is not an operator change, so it must not
  # arm the dead-man switch. Arming here would start a countdown nobody is waiting to confirm, and
  # its snapshot would be of the broken state.
  reconcileScript = pkgs.writeShellScript "nixnet-firewall-reconcile" ''
    set -eu
    ${metricsFunc}
    ${inForceFunc}

    mkdir -p ${stateDir}
    chmod 0700 ${stateDir}

    if nixnet_in_force; then
      nixnet_write_metrics 1
      exit 0
    fi

    # Name the KIND of drift before acting on it. "The table is gone" and "the table is someone
    # else's generation" are different incidents, and the journal line is where that gets read.
    if ${pkgs.nftables}/bin/nft list table inet ${cfg.table} >/dev/null 2>&1; then
      reason="table inet ${cfg.table} is loaded but is NOT this generation (${generationMark} absent)"
    else
      reason="table inet ${cfg.table} is absent"
    fi

    # The one case where the right move is to leave it broken and say so. The dead-man switch fired,
    # which means an operator applied a ruleset and never confirmed they could still get in.
    # Repairing would reload exactly that ruleset, once per interval, forever.
    if [ -f ${revertedHashFile} ] && [ "$(cat ${revertedHashFile})" = "${rulesetHash}" ]; then
      echo "nixnet: $reason — NOT repairing." >&2
      echo "nixnet: auto-revert replaced this ruleset deliberately; the host is running rules nixnet did not choose." >&2
      echo "nixnet: fix the ruleset and redeploy, or run nixnet-firewall-confirm to put it back." >&2
      nixnet_write_metrics 0
      exit 1
    fi

    echo "nixnet: $reason — repairing." >&2
    ${pkgs.nftables}/bin/nft -f ${rulesetFile}

    # Same discipline as the apply path: the loader's exit status is not proof. Check the kernel.
    if ! nixnet_in_force; then
      echo "nixnet: repair loaded without error and the ruleset is STILL not in force." >&2
      nixnet_write_metrics 0
      exit 1
    fi

    _count=0
    if [ -f ${repairCountFile} ]; then _count="$(cat ${repairCountFile})"; fi
    _count=$((_count + 1))
    printf %s "$_count" > ${repairCountFile}
    nixnet_write_metrics 1
    echo "nixnet: firewall repaired (repair #$_count). Not routine — something on this host removes it." >&2
  '';

  # `set -eu`, and no `|| true` anywhere: FW-3. The loader's exit status IS the signal, and a
  # swallowed one is how a production host came to be running with no packet filter at all,
  # discovered from a serial console rather than from anything the host said.
  applyScript = pkgs.writeShellScript "nixnet-firewall-apply" ''
    set -eu
    ${metricsFunc}
    ${inForceFunc}
    ${lib.optionalString cfg.autoRevert.enable "${snapshotScript}"}
    ${pkgs.nftables}/bin/nft -f ${rulesetFile}

    # The other half a loader cannot report: a unit that FINISHED while nixnet's table is not
    # present. Presence is checkable, so check it — a green apply unit over an absent firewall is
    # exactly the state that went unnoticed. Checked via the generation marker rather than the
    # table, so "a table is there" cannot pass for "MY table is there".
    if ! nixnet_in_force; then
      echo "nixnet: table inet ${cfg.table} is NOT in force after a successful load — refusing to report success." >&2
      nixnet_write_metrics 0
      exit 1
    fi

    # An apply supersedes a revert: this is the operator putting a ruleset on the host, which is
    # the authority the reconcile loop stood down for. Leaving the file would have reconcile refuse
    # to repair a future flush of a ruleset that is currently loaded and fine.
    rm -f ${revertedHashFile}
    nixnet_write_metrics 1
  '';

  # What the unit does when the firewall is DISABLED — it still runs. `enable = false` has to mean
  # the table is gone, not "nixnet stopped talking about it": a host that turns the firewall off in
  # one generation would otherwise keep the previous generation's rules in the kernel until reboot,
  # with nothing declarative left that even mentions them.
  #
  # add-then-delete, because deleting a table that does not exist is an error, and this runs on
  # every host that has never had one.
  teardownScript = pkgs.writeShellScript "nixnet-firewall-teardown" ''
    set -eu
    ${pkgs.nftables}/bin/nft "add table inet ${cfg.table}; delete table inet ${cfg.table}"
    if ${pkgs.nftables}/bin/nft list table inet ${cfg.table} >/dev/null 2>&1; then
      echo "nixnet: table inet ${cfg.table} is still present after teardown." >&2
      exit 1
    fi

    # Forget which ruleset was last applied. `applied-hash` means "this exact ruleset is loaded on
    # this box"; after a teardown nothing is, and leaving the file behind means re-enabling the
    # firewall with the SAME ruleset is read as "unchanged, do not arm" — the dead-man switch
    # silently disarmed for a ruleset the host has not run since. The revert marker goes with it:
    # it refers to a table that no longer exists either.
    rm -f ${appliedHashFile} ${pendingFile} ${revertedHashFile}
  '';

  # ONE unit name on both planes, and NO ExecStop. Both are load-bearing:
  #
  #   * one name, because the observable "did this host's firewall apply?" must be the same
  #     question everywhere — `systemctl is-failed nixnet-firewall.service` on a NixOS box and on a
  #     foreign distro alike.
  #   * no ExecStop, because a changed ruleset makes the switch stop-and-start this unit. An
  #     ExecStop that deleted the table would tear the firewall down BEFORE trying to load the new
  #     one, so a ruleset that fails to load would leave the host with nothing instead of with the
  #     previous ruleset. The load is one `nft -f` transaction; failing it changes nothing, and
  #     that property is worth more than a tidy stop.
  #
  # Delegating to nixpkgs' `networking.nftables` was the obvious alternative and is wrong twice
  # over: its `flushRuleset` is mkDefault TRUE whenever a raw ruleset is set and it concatenates
  # that `flush ruleset` into the same transaction — wiping k3s, docker, podman, libvirt and
  # nixnet's own overlay table off the host on every apply — and it reloads rather than restarts on
  # change, where a failed `ExecReload` leaves the unit ACTIVE and SUCCESSFUL (measured: systemd
  # marks the job failed, not the unit). A firewall that failed to apply and reports success is the
  # exact failure this repo is being rebuilt around.
  applyUnit =
    {
      description =
        if cfg.enable
        then "nixnet: apply the host packet filter (table inet ${cfg.table})"
        else "nixnet: assert nixnet's packet-filter table is absent";
      wantedBy = [ (if isSystemManager then "system-manager.target" else "multi-user.target") ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${if cfg.enable then applyScript else teardownScript}";
      };
    }
    // lib.optionalAttrs (!isSystemManager) {
      # Same ordering nixpkgs' own nftables unit uses: the filter is in force before anything
      # brings an interface up, and it is not subject to the default dependency web that would
      # order it after the network it is supposed to precede.
      after = [ "sysinit.target" ];
      before = [ "network-pre.target" "shutdown.target" ];
      wants = [ "network-pre.target" ];
      conflicts = [ "shutdown.target" ];
      unitConfig.DefaultDependencies = false;
    };

  ruleType = lib.types.submodule {
    options = {
      protocol = lib.mkOption {
        type = lib.types.enum [ "tcp" "udp" ];
        default = "tcp";
        description = "Transport protocol this rule matches.";
      };
      ports = lib.mkOption {
        type = lib.types.listOf lib.types.port;
        default = [ ];
        description = "Discrete destination ports. Rendered as an nftables set alongside `portRanges` when there is more than one entry total.";
      };
      portRanges = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options = {
            from = lib.mkOption { type = lib.types.port; description = "First port, inclusive."; };
            to = lib.mkOption { type = lib.types.port; description = "Last port, inclusive."; };
          };
        });
        default = [ ];
        example = [{ from = 49160; to = 49360; }];
        description = ''
          Destination port ranges. For a service that needs more than a handful of ports (a TURN
          relay range, say) — enumerating each one individually in `ports` would work but reads as
          noise and invites a typo'd gap. Mixes freely with `ports` in the same rule; nftables sets
          accept discrete values and ranges side by side.
        '';
      };
      sourcesV4 = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "192.0.2.0/24" ];
        description = ''
          IPv4 source prefixes. Empty means ANY v4 source — which is a real choice, not a default to
          reach for absentmindedly. On a host with a public address, an empty list here is the whole
          internet.
        '';
      };
      sourcesV6 = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "IPv6 source prefixes. Empty means ANY v6 source. Rendered as separate rules — v4 and v6 need different matchers.";
      };
      interface = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Restrict to one inbound interface. `null` matches any. A named interface must exist in
          `nixnet.interfaces` with its addressing declared — a misspelled interface here matches
          nothing and fails OPEN silently, so it is an eval error instead.
        '';
      };
      comment = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Rendered into the ruleset. Worth writing: `nft list ruleset` is what a future reader debugs from, and an unexplained port is indistinguishable from a mistake.";
      };
    };
  };

  # The addressing fact, per family. Separate enums rather than one shared list: there is no v4
  # SLAAC, and a type error names the mistake better than an assertion can.
  addressingType = lib.types.submodule {
    options = {
      v4 = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum [ "static" "dhcp" "none" "unmanaged" ]);
        default = null;
        example = "dhcp";
        description = ''
          How this interface gets its IPv4 address. `null` (the default) means NOBODY SAID, which is
          deliberately not the same state as `unmanaged` ("somebody said this is not nixnet's") —
          collapsing the two is how a fact goes missing without anyone noticing.

          nixnet does not configure addressing: it neither runs a DHCP client nor assigns an
          address. It records how addressing HAPPENS so everything downstream derives from it —
          today, the DHCP client accepts in this host's own ruleset, which is the rule that was
          missing when a firewall repo could not see this fact.
        '';
      };
      v6 = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum [ "static" "dhcp" "slaac" "none" "unmanaged" ]);
        default = null;
        example = "slaac";
        description = ''
          How this interface gets its IPv6 address. `dhcp` means DHCPv6 (a client bound on UDP 546)
          and earns the matching accept; `slaac` needs no accept of its own, because it rides
          ICMPv6 router advertisements, which the ruleset accepts unconditionally.
        '';
      };
    };
  };

in
{
  # Extends core.nix's interface fact table rather than starting a second one: the module system
  # merges submodule declarations at the same option path, so `nixnet.interfaces.<name>` ends up
  # with core's `mac`/`addresses` AND this `addressing` in ONE table. Declared with a TYPE ONLY —
  # no `description`, `default` or `example` — because a second declaration carrying any of those
  # is a hard "already declared" error against core's own.
  options.nixnet.interfaces = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule {
      options.addressing = lib.mkOption {
        type = addressingType;
        default = { };
        description = ''
          How this interface is addressed, per family. THE fact the firewall could not see when it
          lived in its own repo. Declared, never discovered from the running system: nixnet reports
          a disagreement between this and the kernel, it does not correct one.
        '';
      };
    });
  };

  options.nixnet.firewall = {
    enable = lib.mkEnableOption ''
      the nixnet host firewall (nftables, default-deny input).

      OFF does not mean ABSENT: `nixnet-firewall.service` exists either way, and with this off its
      job is to assert nixnet's table is gone. A host that turns the firewall off in one generation
      would otherwise keep the previous generation's rules in the kernel until the next reboot,
      with nothing declarative left that even mentions them.

      Requires `networking.firewall.enable = false` on NixOS (asserted): two default-drop input
      chains at one hook intersect rather than combine
    '';

    table = lib.mkOption {
      type = lib.types.str;
      default = "nixnet";
      description = ''
        Name of the inet table this module owns. It touches ONLY this table and never issues
        `flush ruleset`.

        That is not tidiness, it is a hard requirement: k3s, docker, podman and libvirt all write
        their own chains via iptables-nft, into tables this module does not own — and so does
        nixnet's own overlay module. A `flush ruleset` on re-apply would silently delete every one
        of them, container networking and overlay confinement included, and the failure would look
        like an application outage rather than a firewall change.
      '';
    };

    management = {
      interfaces = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "wt0" ];
        description = ''
          Interfaces that ALWAYS keep the management port open, no matter what else is declared.

          This exists because of a specific, real near-miss: a hand-written ruleset accepted ssh
          from a LAN range only, and named the overlay interface for exactly one unrelated port.
          Loading it would have cut ssh over the overlay — the only way in to some hosts. Nobody
          forgets to allow ssh; what happens is that the overlay is not in the range you allowed,
          and you do not notice because you tested from the LAN.

          Rules generated from this list are emitted before the host's own and cannot be overridden
          by them. Every entry must exist in `nixnet.interfaces` with its addressing declared.
        '';
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 22;
        description = "The management (ssh) port held open on every `management.interfaces` entry.";
      };

      rateLimitNew = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "6/minute";
        description = ''
          Rate-limit NEW connections to the management port instead of accepting them
          unconditionally — a brute-force throttle for a host that faces the open internet directly.
          Value is an nftables `limit rate` expression (e.g. `"6/minute"`).

          Only touches new connections: the preamble's `ct state established,related accept` runs
          before any management rule, so it is never reached for a connection this rule already let
          through. Traffic beyond the rate hits an explicit drop, so it does not fall through into
          the rest of the ruleset and get evaluated against every other rule for nothing.

          `null` (the default) keeps the unconditional accept — the right choice for an overlay-only
          management interface reachable only by trusted mesh peers, where a rate limit adds nothing
          but a way to lock yourself out under a burst of legitimate retries.
        '';
      };
    };

    trustedInterfaces = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Interfaces where ALL inbound traffic is accepted. Use sparingly — this is a much bigger grant than `management.interfaces`, which opens exactly one port.";
    };

    allow = lib.mkOption {
      type = lib.types.listOf ruleType;
      default = [ ];
      description = "Accept rules, in declaration order, after the derived and management rules.";
    };

    silentDrops = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          match = lib.mkOption { type = lib.types.str; description = "Raw nftables matcher, e.g. `udp dport 5355`."; };
          comment = lib.mkOption { type = lib.types.str; default = ""; description = "Why this is dropped without logging."; };
        };
      });
      default = [ ];
      description = ''
        Traffic dropped WITHOUT logging. These packets are dropped either way; the point is to stop
        them drowning the kernel log. That is a security measure, not a cosmetic one — on the host
        this generalises, 66% of kernel log lines were the firewall logging ordinary LAN broadcast
        housekeeping, and that noise is exactly what hid a genuine WireGuard drop.
      '';
    };

    forward = {
      enable = lib.mkEnableOption ''
        a forward chain. OFF by default, and that default is deliberate.

        nftables does not work the way iptables did here: every base chain at a hook sees the
        packet, and ANY chain's drop is final. A drop-policy forward chain in this table would
        therefore override the ACCEPTs libvirt/docker/k3s insert in THEIR tables, and break guest
        and container networking — a regression the iptables setup never had. Enable this only on a
        host that genuinely routes and knows it. On a routing peer the overlay path is accepted
        automatically (derived from `nixnet.overlay.advertiseRoutes`), because the same
        any-drop-is-final rule would otherwise silently kill the traffic the overlay module NATs
      '';
      rules = lib.mkOption {
        type = lib.types.listOf ruleType;
        default = [ ];
        description = "Forward-chain accepts. Only meaningful with `forward.enable`.";
      };

      trustedInterfacePairs = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options = {
            ingress = lib.mkOption {
              type = lib.types.str;
              description = "Authenticated ingress interface.";
            };
            egress = lib.mkOption {
              type = lib.types.str;
              description = "Permitted egress interface for packets from ingress.";
            };
          };
        });
        default = [ ];
        description = ''
          Exact interface pairs trusted to forward every protocol. This is for a
          cryptographically authenticated transit, such as WireGuard, where
          the tunnel's peer and AllowedIPs policy already restricts identities.
          It never grants forwarding to or from any other interface.
        '';
      };
    };

    overlayConfinement = {
      network = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "198.51.100.0/24"; # TEST-NET-2 placeholder overlay CIDR
        description = ''
          The overlay's own address space, as a /24. Set this to DERIVE
          `nixnet.overlay.confineExternalRanges` from the least-trust octet band the operator
          already declares in `nixnet.netbirdGroupReconcile`, instead of hand-writing a CIDR that
          restates the same boundary and can quietly stop matching it.

          A /24 specifically, and asserted: the band scheme keys off the LAST octet, so anything
          else means the two declarations are not describing the same address space.

          `null` (the default) leaves `confineExternalRanges` entirely to the operator and disables
          both the derivation and its agreement check.
        '';
      };

      band = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "external";
        description = ''
          Which declared band is the confined one, by group name. Defaults to
          `nixnet.netbirdGroupReconcile.excludeFromCatchAll.forBand` — the band whose members join
          only their own group and never the catch-all, i.e. the one the account already treats as
          least-trust. Set this only when the confined band is NOT that one.
        '';
      };

      ranges = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        readOnly = true;
        description = ''
          The CIDRs derived from the confined band. Read-only: declare the band, not this.

          Exposed because a derivation you cannot read is a derivation you are trusting blind —
          `nix eval` this to see exactly which addresses the confinement covers before a host loads
          it.
        '';
      };
    };

    autoRevert = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Dead-man switch. Snapshots the live ruleset before applying a CHANGED one, then restores
          it unless the new one is confirmed within `seconds` by running `nixnet-firewall-confirm`.

          Defaults ON. A firewall you cannot recover from remotely is the failure this module is
          most likely to cause, and the cost of the safety net is one timer.
        '';
      };
      seconds = lib.mkOption {
        type = lib.types.int;
        default = 120;
        description = "Seconds to wait for confirmation before restoring the snapshot.";
      };
    };

    reconcile = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Re-check, on a timer, that the ruleset this generation renders is the one the kernel is
          actually enforcing — and reload it if it is not.

          Defaults ON, because the alternative is not "no safety net", it is a WRONG net. The apply
          unit is a `Type=oneshot` with `RemainAfterExit`, so once it has succeeded it reports
          `active (exited)` for the rest of the boot no matter what happens to the table afterwards.
          Found in production on a public host: unit green, packet filter entirely absent.

          What removes a table is never nixnet: a container runtime's reset path, an overlay client,
          a rollback to a generation with a different firewall, a hand-run `nft flush ruleset`. None
          of them report anything. Presence is checkable, so this checks it.

          A repair does NOT arm the auto-revert dead-man switch — a repair is not an operator
          changing the rules, and there would be nobody waiting to confirm it.
        '';
      };
      intervalSec = lib.mkOption {
        type = lib.types.ints.positive;
        default = 60;
        description = ''
          Seconds between checks, and therefore the worst-case window in which a host runs without
          the firewall it declares. One `nft list chain` per interval; the cost is not the reason to
          raise this.
        '';
      };
    };

    metricsFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "${stateDir}/metrics.prom";
      description = ''
        Where to write Prometheus textfile-collector metrics, or `null` to write none.

        Three series: `nixnet_firewall_enforced` (1 when the loaded table is this generation's),
        `nixnet_firewall_repairs_total`, and `nixnet_firewall_last_check_seconds`. Written by every
        path that establishes the truth of them, atomically, so a collector reading mid-write sees
        the old file rather than half of a new one.

        The default keeps the data next to the rest of this module's state. Point it INTO a
        collector's directory to have it scraped: `nixnet.firewall.metricsFile =
        "/var/lib/node-exporter/textfile/nixnet-firewall.prom"`.

        `enforced 0` is the series that matters. It means the host is not filtering the way it says
        it is, and — unlike the unit's status — it is true in the present tense.
      '';
    };

    tooling = lib.mkOption {
      type = lib.types.listOf (lib.types.enum (lib.attrNames tl.tools));
      default = [ "nft" ];
      description = ''
        Tools for INSPECTING the ruleset this module enforces, installed onto the host.

        Defaults to `[ "nft" ]`, and the default is the behaviour: a host that enforces an
        nftables ruleset must be able to look at one. Found in production the other way round — a
        host enforcing a nixnet table with no `nft` on it anywhere, because applying the ruleset
        reads it from a store path and therefore never needed the binary. Nothing failed; every
        diagnosis did, and the only way to ask the host a question about its own firewall was to
        fetch the tool over the network the firewall may be the reason you cannot use.

        Set to `[ ]` to opt out — appropriate where the distro already ships `nft` and a second
        copy on PATH is not wanted. Unknown names are an evaluation error rather than a silent
        no-op.

        Resolution is per BACKEND (lib/tooling.nix). On NixOS and on system-manager this is a
        nixpkgs build added to `environment.systemPackages`; system-manager does not drive the
        distro's package manager, so a nixpkgs build placed on PATH is the answer there rather than
        a pacman/apt package. On nix-darwin there is NO nftables — macOS filters with pf — and the
        selection is reported as unsatisfiable in `warnings` instead of installing nothing quietly.
      '';
    };

    ruleset = lib.mkOption {
      type = lib.types.lines;
      readOnly = true;
      description = ''
        The generated nftables ruleset. Read-only: hosts describe intent through the options above
        and this is the single rendering of it, so the NixOS and system-manager planes cannot drift.

        Written to the store and loaded from there by `nixnet-firewall.service` — the same unit
        name on both planes — and copied to /etc/nftables/nixnet.nft for reading. Rendered even
        when `enable` is false, so a host can `nix eval` exactly what enabling this would load
        before committing to it.
      '';
    };
  };

  config = lib.mkMerge [
    # Rendered unconditionally, outside the enable gate — same reasoning as
    # `nixnet.overlay.ruleset`: a ruleset you cannot read before it is applied is one you trust
    # blind.
    {
      nixnet.firewall.ruleset = rulesetText;
      nixnet.firewall.overlayConfinement.ranges = derivedConfinementRanges;
    }

    # The derivation, published into the module that owns the confinement rules. mkDefault, so an
    # operator can still override — and the assertions report the disagreement instead of letting
    # the two quietly differ. Gated on the overlay actually advertising routes: setting
    # `confineExternalRanges` on a non-routing peer trips that module's own assertion, which is
    # correct there and would be this module's fault here.
    #
    # NOTE what this block is NOT gated on: `cfg.enable`. A host can run the overlay's confinement
    # while leaving this module's own firewall off, and then this derivation is the only thing
    # deciding where the fence goes. That is why its four guards sit in the UNCONDITIONAL assertion
    # list below rather than beside the rest of the firewall's checks.
    (lib.optionalAttrs (options.nixnet ? overlay) {
      nixnet.overlay.confineExternalRanges =
        lib.mkIf (confinementActive && (overlayCfg.advertiseRoutes or [ ]) != [ ])
          (lib.mkDefault derivedConfinementRanges);
    })

    # OUTSIDE the enable gate on purpose — see `applyUnit` and `teardownScript`: `enable = false`
    # has to mean the table is GONE, which takes a unit present in the generation that disables it.
    # A host that never enables the firewall runs one oneshot per boot that creates and immediately
    # deletes an empty table, and can then never be carrying a previous generation's rules.
    {
      systemd.services.nixnet-firewall = applyUnit;

      # ── TWO TABLES, ONE HOST — and this assertion is OUTSIDE the enable gate ──────────────
      #
      # On a routing peer, nixnet writes two nftables tables: this one (host policy) and
      # `nixnet.overlay`'s (the overlay mechanism's own confinement and source-NAT). Two writers,
      # two units, two apply orders — so the ways they can contradict each other are worth naming,
      # because none of them produce an error at runtime.
      #
      # SAME NAME, FIREWALL ENABLED: both units render `add table; delete table; define` for the
      # SAME table, so whichever applies last deletes the other's chains outright. Concretely: a
      # switch that runs the overlay's apply after this one leaves the host with the confinement
      # and NO input policy — a default-drop chain silently gone, every port open, `systemctl
      # status` green on both units.
      #
      # SAME NAME, FIREWALL DISABLED — the reason this assertion does not live under
      # `mkIf cfg.enable`, where it used to. `applyUnit` above is unconditional by design: with
      # `enable = false` its ExecStart is `teardownScript`, which runs
      # `nft "add table inet <table>; delete table inet <table>"` on EVERY boot. Point `table` at
      # the overlay's name and turn the firewall off, and that teardown deletes the overlay's
      # confinement and source-NAT wholesale, once per boot, with no assertion, no error and both
      # units green. The collision is exactly as fatal with the firewall off as with it on — more
      # so, because nothing is left that even mentions the table.
      #
      # The name is PARSED from the text `nixnet.overlay` will actually load (`overlayTableNames`),
      # not hardcoded here, so renaming it there cannot silently stop this check from matching.
      assertions = [
        {
          assertion = !(lib.elem cfg.table overlayTableNames);
          message = ''
            nixnet.firewall.table is "${cfg.table}", which is also the table nixnet.overlay
            renders into.

            With nixnet.firewall.enable = true, both modules replace their table with
            `add; delete; define`, so the one that applies second deletes the other's chains —
            leaving the host with either no input policy or no overlay confinement, with both
            units reporting success.

            With nixnet.firewall.enable = false it is worse: `nixnet-firewall.service` still runs,
            and its job in that generation is to assert this table is ABSENT. It would delete the
            overlay's confinement and source-NAT on every boot.

            Give this module a table name of its own.
          '';
        }

        # ── The confinement checks, and why they are OUT here too ─────────────────────────────
        #
        # Same reasoning as the table-name assertion above, and measurably so for these: the
        # derivation they guard is published OUTSIDE the enable gate (the
        # `nixnet.overlay.confineExternalRanges` block further up), so a host that runs the overlay
        # for its confinement while leaving THIS module's firewall off gets the derived fence — and,
        # with the checks inside the gate, none of the guards that make it trustworthy.
        #
        # Proved by evaluating it rather than by reading it: with `enable = false` and a band that
        # does not exist, `derivedConfinementRanges` degrades to `[ ]`, `mkDefault [ ]` is published,
        # the overlay renders NO jump to its confine chain, and not one assertion fires. Every
        # least-trust peer then has unrestricted reach into the advertised LAN, both units green and
        # `nft list ruleset` looking correct. `enable = true` on the identical config is an eval
        # error — which is the wrong way round, since `enable` defaults to false.
        #
        # All four are additionally guarded by `confinementActive`, so a host that never sets
        # `overlayConfinement.network` is unaffected either way.
        #
        # DISAGREEING CONTENT: the confinement lives in the overlay's table, this module derives
        # what it should contain. If the effective value drops a derived range, the peers in that
        # part of the band are unconfined — every rule still present, `nft list ruleset` still
        # looking correct, and the hole exactly where the operator believes the fence is.
        {
          assertion =
            !(confinementActive && (overlayCfg.advertiseRoutes or [ ]) != [ ])
            || lib.all (r: lib.elem r (overlayCfg.confineExternalRanges or [ ])) derivedConfinementRanges;
          message = ''
            nixnet.firewall.overlayConfinement derives, from the "${toString confinedBandName}" band:
              ${lib.concatStringsSep ", " derivedConfinementRanges}
            nixnet.overlay.confineExternalRanges does not contain every one of them:
              ${lib.concatStringsSep ", " (overlayCfg.confineExternalRanges or [ ])}

            The confinement is rendered from the overlay's value, so any derived range missing
            above is NOT confined: those peers keep full reach into the advertised LAN while the
            band they belong to is the one the account treats as least-trust. Nothing fails at
            runtime — the rules that exist are correct, the ones that are missing are the point.

            This is a check on the LIST, not on address coverage: each derived CIDR must appear
            verbatim in `confineExternalRanges`. A single wider prefix that happens to contain
            them all trips this too, deliberately — proving containment would mean this module
            re-deriving the boundary a second way, which is the duplicated statement of one fact
            the whole derivation exists to remove.

            So: drop the override and let the band decide, widen the band, or — if the override
            really must stand — include the derived CIDRs above in it verbatim.
          '';
        }
        {
          assertion = !confinementActive || networkMatch != null;
          message = ''
            nixnet.firewall.overlayConfinement.network ("${toString confinement.network}") is not
            a /24. The band scheme it derives from keys off the last octet, so a different prefix
            length means the two declarations are not describing the same address space.
          '';
        }
        {
          assertion = !confinementActive || confinedBandName != null;
          message = ''
            nixnet.firewall.overlayConfinement.network is set but there is no band to derive from:
            `nixnet.netbirdGroupReconcile.excludeFromCatchAll.forBand` is unset and
            `overlayConfinement.band` names nothing. The derivation would produce an empty
            confinement — a fence that evaluates clean and does not exist.
          '';
        }
        {
          assertion = !confinementActive || confinedBands != [ ];
          message = ''
            nixnet.firewall.overlayConfinement derives from band "${toString confinedBandName}",
            which is not among the declared `nixnet.netbirdGroupReconcile.bands`. The derivation
            produces nothing, so the confinement would silently not exist.
          '';
        }
      ];
    }

    (lib.mkIf cfg.enable (lib.mkMerge [
      {
        assertions = [
          {
            # THE assertion. Everything else in this module is convenience; this is the one that
            # stops a machine being lost. A default-drop input policy with no management interface
            # is a config that builds, activates, reports success, and strands the host — and it
            # fails HERE, on the build host, not at activation time on the far end of the ssh
            # session that is about to close.
            assertion = cfg.management.interfaces != [ ] || cfg.trustedInterfaces != [ ];
            message = ''
              nixnet.firewall: refusing to build a default-drop firewall with no way back in.

              `nixnet.firewall.management.interfaces` is empty and so is
              `nixnet.firewall.trustedInterfaces`, so nothing would keep the management port
              reachable. On a remote host this activates cleanly and then strands the machine.

              Set `nixnet.firewall.management.interfaces` to the interface you administer this host
              over — the overlay interface, not the LAN, if the LAN is not how you actually reach it.
            '';
          }
          {
            # The typo class, and the DHCP class, closed by the same check: an interface named in a
            # rule must be one this host has declared, with its addressing stated. A misspelled
            # interface matches nothing and fails OPEN with no error anywhere; an interface whose
            # addressing nobody stated is one whose DHCP accepts nothing can derive.
            assertion = undeclaredInterfaces == [ ];
            message = ''
              nixnet.firewall names an interface that is not declared in `nixnet.interfaces`:
              ${lib.concatStringsSep ", " undeclaredInterfaces}

              A rule naming an interface this host does not have matches nothing and fails OPEN —
              silently, with the rule still sitting there looking correct. Declare the interface
              (with its `addressing`), or fix the name.
            '';
          }
          {
            assertion = addressinglessInterfaces == [ ];
            message = ''
              nixnet.firewall names an interface whose addressing nobody stated:
              ${lib.concatStringsSep ", " addressinglessInterfaces}

              Set both `addressing.v4` and `addressing.v6` (`static`/`dhcp`/`slaac`/`none`/
              `unmanaged`). This is the fact the DHCP client accepts derive from: unset means
              nobody said, and a DHCP-addressed host that nobody said was DHCP-addressed gets a
              default-drop input chain that eats its own lease renewal — a host that stays up for
              most of a day and then goes dark. `unmanaged` is a real answer, and a different one
              from silence.
            '';
          }
          {
            assertion = !cfg.forward.enable -> cfg.forward.rules == [ ];
            message = ''
              nixnet.firewall: `forward.rules` are declared but `forward.enable` is false, so none
              of them apply. Declaring rules into a chain that is never created reads as done and
              does nothing — the same class of silent no-op this module exists to prevent elsewhere.
            '';
          }
          {
            assertion = !cfg.forward.enable -> cfg.forward.trustedInterfacePairs == [ ];
            message = ''
              nixnet.firewall: `forward.trustedInterfacePairs` are declared but `forward.enable`
              is false, so none apply. Enable the forward chain explicitly before granting an
              authenticated transit any forwarding privilege.
            '';
          }
          {
            assertion = lib.all (r: r.ports != [ ] || r.portRanges != [ ]) (cfg.allow ++ cfg.forward.rules);
            message = ''
              nixnet.firewall: a rule in `allow` or `forward.rules` has neither `ports` nor
              `portRanges` set, so it matches nothing — almost certainly a missing value rather than
              an intentional rule.
            '';
          }

        ];

        warnings =
          lib.optional (cfg.trustedInterfaces != [ ] && cfg.management.interfaces == [ ])
            ''
              nixnet.firewall: relying on `trustedInterfaces` alone for management access. That
              works, but it accepts ALL traffic on those interfaces rather than just the management
              port. Prefer `management.interfaces` unless the blanket trust is intended.
            ''
          ++ lib.optional (cfg.forward.enable && isRoutingPeer && overlayInterface == null)
            ''
              nixnet.firewall: this host advertises overlay routes and enables a drop-policy forward
              chain, but nixnet.overlay.overlayInterface is null, so the routed overlay accepts
              could not be derived. Routed traffic will be dropped by this chain.
            ''
          # A selection this backend cannot satisfy is SAID, never silently dropped. Same reasoning
          # as the tool catalogue's own `null`: "installed nothing because there is nothing to
          # install" and "installed nothing" are the same observation from outside unless one of
          # them speaks.
          ++ lib.optional (tooling.unavailable != [ ])
            (tl.unavailableWarning {
              option = "nixnet.firewall.tooling";
              inherit (tooling) backend unavailable;
            });

        # `environment.systemPackages` is the SAME option name on both Linux backends -- NixOS
        # links it into the system profile, system-manager buildEnv's it into
        # /run/system-manager/sw and puts that on PATH -- so the install site needs no backend
        # branch at all. What needed one is the package NAME, and that lives in lib/tooling.nix.
        environment.systemPackages =
          lib.optionals cfg.autoRevert.enable [ confirm ]
          ++ tooling.packages;

        systemd.services.nixnet-firewall-revert = lib.mkIf cfg.autoRevert.enable {
          description = "nixnet: restore the previous ruleset (confirmation window expired)";
          serviceConfig = { Type = "oneshot"; ExecStart = "${revertScript}"; };
        };

        # Deliberately NOT `wantedBy = [ "timers.target" ]`. That is what armed the countdown on
        # every boot regardless of whether anything had changed; the apply path starts this timer
        # explicitly, and only when the ruleset differs from the last one applied.
        systemd.timers.nixnet-firewall-revert = lib.mkIf cfg.autoRevert.enable {
          description = "nixnet: auto-revert countdown";
          timerConfig = {
            OnActiveSec = cfg.autoRevert.seconds;
            AccuracySec = "1s";
            RemainAfterElapse = false;
          };
        };

        # FW-4. This one IS `wantedBy = timers.target` — the opposite of the revert timer above, and
        # for the opposite reason: the revert must fire only when an operator changed something,
        # this must fire always, because the events it watches for are precisely the ones nobody
        # announces.
        systemd.services.nixnet-firewall-reconcile = lib.mkIf cfg.reconcile.enable {
          description = "nixnet: verify the packet filter is in force, and reload it if not";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${reconcileScript}";
          };
        };

        systemd.timers.nixnet-firewall-reconcile = lib.mkIf cfg.reconcile.enable {
          description = "nixnet: firewall reconcile interval";
          wantedBy = [ "timers.target" ];
          timerConfig = {
            # OnBootSec, not OnStartupSec: the first check is a real check, after the apply unit has
            # had its turn. A check that races the apply reports a drift that is one second old.
            OnBootSec = "${toString cfg.reconcile.intervalSec}s";
            OnUnitActiveSec = "${toString cfg.reconcile.intervalSec}s";
            AccuracySec = "5s";
            Unit = "nixnet-firewall-reconcile.service";
          };
        };
      }

      # The ruleset on disk, for a human with an `nft` and a question. The unit does NOT load it
      # from here (it names the store path, see `rulesetFile`); this copy is documentation that
      # happens to be executable.
      #
      # `replaceExisting` is system-manager-only, and there it is not tidiness: on a foreign distro
      # the distro's own package may already own this path, and without the flag system-manager
      # SILENTLY SKIPS the file — the module would appear to apply, change nothing, and leave
      # whatever was there in force. It does not exist as an option under real NixOS at all, hence
      # `optionalAttrs` rather than `mkIf`: the module system checks a definition's structural KEYS
      # against declared options independent of any mkIf condition, the same trap core.nix
      # documents for `system.activationScripts`.
      {
        environment.etc."nftables/nixnet.nft" = {
          source = rulesetFile;
          mode = "0444";
        } // lib.optionalAttrs isSystemManager {
          replaceExisting = true;
        };
      }

      (lib.optionalAttrs (!isSystemManager) {
        assertions = [
          {
            # Two default-drop input chains at the same hook is not "belt and braces": every base
            # chain sees the packet and ANY chain's drop is final, so the effective policy is the
            # INTERSECTION of the two accept sets. A port this module opens that nixpkgs' firewall
            # does not is closed anyway, with both configurations looking correct in isolation.
            assertion = !(config.networking.firewall.enable or false)
              && !(config.networking.nftables.enable or false);
            message = ''
              nixnet.firewall is enabled alongside networking.firewall or networking.nftables.

              Set `networking.firewall.enable = false;` (it defaults to true) and leave
              `networking.nftables.enable` off.

              Two default-drop input chains at one hook intersect rather than combine: a rule this
              module accepts is still dropped if the other chain does not, and neither
              configuration looks wrong on its own. nixpkgs' nftables module additionally defaults
              to `flush ruleset` whenever it is handed a raw ruleset, which would take every other
              table on this host with it.
            '';
          }
        ];
      })
    ]))
  ];
}
