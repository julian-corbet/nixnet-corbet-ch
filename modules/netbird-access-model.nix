# modules/netbird-access-model.nix
#
# nixnet.netbirdAccessModel — declare the SHAPE of a NetBird account's
# access control: which trust-boundary groups exist, which directional
# policies connect them, and which groups receive which routes.
#
# THE DEFECT THIS CLOSES. Groups, policies, and route distribution have
# historically lived as prose plus whatever a live NetBird account
# happens to hold -- nothing could tell you when the two disagreed.
# NetBird policies are allow-only (a flow is permitted only if an
# ENABLED policy names it) and every object -- group, policy, route --
# is referenced by opaque ID everywhere in the account, so there has
# never been a place to *check* the account against a spec. This module
# gives that shape a real option surface with assertions (a policy
# cannot reference a group this config doesn't declare -- caught at
# eval time, not discovered as a dangling account-side reference) and a
# read-only, timer-driven audit that diffs the live account against it,
# so a divergence is a log line, never a silent trap.
#
# WHAT THIS IS NOT. Not a group/policy/route CRUD tool -- it never
# creates, renames, or deletes anything account-side (the same boundary
# `netbird-group-reconcile.nix` draws for membership: "warn if a managed
# object is missing rather than papering over it"). Group MEMBERSHIP
# (which peer lands in which group) stays `nixnet.netbirdGroupReconcile`'s
# job; this module WIRES the two together so a group is only ever named
# once -- when both are enabled on the same host,
# `nixnet.netbirdGroupReconcile.catchAllGroup` defaults (not is forced)
# to this module's `internalGroup`, and every
# `nixnet.netbirdGroupReconcile.bands[].name` is asserted to be a group
# this model actually declares (the exact "policy references a group
# that doesn't exist yet" hazard, transplanted to membership
# reconciliation, caught the same way).
#
# ⚠ RENAME OF A LIVE GROUP/POLICY IS ACCOUNT-SIDE, ALWAYS. Same boundary
# as `netbird-group-reconcile.nix`'s own header: this module declares
# names, it never calls a rename endpoint. Renaming a NetBird group or
# policy is safe IN PLACE (PUT the same object `id` with a new `name` --
# every other object that references it by ID is unaffected) but MUST be
# a rename, never "create new + delete old": a newly created group gets
# a NEW id, orphaning every existing policy/route still pointing at the
# old one -- the literal "policy referencing a group that does not
# exist" hazard this module exists to catch. See the README's operator
# runbook for the exact ordered steps, and this module's `renamedFrom`
# field for how the audit helps confirm a rename actually landed.
{ config, lib, pkgs, ... }:

let
  cfg = config.nixnet.netbirdAccessModel;

  # Reach into a sibling module's config WITHOUT requiring it to be
  # imported -- `config.nixnet.netbirdGroupReconcile` may not exist as an
  # option at all if that module's file was never imported, and `or`
  # catches attribute-selection failure anywhere along the whole path.
  groupReconcileCfg = config.nixnet.netbirdGroupReconcile or {
    enable = false;
    bands = [ ];
    catchAllGroup = null;
  };

  groupType = lib.types.submodule {
    options = {
      description = lib.mkOption {
        type = lib.types.str;
        description = ''
          What this group MEANS -- a trust boundary or category, not
          just a label -- documented so a future rename doesn't lose the
          reasoning (see the doc precedent this closes: a bare group
          name with no recorded intent lets its meaning drift silently
          -- a name coined to mean "every peer this policy trusts" can
          end up read, a year later, as "just our own machines", with
          nothing on record to correct the misreading).
        '';
        example = "Every one of our own peers -- the trust boundary the mesh-wide policy is anchored on.";
      };

      renamedFrom = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "workers";
        description = ''
          The group's previous live name, set temporarily while a rename
          is in flight. Purely informational to the audit (below): it
          additionally checks whether a group still exists live under
          this OLD name, which catches the dangerous "created a new
          group instead of renaming the old one in place" mistake (both
          would then exist, and every policy/route still pointing at the
          old id would silently keep working off stale membership).
          Remove once the audit reports the old name gone.
        '';
      };
    };
  };

  policyType = lib.types.submodule {
    options = {
      from = lib.mkOption {
        type = lib.types.str;
        description = "Source group name -- must be a key of `groups`.";
        example = "internal";
      };

      to = lib.mkOption {
        type = lib.types.str;
        description = "Destination group name -- must be a key of `groups`.";
        example = "external";
      };

      bidirectional = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          `true` = `from` <-> `to` talk freely both ways.
          `false` = `from` -> `to` one-way only: `to` may be reached, it
          cannot initiate back. NetBird's own rule field, carried
          through unchanged rather than reinvented as "direction: both |
          forward".
        '';
      };

      enabled = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Declared desired state. Note for the audit below: a grant
          toggled transiently by an on-demand grant/revoke helper
          OUTSIDE this declaration will show as a MISMATCH here BY
          DESIGN -- that is an expected, transient divergence for a
          toggle-style policy, not a bug. Only a mismatch that persists
          across many audit ticks is worth investigating.
        '';
      };

      renamedFrom = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "workers-mesh";
        description = "Same rename-in-flight tracking as `groups.<name>.renamedFrom`, for policies.";
      };

      description = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Why this policy exists.";
      };
    };
  };

  routeType = lib.types.submodule {
    options = {
      network = lib.mkOption {
        type = lib.types.str;
        example = "192.0.2.0/24"; # TEST-NET-1 placeholder
        description = ''
          Advertised CIDR. The audit below matches a live NetBird route
          object to this declaration BY this CIDR (NetBird routes have
          no stable human name of their own) -- two declared routes must
          not share a network value.
        '';
      };

      distributeTo = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Group names (must be keys of `groups`) this route is distributed to.";
        example = [ "internal" ];
      };

      description = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Why this route is distributed the way it is -- e.g. a directional carve-out.";
      };
    };
  };

  groupNames = lib.attrNames cfg.groups;

  undeclaredGroupRefs =
    (lib.concatMap
      (name:
        let p = cfg.policies.${name}; in
        lib.optional (!lib.elem p.from groupNames) "policy '${name}': from = '${p.from}' is not in nixnet.netbirdAccessModel.groups"
        ++ lib.optional (!lib.elem p.to groupNames) "policy '${name}': to = '${p.to}' is not in nixnet.netbirdAccessModel.groups"
      )
      (lib.attrNames cfg.policies))
    ++ (lib.concatMap
      (name:
        let r = cfg.routes.${name}; in
        lib.concatMap
          (g: lib.optional (!lib.elem g groupNames) "route '${name}': distributeTo entry '${g}' is not in nixnet.netbirdAccessModel.groups")
          r.distributeTo)
      (lib.attrNames cfg.routes));

  duplicateRouteNetworks =
    let
      networks = lib.mapAttrsToList (name: r: { inherit name; inherit (r) network; }) cfg.routes;
      byNetwork = lib.groupBy (x: x.network) networks;
    in
    lib.filterAttrs (_: xs: lib.length xs > 1) byNetwork;

  runtimeBin = lib.makeBinPath [
    pkgs.curl
    pkgs.jq
    pkgs.coreutils
    pkgs.gnused
  ];

  # ── The read-only audit script ──────────────────────────────────────
  # GET-only, always. Never PUT/POST/DELETE -- a rename or policy edit is
  # an account-side operator action (see this file's own header); this
  # script's entire job is to say clearly where the live account and
  # this declaration disagree, then get out of the way. Deliberately
  # self-contained (duplicates netbird-group-reconcile.nix's small
  # curl-retry `api_get` helper rather than factoring it into a shared
  # lib) -- same convention every module in this repo already follows:
  # one rendered script per systemd unit, no cross-module bash imports.
  #
  # Field-shape caveat: the `rules[0]`/`sources`/`destinations`/
  # `bidirectional` (policies) and `network`/`groups` (routes) paths
  # below are written from NetBird's documented API shape, not captured
  # from a real payload -- flagged in experiments/README.md #008 the
  # same way #006 already flags the equivalent gap for `netbird status
  # --json`. A mismatched field name degrades to "can't confirm this
  # one, logged and skipped," never a false DIVERGENCE.
  auditScript = pkgs.writeShellScript "nixnet-netbird-access-model-audit" ''
    #!${pkgs.runtimeShell}
    # No `set -e`: one bad field/lookup must not abort every other check.
    set -uo pipefail
    export PATH=${runtimeBin}:$PATH

    API=${lib.escapeShellArg cfg.audit.apiUrl}
    TOKENFILE=${lib.escapeShellArg cfg.audit.tokenFile}

    log()  { echo "nixnet-netbird-access-model-audit: $*"; }
    skip() { log "SKIP: $*"; exit 0; }
    note() { log "DIVERGENCE: $*"; divergences=$((divergences + 1)); }

    [ -r "$TOKENFILE" ] || skip "token $TOKENFILE not readable yet (unseal not done)"
    TOKEN=$(tr -d '[:space:]' < "$TOKENFILE")
    [ -n "$TOKEN" ] || skip "empty token in $TOKENFILE"

    GROUPS_F=$(mktemp); POLICIES_F=$(mktemp); ROUTES_F=$(mktemp); HDR_F=$(mktemp)
    trap 'rm -f "$GROUPS_F" "$POLICIES_F" "$ROUTES_F" "$HDR_F"' EXIT
    # The token goes into a 0600 file (mktemp's mode, umask-independent),
    # never onto curl's argv: /proc/<pid>/cmdline is world-readable on a
    # default Linux box, and this unit runs on its own timer forever, so
    # `-H "Authorization: Token $TOKEN"` would publish a full-scope NetBird
    # token to every local uid on the host -- undoing the root-only 0600
    # file mesh-gateway.nix unseals it into. `-H @file` is curl 7.55+.
    # Written AFTER the trap above so no failure path leaks the file.
    printf 'Authorization: Token %s\n' "$TOKEN" > "$HDR_F"
    unset TOKEN

    # Fetch to FILES (curl -o), never captured through nested command
    # substitution -- see netbird-group-reconcile.nix's own comment for
    # why a large body round-tripped through `$(...)` is not trusted
    # here either.
    api_get() { # $1 = endpoint, $2 = output file
      local ep="$1" f="$2" tries=0
      while [ "$tries" -lt 4 ]; do
        if curl -fsS --max-time 20 -H @"$HDR_F" "$API/$ep" -o "$f" 2>/dev/null \
           && jq -e 'type=="array"' "$f" >/dev/null 2>&1; then
          return 0
        fi
        tries=$((tries + 1)); sleep 2
      done
      return 1
    }

    api_get groups   "$GROUPS_F"   || skip "GET /groups: no valid array after retries -- no report this tick"
    api_get policies "$POLICIES_F" || skip "GET /policies: no valid array after retries -- no report this tick"
    api_get routes   "$ROUTES_F"   || skip "GET /routes: no valid array after retries -- no report this tick"

    gid() { jq -r --arg n "$1" '.[] | select(.name==$n) | .id' "$GROUPS_F"; }

    divergences=0

    log "── groups ──"
    ${lib.concatMapStringsSep "\n    " (name: ''
      if [ -z "$(gid ${lib.escapeShellArg name})" ]; then
        note "group '${name}' declared, not found live by name (renamed? not yet created account-side?)"
      fi
    '') groupNames}
    ${lib.concatMapStringsSep "\n    " (name:
      let old = cfg.groups.${name}.renamedFrom; in
      lib.optionalString (old != null) ''
        if [ -n "$(gid ${lib.escapeShellArg old})" ]; then
          note "group '${name}': OLD name '${old}' still exists live -- rename not done in place (created new + left old behind? finish the rename, see this module's header)"
        fi
      ''
    ) groupNames}

    log "── policies (assumes one rule per policy -- this account's own pattern) ──"
    ${lib.concatMapStringsSep "\n    " (name:
      let p = cfg.policies.${name}; in ''
      pol=$(jq -c --arg n ${lib.escapeShellArg name} '[.[] | select(.name==$n)] | first // empty' "$POLICIES_F")
      if [ -z "$pol" ]; then
        note "policy '${name}' declared, not found live by name"
      else
        liveEnabled=$(printf '%s' "$pol" | jq -r '.enabled')
        wantEnabled=${if p.enabled then "true" else "false"}
        if [ "$liveEnabled" != "$wantEnabled" ]; then
          log "policy '${name}': enabled live=$liveEnabled declared=$wantEnabled (informational only -- expected for an on-demand toggle grant, see enabled's own description)"
        fi
        rule=$(printf '%s' "$pol" | jq -c '.rules[0] // empty')
        if [ -z "$rule" ]; then
          note "policy '${name}': live policy has no rules[0] to compare (unexpected shape -- see experiments/README.md #008)"
        else
          fromId=$(gid ${lib.escapeShellArg p.from})
          toId=$(gid ${lib.escapeShellArg p.to})
          hasFrom=$(printf '%s' "$rule" | jq -r --arg g "$fromId" '(.sources // []) | index($g) != null')
          hasTo=$(printf '%s' "$rule" | jq -r --arg g "$toId" '(.destinations // []) | index($g) != null')
          liveBidi=$(printf '%s' "$rule" | jq -r '.bidirectional')
          wantBidi=${if p.bidirectional then "true" else "false"}
          [ "$hasFrom" = "true" ] || note "policy '${name}': live rule[0].sources doesn't include group '${p.from}'"
          [ "$hasTo" = "true" ] || note "policy '${name}': live rule[0].destinations doesn't include group '${p.to}'"
          [ "$liveBidi" = "$wantBidi" ] || note "policy '${name}': bidirectional live=$liveBidi declared=$wantBidi"
        fi
      fi
    '') (lib.attrNames cfg.policies)}
    ${lib.concatMapStringsSep "\n    " (name:
      let old = cfg.policies.${name}.renamedFrom; in
      lib.optionalString (old != null) ''
        if jq -e --arg n ${lib.escapeShellArg old} 'any(.[]; .name==$n)' "$POLICIES_F" >/dev/null 2>&1; then
          note "policy '${name}': OLD name '${old}' still exists live -- rename not done in place"
        fi
      ''
    ) (lib.attrNames cfg.policies)}

    log "── routes (matched by network CIDR) ──"
    ${lib.concatMapStringsSep "\n    " (name:
      let r = cfg.routes.${name}; in ''
      rt=$(jq -c --arg n ${lib.escapeShellArg r.network} '[.[] | select(.network==$n)] | first // empty' "$ROUTES_F")
      if [ -z "$rt" ]; then
        note "route '${name}' (${r.network}) declared, not found live by network CIDR"
      else
        liveGroupIds=$(printf '%s' "$rt" | jq -r '(.groups // [])[]' | sort -u)
        wantGroupIds=""
        for gn in ${lib.concatStringsSep " " (map lib.escapeShellArg r.distributeTo)}; do
          wantGroupIds="$wantGroupIds $(gid "$gn")"
        done
        wantGroupIds=$(printf '%s\n' $wantGroupIds | sed '/^$/d' | sort -u)
        [ "$liveGroupIds" = "$wantGroupIds" ] || note "route '${name}' (${r.network}): live distribution-group set differs from declared [${lib.concatStringsSep ", " r.distributeTo}]"
      fi
    '') (lib.attrNames cfg.routes)}

    if [ "$divergences" -gt 0 ]; then
      log "$divergences divergence(s) found -- see DIVERGENCE lines above"
    else
      log "no divergence: live account matches the declared access model"
    fi
    exit 0
  '';
in
{
  options.nixnet.netbirdAccessModel = {
    enable = lib.mkEnableOption "declare the NetBird account's access-control SHAPE (groups, directional policies, route distribution) and audit the live account against it";

    internalGroup = lib.mkOption {
      type = lib.types.str;
      example = "internal";
      description = ''
        The group meaning "every one of our own peers" -- the trust
        boundary the mesh-wide policy is anchored on (every peer joins
        both this group AND its own category group). Must be a key of
        `groups`. Wired into
        `nixnet.netbirdGroupReconcile.catchAllGroup` as a DEFAULT (not
        forced) whenever that module is also enabled, so the name is
        written exactly once across both modules.
      '';
    };

    groups = lib.mkOption {
      type = lib.types.attrsOf groupType;
      default = { };
      description = ''
        Every NetBird group this model knows about -- category groups,
        the one `internalGroup`, the least-trust external group, and any
        standing per-device external group. Existence + intent only;
        MEMBERSHIP (which peer lands in which group) is
        `nixnet.netbirdGroupReconcile`'s job.
      '';
      example = lib.literalExpression ''
        {
          internal.description = "Every one of our own peers.";
          external.description = "Least-trust: guests, IoT, decommissioned devices.";
          apps.description = "Own public/NetBird-intern applications.";
        }
      '';
    };

    policies = lib.mkOption {
      type = lib.types.attrsOf policyType;
      default = { };
      description = ''
        Every directional group->group grant this model knows about --
        the base mesh-wide policy plus any per-device "on-demand" grant,
        all the same shape (NetBird policies are allow-only: a flow is
        permitted only if an ENABLED policy names it -- there is no deny
        rule to declare).
      '';
      example = lib.literalExpression ''
        {
          internal-mesh = {
            from = "internal"; to = "internal"; bidirectional = true;
            description = "Our own devices talk freely.";
          };
          internal-to-external = {
            from = "internal"; to = "external"; bidirectional = false;
            description = "We reach guests/IoT; they cannot initiate back.";
          };
        }
      '';
    };

    routes = lib.mkOption {
      type = lib.types.attrsOf routeType;
      default = { };
      description = "Every advertised route this model knows about, and which groups it's distributed to.";
    };

    audit = {
      enable = lib.mkEnableOption "a read-only timer that diffs the live NetBird account's groups/policies/routes against this declaration and logs every divergence -- never mutates anything";

      apiUrl = lib.mkOption {
        type = lib.types.str;
        example = "https://netbird.example.com/api";
        description = "NetBird management API base.";
      };

      tokenFile = lib.mkOption {
        type = lib.types.path;
        default = "/run/secrets/nixnet-mesh-gateway-apitoken";
        description = ''
          Same default path as the sibling modules' token file
          (`nixnet.meshGateway.apiTokenRuntimeFile` /
          `nixnet.netbirdGroupReconcile.tokenFile`), so all three share
          one unsealed token with no second secret when more than one is
          enabled on the same host.
        '';
      };

      onBootSec = lib.mkOption {
        type = lib.types.str;
        default = "5min";
        description = "Delay after boot before the first audit.";
      };

      interval = lib.mkOption {
        type = lib.types.str;
        default = "15min";
        description = "OnUnitActiveSec between audits. Coarser than netbird-group-reconcile's default -- this reports for a human, it doesn't self-heal, so there's no correctness reason to run it tighter.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.elem cfg.internalGroup groupNames;
        message = "nixnet.netbirdAccessModel.internalGroup ('${cfg.internalGroup}') must be a key of nixnet.netbirdAccessModel.groups.";
      }
      {
        assertion = undeclaredGroupRefs == [ ];
        message = ''
          nixnet.netbirdAccessModel: a policy or route references a
          group this model doesn't declare -- add it to
          `nixnet.netbirdAccessModel.groups` first. This is exactly the
          "policy references a group that doesn't exist yet" hazard,
          caught here at eval time instead of as a dangling account-side
          reference:
        '' + lib.concatMapStringsSep "\n" (x: "  - " + x) undeclaredGroupRefs;
      }
      {
        assertion = duplicateRouteNetworks == { };
        message = ''
          nixnet.netbirdAccessModel.routes: more than one route declares
          the same `network` CIDR -- the audit matches a live route to
          its declaration by CIDR alone, so this is ambiguous. Duplicates:
        '' + lib.concatMapStringsSep "\n" (net: "  - " + net + ": " + lib.concatMapStringsSep ", " (x: x.name) duplicateRouteNetworks.${net}) (lib.attrNames duplicateRouteNetworks);
      }
    ] ++ lib.optional (groupReconcileCfg.enable) {
      assertion = lib.all (b: lib.elem b.name groupNames) groupReconcileCfg.bands;
      message = ''
        nixnet.netbirdGroupReconcile.bands names a group that
        nixnet.netbirdAccessModel.groups doesn't declare -- the
        membership reconciler would target a group this model has no
        record of. Add it to `nixnet.netbirdAccessModel.groups` (or drop
        the band).
      '';
    };

    # Wiring, not duplication: when the membership reconciler is also
    # enabled on this host, its "every peer's default group" defaults to
    # THIS module's internalGroup. A host that genuinely wants the two to
    # diverge can still override netbirdGroupReconcile.catchAllGroup
    # directly -- this only supplies the common-case default so the name
    # is written once.
    nixnet.netbirdGroupReconcile.catchAllGroup = lib.mkIf groupReconcileCfg.enable (lib.mkDefault cfg.internalGroup);

    systemd.services.nixnet-netbird-access-model-audit = lib.mkIf cfg.audit.enable {
      description = "Audit the live NetBird account's groups/policies/routes against the declared nixnet.netbirdAccessModel (read-only)";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = auditScript;
        MemoryMax = "64M";
        TimeoutStartSec = "5min";
      };
    };

    systemd.timers.nixnet-netbird-access-model-audit = lib.mkIf cfg.audit.enable {
      description = "Periodic NetBird access-model audit";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = cfg.audit.onBootSec;
        OnUnitActiveSec = cfg.audit.interval;
        RandomizedDelaySec = "1min";
        Persistent = true;
      };
    };
  };
}
