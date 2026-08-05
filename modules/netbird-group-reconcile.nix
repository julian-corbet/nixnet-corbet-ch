# modules/netbird-group-reconcile.nix
#
# nixnet.netbirdGroupReconcile — keep NetBird peer->group membership in
# sync with a declared IP-octet addressing scheme, on a timer.
#
# WHY. A NetBird ACL model commonly grants access group->group, by octet
# band (e.g. "this whole band of peers may reach that whole band"). For a
# forward-grant to actually pick up a peer that appears LATER, the peer
# must land in the right group automatically as soon as it's enrolled and
# has an address — enrollment alone (e.g. an `auto_groups` on the setup
# key) puts a peer in a single default group, but cannot band-sort, because
# the peer's overlay address is assigned by the control plane, not known at
# key-creation time. This reconciler closes that gap: each tick it reads
# the live peer list and re-derives every MANAGED group's membership purely
# from each peer's IP octet, then PUTs any group whose set drifted.
#
# WHAT IT LEAVES ALONE. Any group not listed in `bands`/`catchAllGroup`
# (auto-created groups, per-device hand-set groups) and every policy.
# Group MEMBERSHIP only — it never creates/deletes groups or policies (a
# recreated group would orphan the policies that reference its id), and it
# warns if a managed group is missing rather than papering over it.
#
# SAFE BY CONSTRUCTION. Read-mostly; on any API hiccup it logs and exits 0
# (never a crash-loop, never a partial wipe). The PUT is declarative
# desired-state, so a re-IP'd or deleted peer self-corrects on the next
# tick.
#
# ⚠ `bands.*.name` / `catchAllGroup` / `excludeFromCatchAll.groupName`
# values are LIVE NetBird object names (real, already-configured groups
# your account's policies reference by name), not free-form labels this
# module invents — get them from your own NetBird account before wiring
# this in, and do not rename a group here expecting NetBird to follow;
# renaming a group is an account-side change with its own outage window.
{ config, lib, pkgs, ... }:

let
  cfg = config.nixnet.netbirdGroupReconcile;

  bandType = lib.types.submodule {
    options = {
      min = lib.mkOption { type = lib.types.ints.between 0 255; description = "Octet range start (inclusive)."; };
      max = lib.mkOption { type = lib.types.ints.between 0 255; description = "Octet range end (inclusive)."; };
      name = lib.mkOption { type = lib.types.str; description = "The live NetBird group name this band maps to."; };
    };
  };

  runtimeBin = lib.makeBinPath [
    pkgs.curl
    pkgs.jq
    pkgs.coreutils
    pkgs.gnused
  ];

  bandFnBody = lib.concatMapStringsSep "\n      " (b: ''
    if [ "$o" -ge ${toString b.min} ] && [ "$o" -le ${toString b.max} ]; then echo ${lib.escapeShellArg b.name}; return; fi
  '') cfg.bands;

  managedGroupNames = lib.unique ((map (b: b.name) cfg.bands) ++ [ cfg.catchAllGroup ]);

  # A shell-safe stand-in for "no excluded band" that can never equal a real
  # band name or the empty string `band()` returns for an unmatched octet --
  # `escapeShellArg` needs a string, and `excludeFromCatchAll.forBand`'s Nix
  # value is `null` in the common case (every band also joins the catch-all).
  excludeBandShell =
    if cfg.excludeFromCatchAll.forBand == null
    then "__nixnet_no_exclude__"
    else cfg.excludeFromCatchAll.forBand;

  reconcile = pkgs.writeShellScript "nixnet-netbird-group-reconcile" ''
    #!${pkgs.runtimeShell}
    # No `set -e`: an API blip mid-loop must not skip the rest / abort recovery.
    # Every failure is handled explicitly; the default is "leave the account as-is".
    set -uo pipefail
    export PATH=${runtimeBin}:$PATH

    API=${lib.escapeShellArg cfg.apiUrl}
    TOKENFILE=${lib.escapeShellArg cfg.tokenFile}

    log()  { echo "nixnet-netbird-group-reconcile: $*"; }
    skip() { log "SKIP: $*"; exit 0; }

    [ -r "$TOKENFILE" ] || skip "token $TOKENFILE not readable yet (unseal not done)"
    TOKEN=$(tr -d '[:space:]' < "$TOKENFILE")
    [ -n "$TOKEN" ] || skip "empty token in $TOKENFILE"

    # Fetch to FILES (curl -o), never captured through nested command
    # substitution -- a large curl body round-tripped through `$(...)`
    # twice in a row has been observed to intermittently truncate the
    # SECOND fetch. api_get retries and validates the file is a JSON
    # array, so a transient bad response is a clean no-op (skip), never a
    # partial group wipe.
    #
    # HDR_F is the same idea applied to the credential: the token must
    # never become a curl ARGV element. /proc/<pid>/cmdline is world-
    # readable on a default Linux box (nothing here or in any consumer
    # sets hidepid= / ProtectProc=), and this unit re-runs every
    # `interval` forever, spawning one token-bearing curl per managed
    # group per tick -- each with --max-time 20 and up to 4 retries, so
    # the window is tens of seconds, not microseconds. Any local uid that
    # polls /proc (including a hostPID:true container running as nobody)
    # would harvest a full-scope NetBird token: /api/groups, /api/policies,
    # /api/routes -- the whole ACL model. That would also undo the
    # boundary mesh-gateway.nix builds one file over: it unseals this
    # exact token to a root-owned 0600 file precisely so it stays off
    # every other uid's radar. `-H @file` (curl 7.55+) reads the header
    # from a file instead; mktemp creates it 0600 regardless of umask, and
    # the trap is installed BEFORE the secret is written into it so no
    # failure path can leave it behind.
    PEERS_F=$(mktemp); GROUPS_F=$(mktemp); HDR_F=$(mktemp)
    trap 'rm -f "$PEERS_F" "$GROUPS_F" "$HDR_F"' EXIT
    printf 'Authorization: Token %s\n' "$TOKEN" > "$HDR_F"
    unset TOKEN

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

    api_get peers  "$PEERS_F"  || skip "GET /peers: no valid array after retries — no change"
    api_get groups "$GROUPS_F" || skip "GET /groups: no valid array after retries — no change"

    # GUARD 1 (global floor): `type=="array"` proves it's an array, not a
    # SANE one. A valid-but-empty [] (or truncated) response would compute
    # every group's desired membership as empty and PUT them all empty —
    # wiping every managed group at once. Never reconcile off a degenerate
    # peer list; a bad response must be a clean no-op, not a wipe.
    PCOUNT=$(jq 'length' "$PEERS_F" 2>/dev/null || echo 0)
    [ "$PCOUNT" -ge 1 ] 2>/dev/null || skip "peers response has $PCOUNT entries — refusing to reconcile (would wipe groups)"

    # last-octet -> managed band group name ("" = not managed by any band)
    band() {
      local o=$1
      ${bandFnBody}
      echo ""
    }

    MANAGED="${lib.concatStringsSep " " managedGroupNames}"
    declare -A DESIRED
    for g in $MANAGED; do DESIRED[$g]=""; done

    # Build desired membership from each peer's IP octet.
    while read -r id ip; do
      [ -n "$id" ] || continue
      [ "$ip" != "null" ] || { log "WARN: peer $id has no IP — skipping"; continue; }
      o=''${ip##*.}
      b=$(band "$o")
      if [ "$b" = ${lib.escapeShellArg excludeBandShell} ]; then
        DESIRED[$b]+=" $id"
      else
        DESIRED[${lib.escapeShellArg cfg.catchAllGroup}]+=" $id"
        [ -n "$b" ] && DESIRED[$b]+=" $id"
      fi
    done < <(jq -r '.[] | select(.ip != null) | "\(.id) \(.ip)"' "$PEERS_F")

    changed=0
    for g in $MANAGED; do
      gid=$(jq -r --arg n "$g" '.[] | select(.name==$n) | .id' "$GROUPS_F")
      if [ -z "$gid" ] || [ "$gid" = "null" ]; then
        log "WARN: managed group '$g' absent — create it once (this is membership-only)"; continue
      fi
      want=$(printf '%s\n' ''${DESIRED[$g]} | sed '/^$/d' | sort -u)
      have=$(jq -r --arg n "$g" \
        '.[] | select(.name==$n) | .peers[]? | if type=="object" then .id else . end' "$GROUPS_F" | sort -u)
      [ "$want" = "$have" ] && continue
      # GUARD 2 (per-group anti-wipe): never PUT a currently-non-empty
      # group down to EMPTY. A to-zero delta is almost always bad input
      # (partial response), not real state — refuse it and alarm. A
      # genuine "remove the last member" is rare and stays a manual op.
      # This protects the catch-all group from a partial response GUARD
      # 1's floor (>=1 peer) wouldn't catch.
      if [ -z "$want" ] && [ -n "$have" ]; then
        log "WARN: '$g' would be emptied ($(printf '%s\n' $have | grep -c . )→0) — refusing to wipe (bad response? manual removal? investigate)"; continue
      fi
      peers_json=$(printf '%s\n' $want | sed '/^$/d' | jq -R . | jq -s .)
      body=$(jq -n --arg name "$g" --argjson peers "$peers_json" '{name:$name, peers:$peers}')
      if curl -fsS --max-time 20 -H @"$HDR_F" -H 'Content-Type: application/json' \
           -X PUT -d "$body" "$API/groups/$gid" >/dev/null; then
        n=$(printf '%s\n' $want | sed '/^$/d' | wc -l | tr -d ' ')
        log "reconciled '$g' → $n peers"; changed=1
      else
        log "WARN: PUT group '$g' failed — will retry next tick"
      fi
    done

    [ "$changed" = 0 ] && log "no changes (all managed groups already in desired state)"
    exit 0
  '';
in
{
  options.nixnet.netbirdGroupReconcile = {
    enable = lib.mkEnableOption "reconcile NetBird peer->group membership from a declared octet addressing scheme (timer)";

    apiUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://netbird.example.com/api";
      description = "NetBird management API base.";
    };

    tokenFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/secrets/nixnet-mesh-gateway-apitoken";
      description = ''
        Path to the NetBird API token. Defaults to
        `nixnet.meshGateway.apiTokenRuntimeFile`'s own default so the two
        modules share one unsealed token with no second secret when both
        are enabled on the same host — override if this host reconciles
        groups without also running `nixnet.meshGateway`.
      '';
    };

    bands = lib.mkOption {
      type = lib.types.listOf bandType;
      default = [ ];
      example = lib.literalExpression ''
        [
          { min = 80;  max = 95;  name = "management"; }
          { min = 160; max = 175; name = "apps"; }
        ]
      '';
      description = ''
        Octet ranges mapped to a live NetBird group name each. A peer whose
        overlay address's last octet falls in a band's [min,max] is put in
        that band's group (in addition to the catch-all group, unless the
        band matches `excludeFromCatchAll.forBand`).
      '';
    };

    catchAllGroup = lib.mkOption {
      type = lib.types.str;
      example = "all-peers";
      description = "Live NetBird group name every reconciled peer belongs to, except those in `excludeFromCatchAll.forBand`.";
    };

    excludeFromCatchAll = {
      forBand = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "external";
        description = ''
          One band `name` (from `bands`) whose members are put ONLY in
          their own band's group, never also in `catchAllGroup` — the
          asymmetry a least-trust external band typically needs (reachable
          BY the rest of the account, initiating nothing itself). `null`
          (default) means every band's members also join `catchAllGroup`.
        '';
      };
    };

    onBootSec = lib.mkOption {
      type = lib.types.str;
      default = "5min";
      description = "Delay after boot before the first reconcile.";
    };

    interval = lib.mkOption {
      type = lib.types.str;
      default = "10min";
      description = "OnUnitActiveSec between reconciles. Peers change rarely; a coarse interval is responsive without polling hard.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.bands != [ ] -> cfg.catchAllGroup != "";
        message = "nixnet.netbirdGroupReconcile.catchAllGroup must be set (a real, live NetBird group name) whenever nixnet.netbirdGroupReconcile.bands is non-empty.";
      }
    ];

    systemd.services.nixnet-netbird-group-reconcile = {
      description = "Reconcile NetBird peer->group membership from the declared octet addressing scheme";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = reconcile;
        MemoryMax = "64M";
        TimeoutStartSec = "5min";
      };
      unitConfig.StartLimitIntervalSec = 0;
    };

    systemd.timers.nixnet-netbird-group-reconcile = {
      description = "Periodic NetBird group-membership reconcile";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = cfg.onBootSec;
        OnUnitActiveSec = cfg.interval;
        RandomizedDelaySec = "1min";
        Persistent = true;
      };
    };
  };
}
