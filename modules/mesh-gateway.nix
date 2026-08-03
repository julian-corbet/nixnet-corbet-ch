# modules/mesh-gateway.nix
#
# nixnet.meshGateway — one userspace process holding N self-hosted-NetBird
# identities (an embed client per configured peer), L4-forwarding each
# peer's listeners into the host netns. The point: a service (or a
# client-less machine) gets its OWN overlay identity/address without
# running its own NetBird client — the gateway holds the identity and
# forwards traffic to wherever that service/machine actually lives (a
# ClusterIP, a LAN address, ...).
#
# This module owns the SYSTEMD + CONFIG-RENDERING mechanism only — it does
# NOT build the embed-client binary itself. `package` (below) is a required
# option: bring your own build of a program that reads the rendered
# `MESH_GATEWAY_CONFIG` JSON (schema: see `configFile` below) and speaks
# NetBird's `client/embed` package. This is a deliberate boundary, not an
# oversight — the binary is a from-source Go program with its own
# toolchain/vendoring concerns, orthogonal to "what does the overlay option
# surface look like."
{ config, lib, pkgs, ... }:

let
  cfg = config.nixnet.meshGateway;

  peerType = lib.types.submodule {
    options = {
      ip = lib.mkOption {
        type = lib.types.str;
        description = "This peer's pinned overlay address.";
        example = "192.0.2.10"; # TEST-NET-1 placeholder
      };
      forwards = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options = {
            proto = lib.mkOption { type = lib.types.enum [ "tcp" "udp" ]; default = "tcp"; };
            listenPort = lib.mkOption { type = lib.types.port; description = "Port this peer listens on, overlay-side."; };
            dial = lib.mkOption { type = lib.types.str; description = "host:port to forward to, on the real network."; };
          };
        });
        default = [ ];
        description = "L4 forwards: overlay listener -> backend dial target.";
      };
    };
  };

  privateKeyFile = name: "${cfg.stateDir}/${name}/private.key";

  allPeerNames = lib.attrNames cfg.peers;

  # Captures each peer's already-NetBird-enrolled key into a stable identity
  # file, if one exists yet and hasn't already been captured. Run as an
  # ExecStartPre= on the gateway unit itself (not a separate ordered unit)
  # so it re-runs before EVERY start of that unit, self-restarts included.
  #
  # WHY THIS EXISTS: an embed-client library typically only reuses a
  # persisted WireGuard identity via an explicit PrivateKeyFile — it does
  # NOT read back an existing ConfigPath/StatePath on its own. Without
  # this, every process start would silently enroll a brand-new identity
  # for every peer, permanently orphaning whichever identity previously
  # held each pinned overlay address. The fix is NOT "generate a fresh
  # WireGuard key and persist that" — SetupKey and PrivateKey are mutually
  # exclusive in this class of embed library, so a never-enrolled key
  # can't log in at all. This CAPTURES the real key NetBird itself
  # generated for the peer's most recent successful (setup-key) enrollment
  # straight out of that peer's own ConfigPath, the first time it's seen —
  # never invents one. A consumer binary's own resolvePrivateKey path must
  # treat a not-yet-populated PrivateKeyFile as "no key yet, fall through
  # to SetupKey enrollment," never a hard error — see package.nix's own
  # consumer contract note (this module cannot enforce that from the Nix
  # side; it's a binary-side requirement).
  keysBootstrapScript = pkgs.writeShellApplication {
    name = "nixnet-mesh-gateway-keys-bootstrap";
    runtimeInputs = [ pkgs.jq pkgs.coreutils ];
    text = lib.concatMapStringsSep "\n" (name: ''
      keyfile=${lib.escapeShellArg (privateKeyFile name)}
      configjson=${lib.escapeShellArg "${cfg.stateDir}/${name}/config.json"}
      mkdir -p "$(dirname "$keyfile")"
      if [ ! -s "$keyfile" ] && [ -r "$configjson" ]; then
        key=$(jq -r '.PrivateKey // empty' "$configjson" 2>/dev/null || true)
        if [ -n "$key" ]; then
          umask 077
          printf '%s' "$key" > "$keyfile.tmp"
          mv -f "$keyfile.tmp" "$keyfile"
          echo "nixnet-mesh-gateway-keys-bootstrap: captured ${name}'s already-enrolled identity"
        fi
      fi
    '') allPeerNames;
  };

  configFile = pkgs.writeText "nixnet-mesh-gateway.json" (
    builtins.toJSON {
      managementURL = cfg.managementUrl;
      apiURL = cfg.apiUrl;
      setupKeyFile = cfg.setupKeyRuntimeFile;
      apiTokenFile = cfg.apiTokenRuntimeFile;
      stateDir = cfg.stateDir;
      peers = lib.mapAttrsToList
        (name: p: { inherit name; ip = p.ip; privateKeyFile = privateKeyFile name; forwards = p.forwards; })
        cfg.peers;
    }
  );

  # sops+age binary-blob unseal -> a root-only runtime file. Generic
  # "decrypt this secret to that path before the unit starts" glue; a host
  # already running a similar unseal for another secret can reuse the
  # pattern, this one is self-contained.
  unseal = label: secretFile: outFile: {
    description = "Unseal ${label} for nixnet's mesh-gateway";
    before = [ "nixnet-mesh-gateway.service" ];
    wantedBy = [ "multi-user.target" ];
    path = [ pkgs.sops ];
    # The age key -- and, whenever it isn't a store path, the sealed
    # secret -- can sit on a filesystem some OTHER unit mounts: a ZFS
    # dataset, an NFS export, a LUKS-backed volume. RequiresMountsFor
    # derives that ordering from the PATHS THEMSELVES, so no consumer ever
    # has to name a mount unit by hand (a name it would have to spell in
    # systemd's escaped form, and re-spell whenever the path moved).
    # systemd resolves each path to its covering mount, pulls it in, and
    # orders it before this unit.
    #
    # Without this, the unseal races the mount -- and a lost race is not
    # intermittent-and-self-correcting, it is permanent: a Type=oneshot
    # failure latches, and nothing re-queues the gateway that depended on
    # it. Observed in production as exactly a 10-second loss (unseal at
    # T+0, the dataset holding the age key mounted at T+10), which took
    # every embedded identity off the overlay until a human noticed.
    unitConfig.RequiresMountsFor = [ (toString cfg.ageKeyFile) (toString secretFile) ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      Environment = "SOPS_AGE_KEY_FILE=${cfg.ageKeyFile}";
      # Defence in depth behind that ordering: a secret store can be
      # briefly unreadable for reasons no ordering edge expresses (a
      # network mount reconnecting, a key being rewritten under us).
      # Retry, bounded, instead of latching a failed state only a human
      # can clear. `on-failure` is the one Restart= mode Type=oneshot
      # accepts -- `always`/`on-success` are rejected for oneshot, which
      # is correct here anyway: a SUCCESSFUL unseal must stay done.
      Restart = "on-failure";
      RestartSec = "5s";
    };
    startLimitIntervalSec = 300;
    startLimitBurst = 10;
    script = ''
      set -u
      mkdir -p "$(dirname ${lib.escapeShellArg outFile})"
      if sops -d --input-type binary --output-type binary ${secretFile} > ${outFile}.tmp 2>/dev/null; then
        chmod 600 ${outFile}.tmp && mv -f ${outFile}.tmp ${outFile} && echo "${label} unsealed -> ${outFile}"
      else
        rm -f ${outFile}.tmp
        echo "ERROR: ${label} unseal failed (missing key/file)" >&2
        exit 1
      fi
    '';
  };
in
{
  options.nixnet.meshGateway = {
    enable = lib.mkEnableOption "the NetBird embed mesh-gateway (one process, N overlay identities forwarded into the host netns)";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The embed-client binary consuming the rendered config (see this
        file's own header comment for the config schema and why this has
        no default — the binary itself is out of this module's scope).
      '';
    };

    managementUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://netbird.example.com";
      description = "Self-hosted NetBird management URL the embedded clients enroll against.";
    };

    apiUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://netbird.example.com/api";
      description = "NetBird API base — used to pin each peer's overlay IP to its intended address.";
    };

    ageKeyFile = lib.mkOption {
      type = lib.types.path;
      description = "age key that decrypts setupKeySecret + apiTokenSecret. Environment-specific — no default.";
    };

    setupKeySecret = lib.mkOption {
      type = lib.types.path;
      description = "sops-encrypted (binary) reusable NetBird setup key that enrolls the peers.";
    };

    apiTokenSecret = lib.mkOption {
      type = lib.types.path;
      description = "sops-encrypted (binary) NetBird API token used to pin overlay IPs.";
    };

    setupKeyRuntimeFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/secrets/nixnet-mesh-gateway-setupkey";
      description = "Where the unsealed setup key is written at runtime.";
    };

    apiTokenRuntimeFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/secrets/nixnet-mesh-gateway-apitoken";
      description = ''
        Where the unsealed API token is written at runtime. Also the
        default `nixnet.netbirdGroupReconcile.tokenFile` value, since both
        consume the same token by design — no second secret needed when
        both modules are enabled on the same host.
      '';
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/nixnet-mesh-gateway";
      description = "Persisted per-peer embed identities (StateDirectory=).";
    };

    peers = lib.mkOption {
      type = lib.types.attrsOf peerType;
      default = { };
      description = "One entry per overlay identity this gateway holds.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.nixnet-mesh-gateway-setupkey-unseal = unseal "mesh-gateway setup key" cfg.setupKeySecret cfg.setupKeyRuntimeFile;
    systemd.services.nixnet-mesh-gateway-apitoken-unseal = unseal "mesh-gateway API token" cfg.apiTokenSecret cfg.apiTokenRuntimeFile;

    systemd.services.nixnet-mesh-gateway = {
      description = "nixnet mesh-gateway — one process, N overlay identities forwarded into the host netns";
      after = [
        "network-online.target"
        "nixnet-mesh-gateway-setupkey-unseal.service"
        "nixnet-mesh-gateway-apitoken-unseal.service"
      ];
      # Deliberately `wants`, NOT `requires`, on the two unseals. A hard
      # requirement makes a single failed unseal cancel this unit's start
      # job outright -- and nothing ever re-queues it, so the unseal
      # succeeding later (on its own retry) changes nothing and the
      # overlay stays down until a human runs systemctl. `wants` keeps
      # the `after` ordering above (this unit still waits for the unseal
      # job to settle) while degrading a secret-store hiccup into a
      # visible crash-loop that converges by itself: the gateway starts,
      # fails to read the secret, and retries under its own
      # Restart=always until the unseal's own retry lands.
      wants = [
        "network-online.target"
        "nixnet-mesh-gateway-setupkey-unseal.service"
        "nixnet-mesh-gateway-apitoken-unseal.service"
      ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        # Runs before EVERY start of THIS unit (crash, a deliberate
        # self-pin restart, a real deploy switch) -- unlike a separate
        # `before`-ordered unit, which systemd does not re-invoke on a
        # self-restart alone.
        ExecStartPre = lib.getExe keysBootstrapScript;
        ExecStart = lib.getExe cfg.package;
        Environment = [
          "MESH_GATEWAY_CONFIG=${configFile}"
          "MESH_GATEWAY_LOG_LEVEL=info"
        ];
        StateDirectory = baseNameOf (toString cfg.stateDir);
        # A binary that self-pins overlay addresses on start and finds one
        # already reassigned elsewhere is expected to exit(0) deliberately
        # so systemd relaunches it onto the corrected pins -- a normal
        # convergence, covered by the same Restart=always as an actual
        # crash. Root: reads the root-owned unsealed secrets; the datapath
        # itself is expected to be pure userspace (no NET_ADMIN needed).
        Restart = "always";
        RestartSec = "5s";
      };
    };
  };
}
