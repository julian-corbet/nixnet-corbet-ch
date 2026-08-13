# modules/wireless.nix
#
# nixnet.wireless — the radios a host has, the networks it may join, and which of them stays
# powered. One more part of "this host's network reality", declared in the repo that already owns
# addressing, ranking and the packet filter.
#
# WHY THIS EXISTS. A laptop's Wi-Fi profiles were hand-made files in
# /etc/NetworkManager/system-connections: owned by nobody, reproduced by nothing, and carrying a
# duplicate stale profile for the same SSID whose key NetworkManager would only ever ask a HUMAN
# for. The observable failure on a headless boot is one line —
# `no secrets: No agents were available for this request` — and it is not a slow path, it is a dead
# one: the agent it wants is a logged-in session, and there is none. So the profile is DECLARED
# here, the key is stored in it (`psk-flags=0`), and the file is assembled at activation from a
# runtime path rather than rendered into the world-readable Nix store.
#
# WHAT IT DOES NOT DO. It does not pick a winner among transports, and it does not fail over: that
# is `TF-1`/`TF-3` and the engine in core.nix already implements it. This module feeds that model by
# giving each radio's connections a route metric derived from the SAME lower-wins priority — one
# ranking, in one direction, everywhere in this repo. A second failover engine living next to the
# first is how two mechanisms end up with authority over one decision (`ISO-1`'s warning).
#
# GENERIC BY CONSTRUCTION. Radios and networks are attrsets keyed by a stable id. Adding a Wi-Fi
# adapter to another host is a declaration; nothing here knows about any particular machine.
{ config, lib, options, pkgs, ... }:

let
  cfg = config.nixnet.wireless;
  tl = import ../lib/tooling.nix { inherit lib; };

  # Same backend detection every other module in this repo uses, from lib/tooling.nix, so the
  # question "which module system is evaluating this" has exactly one answer in the whole repo.
  backend = tl.backendOf options;
  isSystemManager = backend == "system-manager";

  q = lib.escapeShellArg;

  # ── The association mechanism, per backend ──────────────────────────────────────────────────
  #
  # Deliberately shaped like lib/tooling.nix's catalogue, for the reason that file states at
  # length: the interesting value is `null`. A backend that cannot associate must come back NAMED
  # as unsatisfiable, because "rendered nothing because there is nothing to render" and "rendered
  # nothing" are the same observation from outside unless one of them speaks (`FW-6`, one layer up).
  #
  # macOS associates through CoreWLAN and its own preferred-networks store; there is no
  # NetworkManager to write a keyfile for and there will not be one. nixnet publishes no
  # `darwinModules` today, so nothing reaches that value yet — it is declared anyway, because a
  # table that omits the backend it cannot serve is a table that looks complete and is not.
  associationMechanisms = {
    networkmanager = {
      nixos = "NetworkManager";
      system-manager = "NetworkManager";
      nix-darwin = null;
    };
  };

  mechanism = associationMechanisms.${cfg.backend}.${backend};

  radioList = lib.mapAttrsToList (name: r: r // { inherit name; }) cfg.radios;
  networkList = lib.mapAttrsToList (name: n: n // { inherit name; }) cfg.networks;

  # What the assembly script writes. Empty when the module is disabled, which is how
  # `enable = false` comes to mean "the profiles are gone" rather than "nixnet stopped talking
  # about them" -- the same job `nixnet-firewall.service` does for its table.
  activeNetworks = lib.optionals cfg.enable
    (lib.filter (n: cfg.profiles ? ${n.name}) networkList);
  activeSecretFiles = map (n: n.secretFile)
    (lib.filter (n: n.secretFile != "") activeNetworks);

  declaredKinds = lib.unique (map (r: r.kind) radioList);
  hasWwanRadio = lib.elem "wwan" declaredKinds;

  # ── Ranking ─────────────────────────────────────────────────────────────────────────────────
  #
  # `TF-1`: lower priority wins. Two spellings of that one order have to be produced here, and
  # NEITHER is a second ranking:
  #
  #   * a ROUTE METRIC, where lower also wins — `metricBase + priority`, derived straight from the
  #     radio's own number so adding or removing a radio never renumbers another one. Distinct
  #     priorities therefore give distinct metrics, which is `TF-3`'s requirement stated at
  #     declaration time instead of hoped for at runtime (see the uniqueness assertion below).
  #
  #   * NetworkManager's `autoconnect-priority`, which ranks the other way up: HIGHER wins, range
  #     -999..999, default 0. So the renderer negates. It negates into the POSITIVE half
  #     deliberately: a hand-made profile left behind on the host sits at 0, and a declared network
  #     must outrank it, or the legacy file this module exists to replace keeps winning the race it
  #     already wins today.
  metricOf = radio: cfg.metricBase + radio.priority;
  autoconnectPriorityOf = network: 999 - network.priority;

  radioOf = network: cfg.radios.${network.radio};

  # ── The profile template ────────────────────────────────────────────────────────────────────
  #
  # Everything except the key. `[wifi-security]` is rendered LAST on purpose: the assembly script
  # appends one `psk=` line to the end of the file, which is the cheapest possible way to put a
  # secret into a keyfile without a substitution pass over text that contains it. There is no
  # placeholder to fail to replace and no escaping to get wrong.
  #
  # `psk-flags=0` is the entry `RADIO-1` is about. Flag 1 ("agent-owned") is what a GUI writes, and
  # it means NetworkManager asks a running session for the key — on a headless boot there is no
  # session, so the profile cannot ever complete. 0 means the key lives in this file, which is why
  # the file is 0600 root and lives on a tmpfs.
  #
  # A deterministic UUID, derived from the network id: NetworkManager keys a connection's identity
  # on it, so a value that changed per rebuild would present every activation as a NEW connection
  # and leave the old one behind — the duplicate-profile shape this module exists to end.
  uuidOf = id:
    let h = builtins.hashString "sha256" "nixnet-wireless:${id}"; in
    lib.concatStringsSep "-" [
      (builtins.substring 0 8 h)
      (builtins.substring 8 4 h)
      "4${builtins.substring 13 3 h}"
      "a${builtins.substring 17 3 h}"
      (builtins.substring 20 12 h)
    ];

  # PMF (802.11w management-frame protection) is REQUIRED by WPA3: an SAE association without it is
  # not a weaker WPA3, it is a profile the AP refuses. NetworkManager's own default here is 0 ("use
  # the global default"), which negotiates rather than states — so the value is written, matching
  # what a working SAE profile on real hardware carries. 3 is NetworkManager's "required".
  #
  # NOT set for `wpa-psk`: forcing PMF on a WPA2 AP that does not offer it turns a working
  # association into a silent refusal, and WPA2 does not mandate it. Left at NetworkManager's
  # default there, which negotiates it when both ends have it.
  pmfLine = network: lib.optionalString (network.security == "sae") "pmf=3\n";

  securitySection = network:
    if network.security == "open" then ""
    else ''

      [wifi-security]
      key-mgmt=${network.security}
      psk-flags=0
      ${pmfLine network}'';

  # ── The addressing method, DERIVED ──────────────────────────────────────────────────────────
  #
  # `OWN-1`, applied here: how this interface gets its address is already a declared fact
  # (`nixnet.interfaces.<if>.addressing`), so the profile does not restate it. A hardcoded
  # `method=auto` would be a second statement of the same thing — one that keeps saying "DHCP" on
  # an interface whose declaration says otherwise, and the only symptom is a connection that
  # activates and then tears itself down when no lease arrives.
  #
  # The mapping is deliberately partial: `static` and `unmanaged` have no honest rendering here
  # (NetworkManager's `manual` needs the addresses, which this table does not carry per family and
  # per profile), so they are an evaluation error rather than a guess. See `addressingSupported`.
  methodFor = fact:
    if fact == "none" then "disabled" else "auto";

  addressingSupported = {
    v4 = [ "dhcp" "none" ];
    v6 = [ "dhcp" "slaac" "none" ];
  };

  ipSection = family: header: radio:
    let
      # Defensive only against a configuration the assertions below already refuse (an interface
      # nobody declared): the point of a refusal is that the operator reads the refusal, not an
      # "attribute missing" from a renderer that got there first.
      fact = lib.attrByPath [ radio.interface "addressing" family ] "dhcp" interfaces;
      method = methodFor fact;
    in
    ''

      [${header}]
      method=${method}
    '' + lib.optionalString (method != "disabled") ''
      route-metric=${toString (metricOf radio)}
    '' + lib.optionalString (family == "v6" && method != "disabled") ''
      addr-gen-mode=stable-privacy
    '';

  profileText = network:
    let radio = radioOf network; in
    ''
      # Generated by nixnet's wireless module. Do not edit — edit the host's nixnet.wireless.*
      # options. The key is NOT in this file and never reaches the Nix store (RADIO-5); it is
      # appended at activation from the declared runtime path.
      [connection]
      id=nixnet-${network.name}
      uuid=${uuidOf network.name}
      type=wifi
      interface-name=${radio.interface}
      autoconnect=${lib.boolToString network.autoconnect}
      autoconnect-priority=${toString (autoconnectPriorityOf network)}
      permissions=

      [wifi]
      mode=infrastructure
      ssid=${network.ssid}
    ''
    + ipSection "v4" "ipv4" radio
    + ipSection "v6" "ipv6" radio
    + securitySection network;

  profileFiles = lib.mapAttrs
    (name: text: pkgs.writeText "nixnet-wireless-${name}.nmconnection" text)
    cfg.profiles;

  profileFileName = name: "nixnet-${name}.nmconnection";

  # ── The per-radio route metric, for connections nixnet did NOT write ────────────────────────
  #
  # A WWAN radio has no SSID and no keyfile here: the modem's own connection belongs to
  # ModemManager and whoever provisioned the APN. nixnet still has to RANK it, or "Wi-Fi outranks
  # the modem" is a claim about a profile that does not exist. NetworkManager's connection defaults
  # answer exactly that: a property applied to every connection on a matched device that does not
  # set it itself. So the ranking is a property of the RADIO, and it reaches a profile nixnet never
  # wrote.
  #
  # The declared networks above ALSO carry the same metric in their own keyfile. That is not a
  # second statement of the fact — both are `metricOf radio`, one number, computed once.
  radioDefaultsText = radio: ''
    # Generated by nixnet's wireless module. The route metric this host's ${radio.kind} radio
    # ${radio.name} ranks at, derived from its declared priority (lower wins, TF-1). Applies to
    # every connection on this device that does not set the property itself — including one
    # ModemManager or the operator created, which is the point.
    [connection-nixnet-${radio.name}]
    match-device=interface-name:${radio.interface}
    ipv4.route-metric=${toString (metricOf radio)}
    ipv6.route-metric=${toString (metricOf radio)}
  '';

  # ── Assembling the keyfiles ─────────────────────────────────────────────────────────────────
  #
  # Names every template's STORE PATH, so the unit's own text moves whenever a profile moves —
  # the only diff either delivery engine acts on (system-manager restarts a unit when its store
  # path changes and has no "a file this unit reads changed" notion at all; NixOS' switch compares
  # unit files the same way). Same reasoning as the firewall's apply unit.
  assembleScript = pkgs.writeShellApplication {
    name = "nixnet-wireless-profiles";
    runtimeInputs = [ pkgs.coreutils pkgs.diffutils ];
    text = ''
      umask 077
      dir=${q cfg.profileDirectory}
      changed=0

      # 0755 on the DIRECTORY, 0600 on the files. NetworkManager runs as root and needs no more;
      # the directory being traversable is what lets an operator `ls` it and see WHICH profiles
      # exist without being able to read one.
      install -d -m 0755 "$dir"

      write_profile() {
        local id="$1" template="$2" secret_path="$3"
        local dest="$dir/nixnet-$id.nmconnection"
        local tmp="$dest.nixnet-new"
        local secret=""

        cat "$template" > "$tmp"

        if [ -n "$secret_path" ]; then
          if [ ! -r "$secret_path" ]; then
            rm -f "$tmp"
            echo "nixnet.wireless: $secret_path (network $id) is missing or unreadable." >&2
            echo "nixnet.wireless: refusing to write a profile with no key -- NetworkManager would" >&2
            echo "  then ask a secret agent for it, and on a headless host there is none." >&2
            exit 1
          fi

          # The FIRST LINE is the key. A pre-shared key is one line of printable ASCII, and a file
          # provisioned by sops/agenix/`printf` ends with a newline that must not become part of
          # it -- a trailing byte in a passphrase fails association with no error that names it.
          IFS= read -r secret < "$secret_path" || true
          if [ -z "$secret" ]; then
            rm -f "$tmp"
            echo "nixnet.wireless: $secret_path (network $id) is empty on its first line." >&2
            exit 1
          fi
          printf 'psk=%s\n' "$secret" >> "$tmp"
        fi

        chmod 0600 "$tmp"
        chown root:root "$tmp"

        # Identical content produces no write, no reload, no log line -- the same discipline TF-2
        # states for publication. A rewrite here is not free: NetworkManager reloads the profile
        # and can bounce a connection that was perfectly healthy.
        if [ -e "$dest" ] && cmp -s "$tmp" "$dest"; then
          rm -f "$tmp"
        else
          mv -f "$tmp" "$dest"
          changed=1
        fi
      }

      ${lib.concatMapStrings
        (n: "write_profile ${q n.name} ${profileFiles.${n.name}} ${q n.secretFile}\n")
        activeNetworks}

      # ── Profiles nixnet wrote and no longer declares ────────────────────────────────────────
      #
      # The stale duplicate is not hypothetical: the host this generalises had two profiles for one
      # SSID, one of them hand-made and keyless, and NetworkManager is free to pick either. A
      # declaration that only ever ADDS leaves exactly that behind on every rename.
      #
      # Scoped to this directory and to the `nixnet-` prefix, never to a profile someone else
      # wrote -- the same own-what-you-own discipline the firewall applies to its table.
      declared=" ${lib.concatMapStringsSep " " (n: profileFileName n.name) activeNetworks} "
      for existing in "$dir"/nixnet-*.nmconnection; do
        [ -e "$existing" ] || continue
        base="$(basename "$existing")"
        case "$declared" in
          *" $base "*) continue ;;
        esac
        echo "nixnet.wireless: removing $base -- no longer declared." >&2
        rm -f "$existing"
        changed=1
      done

      if [ "$changed" = 1 ]; then
        # A daemon that has not started yet needs no reload: this unit is ordered BEFORE
        # NetworkManager precisely so the profiles are on disk when it makes its first autoconnect
        # decision, and at boot that is the ORDINARY case, not a fault.
        #
        # So the state is CHECKED rather than inferred from the reload's exit status. Measured in a
        # VM: `nmcli connection reload` against a stopped NetworkManager exits 1 -- the generic
        # error -- not the 8 that nmcli(1) documents for "NetworkManager is not running". Keying a
        # tolerance on that number would have swallowed every real reload failure as well, which is
        # FW-3's failure with a different daemon's name on it. If NetworkManager IS reachable, a
        # failing reload fails this unit; nothing is swallowed either way.
        if ${cfg.nmcli} --terse --fields RUNNING general status > /dev/null 2>&1; then
          ${cfg.nmcli} connection reload
        fi
      fi
    '';
  };

  # ── The power policy ────────────────────────────────────────────────────────────────────────
  #
  # One script, three callers: a boot unit, the NetworkManager dispatcher (the winner changes when
  # a connection comes up or goes down) and a udev rule on the power supply (the policy changes
  # when the cable does). The state argument is what makes it testable from outside: with no
  # argument it reads the power supplies itself, which is what all three callers do.
  #
  # The switch is NetworkManager's per-KIND radio state, because that is the control the mechanism
  # actually has -- `nmcli radio wifi off` is rfkill for every Wi-Fi phy at once. A host with two
  # radios of one kind therefore cannot express `preferredOnly`, and that is an evaluation error
  # below rather than a policy that quietly powers down both.
  powerScript = pkgs.writeShellApplication {
    name = "nixnet-radio-power";
    runtimeInputs = [ pkgs.coreutils pkgs.gnugrep pkgs.util-linux ];
    text = ''
      # Automatic events are skipped rather than queued when another run holds the lock: every
      # action this script takes generates the same device/radio events that call it again. An
      # explicit operator/test request blocks, however, because returning success without applying
      # the requested policy is a lie.
      exec 9>/run/nixnet-radio-power.lock
      state="''${1:-}"
      if [ -n "$state" ]; then
        flock 9
      else
        flock -n 9 || exit 0
      fi
      if [ -z "$state" ]; then
        state=battery
        mains=0
        for supply in /sys/class/power_supply/*; do
          [ -r "$supply/type" ] || continue
          IFS= read -r supply_type < "$supply/type" || continue
          [ "$supply_type" = "Mains" ] || continue
          mains=1
          online=0
          [ ! -r "$supply/online" ] || IFS= read -r online < "$supply/online" || true
          # Several supplies can be called Mains (for example AC plus a dock). The machine is on
          # mains when ANY of them is online, not only when every one is.
          [ "$online" = "1" ] && state=ac
        done
        # No mains supply at all is a desktop, a server or a VM: there is no battery to save, so
        # the AC policy is the honest answer.
        [ "$mains" = 1 ] || state=ac
      fi

      case "$state" in
        ac) policy=${q cfg.powerPolicy.onAc} ;;
        battery) policy=${q cfg.powerPolicy.onBattery} ;;
        *) echo "usage: nixnet-radio-power [ac|battery]" >&2; exit 2 ;;
      esac

      # One daemon query per decision, not one per declared radio. Capturing before grep also
      # avoids grep -q closing a pipe early under pipefail and turning a match into an error.
      device_states=$(${cfg.nmcli} --terse --fields DEVICE,STATE device)
      is_connected() {
        grep -qx "$1:connected" <<<"$device_states"
      }

      set_radio() {
        ${cfg.nmcli} radio "$1" "$2"
      }

      winner_kind=""
      winner_priority=1000
      ${lib.concatMapStrings
        (r: ''
          if [ ${toString r.priority} -lt "$winner_priority" ] && is_connected ${q r.interface}; then
            winner_priority=${toString r.priority}
            winner_kind=${q r.kind}
          fi
        '')
        radioList}

      # NOTHING is associated. Powering radios down would remove the machine's last way back onto
      # a network, so every radio remains available for recovery.
      if [ -z "$winner_kind" ]; then
        policy=all
      fi

      ${lib.concatMapStrings
        (kind: ''
          if [ "$policy" = all ] || [ "$winner_kind" = ${q kind} ]; then
            set_radio ${q kind} on
          else
            set_radio ${q kind} off
          fi
        '')
        declaredKinds}
    '';
  };

  dispatcherScript = pkgs.writeShellScript "nixnet-radio-power-dispatcher" ''
    # NetworkManager dispatcher: $1 = interface, $2 = action. Only the two actions that can change
    # WHICH radio is winning are acted on; everything else (dhcp4-change, connectivity-change, ...)
    # would re-run the same computation for no reason.
    case "''${2:-}" in
      up|down) exec ${powerScript}/bin/nixnet-radio-power ;;
    esac
  '';

  # A power-supply transition is the other event that changes the policy. Expressed as a systemd
  # WANT rather than a `RUN+=` on a systemctl binary, for two reasons: a udev RUN+= must not block,
  # and naming a binary here would name a BACKEND's binary -- on a foreign distro the systemd
  # running the unit is the distro's, and pointing a rule at a nixpkgs systemctl is the version-skew
  # trap `nixnet.wireless.nmcli` documents. The unit deliberately has no RemainAfterExit, so each
  # transition really does run it again.
  udevRule = ''
    SUBSYSTEM=="power_supply", ACTION=="change", TAG+="systemd", ENV{SYSTEMD_WANTS}+="nixnet-radio-power.service"
  '';

  # `replaceExisting` exists only on the system-manager backend (real NixOS reconciles /etc from
  # scratch on every activation and has no such option). Without it, system-manager SILENTLY SKIPS
  # a path that already exists on the foreign distro -- the module appears to apply and changes
  # nothing. `optionalAttrs`, not `mkIf`: the module system checks a definition's structural keys
  # against declared options independent of any mkIf condition, the trap core.nix documents at
  # length for `system.activationScripts`.
  etcFile = attrs: attrs // lib.optionalAttrs isSystemManager { replaceExisting = true; };

  radioType = lib.types.submodule {
    options = {
      interface = lib.mkOption {
        type = lib.types.str;
        example = "wlp0s20f3";
        description = ''
          The kernel interface name this radio presents. Must exist in `nixnet.interfaces` with its
          addressing declared (`ADDR-1`) — a misspelled name here does not fail loudly, it makes
          NetworkManager match no device at all while the profile sits there looking correct.
        '';
      };

      kind = lib.mkOption {
        type = lib.types.enum [ "wifi" "wwan" ];
        description = ''
          What this radio is. `wifi` associates with a declared network; `wwan` is a modem whose own
          connection belongs to ModemManager — nixnet ranks it and powers it, it does not create its
          profile.

          This is also the granularity of the power switch: NetworkManager's radio state is per
          kind, not per device.
        '';
      };

      priority = lib.mkOption {
        type = lib.types.ints.between 0 999;
        example = 10;
        description = ''
          LOWER WINS, the same order `TF-1` uses for every other ranked thing in this repo. It
          decides the route metric every connection on this radio gets (`metricBase + priority`), so
          two radios must not share one — that is `TF-3`'s "no two of the subject's transports share
          a metric", asserted at declaration time instead of discovered as a kernel coin-flip
          between two equal-cost defaults.
        '';
      };
    };
  };

  networkType = lib.types.submodule {
    options = {
      radio = lib.mkOption {
        type = lib.types.str;
        example = "wifi0";
        description = "Which declared radio joins this network. Must be a key of `nixnet.wireless.radios`, of kind `wifi`.";
      };

      ssid = lib.mkOption {
        type = lib.types.str;
        example = "example-net";
        description = "The network's SSID, as broadcast.";
      };

      security = lib.mkOption {
        type = lib.types.enum [ "sae" "wpa-psk" "open" ];
        default = "sae";
        description = ''
          How the association is secured. `sae` is WPA3, `wpa-psk` is WPA2, `open` has no key and
          therefore no `secretFile` — anything but `open` must have one, asserted, because a profile
          with no key is precisely the profile NetworkManager asks a human about.

          These are NetworkManager's own `key-mgmt` values, rendered verbatim.
        '';
      };

      secretFile = lib.mkOption {
        type = lib.types.str;
        default = "";
        example = "/run/secrets/wlan-example";
        description = ''
          RUNTIME PATH of a file whose FIRST LINE is the pre-shared key. Not the key itself, and not
          a `types.path`: the Nix store is world-readable and world-copyable, so a key that reaches
          it is published to every user on this host and to every machine the closure is copied to,
          with nothing about the running system looking any different (`RADIO-5`). A path under
          `/nix/store` is an evaluation error for the same reason.

          The file is read at ACTIVATION, and only then. Where it comes from — sops, agenix, a
          hand-written file — is the host's business; nixnet requires only that it is there, and
          fails the unit loudly if it is not.

          QUOTE A NUMERIC KEY IN YAML. A pre-shared key that is all digits is a STRING that looks
          like a number, and every YAML parser in the sops/agenix path will treat it as one unless
          it is quoted: a leading zero is lost, and 19 digits or more exceeds a 64-bit integer and
          comes back as a float — `12345678901234567890` written out again as
          `1.2345678901234567e+19`. Neither mangling is visible in the profile; both fail
          association with a message about the key being wrong. Write `key: "01234567890123456789"`.

          `""` (the default) means no key, which is only valid with `security = "open"`.
        '';
      };

      autoconnect = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether NetworkManager joins this network on its own. `false` leaves the profile declared but only ever activated by hand.";
      };

      priority = lib.mkOption {
        type = lib.types.ints.between 0 999;
        default = 0;
        description = ''
          LOWER WINS, among the networks of ONE radio — which of several known SSIDs in range is
          tried first. It is rendered as NetworkManager's `autoconnect-priority`, which ranks the
          other way up, so the renderer negates into the positive half: every declared network
          therefore outranks a hand-made profile left behind on the host, which sits at 0.

          Radio priority and network priority answer different questions and never compete: the
          radio decides which link carries traffic once both are up, this decides which SSID a radio
          joins.
        '';
      };
    };
  };

  # ── Facts this module is not allowed to invent ──────────────────────────────────────────────
  interfaces = config.nixnet.interfaces;
  namedInterfaces = lib.unique (map (r: r.interface) radioList);
  undeclaredInterfaces = lib.filter (n: !(interfaces ? ${n})) namedInterfaces;
  addressinglessInterfaces = lib.filter
    (n: (interfaces ? ${n})
      && (interfaces.${n}.addressing.v4 == null || interfaces.${n}.addressing.v6 == null))
    namedInterfaces;

  undeclaredRadios = lib.filter (n: !(cfg.radios ? ${n.radio})) networkList;
  nonWifiRadios = lib.filter (n: (cfg.radios ? ${n.radio}) && (radioOf n).kind != "wifi") networkList;

  keylessNetworks = lib.filter (n: n.security != "open" && n.secretFile == "") networkList;
  openWithKey = lib.filter (n: n.security == "open" && n.secretFile != "") networkList;
  storedSecrets = lib.filter (n: lib.hasPrefix builtins.storeDir n.secretFile) networkList;
  relativeSecrets = lib.filter
    (n: n.secretFile != "" && !(lib.hasPrefix "/" n.secretFile))
    networkList;

  # Addressing facts this module has no honest rendering for. Only Wi-Fi radios are checked: a WWAN
  # radio gets no profile here, so its addressing is between the modem's connection and whoever
  # wrote it.
  wifiRadiosWithInterface = lib.filter
    (r: r.kind == "wifi" && (interfaces ? ${r.interface}))
    radioList;

  unsupportedAddressing = lib.concatMap
    (r: lib.concatMap
      (family:
        let fact = interfaces.${r.interface}.addressing.${family}; in
        lib.optional (fact != null && !(lib.elem fact addressingSupported.${family}))
          "${r.name} (${r.interface}): addressing.${family} = \"${fact}\"")
      [ "v4" "v6" ])
    wifiRadiosWithInterface;

  priorities = map (r: r.priority) radioList;
  # NOT `subtractLists (unique priorities) priorities`, which removes every occurrence of a value
  # and reports [ ] for the duplicate case -- an assertion that never fires, found by the check
  # that expected it to.
  duplicatePriorities = lib.unique (lib.filter (p: lib.count (x: x == p) priorities > 1) priorities);

  preferredOnlySelected =
    cfg.powerPolicy.onBattery == "preferredOnly" || cfg.powerPolicy.onAc == "preferredOnly";
  kindCounts = lib.mapAttrs (_: v: lib.length v) (lib.groupBy (r: r.kind) radioList);
  sharedKinds = lib.attrNames (lib.filterAttrs (_: n: n > 1) kindCounts);

  # The mechanism this module needs, per backend. `nixnet.backend.*` is read defensively because
  # that module is a separate, opt-in import (it exists to publish package NAMES for a foreign
  # distro's own reconciler); `networking.networkmanager` exists only on real NixOS. Either answer
  # satisfies the requirement — what must not happen is a host rendering profiles for a daemon
  # nothing on it declares.
  mechanismEnabled = nixnetBackendPath: nixosPath:
    (lib.attrByPath nixnetBackendPath false config)
    || (backend == "nixos" && (lib.attrByPath nixosPath false config));

  networkManagerEnabled = mechanismEnabled
    [ "nixnet" "backend" "networkManager" "enable" ]
    [ "networking" "networkmanager" "enable" ];

  modemManagerEnabled = mechanismEnabled
    [ "nixnet" "backend" "modemManager" "enable" ]
    [ "networking" "modemmanager" "enable" ];

in
{
  # core.nix owns `nixnet.interfaces`, which every radio here has to name. Imported rather than
  # read defensively for the same reason firewall.nix does not read it defensively: a radio whose
  # interface fact table is missing is a broken import, and hiding that behind an `or` would turn a
  # build error into a silently unranked radio.
  imports = [ ./core.nix ];

  options.nixnet.wireless = {
    enable = lib.mkEnableOption ''
      declaring this host's radios and the networks it may join.

      OFF does not mean UNMENTIONED: `nixnet-wireless-profiles.service` exists either way, and with
      this off its job is to remove every profile nixnet wrote. A generation that stops declaring a
      network would otherwise leave that network's keyfile on the host, still autoconnecting, with
      nothing declarative left that even mentions it
    '';

    backend = lib.mkOption {
      type = lib.types.enum [ "networkmanager" ];
      default = "networkmanager";
      description = ''
        Which association mechanism renders this declaration. `networkmanager` is the only one
        today, and the option exists so that the answer is a VALUE rather than an assumption baked
        into the renderer — a second backend (iwd, wpa_supplicant on its own) is a new entry in this
        module's catalogue, not a new module.

        Whether the SELECTED backend can be satisfied is a separate question, answered per module
        system: nix-darwin associates through CoreWLAN, so the selection is reported as
        unsatisfiable there instead of rendering nothing (`RADIO-6`).
      '';
    };

    nmcli = lib.mkOption {
      type = lib.types.str;
      default = if backend == "nixos" then "${pkgs.networkmanager}/bin/nmcli" else "nmcli";
      defaultText = lib.literalExpression ''"''${pkgs.networkmanager}/bin/nmcli" on NixOS, "nmcli" (from PATH) elsewhere'';
      description = ''
        The `nmcli` this module's scripts call.

        The default is backend-shaped and the reason is `nixnet.backend`'s whole premise: on a
        foreign distro the DISTRO owns NetworkManager, so the client that talks to its D-Bus API
        should be the distro's own — a nixpkgs `nmcli` against a distro daemon is a version-skew bug
        waiting for the worst moment. On NixOS the store path is exact and needs no PATH at all.

        Set it explicitly on a host where neither is true.
      '';
    };

    radios = lib.mkOption {
      type = lib.types.attrsOf radioType;
      default = { };
      example = lib.literalExpression ''
        {
          wifi0 = { interface = "wlp0s20f3"; kind = "wifi"; priority = 10; };
          wwan0 = { interface = "wwan0";     kind = "wwan"; priority = 50; };
        }
      '';
      description = ''
        The radios this host physically has, keyed by a short stable id. A FACT table in the same
        sense `nixnet.interfaces` is one: nixnet never discovers a radio, and an adapter nobody
        declared is not nixnet's.
      '';
    };

    networks = lib.mkOption {
      type = lib.types.attrsOf networkType;
      default = { };
      example = lib.literalExpression ''
        {
          home = {
            radio = "wifi0";
            ssid = "example-net";
            security = "sae";
            secretFile = "/run/secrets/wlan-example";
          };
        }
      '';
      description = ''
        The networks this host MAY join, keyed by a short stable id. One rendered NetworkManager
        keyfile each, assembled at activation with the key appended from `secretFile`.
      '';
    };

    powerPolicy = {
      onBattery = lib.mkOption {
        type = lib.types.enum [ "all" "preferredOnly" ];
        default = "preferredOnly";
        description = ''
          Which radios stay powered while the host runs on battery. `all` keeps every declared radio
          up; `preferredOnly` powers down every kind except the currently-winning radio's.

          The default is the frugal one because that is what the state means: keeping a modem
          associated beside an associated Wi-Fi radio spends battery on a link nothing is routing
          over.

          Never leaves a host with no radio: when NOTHING is associated, every radio is powered on
          regardless of this setting (see the module's own power script).
        '';
      };

      onAc = lib.mkOption {
        type = lib.types.enum [ "all" "preferredOnly" ];
        default = "all";
        description = ''
          The same, on mains power — where the power a second radio costs buys a faster failover and
          is worth nothing saved.
        '';
      };
    };

    metricBase = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 100;
      description = ''
        The route metric a radio of priority 0 would rank at; every radio gets
        `metricBase + priority`.

        The band matters more than the number: it has to sit above whatever a wired uplink ranks at
        (a cable should beat a radio without anyone declaring that) and below nothing in particular.
        See `BEHAVIORS.md` open question 1 — no survey says what "high enough" is on a given host,
        and this default is chosen to be comparable with the metrics NetworkManager and DHCP clients
        already assign rather than to win against them.
      '';
    };

    profileDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/run/NetworkManager/system-connections";
      description = ''
        Where the assembled keyfiles land. A TMPFS by default, and that is half of `RADIO-5`: the
        key exists on this host only while it is running, so a stolen disk, a backup and a
        filesystem image carry no key at all. NetworkManager reads this directory exactly as it
        reads `/etc/NetworkManager/system-connections`.

        Point it at `/etc/NetworkManager/system-connections` only on a host that genuinely needs a
        profile to survive without the provisioner that supplies its key — and know that this is
        the trade you are making.
      '';
    };

    profiles = lib.mkOption {
      type = lib.types.attrsOf lib.types.lines;
      readOnly = true;
      description = ''
        The rendered profile templates, keyed by network id — everything the host will load EXCEPT
        the key. Read-only: hosts describe intent through the options above and this is the single
        rendering of it, so the two planes cannot drift.

        Exposed because a file you cannot read before it is written is one you are trusting blind:
        `nix eval` this to see exactly what a host will present to NetworkManager. Also written to
        /etc/nixnet/wireless/ on the host, which is where the same question gets asked mid-incident.
      '';
    };
  };

  config = lib.mkMerge [
    # Rendered unconditionally, outside the enable gate — same reasoning as `nixnet.firewall.ruleset`
    # and `nixnet.overlay.ruleset`: a profile you cannot read before it is applied is one you trust
    # blind, and the question is asked most often by someone deciding whether to turn this on.
    {
      # Networks whose radio (and that radio's interface) is actually declared. A network that
      # names neither is a configuration the assertions refuse; rendering it anyway would only
      # decide WHICH error the operator sees, and "attribute missing" is the worse one.
      nixnet.wireless.profiles = lib.mapAttrs
        (name: n: profileText (n // { inherit name; }))
        (lib.filterAttrs
          (_: n: (cfg.radios ? ${n.radio}) && (interfaces ? ${cfg.radios.${n.radio}.interface}))
          cfg.networks);
    }

    # OUTSIDE the enable gate on purpose, exactly like `nixnet-firewall.service`: `enable = false`
    # has to mean the profiles are GONE, which takes a unit present in the generation that disables
    # them. A host that never enables this runs one oneshot per boot that finds nothing to remove.
    {
      systemd.services.nixnet-wireless-profiles = {
        description =
          if cfg.enable
          then "nixnet: assemble the declared NetworkManager profiles"
          else "nixnet: remove the NetworkManager profiles nixnet no longer declares";
        wantedBy = [ (if isSystemManager then "system-manager.target" else "multi-user.target") ];
        # BEFORE NetworkManager, not after: a profile that lands once the daemon has already made
        # its autoconnect decision costs an association round trip on every single boot. Which means
        # that at boot the daemon is normally NOT running when this unit finishes -- the ordinary
        # case, not a fault -- and that is why the script asks whether NetworkManager is reachable
        # instead of reading a reload's exit status. See the assembly script for what was measured.
        before = [ "NetworkManager.service" ];
        unitConfig = {
          RequiresMountsFor = activeSecretFiles;
          StartLimitIntervalSec = 0;
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          UMask = "0077";
          ExecStart = "${assembleScript}/bin/nixnet-wireless-profiles";
          Restart = "on-failure";
          RestartSec = "30s";
          TimeoutStartSec = "2min";
        };
      };
    }

    (lib.mkIf cfg.enable (lib.mkMerge [
      {
        assertions = [
          # ── RADIO-6: a backend that cannot associate says so ─────────────────────────────────
          {
            assertion = mechanism != null;
            message = ''
              nixnet.wireless.backend = "${cfg.backend}" is unsatisfiable on this backend
              (${backend}).

              ${if backend == "nix-darwin"
                then "macOS associates through CoreWLAN and its own preferred-networks store; there is no NetworkManager to write a keyfile for."
                else "This module system has no ${cfg.backend} to render a profile for."}

              Rendering nothing here would be indistinguishable from having worked: the host would
              build clean, activate clean, and never join a network. Declare the radios on a backend
              that can associate, or drop nixnet.wireless on this one.
            '';
          }
          {
            assertion = networkManagerEnabled;
            message = ''
              nixnet.wireless.enable is set, but nothing on this host enables NetworkManager.

              Set `nixnet.backend.networkManager.enable = true` (system-manager hosts: it publishes
              the distro package names for the host's own reconciler) or, on NixOS,
              `networking.networkmanager.enable = true`.

              Without it this module writes keyfiles for a daemon that is not running: the profiles
              are correct, the host is not on a network, and nothing anywhere reports a fault.
            '';
          }
          {
            assertion = !hasWwanRadio || modemManagerEnabled;
            message = ''
              nixnet.wireless declares a radio of kind "wwan".
              Nothing on this host enables ModemManager.

              Set `nixnet.backend.modemManager.enable = true` or, on NixOS,
              `networking.modemmanager.enable = true`. NetworkManager does not talk to a modem by
              itself — without ModemManager the radio never appears as a device, so it can neither
              be ranked nor powered down, and the declaration is decoration.
            '';
          }

          # ── RADIO-4: the declaration refusals ────────────────────────────────────────────────
          {
            assertion = undeclaredInterfaces == [ ];
            message = ''
              nixnet.wireless names an interface that is not declared in `nixnet.interfaces`:
              ${lib.concatStringsSep ", " undeclaredInterfaces}

              ADDR-1: an interface name appearing anywhere in a nixnet declaration must be a fact
              this host stated. A misspelled radio interface matches no device at all —
              NetworkManager simply never activates the profile, which looks exactly like being out
              of range. Declare the interface (with its `addressing`), or fix the name.
            '';
          }
          {
            assertion = addressinglessInterfaces == [ ];
            message = ''
              nixnet.wireless names an interface whose addressing nobody stated:
              ${lib.concatStringsSep ", " addressinglessInterfaces}

              Set both `addressing.v4` and `addressing.v6` (`static`/`dhcp`/`slaac`/`none`/
              `unmanaged`) on it. A radio is addressed by whatever answers on the network it joins,
              which is a fact — usually `dhcp` — and the firewall's own DHCP client accepts derive
              from it. `unmanaged` is a real answer, and a different one from silence.
            '';
          }
          {
            assertion = unsupportedAddressing == [ ];
            message = ''
              nixnet.wireless has a Wi-Fi radio whose declared addressing it cannot render:
              ${lib.concatStringsSep "\n              " unsupportedAddressing}

              The profile's IP method is DERIVED from `nixnet.interfaces.<if>.addressing` rather
              than assumed (OWN-1), and only the automatic answers have an honest rendering here:
              v4 `dhcp`/`none`, v6 `dhcp`/`slaac`/`none`. A `static` address needs the address
              itself, which is a per-interface fact this module does not carry into a per-network
              profile, and `unmanaged` says the addressing is somebody else's while this profile
              would configure it anyway.

              Declare the interface `dhcp` (or `none`, and address it elsewhere), or take this
              radio out of nixnet.wireless.
            '';
          }
          {
            assertion = undeclaredRadios == [ ];
            message = ''
              nixnet.wireless.networks names a radio that is not declared:
              ${lib.concatMapStringsSep ", " (n: "${n.name} -> ${n.radio}") undeclaredRadios}

              A network belongs to exactly one declared radio; naming one that does not exist
              renders a profile bound to an interface nobody named.
            '';
          }
          {
            assertion = nonWifiRadios == [ ];
            message = ''
              nixnet.wireless.networks attaches an SSID to a radio that is not of kind "wifi":
              ${lib.concatMapStringsSep ", " (n: "${n.name} -> ${n.radio}") nonWifiRadios}

              A WWAN radio has no SSID and no pre-shared key: its connection is ModemManager's, and
              nixnet's part in it is the ranking and the power policy. Declare the radio as `wifi`,
              or drop the network.
            '';
          }
          {
            assertion = duplicatePriorities == [ ];
            message = ''
              nixnet.wireless.radios share a priority: ${lib.concatMapStringsSep ", " toString (lib.unique duplicatePriorities)}

              Priority decides the route metric (`metricBase + priority`), so two radios at one
              priority publish two default routes at one metric — and the kernel then chooses
              between them on its own, possibly the one you are paying per megabyte for. That is
              exactly the tie TF-3 exists to prevent; give each radio its own number.
            '';
          }
          {
            assertion = !preferredOnlySelected || sharedKinds == [ ];
            message = ''
              nixnet.wireless.powerPolicy selects "preferredOnly", but this host declares more than
              one radio of kind: ${lib.concatStringsSep ", " sharedKinds}

              The power switch is NetworkManager's per-KIND radio state (`nmcli radio wifi off` is
              rfkill for every Wi-Fi phy on the box), so "power down everything except the winner"
              cannot be expressed here without powering down the winner too. Use
              `powerPolicy.onBattery = "all"` (and `onAc`), or declare only one radio per kind.
            '';
          }

          # ── RADIO-5: the key never reaches the store ─────────────────────────────────────────
          {
            assertion = keylessNetworks == [ ];
            message = ''
              nixnet.wireless.networks has a secured network with no `secretFile`:
              ${lib.concatMapStringsSep ", " (n: n.name) keylessNetworks}

              A profile with no key is precisely the profile that fails with
              `no secrets: No agents were available for this request` — NetworkManager asks a logged
              -in session for the key, and a headless boot has none. Set `secretFile`, or declare the
              network `security = "open"` if it genuinely has no key.
            '';
          }
          {
            assertion = openWithKey == [ ];
            message = ''
              nixnet.wireless.networks declares `security = "open"` together with a `secretFile`:
              ${lib.concatMapStringsSep ", " (n: n.name) openWithKey}

              An open network has no key to store, so the file would be read, held and never used —
              a secret with no purpose is still a secret to leak. Pick one.
            '';
          }
          {
            assertion = storedSecrets == [ ];
            message = ''
              nixnet.wireless.networks points `secretFile` into the Nix store:
              ${lib.concatMapStringsSep ", " (n: "${n.name} -> ${n.secretFile}") storedSecrets}

              The store is world-readable on this host and world-copyable off it, so a key that
              lands there is published to every user and to every machine the closure reaches — with
              nothing about the running system looking any different. That is the whole reason this
              option takes a runtime PATH rather than the key itself.

              Point it at a path a provisioner (sops, agenix, a systemd unit) writes at runtime.
            '';
          }
          {
            assertion = relativeSecrets == [ ];
            message = ''
              nixnet.wireless.networks has a `secretFile` that is not an absolute path:
              ${lib.concatMapStringsSep ", " (n: "${n.name} -> ${n.secretFile}") relativeSecrets}

              It is read by a systemd unit whose working directory is not yours.
            '';
          }
        ];

        # One profile template per network: readable, in the store, carrying no key. This is the
        # copy an operator greps mid-incident -- and the copy that proves, on the host itself, that
        # the key is not in the store: same content, minus the one line that matters.
        #
        # Left as a SYMLINK (no `mode`), unlike the dispatcher below, precisely so that
        # `readlink -f` on it lands in /nix/store. That is not cosmetic: it is how someone standing
        # at the host can see which of the two copies is the world-readable one.
        environment.etc = lib.mapAttrs'
          (name: file: lib.nameValuePair "nixnet/wireless/${profileFileName name}" (etcFile {
            source = file;
          }))
          profileFiles
        # The per-radio route metric, applied to every connection on that device -- including the
        # modem's, which nixnet never wrote.
        // lib.listToAttrs (map
          (r: lib.nameValuePair "NetworkManager/conf.d/nixnet-radio-${r.name}.conf" (etcFile {
            text = radioDefaultsText r;
          }))
          radioList)
        # The dispatcher. 0544 and root-owned because NetworkManager refuses to run a dispatcher
        # script that anyone else could write -- the same rule nixpkgs' own dispatcherScripts obey.
        // {
          "NetworkManager/dispatcher.d/50-nixnet-radio-power" = etcFile {
            source = dispatcherScript;
            mode = "0544";
          };
        };

        environment.systemPackages = [ powerScript ];

        systemd.services.nixnet-radio-power = {
          description = "nixnet: apply the radio power policy for the current power source";
          wantedBy = [ (if isSystemManager then "system-manager.target" else "multi-user.target") ];
          after = [ "NetworkManager.service" "nixnet-wireless-profiles.service" ];
          wants = [ "NetworkManager.service" ];
          serviceConfig = {
            Type = "oneshot";
            # Deliberately NOT RemainAfterExit: this unit is restarted by a udev rule on every
            # power-supply transition, and a unit that reports itself active forever is one systemd
            # can skip starting again.
            ExecStart = "${powerScript}/bin/nixnet-radio-power";
          };
        };
      }

      # The power-supply trigger, per backend. NixOS owns /etc/udev/rules.d as ONE environment.etc
      # entry (the whole directory), so a file added there by hand collides with it; system-manager
      # has no `services.udev` at all. Same rule, two delivery sites.
      (lib.optionalAttrs (!isSystemManager) {
        services.udev.extraRules = udevRule;
      })
      (lib.optionalAttrs isSystemManager {
        environment.etc."udev/rules.d/60-nixnet-radio-power.rules" = etcFile {
          text = udevRule;
        };
      })
    ]))
  ];
}
