# checks/vm/wireless-association.nix — RADIO-1.
#
# The production failure, reproduced as a machine that must NOT have it: a real radio, a real
# access point, a key that exists only as a file at runtime, and nobody logged in. The line this
# test exists to keep out of the journal is
#
#   no secrets: No agents were available for this request
#
# which is what NetworkManager says when a profile expects a human to supply its key. A NixOS test
# machine is that host by construction — no session, no agent, no way to answer — so "it associated"
# is the whole assertion, and it is only meaningful on a machine where nothing could have been
# typed.
#
# ── WHY THIS FIXTURE DECLARES `addressing = none` ──────────────────────────────────────────────
# The radio's addressing is declared as `none` on both families, so the rendered profile disables
# IP configuration and the only variable left in the test is the association itself. That is
# deliberate: whether a DHCP client gets a lease is OWN-1's subject and has its own test with its
# own access point, and folding it in here would mean a missing key and a missing lease produce the
# same red. The layer under test is L2 — the four-way handshake that needs the key nobody typed.
#
# ── WPA3-SAE, BECAUSE THAT IS WHAT THE HOST RUNS ───────────────────────────────────────────────
# The profile this module replaces is `key-mgmt=sae` with PMF required, so that is what associates
# here — including `pmf=3`, which WPA3 mandates and which a profile can get wrong without any
# symptom other than "it does not connect". Testing the easier WPA2 path would have proven the
# rendering of a security mode this host does not use.
{ pkgs }:

let
  # A disposable test passphrase. It reaches the store here on the ACCESS POINT's side, which is
  # fine and is not what RADIO-5 is about: the AP's own config is not the host under test. The
  # CLIENT never sees it as a Nix value — it arrives as a file written at runtime, below.
  passphrase = "nixnet-vm-test-passphrase";
  ssid = "nixnet-vm-test";
in
{
  name = "wireless-association";
  behaviours = [ "RADIO-1" ];
  requiresModules = [ "wireless.nix" ];
  requiresOptions = [
    [ "nixnet" "wireless" "enable" ]
    [ "nixnet" "wireless" "radios" "interface" ]
    [ "nixnet" "wireless" "radios" "kind" ]
    [ "nixnet" "wireless" "networks" "ssid" ]
    [ "nixnet" "wireless" "networks" "secretFile" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-wireless-association";

    nodes.machine = { lib, ... }: {
      imports = [ modules.core modules.wireless baseline ];

      # Two virtual radios: wlan0 runs the access point, wlan1 is the host's own.
      boot.kernelModules = [ "mac80211_hwsim" ];

      environment.systemPackages = [ pkgs.iw ];

      networking.networkmanager = {
        enable = true;
        # The AP's radio is not a client radio. Left managed, NetworkManager would take it away
        # from hostapd mid-test.
        unmanaged = [ "interface-name:wlan0" ];
        # Otherwise NetworkManager invents a wired profile per ethernet device, which is noise in
        # every `nmcli` assertion below.
        settings.main.no-auto-default = "*";
      };

      # qemu-vm.nix sets `networking.wireless.enable = mkVMOverride false`, which outranks the
      # nixpkgs NetworkManager module's own `= true` and would leave NetworkManager with no
      # wpa_supplicant to talk to at all -- i.e. a wifi test with no wifi, passing or failing for
      # reasons that have nothing to do with this module. Same override nixpkgs' own
      # wpa_supplicant test uses.
      networking.wireless.enable = lib.mkOverride 0 true;

      services.hostapd = {
        enable = true;
        radios.wlan0 = {
          band = "2g";
          channel = 6;
          networks.wlan0 = {
            inherit ssid;
            authentication = {
              mode = "wpa3-sae";
              saePasswords = [{ password = passphrase; }];
            };
          };
        };
      };

      # The key, as the host actually receives it: a file that exists only at runtime, written by
      # something that is not nixnet (here a unit; on the real host, sops).
      systemd.services.test-wlan-secret = {
        description = "Provision the disposable test pre-shared key";
        wantedBy = [ "multi-user.target" ];
        before = [ "nixnet-wireless-profiles.service" ];
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
        script = ''
          install -d -m 0700 /run/test-secrets
          printf '%s\n' '${passphrase}' > /run/test-secrets/wlan
          chmod 0600 /run/test-secrets/wlan
        '';
      };

      nixnet.interfaces.wlan1.addressing = { v4 = "none"; v6 = "none"; };

      nixnet.wireless = {
        enable = true;
        radios.wifi0 = { interface = "wlan1"; kind = "wifi"; priority = 10; };
        networks.testnet = {
          radio = "wifi0";
          inherit ssid;
          security = "sae";
          secretFile = "/run/test-secrets/wlan";
        };
        # Out of scope here, and pinned rather than left at its default so a power policy cannot
        # power the radio down half way through an association test. RADIO-3 has its own.
        powerPolicy = { onBattery = "all"; onAc = "all"; };
      };
    };

    testScript = ''
      machine.wait_for_unit("hostapd.service")
      machine.wait_for_unit("nixnet-wireless-profiles.service")
      machine.wait_for_unit("NetworkManager.service")

      profiles = "/run/NetworkManager/system-connections"

      # NetworkManager's own view of the profile, not the file's text: it parsed the key as
      # SYSTEM-owned (flags 0). Flag 1 is "ask an agent", which is the failure this test is named
      # after -- and it is a value NetworkManager reports, so a profile that renders the string and
      # is rejected cannot pass this.
      machine.wait_until_succeeds("nmcli -t -f NAME connection show | grep -qx nixnet-testnet")
      flags = machine.succeed(
          "nmcli -g 802-11-wireless-security.psk-flags connection show nixnet-testnet"
      ).strip()
      assert flags == "0", f"the key is not stored in the profile; psk-flags={flags!r}"

      # WPA3 requires management-frame protection, so a profile that leaves it to negotiation is a
      # profile that can silently fail to associate. Read back from NetworkManager, which is the
      # thing that has to have accepted it.
      pmf = machine.succeed(
          "nmcli -g 802-11-wireless-security.pmf connection show nixnet-testnet"
      ).strip()
      assert pmf in ("3", "required"), f"PMF is not required on an SAE profile; pmf={pmf!r}"

      # ── THE assertion: associated, on a machine where nobody could have typed anything ───────
      machine.wait_until_succeeds(
          "nmcli -t -f DEVICE,STATE device | grep -qx 'wlan1:connected'", timeout=180
      )
      link = machine.succeed("iw dev wlan1 link")
      assert "${ssid}" in link, f"wlan1 is not associated with the declared SSID:\n{link}"

      journal = machine.succeed("journalctl -u NetworkManager --no-pager")
      assert "No agents were available" not in journal, (
          "NetworkManager asked for a secret. On this machine there is nobody to ask, which is the "
          f"entire point:\n{journal}"
      )

      # ── The stale duplicate, which is how the real host got here ─────────────────────────────
      # A profile nixnet wrote for a network nobody declares any more must go. Written by hand
      # here with its own id and uuid, so nothing about it collides with the live one -- what makes
      # it nixnet's is the file name, which is the only claim this module makes on a directory it
      # shares.
      def write_profile(path, connection_id, uuid, network):
          machine.succeed(
              f"cat > {path} <<'EOF'\n"
              "[connection]\n"
              f"id={connection_id}\n"
              f"uuid={uuid}\n"
              "type=wifi\n"
              "interface-name=wlan1\n"
              "autoconnect=false\n"
              "\n"
              "[wifi]\n"
              "mode=infrastructure\n"
              f"ssid={network}\n"
              "EOF"
          )
          machine.succeed(f"chmod 0600 {path}")

      write_profile(
          f"{profiles}/nixnet-stale.nmconnection",
          "nixnet-stale",
          "1c6f9f4a-0000-4000-a000-00000000dead",
          "some-old-network",
      )

      # ...and a profile nixnet did NOT write must survive, whatever it is. Owning a directory is
      # not owning everything in it (FW-2, one layer up).
      write_profile(
          f"{profiles}/handmade.nmconnection",
          "handmade",
          "1c6f9f4a-0000-4000-a000-0000000000ff",
          "someone-elses",
      )

      machine.succeed("systemctl restart nixnet-wireless-profiles.service")

      machine.fail(f"test -e {profiles}/nixnet-stale.nmconnection")
      machine.succeed(f"test -e {profiles}/handmade.nmconnection")
      machine.succeed(f"test -e {profiles}/nixnet-testnet.nmconnection")

      # The declared connection survived its own module's housekeeping.
      machine.succeed("nmcli -t -f DEVICE,STATE device | grep -qx 'wlan1:connected'")
    '';
  };
}
