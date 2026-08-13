# checks/vm/wireless-secret-handling.nix — RADIO-5.
#
# Two kinds of evidence, because the behaviour has two halves and evidence for one is not evidence
# for the other:
#
#   * ON A BOOTED MACHINE: the assembled keyfile is 0600 root on a tmpfs, another user genuinely
#     cannot read it, and the copy that IS world-readable — the template in the Nix store — carries
#     the key-management flags and no key.
#   * AT EVALUATION: a `secretFile` pointing into the store is refused, and so is a secured network
#     with no key at all. Both are the mistake this option shape exists to make impossible, and
#     both are decided on the build host where no machine ever boots.
#
# ── WHAT THIS DELIBERATELY DOES NOT DO ─────────────────────────────────────────────────────────
# It does not grep /nix/store for the key. In a sandboxed build the VM sees the builder's whole
# store, so that grep is a full-store scan pretending to be an assertion — and it would pass
# vacuously anyway, since the fixture's key is written at runtime and never had a chance to be
# there. What actually distinguishes a leaking module from this one is WHICH FILE holds the key:
# the store-resident template, or the 0600 file on tmpfs. So that is what is asserted, from both
# sides.
#
# No access point and nothing to associate with: the assembly path is the subject, and the network
# is declared `autoconnect = false` so NetworkManager does not spend the test scanning for an SSID
# that does not exist. `sae` is rendered here for the same reason checks/vm/wireless-association.nix
# associates over it — it is the key-management the host this module was written for uses. The
# `wpa-psk` rendering (this profile minus `pmf=3`) is never assembled on a booted machine in this
# repo; it appears only as a refusal case below, where nothing is rendered at all.
{ pkgs }:

let
  passphrase = "correct-horse-battery-staple";
in
{
  name = "wireless-secret-handling";
  behaviours = [ "RADIO-5" ];
  requiresModules = [ "wireless.nix" ];
  requiresOptions = [
    [ "nixnet" "wireless" "enable" ]
    [ "nixnet" "wireless" "networks" "secretFile" ]
    [ "nixnet" "wireless" "profileDirectory" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-wireless-secret-handling";

    nodes.machine = { lib, ... }: {
      imports = [ modules.core modules.wireless baseline ];

      # One virtual radio, so the declared interface is a device this machine really has.
      boot.kernelModules = [ "mac80211_hwsim" ];
      boot.extraModprobeConfig = "options mac80211_hwsim radios=1";

      networking.networkmanager = {
        enable = true;
        settings.main.no-auto-default = "*";
      };
      networking.wireless.enable = lib.mkOverride 0 true;

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

      nixnet.interfaces.wlan0.addressing = { v4 = "dhcp"; v6 = "slaac"; };

      nixnet.wireless = {
        enable = true;
        radios.wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
        networks.home = {
          radio = "wifi0";
          ssid = "nixnet-vm-absent-network";
          security = "sae";
          secretFile = "/run/test-secrets/wlan";
          autoconnect = false;
        };
        powerPolicy = { onBattery = "all"; onAc = "all"; };
      };
    };

    testScript = ''
      machine.wait_for_unit("nixnet-wireless-profiles.service")

      mounts = machine.succeed(
          "systemctl show -p RequiresMountsFor --value nixnet-wireless-profiles.service"
      )
      assert "/run/test-secrets/wlan" in mounts, f"secret mount dependency missing: {mounts}"

      live = "/run/NetworkManager/system-connections/nixnet-home.nmconnection"
      template = "/etc/nixnet/wireless/nixnet-home.nmconnection"
      key = "${passphrase}"

      # ── The file that holds the key ──────────────────────────────────────────────────────────
      machine.succeed(f"test -f {live}")
      machine.succeed(f"test ! -L {live}")   # a symlink would point somewhere with other modes

      mode = machine.succeed(f"stat -c %a {live}").strip()
      owner = machine.succeed(f"stat -c %U:%G {live}").strip()
      assert mode == "600", f"the keyfile is mode {mode}, not 600"
      assert owner == "root:root", f"the keyfile is owned by {owner}, not root:root"

      # The mode, tested the way it is actually relied on rather than as a number.
      machine.fail(f"runuser -u nobody -- cat {live}")

      # On a tmpfs: the key exists on this host only while it is running, so a disk image, a backup
      # and a stolen machine carry none of it.
      fstype = machine.succeed("stat -f -c %T /run/NetworkManager/system-connections").strip()
      assert fstype == "tmpfs", f"the profile directory is on {fstype}, not a tmpfs"

      # Assembled from the RUNTIME path, first line only -- the provisioner's trailing newline is
      # not part of the key, and a passphrase with one silently fails to associate.
      machine.succeed(f"grep -qxF 'psk={key}' {live}")

      # ── The file that does not ───────────────────────────────────────────────────────────────
      resolved = machine.succeed(f"readlink -f {template}").strip()
      assert resolved.startswith("/nix/store/"), (
          f"{template} does not resolve into the store, so this half tests nothing: {resolved}"
      )
      machine.succeed(f"grep -q '^psk-flags=0$' {template}")
      machine.fail(f"grep -q '^psk=' {template}")
      machine.fail(f"grep -qF '{key}' {template}")

      # ...and the store copy is world-readable, which is the whole reason the key is not in it.
      machine.succeed(f"runuser -u nobody -- cat {template} >/dev/null")

      # ── The unit's own refusal ───────────────────────────────────────────────────────────────
      # A missing secret must fail the unit rather than write a profile with no key -- which is
      # the profile NetworkManager would then ask a human about (RADIO-1).
      machine.succeed("rm -f /run/test-secrets/wlan")
      machine.succeed(f"rm -f {live}")
      machine.fail("systemctl restart nixnet-wireless-profiles.service")
      machine.fail(f"test -e {live}")
    '';
  };

  refusals = { modules, evalBaseline }:
    let
      base = {
        networking.networkmanager.enable = true;
        nixnet.interfaces.wlan0.addressing = { v4 = "dhcp"; v6 = "slaac"; };
        nixnet.wireless = {
          enable = true;
          radios.wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
        };
      };
      host = network: [
        modules.core
        modules.wireless
        base
        { nixnet.wireless.networks.home = { radio = "wifi0"; ssid = "example-net"; } // network; }
      ];
    in
    [
      {
        name = "control-a-runtime-path-evaluates-clean";
        modules = host { security = "sae"; secretFile = "/run/secrets/wlan"; };
        expect = null;
      }
      {
        name = "a-secretFile-in-the-store-is-refused";
        # The shape that actually happens: an interpolated Nix path, which reads as a path and IS
        # a store path. `types.str` already stops the un-interpolated form at the type checker.
        modules = host { security = "sae"; secretFile = "${pkgs.writeText "psk" "not-a-real-key"}"; };
        expect = "points `secretFile` into the Nix store";
      }
      {
        name = "a-secured-network-with-no-key-is-refused";
        modules = host { security = "wpa-psk"; };
        expect = "secured network with no `secretFile`";
      }
      {
        name = "an-open-network-carrying-a-key-is-refused";
        modules = host { security = "open"; secretFile = "/run/secrets/wlan"; };
        expect = "together with a `secretFile`";
      }
      {
        name = "a-relative-secretFile-is-refused";
        modules = host { security = "sae"; secretFile = "secrets/wlan"; };
        expect = "not an absolute path";
      }
    ];
}
