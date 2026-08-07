# NixNet's native-package declaration for foreign system-manager hosts.
#
# It names mechanisms, not a generic "network stack": a host chooses only
# the client, tunnel, radios and tuner it actually has. The output is a pair
# of package-name lists for a host-provided reconciler; this module never
# installs a second nixpkgs daemon or writes a foreign systemd unit.
{ lib, config, ... }:
let
  cfg = config.nixnet.backend;
  table = import ../lib/packages.nix { };
  resolve = import ../lib/resolve.nix { inherit lib; };

  selectedNames = lib.flatten [
    (lib.optional cfg.netbird.enable "netbird")
    (lib.optional cfg.netbird.ui.enable "netbird-ui")
    (lib.optional cfg.cloudflared.enable "cloudflared")
    (lib.optional cfg.networkManager.enable "networkmanager")
    (lib.optional cfg.networkManager.enable "wpa-supplicant")
    (lib.optional cfg.modemManager.enable "modemmanager")
    (lib.optionals cfg.bluez.enable [ "bluez" "bluez-utils" ])
    (lib.optional cfg.bluez.obex.enable "bluez-obex")
    (lib.optional cfg.bluez.hid2hci.enable "bluez-hid2hci")
    (lib.optional cfg.bpftune.enable "bpftune")
  ];

  selectedEntries = map (name: table.packages.${name} // { inherit name; }) selectedNames;
  activeEntries = if cfg.enable then selectedEntries else [ ];
in
{
  options.nixnet.backend = {
    enable = lib.mkEnableOption "declaring this host's native NixNet mechanism packages";

    netbird = {
      enable = lib.mkEnableOption "the native NetBird client";
      ui.enable = lib.mkEnableOption "the NetBird GUI tray companion, for a host with a Wayland session";
    };
    cloudflared.enable = lib.mkEnableOption "the native Cloudflare Tunnel client";

    networkManager.enable = lib.mkEnableOption "NetworkManager with wpa_supplicant Wi-Fi association";
    modemManager.enable = lib.mkEnableOption "ModemManager for a WWAN uplink";

    bluez = {
      enable = lib.mkEnableOption "the BlueZ Bluetooth transport backend";
      obex.enable = lib.mkEnableOption "the optional BlueZ OBEX transfer backend";
      hid2hci.enable = lib.mkEnableOption "bluez-hid2hci for a Bluetooth HID adapter that needs conversion";
    };

    bpftune.enable = lib.mkEnableOption "the optional bpftune runtime network tuner";

    selection = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = "Selected NixNet mechanisms by catalogue key, before delivery is resolved.";
    };

    archPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        Official repository package names for the host's native reconciler.
        This module publishes names only; wire this to the host's package backend.
      '';
    };

    aurPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        AUR package names for the host's native reconciler. Kept separate because
        passing one to pacman aborts the whole repository transaction.
      '';
    };
  };

  config = {
    nixnet.backend = {
      selection = map (entry: entry.name) activeEntries;
      archPackages = resolve.archPackages activeEntries;
      aurPackages = resolve.aurPackages activeEntries;
    };

    assertions = [
      {
        assertion = cfg.enable || selectedNames == [ ];
        message = "nixnet.backend: mechanism selections require nixnet.backend.enable = true.";
      }
      {
        assertion = !cfg.netbird.ui.enable || cfg.netbird.enable;
        message = "nixnet.backend: the NetBird tray UI requires nixnet.backend.netbird.enable = true.";
      }
      {
        assertion = !cfg.bluez.obex.enable || cfg.bluez.enable;
        message = "nixnet.backend: BlueZ OBEX requires nixnet.backend.bluez.enable = true.";
      }
      {
        assertion = !cfg.bluez.hid2hci.enable || cfg.bluez.enable;
        message = "nixnet.backend: bluez-hid2hci requires nixnet.backend.bluez.enable = true.";
      }
    ];
  };
}
