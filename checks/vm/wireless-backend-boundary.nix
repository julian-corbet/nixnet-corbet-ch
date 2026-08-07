# checks/vm/wireless-backend-boundary.nix — RADIO-6.
#
# FW-6's shape, one layer up: a selection this backend cannot satisfy must SAY so, because
# "rendered nothing because there is nothing to render" and "rendered nothing" are the same
# observation from outside unless one of them speaks. A host that builds clean, activates clean and
# is simply never on a network is the failure — with the declaration sitting in the config looking
# like the reason it should be.
#
# A refusal check for the same reason FW-6 is waived from a VM test: what is decided here is
# decided at evaluation, and the nix-darwin arm cannot be booted from this repo at all (nixnet
# publishes no `darwinModules`). So the backend is presented the way lib/tooling.nix's own resolver
# is tested — through the option NAMESPACE each backend is detected by, which is what the code
# actually reads.
{ pkgs }:

let
  lib = pkgs.lib;

  # The one thing that makes a config nix-darwin to `lib/tooling.nix`'s `backendOf`: the
  # `system.defaults` option namespace, which NixOS never declares. Declaring it here is not a
  # mock of nix-darwin — it is the exact fact the detection keys on, and detecting the backend
  # wrongly is itself a failure this pins.
  fakeDarwin = { lib, ... }: {
    options.system.defaults = lib.mkOption {
      type = lib.types.attrs;
      default = { };
      description = "Stand-in for nix-darwin's own namespace, so backend detection sees it.";
    };
  };
in
{
  name = "wireless-backend-boundary";
  behaviours = [ "RADIO-6" ];
  requiresModules = [ "wireless.nix" ];
  requiresOptions = [
    [ "nixnet" "wireless" "enable" ]
    [ "nixnet" "wireless" "backend" ]
  ];

  refusals = { modules, evalBaseline }:
    let
      wifiFact = { addressing = { v4 = "dhcp"; v6 = "slaac"; }; };

      host = extra: [
        modules.core
        modules.wireless
        {
          nixnet.interfaces.wlan0 = wifiFact;
          nixnet.wireless = {
            enable = true;
            radios.wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
          };
        }
        extra
      ];
    in
    [
      {
        name = "control-networkmanager-on-a-linux-backend-evaluates-clean";
        modules = host { networking.networkmanager.enable = true; };
        expect = null;
      }
      {
        name = "a-backend-with-no-networkmanager-is-named-unsatisfiable";
        modules = host { networking.networkmanager.enable = true; } ++ [ fakeDarwin ];
        expect = "unsatisfiable on this backend";
      }
      {
        # The other half, and the one that actually happens: a Linux host that declares radios and
        # never enables the mechanism that would use them.
        name = "no-networkmanager-mechanism-anywhere-is-refused";
        modules = host { };
        expect = "nothing on this host enables NetworkManager";
      }
      {
        # A WWAN radio needs the modem control plane as well. Without it the radio never appears as
        # a device, so it can be neither ranked nor powered down -- and the declaration is
        # decoration that looks like configuration.
        name = "a-wwan-radio-with-no-modemmanager-is-refused";
        modules = host {
          networking.networkmanager.enable = true;
          # NetworkManager's own module turns ModemManager on by default, so this has to be forced
          # off to reach the case at all -- which is worth knowing: on NixOS the requirement is
          # satisfied for free, and the assertion is there for the backend where it is not.
          networking.modemmanager.enable = lib.mkForce false;
          nixnet.interfaces.wwan0 = wifiFact;
          nixnet.wireless.radios.modem = { interface = "wwan0"; kind = "wwan"; priority = 50; };
        };
        expect = "Nothing on this host enables ModemManager";
      }
    ];
}
