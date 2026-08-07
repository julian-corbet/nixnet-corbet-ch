# checks/vm/wireless-declaration.nix — RADIO-4.
#
# A refusal check, not a VM test, and the distinction is the behaviour: every case here must fail
# ON THE BUILD HOST, so there is no machine to boot and nothing a booted machine could tell you.
# See checks/vm/lib.nix's header for why refusal evidence lives beside the VM tests rather than as
# a waiver in ../coverage.nix.
#
# The class being closed is the one that does NOT announce itself. A misspelled radio interface
# makes NetworkManager match no device: the profile is there, correct-looking, and the host simply
# never associates — which reads exactly like being out of range, or like a bad key, or like a
# broken adapter. Every case below is a mistake whose runtime symptom is indistinguishable from an
# unrelated fault.
#
# Each case names the message it expects, by a phrase only that assertion carries, so a case cannot
# pass on the WRONG refusal — and the control proves the module can still say yes.
{ pkgs }:

{
  name = "wireless-declaration";
  behaviours = [ "RADIO-4" ];
  requiresModules = [ "wireless.nix" ];
  requiresOptions = [
    [ "nixnet" "wireless" "enable" ]
    [ "nixnet" "wireless" "radios" "interface" ]
    [ "nixnet" "wireless" "radios" "priority" ]
    [ "nixnet" "wireless" "networks" "radio" ]
    [ "nixnet" "interfaces" "addressing" "v4" ]
  ];

  refusals = { modules, evalBaseline }:
    let
      host = extra: [
        modules.core
        modules.wireless
        { networking.networkmanager.enable = true; }
        extra
      ];

      wifiFact = { addressing = { v4 = "dhcp"; v6 = "slaac"; }; };
      network = { radio = "wifi0"; ssid = "example-net"; secretFile = "/run/secrets/wlan"; };
    in
    [
      {
        name = "control-a-complete-declaration-evaluates-clean";
        modules = host {
          nixnet.interfaces.wlan0 = wifiFact;
          nixnet.wireless = {
            enable = true;
            radios.wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
            networks.home = network;
          };
        };
        expect = null;
      }
      {
        name = "an-undeclared-radio-interface-is-refused";
        modules = host {
          nixnet.interfaces.wlan0 = wifiFact;
          nixnet.wireless = {
            enable = true;
            radios.wifi0 = { interface = "wlan1"; kind = "wifi"; priority = 10; };
          };
        };
        expect = "not declared in `nixnet.interfaces`";
      }
      {
        name = "an-interface-with-no-addressing-fact-is-refused";
        modules = host {
          nixnet.interfaces.wlan0 = { };
          nixnet.wireless = {
            enable = true;
            radios.wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
          };
        };
        expect = "whose addressing nobody stated";
      }
      {
        # `static` is a real answer to ADDR-1 and an unrenderable one here: this module writes
        # NetworkManager's automatic methods, and a manual address is a fact it does not carry.
        # Refusing is the difference between "nixnet cannot express this" and a profile that
        # quietly DHCPs an interface someone declared static.
        name = "an-unrenderable-addressing-fact-is-refused";
        modules = host {
          nixnet.interfaces.wlan0.addressing = { v4 = "static"; v6 = "none"; };
          nixnet.wireless = {
            enable = true;
            radios.wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
          };
        };
        expect = "cannot render";
      }
      {
        name = "a-network-on-an-undeclared-radio-is-refused";
        modules = host {
          nixnet.interfaces.wlan0 = wifiFact;
          nixnet.wireless = {
            enable = true;
            radios.wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
            networks.home = network // { radio = "wifi1"; };
          };
        };
        expect = "names a radio that is not declared";
      }
      {
        name = "an-ssid-on-a-wwan-radio-is-refused";
        modules = host {
          nixnet.interfaces.wwan0 = wifiFact;
          nixnet.wireless = {
            enable = true;
            radios.modem = { interface = "wwan0"; kind = "wwan"; priority = 50; };
            networks.home = network // { radio = "modem"; };
          };
          networking.modemmanager.enable = true;
        };
        expect = "not of kind";
      }
      {
        # TF-3, stated at declaration time: equal priorities are equal route metrics, and the
        # kernel then picks a default route on its own.
        name = "two-radios-sharing-a-priority-are-refused";
        modules = host {
          nixnet.interfaces = { wlan0 = wifiFact; wwan0 = wifiFact; };
          nixnet.wireless = {
            enable = true;
            radios = {
              wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
              modem = { interface = "wwan0"; kind = "wwan"; priority = 10; };
            };
          };
          networking.modemmanager.enable = true;
        };
        expect = "share a priority";
      }
      {
        # The mechanism's own limit, said out loud: NetworkManager's radio switch is per KIND, so
        # "power down everything but the winner" cannot be honoured with two radios of one kind.
        name = "preferredOnly-with-two-radios-of-one-kind-is-refused";
        modules = host {
          nixnet.interfaces = { wlan0 = wifiFact; wlan1 = wifiFact; };
          nixnet.wireless = {
            enable = true;
            radios = {
              wifi0 = { interface = "wlan0"; kind = "wifi"; priority = 10; };
              wifi1 = { interface = "wlan1"; kind = "wifi"; priority = 20; };
            };
            powerPolicy.onBattery = "preferredOnly";
          };
        };
        expect = "one radio of kind";
      }
    ];
}
