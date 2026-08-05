# Native package names for the mechanisms NixNet can declare on a foreign
# system-manager host. This is data only: the backend publishes the names and
# the host's own reconciler installs the distro packages.
{ }:
{
  packages = {
    netbird = {
      arch = "netbird-bin";
      aur = true;
      reason = "The native NetBird client and its distro-owned systemd unit.";
    };
    cloudflared = {
      arch = "cloudflared";
      reason = "The native Cloudflare Tunnel client and its distro-owned systemd unit.";
    };
    networkmanager = {
      arch = "networkmanager";
      reason = "The connection and route manager for a roaming host.";
    };
    wpa-supplicant = {
      arch = "wpa_supplicant";
      reason = "NetworkManager's selected Wi-Fi association backend.";
    };
    modemmanager = {
      arch = "modemmanager";
      reason = "The WWAN control plane for a cellular uplink.";
    };
    bluez = {
      arch = "bluez";
      reason = "The Bluetooth daemon and base transport stack.";
    };
    bluez-utils = {
      arch = "bluez-utils";
      reason = "Bluetooth controller and transport administration tools.";
    };
    bluez-obex = {
      arch = "bluez-obex";
      reason = "Optional OBEX transfer backend, separate from base Bluetooth transport.";
    };
    bluez-hid2hci = {
      arch = "bluez-hid2hci";
      reason = "Optional converter for Bluetooth HID adapters that need it.";
    };
    bpftune = {
      arch = "bpftune-git";
      reason = "Optional runtime network-tuning daemon supplied by CachyOS.";
    };
  };
}
