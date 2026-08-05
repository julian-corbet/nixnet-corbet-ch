# NixNet's NixOS-only owner for bpftune.
#
# bpftune continuously changes transport-related kernel policy, so a host must
# opt in explicitly. Foreign system-manager hosts use the package catalogue
# backend instead; that backend deliberately does not create a second native
# service unit.
{ lib, config, ... }:
let
  cfg = config.nixnet.bpftune;
in
{
  options.nixnet.bpftune.enable = lib.mkEnableOption "the bpftune BPF transport-tuning daemon";

  config = lib.mkIf cfg.enable {
    services.bpftune.enable = true;
  };
}
