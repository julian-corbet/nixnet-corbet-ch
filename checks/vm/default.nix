# checks/vm/default.nix — the VM check set.
#
# Each test file returns a SPEC (name, the BEHAVIORS.md ids it proves, what it
# needs from modules/, and the runNixOSTest argument). Assembling them here
# rather than exporting derivations directly is what lets `../coverage.nix`
# answer TEST-1 mechanically: the id set is data, not a comment.
#
# Every test is exposed twice -- once as `vm-<slug>`, once under each behaviour
# id it proves, so `nix build .#checks.<system>.FW-3` names the behaviour rather
# than the file someone happened to put it in. Same derivation both ways; Nix
# builds it once.

{ pkgs, nixpkgs, moduleDir }:

let
  lib = pkgs.lib;
  harness = import ./lib.nix { inherit pkgs nixpkgs moduleDir; };

  specs = map (f: import f { inherit pkgs; }) [
    ./dhcp-addressing.nix
    ./firewall-apply-failure.nix
    ./firewall-foreign-table.nix
    ./hosts-single-writer.nix
    ./lastknowngood-staleness.nix
  ];

  built = map (s: s // { drv = harness.mkTest s; }) specs;

  slugged = builtins.listToAttrs (map (s: { name = "vm-${s.name}"; value = s.drv; }) built);

  aliases = builtins.listToAttrs (lib.concatMap
    (s: map (b: { name = b; value = s.drv; }) s.behaviours)
    built);

  covered = lib.concatMap (s: s.behaviours) built;

  # A behaviour id claimed by two tests is a merge accident, not a feature: the
  # alias attribute would silently keep one of them and the coverage report
  # would count the id as proven by whichever won.
  duplicates = lib.subtractLists (lib.unique covered) covered;
in
assert lib.assertMsg (duplicates == [ ])
  "checks/vm: behaviour id(s) claimed by more than one test: ${lib.concatStringsSep ", " duplicates}";
{
  checks = slugged // aliases;
  inherit covered;
}
