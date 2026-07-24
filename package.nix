# The nixnetd + nixnetctl build, shared by flake.nix's `packages` output and
# modules/core.nix's `services.nixnet.package` default so there is exactly
# one place this derivation is defined.
{ lib, buildGoModule }:

buildGoModule {
  pname = "nixnet";
  version = "0.1.0";
  src = ./.;

  # vendor/ is committed (see go.mod, go.sum, vendor/modules.txt) so this
  # builds fully offline and reproducibly without a network-fetch FOD hash
  # to keep in sync. Re-run `go mod vendor` after any dependency bump.
  vendorHash = null;

  # Deliberately NOT setting subPackages: the real, substantive tests
  # (internal/config, internal/engine, internal/probe) live outside
  # cmd/*, and buildGoModule's checkPhase only tests whatever subPackages
  # restricts the build to. Leaving it unset builds/tests `./...` (every
  # package, including internal/*) and still only *installs* the two
  # `package main` dirs under cmd/ -- a library package produces nothing
  # for `go install` to place in $out/bin, so this is both simpler and
  # correct, not just "more thorough."
  ldflags = [ "-s" "-w" ];

  # design.md §1 picks Go specifically for "a single static
  # cross-compiled artifact" -- without this, `net` pulls in cgo on a
  # glibc host and nixnetd links dynamically against glibc instead
  # (harmless inside this same derivation's own Nix closure, but not
  # actually the static artifact the design rationale describes). Safe
  # here: every net.ResolveIPAddr call in internal/probe resolves either
  # a literal IP (no resolver needed at all) or a target the operator
  # configured directly -- nixnet is not depending on cgo's NSS
  # integration for anything.
  env.CGO_ENABLED = "0";

  meta = {
    description = "Provider-agnostic transport failover daemon: peer address publish + uplink route-metric publish, health-checked, hysteresis-damped";
    homepage = "https://github.com/julian-corbet/nixnet-corbet-ch";
    license = lib.licenses.mit;
    mainProgram = "nixnetd";
    platforms = lib.platforms.linux;
  };
}
