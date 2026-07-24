# The nixnetd + nixnetctl build, shared by flake.nix's `packages` output and
# modules/core.nix's `services.nixnet.package` default so there is exactly
# one place this derivation is defined.
{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "nixnet";
  version = "0.1.0";
  src = ./.;

  # Cargo.lock is committed so this builds fully offline and reproducibly
  # -- importCargoLock derives its own fixed-output fetch hash straight
  # from the lockfile, no separate vendorHash/cargoHash to keep in sync.
  # Re-run `cargo build` (or `cargo generate-lockfile`) after any
  # dependency bump to refresh it.
  cargoLock.lockFile = ./Cargo.lock;

  # A Cargo workspace with two [[bin]] targets (nixnetd, nixnetctl) over
  # one shared library crate -- mirrors the Go layout's cmd/nixnetd +
  # cmd/nixnetctl thin mains over internal/*. buildRustPackage's default
  # checkPhase runs `cargo test`, which exercises every unit test (in
  # src/**) and integration test (tests/*.rs) in the crate, same "build
  # everything, test everything, install just the two binaries" shape the
  # previous Go derivation had.
  meta = {
    description = "Provider-agnostic transport failover daemon: peer address publish + uplink route-metric publish, health-checked, hysteresis-damped";
    homepage = "https://github.com/julian-corbet/nixnet-corbet-ch";
    license = lib.licenses.mit;
    mainProgram = "nixnetd";
    platforms = lib.platforms.linux;
  };
}
