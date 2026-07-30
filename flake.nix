{
  description = "Provider-agnostic transport failover: a health-checked, hysteresis-damped best-path publisher for both remote peers (LAN/overlay-VPN/...) and local uplinks (wired/wireless/cellular/...), plus resident-daemon health watchdogs (NetBird, Cloudflare Tunnel) for any declaratively-managed network connection that can fail and needs non-interactive recovery.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      # ---------------------------------------------------------------
      # The generic engine. `nixosModules.default = nixosModules.core` so
      # a bare `imports = [ inputs.nixnet.nixosModules.default ]` gets
      # the peer+uplink engine with zero providers — providers are opt-in
      # additional imports (design.md §11/§12).
      # ---------------------------------------------------------------
      nixosModules.core = ./modules/core.nix;
      nixosModules.default = self.nixosModules.core;
      nixosModules.netbird-provider = ./modules/netbird-provider.nix;

      # cloudflared-provider: NOT a peer/uplink transport contributor (see
      # its own header comment) -- a standalone resident-daemon health
      # watchdog reusing netbird-provider's drift-check/reprovision
      # pattern. Does not require nixosModules.core to be imported at all.
      nixosModules.cloudflared-provider = ./modules/cloudflared-provider.nix;

      # ---------------------------------------------------------------
      # Same files, rendered onto system-manager's smaller option surface
      # instead of a real NixOS rebuild (design.md §9). nixnet only ever
      # touches environment.etc, systemd.services/timers/paths, and a
      # rendered JSON config — none of the primitives system-manager
      # categorically can't reach (no boot.kernel.sysctl, no kernel
      # command-line parameters).
      # ---------------------------------------------------------------
      systemManagerModules.core = ./modules/core.nix;
      systemManagerModules.default = self.systemManagerModules.core;
      systemManagerModules.netbird-provider = ./modules/netbird-provider.nix;
      systemManagerModules.cloudflared-provider = ./modules/cloudflared-provider.nix;

      packages = forAllSystems (system: {
        nixnet = (pkgsFor system).callPackage ./package.nix { };
        default = self.packages.${system}.nixnet;
      });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
