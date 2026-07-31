{
  description = "Provider-agnostic transport failover: a health-checked, hysteresis-damped best-path publisher for both remote peers (LAN/overlay-VPN/...) and local uplinks (wired/wireless/cellular/...), plus resident-daemon health watchdogs (NetBird, Cloudflare Tunnel) for any declaratively-managed network connection that can fail and needs non-interactive recovery -- plus the networking mechanism itself: a NetBird overlay client/routing-peer, an embed multi-peer mesh gateway, NetBird ACL group reconciliation, a declared NetBird access-model (groups/directional policies/route distribution) audited against the live account, Cloudflare Tunnel ingress provisioning, and a split-horizon in-cluster proxy/DNS config generator.";

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
      # The networking-ownership modules: none of these contribute a
      # peer/uplink transport and none require nixosModules.core
      # -- they provision/manage the underlying network connections
      # themselves (a NetBird overlay client, an embed multi-peer gateway, an
      # ACL group reconciler, a Cloudflare Tunnel) rather than health-checking
      # an address someone else already brought up. NixOS-only for now (each
      # uses at least one primitive -- boot.kernel.sysctl,
      # networking.firewall.extraCommands, or upstream services.cloudflared --
      # outside system-manager's smaller option surface; see core.nix's own
      # header for that boundary).
      nixosModules.overlay = ./modules/overlay.nix;
      nixosModules.mesh-gateway = ./modules/mesh-gateway.nix;
      nixosModules.netbird-group-reconcile = ./modules/netbird-group-reconcile.nix;
      nixosModules.netbird-access-model = ./modules/netbird-access-model.nix;
      nixosModules.ingress = ./modules/ingress.nix;

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

      # Pure functions, not NixOS modules -- called from a consumer's own
      # flake `outputs` or host config `let`, the same way `nixpkgs.lib`
      # itself is consumed. See lib/svc-proxy-config.nix's own header for
      # the full contract.
      lib.svcProxyConfig = import ./lib/svc-proxy-config.nix;

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
