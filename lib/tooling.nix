# lib/tooling.nix — the tools a host needs in order to LOOK AT what nixnet made it enforce, named
# per backend.
#
# THE FAILURE THIS EXISTS FOR, stated plainly. A production host was enforcing a nixnet-authored
# `inet` table while `nft` was not installed on it at all. Nothing failed, and that is the point:
# the ruleset loads from a store path, so ENFORCEMENT never needs the binary. Every QUESTION about
# it does — is the table there, which chain dropped that packet, did the confinement survive the
# last foreign flush — and the answer, mid-incident, was to fetch nftables over a network the
# firewall under investigation is a candidate cause of having lost. A host that enforces a ruleset
# must be able to read it.
#
# WHY A TABLE, FOR WHAT IS CURRENTLY ONE PACKAGE. Because the interesting value in it is `null`. A
# selection here resolves to a package NAME, and what varies across backends is that name —
# including the case where a backend has NO answer at all. `null` is not an oversight and not a
# to-do: it is this file stating, in a value a consumer can read and act on, that the selection
# cannot be satisfied on that backend. The alternative — a module that installs an empty list on a
# backend without nftables — is indistinguishable from one that worked, which is the exact shape of
# the failure above.
#
# Shared by `modules/firewall.nix` and `modules/overlay.nix` because BOTH write an nftables table,
# so both owe the host the means to read one. One catalogue, so "which backend cannot do this" is
# answered in one place rather than per module.
{ lib }:

rec {
  # ── The catalogue ───────────────────────────────────────────────────────────────────────────
  #
  # One entry per tool, naming it per BACKEND — which Nix module system is evaluating this config —
  # rather than per operating system. The backend is what decides how a package is DELIVERED, and
  # delivery is the whole difficulty here.
  tools = {
    nft = {
      # The nftables CLI: `nft list ruleset`, `nft list table inet <name>`, `nft monitor`.

      # A nixpkgs attribute path, resolved against the consumer's own `pkgs`.
      nixos = "nftables";

      # THE SAME nixpkgs attribute, deliberately, and the comment is the answer to "why not the
      # distro's package". system-manager manages a foreign distro's /etc and systemd units; it
      # does not drive pacman, apt or dnf and has no reconciler that could. Installing the DISTRO's
      # nftables is a different tool's job in a different repo, and coupling this module to any one
      # such reconciler would make nixnet unusable to anyone who does not run it.
      #
      # So on this backend the answer is a nixpkgs build placed on PATH, and that is what this
      # entry means. system-manager declares the same `environment.systemPackages` option NixOS
      # does (its nix/modules/environment.nix buildEnv's the list into /run/system-manager/sw and
      # prepends /run/system-manager/sw/bin to PATH from /etc/profile.d and /etc/environment.d), so
      # the option a module writes is identical on both Linux backends and only the mechanism
      # underneath differs.
      #
      # KNOWN LIMIT, worth stating because it decides whether this actually delivers: that PATH
      # hook reaches shells that source /etc/profile (and services that read /etc/environment.d).
      # A shell that reads neither — fish is the one system-manager's own source calls out as an
      # open TODO — does not get it, and on such a host `nft` must be invoked by path or supplied
      # by the distro. The binary is installed either way; what varies is whether bare `nft`
      # resolves.
      system-manager = "nftables";

      # NOT APPLICABLE, and said out loud rather than left as an absent branch. macOS filters
      # packets with pf (`pfctl`), not netfilter; there is no nftables to install and there will
      # not be one. `null` here is the honest answer, and `resolve` below reports it as an
      # unsatisfiable selection instead of quietly installing nothing.
      #
      # nixnet publishes no `darwinModules` today, so nothing reaches this value yet. It is
      # declared anyway because the question "what happens on darwin" has an answer, and a table
      # that omits the backend it cannot serve is a table that looks complete and is not.
      nix-darwin = null;
    };
  };

  # ── Which module system is evaluating this ──────────────────────────────────────────────────
  #
  # Each backend is detected through its OWN option namespace — the idiom modules/core.nix already
  # uses for system-manager, generalised rather than copied a third time. Cheaper and more precise
  # than probing for the presence of some NixOS option that a backend might also happen to declare:
  # system-manager's `networking.firewall` MOCK accepts the full NixOS schema, warns, and touches
  # nothing, so "the option exists" proves nothing at all about the backend.
  #
  # `system-manager.*` exists only under system-manager. `system.defaults.*` exists only under
  # nix-darwin (NixOS declares `system`, never `system.defaults`). Anything else is real NixOS.
  backendOf = options:
    if options ? system-manager then "system-manager"
    else if options ? system.defaults then "nix-darwin"
    else "nixos";

  # ── Resolving a selection ───────────────────────────────────────────────────────────────────
  #
  # Returns BOTH halves — what this backend can install, and what it cannot. The second half is not
  # an error and not silence: the caller is expected to say it, in a warning or an option
  # description, because a backend that cannot satisfy a selection and a backend that satisfied it
  # must not look the same from outside.
  resolve = { pkgs, options, names }:
    let
      backend = backendOf options;
      entries = map (name: { inherit name; attr = tools.${name}.${backend}; }) names;
    in
    {
      inherit backend;

      packages = map (e: lib.getAttrFromPath (lib.splitString "." e.attr) pkgs)
        (lib.filter (e: e.attr != null) entries);

      unavailable = map (e: e.name) (lib.filter (e: e.attr == null) entries);
    };

  # The warning a consumer emits for an unsatisfiable selection. Here rather than in each module so
  # the two modules cannot drift into saying different things about the same fact.
  unavailableWarning = { option, backend, unavailable }: ''
    ${option}: this backend (${backend}) has no ${lib.concatStringsSep ", " unavailable}, so
    nothing was installed for ${if lib.length unavailable == 1 then "it" else "them"}. The ruleset
    is still enforced; only the means to READ it from this host is missing. Set `${option} = [ ];`
    to state that you know, or inspect the ruleset from somewhere that has the tool.
  '';
}
