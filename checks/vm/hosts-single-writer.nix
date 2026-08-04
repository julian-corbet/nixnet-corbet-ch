# checks/vm/hosts-single-writer.nix — PUB-1.
#
# Two writers, no handshake, and the root-side writer wins. The daemon
# publishes the declared `hostnames` aliases into its hosts file; a root
# activation script rewrites the same file from scratch, keyed by the peer's
# Nix ATTRIBUTE NAME. So every switch reverted the daemon's block and every
# alias went NXDOMAIN -- until the next winner change, which on a settled fleet
# never comes. Foreign entries die the same way: the daemon snapshots the
# non-managed prefix once at start and replays that snapshot forever.
#
# This test runs against modules/core.nix AS IT STANDS. It is expected to fail
# until the rebuild lands, and the shape of the failure is the specification:
# what is asserted is not "the seed was deleted" but the three separable
# outcomes PUB-1 names, each of which can regress on its own.
#
#   1. the daemon's DECLARED aliases resolve. Asserted with `getent`, not with
#      a grep of the file: "the line is in the file" and "the name resolves"
#      are different claims, and only the second is what a consumer
#      experiences. Both aliases, because the seed writes exactly one name --
#      the attribute name -- so a one-name assertion cannot tell the two
#      writers apart.
#   2. a system activation with the daemon RUNNING leaves the file
#      byte-identical, and every published name still resolving afterwards.
#   3. an entry written outside nixnet's markers by something that is not
#      nixnet survives the daemon's next publication.
#
# Clause 3 needs care, and the care is the interesting part: it is vacuous
# unless a publication actually happens after the foreign line appears.
# Publication today is emitted only inside the winner-change branch (TF-2 is
# the entry that fixes that), and under the default `lastKnownGood` an
# all-down group takes the explicit no-publish branch while recovery
# re-selects the same winner index -- so a down/up flap emits nothing at all.
# The peer here therefore declares `onAllDown = "unpublish"`, which publishes
# on both edges. Without that, this clause would pass against the very bug it
# is written for.

{ pkgs }:

{
  name = "hosts-single-writer";
  behaviours = [ "PUB-1" ];
  requiresModules = [ ];
  requiresOptions = [
    [ "nixnet" "daemon" "hostsFile" ]
    [ "nixnet" "peers" "hostnames" ]
    [ "nixnet" "peers" "onAllDown" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-hosts-single-writer";

    nodes = {
      # The probe target. Nothing nixnet-specific runs here: it exists to be
      # reachable, and to stop being reachable on command.
      peer = { ... }: {
        imports = [ baseline ];
        virtualisation.vlans = [ 1 ];
        services.openssh.enable = true;
      };

      host = { nodes, ... }: {
        imports = [ modules.core baseline ];
        virtualisation.vlans = [ 1 ];

        nixnet = {
          enable = true;
          # Fast enough that a state change is observable inside a test's
          # patience, slow enough that a probe is still a probe.
          daemon.defaultProbe = {
            intervalMs = 500;
            timeoutMs = 400;
            upThreshold = 1;
            downThreshold = 2;
          };
          peers.peerA = {
            # Deliberately unlike the attribute name `peerA`: the activation
            # seed keys its entries by the attribute name, so a seed that wins
            # is directly visible as these two names disappearing.
            hostnames = [ "host-a" "host-a.example.org" ];
            onAllDown = "unpublish";
            transports = [{
              address = nodes.peer.networking.primaryIPAddress;
              priority = 10;
              probe = { method = "tcp"; port = 22; };
            }];
          };
        };
      };
    };

    testScript = { nodes, ... }: ''
      HOSTS = "${nodes.host.nixnet.daemon.hostsFile}"
      PEER_IP = "${nodes.peer.networking.primaryIPAddress}"

      start_all()
      peer.wait_for_unit("sshd.service")
      host.wait_for_unit("nixnetd.service")

      # ── 1. the daemon publishes the declared aliases ───────────────────
      host.wait_until_succeeds(f"getent hosts host-a.example.org | grep -q {PEER_IP}")
      host.succeed(f"getent hosts host-a | grep -q {PEER_IP}")

      # ── 2. THE two-writer assertion ────────────────────────────────────
      # Ordered before clause 3 on purpose: 3 fails first against today's
      # code, and an assertion that never runs is an assertion nobody has
      # the result of.
      #
      # `switch-to-configuration test` is the activation path a real
      # `nixos-rebuild switch` takes, activation scripts included -- which is
      # where the competing writer lives.
      before = host.succeed(f"cat {HOSTS}")
      host.succeed("/run/current-system/bin/switch-to-configuration test")
      after = host.succeed(f"cat {HOSTS}")

      assert after == before, (
          "a system activation rewrote the daemon's published hosts file:\n"
          f"--- before activation ---\n{before}--- after activation ---\n{after}"
      )

      # State, not bytes. Asserted separately because a seed could preserve
      # the file's content while breaking the /etc/hosts link that makes it
      # reachable to NSS at all, and that failure is invisible to a diff.
      host.succeed(f"getent hosts host-a.example.org | grep -q {PEER_IP}")
      host.succeed(f"getent hosts host-a | grep -q {PEER_IP}")

      # The daemon must survive its own file being reconciled underneath it. A
      # publisher that dies here leaves a file that is correct exactly once,
      # which is indistinguishable from a working one until the next winner
      # change -- i.e. never, on a settled fleet.
      host.succeed("systemctl is-active nixnetd.service")

      # ── 3. a foreign entry survives the next publication ───────────────
      host.succeed(f"sed -i '1i 192.0.2.99\\tforeign.example.org' {HOSTS}")
      host.succeed("getent hosts foreign.example.org | grep -q 192.0.2.99")

      # Force a genuine publication, observed at both edges through NSS --
      # withdrawal and republication are what a consumer sees, and they are
      # the same two events the file rewrite rides on.
      peer.succeed("systemctl stop sshd.service")
      host.wait_until_fails("getent hosts host-a.example.org")
      peer.succeed("systemctl start sshd.service")
      host.wait_until_succeeds(f"getent hosts host-a.example.org | grep -q {PEER_IP}")

      host.succeed("getent hosts foreign.example.org | grep -q 192.0.2.99")
    '';
  };
}
