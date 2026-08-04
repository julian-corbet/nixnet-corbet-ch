# checks/vm/lastknowngood-staleness.nix — STALE-2.
#
# Unbounded `lastKnownGood` is not a trade-off, it is a leak. One peer on this
# estate has been published continuously since 2026-07-24 across roughly 48,000
# consecutive probe failures: degraded in status.json, and resolving perfectly
# for anyone who just asks the resolver, which is everyone. Restore-at-start
# has no age check either, which is how it survived every restart that might
# have cleared it.
#
# Three assertions, and the FIRST is what stops the other two from being
# satisfied by a module that simply never publishes:
#
#   1. inside the bound, a failing peer still resolves. lastKnownGood is doing
#      its job; an implementation that withdrew immediately would be
#      `unpublish` wearing a different name, and would pass (2) and (3)
#      trivially.
#   2. past the bound, the entry is withdrawn -- observed through NSS, because
#      "still in the file" and "still resolving" are the same thing to a
#      consumer and neither is acceptable.
#   3. a daemon restart after the bound has elapsed does not resurrect it. The
#      startup re-assert reads the last winner out of state.json; if that path
#      has no age check, every restart launders a stale entry into a
#      fresh-looking one and the bound in (2) is decorative.
#
# Then the peer comes back, and must be published again: a bound that expired
# an entry permanently would trade a stale address for a missing one.
#
# Deliberately NOT asserted: the shape of the staleness fields in status.json
# (STALE-1). That is a document-format claim, and pinning a field name from a
# VM test would freeze a format this rebuild is still choosing. What is
# asserted is what a consumer can observe without reading nixnet's documents at
# all.

{ pkgs }:

let
  # Long enough that assertion 1 has room to run before it expires, short
  # enough that assertion 2 does not dominate the test's runtime.
  maxAgeSec = 20;
in
{
  name = "lastknowngood-staleness";
  behaviours = [ "STALE-2" ];
  requiresModules = [ ];
  requiresOptions = [
    [ "nixnet" "peers" "onAllDown" ]
    [ "nixnet" "peers" "lastKnownGood" "maxAgeSec" ]
  ];

  test = { modules, baseline }: {
    name = "nixnet-lastknowngood-staleness";

    nodes = {
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
          daemon.defaultProbe = {
            intervalMs = 500;
            timeoutMs = 400;
            upThreshold = 1;
            downThreshold = 2;
          };
          peers.peerA = {
            hostnames = [ "host-a.example.org" ];
            onAllDown = "lastKnownGood";
            lastKnownGood.maxAgeSec = maxAgeSec;
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
      PEER_IP = "${nodes.peer.networking.primaryIPAddress}"
      MAX_AGE = ${toString maxAgeSec}

      start_all()
      peer.wait_for_unit("sshd.service")
      host.wait_for_unit("nixnetd.service")

      host.wait_until_succeeds(f"getent hosts host-a.example.org | grep -q {PEER_IP}")

      # Break the only transport. The peer stays declared and the daemon stays
      # up: this is a peer that is unreachable, not one that was removed.
      peer.succeed("systemctl stop sshd.service")

      # ── 1. inside the bound: still published, on purpose ───────────────
      host.sleep(4)
      host.succeed(f"getent hosts host-a.example.org | grep -q {PEER_IP}")

      # ── 2. past the bound: withdrawn ───────────────────────────────────
      # Bounded wait, because the failure mode under test is "never
      # withdrawn"; an unbounded wait would report that as a hang instead of
      # as a failure.
      host.wait_until_fails("getent hosts host-a.example.org", timeout=MAX_AGE + 40)

      # ── 3. a restart must not launder it back ──────────────────────────
      host.succeed("systemctl restart nixnetd.service")
      host.wait_for_unit("nixnetd.service")
      host.sleep(5)
      host.fail("getent hosts host-a.example.org")

      # Recovery still works.
      peer.succeed("systemctl start sshd.service")
      host.wait_until_succeeds(f"getent hosts host-a.example.org | grep -q {PEER_IP}")
    '';
  };
}
