# checks/coverage.nix — TEST-1, and the only honest place to record what this
# repo cannot yet prove about itself.
#
# BEHAVIORS.md declares behaviour ids; the flake exposes checks named after
# them. This check is the mechanical link between the two sets, and it fails on
# drift in EITHER direction:
#
#   * an id in the document with no check and no waiver -- a behaviour someone
#     wrote down and nobody wired to evidence;
#   * an id waived here that a test now covers -- a waiver nobody deleted, which
#     is how a to-do list turns into decoration;
#   * a check or waiver naming an id the document does not declare -- a stale
#     test, or a typo that would otherwise read as coverage.
#
# The `waived` list is deliberately verbose and deliberately uncomfortable. A
# behaviour contract with no link to a test is a wish list; a link that quietly
# reports "covered" for a behaviour nothing exercises is worse, because it
# converts an unknown into a false assurance. So absence is written down, by
# id, with the reason -- and the list is expected to shrink.

{ pkgs, behaviorsFile, covered }:

let
  lib = pkgs.lib;

  # TEST-1 is satisfied by THIS derivation: the check of that name is the id
  # link it demands. Kept separate from `covered` so a VM test can never
  # accidentally claim it.
  #
  # Read the circularity honestly: TEST-1 says "every behaviour id has a VM
  # test", and the check that claims to prove it is this one -- which passes
  # with 21 of 28 ids waived. So TEST-1 proves the LINK exists and is
  # maintained, not that the obligation is met. The `waived` list below is the
  # actual answer to TEST-1, and it is 21 entries long.
  selfCovered = [ "TEST-1" ];

  # A behaviour whose check exercises only PART of the entry. Not a waiver --
  # the check exists, runs, and would catch a regression in what it does cover
  # -- and not silence either, because a coverage report that says "proven"
  # for a half-tested behaviour is the false assurance this file's header
  # warns about. Printed alongside the proven set.
  partial = {
    "FW-2" = "the foreign-table half is tested (checks/vm/firewall-foreign-table.nix: a table nixnet does not own survives first apply, re-apply and removal, byte-identical). The SECOND half of FW-2 -- 'every rule any nixnet module contributes lands in nixnet's one table' -- is neither implemented nor tested: modules/overlay.nix still renders and applies its own `inet nixnet-overlay` table. modules/firewall.nix derives the confinement and asserts the two agree, which is a check on the VALUE, not on where the rule lands";
  };

  waived = {
    "OWN-2" = "no test drives every transport of a subject down for long enough to prove nixnet takes no larger action; proving a NEGATIVE (no reboot, no teardown) needs a bounded observation window nobody has specified yet";
    "OWN-3" = "watchdog restart-with-rate-limit is testable in a VM (fake a wedged daemon, assert one restart per minRestartIntervalSec) -- not written";
    "ADDR-1" = "an EVAL-time failure, so a VM test is the wrong instrument. The FIREWALL half is now covered by eval checks (`typoFires`, `unstatedAddressingFires` in experiments/render-check.nix, which checks/default.nix runs). The rest of ADDR-1's 'anywhere' is NOT implemented and therefore cannot be tested: an interface named by a transport's `probe`/`interface`, by an uplink, or by `nixnet.overlay.overlayInterface` on a peer with no forward chain is accepted with no assertion at all -- verified, zero assertions fire. That is the typo-fails-open class this entry exists to kill, still open outside the firewall";
    "ADDR-2" = "eval-time failure, same instrument problem as ADDR-1; the `probe.target` requirement on a dynamically-addressed transport is not implemented either";
    "ADDR-3" = "needs the addressing drift reconciler, which does not exist; the VM shape is clear (declare a static address the kernel does not hold, assert the subject degrades)";
    "FW-1" = "eval-time failure, so a VM test is the wrong instrument -- a refusal's whole point is that no machine ever boots. Covered by `lockoutFires` in experiments/render-check.nix, which checks/default.nix now runs, so this is waived from a VM test rather than from evidence";
    "FW-5" = "the dead-man switch arms on change and not on boot; a VM test needs two boots of the same generation plus a boot of a changed one, which the driver supports but no test does yet";
    "FW-6" = "waived from a VM test rather than from evidence, same as FW-1. What lands in `environment.systemPackages` is decided at eval time, so eval checks are the sharper instrument here, and both directions plus all three backends are covered by `firewallInstallsNft`, `overlayInstallsNft`, `noToolingInstallsNothing`, `overlayNoToolingInstallsNothing`, `disabledFirewallInstallsNothing`, `toolingSilentWhenSatisfied`, `nixosResolvesToPackage`, `systemManagerResolvesToPackage`, `darwinResolvesToNothingAndSaysSo`, `darwinDeclaredNullNotMissing` and `unavailableWarningNamesOption` in experiments/render-check.nix, which checks/default.nix runs. STATE THE GAP HONESTLY: those prove the PACKAGE is selected and installed, not that the BINARY resolves as bare `nft` for a root shell. On NixOS the system profile makes that equivalent; on system-manager it does not -- delivery is /run/system-manager/sw/bin prepended by /etc/profile.d and /etc/environment.d, so a shell that sources neither (fish is an open TODO in system-manager's own source) has the package installed and `nft` still not on PATH. That is a VM test nobody has written, and it is the half that would actually fail. The nix-darwin arm is proved at the resolver, not on a darwin machine, because nixnet publishes no darwinModules to evaluate";
    "TF-1" = "winner determinism and the hysteresis hold window are exercised by unit tests only; a VM test would flap a probe target and assert the published value's timing";
    "TF-2" = "publish-on-reconcile is IMPLEMENTED and unit-tested on both backends -- a settled single-uplink host with no winner change publishes its metric (`a_settled_single_uplink_host_still_publishes_its_metric`), an emptied hosts block is restored on the next tick (`a_hosts_block_emptied_behind_the_daemon_is_restored_on_the_next_tick`), and the 'Not:' half is pinned from both sides: an agreeing routing table produces zero route commands and an unchanged peer set does not even change the hosts file's inode. It stays WAIVED because none of that boots a machine: the VM shape is to change the live route out from under a settled daemon, with a real DHCP client on the other side, and assert it is re-asserted within one reconcile interval. Unit tests prove the daemon issues the right commands; only a VM proves the kernel ends up in the state the commands intended";
    "TF-3" = "loser demotion is IMPLEMENTED and unit-tested: after a failover the ex-winner is re-metricked in the same publication, no two transports of the subject share a metric, and the loser's default route is demoted rather than deleted (`a_winner_change_leaves_no_two_transports_sharing_a_metric`, `the_demoted_loser_keeps_a_default_route`, and `the_loser_is_demoted_in_the_same_apply_that_promotes_the_winner` at the publisher). Still WAIVED for the same reason as TF-2, and one more specific to it: the assertion that matters most -- that the kernel then routes over the surviving link -- needs two real uplinks in one VM and traffic across them, which no test here has";
    "TF-4" = "netlink route publication is not implemented, so there is nothing to point a test at";
    "TF-5" = "the all-down policies are half-covered: STALE-2's test exercises lastKnownGood, nothing exercises unpublish";
    "TF-6" = "state restore by transport identity is unit-testable and untested here; a VM test would restart the daemon across a config edit and assert counters did not transplant";
    "ISO-1" = "per-layer isolation classification does not exist; the VM shape is a node with a reachable gateway and a dead resolver, asserting l3 green and dns red";
    "PUB-2" = "the first-ever activation, before the daemon has ever run, is not reachable from a VM that boots an already-activated system; testing it needs a node that installs itself, not one that starts installed";
    "STALE-1" = "the data is published -- status.json carries `lastConfirmedAt` per group alongside the snapshot's `generatedAt`, and the hosts block carries `# nixnet written=<ts>` plus a `# nixnet <address> confirmed=<ts>` line above each entry -- but nothing ASSERTS either shape. Deliberate while the rebuild is still choosing the health document's format: a VM test that greps for those exact field names freezes them, and STALE-1's claim is about what a consumer can compute, not about a spelling. The half that is genuinely untested is the health document, which does not exist (see HEALTH-1)";
    "HEALTH-1" = "no health document exists to assert one subject per domain against";
    "HEALTH-2" = "validUntil semantics need a document first; the test is trivial once it exists (stop the daemon, assert the document expires)";
    "HEALTH-3" = "needs the health document and a way to fail one subject while the others stay green";
  };

  behavioursPresent = builtins.pathExists behaviorsFile;

  ids =
    let
      lines = lib.splitString "\n" (builtins.readFile behaviorsFile);
      headings = builtins.filter (l: lib.hasPrefix "### " l) lines;
    in
    map (l: lib.head (lib.splitString " " (lib.removePrefix "### " l))) headings;

  claimed = covered ++ selfCovered;
  waivedIds = builtins.attrNames waived;
  accountedFor = claimed ++ waivedIds;

  unaccounted = lib.subtractLists accountedFor ids;
  staleWaivers = builtins.filter (i: builtins.elem i claimed) waivedIds;
  unknown = lib.subtractLists ids accountedFor;

  partialIds = builtins.attrNames partial;

  problems =
    (map (i: "behaviour ${i} is declared in BEHAVIORS.md but has neither a check nor a waiver") unaccounted)
    ++ (map (i: "behaviour ${i} is waived in checks/coverage.nix but a check now covers it -- delete the waiver") staleWaivers)
    ++ (map (i: "id ${i} is claimed by a check or a waiver but BEHAVIORS.md does not declare it") unknown)
    # A partial note that names an id nothing claims is a note about a test that
    # no longer exists -- the same rot the stale-waiver rule catches, from the
    # other side.
    ++ (map (i: "behaviour ${i} is noted as PARTIAL in checks/coverage.nix but no check claims it -- delete the note or write the test")
      (lib.subtractLists claimed partialIds))
    ++ (map (i: "id ${i} is noted as PARTIAL but BEHAVIORS.md does not declare it")
      (lib.subtractLists ids partialIds));

  report = lib.concatMapStringsSep "\n" (p: "  - ${p}") problems;
in
if !behavioursPresent then
  pkgs.runCommand "nixnet-behaviour-coverage-NO-CONTRACT" { } ''
    echo "BEHAVIORS.md is not present in the flake source." >&2
    echo "If it exists in the working tree, it is untracked -- flakes copy tracked" >&2
    echo "files only, so the behaviour contract is invisible to this check." >&2
    exit 1
  ''
else if problems != [ ] then
  throw ''
    nixnet behaviour coverage FAILED (${toString (builtins.length problems)} problem(s)):
    ${report}
  ''
else
  pkgs.runCommand "nixnet-behaviour-coverage"
    {
      total = toString (builtins.length ids);
      # "claimed", not "proven". A check named after a behaviour may still be
      # the `unrunnable` stub checks/vm/lib.nix emits for a test whose options
      # do not exist yet: it FAILS rather than passing, so CI is honest, but
      # this report would have called it proof. The evidence is the check's
      # exit status, never this line. No claimed id is a stub as it stands.
      claimedIds = lib.concatStringsSep " " (lib.naturalSort claimed);
      partialIds = lib.concatStringsSep " " (lib.naturalSort partialIds);
      unproven = lib.concatStringsSep " " (lib.naturalSort waivedIds);
    }
    ''
      echo "BEHAVIORS.md declares $total behaviours."
      echo "claimed by a check: $claimedIds"
      echo "  of those, PARTIAL: $partialIds"
      echo "waived, no check:   $unproven"
      touch $out
    ''
