# nixnet — behaviour contract
Review this INSTEAD of the code. Every entry is decidable from outside the process: a situation, an observable
outcome, the failure it prevents, and the boundary next to it. **This is the TARGET contract for the rebuild,
not a description of what runs today** — several entries exist because the current code does the opposite, and
`TEST-1` is what turns an entry into evidence.

**Why one repo.** nixnet owns a host's network reality: addressing, transports and failover, the overlay, peers,
DNS, ingress — and now the packet filter, split into a separate repo and folding back in. The split's cost is
structural rather than anecdotal: a firewall repo cannot see how a host gets its address, so every rule that
depends on that fact is something a human has to remember. One owner, one evaluation, one place where "this host
is DHCP-addressed" and "this host drops unmatched input" meet.

A caution about the example that motivated this, because it was wrong. The rebuild began believing a
default-deny chain without DHCP accepts had cost an edge host its address at lease expiry. Measured in a VM
(`TEST-2`), it does not: conntrack's established/related accept matches the unicast RENEW's reply, and on the
broadcast leg both dhcpcd and systemd-networkd fall back to a raw AF_PACKET socket delivered before the input
hook. The rules are parity with nixpkgs, not a rescue, and that host died of something else entirely. The
derivation in `OWN-1` is still right — a rule that cannot see the fact it depends on is a rule waiting to be
forgotten — but it is justified by the structure, not by that outage.

Ids are machine-read (`### <ID> — <title>`, id is the first token) and stable. Do not renumber.

## Ownership — what nixnet decides, and what it refuses to decide
### OWN-1 — one evaluation sees every network fact of the host
**GIVEN** a host declaring `nixnet.interfaces.eth0.addressing.v4 = "dhcp"`, a default-deny firewall, and no DHCP
rule of its own, **THEN** the ruleset contains the DHCPv4 client accept, and removing the addressing declaration
removes it.

Why: the rule and the fact motivating it lived in two repos that could not see each other, so the rule was
something to remember. Derivation makes forgetting impossible. Overlay confinement, gateway listeners and
ingress accepts derive the same way.

Not: facts are DECLARED, never discovered from the running system and acted on; drift is REPORTED (`ADDR-3`).

### OWN-2 — nixnet never takes an action bigger than a network object it owns
**GIVEN** every transport of every subject down for an arbitrarily long time, **THEN** nixnet publishes the
isolation (`ISO-1`), keeps probing, and does nothing else: no reboot, no reimage, no deploy rollback, no
interface teardown it was not asked for.

Why: a network layer that reboots on its own judgement destroys the evidence of the fault underneath it, and the
reboot becomes the story — the shape of the outage above, where an unattended self-heal fired on a symptom while
the cause went unexamined. Reboot, reimage and console are a DEPLOY concern: different blast radius, different
owner.

Not: no lifeline that power-cycles a host on overlay loss. Such a mechanism consumes nixnet's health document;
it never lives inside nixnet.

### OWN-3 — a watchdog restarts one named unit, rate-limited, and says why
**GIVEN** a watched daemon unhealthy for `driftFailureThreshold` consecutive checks, last restart older than
`minRestartIntervalSec`, **THEN** nixnet restarts THAT unit, logs the reason, and holds the subject degraded
until a healthy check.

Why: the failure class is "process alive, connection wedged" — `Restart=on-failure` never fires for it. The rate
limit and startup grace are not tuning: without them a slow boot restarts a healthy daemon forever, a
self-inflicted outage dressed as self-healing.

Not: a watchdog never re-enrols an identity as a first response. Re-keying an already-enrolled overlay peer
mints a NEW peer object and orphans the original with its advertised routes — that happened in production. Plain
reattach first; destructive re-enrolment only after it fails.

## Addressing facts — the declaration everything derives from
### ADDR-1 — how a host gets its address is declared, per interface, per family
**GIVEN** an interface name appearing anywhere in a nixnet declaration — firewall rule, probe, uplink, overlay,
publisher — **THEN** evaluation fails unless it exists in `nixnet.interfaces` with `addressing.v4` and
`addressing.v6` set (`static`/`dhcp`/`slaac`/`none`/`unmanaged`).

Why: this is the fact the firewall could not see. It also kills the typo class: a misspelled interface in a rule
matches nothing and fails open silently, whereas here it fails on the build host. `unmanaged` is a real answer,
so "nobody said" and "somebody said not mine" stop being one state.

Not: nixnet does not configure addressing — no DHCP client, no address assignment, no link bring-up. It records
how addressing HAPPENS so everything downstream derives from it.

### ADDR-2 — probes on a dynamically-addressed interface must name their own target
**GIVEN** an uplink transport whose address is unknown at evaluation time, **THEN** evaluation fails unless it
sets `probe.target`, or uses `probe.method = "exec"`, which supplies its own.

Why: a probe defaulting to "this transport's address" has nothing to default to when the address arrives at
runtime. Left implicit it probes an empty target and fails closed forever, which reads identically to a
genuinely dead uplink.

Not: the target is not resolved at evaluation time. It may be a name, resolved per tick; a resolution failure is
an ordinary counted probe failure, not a crash.

### ADDR-3 — declared addressing that disagrees with the kernel is reported, never corrected
**GIVEN** an interface declared static `192.0.2.10/24` while the kernel holds a different address or none,
**THEN** the `addressing` subject goes degraded within one reconcile interval, carrying both values.

Why: silent absorption is how a host ends up with a declaration nobody has believed for months. Reporting is
safe; correcting is not — rewriting an address underneath a running DHCP client or a foreign network manager is
a fight nixnet loses at the worst possible moment.

Not: no auto-repair in either direction. nixnet neither adds the declared address nor removes the live one.

## Firewall — one table, derived rules, and a failure you cannot miss
### FW-1 — a default-deny ruleset with no way back in fails at evaluation
**GIVEN** a default-deny input policy with neither `management.interfaces` nor `trustedInterfaces` set, **THEN**
evaluation fails on the build host, naming the missing option.

Why: the dangerous firewall configurations are all VALID — they build, activate, report success, and strand a
machine reachable only over the interface nobody named. Nobody forgets to allow ssh; what happens is that the
way you actually reach the host is not in the range you allowed, and you do not notice because you tested from
the LAN. The near-miss here was exactly that.

Not: never a runtime check. A check that runs on the far end of the ssh session that is about to close is worth
nothing.

### FW-2 — nixnet owns exactly one table and never flushes another
**GIVEN** other tools (container runtimes, the overlay client, a hypervisor) holding their own nftables tables,
**THEN** applying, re-applying or removing nixnet's ruleset leaves every one of them byte-identical, and every
rule any nixnet module contributes lands in nixnet's one table.

Why: `flush ruleset` on re-apply silently deletes container and guest networking, and the outage reads as an
application fault. The second half matters as much: confinement rules used to live in an iptables-only escape
hatch and a module-private table, which is how a deny rule ended up somewhere it could silently not exist at
all.

Not: no egress filtering, and no forward chain unless asked. Any base chain's drop is final across all tables,
so an unrequested drop-policy forward chain overrides ACCEPTs another tool wrote in its own table.

### FW-3 — a failed apply is loud, and never a host with no firewall
**GIVEN** a ruleset that fails to load for any reason — syntax, unsupported match, missing module — **THEN** the
apply unit exits non-zero; the previous ruleset stays in force because the load is one transaction; the
`firewall` subject goes RED carrying the loader's stderr; and a finished apply unit with no nixnet table present
is itself a unit failure.

Why: **the load-bearing entry of this document.** The current code renders text, calls the loader and swallows
the result — a production host is running with no packet filter at all right now, found from a serial console
rather than from any signal the host emitted. An unapplied firewall must be indistinguishable from a crashed
one: same failed unit, same red subject, still red next reconcile.

Not: nixnet does NOT install a panic default-drop ruleset on failure. Dropping everything on a host reachable
only over the network turns a firewall bug into a lost machine.

### FW-4 — a foreign flush is detected and repaired within one reconcile interval
**GIVEN** something outside nixnet issuing `flush ruleset`, **THEN** nixnet's table is back within one reconcile
interval, logged as a repair rather than as routine.

Why: ordering against the two units this repo happens to know about covers only hosts running exactly those two.
A container CNI, an overlay client's reset path or a hand-run command removes the confinement rules with no
error, and nothing restores them until the next deploy. Presence of a table is checkable; checking beats
enumerating everyone who might flush it.

Also: a green unit is not evidence. The apply unit is a `Type=oneshot` with `RemainAfterExit`, so it reports
`active (exited)` for the rest of the boot regardless of what happens to the table afterwards — measured on a
public production host that had no packet filter at all while every systemd answer said success. The reconcile
loop is what makes the claim present-tense, and `nixnet_firewall_enforced` is where it is readable.

Not: nixnet does not detect that another table changed. It asserts its own table's presence and generation,
via an empty unhooked chain named for the ruleset hash — which distinguishes a deleted table, an emptied one
and a FOREIGN one (a rollback that reloaded older rules) without text-comparing against `nft list`'s rendering.

Not: it does not repair a ruleset the dead-man switch deliberately replaced. That is the one case where the
correct action is to leave the host as it is and go red — repairing would reload the rules that just locked an
operator out, once per interval, forever. `nixnet-firewall-confirm` is the way back.

### FW-5 — the dead-man switch never reverts INTO an unfirewalled host
**GIVEN** an apply with no previous ruleset to restore — a host's first, or its first after a reimage —
**THEN** the auto-revert timer does not arm, and the host is still firewalled after the confirmation window
would have expired. **GIVEN** a reboot with a ruleset byte-identical to the last one applied, likewise.

Why: both halves are the same production failure, found twice because the first fix was too narrow. Arming
every boot meant the timer fired on every headless boot, nobody typed the confirmation, and the revert — with
no prior table to restore — deleted the firewall outright. Narrowing to "arm only on a CHANGE" left the hole
open, because a host's FIRST ruleset is by definition a change: on 2026-08-04 that put a public host, the
overlay control plane, on the open internet with no packet filter, unit green. A revert whose restore file
says only `add table; delete table` is not a recovery from a bad ruleset — it is a worse outcome than the
ruleset, and a firewall that is merely WRONG beats one that is ABSENT.

Not: this is not remote-lockout protection for an unattended deploy. That is the deploy layer's rollback,
which reverts the whole generation rather than one table; conflating the two produced both bugs above. A host
deployed with no human in the loop should turn this off and rely on that.

Also: a revert that FAILS keeps its snapshot and leaves the reconcile loop enabled. Discarding the only copy
of the previous ruleset and standing the repair loop down, on the strength of a command whose exit status
nobody read, retires both safety nets at once.

### FW-6 — a host that enforces a ruleset can read it
**GIVEN** a host where `nixnet.firewall` or `nixnet.overlay` is enabled, on a backend that has nftables, **THEN**
`nft` is installed on that host; **GIVEN** a backend that does not have it — nix-darwin, where the kernel filters
with pf — **THEN** evaluation SAYS the selection is unsatisfiable instead of installing nothing.

Why: found in production. A host was enforcing a nixnet-authored `inet` table with no `nft` on it anywhere.
Nothing failed and nothing warned, because applying a ruleset never needs the binary — it loads from a store
path. Every question about the ruleset needs it, and the answer mid-incident was to fetch nftables over the
network the firewall is a candidate cause of having lost. Enforcing a policy you cannot read is the same
blindness `FW-3` names from the other side: there, the host could not tell you the apply failed; here, it cannot
tell you what it applied.

Not: not a diagnostic toolbox. One tool, the one that reads the thing this repo wrote, selected by name and
removable with `tooling = [ ]` on a host whose distro already ships it. And never a substitute for the rendered
`ruleset` option — that is readable from the build host, which is where you look when the host is unreachable.

## Private dual-stack transit
### WG-1 — only a declared WireGuard listener opens a public port
**GIVEN** a WireGuard transit peer with no `listenPort`, **THEN** NixNet adds no firewall accept. **GIVEN** a peer
with both `listenPort` and `openFirewall`, **THEN** only that UDP port is accepted by NixNet's host policy.

Why: the encrypted peer network must not create an accidental public service. A client only needs an outbound
packet; the hub is the one deliberate public listener.

Not: this is not address translation, public port forwarding, or a second overlay control plane.

### WG-2 — an authenticated private IPv4 and IPv6 transit routes both ways
**GIVEN** two peers with private IPv4 and IPv6 addresses on a WireGuard hub, **THEN** each can reach the other in
both families through the hub. The hub forwards only its declared tunnel interface pair, and each peer's
`AllowedIPs` remains the source-address authority.

Why: an IPv4-only origin can reach an IPv6-only public host over a private IPv4 tunnel address, without exposing
the service publicly or introducing stateful address translation.

Not: the hub never allocates public addresses, NATs the tunnel, or grants forwarding to another interface.

## Transport failover — winners, publication, demotion
### TF-1 — the winner is deterministic and damped
**GIVEN** a subject with N priority-ordered transports in mixed health, **THEN** the winner is the lowest
`priority` among currently-Up transports, ties broken by declaration order, unchanged again until
`hysteresis.minHoldMs` has elapsed since the last change.

Why: without a total order, two equally-ranked healthy transports alternate on probe jitter alone, and every
alternation is a published change — a rewritten hosts file, a rewritten route. The hold window turns a flapping
link into a slow link instead of into churn.

Not: hysteresis never delays a change AWAY from a failed winner. Damping applies to upgrades, not escapes;
holding a dead winner for the window's sake is the failure the window prevents, inverted.

### TF-2 — publication happens on reconcile, not only on winner change
**GIVEN** a host whose winner has not changed since boot — a single-uplink host, a settled fleet — **THEN**
every reconcile tick compares published state against live state and re-applies on any difference, logging the
re-assert.

Why: the defect that made half this project fiction. Publication was emitted only inside the winner-change
branch, so a single-uplink host never published at all: metric 600 declared, metric 100 live, zero publish log
lines in the deployment's entire history. Publication is reconciliation against observed reality — a
transition-driven publisher is correct exactly until something else changes the world behind its back, which is
always.

Not: reconcile is not a rewrite. Identical state produces no write, no log line, no transaction — otherwise the
fix trades a silent no-op for constant churn.

### TF-3 — the loser is demoted in the same transaction that promotes the winner
**GIVEN** a winner change between two uplinks, **THEN** afterwards the new winner's route metric is strictly
lower than the ex-winner's, and no two of the subject's transports share a metric.

Why: the current publisher only re-metrics candidates it can verify as Up, so the transport that just FAILED
keeps the metric it had — both at the base value, tied. The kernel then picks between two equal-cost defaults,
possibly the dead one. Demoting the loser is not a detail of metric failover; it is the entirety of it.

Not: nixnet does not delete the loser's route. Deleting a default a foreign DHCP client installed puts the host
one renew away from a fight nixnet loses.

### TF-4 — the kernel is driven through netlink, never through a shelled-out command
**GIVEN** a route publication, **THEN** it is one netlink transaction, needs no external binary at runtime, and
on failure reports the kernel's error verbatim, fails the tick and reddens the subject rather than being
discarded.

Why: metric is part of a route's identity, so a text-mode `replace` at the wrong metric ADDS a second default
instead of replacing one, and a replace omitting the gateway rewrites a DHCP-supplied default into an unusable
on-link route. At netlink level that identity is explicit, and the ordering — install before delete, never
delete if install failed — becomes checkable rather than incidental.

Not: nixnet does not take ownership of the routing table. It rewrites metrics of defaults on interfaces it was
told about; every other route is untouched.

### TF-5 — when everything is down, the subject is red under either policy
**GIVEN** every transport of a subject down, **THEN** the subject is RED and the published value follows the
declared `onAllDown`: `unpublish` (remove the entry, let resolution fall through) or `lastKnownGood` (keep the
last winner, bounded by `STALE-2`).

Why: stale answer versus no answer is genuinely the operator's call — a soft-mounted filesystem prefers a stale
address to an immediate failure, a discovery path prefers the failure. What is not their call is whether the
state is visible: both policies are the same shade of red.

Not: `lastKnownGood` is not "healthy with an old address". A consumer reading only the value gets the old
address on purpose; one reading the health document cannot mistake it for current.

### TF-6 — transport state is restored by identity, not by list position
**GIVEN** persisted state and a config in which a transport was added, removed or reordered, **THEN** state is
matched by stable transport id, unmatched persisted entries are discarded with a log line, and unmatched config
entries start cold.

Why: positional restore means inserting one transport at the top of a list silently transplants its neighbour's
up/down counters and last-known-good address onto it, with nothing logged — a silent-corruption shape in the
exact structure that decides which address a host publishes.

Not: a cold start is not a failure. A transport with no restored state runs its thresholds from zero, costs one
detection interval, and cannot be wrong.

## Publication — one writer, one file
### PUB-1 — the daemon owns the published hosts file; activation never rewrites it
**GIVEN** a system activation while the daemon is running, **THEN** the file's content is unchanged by the
activation, every name the daemon had published still resolves immediately afterwards, and any entry written
outside nixnet's markers survives every later publication.

Why: two writers, no handshake, and the root-side writer wins. Activation seeds entries keyed by the peer's Nix
ATTRIBUTE NAME while the daemon publishes the declared `hostnames` aliases, so every switch reverted the
daemon's block and every alias went NXDOMAIN — until a winner change that, on a settled fleet, never comes.
Foreign entries die the same way: the daemon snapshots the non-managed prefix once at start and replays it
forever, deleting anything added later.

Not: activation may still create the file when absent (`PUB-2`) and may write a SEPARATE seed file. Creating is
not rewriting.

### PUB-2 — the seed is a floor for first boot, consulted only when it must be
**GIVEN** a first-ever activation, before the daemon has ever run, **THEN** declared peers resolve through the
seed, the hosts path is a real non-dangling file, and the first daemon publication supersedes it with no
intervening NXDOMAIN window.

Why: the foreign-distro activation engine canonicalises every `/etc` symlink, and one dangling target aborts
collection of the ENTIRE `/etc` list — meaning no `/etc` at all, so the daemon's own unit is never even written.
The seed makes that impossible: created-if-absent, otherwise read as declared input.

Not: the seed is not a fallback for a running daemon. If the daemon is up, its publication is authoritative even
when it publishes nothing.

## Isolation — say which layer, decide nothing
### ISO-1 — isolation is classified per layer, independently, and published
**GIVEN** a host that reaches its default gateway but whose resolver returns nothing, **THEN** the `l3` subject
is green and the `dns` subject is red — and symmetrically for every other combination of L3 / DNS / overlay.

Why: "the network is down" is not a diagnosis, and the outage above is what happens when every symptom lands at
the same layer. Three independent probes give three independent answers, and the SHAPE of the answer names the
fault class before anyone reads a log.

Not: nixnet never classifies the CAUSE and never acts on the classification, which triggers nothing beyond
`TF-2`, `FW-4` and `OWN-3`. There is deliberately no hook to attach remediation to: the tempting code is three
lines long, reads as obviously correct ("everything is down, bounce the interface"), and converts a diagnosable
outage into an undiagnosable one.

## Staleness — freshness is data, not an absence
### STALE-1 — everything published carries when it was last confirmed
**GIVEN** any published artifact — hosts block, health document, status file — **THEN** each entry carries the
timestamp of the last successful probe that confirmed it and of the write, so a consumer can compute its age
without knowing nixnet's cadence.

Why: a value with no age is indistinguishable from a current one, which is how an address dead for eleven days
kept being served as if it were fine. Age is not a debugging nicety; it is half the value.

Not: nixnet does not decide what age is too old for a consumer. It publishes the number; the tolerance is the
consumer's.

### STALE-2 — last-known-good expires, including when restored from disk
**GIVEN** `onAllDown = "lastKnownGood"` and a winner down continuously longer than `lastKnownGood.maxAgeSec` —
whether that time elapsed live or across a restart that restored it from disk — **THEN** the entry is withdrawn,
logged once with its age, and the subject stays red.

Why: unbounded last-known-good is not a trade-off, it is a leak. One peer here has been published continuously
for eleven days across roughly 48,000 consecutive probe failures, marked degraded and still resolving for anyone
who asks; restore-at-start has no age check either, which is how it survived every restart that might have
cleared it.

Not: an unreadable state file is not an error — it is a logged cold start. A corrupt state file must never
crash-loop the layer that makes the host reachable.

## The estate seam — health for an aggregator
### HEALTH-1 — one subject per domain, with state, since, and checked-at
**GIVEN** a running nixnet, **THEN** it writes a health document with exactly one subject per domain it owns
(`addressing`, `firewall`, `uplink`, `peers`, `overlay`, `dns`, `ingress`), each with a state, when it entered
that state, when it was last checked, and a detail string.

Why: an aggregator that must understand nixnet's internals to render a colour breaks on every refactor. One
subject per domain is the coarsest granularity that still says which of nixnet's jobs is failing; specifics go
in the detail string.

Not: this is not per-transport telemetry. Individual transport states stay in the status file for the CLI.

### HEALTH-2 — silence reads as red without anyone alive to say so
**GIVEN** nixnet stopped, crashed, or never started, **THEN** the health document is absent or its `validUntil`
is in the past, and a conforming aggregator renders every subject RED.

Why: the default failure mode of every health mechanism is that the reporter dies and the last green reading
sits on a dashboard forever. `validUntil` inverts the burden: freshness is asserted by the document with an
expiry, so staleness is decidable by the reader alone. On this estate a two-week silent outage went unnoticed
because the thing that would have alerted was part of it.

Not: nixnet does not push, retry or alert. It writes a document with an expiry; delivery and escalation belong
to the aggregator.

### HEALTH-3 — subjects fail independently; green means every subject green AND fresh
**GIVEN** a failed firewall apply while every probe is healthy, **THEN** the `firewall` subject is red, the
others are green, and the aggregate is red.

Why: the point of splitting subjects is that a healthy daemon must not vouch for a component it did not check.
"The daemon is up, therefore everything is fine" is what let a host run unfirewalled while reporting nothing at
all.

Not: the document carries no aggregate field. The reader computes it from the subjects, so a reader that does
not know about a subject added later cannot report green for it.

## Test obligation
### TEST-1 — every behaviour id in this file has a VM test
**GIVEN** this file declaring a behaviour id, **THEN** the flake exposes a check of the same name, and CI fails
on any id present here and absent there, or the reverse.

Why: all three of the sharpest bugs in this repo's history came from production, on the layer where a bug means
the machine is unreachable and therefore unfixable remotely — and this repo has zero VM tests. A behaviour
contract with no mechanical link to a test is a wish list; the id set is that link, and it is cheap because both
sides are already text.

Not: unit tests do not satisfy this. A rendered-ruleset string comparison passes for a rule that loads and
matches nothing.

### TEST-2 — reachability behaviours are tested by reaching, from a second machine
**GIVEN** a behaviour whose failure mode is "the host becomes unreachable", **THEN** its test runs a
multi-machine VM network and asserts reachability from the OTHER node, over the interface the behaviour
concerns, after the change is applied — including a DHCP-addressed node held past lease expiry on a deliberately
short lease, which must keep its address.

Why: the DHCP case is the specification, and it is subtler than it first looks. The obvious test is vacuous —
the initial handshake goes out over a raw socket that never traverses the filter, so a host comes up addressed
whatever the ruleset says. The second-obvious test is ALSO vacuous: waiting out a lease proves nothing either,
because conntrack admits the unicast renew's reply and both common clients fall back to AF_PACKET when pushed
onto the broadcast leg. Measured: 13 of 13 replies hit the policy drop and the lease renewed anyway. So the test
asserts the PACKET VERDICT — observer chains straddling nixnet's input chain — rather than an address the host
would have kept regardless.

Not: the code under test is never handed a stub for the kernel interface it is tested against. A route test
whose route command is a no-op binary tests the test.

## OPEN QUESTIONS
Open, not deferred. Each blocks a default, not a behaviour.

1. **Uplink metric band.** The default base is exactly the metric DHCP clients assign, so nixnet's route and the
   OS's are indistinguishable by metric, and no survey says what "high enough" is on a given host. Also
   unresolved: whether metric rewriting is the right mechanism at all, versus a dedicated routing table plus a
   policy rule — which would end the fight with foreign network managers instead of ranking within it.

2. **`lastKnownGood.maxAgeSec` default.** `STALE-2` requires a finite bound; nothing measured justifies a value.
   The only number in the existing deployment is described as matching a soft-mount's retry tolerance, which is
   a claim with no number behind it.

3. **Whether a failing probe's reported address may be published.** An exec probe can report a freshly
   re-enrolled address on the same tick it reports unhealthy. Trusting it converges one tick sooner; distrusting
   it keeps a failing prober's output out of the hosts file. No evidence either way.

4. **Foreign-flush cadence.** The mechanism is settled — poll every `reconcile.intervalSec` (60s) for a
   generation-marker chain. What is not settled: whether `nft monitor`'s change notification is reliable enough
   to replace polling, and how fast a flush must be repaired before the gap matters. 60 seconds is a guess with
   no measurement behind it, chosen because it is cheap, not because anything said it was enough.

5. **Who owns overlay self-heal where an independent lifeline watchdog also exists.** One such watchdog exists
   precisely because nixnet's reprovisioning has a dependency that host cannot satisfy. Two mechanisms with
   authority over the same thing is the condition `OWN-2` and `ISO-1` exist to prevent; the resolution is a
   policy decision, not a code one.

6. **Whether the NSS ordering guard is needed at all.** It exists because a resolver short-circuiting ahead of
   the `files` source made a correct hosts file unreadable. But the host it was written for sits in the
   documented-fatal order today and resolves correctly anyway, because that resolver parses the hosts file
   itself. The premise may be wrong, version-dependent, or true only when a search domain is pushed — re-derive
   before porting, and make it backend-symmetric.

7. **ICMPv6.** The ICMP prober is IPv4-only and fails closed on a v6-only target with a message that reads like
   unreachability; a v6-only peer is reachable today only because it is probed over the overlay. Implement
   ICMPv6, or make `method = "icmp"` a hard eval error against a v6-only target — silently failing closed is not
   an option either way.

8. **Health document transport.** `HEALTH-2` specifies a document with an expiry and no delivery. Whether the
   aggregator scrapes it over a local socket, reads it off a shared filesystem, or is handed it by the deploy
   layer is unresolved — and it decides whether "absent" is observable to the reader at all, which that entry
   currently assumes.
