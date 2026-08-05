# nixnet package surface

What nixnet should declare as PACKAGES, in three tiers, one row per candidate, from a live read of two NixOS backends and two Arch/system-manager backends.
Mark the last column `keep` / `kill` / `?`. Rows marked **[ASYM]** are the design problem: NixOS delivers the thing implicitly through a `services.<x>.enable` and Arch must name it, or the reverse.
Answer these three first:
**OQ-1** — `bpftune` auto-tunes network sysctls at runtime and is therefore a second writer of everything nixnet declares. In or out.
**OQ-2** — on Arch, does nixnet deliver a daemon as a nixpkgs build under system-manager, or PUBLISH a package name for someone else's reconciler? nixnet has no reconciler and must not grow one.
**OQ-3** — is inspection installed by DEFAULT (today `tooling` defaults to `[ "nft" ]`) or empty until asked for?

## TIER 1 — MECHANISM (makes the network work)

| # | what it is | why it is nixnet's | on NixOS | on Arch / system-manager | keep/kill/? |
|---|---|---|---|---|---|
| MECH-1 | overlay client (WireGuard mesh daemon) | nixnet already owns it: `overlay.nix:317` and `netbird-provider.nix:475` both set `services.netbird.enable = true` | **[ASYM]** IMPLICIT — the option installs package + unit + state dir. The binary is on no PATH and appears in no `systemPackages` anywhere | **[ASYM]** MUST BE NAMED — no `services.netbird` option exists under system-manager. Live Arch hosts run a distro/AUR build with the distro's unit | |
| MECH-2 | `nixnetd`, nixnet's own daemon | it is this repo | store path + module-written unit | store path + module-written unit — identical. No distro package, no catalogue entry needed | |
| MECH-3 | tunnel ingress client | `nixnet.ingress` wraps it at `ingress.nix:129` | **[ASYM]** IMPLICIT via `services.cloudflared`; binary absent from PATH on the host that runs it | **[ASYM]** would need a NAME plus a unit nixnet writes. No Arch host runs ingress today; the one Arch install of it has no unit at all | |
| MECH-4 | kernel WireGuard | the overlay's data plane | no package on either backend — in-tree kernel module | same | |
| MECH-5 | `systemd-networkd` | sole addressing owner on both NixOS hosts and on one Arch host; `nixnet.interfaces` already declares its facts | `networking.useNetworkd = true` — an option, never a package | a UNIT to enable, never a package (part of systemd). system-manager can write the unit | |
| MECH-6 | NetworkManager | addressing owner on the roaming Arch host; the alternative to MECH-5, and nixnet must own the CHOICE (see CONF-7) | `networking.networkmanager.enable` | NAMED package | |
| MECH-7 | Wi-Fi supplicant | MECH-6's radio backend | pulled in by the networkmanager option, never named | **[ASYM]** NAMED — but must NEVER be unit-enabled; NetworkManager D-Bus-activates it. Live state is `disabled / active`, which is correct | |
| MECH-8 | WWAN modem manager | second uplink on the roaming host; a transport `nixnet.uplinks` fails over to | `networking.modemmanager.enable` | NAMED. Drags ppp / libmbim / libqmi / provider-info as DEPS — never name those | |
| MECH-9 | nftables, as ruleset LOADER | `nixnet.firewall` and `nixnet.overlay` each apply a table | needs nothing on PATH: the apply script carries nftables in its own `runtimeInputs` from the store | already present transitively (base → iproute2 → iptables → nftables). Never declare. The CLI question is INSP-1, deliberately separate | |
| MECH-10 | iptables / iptables-nft | the compat backend one host is deliberately pinned to | `networking.firewall` (iptables) vs `networking.nftables.enable` — an option, not a package | ONE package. `iptables-nft` is a *provides* alias, not an installed package; declaring both lists one package twice | |
| MECH-11 | recursive resolver | serves split-horizon DNS for the estate; nixnet has NO option for it and references it nowhere | `services.unbound.enable` | NAMED | |
| MECH-12 | mDNS responder + NSS plugin | name resolution on the local link | `services.avahi.enable` (arrives from an imported flake module — declared in no consuming repo) | NAMED, but both have reverse deps in the print / audio / streaming domains and would arrive anyway. See CONF-1 | |
| MECH-13 | `bpftune` | runtime BPF auto-tuner of network sysctls — a SECOND writer of what nixnet declares | no option; would be package + unit | NAMED, explicitly installed, active. **OQ-1** | |
| MECH-14 | DHCP client | leases on every dynamically-addressed interface in `nixnet.interfaces` | networkd's built-in client | whichever addressing owner CONF-7 picks provides it. `dhcpcd` sits installed as a dep with zero reverse deps, inactive. Never declare a DHCP package | |

## TIER 2 — INSPECTION (lets you SEE what nixnet made the host do)

Enabling a daemon installs the daemon, never its diagnostic. This tier is the only one where a NixOS host is measurably WORSE off than an Arch host.

| # | what it is | why it is nixnet's | on NixOS | on Arch / system-manager | keep/kill/? |
|---|---|---|---|---|---|
| INSP-1 | `nft` | reads the tables `nixnet.firewall` / `nixnet.overlay` enforce. Already the sole entry in `lib/tooling.nix` | **[ASYM]** MUST BE NAMED — `pkgs.nftables`. No option supplies it; the apply script's `runtimeInputs` are store-internal. A live host enforced a nixnet table with no `nft` at all | **[ASYM]** ALREADY ON PATH via base. `tooling.nix` names `nftables` here too, which puts a SECOND nixpkgs copy ahead of the distro's — **OQ-4** | |
| INSP-2 | `conntrack` | reads the state table every `ct state` rule in the generated ruleset depends on | NAMED — `pkgs.conntrack-tools`. No option supplies it | NAMED — `conntrack-tools`. TRAP: the dep-pulled `libnetfilter_conntrack` is a LIBRARY, not the CLI | |
| INSP-3 | `wg` | the ONLY way to read handshake age, endpoint and rx/tx of the kernel WireGuard link MECH-1 runs on. Absent on every host today | NAMED — `pkgs.wireguard-tools`. The overlay option does not supply it | NAMED — `wireguard-tools` | |
| INSP-4 | `dig` / `host` | query a SPECIFIC resolver — the only way to test split horizon or the overlay's own resolver | NAMED — `pkgs.dnsutils`: query tools, NO server binary | **[ASYM]** NAMED — `bind`, the full DNS-server package, is the sole provider of `dig`; there is no `bind-tools` split, so the authoritative server binary and its config ride in. See **OQ-6** | |
| INSP-5 | `tcpdump` | capture on an interface `nixnet.interfaces` names | NAMED | NAMED | |
| INSP-6 | `ethtool` | link / driver / ring state for an interface nixnet declares addressing for | NAMED | NAMED | |
| INSP-7 | `mtr` | per-hop loss on an uplink `nixnet.uplinks` is failing over between. Absent everywhere | NAMED | NAMED | |
| INSP-8 | `traceroute` | same concern as INSP-7, strictly less capable — pick one, not both | NAMED | NAMED | |
| INSP-9 | `iproute2` (`ip` / `ss` / `bridge` / `tc`) | the primary read surface for everything nixnet writes | NEVER DECLARE — in the default system path | NEVER DECLARE — `base` dep | |
| INSP-10 | `ping` / `arping` / `tracepath` | liveness of a peer nixnet publishes | NEVER DECLARE — base system | NEVER DECLARE — `base` dep | |
| INSP-11 | overlay `status` / `nixnetctl` | the daemons' own state readers | arrives with its daemon | arrives with its daemon | |
| INSP-12 | `socat` | reachability probe with an arbitrary payload, where `nc` will not do | NAMED | NAMED. The dep-pulled netcat belongs to another domain and must not be relied on | |
| INSP-13 | `iperf3` | throughput — a MEASUREMENT, not a read of nixnet state | NAMED | NAMED | |
| INSP-14 | `nmap` | scans OTHER hosts' state, not this host's. Installed explicitly on one Arch host, unused | NAMED | NAMED | |
| INSP-15 | `tshark` | a heavier INSP-5 with a decode engine | NAMED | NAMED | |

## TIER 3 — FRONTEND (a human clicks it) — DECLARED EMPTY

Kept as rows so the tier is ANSWERED rather than absent. Every NixOS host in scope is headless; the tier is empty there by construction.

| # | what it is | why it is not nixnet's | on NixOS | on Arch / system-manager | keep/kill/? |
|---|---|---|---|---|---|
| FE-1 | overlay tray GUI | duplicates the CLI's job; the daemon runs headless and the GUI's only reverse-dep relationship makes the TRAY the root and the DAEMON a leaf, inverting the dependency an automated pass would infer | no package | installed on one Arch host, not running | |
| FE-2 | GUI packet viewer (`sniffnet`) | a person's tool for INSP-5's job | no package | explicitly installed on BOTH Arch hosts | |
| FE-3 | NM applet + VPN plugin GUIs | frontends to MECH-6, already rejected once | no package | installed, unused | |
| FE-4 | overlay control-plane web dashboard | server-side MECHANISM on the control-plane host, not a frontend — the row exists so it is not mis-tiered into this table | `services.*` on that host only | n/a | |
| FE-5 | any GUI at all | the tier exists to be declared empty, not omitted | zero displays | out of scope for a network domain | |

## CONFLICTS — two owners, one job

| # | the job | owner A (live) | owner B | evidence | recommended single owner | ok/? |
|---|---|---|---|---|---|---|
| CONF-1 | mDNS response | avahi-daemon | systemd-resolved `+mDNS` | both bound to `0.0.0.0:5353` and `[::]:5353` on a NixOS host AND on an Arch host; `+mDNS` set Global and per-link on ~10 links | avahi where discovery is actually used; resolved's mDNS off. nixnet ASSERTS the single owner, installs neither | |
| CONF-2 | LLMNR | systemd-resolved | nothing | resolved holds `:5355` v4+v6 on every link; no consumer exists | off. A third name-resolution protocol nobody chose | |
| CONF-3 | recursive DNS | LAN recursor on the host address | resolved stub + the overlay client's embedded resolver | THREE `:53` listeners on one host; the overlay resolver reports `Nameservers: 0/0 Available`; the recursor runs with `resolveLocalQueries = false` so the split is deliberate for two of the three | recursor owns LAN, resolved's stub owns local clients, the overlay resolver is CONFIGURED or DISABLED — today it is neither | |
| CONF-4 | packet filtering | the distro firewall module (one host) | `nixnet.firewall` + its own unit (two hosts) | `networking.firewall.enable = mkForce false` on the nixnet hosts; `nixnet.firewall` reads `networking.firewall.*` NOT AT ALL, so every `openFirewall = true` in the tree is silently inert there | `nixnet.firewall`, plus an assertion that fails when both are enabled and a documented import path for `openFirewall` | |
| CONF-5 | the nftables ruleset | nixnet's / nixfw's `inet` tables | the overlay client's own `ip`/`ip6` tables, libvirt's, and the iptables-nft compat set | FOUR independent writers in one ruleset on an Arch host, THREE on a NixOS host; same-priority hook order is registration order and is declared nowhere (livehack FW-4) | nixnet declares the priority band it owns and asserts no foreign table shares it | |
| CONF-6 | loading `/etc/nftables.conf` | the system-manager reapply unit (active, and the one that actually loaded the table) | the distro's stock nftables unit (enabled, dead) | two ENABLED units with the same input file | the declarative reapply unit; mask the distro one | |
| CONF-7 | link + addressing | networkd (two hosts) / NetworkManager (one host) | `netctl`, installed, `Required By: None`, never enabled | two live implementations across four hosts, plus one dead third on the same box as NetworkManager | `nixnet.interfaces` names the owner per host and asserts exactly one is enabled | |
| CONF-8 | Wi-Fi association | wpa_supplicant, D-Bus-activated by NetworkManager | `iwd`, installed, `Required By: None`, inactive | NetworkManager has no backend override configured, so the second install is inert | wpa_supplicant. Never unit-enable it | |
| CONF-9 | network sysctls | `bpftune` at runtime | anything nixnet declares statically | bpftune is active with no config file and no reverse deps; last writer wins, non-deterministically | **OQ-1** | |
| CONF-10 | `/etc/resolv.conf` | a hand-edited stock file (authoritative) | networkd `DNS=` lines (INERT — resolved is masked on that host) | two declarations, one effective, no link between them | one writer. If resolved is masked, nixnet writes the file | |
| CONF-11 | the iptables package name | one real package | its `provides` alias | `pacman -Qi <alias>` answering is a provides artifact, not an install | the catalogue stores real package names only, never aliases | |
| CONF-12 | DHCP leases | the addressing owner's internal client | a standalone client, dep-installed, zero reverse deps, inactive | the live default route carries `proto dhcp` from the addressing owner, not from the standalone client | whatever CONF-7 picks | |
| CONF-13 | the overlay daemon's identity on Arch | the distro/AUR build + the distro's unit (live) | a nixpkgs build under system-manager + a nixnet-written unit | `tooling.nix`'s `system-manager` branch already chooses "a nixpkgs build on PATH" for INSPECTION; extending that to a DAEMON also moves its unit, state dir and enrollment identity | **OQ-2** | |

## PATTERN — which sibling to copy

Adopt **nixaudio's entry shape**, not nixdev's flat table and not nixdesktop's roles.

NAMES, not roles: nixnet's own option surface already names each mechanism (`nixnet.overlay`, `nixnet.ingress`, `nixnet.firewall`, `nixnet.meshGateway`). There is no interchangeable-implementation slot anywhere in it — no `overlay.implementation = "a" | "b"` — so role indirection buys nothing and hides which daemon owns a job. NAMES, not capabilities either: nixdesktop's own comments record that a bare capability fails exactly where an implicit option is the real mechanism, which is this repo's whole difficulty.

What nixaudio adds and nixnet needs is the `nixosOption` field plus its **anti-shadowing invariant**: exactly one of `nixpkgs` / `nixosOption`, never both, asserted and covered by a fixture. That is MECH-1 precisely — `services.netbird.enable` already installs the daemon, so naming a package beside it yields two closures and an ambiguity about which binary the units point at.

Keep `backendOf` and keep `null` meaning "unsatisfiable here". Add a `tier` field so `resolve` can refuse to install a frontend.

## OPEN QUESTIONS

- **OQ-1 — `bpftune`.** A second writer of every network sysctl nixnet declares, with no config file, no reverse deps, and no NixOS option. Either nixnet owns it (and derives its allowed scope from `nixnet.interfaces`) or it goes. There is no "both" that is deterministic. Blocks MECH-13 and CONF-9.
- **OQ-2 — Arch mechanism delivery.** `tooling.nix` says system-manager gets a nixpkgs build on PATH, and its comment is explicit that system-manager drives no package manager. That is sound for a CLI. For a DAEMON it also relocates the unit, the state directory and the overlay enrollment identity. The alternative is nixdev's model: PUBLISH a read-only `archPackages` list and let a reconciler in another repo install it — which keeps nixnet usable by people who run no such reconciler. Blocks every `[ASYM]` mechanism row.
- **OQ-3 — inspection default.** `tooling` currently defaults to `[ "nft" ]`, i.e. nixnet installs a package nobody asked for. Is the default the full inspection set, `nft` only, or empty?
- **OQ-4 — INSP-1 shadows the distro binary.** On Arch, `nft` is already on PATH via `base`. Naming `nftables` for the system-manager backend installs a second copy and PATH order decides which one an operator gets — the same shadowing hazard the invariant in the PATTERN section exists to prevent, one layer down.
- **OQ-5 — is DNS SERVING in scope?** nixnet owns a hosts-file publisher and a resolver-shaped conflict (CONF-3) but has no resolver option at all. Either MECH-11/MECH-12 are in the domain, or nixnet asserts single ownership over daemons it does not install — a shape it uses nowhere today.
- **OQ-6 — INSP-4's Arch name is contested.** Two independent reads disagreed on whether a query-tools-only package exists on Arch; the verified read says it does not, and that `dig` comes only from the full server package. Confirm before the catalogue names it, because the answer decides whether INSP-4 is `[ASYM]` or ordinary.
- **OQ-7 — does TIER 3 exist in the model?** Declared-empty (a `tier = "frontend"` that `resolve` refuses) documents the decision; omitting it entirely is smaller. The first costs a field, the second makes "why is there no GUI entry" unanswerable from the source.
- **OQ-8 — assert-without-installing.** CONF-1, CONF-6, CONF-7, CONF-8 and CONF-12 all want nixnet to fail an evaluation over a daemon it does not own or install. Is that in nixnet's remit, or does it stop at the boundary of what it declares?
