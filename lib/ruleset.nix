# lib/ruleset.nix — the nftables ruleset GENERATOR for `nixnet.firewall`. Pure: declared values in,
# lines of nftables text out. No `pkgs`, no paths, nothing that can only be evaluated on the host
# that will load it.
#
# Kept out of modules/firewall.nix on purpose: the module carries TWO delivery planes (NixOS hands
# this text to `networking.nftables`; system-manager writes it to /etc and re-applies it from a
# unit) and both must apply byte-identical RULES. If generation lived in either plane the two would
# drift, and firewall drift is the kind you discover from the wrong side of a closed port.
#
# Every generator here returns a LIST OF LINES, unindented. Indentation is the renderer's job, so a
# generator can never be the reason a rule lands in the wrong chain body.
{ lib }:
let
  inherit (lib) concatStringsSep optionalString;

  # nftables set syntax for a list: `{ a, b }` for many, a bare literal for one. Writing `{ 22 }` is
  # legal but an anonymous set costs a lookup where a constant would do, and it reads worse in
  # `nft list ruleset` output, which is what anyone debugging this will actually be reading.
  set = xs: if builtins.length xs == 1 then builtins.head xs else "{ ${concatStringsSep ", " xs} }";

  # Discrete ports and ranges share one set — nftables mixes `22, 100-200` freely inside a single
  # `{ }`, and a rule with exactly one spec total (one port, or one bare range) renders without
  # braces via `set` above.
  portsOf = r: set (
    (map toString r.ports)
    ++ (map (pr: "${toString pr.from}-${toString pr.to}") r.portRanges)
  );

  # Aligned block size -> prefix length. Only the nine sizes a /24's host part can hold, because
  # that is the only shape `octetRangeToCidrs` below can be asked for.
  prefixLenOf = {
    "1" = 32;
    "2" = 31;
    "4" = 30;
    "8" = 29;
    "16" = 28;
    "32" = 27;
    "64" = 26;
    "128" = 25;
    "256" = 24;
  };

  # Biggest power-of-two block that starts ON `start`'s own alignment and still fits in `remaining`.
  largestBlock = start: remaining:
    lib.foldl'
      (acc: size: if size <= remaining && lib.mod start size == 0 then size else acc)
      1
      [ 1 2 4 8 16 32 64 128 256 ];

in
rec {
  inherit set portsOf;

  # A declared last-octet band [min,max] inside a /24 -> the minimal list of CIDRs covering EXACTLY
  # it, no more and no less.
  #
  # This exists so a trust boundary is declared once. The octet band ("peers .0-.15 are the
  # least-trust group") is already stated where group membership is reconciled from it; restating
  # the same boundary a second time as a hand-written prefix is how the two quietly stop matching —
  # and the direction that fails silently is the dangerous one: a confinement prefix that is
  # NARROWER than the band leaves the peers outside it unconfined, with every rule still present
  # and every `nft list ruleset` still looking correct.
  #
  # Exact, not approximate: an unaligned band renders as several CIDRs (3-9 -> .3/32, .4/30, .8/31)
  # rather than being rounded out to a prefix that would swallow addresses the operator never put
  # in that band.
  octetRangeToCidrs = base: min: max:
    let
      go = start:
        if start > max then [ ]
        else
          let block = largestBlock start (max - start + 1);
          in [ "${base}.${toString start}/${toString prefixLenOf.${toString block}}" ]
            ++ go (start + block);
    in
    go min;

  # One accept rule, as one line per source prefix. Order of matchers is deliberate: cheapest
  # discriminator first (interface, then source, then protocol/port) so the common reject path
  # exits early.
  ruleLines = r:
    let
      iif = optionalString (r.interface != null) "iifname \"${r.interface}\" ";
      # v4 and v6 sources need different matchers, so a rule carrying both emits two lines.
      srcs =
        (map (s: "ip saddr ${s} ") r.sourcesV4)
        ++ (map (s: "ip6 saddr ${s} ") r.sourcesV6);
      src = if srcs == [ ] then [ "" ] else srcs;
      comment = optionalString (r.comment != "") "  # ${r.comment}";
    in
    map (s: "${iif}${s}${r.protocol} dport ${portsOf r} accept${comment}") src;

  # THE ANTI-LOCKOUT RULE. Emitted before any host rule, and unconditionally.
  #
  # This is the whole reason the firewall is a module rather than a pile of per-host rulesets. The
  # fleet's previous hand-written ruleset accepted ssh only from a LAN range and named the overlay
  # interface for exactly one unrelated port — so loading it would have severed ssh over the
  # overlay, on a host reachable no other way. That is not a rule anyone forgets to write; it is a
  # rule nobody notices is missing, because the machine you test from is usually on the LAN.
  #
  # Here it cannot be missing: every interface in `management.interfaces` gets an unconditional
  # accept on the management port, generated before the host's own rule list and not overridable
  # by it.
  # PER SOURCE ADDRESS, never one shared bucket — and the difference is the whole value of the
  # option. A bare `limit rate 6/minute` is ONE token bucket for the rule: every new connection on
  # earth draws from it, so anyone who can reach the port can empty it and the very next rule drops
  # the operator. A brute-forcer does not need to guess a password to lock you out of your own box;
  # it needs to knock seven times a minute. That converts a hardening measure into a remote denial
  # of service against exactly the interface you would use to fix it.
  #
  # A dynamic set keyed on the source address gives each source its own bucket, which is what
  # "rate-limit new connections" was always meant to mean. Two sets because the table is `inet` and
  # an address type cannot be both families; `meta nfproto` selects which rule a packet reaches.
  mgmtSetV4 = "nixnet-management-ratelimit-v4";
  mgmtSetV6 = "nixnet-management-ratelimit-v6";

  # Element lifetime, not the rate window: an idle source's entry is garbage after this, and the
  # set stays small on a host being scanned continuously.
  mgmtSetTimeout = "10m";

  managementSetLines = cfg:
    lib.optionals (cfg.management.rateLimitNew != null && cfg.management.interfaces != [ ]) [
      "set ${mgmtSetV4} {"
      "  type ipv4_addr"
      "  flags dynamic,timeout"
      "  timeout ${mgmtSetTimeout}"
      "}"
      ""
      "set ${mgmtSetV6} {"
      "  type ipv6_addr"
      "  flags dynamic,timeout"
      "  timeout ${mgmtSetTimeout}"
      "}"
    ];

  managementLines = cfg:
    lib.concatMap
      (i:
        if cfg.management.rateLimitNew == null then
          [ "iifname \"${i}\" tcp dport ${toString cfg.management.port} accept  # nixnet: management, never removable" ]
        else [
          "iifname \"${i}\" meta nfproto ipv4 tcp dport ${toString cfg.management.port} ct state new add @${mgmtSetV4} { ip saddr limit rate ${cfg.management.rateLimitNew} } accept  # nixnet: management, rate-limited per source"
          "iifname \"${i}\" meta nfproto ipv6 tcp dport ${toString cfg.management.port} ct state new add @${mgmtSetV6} { ip6 saddr limit rate ${cfg.management.rateLimitNew} } accept  # nixnet: management, rate-limited per source"
          "iifname \"${i}\" tcp dport ${toString cfg.management.port} ct state new drop  # nixnet: management, this source is over its rate"
        ])
      cfg.management.interfaces;

  # Conntrack + loopback + ICMP. Every one of these is load-bearing:
  #   - established/related first: the single most-hit rule, so it goes at the top.
  #   - loopback accept: without it, local services talking to 127.0.0.1 break in ways that look
  #     like application bugs. `iifname "lo"`, not `iif lo`: `iif` resolves the name to an ifindex
  #     when the ruleset is LOADED, which makes the rule depend on that interface existing at load
  #     time — including inside the build-time ruleset check. A string match costs a comparison and
  #     has no load-time dependency at all.
  #   - ICMP unconditional: ICMPv6 carries NDP and RA. Dropping it does not "harden" a host, it
  #     breaks IPv6 neighbour discovery and the box loses v6 connectivity by degrees. This is also
  #     what makes `addressing.v6 = "slaac"` need no rule of its own below.
  preambleLines = [
    "ct state established,related accept"
    "ct state invalid drop"
    "iifname \"lo\" accept"
    ""
    "# ICMP is unconditional, both families. ICMPv6 carries NDP/RA — filtering it breaks IPv6"
    "# rather than securing it, and SLAAC addressing depends on exactly these packets."
    "meta l4proto icmp accept"
    "meta l4proto ipv6-icmp accept"
  ];

  # THE DHCP CLIENT ACCEPTS — derived, per interface, from that interface's DECLARED addressing.
  #
  # This is the rule that cost a production edge host most of a day, and the reason the packet
  # filter is not allowed to live in a repo of its own again.
  #
  # nixpkgs' own firewall emits DHCP client accepts, so every host that has ever run
  # `networking.firewall` has had them. A host that adopts a default-drop ruleset instead, and
  # whose address comes from DHCP, silently loses them.
  #
  # The failure is delayed, which is what makes it dangerous. A client's initial DISCOVER goes out
  # over AF_PACKET and never traverses netfilter, so the box comes up with an address and looks
  # completely healthy. The RENEW and REBIND legs later in the lease use an ordinary UDP socket,
  # and those the input chain drops. Nothing is logged that names DHCP. The host then keeps working
  # until the lease expires — half a day, a day — and only then loses its address, with every
  # symptom pointing somewhere else entirely: DNS failing, the metadata service unreachable,
  # tunnels down, an overlay that "broke". The firewall change and the outage were 21 hours apart.
  #
  # Not a remembered rule any more: the accept exists because the host DECLARED
  # `nixnet.interfaces.<i>.addressing.v4 = "dhcp"`, and a statically-addressed host does not carry
  # it. The declaration also says WHICH interface renews, so the accept is scoped to it — a host
  # renewing on an interface nobody declared is a fact error, not a firewall exception.
  #
  # Client direction only: server -> client on v4, and the link-local destination the RFC 8415
  # client binds on v6. A host that SERVES DHCP declares that in `allow`, where it is visible;
  # accepting dport 67 here would quietly turn every DHCP-addressed host into one.
  dhcpClientLines = { v4Interfaces, v6Interfaces }:
    (map
      (i: "iifname \"${i}\" meta nfproto ipv4 udp sport 67 udp dport 68 accept  # nixnet: DHCPv4 client, derived from nixnet.interfaces.${i}.addressing.v4")
      v4Interfaces)
    ++ (map
      (i: "iifname \"${i}\" ip6 daddr fe80::/64 udp dport 546 accept  # nixnet: DHCPv6 client, derived from nixnet.interfaces.${i}.addressing.v6")
      v6Interfaces);

  # Blanket accept for an interface, both directions, in a FORWARD chain. Used for the routed
  # overlay path — see modules/firewall.nix for the fact this is derived from and the failure it
  # prevents.
  forwardInterfaceLines = iface: why: [
    "iifname \"${iface}\" accept  # nixnet: ${why} (inbound)"
    "oifname \"${iface}\" accept  # nixnet: ${why} (outbound)"
  ];

  # Drops that happen anyway, made silent. Purely a log-noise measure, and it is not cosmetic: on
  # the host this pattern came from, 66% of kernel log lines were the firewall logging ordinary LAN
  # broadcast housekeeping — which is precisely what hid a real WireGuard drop for weeks.
  silentDropLines = drops: map (d: "${d.match} drop  # ${d.comment}") drops;
}
