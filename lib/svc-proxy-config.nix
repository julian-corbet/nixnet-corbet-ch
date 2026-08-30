# lib/svc-proxy-config.nix — a pure function generating the SPLIT-HORIZON
# in-cluster routing surface (an nginx config + a CoreDNS zone) from a
# service registry, so an in-cluster caller of `<svc>.<zone>` gets the
# SAME https experience whether reached via an overlay network, a public
# tunnel, or in-cluster DNS.
#
# Not a NixOS module (no `options`/`config`) — a plain function, called
# from a flake's own `outputs` or a host config's `let`, the same way
# `nixpkgs.lib` itself is consumed. Exposed as this flake's own
# `lib.svcProxyConfig`.
#
# WHY an in-cluster proxy at all: an in-cluster pod calling `<svc>.<zone>`
# must NOT hairpin out to the public edge / an overlay peer (dead ends on
# an RFC1918/CGNAT address a pod's own network can't reach); it resolves to
# this proxy instead.
#
# Input shape (`services.<name>`, matching the shape a caller's own
# service registry already has reason to keep):
#   backend   = "host:port" this service's HTTP traffic is proxied to.
#   public    = true if it's also reachable from outside the cluster (has a
#               tunnel ingress rule elsewhere) — affects nothing here beyond
#               being OR'd with `nb` and `internal` for the HTTP/L4 split below.
#   nb        = true if it's also reachable as an overlay peer.
#   internal  = true if it has only the split-horizon in-cluster HTTP route:
#               nginx + CoreDNS, with no implication for tunnel or overlay.
#   l4        = true if this is a non-HTTP (binary protocol) service.
#   httpUi    = true if an `l4` service ALSO exposes an HTTP UI on the same
#               port (so it still gets an nginx block).
#   slot      = a small integer, this service's stable offset within
#               `l4ClusterIpPrefix` for the direct (non-proxied) DNS answer.
{ lib
, services
, machines ? { } # name -> { lan = "host-or-ip"; } for extra hosts{} entries
, zone # e.g. "example.com" — the domain this proxies/resolves
, proxyClusterIP # the in-cluster ClusterIP this nginx itself listens on
, l4ClusterIpPrefix # e.g. "10.42.64" — direct L4 services get "<prefix>.<slot>"
, upstreamForward ? [ "1.1.1.1" "1.0.0.1" ] # DNS forwarded here for anything NOT in the registry
}:
let
  # An HTTP service gets a proxy block + a DNS answer to the proxy when it is
  # present on at least one named HTTP plane (internal OR public OR nb) and is
  # not an L4 service, unless that L4 port is explicitly an HTTP UI.
  isHttp = s:
    ((s.internal or false) || (s.public or false) || (s.nb or false))
    && (!(s.l4 or false) || (s.httpUi or false));
  httpSvcs = lib.filterAttrs (_: isHttp) services;

  # An L4 service that is NOT an HTTP UI resolves DIRECT to its own
  # ClusterIP (a binary client speaks the protocol straight at
  # `svc.zone:<port>`; no HTTP proxy in that path).
  isL4Direct = s: (s.l4 or false) && !(s.httpUi or false);
  l4Svcs = lib.filterAttrs (_: isL4Direct) services;

  clusterIP = s: "${l4ClusterIpPrefix}.${toString s.slot}";

  serverBlock = name: s: ''
      server { listen 80; listen 443 ssl; server_name ${name}.${zone}; ssl_certificate /certs/tls.crt; ssl_certificate_key /certs/tls.key;
        location / { proxy_pass http://${s.backend}; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $conn_upgrade; } }'';

  nginxConf = ''
    worker_processes auto; events { worker_connections 1024; }
    http {
      map $http_upgrade $conn_upgrade { default upgrade; "" close; }
      proxy_http_version 1.1; client_max_body_size 0;
      server { listen 80 default_server; listen 443 ssl default_server; ssl_certificate /certs/tls.crt; ssl_certificate_key /certs/tls.key; return 404; }
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList serverBlock httpSvcs)}
    }
  '';

  # hosts{} entries — order is irrelevant to CoreDNS (name lookup), grouped for readability.
  hostLine = ip: name: "        ${ip} ${name}.${zone}";
  corednsHosts =
    (lib.mapAttrsToList (name: _: hostLine proxyClusterIP name) httpSvcs)
    ++ (lib.mapAttrsToList (name: s: hostLine (clusterIP s) name) l4Svcs)
    ++ (lib.mapAttrsToList (name: m: hostLine m.lan name) machines);

  corednsConfig = ''
    ${zone}:53 {
      hosts {
    ${lib.concatStringsSep "\n" corednsHosts}
        ttl 60
        fallthrough
      }
      forward . ${lib.concatStringsSep " " upstreamForward}
    }
  '';
in
{
  inherit nginxConf corednsConfig;
  # exposed for verification/audit
  httpNames = lib.attrNames httpSvcs;
  l4Names = lib.attrNames l4Svcs;
}
