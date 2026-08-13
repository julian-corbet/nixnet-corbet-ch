# modules/ingress.nix
#
# nixnet.ingress — provision a Cloudflare Tunnel (public hostname ->
# local service ingress rules) plus an optional host-side DNS reconciler
# that keeps the zone's records pointed at it.
#
# Companion to `cloudflared-provider.nix` (`nixnet.cloudflared`), not a
# replacement for it: that module is a resident health WATCHDOG for an
# already-running tunnel unit (probes /ready, restarts on wedge); this
# module is what actually PROVISIONS the tunnel + its ingress + DNS in the
# first place. A host commonly wants both — set
# `nixnet.cloudflared.tunnelUnit = "cloudflared-tunnel-${config.nixnet.ingress.tunnelId}"`
# to point the watchdog at the tunnel this module creates (not wired
# automatically — nixnet's providers are independently composable by
# design, see docs/providers.md).
#
# Wraps upstream `services.cloudflared` — never reimplements cloudflared's
# own tunnel/config management.
{ config, lib, pkgs, ... }:

let
  cfg = config.nixnet.ingress;
  q = lib.escapeShellArg;
  ingressHostnames = map (rule: rule.hostname) cfg.ingress;
  duplicateIngressHostnames =
    lib.length ingressHostnames != lib.length (lib.unique ingressHostnames);
  reconciledHostnames =
    if cfg.dnsReconcile.enable then
      lib.filter
        (hostname:
          hostname == cfg.dnsReconcile.zone
          || lib.hasSuffix ".${cfg.dnsReconcile.zone}" hostname)
        ingressHostnames
    else
      [ ];
  unreconciledHostnames =
    if cfg.dnsReconcile.enable
    then lib.subtractLists reconciledHostnames ingressHostnames
    else [ ];
  conflictingMgmtHostnames = lib.intersectLists
    ingressHostnames
    (lib.attrNames cfg.dnsReconcile.mgmtRecords);
in
{
  options.nixnet.ingress = {
    enable = lib.mkEnableOption "Cloudflare Tunnel daemon (cloudflared) for HTTPS-fronted services";

    tunnelId = lib.mkOption {
      type = lib.types.str;
      description = "Cloudflare Tunnel UUID.";
    };

    credentialsFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/secrets/cloudflared-credentials.json";
      description = "Path to the tunnel credentials JSON.";
    };

    ingress = lib.mkOption {
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            hostname = lib.mkOption {
              type = lib.types.str;
              description = "Public hostname.";
              example = "app.example.com";
            };
            service = lib.mkOption {
              type = lib.types.str;
              description = "Local service URL.";
              example = "http://localhost:17170";
            };
            path = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Optional path regex filter: only matching request paths are
                routed to `service`; the rest of the hostname falls through
                to the 404 catch-all. Used to expose a single endpoint
                (e.g. a webhook receiver) of an otherwise-private service.
              '';
            };
          };
        }
      );
      default = [ ];
      description = ''
        Ingress rules mapping public hostnames to local service URLs.
        Hostnames must be unique because the upstream NixOS cloudflared
        module represents ingress as an attribute set. This module appends
        the `http_status:404` catch-all itself.
      '';
    };

    edgeIpVersion = lib.mkOption {
      type = lib.types.enum [ "4" "6" "auto" ];
      default = "auto";
      description = ''
        IP version for the Cloudflare edge connection. Set "6" on a host
        that lacks public IPv4 — otherwise cloudflared tries v4 edges and
        times out.
      '';
    };

    transportProtocol = lib.mkOption {
      type = lib.types.enum [ "quic" "http2" "auto" ];
      default = "auto";
      description = ''
        Tunnel transport protocol. "http2" is more compatible across
        NAT/firewalls than "quic" (UDP) — useful on a host whose IPv6 path
        occasionally drops QUIC.
      '';
    };

    dnsReconcile = {
      enable = lib.mkEnableOption ''
        host-side Cloudflare DNS reconciler — declaratively UPSERTs (never
        deletes) a proxied CNAME -> the tunnel for every `ingress` hostname,
        plus optional internal-only A-records
      '';
      apiTokenFile = lib.mkOption {
        type = lib.types.path;
        default = "/run/secrets/cloudflared-cf-api-token";
        description = "Path to the Cloudflare DNS-edit API token (a file containing just the token).";
      };
      zone = lib.mkOption {
        type = lib.types.str;
        description = "Cloudflare zone the records live in.";
        example = "example.com";
      };
      onCalendar = lib.mkOption {
        type = lib.types.str;
        default = "*:0/15";
        description = "systemd OnCalendar for the reconcile timer (default: every 15 min).";
      };
      mgmtRecords = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = { };
        example = { "internal-app.example.com" = "192.0.2.10"; };
        description = ''
          Internal-only hostnames -> their INTERNAL IP, UPSERTed as
          proxied=false A-records. These do NOT go through the tunnel — for
          hostnames an overlay network (or LAN) routes to directly.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !duplicateIngressHostnames;
        message = ''
          nixnet.ingress.ingress contains the same hostname more than once.
          The upstream cloudflared module stores ingress by hostname, so a
          duplicate would be silently discarded (including a second path
          rule). Give every rule a unique hostname.
        '';
      }
    ] ++ lib.optionals cfg.dnsReconcile.enable [
      {
        assertion = unreconciledHostnames == [ ];
        message = ''
          nixnet.ingress.dnsReconcile is enabled, but these ingress
          hostnames are outside zone ${cfg.dnsReconcile.zone} and would be
          silently skipped: ${lib.concatStringsSep ", " unreconciledHostnames}
        '';
      }
      {
        assertion = conflictingMgmtHostnames == [ ];
        message = ''
          nixnet.ingress hostnames cannot also be declared as management
          A records: ${lib.concatStringsSep ", " conflictingMgmtHostnames}.
          DNS does not permit a CNAME and other record data at one name.
        '';
      }
    ];

    services.cloudflared = {
      enable = true;
      tunnels.${cfg.tunnelId} = {
        credentialsFile = cfg.credentialsFile;
        default = "http_status:404";
        edgeIPVersion = cfg.edgeIpVersion;
        protocol = cfg.transportProtocol;
        ingress = builtins.listToAttrs (
          map (rule: {
            name = rule.hostname;
            value =
              if rule.path == null then
                rule.service
              else
                { service = rule.service; path = rule.path; };
          }) cfg.ingress
        );
      };
    };

    # Host-side DNS reconciler. UPSERT-only (never deletes), so
    # externally-managed records in the same zone are untouched. Hostnames
    # come straight from `ingress` — publishing a new app is adding its
    # ingress rule here, nothing else.
    systemd.services.nixnet-ingress-dns-reconcile = lib.mkIf cfg.dnsReconcile.enable {
      description = "Reconcile Cloudflare DNS for the cloudflared tunnel ingress hostnames (+ mgmt A-records)";
      # Ordering to whatever unseals apiTokenFile is declared host-side, so
      # this module stays independent of any particular secrets mechanism.
      # Bounded run so an unreachable CF API can never wedge the timer.
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      path = [ pkgs.curl pkgs.jq pkgs.coreutils ];
      unitConfig.RequiresMountsFor = [ cfg.dnsReconcile.apiTokenFile ];
      serviceConfig = { Type = "oneshot"; TimeoutStartSec = 120; };
      script = ''
        set -u
        CF=https://api.cloudflare.com/client/v4
        ZONE=${q cfg.dnsReconcile.zone}
        TUNNEL=${q "${cfg.tunnelId}.cfargotunnel.com"}
        TOKEN_FILE=${q cfg.dnsReconcile.apiTokenFile}
        [ -r "$TOKEN_FILE" ] || { echo "no readable API token at $TOKEN_FILE"; exit 1; }
        CF_API_TOKEN=$(tr -d '\r\n' < "$TOKEN_FILE")
        [ -n "$CF_API_TOKEN" ] || { echo "empty API token at $TOKEN_FILE"; exit 1; }
        HEADER_FILE=$(mktemp)
        trap 'rm -f "$HEADER_FILE"' EXIT
        printf 'Authorization: Bearer %s\n' "$CF_API_TOKEN" > "$HEADER_FILE"
        unset CF_API_TOKEN
        auth() { curl -fsS --connect-timeout 10 --max-time 30 -H @"$HEADER_FILE" -H "Content-Type: application/json" "$@"; }
        ZID=$(auth --get "$CF/zones" --data-urlencode "name=$ZONE" | jq -r 'if .success == true then .result[0].id // empty else empty end')
        [ -n "$ZID" ] || { echo "zone lookup failed (token scope?)"; exit 1; }
        rc=0
        upsert() { # name type content proxied — UPSERT only, never delete
          local name="$1" type="$2" content="$3" proxied="$4" rec count id body cur
          if ! rec=$(auth --get "$CF/zones/$ZID/dns_records" \
              --data-urlencode "name=$name" --data-urlencode "type=$type"); then
            echo "[$name] LOOKUP FAILED"
            rc=1
            return
          fi
          if ! printf '%s' "$rec" | jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1; then
            echo "[$name] LOOKUP RETURNED AN API ERROR"
            rc=1
            return
          fi
          count=$(printf '%s' "$rec" | jq -r '.result | length')
          if [ "$count" -gt 1 ]; then
            echo "[$name] AMBIGUOUS: $count existing $type records; refusing to update an arbitrary one"
            rc=1
            return
          fi
          id=$(printf '%s' "$rec" | jq -r '.result[0].id // empty')
          body=$(jq -nc --arg type "$type" --arg name "$name" --arg content "$content" \
            --argjson proxied "$proxied" \
            '{type:$type,name:$name,content:$content,proxied:$proxied,ttl:1}')
          if [ -z "$id" ]; then
            if auth -X POST "$CF/zones/$ZID/dns_records" --data "$body" | jq -e '.success' >/dev/null 2>&1; then
              echo "[$name] CREATED $type -> $content (proxied=$proxied)"
            else echo "[$name] CREATE FAILED"; rc=1; fi
          else
            cur=$(printf '%s' "$rec" | jq -r '.result[0] | "\(.content)|\(.proxied)"')
            if [ "$cur" = "$content|$proxied" ]; then echo "[$name] ok"; else
              if auth -X PUT "$CF/zones/$ZID/dns_records/$id" --data "$body" | jq -e '.success' >/dev/null 2>&1; then
                echo "[$name] UPDATED ($cur) -> $content|$proxied"
              else echo "[$name] UPDATE FAILED"; rc=1; fi
            fi
          fi
        }
        for h in ${lib.concatMapStringsSep " " q reconciledHostnames}; do upsert "$h" CNAME "$TUNNEL" true; done
        ${lib.concatStringsSep "\n        " (lib.mapAttrsToList (host: ip: "upsert ${q host} A ${q ip} false") cfg.dnsReconcile.mgmtRecords)}
        echo "nixnet-ingress-dns-reconcile done (rc=$rc)"
        exit $rc
      '';
    };
    systemd.timers.nixnet-ingress-dns-reconcile = lib.mkIf cfg.dnsReconcile.enable {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.dnsReconcile.onCalendar;
        OnBootSec = "2min";
        Persistent = true;
      };
    };
  };
}
