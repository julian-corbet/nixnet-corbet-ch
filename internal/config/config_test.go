package config

import "testing"

// testdata/nix-rendered-example.json is not hand-written: it's the actual
// config.json modules/core.nix + modules/netbird-provider.nix rendered for
// this repo's own README quickstart example, captured via `nix eval` against
// a minimal evalModules harness during development (see the deviations and
// clarifications documented in docs/providers.md — this fixture is what
// pins them down as actually-agreeing, not just independently plausible).
// If the Nix schema and this Go schema ever drift apart, this test is what
// catches it.
func TestLoad_NixRenderedExample(t *testing.T) {
	cfg, err := Load("testdata/nix-rendered-example.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	peer, ok := cfg.Peers["host-b"]
	if !ok {
		t.Fatalf("expected peer %q in rendered config", "host-b")
	}
	if len(peer.Hostnames) != 1 || peer.Hostnames[0] != "host-b" {
		t.Errorf("peer host-b hostnames = %v, want [host-b]", peer.Hostnames)
	}
	if len(peer.Transports) != 2 {
		t.Fatalf("peer host-b: got %d transports, want 2 (one hand-written, one netbird-provider-contributed)", len(peer.Transports))
	}

	var sawNetbird, sawTCP bool
	for _, tr := range peer.Transports {
		switch tr.ProviderID {
		case "netbird":
			sawNetbird = true
			if tr.Probe.Method != "exec" {
				t.Errorf("netbird transport: probe.method = %q, want exec", tr.Probe.Method)
			}
			// probe.exec must be a full command line whose argv[0] is an
			// absolute Nix store path (see the "Deviation: probe.exec is
			// a command line" note in docs/providers.md); the actual
			// tokenizing/exec'ing of it is internal/probe's concern and
			// is covered by internal/probe's own tests.
			if tr.Probe.Exec == "" || tr.Probe.Exec[0] != '/' {
				t.Errorf("netbird transport: probe.exec = %q, want a command line starting with an absolute path", tr.Probe.Exec)
			}
		case "":
			sawTCP = true
			if tr.Probe.Method != "tcp" {
				t.Errorf("hand-written transport: probe.method = %q, want tcp", tr.Probe.Method)
			}
			if tr.EffectiveTarget() != "192.0.2.20" {
				t.Errorf("hand-written transport: EffectiveTarget() = %q, want 192.0.2.20", tr.EffectiveTarget())
			}
		}
	}
	if !sawNetbird {
		t.Errorf("never saw the netbird-provider-contributed transport")
	}
	if !sawTCP {
		t.Errorf("never saw the hand-written tcp transport")
	}

	uplink, ok := cfg.Uplinks["internet"]
	if !ok {
		t.Fatalf("expected uplink %q in rendered config", "internet")
	}
	if len(uplink.Transports) != 2 {
		t.Fatalf("uplink internet: got %d transports, want 2", len(uplink.Transports))
	}
	for _, tr := range uplink.Transports {
		if tr.Interface == "" {
			t.Errorf("uplink transport missing interface: %+v", tr)
		}
	}
	if !uplink.Publish.RouteMetric {
		t.Errorf("uplink internet: publish.routeMetric = false, want true")
	}
	if uplink.Publish.MetricBase != 100 || uplink.Publish.MetricStep != 50 {
		t.Errorf("uplink internet: metricBase/metricStep = %d/%d, want 100/50", uplink.Publish.MetricBase, uplink.Publish.MetricStep)
	}

	if cfg.NeedsNetAdmin() != true {
		t.Errorf("NeedsNetAdmin() = false, want true (routeMetric is enabled)")
	}
	if cfg.NeedsNetRaw() != true {
		t.Errorf("NeedsNetRaw() = false, want true (wireless0 uses icmp+bindToInterface)")
	}
}
