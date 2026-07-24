//! testdata/nix-rendered-example.json is not hand-written: it's the
//! actual config.json `modules/core.nix` + `modules/netbird-provider.nix`
//! rendered for this repo's own README quickstart example, captured via
//! `nix eval` against a minimal evalModules harness during development
//! (see the deviations and clarifications documented in
//! docs/providers.md -- this fixture is what pins them down as
//! actually-agreeing, not just independently plausible). If the Nix
//! schema and this Rust schema ever drift apart, this test is what
//! catches it.

use std::path::Path;

use nixnet::config;

#[test]
fn load_nix_rendered_example() {
    let cfg = config::load(Path::new("tests/testdata/nix-rendered-example.json")).expect("load");

    let peer = cfg
        .peers
        .get("host-b")
        .expect("expected peer \"host-b\" in rendered config");
    assert_eq!(peer.hostnames, vec!["host-b".to_string()]);
    assert_eq!(
        peer.transports.len(),
        2,
        "peer host-b: want 2 transports (one hand-written, one netbird-provider-contributed)"
    );

    let mut saw_netbird = false;
    let mut saw_tcp = false;
    for tr in &peer.transports {
        match tr.provider_id.as_str() {
            "netbird" => {
                saw_netbird = true;
                assert_eq!(tr.probe.method, "exec");
                // probe.exec must be a full command line whose argv[0] is
                // an absolute Nix store path (see the "Deviation:
                // probe.exec is a command line" note in
                // docs/providers.md); the actual tokenizing/exec'ing of
                // it is crate::probe's own concern, covered by its own
                // tests.
                assert!(
                    !tr.probe.exec.is_empty() && tr.probe.exec.starts_with('/'),
                    "netbird transport: probe.exec = {:?}, want a command line starting with an absolute path",
                    tr.probe.exec
                );
            }
            "" => {
                saw_tcp = true;
                assert_eq!(tr.probe.method, "tcp");
                assert_eq!(tr.effective_target(), "192.0.2.20");
            }
            other => panic!("unexpected providerId {:?}", other),
        }
    }
    assert!(
        saw_netbird,
        "never saw the netbird-provider-contributed transport"
    );
    assert!(saw_tcp, "never saw the hand-written tcp transport");

    let uplink = cfg
        .uplinks
        .get("internet")
        .expect("expected uplink \"internet\" in rendered config");
    assert_eq!(
        uplink.transports.len(),
        2,
        "uplink internet: want 2 transports"
    );
    for tr in &uplink.transports {
        assert!(
            !tr.interface.is_empty(),
            "uplink transport missing interface: {:?}",
            tr
        );
    }
    assert!(
        uplink.publish.route_metric,
        "uplink internet: publish.routeMetric = false, want true"
    );
    assert_eq!(uplink.publish.metric_base, 100);
    assert_eq!(uplink.publish.metric_step, 50);

    assert!(
        cfg.needs_net_admin(),
        "needs_net_admin() = false, want true (routeMetric is enabled)"
    );
    assert!(
        cfg.needs_net_raw(),
        "needs_net_raw() = false, want true (wireless0 uses icmp+bindToInterface)"
    );
}
