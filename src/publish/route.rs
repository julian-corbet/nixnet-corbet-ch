//! Route-metric reprioritization for uplinks. Never creates a default
//! route where there was none, and never touches an interface the engine
//! didn't rank -- but it does rewrite the routes it reprioritizes, because
//! Linux offers no way to edit a route's metric in place.
//!
//! Two facts about the kernel's routing table shape everything below.
//! First, **the metric is part of a route's identity**: `ip route replace
//! ... metric N` only matches a route that already *has* metric N, so
//! aiming it at a route sitting on some other metric quietly installs a
//! *second* default route instead of moving the first. The kernel goes on
//! using whichever of the two has the lower metric, so a demotion of the
//! old winner silently doesn't happen and failover doesn't either -- the
//! whole point of the exercise. The stale route is therefore deleted, and
//! only *after* the new one is in place, so the box is never even
//! momentarily left without a default route.
//!
//! Second, **`replace` rewrites the whole route, not one attribute of
//! it**: `replace default dev IFACE metric N` -- with no `via` -- yields an
//! *on-link* default, which is unusable for any off-link destination. The
//! interface's current default route is therefore read back first and its
//! gateway carried over verbatim; the on-link form is emitted only when
//! the real route genuinely has no gateway, which is the normal shape for
//! a point-to-point link (PPP, WWAN, some tunnels).
//!
//! Attributes other than the gateway are *not* carried over: the rewritten
//! route comes back as `proto boot` with no `src`, where DHCP's original
//! was `proto dhcp src <lease address>`. Source-address selection then
//! falls back to a suitable address on the same interface, which is the
//! lease address on every single-address uplink; an uplink carrying
//! several addresses may see locally-generated traffic pick a different
//! one.

use std::fmt;
use std::process::Command;

use serde::Deserialize;

/// One transport of a subject, in published rank order: index 0 is the
/// winner, and each later entry is one `metric_step` less preferred.
///
/// TF-3: EVERY transport of the subject belongs in this list, not only the
/// healthy ones. Publishing the healthy candidates alone leaves the
/// transport that just failed sitting on the metric it won with, so the
/// ex-winner and the new winner both end up at `metric_base` -- two
/// equal-cost defaults, between which the kernel picks whichever it likes,
/// possibly the dead one.
#[derive(Debug, Clone)]
pub struct RankedInterface {
    pub interface: String,
    /// Whether the transport behind this interface is currently Up. Only
    /// used to decide whether a MISSING default route is worth an error:
    /// see `reprioritize`.
    pub healthy: bool,
}

/// One default route this publisher actually moved. Reported rather than
/// merely logged in place, so the engine can name the subject the
/// interface belongs to -- "dev wan0 went 600 -> 100" is only half an
/// answer on a host with two uplink groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteChange {
    pub interface: String,
    pub from_metric: i64,
    pub to_metric: i64,
}

/// What one `apply` did, and the first thing that went wrong while doing
/// it. Both, never one or the other: `apply` deliberately keeps going past
/// a failed interface, so a partial repair that reached the kernel must
/// still reach the log -- otherwise an operator reads one error and has no
/// record of the half that worked.
///
/// An empty `changes` with no `error` is the ordinary steady state under
/// TF-2: the live table already says what nixnet would have written, so
/// nothing was written and nothing is logged.
#[derive(Debug, Default)]
pub struct Publication {
    pub changes: Vec<RouteChange>,
    pub error: Option<RouteError>,
}

impl Publication {
    /// Records `msg` as the failure, keeping the FIRST one: it is the one
    /// with a cause, where later failures on the same tick are frequently
    /// its consequences.
    fn fail(&mut self, msg: String) {
        if self.error.is_none() {
            self.error = Some(RouteError(msg));
        }
    }
}

/// Reprioritizes metrics on default routes the OS/DHCP already
/// established.
pub struct RoutePublisher {
    /// Absolute (Nix-store-resolved) path to the `ip` binary. This is the
    /// one narrow, well-tested exec that's an acceptable exception to "no
    /// PATH dependency" -- resolved once at Nix build time, not looked up
    /// on PATH at run time (falls back to `"ip"` only for the non-Nix,
    /// hand-written-config path).
    pub ip_path: String,
}

#[derive(Debug)]
pub struct RouteError(String);

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RouteError {}

/// The two fields of an `ip -j route show` object nixnet needs. Both are
/// absent from the JSON in ordinary cases -- `gateway` for an on-link
/// (point-to-point) default, `metric` for a route carrying the kernel's
/// implicit priority of 0 -- so both are optional here. Every other key
/// `ip` emits (`dst`, `dev`, `protocol`, `prefsrc`, `flags`, ...) is
/// deliberately ignored: serde drops unknown fields, which keeps this
/// parse working across iproute2 versions that add new ones.
#[derive(Debug, Deserialize)]
struct IpRoute {
    gateway: Option<String>,
    metric: Option<i64>,
}

impl IpRoute {
    /// A route with no explicit metric sits at priority 0, so that is the
    /// value `ip route del` has to be handed to match it again.
    fn metric(&self) -> i64 {
        self.metric.unwrap_or(0)
    }
}

impl RoutePublisher {
    /// Reprioritizes each ranked transport's existing default route, winner
    /// first at `metric_base`, each subsequent one `metric_step` higher --
    /// including the ones that are currently Down, which is TF-3: the
    /// demotion of the loser IS the failover. Keeps going even if one
    /// interface fails (it just disappeared, has no default route yet,
    /// etc.), reporting the first error alongside whatever did get
    /// rewritten.
    ///
    /// Called on every reconcile tick (TF-2), not only on a winner change,
    /// so the common case is that nothing differs and nothing is written:
    /// one read-back per interface and no route-table transaction at all.
    pub fn apply(
        &self,
        candidates: &[RankedInterface],
        metric_base: i64,
        metric_step: i64,
    ) -> Publication {
        let mut out = Publication::default();
        for (i, c) in candidates.iter().enumerate() {
            let metric = metric_base + (i as i64) * metric_step;
            self.reprioritize(&mut out, &c.interface, metric, c.healthy);
        }
        out
    }

    /// The empty-string case is the hand-written-config path, where the
    /// config loader has nothing from Nix to substitute.
    fn ip(&self) -> &str {
        if self.ip_path.is_empty() {
            "ip"
        } else {
            &self.ip_path
        }
    }

    /// Moves `iface`'s default route to `metric`, preserving its gateway.
    /// Records the move (or the failure) in `out`; writes nothing when the
    /// live table already says exactly this.
    fn reprioritize(&self, out: &mut Publication, iface: &str, metric: i64, healthy: bool) {
        let existing = match self.show_default(iface) {
            Ok(e) => e,
            Err(e) => return out.fail(e),
        };

        // More than one default route on a single interface only happens
        // if something already installed a duplicate -- including an
        // earlier nixnet, whose `replace` at a fresh metric added rather
        // than moved. The one the kernel is *using* is the lowest-metric
        // one, so that is the route whose gateway is authoritative; the
        // rest are cleaned up below along with the original.
        let chosen = match existing.iter().min_by_key(|r| r.metric()) {
            Some(r) => r,
            None => {
                // A Down transport with no default route left is the
                // ordinary shape of a link that went away -- the DHCP
                // client withdrew the lease, or the interface lost its
                // address -- and there is nothing to demote. Reporting it
                // would emit one error per reconcile tick (TF-2 made this
                // a per-tick operation) for as long as the link stays
                // down, which buries the errors that mean something. A
                // HEALTHY transport with no default route is the opposite:
                // nixnet is being asked to steer traffic onto an interface
                // the kernel has no route for, and that is worth saying.
                if !healthy {
                    return;
                }
                return out.fail(format!(
                    "no default route on dev {} to reprioritize -- nixnet only \
                     reprioritizes routes the OS/DHCP established, it never \
                     creates one",
                    iface
                ));
            }
        };

        // TF-2's other half: reconcile is not a rewrite. The metric is part
        // of a route's identity, so a single default already sitting on the
        // target metric is byte-for-byte what the rewrite below would
        // install. Writing it anyway would mean two route-table
        // transactions per interface per tick forever -- churn on the one
        // table whose stability is this daemon's entire product, and every
        // one of them a window in which the route is momentarily absent.
        let from_metric = chosen.metric();
        if existing.len() == 1 && from_metric == metric {
            return;
        }

        let metric_arg = metric.to_string();
        let mut args = vec!["route", "replace", "default"];
        if let Some(gw) = &chosen.gateway {
            args.push("via");
            args.push(gw);
        }
        args.extend_from_slice(&["dev", iface, "metric", &metric_arg]);
        // A failed install is fatal for this interface: deleting the
        // routes below would then strip its last default route instead of
        // superseding it.
        if let Err(e) = self.run(&args) {
            return out.fail(e);
        }
        out.changes.push(RouteChange {
            interface: iface.to_string(),
            from_metric,
            to_metric: metric,
        });

        for r in &existing {
            // The route already sitting at the target metric is the one
            // the `replace` above just wrote. Deleting it would undo the
            // whole operation.
            if r.metric() == metric {
                continue;
            }
            let old_metric = r.metric().to_string();
            let mut args = vec!["route", "del", "default"];
            if let Some(gw) = &r.gateway {
                args.push("via");
                args.push(gw);
            }
            args.extend_from_slice(&["dev", iface, "metric", &old_metric]);
            if let Err(e) = self.run(&args) {
                out.fail(e);
                // Keep going for the same reason `apply` does: a leftover
                // duplicate on one metric shouldn't stop the others from
                // being cleared.
            }
        }
    }

    /// Reads back every default route currently on `iface`. JSON rather
    /// than `ip route show`'s human output because the crate already
    /// carries serde_json and the text form is a positional, version-
    /// dependent word soup whose fields (`proto`, `src`, `metric`,
    /// `linkdown`, ...) appear and vanish per route.
    fn show_default(&self, iface: &str) -> Result<Vec<IpRoute>, String> {
        let args = ["-j", "route", "show", "default", "dev", iface];
        let out = Command::new(self.ip())
            .args(args)
            .output()
            .map_err(|e| format!("ip {}: {}", args.join(" "), e))?;
        if !out.status.success() {
            return Err(format!(
                "ip {}: exit {} ({}{})",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        // A selector that matches nothing gives `[]` on current iproute2
        // and completely empty output on some older builds; both mean the
        // same thing and neither is an error.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let text = stdout.trim();
        if text.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(text).map_err(|e| {
            format!(
                "ip {}: unparseable JSON ({}) -- does this iproute2 support -j?",
                args.join(" "),
                e
            )
        })
    }

    /// Runs one mutating `ip` command, turning a non-zero exit into the
    /// error string `apply` collects.
    fn run(&self, args: &[&str]) -> Result<(), String> {
        match Command::new(self.ip()).args(args).output() {
            Ok(out) if out.status.success() => Ok(()),
            Ok(out) => Err(format!(
                "ip {}: exit {} ({}{})",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )),
            Err(e) => Err(format!("ip {}: {}", args.join(" "), e)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::Path;

    // The stand-in `ip` and its argv log live here rather than beside the
    // engine's tests, and are `pub(crate)` for that reason: the engine
    // asserts on which TICKS this publisher is reached (TF-2), this module
    // asserts on what it then emits, and both are claims about one argv
    // grammar. A second copy of the harness is how those two turn into
    // claims about different programs.

    /// Writes a stand-in `ip` into `dir` and returns its path. It appends its
    /// argv to `dir/argv.log` -- one argument per line, a lone `--`
    /// terminating each invocation, which is unambiguous because no argument
    /// nixnet passes is ever itself `--` or contains a newline -- and answers a
    /// `route show` with the canned contents of `dir/show-<iface>.json`, or
    /// `[]` when that file is absent. If `dir/fail-replace` exists, every
    /// `route replace` exits non-zero, which is how the "don't delete what we
    /// failed to supersede" invariant gets exercised without a routing table.
    pub(crate) fn fake_ip(dir: &Path) -> String {
        let path = dir.join("ip");
        let d = dir.display();
        let script = format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{d}/argv.log'\n\
             printf -- '--\\n' >> '{d}/argv.log'\n\
             if [ \"$2\" = replace ] && [ -f '{d}/fail-replace' ]; then\n\
             \techo 'RTNETLINK answers: Network is unreachable' >&2\n\
             \texit 2\n\
             fi\n\
             if [ \"$1\" = -j ]; then\n\
             \tif [ -f \"{d}/show-$6.json\" ]; then cat \"{d}/show-$6.json\"; else printf '[]'; fi\n\
             fi\n\
             exit 0\n"
        );
        // The script is written by a *child* process rather than by this one,
        // and that detail is load-bearing. libtest runs these tests on threads
        // while other tests in the crate fork their own subprocesses; a child
        // forked while this thread holds a writable fd on the script inherits
        // that fd, and exec'ing the script then fails with ETXTBSY, "Text file
        // busy", until that child reaches its own exec (rust-lang/rust#39745 --
        // reproduced here, roughly one full-suite run in three). Handing the
        // text to `sh` on stdin instead keeps the only writable fd inside a
        // process nothing else can fork from, so once it exits the inode has no
        // writer anywhere and every exec below is race-free.
        let mut writer = std::process::Command::new("/bin/sh")
            .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        writer
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        assert!(writer.wait().unwrap().success());
        path.to_str().unwrap().to_string()
    }

    /// The default route(s) the fake `ip` will report for `iface`.
    pub(crate) fn canned_route(dir: &Path, iface: &str, json: &str) {
        std::fs::write(dir.join(format!("show-{}.json", iface)), json).unwrap();
    }

    /// One expected argv, written the way an operator would type the command.
    /// Safe to split on spaces because no argument nixnet passes contains one.
    pub(crate) fn argv(line: &str) -> Vec<String> {
        line.split(' ').map(String::from).collect()
    }

    /// The recorded argv of every `ip` invocation, in order.
    pub(crate) fn invocations(dir: &Path) -> Vec<Vec<String>> {
        let log = std::fs::read_to_string(dir.join("argv.log")).unwrap_or_default();
        let mut all = Vec::new();
        let mut cur = Vec::new();
        for line in log.lines() {
            if line == "--" {
                all.push(std::mem::take(&mut cur));
            } else {
                cur.push(line.to_string());
            }
        }
        all
    }

    /// Every `ip` invocation that MUTATES the routing table, i.e. everything
    /// but the read-back. TF-2's "identical state produces no write" is a claim
    /// about exactly this list being empty.
    pub(crate) fn writes(dir: &Path) -> Vec<Vec<String>> {
        invocations(dir)
            .into_iter()
            .filter(|a| a.first().map(String::as_str) != Some("-j"))
            .collect()
    }

    /// The `dev`/`metric` pair of every `route replace` issued, in order --
    /// i.e. what nixnet actually told the kernel each interface's default route
    /// should now cost.
    pub(crate) fn published_metrics(dir: &Path) -> Vec<(String, i64)> {
        invocations(dir)
            .iter()
            .filter(|a| a.get(1).map(String::as_str) == Some("replace"))
            .map(|a| {
                let dev = a[a.iter().position(|x| x == "dev").unwrap() + 1].clone();
                let metric = a[a.iter().position(|x| x == "metric").unwrap() + 1]
                    .parse()
                    .unwrap();
                (dev, metric)
            })
            .collect()
    }

    /// Every interface healthy -- the shape of a publication where nothing
    /// has failed. Demotion of a DOWN transport is ranked the same way and
    /// differs only in `healthy`, which is what `ranked_with_health` below
    /// exists to express.
    fn ranked(ifaces: &[&str]) -> Vec<RankedInterface> {
        ifaces
            .iter()
            .map(|i| RankedInterface {
                interface: i.to_string(),
                healthy: true,
            })
            .collect()
    }

    fn ranked_with_health(ifaces: &[(&str, bool)]) -> Vec<RankedInterface> {
        ifaces
            .iter()
            .map(|(i, healthy)| RankedInterface {
                interface: i.to_string(),
                healthy: *healthy,
            })
            .collect()
    }

    #[test]
    fn gateway_is_carried_over_and_the_old_metric_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        canned_route(
            dir.path(),
            "eth0",
            r#"[{"dst":"default","gateway":"192.168.1.1","dev":"eth0","protocol":"dhcp","prefsrc":"192.168.1.50","metric":600,"flags":[]}]"#,
        );

        let out = rp.apply(&ranked(&["eth0"]), 100, 50);

        assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
        assert_eq!(
            out.changes,
            vec![RouteChange {
                interface: "eth0".to_string(),
                from_metric: 600,
                to_metric: 100,
            }],
            "the move was not reported, so nothing would log the re-assert"
        );
        assert_eq!(
            invocations(dir.path()),
            vec![
                argv("-j route show default dev eth0"),
                argv("route replace default via 192.168.1.1 dev eth0 metric 100"),
                argv("route del default via 192.168.1.1 dev eth0 metric 600"),
            ]
        );
    }

    #[test]
    fn a_gatewayless_route_stays_on_link() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        // No `gateway` key and no `metric` key: a point-to-point default
        // at the kernel's implicit priority 0.
        canned_route(
            dir.path(),
            "wwan0",
            r#"[{"dst":"default","dev":"wwan0","protocol":"static","flags":[]}]"#,
        );

        let out = rp.apply(&ranked(&["wwan0"]), 100, 50);

        assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
        assert_eq!(
            invocations(dir.path()),
            vec![
                argv("-j route show default dev wwan0"),
                argv("route replace default dev wwan0 metric 100"),
                argv("route del default dev wwan0 metric 0"),
            ]
        );
    }

    #[test]
    fn an_interface_with_no_default_route_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        // No canned file at all -- the fake `ip` answers `[]`.

        let out = rp.apply(&ranked(&["eth9"]), 100, 50);

        let err = out
            .error
            .expect("a healthy interface with no default route is a fault");
        assert!(
            err.to_string().contains("no default route on dev eth9"),
            "unexpected error text: {}",
            err
        );
        assert_eq!(
            invocations(dir.path()),
            vec![argv("-j route show default dev eth9")],
            "nixnet must never create a default route that wasn't there"
        );
    }

    /// The same missing route on a transport that is DOWN, which is what a
    /// link whose DHCP lease has been withdrawn looks like. TF-3 puts that
    /// transport in the ranking so it can be demoted; there is nothing to
    /// demote, and saying so once per reconcile tick for as long as the
    /// link stays down (TF-2 made this per-tick) buries every error that
    /// means something.
    #[test]
    fn a_down_interface_with_no_default_route_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        canned_route(
            dir.path(),
            "eth0",
            r#"[{"dst":"default","gateway":"192.168.1.1","dev":"eth0","metric":100,"flags":[]}]"#,
        );

        let out = rp.apply(
            &ranked_with_health(&[("eth0", true), ("wwan0", false)]),
            100,
            50,
        );

        assert!(
            out.error.is_none(),
            "a down link with no route left to demote was reported as a fault: {:?}",
            out.error
        );
    }

    /// TF-2, at the layer that talks to the kernel: a reconcile tick that
    /// finds the live table already saying what nixnet would write must
    /// issue NO route command at all. The read-back is the whole
    /// interaction. Before this, every tick rewrote the winner's default
    /// route -- and with publication moved onto the tick (TF-2's other
    /// half) that is a route-table transaction every few seconds, forever,
    /// each one a window in which the default route does not exist.
    #[test]
    fn a_route_already_at_the_target_metric_is_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        canned_route(
            dir.path(),
            "eth0",
            r#"[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":100,"flags":[]}]"#,
        );

        let out = rp.apply(&ranked(&["eth0"]), 100, 50);

        assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
        assert!(
            out.changes.is_empty(),
            "an unchanged table reported a change, which would log a \
             re-assert every tick: {:?}",
            out.changes
        );
        assert_eq!(
            invocations(dir.path()),
            vec![argv("-j route show default dev eth0")],
            "identical state must produce no write and no transaction"
        );
    }

    /// The other direction of the same rule, and the reason the check is
    /// `len() == 1` rather than "the lowest metric matches": a duplicate
    /// default left behind by anything -- including an earlier nixnet whose
    /// `replace` at a fresh metric ADDED rather than moved -- is not
    /// identical state, and must still be cleaned up.
    #[test]
    fn a_duplicate_default_at_the_target_metric_is_still_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        canned_route(
            dir.path(),
            "eth0",
            r#"[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":100,"flags":[]},
                {"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":600,"flags":[]}]"#,
        );

        let out = rp.apply(&ranked(&["eth0"]), 100, 50);

        assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
        assert_eq!(
            invocations(dir.path()),
            vec![
                argv("-j route show default dev eth0"),
                argv("route replace default via 10.0.0.1 dev eth0 metric 100"),
                argv("route del default via 10.0.0.1 dev eth0 metric 600"),
            ],
            "the stale duplicate survived, so the kernel still has two defaults"
        );
    }

    #[test]
    fn each_interface_keeps_its_own_gateway_and_gets_the_next_metric() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        canned_route(
            dir.path(),
            "eth0",
            r#"[{"dst":"default","gateway":"192.168.1.1","dev":"eth0","metric":600,"flags":[]}]"#,
        );
        canned_route(
            dir.path(),
            "wlan0",
            r#"[{"dst":"default","gateway":"10.7.0.1","dev":"wlan0","metric":700,"flags":[]}]"#,
        );

        let out = rp.apply(&ranked(&["eth0", "wlan0"]), 100, 50);

        assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
        assert_eq!(
            invocations(dir.path()),
            vec![
                argv("-j route show default dev eth0"),
                argv("route replace default via 192.168.1.1 dev eth0 metric 100"),
                argv("route del default via 192.168.1.1 dev eth0 metric 600"),
                argv("-j route show default dev wlan0"),
                argv("route replace default via 10.7.0.1 dev wlan0 metric 150"),
                argv("route del default via 10.7.0.1 dev wlan0 metric 700"),
            ]
        );
    }

    /// TF-3 at the publisher: a failover where the ex-winner is DOWN. The
    /// loser is in the ranking, so it is moved UP the metric scale in the
    /// same `apply` that moves the winner down -- and the two end on
    /// different metrics. Before this, the ranking held healthy candidates
    /// only, so the dead eth0 kept metric 100, the live wlan0 was written
    /// to metric 100 as well, and the kernel was left choosing between two
    /// equal-cost defaults.
    #[test]
    fn the_loser_is_demoted_in_the_same_apply_that_promotes_the_winner() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        // The state a previous publication left behind: eth0 won at 100,
        // wlan0 sat one step behind at 150. eth0 has since gone down.
        canned_route(
            dir.path(),
            "eth0",
            r#"[{"dst":"default","gateway":"192.168.1.1","dev":"eth0","metric":100,"flags":[]}]"#,
        );
        canned_route(
            dir.path(),
            "wlan0",
            r#"[{"dst":"default","gateway":"10.7.0.1","dev":"wlan0","metric":150,"flags":[]}]"#,
        );

        let out = rp.apply(
            &ranked_with_health(&[("wlan0", true), ("eth0", false)]),
            100,
            50,
        );

        assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
        assert_eq!(
            invocations(dir.path()),
            vec![
                argv("-j route show default dev wlan0"),
                argv("route replace default via 10.7.0.1 dev wlan0 metric 100"),
                argv("route del default via 10.7.0.1 dev wlan0 metric 150"),
                argv("-j route show default dev eth0"),
                argv("route replace default via 192.168.1.1 dev eth0 metric 150"),
                argv("route del default via 192.168.1.1 dev eth0 metric 100"),
            ]
        );

        let metrics = published_metrics(dir.path());
        assert_eq!(metrics, vec![("wlan0".into(), 100), ("eth0".into(), 150)]);
        assert!(
            metrics[0].1 < metrics[1].1,
            "the new winner is not strictly cheaper than the ex-winner: {metrics:?}"
        );

        // TF-3's boundary: the ex-winner's default route is MOVED, never
        // removed. Deleting a default a foreign DHCP client installed puts
        // the host one lease renewal away from a fight nixnet loses.
        let deleted_at_new_metric = invocations(dir.path()).iter().any(|a| {
            a.contains(&"del".to_string())
                && a.contains(&"eth0".to_string())
                && a.last() == Some(&"150".to_string())
        });
        assert!(
            !deleted_at_new_metric,
            "the loser's route was demoted and then deleted -- the host now \
             has no route over that interface at all"
        );
    }

    #[test]
    fn a_failed_replace_never_deletes_the_surviving_route() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        std::fs::write(dir.path().join("fail-replace"), "").unwrap();
        canned_route(
            dir.path(),
            "eth0",
            r#"[{"dst":"default","gateway":"192.168.1.1","dev":"eth0","metric":600,"flags":[]}]"#,
        );

        let out = rp.apply(&ranked(&["eth0"]), 100, 50);

        let err = out.error.expect("a failed replace must be reported");
        assert!(
            err.to_string().contains("Network is unreachable"),
            "unexpected error text: {}",
            err
        );
        assert!(
            out.changes.is_empty(),
            "a failed replace was reported as a change: {:?}",
            out.changes
        );
        assert_eq!(
            invocations(dir.path()).len(),
            2,
            "show + the failed replace, and no del: {:?}",
            invocations(dir.path())
        );
    }
}
