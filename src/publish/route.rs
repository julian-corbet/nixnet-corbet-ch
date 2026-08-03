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

/// One currently-healthy candidate, already in priority order (lowest
/// priority number first == most preferred).
#[derive(Debug, Clone)]
pub struct RankedInterface {
    pub interface: String,
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
    /// Reprioritizes each candidate's existing default route, winner first
    /// at `metric_base`, each subsequent one `metric_step` higher. Only
    /// currently-healthy candidates are touched -- a transport that's Down
    /// keeps whatever metric it last had. Keeps going even if one
    /// candidate fails (interface just disappeared, no default route on it
    /// yet, etc.) -- collects and returns only the *first* error
    /// encountered, after attempting every candidate.
    pub fn apply(
        &self,
        candidates: &[RankedInterface],
        metric_base: i64,
        metric_step: i64,
    ) -> Result<(), RouteError> {
        let mut first_err: Option<RouteError> = None;
        for (i, c) in candidates.iter().enumerate() {
            let metric = metric_base + (i as i64) * metric_step;
            if let Err(msg) = self.reprioritize(&c.interface, metric) {
                if first_err.is_none() {
                    first_err = Some(RouteError(msg));
                }
                // Keep going: one interface's route command failing (e.g.
                // the interface just disappeared) shouldn't stop the
                // others from being reprioritized correctly.
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
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
    fn reprioritize(&self, iface: &str, metric: i64) -> Result<(), String> {
        let existing = self.show_default(iface)?;

        // More than one default route on a single interface only happens
        // if something already installed a duplicate -- including an
        // earlier nixnet, whose `replace` at a fresh metric added rather
        // than moved. The one the kernel is *using* is the lowest-metric
        // one, so that is the route whose gateway is authoritative; the
        // rest are cleaned up below along with the original.
        let chosen = match existing.iter().min_by_key(|r| r.metric()) {
            Some(r) => r,
            None => {
                return Err(format!(
                    "no default route on dev {} to reprioritize -- nixnet only \
                     reprioritizes routes the OS/DHCP established, it never \
                     creates one",
                    iface
                ))
            }
        };

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
        self.run(&args)?;

        let mut first_err: Option<String> = None;
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
                if first_err.is_none() {
                    first_err = Some(e);
                }
                // Keep going for the same reason `apply` does: a leftover
                // duplicate on one metric shouldn't stop the others from
                // being cleared.
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
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
mod tests {
    use super::*;
    use std::path::Path;

    /// Writes a stand-in `ip` into `dir` and returns its path. It appends
    /// its argv to `dir/argv.log` -- one argument per line, a lone `--`
    /// terminating each invocation, which is unambiguous because no
    /// argument nixnet passes is ever itself `--` or contains a newline --
    /// and answers a `route show` with the canned contents of
    /// `dir/show-<iface>.json`, or `[]` when that file is absent. If
    /// `dir/fail-replace` exists, every `route replace` exits non-zero,
    /// which is how the "don't delete what we failed to supersede"
    /// invariant gets exercised without a routing table.
    fn fake_ip(dir: &Path) -> String {
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
        // The script is written by a *child* process rather than by this
        // one, and that detail is load-bearing. libtest runs these tests on
        // threads while other tests in the crate fork their own
        // subprocesses; a child forked while this thread holds a writable
        // fd on the script inherits that fd, and exec'ing the script then
        // fails with ETXTBSY, "Text file busy", until that child reaches
        // its own exec (rust-lang/rust#39745 -- reproduced here, roughly
        // one full-suite run in three). Handing the text to `sh` on stdin
        // instead keeps the only writable fd inside a process nothing else
        // can fork from, so once it exits the inode has no writer anywhere
        // and every exec below is race-free.
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

    fn canned_route(dir: &Path, iface: &str, json: &str) {
        std::fs::write(dir.join(format!("show-{}.json", iface)), json).unwrap();
    }

    /// One expected argv, written the way an operator would type the
    /// command. Safe to split on spaces because no argument nixnet passes
    /// contains one.
    fn argv(line: &str) -> Vec<String> {
        line.split(' ').map(String::from).collect()
    }

    /// The recorded argv of every `ip` invocation, in order.
    fn invocations(dir: &Path) -> Vec<Vec<String>> {
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

    fn ranked(ifaces: &[&str]) -> Vec<RankedInterface> {
        ifaces
            .iter()
            .map(|i| RankedInterface {
                interface: i.to_string(),
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

        rp.apply(&ranked(&["eth0"]), 100, 50).unwrap();

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

        rp.apply(&ranked(&["wwan0"]), 100, 50).unwrap();

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

        let err = rp.apply(&ranked(&["eth9"]), 100, 50).unwrap_err();

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

    #[test]
    fn a_route_already_at_the_target_metric_is_not_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let rp = RoutePublisher {
            ip_path: fake_ip(dir.path()),
        };
        canned_route(
            dir.path(),
            "eth0",
            r#"[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":100,"flags":[]}]"#,
        );

        rp.apply(&ranked(&["eth0"]), 100, 50).unwrap();

        assert_eq!(
            invocations(dir.path()),
            vec![
                argv("-j route show default dev eth0"),
                argv("route replace default via 10.0.0.1 dev eth0 metric 100"),
            ],
            "deleting metric 100 here would delete the route just installed"
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

        rp.apply(&ranked(&["eth0", "wlan0"]), 100, 50).unwrap();

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

        let err = rp.apply(&ranked(&["eth0"]), 100, 50).unwrap_err();

        assert!(
            err.to_string().contains("Network is unreachable"),
            "unexpected error text: {}",
            err
        );
        assert_eq!(
            invocations(dir.path()).len(),
            2,
            "show + the failed replace, and no del: {:?}",
            invocations(dir.path())
        );
    }
}
