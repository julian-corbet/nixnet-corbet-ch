//! Route-metric reprioritization for uplinks. Never creates a route, never
//! touches any field but `metric`, never removes a route.

use std::fmt;
use std::process::Command;

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

impl RoutePublisher {
    /// Issues one `ip route replace default dev <iface> metric <n>` per
    /// candidate, winner first at `metric_base`, each subsequent one
    /// `metric_step` higher. Only currently-healthy candidates are
    /// touched -- a transport that's Down keeps whatever metric it last
    /// had, since nixnet never removes a route, only reprioritizes ones
    /// that exist. Keeps going even if one candidate's command fails
    /// (interface just disappeared, etc.) -- collects and returns only the
    /// *first* error encountered, after attempting every candidate.
    pub fn apply(
        &self,
        candidates: &[RankedInterface],
        metric_base: i64,
        metric_step: i64,
    ) -> Result<(), RouteError> {
        let ip_path = if self.ip_path.is_empty() {
            "ip"
        } else {
            &self.ip_path
        };
        let mut first_err: Option<RouteError> = None;
        for (i, c) in candidates.iter().enumerate() {
            let metric = metric_base + (i as i64) * metric_step;
            let output = Command::new(ip_path)
                .args([
                    "route",
                    "replace",
                    "default",
                    "dev",
                    &c.interface,
                    "metric",
                    &metric.to_string(),
                ])
                .output();
            let failed = match &output {
                Ok(out) if out.status.success() => None,
                Ok(out) => Some(format!(
                    "ip route replace default dev {} metric {}: exit {} ({}{})",
                    c.interface,
                    metric,
                    out.status,
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )),
                Err(e) => Some(format!(
                    "ip route replace default dev {} metric {}: {}",
                    c.interface, metric, e
                )),
            };
            if let Some(msg) = failed {
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
}
