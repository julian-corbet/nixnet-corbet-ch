//! The two publish backends: a managed `/etc/hosts` block for peers
//! (`hosts`) and route-metric reprioritization for uplinks (`route`).
//! Two independent backends because peers publish an *address* (consumed
//! by ordinary NSS hostname resolution) while uplinks publish a *route
//! priority* (consumed by the kernel routing table) -- different
//! consumers, different mechanisms, same upstream "one deterministic
//! winner" abstraction.

mod hosts;
// `pub(crate)` only so the engine's tests can reach the recording stand-in
// `ip` this module's tests already own -- TF-2 is a claim about which ticks
// reach the publisher, and proving it needs the publisher's own harness.
pub(crate) mod route;

#[allow(unused_imports)]
pub use hosts::parse_nix_hosts;
pub use hosts::{Entry, HostsPublisher};
pub use route::{Publication, RankedInterface, RouteChange, RoutePublisher};
