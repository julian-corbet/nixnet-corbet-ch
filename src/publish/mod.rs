//! The two publish backends: a managed `/etc/hosts` block for peers
//! (`hosts`) and route-metric reprioritization for uplinks (`route`).
//! Two independent backends because peers publish an *address* (consumed
//! by ordinary NSS hostname resolution) while uplinks publish a *route
//! priority* (consumed by the kernel routing table) -- different
//! consumers, different mechanisms, same upstream "one deterministic
//! winner" abstraction.

mod hosts;
mod route;

#[allow(unused_imports)]
pub use hosts::parse_nix_hosts;
pub use hosts::{Entry, HostsPublisher};
pub use route::{RankedInterface, RoutePublisher};
