//! nixnet's shared library crate. `nixnetd` (the resident daemon,
//! `src/bin/nixnetd.rs`) and `nixnetctl` (the status CLI,
//! `src/bin/nixnetctl.rs`) are both thin mains over the modules here --
//! the same shape as the original Go layout's `cmd/nixnetd` +
//! `cmd/nixnetctl` over `internal/*`.

pub mod atomic;
pub mod config;
pub mod engine;
pub mod logging;
pub mod probe;
pub mod publish;
pub mod sdnotify;
pub mod shutdown;
pub mod status;
