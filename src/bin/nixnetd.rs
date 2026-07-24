//! Command nixnetd is nixnet's resident health-check + publish daemon.
//!
//! nixnetd is entirely Nix-unaware: it reads one JSON config file and
//! writes JSON/text elsewhere. It never links against, shells out to, or
//! otherwise depends on Nix at runtime.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use nixnet::engine::Engine;
use nixnet::shutdown::Shutdown;
use nixnet::{config, logf, publish, sdnotify};

fn main() -> ExitCode {
    let config_path = match parse_args() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = run(&config_path) {
        logf!("nixnetd: {}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Hand-rolled rather than pulling in a CLI-parsing crate: nixnetd only
/// ever has this one flag, and this keeps the exact `-config PATH` /
/// `-config=PATH` syntax `modules/core.nix`'s `ExecStart` line already
/// hardcodes (mirroring Go's `flag` package, which treats a single dash
/// and a double dash identically).
fn parse_args() -> Result<PathBuf, ExitCode> {
    let mut config_path = PathBuf::from("/etc/nixnet/config.json");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-config" | "--config" => match args.next() {
                Some(v) => config_path = PathBuf::from(v),
                None => {
                    eprintln!("nixnetd: -config requires a value");
                    return Err(ExitCode::from(2));
                }
            },
            "-h" | "--help" => {
                eprintln!("usage: nixnetd [-config PATH]");
                return Err(ExitCode::SUCCESS);
            }
            s if s.starts_with("-config=") || s.starts_with("--config=") => {
                let v = s.split_once('=').map(|(_, v)| v).unwrap_or_default();
                config_path = PathBuf::from(v);
            }
            other => {
                eprintln!("nixnetd: unknown flag {}", other);
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(config_path)
}

fn run(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load(config_path).map_err(|e| format!("loading config: {}", e))?;

    std::fs::create_dir_all(&cfg.daemon.state_dir)
        .map_err(|e| format!("creating state dir: {}", e))?;
    let runtime_dir = format!("/run/{}", cfg.daemon.runtime_dir);
    std::fs::create_dir_all(&runtime_dir).map_err(|e| format!("creating runtime dir: {}", e))?;
    let hosts_dir = Path::new(&cfg.daemon.hosts_file)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    std::fs::create_dir_all(&hosts_dir).map_err(|e| format!("creating hosts file dir: {}", e))?;

    let hosts = publish::HostsPublisher::new(&cfg.daemon.hosts_file)
        .map_err(|e| format!("initializing hosts publisher: {}", e))?;
    let routes = publish::RoutePublisher {
        ip_path: cfg.daemon.ip_path.clone(),
    };

    // status.json lives in the runtime dir proper, independent of
    // wherever hostsFile is configured to point.
    let status_path = PathBuf::from(format!("{}/status.json", runtime_dir));
    let state_path = PathBuf::from(format!("{}/state.json", cfg.daemon.state_dir));

    let peer_count = cfg.peers.len();
    let uplink_count = cfg.uplinks.len();

    let eng = Arc::new(Engine::new(cfg, hosts, routes, status_path, state_path));

    let shutdown = Shutdown::new();
    install_signal_handlers(shutdown.clone())?;

    if let Err(e) = sdnotify::notify("READY=1") {
        logf!(
            "sd_notify READY=1: {} (continuing -- likely not running under systemd)",
            e
        );
    }

    // Watchdog heartbeat: deliberately independent of probe cycles so a
    // wedged event loop still gets caught even if every individual
    // transport's ticker is somehow fine. A separate, cheap thread, not
    // threaded through the engine.
    if let Some(interval) = sdnotify::watchdog_interval() {
        let sd = shutdown.clone();
        std::thread::spawn(move || heartbeat(sd, interval));
    }

    logf!(
        "nixnetd starting: {} peer group(s), {} uplink group(s)",
        peer_count,
        uplink_count
    );
    eng.run(shutdown);
    Ok(())
}

fn heartbeat(shutdown: Shutdown, interval: Duration) {
    loop {
        if shutdown.wait(interval) {
            return;
        }
        if let Err(e) = sdnotify::notify("WATCHDOG=1") {
            logf!("sd_notify WATCHDOG=1: {}", e);
        }
    }
}

/// Replaces Go's `signal.NotifyContext`: a background thread blocks on
/// SIGINT/SIGTERM and triggers `shutdown` the moment either arrives,
/// which every per-transport ticker and the watchdog heartbeat loop are
/// already waiting on via `Shutdown::wait`.
fn install_signal_handlers(shutdown: Shutdown) -> std::io::Result<()> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGINT, SIGTERM])?;
    std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            shutdown.trigger();
        }
    });
    Ok(())
}
