//! Command nixnetctl is a thin formatter over `/run/nixnet/status.json`.
//! It never talks to nixnetd over a socket -- there isn't one; reading the
//! file is enough, and keeps the daemon's listening surface at zero
//! sockets.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use nixnet::status;

fn main() -> ExitCode {
    let (status_path, as_json) = match parse_args() {
        Ok(v) => v,
        Err(code) => return code,
    };

    let snap = match status::read(&status_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nixnetctl: reading {}: {}", status_path.display(), e);
            eprintln!("nixnetctl: is nixnetd running? (systemctl status nixnetd)");
            return ExitCode::FAILURE;
        }
    };

    if as_json {
        match serde_json::to_string_pretty(&snap) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("nixnetctl: encoding status: {}", e);
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
    }

    println!("nixnet status as of {}", snap.generated_at);
    print_groups("peers", &snap.peers);
    print_groups("uplinks", &snap.uplinks);
    ExitCode::SUCCESS
}

fn parse_args() -> Result<(PathBuf, bool), ExitCode> {
    let mut status_path = PathBuf::from("/run/nixnet/status.json");
    let mut as_json = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-status-file" | "--status-file" => match args.next() {
                Some(v) => status_path = PathBuf::from(v),
                None => {
                    eprintln!("nixnetctl: -status-file requires a value");
                    return Err(ExitCode::from(2));
                }
            },
            "-json" | "--json" => as_json = true,
            "-h" | "--help" => {
                eprintln!("usage: nixnetctl [-status-file PATH] [-json]");
                return Err(ExitCode::SUCCESS);
            }
            s if s.starts_with("-status-file=") || s.starts_with("--status-file=") => {
                let v = s.split_once('=').map(|(_, v)| v).unwrap_or_default();
                status_path = PathBuf::from(v);
            }
            other => {
                eprintln!("nixnetctl: unknown flag {}", other);
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok((status_path, as_json))
}

fn print_groups(label: &str, groups: &HashMap<String, status::Group>) {
    if groups.is_empty() {
        return;
    }
    let mut names: Vec<&String> = groups.keys().collect();
    names.sort();

    println!("\n{}:", label);
    for name in names {
        let g = &groups[name];
        let degraded = if g.degraded { "  [DEGRADED]" } else { "" };
        let winner = if g.winner.is_empty() {
            "(none)"
        } else {
            g.winner.as_str()
        };
        println!(
            "  {:<20} winner={:<16} since={}{}",
            name,
            winner,
            or_dash(&g.since),
            degraded
        );

        let mut transport_names: Vec<&String> = g.transports.keys().collect();
        transport_names.sort();
        for t in transport_names {
            let tr = &g.transports[t];
            println!("      {:<30} {:<8} {}", t, tr.state, tr.detail);
        }
    }
}

fn or_dash(s: &str) -> &str {
    if s.trim().is_empty() {
        "-"
    } else {
        s
    }
}
