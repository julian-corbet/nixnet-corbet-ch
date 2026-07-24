// Command nixnetd is nixnet's resident health-check + publish daemon.
// See design.md §4 for the algorithm and §2 for the architecture overview.
//
// nixnetd is entirely Nix-unaware: it reads one JSON config file and
// writes JSON/text elsewhere. It never links against, shells out to, or
// otherwise depends on Nix at runtime (design.md §3.3).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/julian-corbet/nixnet-corbet-ch/internal/config"
	"github.com/julian-corbet/nixnet-corbet-ch/internal/engine"
	"github.com/julian-corbet/nixnet-corbet-ch/internal/publish"
	"github.com/julian-corbet/nixnet-corbet-ch/internal/sdnotify"
)

func main() {
	configPath := flag.String("config", "/etc/nixnet/config.json", "path to nixnet's rendered config.json")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)

	if err := run(*configPath, logger); err != nil {
		logger.Fatalf("nixnetd: %v", err)
	}
}

func run(configPath string, logger *log.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := os.MkdirAll(cfg.Daemon.StateDir, 0o750); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}
	runtimeDir := "/run/" + cfg.Daemon.RuntimeDir
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return fmt.Errorf("creating runtime dir: %w", err)
	}
	hostsDir := dirOf(cfg.Daemon.HostsFile)
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		return fmt.Errorf("creating hosts file dir: %w", err)
	}

	hosts, err := publish.NewHostsPublisher(cfg.Daemon.HostsFile)
	if err != nil {
		return fmt.Errorf("initializing hosts publisher: %w", err)
	}
	routes := &publish.RoutePublisher{IPPath: cfg.Daemon.IPPath}

	// status.json lives in the runtime dir proper (design.md §5.3's
	// "/run/nixnet/status.json"), independent of wherever hostsFile is
	// configured to point.
	statusPath := runtimeDir + "/status.json"
	statePath := cfg.Daemon.StateDir + "/state.json"

	eng := engine.New(cfg, hosts, routes, statusPath, statePath, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := sdnotify.Notify("READY=1"); err != nil {
		logger.Printf("sd_notify READY=1: %v (continuing — likely not running under systemd)", err)
	}

	// Watchdog heartbeat: deliberately independent of probe cycles
	// (design.md §4.4) so a wedged event loop still gets caught even if
	// every individual transport's ticker is somehow fine. This is a
	// separate, cheap goroutine, not threaded through the engine.
	if interval := sdnotify.WatchdogInterval(); interval > 0 {
		go heartbeat(ctx, interval, logger)
	}

	logger.Printf("nixnetd starting: %d peer group(s), %d uplink group(s)", len(cfg.Peers), len(cfg.Uplinks))
	return eng.Run(ctx)
}

func heartbeat(ctx context.Context, interval time.Duration, logger *log.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sdnotify.Notify("WATCHDOG=1"); err != nil {
				logger.Printf("sd_notify WATCHDOG=1: %v", err)
			}
		}
	}
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
