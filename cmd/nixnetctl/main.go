// Command nixnetctl is a thin formatter over /run/nixnet/status.json. It
// never talks to nixnetd over a socket — there isn't one; reading the file
// is enough, and keeps the daemon's listening surface at zero (design.md
// §5.3).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/julian-corbet/nixnet-corbet-ch/internal/status"
)

func main() {
	statusPath := flag.String("status-file", "/run/nixnet/status.json", "path to nixnetd's status.json")
	asJSON := flag.Bool("json", false, "print the raw status.json instead of a formatted table")
	flag.Parse()

	snap, err := status.Read(*statusPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixnetctl: reading %s: %v\n", *statusPath, err)
		fmt.Fprintln(os.Stderr, "nixnetctl: is nixnetd running? (systemctl status nixnetd)")
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snap)
		return
	}

	fmt.Printf("nixnet status as of %s\n", snap.GeneratedAt)
	printGroups("peers", snap.Peers)
	printGroups("uplinks", snap.Uplinks)
}

func printGroups(label string, groups map[string]status.Group) {
	if len(groups) == 0 {
		return
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Printf("\n%s:\n", label)
	for _, name := range names {
		g := groups[name]
		degraded := ""
		if g.Degraded {
			degraded = "  [DEGRADED]"
		}
		winner := g.Winner
		if winner == "" {
			winner = "(none)"
		}
		fmt.Printf("  %-20s winner=%-16s since=%s%s\n", name, winner, orDash(g.Since), degraded)

		transportNames := make([]string, 0, len(g.Transports))
		for t := range g.Transports {
			transportNames = append(transportNames, t)
		}
		sort.Strings(transportNames)
		for _, t := range transportNames {
			tr := g.Transports[t]
			fmt.Printf("      %-30s %-8s %s\n", t, tr.State, tr.Detail)
		}
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
