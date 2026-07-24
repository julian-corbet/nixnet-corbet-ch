package publish

import (
	"fmt"
	"os/exec"
	"strconv"
)

// RoutePublisher reprioritizes metrics on default routes the OS/DHCP
// already established. It never creates a route and never touches any
// field but metric (design.md §5.2).
type RoutePublisher struct {
	// IPPath is the absolute (Nix-store-resolved) path to the `ip`
	// binary. This is the one narrow, well-tested exec design.md §1's
	// rationale table calls out as an acceptable exception to "no PATH
	// dependency" — resolved once at Nix build time, not looked up on
	// PATH at run time (falls back to "ip" only for the non-Nix,
	// hand-written-config path).
	IPPath string
}

// RankedInterface is one currently-healthy candidate, already in
// priority order (lowest priority number first == most preferred).
type RankedInterface struct {
	Interface string
}

// Apply issues one `ip route replace default dev <iface> metric <n>` per
// candidate, winner first at metricBase, each subsequent one metricStep
// higher. Only currently-healthy candidates are touched — a transport
// that's Down keeps whatever metric it last had, since nixnet never
// removes a route, only reprioritizes ones that exist.
func (r *RoutePublisher) Apply(candidates []RankedInterface, metricBase, metricStep int) error {
	ipPath := r.IPPath
	if ipPath == "" {
		ipPath = "ip"
	}
	var firstErr error
	for i, c := range candidates {
		metric := metricBase + i*metricStep
		cmd := exec.Command(ipPath, "route", "replace", "default", "dev", c.Interface, "metric", strconv.Itoa(metric))
		if out, err := cmd.CombinedOutput(); err != nil {
			wrapped := fmt.Errorf("ip route replace default dev %s metric %d: %w (%s)", c.Interface, metric, err, string(out))
			if firstErr == nil {
				firstErr = wrapped
			}
			// Keep going: one interface's route command failing (e.g. the
			// interface just disappeared) shouldn't stop the others from
			// being reprioritized correctly.
		}
	}
	return firstErr
}
