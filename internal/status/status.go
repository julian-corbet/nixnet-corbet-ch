// Package status renders /run/nixnet/status.json — the live health
// snapshot nixnetctl reads (design.md §5.3). There is no control socket;
// reading the file directly is sufficient and keeps the daemon's listening
// surface at zero sockets.
package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Transport struct {
	State  string `json:"state"` // "up" | "down" | "unknown"
	Detail string `json:"detail,omitempty"`
}

type Group struct {
	Winner     string               `json:"winner,omitempty"`
	Since      string               `json:"since,omitempty"`
	Degraded   bool                 `json:"degraded"`
	Transports map[string]Transport `json:"transports"`
}

type Snapshot struct {
	GeneratedAt string           `json:"generatedAt"`
	Peers       map[string]Group `json:"peers"`
	Uplinks     map[string]Group `json:"uplinks"`
}

// Write atomically publishes snap to path (design.md §5.1's "write .tmp,
// fsync, rename" discipline applies here too, not just to the hosts file
// — status.json is read by nixnetctl at arbitrary times and must never be
// observed half-written).
func Write(path string, snap Snapshot) error {
	snap.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".status.json.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Read loads a previously-written status.json — used by nixnetctl.
func Read(path string) (Snapshot, error) {
	var snap Snapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return snap, err
	}
	err = json.Unmarshal(data, &snap)
	return snap, err
}
