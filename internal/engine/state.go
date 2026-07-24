package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// persistedTransport / persistedGroup / persistedState mirror
// /var/lib/nixnet/state.json — the hysteresis counters and last winners
// design.md §4.4 says let "a killed/restarted daemon reconverge[...] with
// no special recovery code path". Loading this at startup is what makes
// that true: without it, a restart would forget every transport's history
// and start every state machine over at Unknown, needlessly re-running the
// up/down thresholds it had already satisfied a moment before.
type persistedTransport struct {
	State              string `json:"state"`
	ConsecutiveSuccess int    `json:"consecutiveSuccess"`
	ConsecutiveFailure int    `json:"consecutiveFailure"`
	Address            string `json:"address,omitempty"`
}

type persistedGroup struct {
	Winner               int                  `json:"winner"` // -1 == none
	WinnerSince          time.Time            `json:"winnerSince"`
	Degraded             bool                 `json:"degraded"`
	LastPublishedAddress string               `json:"lastPublishedAddress,omitempty"`
	Transports           []persistedTransport `json:"transports"`
}

type persistedState struct {
	Peers   map[string]persistedGroup `json:"peers"`
	Uplinks map[string]persistedGroup `json:"uplinks"`
}

// loadState is best-effort by design: a missing or corrupt state.json (first
// boot ever, or a manually-cleared state dir) just means every group starts
// fresh at Unknown/no-winner — never a fatal error.
func (e *Engine) loadState() {
	data, err := os.ReadFile(e.statePath)
	if err != nil {
		return
	}
	var ps persistedState
	if err := json.Unmarshal(data, &ps); err != nil {
		e.logger.Printf("state: ignoring unreadable %s: %v", e.statePath, err)
		return
	}
	restore := func(groups map[string]*group, saved map[string]persistedGroup) {
		for name, g := range groups {
			pg, ok := saved[name]
			if !ok {
				continue
			}
			g.winner = pg.Winner
			if g.winner >= len(g.transports) {
				g.winner = -1 // transports list shrank across a config change
			}
			g.winnerSince = pg.WinnerSince
			g.degraded = pg.Degraded
			g.lastPublishedAddr = pg.LastPublishedAddress
			for i, pt := range pg.Transports {
				if i >= len(g.transports) {
					break
				}
				tr := g.transports[i]
				tr.state = TransportState(pt.State)
				tr.consecutiveSuccess = pt.ConsecutiveSuccess
				tr.consecutiveFailure = pt.ConsecutiveFailure
				tr.currentAddress = pt.Address
			}
		}
	}
	restore(e.peers, ps.Peers)
	restore(e.uplinks, ps.Uplinks)
}

// saveStateLocked writes the full state atomically. Callers must hold e.mu.
func (e *Engine) saveStateLocked() {
	ps := persistedState{
		Peers:   map[string]persistedGroup{},
		Uplinks: map[string]persistedGroup{},
	}
	dump := func(groups map[string]*group) map[string]persistedGroup {
		out := map[string]persistedGroup{}
		for name, g := range groups {
			pg := persistedGroup{
				Winner:               g.winner,
				WinnerSince:          g.winnerSince,
				Degraded:             g.degraded,
				LastPublishedAddress: g.lastPublishedAddr,
			}
			for _, tr := range g.transports {
				pg.Transports = append(pg.Transports, persistedTransport{
					State:              string(tr.state),
					ConsecutiveSuccess: tr.consecutiveSuccess,
					ConsecutiveFailure: tr.consecutiveFailure,
					Address:            tr.currentAddress,
				})
			}
			out[name] = pg
		}
		return out
	}
	ps.Peers = dump(e.peers)
	ps.Uplinks = dump(e.uplinks)

	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		e.logger.Printf("state: marshal failed: %v", err)
		return
	}
	data = append(data, '\n')

	dir := filepath.Dir(e.statePath)
	tmp, err := os.CreateTemp(dir, ".state.json.tmp-*")
	if err != nil {
		e.logger.Printf("state: %v", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		e.logger.Printf("state: write failed: %v", err)
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		e.logger.Printf("state: sync failed: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		e.logger.Printf("state: close failed: %v", err)
		return
	}
	if err := os.Rename(tmpName, e.statePath); err != nil {
		os.Remove(tmpName)
		e.logger.Printf("state: rename failed: %v", err)
	}
}
