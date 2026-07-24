// Package engine implements nixnet's per-transport health state machine and
// per-group winner selection — design.md §4. One goroutine per transport,
// its own ticker (§1: "a slow/hung probe never delays another"); all
// shared state behind one mutex, matching the architecture diagram's
// "mutex-guarded in-memory health table" (this workload ticks in seconds,
// not microseconds — one coarse lock is simpler than per-transport locks
// and costs nothing observable here).
package engine

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/julian-corbet/nixnet-corbet-ch/internal/config"
	"github.com/julian-corbet/nixnet-corbet-ch/internal/probe"
	"github.com/julian-corbet/nixnet-corbet-ch/internal/publish"
	"github.com/julian-corbet/nixnet-corbet-ch/internal/status"
)

type TransportState string

const (
	StateUnknown TransportState = "unknown"
	StateUp      TransportState = "up"
	StateDown    TransportState = "down"
)

type groupKind string

const (
	kindPeer   groupKind = "peer"
	kindUplink groupKind = "uplink"
)

type transportRuntime struct {
	spec    config.Transport
	id      string // human-readable id for logs/status, e.g. "peer/host-b#0(lan)"
	groupID string

	state              TransportState
	consecutiveSuccess int
	consecutiveFailure int
	currentAddress     string
	detail             string
}

type group struct {
	kind   groupKind
	name   string
	peer   *config.Peer   // set iff kind == kindPeer
	uplink *config.Uplink // set iff kind == kindUplink

	transports []*transportRuntime

	winner            int // index into transports; -1 == no winner
	winnerSince       time.Time
	degraded          bool
	lastPublishedAddr string // peers only: what's currently actually in /run/nixnet/hosts for this peer ("" == not published)
}

func (g *group) minHoldMs() int {
	if g.kind == kindPeer {
		return g.peer.Hysteresis.MinHoldMs
	}
	return g.uplink.Hysteresis.MinHoldMs
}

// Engine ties the config, in-memory health table, and publish backends
// together.
type Engine struct {
	cfg    *config.Config
	logger *log.Logger

	hosts  *publish.HostsPublisher
	routes *publish.RoutePublisher

	statusPath string
	statePath  string

	mu      sync.Mutex
	peers   map[string]*group
	uplinks map[string]*group
}

// New builds an Engine from cfg. Transport goroutines are not started
// until Run.
func New(cfg *config.Config, hosts *publish.HostsPublisher, routes *publish.RoutePublisher, statusPath, statePath string, logger *log.Logger) *Engine {
	e := &Engine{
		cfg:        cfg,
		logger:     logger,
		hosts:      hosts,
		routes:     routes,
		statusPath: statusPath,
		statePath:  statePath,
		peers:      map[string]*group{},
		uplinks:    map[string]*group{},
	}

	for name, p := range cfg.Peers {
		p := p
		g := &group{kind: kindPeer, name: name, peer: &p, winner: -1}
		for i, t := range p.Transports {
			g.transports = append(g.transports, &transportRuntime{
				spec:    t,
				id:      transportID(kindPeer, name, i, t),
				groupID: string(kindPeer) + ":" + name,
				state:   StateUnknown,
			})
		}
		e.peers[name] = g
	}

	for name, u := range cfg.Uplinks {
		u := u
		g := &group{kind: kindUplink, name: name, uplink: &u, winner: -1}
		for i, t := range u.Transports {
			g.transports = append(g.transports, &transportRuntime{
				spec:    t,
				id:      transportID(kindUplink, name, i, t),
				groupID: string(kindUplink) + ":" + name,
				state:   StateUnknown,
			})
		}
		e.uplinks[name] = g
	}

	e.loadState()
	return e
}

// transportID derives a stable, readable log/status identifier. Transport
// identity itself is the list position (index) — the design document
// doesn't give transports a name field, only the observability-only
// providerId — so reordering a transports list in Nix is equivalent to
// removing and re-adding entries; see docs/providers.md's "Deviation:
// transport identity" note.
func transportID(kind groupKind, groupName string, idx int, t config.Transport) string {
	label := t.ProviderID
	if label == "" {
		label = t.Interface
	}
	if label == "" {
		label = t.Address
	}
	if label == "" {
		label = "?"
	}
	return string(kind) + "/" + groupName + "#" + itoa(idx) + "(" + label + ")"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// Run starts one goroutine per transport and blocks until ctx is
// cancelled. It always returns nil (probe/publish errors are logged and
// reflected in status.json, never fatal to the daemon itself — a
// single bad transport must never take the whole daemon down).
func (e *Engine) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	all := func(groups map[string]*group) {
		for _, g := range groups {
			for _, tr := range g.transports {
				wg.Add(1)
				go func(g *group, tr *transportRuntime) {
					defer wg.Done()
					e.runTransport(ctx, g, tr)
				}(g, tr)
			}
		}
	}
	all(e.peers)
	all(e.uplinks)

	// Publish an initial status snapshot immediately, so nixnetctl has
	// something sane to read even before the first probe tick completes.
	e.writeStatus()

	wg.Wait()
	return nil
}

func (e *Engine) runTransport(ctx context.Context, g *group, tr *transportRuntime) {
	interval := time.Duration(tr.spec.Probe.IntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = 3 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		e.probeOnce(ctx, g, tr)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Engine) probeOnce(ctx context.Context, g *group, tr *transportRuntime) {
	res, err := probe.Run(ctx, tr.spec)
	if err != nil {
		e.logger.Printf("transport=%s probe misconfigured: %v", tr.id, err)
		res = probe.Result{Healthy: false, Detail: err.Error()}
	}

	e.mu.Lock()
	oldState := tr.state
	if res.Healthy {
		tr.consecutiveFailure = 0
		tr.consecutiveSuccess++
		if tr.state != StateUp && tr.consecutiveSuccess >= threshold(tr.spec.Probe.UpThreshold, 2) {
			tr.state = StateUp
		}
	} else {
		tr.consecutiveSuccess = 0
		tr.consecutiveFailure++
		if tr.state != StateDown && tr.consecutiveFailure >= threshold(tr.spec.Probe.DownThreshold, 3) {
			tr.state = StateDown
		}
	}
	if res.Address != "" {
		tr.currentAddress = res.Address
	} else if tr.currentAddress == "" {
		tr.currentAddress = tr.spec.Address
	}
	tr.detail = res.Detail
	newState := tr.state
	transitionCount := 0
	if newState != oldState {
		if newState == StateUp {
			transitionCount = tr.consecutiveSuccess
		} else if newState == StateDown {
			transitionCount = tr.consecutiveFailure
		}
	}

	e.reconcileLocked(g)
	e.saveStateLocked()
	e.mu.Unlock()

	if newState != oldState {
		e.logger.Printf("transport=%s state=%s->%s after=%d detail=%q", tr.id, oldState, newState, transitionCount, tr.detail)
	}

	e.writeStatus()
}

func threshold(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

type candidate struct {
	idx      int
	priority int
}

// reconcileLocked implements design.md §4.2's winner-selection algorithm,
// plus one documented extension. Callers must hold e.mu.
func (e *Engine) reconcileLocked(g *group) {
	var candidates []candidate
	for i, tr := range g.transports {
		if tr.state == StateUp {
			candidates = append(candidates, candidate{idx: i, priority: tr.spec.Priority})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].priority < candidates[j].priority })

	now := time.Now()

	if len(candidates) == 0 {
		wasDegraded := g.degraded
		g.degraded = true
		if !wasDegraded {
			e.logger.Printf("group=%s DEGRADED: all transports down", g.groupLabel())
		}
		if g.kind == kindPeer && g.peer.OnAllDown == config.OnAllDownUnpublish && g.winner != -1 {
			g.winner = -1
			g.lastPublishedAddr = ""
			e.publishPeersLocked()
		}
		// uplinks, and lastKnownGood peers: leave the last winner/route
		// exactly as it was — deliberately no publish() call at all.
		return
	}

	if g.degraded {
		g.degraded = false
		e.logger.Printf("group=%s RECOVERED: at least one transport is up again", g.groupLabel())
	}

	bestPriority := candidates[0].priority
	newWinner := candidates[0].idx
	if g.winner != -1 {
		for _, c := range candidates {
			if c.priority == bestPriority && c.idx == g.winner {
				newWinner = g.winner // ties: keep the current winner if it's among them
				break
			}
		}
	}

	winnerChanged := newWinner != g.winner

	if winnerChanged && g.winner != -1 && g.transports[g.winner].state == StateUp {
		// The current winner is still healthy — this is "a strictly
		// better option appeared," not a failover. Damp it via minHold,
		// UNLESS the hold window has already elapsed. The hold is never
		// applied when the current winner just went Down (handled
		// implicitly: that branch has g.transports[g.winner].state !=
		// StateUp, so this whole condition is false and we switch
		// immediately).
		minHold := time.Duration(g.minHoldMs()) * time.Millisecond
		if now.Sub(g.winnerSince) < minHold {
			winnerChanged = false
			newWinner = g.winner
		}
	}

	addressDrift := false
	if !winnerChanged && g.winner != -1 && g.kind == kindPeer {
		// Extension beyond the literal §4.2 pseudocode: republish when the
		// CURRENT winner's own dynamically-discovered address changes,
		// even with no winner-index change at all. Taken literally, §4.2
		// only republishes on a winner-index change, which would silently
		// break the entire "dynamic address source" feature (§6.2) for
		// any provider whose winning transport's address moves (e.g.
		// netbird-provider re-enrolling with a new overlay IP after
		// reprovisioning) — see docs/providers.md's "Deviation:
		// address-drift republish" note.
		addr := g.transports[newWinner].currentAddress
		if addr != "" && addr != g.lastPublishedAddr {
			addressDrift = true
		}
	}

	if !winnerChanged && !addressDrift {
		return
	}

	if winnerChanged {
		g.winner = newWinner
		g.winnerSince = now
		e.logger.Printf("group=%s winner-change new=%s", g.groupLabel(), g.transports[newWinner].id)
	}

	switch g.kind {
	case kindPeer:
		g.lastPublishedAddr = g.transports[g.winner].currentAddress
		e.publishPeersLocked()
	case kindUplink:
		e.publishUplinkLocked(g, candidates)
	}
}

func (g *group) groupLabel() string {
	return string(g.kind) + "=" + g.name
}

// publishPeersLocked rewrites the whole managed hosts block from every
// peer group's current lastPublishedAddr (not just the group that just
// changed) — the publish backend is a single shared file, so any change
// requires re-rendering the entire block. Callers must hold e.mu.
func (e *Engine) publishPeersLocked() {
	var entries []publish.Entry
	for _, g := range e.peers {
		if g.lastPublishedAddr == "" {
			continue
		}
		entries = append(entries, publish.Entry{
			Address:   g.lastPublishedAddr,
			Hostnames: g.peer.Hostnames,
		})
	}
	if err := e.hosts.Publish(entries); err != nil {
		e.logger.Printf("publish hosts: %v", err)
	}
}

// publishUplinkLocked reprioritizes route metrics: winner first at
// metricBase, then every other currently-healthy candidate in priority
// order. Callers must hold e.mu.
func (e *Engine) publishUplinkLocked(g *group, candidates []candidate) {
	if !g.uplink.Publish.RouteMetric {
		return
	}
	ranked := make([]publish.RankedInterface, 0, len(candidates))
	ranked = append(ranked, publish.RankedInterface{Interface: g.transports[g.winner].spec.Interface})
	for _, c := range candidates {
		if c.idx == g.winner {
			continue
		}
		ranked = append(ranked, publish.RankedInterface{Interface: g.transports[c.idx].spec.Interface})
	}
	if err := e.routes.Apply(ranked, g.uplink.Publish.MetricBase, g.uplink.Publish.MetricStep); err != nil {
		e.logger.Printf("publish routes for group=%s: %v", g.groupLabel(), err)
	}
}

// writeStatus renders /run/nixnet/status.json — design.md §5.3, "every
// tick, regardless of whether anything changed."
func (e *Engine) writeStatus() {
	e.mu.Lock()
	snap := status.Snapshot{
		Peers:   map[string]status.Group{},
		Uplinks: map[string]status.Group{},
	}
	render := func(g *group) status.Group {
		sg := status.Group{Degraded: g.degraded, Transports: map[string]status.Transport{}}
		if g.winner != -1 {
			sg.Winner = winnerLabel(g)
			sg.Since = g.winnerSince.UTC().Format(time.RFC3339)
		}
		for _, tr := range g.transports {
			sg.Transports[tr.id] = status.Transport{State: string(tr.state), Detail: tr.detail}
		}
		return sg
	}
	for name, g := range e.peers {
		snap.Peers[name] = render(g)
	}
	for name, g := range e.uplinks {
		snap.Uplinks[name] = render(g)
	}
	e.mu.Unlock()

	if err := status.Write(e.statusPath, snap); err != nil {
		e.logger.Printf("write status: %v", err)
	}
}

func winnerLabel(g *group) string {
	if g.winner < 0 || g.winner >= len(g.transports) {
		return ""
	}
	if g.kind == kindPeer {
		return g.lastPublishedAddr
	}
	return g.transports[g.winner].spec.Interface
}
