package engine

import (
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/julian-corbet/nixnet-corbet-ch/internal/config"
	"github.com/julian-corbet/nixnet-corbet-ch/internal/publish"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	hosts, err := publish.NewHostsPublisher(filepath.Join(dir, "hosts"))
	if err != nil {
		t.Fatalf("NewHostsPublisher: %v", err)
	}
	routes := &publish.RoutePublisher{IPPath: "/bin/true"} // never actually mutate routing in a test
	logger := log.New(os.Stderr, "test: ", 0)
	return &Engine{
		hosts:      hosts,
		routes:     routes,
		statusPath: filepath.Join(dir, "status.json"),
		statePath:  filepath.Join(dir, "state.json"),
		logger:     logger,
		peers:      map[string]*group{},
		uplinks:    map[string]*group{},
	}
}

func newPeerGroup(name string, minHoldMs int, onAllDown string) *group {
	peer := &config.Peer{
		Hostnames:  []string{name},
		Hysteresis: config.Hysteresis{MinHoldMs: minHoldMs},
		OnAllDown:  onAllDown,
	}
	return &group{kind: kindPeer, name: name, peer: peer, winner: -1}
}

// addTransport mirrors the real invariant probeOnce() maintains: every
// transport's currentAddress is populated before reconcileLocked ever
// looks at it (falling back to spec.Address when a probe result carries
// no dynamic override). Tests that specifically exercise a *changing*
// dynamic address (e.g. TestReconcile_AddressDriftRepublishesWithoutWinnerChange)
// mutate tr.currentAddress directly afterward.
func addTransport(g *group, priority int, address string) *transportRuntime {
	tr := &transportRuntime{
		spec:           config.Transport{Priority: priority, Address: address},
		id:             address,
		state:          StateUnknown,
		currentAddress: address,
	}
	g.transports = append(g.transports, tr)
	return tr
}

// TestReconcile_PicksLowestPriorityHealthy exercises design.md §4.2's core
// winner-selection rule: among currently-healthy candidates, lowest
// priority number wins.
func TestReconcile_PicksLowestPriorityHealthy(t *testing.T) {
	e := newTestEngine(t)
	// minHoldMs = 0: this test is about priority selection, not damping
	// (that's TestReconcile_HysteresisDampsBetterOption's job) -- with a
	// non-zero hold, "a better option appearing while the winner is still
	// healthy" is correctly damped, which would make this test's second
	// assertion fail for the *right* reason but the *wrong* test.
	g := newPeerGroup("host-b", 0, config.OnAllDownLastKnownGood)
	lowPrio := addTransport(g, 10, "192.0.2.10")  // more preferred (lower number)
	highPrio := addTransport(g, 50, "192.0.2.20") // less preferred
	e.peers["host-b"] = g

	e.mu.Lock()
	highPrio.state = StateUp
	e.reconcileLocked(g)
	e.mu.Unlock()

	if g.winner != 1 {
		t.Fatalf("winner index = %d, want 1 (the only healthy transport)", g.winner)
	}
	if g.lastPublishedAddr != "192.0.2.20" {
		t.Fatalf("lastPublishedAddr = %q, want 192.0.2.20", g.lastPublishedAddr)
	}

	e.mu.Lock()
	lowPrio.state = StateUp
	e.reconcileLocked(g)
	e.mu.Unlock()

	if g.winner != 0 {
		t.Fatalf("winner index = %d, want 0 (lower priority number should win once healthy)", g.winner)
	}
}

// TestReconcile_HysteresisDampsBetterOption exercises design.md §4.2's
// minHold damping: a strictly-better (lower priority number) option
// becoming healthy while the CURRENT winner is still healthy must NOT
// switch the winner until minHoldMs has elapsed since winnerSince.
func TestReconcile_HysteresisDampsBetterOption(t *testing.T) {
	e := newTestEngine(t)
	g := newPeerGroup("host-b", 10_000, config.OnAllDownLastKnownGood) // 10s hold
	worse := addTransport(g, 50, "192.0.2.20")
	better := addTransport(g, 10, "192.0.2.10")
	e.peers["host-b"] = g

	e.mu.Lock()
	worse.state = StateUp
	e.reconcileLocked(g)
	e.mu.Unlock()
	if g.winner != 0 {
		t.Fatalf("winner index = %d, want 0 (worse) before better appears", g.winner)
	}

	// Better option appears immediately after — still well inside the 10s
	// hold window, so it must NOT take over yet.
	e.mu.Lock()
	better.state = StateUp
	e.reconcileLocked(g)
	e.mu.Unlock()
	if g.winner != 0 {
		t.Fatalf("winner index = %d, want 0 (damped: hold window not elapsed)", g.winner)
	}

	// Simulate the hold window having elapsed.
	e.mu.Lock()
	g.winnerSince = time.Now().Add(-11 * time.Second)
	e.reconcileLocked(g)
	e.mu.Unlock()
	if g.winner != 1 {
		t.Fatalf("winner index = %d, want 1 (better) once the hold window elapses", g.winner)
	}
}

// TestReconcile_DeadWinnerSwitchesImmediately exercises the explicit
// design.md §4.2 carve-out: minHold is never applied when the CURRENT
// winner itself just went Down — a dead winner is never held onto to
// satisfy a hold timer, even a second after it became the winner.
func TestReconcile_DeadWinnerSwitchesImmediately(t *testing.T) {
	e := newTestEngine(t)
	g := newPeerGroup("host-b", 10_000, config.OnAllDownLastKnownGood)
	primary := addTransport(g, 10, "192.0.2.10")
	fallback := addTransport(g, 50, "192.0.2.20")
	e.peers["host-b"] = g

	e.mu.Lock()
	primary.state = StateUp
	fallback.state = StateUp
	e.reconcileLocked(g)
	e.mu.Unlock()
	if g.winner != 0 {
		t.Fatalf("winner index = %d, want 0 (primary)", g.winner)
	}
	winnerSince := g.winnerSince

	// primary dies a moment later -- well inside what would otherwise be
	// the 10s hold window.
	e.mu.Lock()
	primary.state = StateDown
	e.reconcileLocked(g)
	e.mu.Unlock()

	if g.winner != 1 {
		t.Fatalf("winner index = %d, want 1 (fallback) -- a dead winner must switch immediately, no hold", g.winner)
	}
	if !g.winnerSince.After(winnerSince) {
		t.Errorf("winnerSince did not advance on failover")
	}
}

// TestReconcile_OnAllDownLastKnownGood exercises design.md §4.3: when
// every transport is down and onAllDown = "lastKnownGood", the group is
// marked degraded but the previously-published address is left alone
// (no unpublish).
func TestReconcile_OnAllDownLastKnownGood(t *testing.T) {
	e := newTestEngine(t)
	g := newPeerGroup("host-b", 10_000, config.OnAllDownLastKnownGood)
	only := addTransport(g, 10, "192.0.2.10")
	e.peers["host-b"] = g

	e.mu.Lock()
	only.state = StateUp
	e.reconcileLocked(g)
	e.mu.Unlock()
	if g.degraded {
		t.Fatalf("degraded = true while a transport is up")
	}

	e.mu.Lock()
	only.state = StateDown
	e.reconcileLocked(g)
	e.mu.Unlock()

	if !g.degraded {
		t.Errorf("degraded = false after all transports went down")
	}
	if g.lastPublishedAddr != "192.0.2.10" {
		t.Errorf("lastPublishedAddr = %q, want 192.0.2.10 (lastKnownGood must not clear it)", g.lastPublishedAddr)
	}
	if g.winner != 0 {
		t.Errorf("winner index = %d, want unchanged 0 (lastKnownGood leaves the winner pointer alone)", g.winner)
	}
}

// TestReconcile_OnAllDownUnpublish exercises the other §4.3 branch: with
// onAllDown = "unpublish", the entry is actually cleared once every
// transport is down.
func TestReconcile_OnAllDownUnpublish(t *testing.T) {
	e := newTestEngine(t)
	g := newPeerGroup("host-b", 10_000, config.OnAllDownUnpublish)
	only := addTransport(g, 10, "192.0.2.10")
	e.peers["host-b"] = g

	e.mu.Lock()
	only.state = StateUp
	e.reconcileLocked(g)
	only.state = StateDown
	e.reconcileLocked(g)
	e.mu.Unlock()

	if g.lastPublishedAddr != "" {
		t.Errorf("lastPublishedAddr = %q, want empty (unpublish must clear it)", g.lastPublishedAddr)
	}
	if g.winner != -1 {
		t.Errorf("winner index = %d, want -1 (unpublish clears the winner too)", g.winner)
	}
}

// TestReconcile_AddressDriftRepublishesWithoutWinnerChange covers the
// documented extension beyond a literal reading of §4.2 -- see
// docs/providers.md's "Deviation: address-drift republish" note. A
// provider's exec probe changing the WINNING transport's own address,
// with no winner-index change at all, must still update
// lastPublishedAddr.
func TestReconcile_AddressDriftRepublishesWithoutWinnerChange(t *testing.T) {
	e := newTestEngine(t)
	g := newPeerGroup("host-b", 10_000, config.OnAllDownLastKnownGood)
	tr := addTransport(g, 10, "203.0.113.5")
	tr.spec.ProviderID = "netbird"
	e.peers["host-b"] = g

	e.mu.Lock()
	tr.state = StateUp
	tr.currentAddress = "203.0.113.5"
	e.reconcileLocked(g)
	e.mu.Unlock()
	if g.lastPublishedAddr != "203.0.113.5" {
		t.Fatalf("lastPublishedAddr = %q, want 203.0.113.5", g.lastPublishedAddr)
	}
	winnerBefore := g.winner

	// The provider re-enrolls and gets handed a new overlay IP. State
	// stays Up throughout -- no transition, no winner-index change.
	e.mu.Lock()
	tr.currentAddress = "203.0.113.99"
	e.reconcileLocked(g)
	e.mu.Unlock()

	if g.winner != winnerBefore {
		t.Fatalf("winner index changed (%d -> %d) -- it shouldn't have, this is the same transport", winnerBefore, g.winner)
	}
	if g.lastPublishedAddr != "203.0.113.99" {
		t.Errorf("lastPublishedAddr = %q, want 203.0.113.99 (address drift on the unchanged winner must still republish)", g.lastPublishedAddr)
	}
}
