// Package config loads nixnet's runtime configuration from a JSON file
// (normally /etc/nixnet/config.json, rendered from Nix at build/activation
// time — see modules/core.nix). nixnetd itself is entirely Nix-unaware: it
// only ever reads this JSON file and never has any dependency on Nix, so
// the same binary works from a Nix-rendered config, a hand-written one, or
// a system-manager render. See design.md §3.3.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Probe is the shared health-check descriptor attached to every transport.
// Field names and defaults mirror the `probe` submodule in
// modules/core.nix's transportType exactly.
type Probe struct {
	Method          string `json:"method"`
	Target          string `json:"target,omitempty"`
	Port            int    `json:"port,omitempty"`
	Path            string `json:"path,omitempty"`
	BindToInterface bool   `json:"bindToInterface,omitempty"`
	IntervalMs      int    `json:"intervalMs,omitempty"`
	TimeoutMs       int    `json:"timeoutMs,omitempty"`
	UpThreshold     int    `json:"upThreshold,omitempty"`
	DownThreshold   int    `json:"downThreshold,omitempty"`
	// Exec is a full command line ("<absolute-store-path> arg1 arg2 ..."),
	// not a bare path. See docs/providers.md "Deviation: probe.exec is a
	// command line, not a bare path" for why this departs from the literal
	// `types.path` typing in the design document's §3.1 pseudocode. It is
	// tokenized and exec'd directly (never via a shell), matching the "no
	// PATH dependency" goal system-manager hosts need.
	Exec string `json:"exec,omitempty"`
}

// applyDefaults fills in the handful of fields a hand-written config.json is
// allowed to omit. A Nix-rendered config.json always sets these explicitly
// (modules/core.nix's transportType wires each probe field's own default to
// the matching services.nixnet.daemon.defaultProbe.* value, so this only
// matters for the "hand-written JSON" adoption path §3.3 explicitly
// promises — def is that same daemon.defaultProbe, already defaulted by
// Config.applyDefaults before this is called, so the fallback chain
// mirrors the Nix side field-for-field.
func (p *Probe) applyDefaults(def DefaultProbe) {
	if p.Method == "" {
		p.Method = "tcp"
	}
	if p.Port == 0 {
		p.Port = 22
	}
	if p.Path == "" {
		p.Path = "/"
	}
	if p.IntervalMs == 0 {
		p.IntervalMs = def.IntervalMs
	}
	if p.TimeoutMs == 0 {
		p.TimeoutMs = def.TimeoutMs
	}
	if p.UpThreshold == 0 {
		p.UpThreshold = def.UpThreshold
	}
	if p.DownThreshold == 0 {
		p.DownThreshold = def.DownThreshold
	}
}

// Transport is the one candidate-transport abstraction shared verbatim by
// peers and uplinks (design.md §3.1).
type Transport struct {
	Address    string `json:"address,omitempty"`
	Interface  string `json:"interface,omitempty"`
	Priority   int    `json:"priority"`
	ProviderID string `json:"providerId,omitempty"`
	Probe      Probe  `json:"probe"`
}

// EffectiveTarget returns what should actually be dialed/pinged/exec'd for
// this transport: probe.target if set, else address. A Nix-rendered config
// already resolves this (transportType sets `probe.target = mkDefault
// address` — see modules/core.nix), this is the hand-written-JSON fallback.
func (t *Transport) EffectiveTarget() string {
	if t.Probe.Target != "" {
		return t.Probe.Target
	}
	return t.Address
}

type Hysteresis struct {
	MinHoldMs int `json:"minHoldMs,omitempty"`
}

func (h *Hysteresis) applyDefault(def int) {
	if h.MinHoldMs == 0 {
		h.MinHoldMs = def
	}
}

// OnAllDown values, peers only.
const (
	OnAllDownLastKnownGood = "lastKnownGood"
	OnAllDownUnpublish     = "unpublish"
)

type Peer struct {
	Hostnames  []string    `json:"hostnames"`
	Transports []Transport `json:"transports"`
	Hysteresis Hysteresis  `json:"hysteresis"`
	OnAllDown  string      `json:"onAllDown,omitempty"`
}

type UplinkPublish struct {
	RouteMetric bool `json:"routeMetric"`
	MetricBase  int  `json:"metricBase,omitempty"`
	MetricStep  int  `json:"metricStep,omitempty"`
}

type Uplink struct {
	Transports []Transport   `json:"transports"`
	Hysteresis Hysteresis    `json:"hysteresis"`
	Publish    UplinkPublish `json:"publish"`
}

type DefaultProbe struct {
	IntervalMs    int `json:"intervalMs,omitempty"`
	TimeoutMs     int `json:"timeoutMs,omitempty"`
	UpThreshold   int `json:"upThreshold,omitempty"`
	DownThreshold int `json:"downThreshold,omitempty"`
}

type Daemon struct {
	StateDir   string `json:"stateDir"`
	RuntimeDir string `json:"runtimeDir"`
	HostsFile  string `json:"hostsFile"`
	// IPPath is the absolute path to the `ip` binary used for uplink
	// route-metric publish (design.md §5.2, and the "resolved to an
	// absolute Nix store path at build time" rationale in §1's table).
	// Not part of the design doc's §3.2 option list verbatim — filled in
	// as the concrete mechanism that rationale requires. Falls back to
	// "ip" (PATH lookup) for the hand-written-config / non-Nix case.
	IPPath       string       `json:"ipPath,omitempty"`
	DefaultProbe DefaultProbe `json:"defaultProbe"`
}

type Config struct {
	Daemon  Daemon            `json:"daemon"`
	Peers   map[string]Peer   `json:"peers"`
	Uplinks map[string]Uplink `json:"uplinks"`
}

// Load reads and validates a config.json from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("validating config %s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Daemon.StateDir == "" {
		c.Daemon.StateDir = "/var/lib/nixnet"
	}
	if c.Daemon.RuntimeDir == "" {
		c.Daemon.RuntimeDir = "nixnet"
	}
	if c.Daemon.HostsFile == "" {
		c.Daemon.HostsFile = "/run/nixnet/hosts"
	}
	if c.Daemon.IPPath == "" {
		c.Daemon.IPPath = "ip"
	}
	if c.Daemon.DefaultProbe.IntervalMs == 0 {
		c.Daemon.DefaultProbe.IntervalMs = 3000
	}
	if c.Daemon.DefaultProbe.TimeoutMs == 0 {
		c.Daemon.DefaultProbe.TimeoutMs = 800
	}
	if c.Daemon.DefaultProbe.UpThreshold == 0 {
		c.Daemon.DefaultProbe.UpThreshold = 2
	}
	if c.Daemon.DefaultProbe.DownThreshold == 0 {
		c.Daemon.DefaultProbe.DownThreshold = 3
	}

	for name, p := range c.Peers {
		if p.OnAllDown == "" {
			p.OnAllDown = OnAllDownLastKnownGood
		}
		p.Hysteresis.applyDefault(10000)
		for i := range p.Transports {
			p.Transports[i].Probe.applyDefaults(c.Daemon.DefaultProbe)
			if p.Transports[i].Probe.Target == "" {
				p.Transports[i].Probe.Target = p.Transports[i].Address
			}
		}
		c.Peers[name] = p
	}

	for name, u := range c.Uplinks {
		u.Hysteresis.applyDefault(15000)
		if u.Publish.MetricBase == 0 {
			u.Publish.MetricBase = 100
		}
		if u.Publish.MetricStep == 0 {
			u.Publish.MetricStep = 10
		}
		for i := range u.Transports {
			u.Transports[i].Probe.applyDefaults(c.Daemon.DefaultProbe)
		}
		c.Uplinks[name] = u
	}
}

// validate re-checks the build-time assertions modules/core.nix already
// enforces at eval time. Re-checking here is what makes the "hand-written
// config.json" path in §3.3 actually safe to use standalone, rather than
// silently trusting Nix to have been the one who wrote the file.
func (c *Config) validate() error {
	seenHostnames := map[string]string{}
	for name, p := range c.Peers {
		if len(p.Hostnames) == 0 {
			return fmt.Errorf("peer %q: hostnames must not be empty", name)
		}
		for _, h := range p.Hostnames {
			if owner, ok := seenHostnames[h]; ok {
				return fmt.Errorf("hostname %q claimed by both peer %q and peer %q", h, owner, name)
			}
			seenHostnames[h] = name
		}
		for i, t := range p.Transports {
			if err := validateProbe(t.Probe); err != nil {
				return fmt.Errorf("peer %q transport[%d]: %w", name, i, err)
			}
		}
		if p.OnAllDown != OnAllDownLastKnownGood && p.OnAllDown != OnAllDownUnpublish {
			return fmt.Errorf("peer %q: onAllDown must be %q or %q, got %q", name, OnAllDownLastKnownGood, OnAllDownUnpublish, p.OnAllDown)
		}
	}
	for name, u := range c.Uplinks {
		for i, t := range u.Transports {
			if t.Interface == "" {
				return fmt.Errorf("uplink %q transport[%d]: interface is required", name, i)
			}
			if err := validateProbe(t.Probe); err != nil {
				return fmt.Errorf("uplink %q transport[%d]: %w", name, i, err)
			}
			if t.Probe.Method != "exec" && t.Probe.Target == "" {
				return fmt.Errorf("uplink %q transport[%d]: probe.target is required (address has no default here)", name, i)
			}
		}
	}
	return nil
}

func validateProbe(p Probe) error {
	switch p.Method {
	case "tcp", "icmp", "http", "exec":
	default:
		return fmt.Errorf("probe.method %q is not one of tcp|icmp|http|exec", p.Method)
	}
	if p.Method == "exec" && p.Exec == "" {
		return fmt.Errorf("probe.method=exec requires probe.exec")
	}
	return nil
}

// NeedsNetAdmin reports whether any uplink group needs CAP_NET_ADMIN to
// reprioritize route metrics (design.md §8).
func (c *Config) NeedsNetAdmin() bool {
	for _, u := range c.Uplinks {
		if u.Publish.RouteMetric {
			return true
		}
	}
	return false
}

// NeedsNetRaw reports whether any transport needs CAP_NET_RAW for ICMP or
// SO_BINDTODEVICE probing (design.md §8).
func (c *Config) NeedsNetRaw() bool {
	all := func(m map[string]Peer) bool {
		for _, p := range m {
			for _, t := range p.Transports {
				if t.Probe.Method == "icmp" || t.Probe.BindToInterface {
					return true
				}
			}
		}
		return false
	}
	if all(c.Peers) {
		return true
	}
	for _, u := range c.Uplinks {
		for _, t := range u.Transports {
			if t.Probe.Method == "icmp" || t.Probe.BindToInterface {
				return true
			}
		}
	}
	return false
}
