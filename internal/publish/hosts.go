// Package publish implements the two publish backends: a managed
// /etc/hosts block for peers (design.md §5.1) and route-metric
// reprioritization for uplinks (§5.2).
package publish

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	beginMarker = "# BEGIN nixnet"
	endMarker   = "# END nixnet"
)

// HostsPublisher owns atomic rewrites of the managed hosts file. Content
// outside the BEGIN/END markers ("the static prefix") is never touched by
// the daemon — it is seeded once, at boot/switch, by the NixOS activation
// script (modules/core.nix), from the user's own networking.hosts /
// extraHosts plus best-effort last-known-good winners. See design.md §5.1.
type HostsPublisher struct {
	path         string
	staticPrefix string
}

// NewHostsPublisher loads the current static prefix from whatever already
// exists at path (normally written moments earlier by the activation
// script). If path doesn't exist yet, or has no marker block, its entire
// existing content — or nothing at all — becomes the static prefix; this
// is what makes running nixnetd directly against a hand-written hosts file
// (no Nix activation script involved) a safe, supported thing to do, per
// design.md §3.3.
func NewHostsPublisher(path string) (*HostsPublisher, error) {
	prefix := ""
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading existing hosts file %s: %w", path, err)
		}
	} else {
		prefix, _ = splitStatic(string(data))
	}
	return &HostsPublisher{path: path, staticPrefix: prefix}, nil
}

// splitStatic returns the content strictly before the BEGIN marker line
// (trailing blank lines trimmed). If no BEGIN marker is present, the whole
// input is treated as static content.
func splitStatic(content string) (staticPrefix string, hadMarkers bool) {
	idx := strings.Index(content, beginMarker)
	if idx < 0 {
		return strings.TrimRight(content, "\n") + "\n", false
	}
	return strings.TrimRight(content[:idx], "\n") + "\n", true
}

// Entry is one resolved hostname -> address mapping for the managed block.
type Entry struct {
	Address   string
	Hostnames []string // all names for this address, e.g. a peer's `hostnames` list
}

// Publish rewrites the whole hosts file: static prefix, unchanged, plus a
// freshly rendered marker block for entries. Entries are sorted by address
// for deterministic, diff-friendly output across ticks.
func (h *HostsPublisher) Publish(entries []Entry) error {
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Address < sorted[j].Address })

	var b strings.Builder
	b.WriteString(h.staticPrefix)
	b.WriteString(beginMarker)
	b.WriteString("\n")
	for _, e := range sorted {
		fmt.Fprintf(&b, "%s\t%s\n", e.Address, strings.Join(e.Hostnames, " "))
	}
	b.WriteString(endMarker)
	b.WriteString("\n")

	return atomicWrite(h.path, []byte(b.String()))
}

// atomicWrite implements design.md §5.1's "write .tmp, fsync, rename()"
// discipline: a killed mid-write process leaves either the old file or
// nothing, never a half-written one.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hosts.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

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
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ParseNixHosts is a small helper the activation script's Go-free bash
// doesn't need, but is kept here (and covered by the same package) as the
// documented inverse of splitStatic, for anything that wants to
// programmatically re-derive the marker-delimited entries nixnetd last
// published — e.g. tests, or a future nixnetctl subcommand.
func ParseNixHosts(content string) []Entry {
	var entries []Entry
	sc := bufio.NewScanner(strings.NewReader(content))
	inBlock := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == beginMarker:
			inBlock = true
		case strings.TrimSpace(line) == endMarker:
			inBlock = false
		case inBlock:
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				entries = append(entries, Entry{Address: fields[0], Hostnames: fields[1:]})
			}
		}
	}
	return entries
}
