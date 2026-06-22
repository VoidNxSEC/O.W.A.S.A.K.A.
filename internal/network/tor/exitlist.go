package tor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
)

// exitNodeFile is the on-disk/cached format: a flat list of known Tor
// exit/relay IPs. Operators populate this manually (e.g. via sneakernet
// from a non-air-gapped machine running a one-off Onionoo export) when
// ExitNodeListURL is left empty.
type exitNodeFile struct {
	IPs []string `json:"ips"`
}

// ExitNodeList holds a set of known Tor exit/relay IPs for O(1) lookups.
// Safe for concurrent use.
type ExitNodeList struct {
	mu    sync.RWMutex
	nodes map[string]bool
}

// NewExitNodeList returns an empty list.
func NewExitNodeList() *ExitNodeList {
	return &ExitNodeList{nodes: make(map[string]bool)}
}

// Contains reports whether ip is a known Tor exit/relay node.
func (l *ExitNodeList) Contains(ip string) bool {
	if ip == "" {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.nodes[ip]
}

// Size returns the number of loaded IPs.
func (l *ExitNodeList) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.nodes)
}

func (l *ExitNodeList) replace(ips []string) {
	next := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if ip != "" {
			next[ip] = true
		}
	}
	l.mu.Lock()
	l.nodes = next
	l.mu.Unlock()
}

// LoadFile reads a cached exitNodeFile from disk. A missing file is not
// an error — it simply leaves the list empty (air-gap-safe default).
func (l *ExitNodeList) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("tor: read exit node list %s: %w", path, err)
	}
	var f exitNodeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("tor: parse exit node list %s: %w", path, err)
	}
	l.replace(f.IPs)
	return nil
}

// SaveFile persists the current list to path, mirroring the on-disk
// format read by LoadFile (used to cache a freshly fetched list).
func (l *ExitNodeList) SaveFile(path string) error {
	l.mu.RLock()
	ips := make([]string, 0, len(l.nodes))
	for ip := range l.nodes {
		ips = append(ips, ip)
	}
	l.mu.RUnlock()

	data, err := json.Marshal(exitNodeFile{IPs: ips})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Fetch retrieves the exit node list from url via client and replaces
// the in-memory set. The remote response must match exitNodeFile's
// {"ips": [...]} shape — operators pointing this at a third-party feed
// (e.g. an Onionoo mirror) are responsible for normalizing the format
// upstream of OWASAKA.
func (l *ExitNodeList) Fetch(client *Client, url string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("tor: fetch exit node list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tor: fetch exit node list: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var f exitNodeFile
	if err := json.Unmarshal(body, &f); err != nil {
		return fmt.Errorf("tor: parse fetched exit node list: %w", err)
	}
	l.replace(f.IPs)
	return nil
}
