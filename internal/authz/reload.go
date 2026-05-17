package authz

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
)

// ReloadFrom parses + validates a policy file and, on success, swaps it
// in atomically. On failure the existing policy is preserved (callers
// keep operating under the last known-good rules).
//
// Returns a Diff describing what changed so callers can audit-log the
// reload.
func (e *Engine) ReloadFrom(path string) (Diff, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Diff{}, fmt.Errorf("authz: reload read %s: %w", path, err)
	}
	return e.ReloadBytes(bytes)
}

// ReloadBytes is the in-memory variant of ReloadFrom; used by the
// admin reload endpoint when the policy arrives in the request body.
func (e *Engine) ReloadBytes(data []byte) (Diff, error) {
	next, err := LoadBytes(data)
	if err != nil {
		return Diff{}, err
	}
	prev := e.Policy()
	e.Replace(next)
	return diffPolicies(prev, next), nil
}

// Diff summarizes role-set changes between two policies. Used by
// audit-log entries on every reload so we can answer "what changed and
// when" without comparing committed YAML files.
type Diff struct {
	Added    []string
	Removed  []string
	Modified []string
}

// IsEmpty reports whether the diff carries no change.
func (d Diff) IsEmpty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Modified) == 0
}

// String formats a single-line summary suitable for audit logs.
func (d Diff) String() string {
	if d.IsEmpty() {
		return "no changes"
	}
	parts := make([]string, 0, 3)
	if len(d.Added) > 0 {
		parts = append(parts, fmt.Sprintf("added=%v", d.Added))
	}
	if len(d.Removed) > 0 {
		parts = append(parts, fmt.Sprintf("removed=%v", d.Removed))
	}
	if len(d.Modified) > 0 {
		parts = append(parts, fmt.Sprintf("modified=%v", d.Modified))
	}
	return joinNonEmpty(parts, " ")
}

func diffPolicies(prev, next *Policy) Diff {
	d := Diff{}
	if prev == nil {
		if next == nil {
			return d
		}
		for name := range next.Roles {
			d.Added = append(d.Added, name)
		}
		sort.Strings(d.Added)
		return d
	}
	for name, role := range next.Roles {
		old, ok := prev.Roles[name]
		if !ok {
			d.Added = append(d.Added, name)
			continue
		}
		if !rolePermsEqual(old, role) {
			d.Modified = append(d.Modified, name)
		}
	}
	for name := range prev.Roles {
		if _, ok := next.Roles[name]; !ok {
			d.Removed = append(d.Removed, name)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Modified)
	return d
}

// rolePermsEqual compares two roles by their (sorted) permission keys.
// Description differences are ignored — auditors care about the
// effective permission set, not docstrings.
func rolePermsEqual(a, b *Role) bool {
	if len(a.Permissions) != len(b.Permissions) {
		return false
	}
	ka := permissionKeys(a.Permissions)
	kb := permissionKeys(b.Permissions)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

func permissionKeys(perms []Permission) []string {
	keys := make([]string, len(perms))
	for i, p := range perms {
		keys[i] = permissionKey(p)
	}
	sort.Strings(keys)
	return keys
}

func joinNonEmpty(parts []string, sep string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += sep
		}
		out += p
	}
	return out
}

// ReloadWatcher wires SIGHUP to engine reload. Returns a cancel function
// that the caller invokes during shutdown to release the signal handler.
//
// The watcher is goroutine-safe and concurrency-safe with respect to
// the engine's atomic.Value; multiple SIGHUPs in flight will queue (the
// OS handles signal coalescing), and each invocation produces a fresh
// reload attempt.
func ReloadWatcher(ctx context.Context, e *Engine, path string, onReload func(Diff, error)) (stop func()) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	var wg sync.WaitGroup
	wg.Add(1)
	doneCh := make(chan struct{})

	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-doneCh:
				return
			case <-sigCh:
				diff, err := e.ReloadFrom(path)
				if onReload != nil {
					onReload(diff, err)
				}
			}
		}
	}()

	return func() {
		signal.Stop(sigCh)
		close(doneCh)
		wg.Wait()
	}
}

// Compile-time guards against accidental import drift.
var _ = errors.New
