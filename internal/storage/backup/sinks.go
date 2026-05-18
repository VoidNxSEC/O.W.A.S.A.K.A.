package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// LocalSink writes backup artifacts to a configured directory on the
// local filesystem. Files are written atomically (tmp + rename) so a
// crash mid-write never leaves an incomplete .age visible to
// operators. Rotation by file count keeps disk usage bounded.
type LocalSink struct {
	dir      string
	keepLast int // 0 means keep all
}

// NewLocalSink prepares a local sink. The directory is created with
// mode 0700 if it does not exist. keepLast = 0 disables rotation.
func NewLocalSink(dir string, keepLast int) (*LocalSink, error) {
	if dir == "" {
		return nil, errors.New("backup: local sink dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: local sink mkdir: %w", err)
	}
	return &LocalSink{dir: dir, keepLast: keepLast}, nil
}

// Name implements Sink.
func (s *LocalSink) Name() string { return "local:" + s.dir }

// Write implements Sink. Writes the encrypted file and its sidecar
// atomically; rotates older backups when keepLast is set.
func (s *LocalSink) Write(ctx context.Context, art Artifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encPath := filepath.Join(s.dir, art.Filename)
	sidePath := encPath + ".sha256"

	if err := atomicWrite(encPath, art.Encrypted); err != nil {
		return err
	}
	if err := atomicWrite(sidePath, art.Sidecar); err != nil {
		// Best-effort cleanup of the orphaned .age so operators don't
		// see "encrypted file without sidecar" — a confusing state.
		_ = os.Remove(encPath)
		return err
	}

	if s.keepLast > 0 {
		if err := s.rotate(); err != nil {
			// Rotation failure is non-fatal; the backup itself
			// succeeded. Surface for logs.
			return fmt.Errorf("backup: local rotate: %w", err)
		}
	}
	return nil
}

// rotate removes the oldest backups beyond keepLast. Entries are
// paired (.age + .age.sha256); both are removed when a pair is
// rotated out.
func (s *LocalSink) rotate() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	type pair struct {
		base, encPath, sidePath string
	}
	var pairs []pair
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".age" {
			continue
		}
		side := filepath.Join(s.dir, name+".sha256")
		if _, err := os.Stat(side); err != nil {
			continue
		}
		pairs = append(pairs, pair{
			base:     name,
			encPath:  filepath.Join(s.dir, name),
			sidePath: side,
		})
	}
	if len(pairs) <= s.keepLast {
		return nil
	}
	// Sort by name; filenames embed an RFC 3339-ish timestamp so
	// lexicographic order = chronological order.
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].base < pairs[j].base })
	toRemove := pairs[:len(pairs)-s.keepLast]
	for _, p := range toRemove {
		_ = os.Remove(p.encPath)
		_ = os.Remove(p.sidePath)
	}
	return nil
}

// atomicWrite is the tmp + rename idiom; on POSIX the rename is
// atomic within a filesystem, so observers either see the old file
// or the new file but never a torn write.
func atomicWrite(path string, body []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MultiSink fans an artifact out to multiple underlying sinks. Used
// for the common "local + NAS" pattern: primary + offsite. Returns
// the first sink error encountered; partial writes are NOT rolled
// back — operators inspect what landed and where.
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink wraps two or more sinks.
func NewMultiSink(sinks ...Sink) (*MultiSink, error) {
	if len(sinks) == 0 {
		return nil, ErrNoSinks
	}
	return &MultiSink{sinks: sinks}, nil
}

// Name implements Sink.
func (m *MultiSink) Name() string {
	names := make([]string, len(m.sinks))
	for i, s := range m.sinks {
		names[i] = s.Name()
	}
	return "multi[" + joinNames(names) + "]"
}

// Write implements Sink.
func (m *MultiSink) Write(ctx context.Context, art Artifact) error {
	for _, s := range m.sinks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.Write(ctx, art); err != nil {
			return fmt.Errorf("multi: %s: %w", s.Name(), err)
		}
	}
	return nil
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		out := names[0]
		for _, n := range names[1:] {
			out += "," + n
		}
		return out
	}
}
