package stream

import (
	"errors"
	"sync"
	"testing"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
)

func mkEvent(id string) models.NetworkEvent {
	return models.NetworkEvent{ID: id, Type: models.EventDNS, Source: "10.0.0.1"}
}

func TestCircularBuffer_DefaultPolicyIsDropOldest(t *testing.T) {
	b := newCircularBuffer(4, "")
	if b.policy != PolicyDropOldest {
		t.Fatalf("expected default policy DropOldest, got %q", b.policy)
	}
}

func TestCircularBuffer_DropOldestDisplacesAndCounts(t *testing.T) {
	b := newCircularBuffer(3, PolicyDropOldest)

	for i, id := range []string{"a", "b", "c"} {
		if err := b.push(mkEvent(id)); err != nil {
			t.Fatalf("push %d failed: %v", i, err)
		}
	}
	if b.Dropped() != 0 {
		t.Fatalf("expected 0 drops before overflow, got %d", b.Dropped())
	}

	// Push 2 more — should displace 2 oldest entries
	if err := b.push(mkEvent("d")); err != nil {
		t.Fatalf("DropOldest must not error: %v", err)
	}
	if err := b.push(mkEvent("e")); err != nil {
		t.Fatalf("DropOldest must not error: %v", err)
	}

	if got := b.Dropped(); got != 2 {
		t.Fatalf("expected 2 dropped, got %d", got)
	}
	if b.len() != 3 {
		t.Fatalf("expected len=3, got %d", b.len())
	}

	snap := b.snapshot()
	wantIDs := []string{"c", "d", "e"}
	for i, w := range wantIDs {
		if snap[i].ID != w {
			t.Fatalf("snapshot[%d]=%s want %s", i, snap[i].ID, w)
		}
	}
}

func TestCircularBuffer_DropNewestRefusesAndCounts(t *testing.T) {
	b := newCircularBuffer(3, PolicyDropNewest)

	for _, id := range []string{"a", "b", "c"} {
		if err := b.push(mkEvent(id)); err != nil {
			t.Fatalf("push failed: %v", err)
		}
	}

	// Next two should be refused
	for _, id := range []string{"d", "e"} {
		err := b.push(mkEvent(id))
		if !errors.Is(err, ErrBufferFull) {
			t.Fatalf("expected ErrBufferFull, got %v", err)
		}
	}

	if got := b.Dropped(); got != 2 {
		t.Fatalf("expected 2 refused, got %d", got)
	}
	if b.len() != 3 {
		t.Fatalf("expected len=3, got %d", b.len())
	}

	snap := b.snapshot()
	wantIDs := []string{"a", "b", "c"}
	for i, w := range wantIDs {
		if snap[i].ID != w {
			t.Fatalf("snapshot[%d]=%s want %s (original kept)", i, snap[i].ID, w)
		}
	}
}

func TestCircularBuffer_ZeroCapacityDefaults(t *testing.T) {
	b := newCircularBuffer(0, PolicyDropNewest)
	if b.capacity != 10000 {
		t.Fatalf("expected default capacity 10000, got %d", b.capacity)
	}
}

func TestCircularBuffer_ConcurrentPush(t *testing.T) {
	b := newCircularBuffer(50, PolicyDropOldest)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = b.push(mkEvent("x"))
			}
		}()
	}
	wg.Wait()

	if b.len() != 50 {
		t.Fatalf("expected len=50, got %d", b.len())
	}
	// 8 * 200 = 1600 pushes, 50 retained, 1550 dropped
	if got := b.Dropped(); got != 1550 {
		t.Fatalf("expected 1550 drops, got %d", got)
	}
}
