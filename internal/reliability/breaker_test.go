package reliability

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewBreaker_RequiresName(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for empty name")
		}
	}()
	NewBreaker(BreakerConfig{})
}

func TestBreaker_PassesThroughSuccess(t *testing.T) {
	b := NewBreaker(BreakerConfig{Name: "test"})
	calls := 0
	for i := 0; i < 5; i++ {
		err := b.Execute(func() error {
			calls++
			return nil
		})
		if err != nil {
			t.Fatalf("iteration %d unexpected error: %v", i, err)
		}
	}
	if calls != 5 {
		t.Errorf("expected 5 calls, got %d", calls)
	}
	if got := b.State(); got != "closed" {
		t.Errorf("state = %q, want closed", got)
	}
}

func TestBreaker_TripsAfterThreshold(t *testing.T) {
	transitions := make([]string, 0, 4)
	var mu sync.Mutex
	b := NewBreaker(BreakerConfig{
		Name:             "trip-test",
		FailureThreshold: 3,
		Timeout:          50 * time.Millisecond,
		OnStateChange: func(_, from, to string) {
			mu.Lock()
			transitions = append(transitions, from+"->"+to)
			mu.Unlock()
		},
	})

	upstream := errors.New("upstream broken")
	// First 3 calls: real failures that pass through.
	for i := 0; i < 3; i++ {
		err := b.Execute(func() error { return upstream })
		if !errors.Is(err, upstream) {
			t.Errorf("call %d should pass upstream error, got %v", i, err)
		}
	}

	// 4th call: circuit should be open → ErrCircuitOpen, fn NOT called.
	called := false
	err := b.Execute(func() error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}
	if called {
		t.Error("fn should NOT be called when breaker is open")
	}

	mu.Lock()
	got := append([]string(nil), transitions...)
	mu.Unlock()
	if len(got) == 0 || got[0] != "closed->open" {
		t.Errorf("expected closed->open transition, got %v", got)
	}

	opens, rejects := b.Counters()
	if opens == 0 {
		t.Errorf("expected at least 1 open transition, got 0")
	}
	if rejects == 0 {
		t.Errorf("expected at least 1 reject, got 0")
	}
}

func TestBreaker_RecoversAfterTimeout(t *testing.T) {
	b := NewBreaker(BreakerConfig{
		Name:             "recover",
		FailureThreshold: 2,
		Timeout:          30 * time.Millisecond,
	})

	upstream := errors.New("broken")
	_ = b.Execute(func() error { return upstream })
	_ = b.Execute(func() error { return upstream })
	if b.State() != "open" {
		t.Fatalf("expected open after threshold, got %s", b.State())
	}

	// Wait past Timeout — breaker goes half-open.
	time.Sleep(50 * time.Millisecond)

	// Single success in half-open closes the breaker.
	if err := b.Execute(func() error { return nil }); err != nil {
		t.Fatalf("half-open call failed: %v", err)
	}
	if b.State() != "closed" {
		t.Errorf("expected closed after successful half-open, got %s", b.State())
	}
}

func TestBreaker_ExcludesContextErrors(t *testing.T) {
	b := NewBreaker(BreakerConfig{
		Name:             "ctx-exclude",
		FailureThreshold: 2,
	})

	// 10 context cancellations should NOT trip the breaker.
	for i := 0; i < 10; i++ {
		err := b.Execute(func() error { return context.Canceled })
		if !errors.Is(err, context.Canceled) {
			t.Errorf("iter %d: expected ctx.Canceled passthrough, got %v", i, err)
		}
	}
	if b.State() != "closed" {
		t.Errorf("context errors should not trip the breaker, state=%s", b.State())
	}

	// Same for DeadlineExceeded.
	for i := 0; i < 10; i++ {
		_ = b.Execute(func() error { return context.DeadlineExceeded })
	}
	if b.State() != "closed" {
		t.Errorf("deadline-exceeded should not trip, state=%s", b.State())
	}
}

func TestBreaker_ExcludesWrappedContextErrors(t *testing.T) {
	b := NewBreaker(BreakerConfig{
		Name:             "wrapped-ctx",
		FailureThreshold: 2,
	})
	for i := 0; i < 5; i++ {
		_ = b.Execute(func() error {
			return fmt.Errorf("dial failed: %w", context.Canceled)
		})
	}
	if b.State() != "closed" {
		t.Errorf("wrapped context error should still be excluded, state=%s", b.State())
	}
}

func TestBreaker_NameAndDefaults(t *testing.T) {
	b := NewBreaker(BreakerConfig{Name: "named"})
	if b.Name() != "named" {
		t.Errorf("Name() = %q, want named", b.Name())
	}
}
