package reliability

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"
)

func TestNewBackoff_PanicsOnBadInput(t *testing.T) {
	cases := []struct {
		name      string
		base, cap time.Duration
	}{
		{"zero base", 0, time.Second},
		{"negative base", -time.Second, time.Second},
		{"zero cap", time.Millisecond, 0},
		{"base > cap", time.Second, time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected panic, got none")
				}
			}()
			NewBackoff(tc.base, tc.cap)
		})
	}
}

func TestBackoff_NextSequenceCaps(t *testing.T) {
	// Deterministic rand so jitter is reproducible; we assert on the
	// upper bound which depends only on base, factor, and cap.
	src := rand.New(rand.NewSource(42))
	b := NewBackoff(10*time.Millisecond, 100*time.Millisecond, WithRand(src))

	// Attempt 0 → upper bound = base = 10ms
	// Attempt 1 → 20ms
	// Attempt 2 → 40ms
	// Attempt 3 → 80ms
	// Attempt 4 → cap at 100ms
	// Attempt 5 → cap at 100ms
	expectMax := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
		100 * time.Millisecond,
		100 * time.Millisecond,
	}
	for i, max := range expectMax {
		got := b.Next()
		if got < 0 || got >= max {
			t.Errorf("attempt %d: got %v, want < %v", i, got, max)
		}
	}
	if b.Attempt() != len(expectMax) {
		t.Errorf("Attempt() = %d, want %d", b.Attempt(), len(expectMax))
	}
}

func TestBackoff_Reset(t *testing.T) {
	b := NewBackoff(time.Millisecond, 10*time.Millisecond)
	_ = b.Next()
	_ = b.Next()
	_ = b.Next()
	if b.Attempt() != 3 {
		t.Fatalf("Attempt() = %d, want 3", b.Attempt())
	}
	b.Reset()
	if b.Attempt() != 0 {
		t.Errorf("after Reset Attempt() = %d, want 0", b.Attempt())
	}
}

func TestBackoff_WithFactor(t *testing.T) {
	b := NewBackoff(10*time.Millisecond, time.Second, WithFactor(1.5))
	// First sample: max = 10ms.
	if got := b.Next(); got >= 10*time.Millisecond {
		t.Errorf("attempt 0 must be < 10ms, got %v", got)
	}
	// Second sample: max = 15ms (1.5x).
	if got := b.Next(); got >= 15*time.Millisecond {
		t.Errorf("attempt 1 must be < 15ms (factor=1.5), got %v", got)
	}
}

func TestBackoff_WithFactor_IgnoresInvalid(t *testing.T) {
	b := NewBackoff(10*time.Millisecond, time.Second, WithFactor(0.5))
	// Invalid factor (<=1) should be ignored; factor stays at default 2.0.
	if b.factor != 2.0 {
		t.Errorf("invalid factor must be rejected; got %v", b.factor)
	}
}

func TestRetry_SucceedsOnFirstAttempt(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), NewBackoff(time.Millisecond, 10*time.Millisecond), 3, func(context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetry_SucceedsAfterFailures(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), NewBackoff(time.Microsecond, time.Millisecond), 5, func(context.Context) error {
		calls++
		if calls < 3 {
			return errors.New("nope")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestRetry_ExhaustsBudget(t *testing.T) {
	calls := 0
	sentinel := errors.New("upstream broken")
	err := Retry(context.Background(), NewBackoff(time.Microsecond, time.Millisecond), 3, func(context.Context) error {
		calls++
		return sentinel
	})
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
	if !errors.Is(err, ErrRetryBudgetExhausted) {
		t.Errorf("expected ErrRetryBudgetExhausted, got %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel via Unwrap, got %v", err)
	}
}

func TestRetry_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	err := Retry(ctx, NewBackoff(50*time.Millisecond, time.Second), 100, func(context.Context) error {
		calls++
		return errors.New("still broken")
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	// Should not have looped 100 times.
	if calls > 5 {
		t.Errorf("expected <5 calls before cancel, got %d", calls)
	}
}

func TestRetry_PropagatesContextErrorFromFn(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), NewBackoff(time.Microsecond, time.Millisecond), 5, func(context.Context) error {
		calls++
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled passthrough, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call (immediate exit on ctx error), got %d", calls)
	}
}

func TestRetry_ZeroAttemptsRunsUntilCtx(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	calls := 0
	err := Retry(ctx, NewBackoff(time.Microsecond, time.Millisecond), 0, func(context.Context) error {
		calls++
		return errors.New("nope")
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}
	if calls < 2 {
		t.Errorf("expected multiple attempts before timeout, got %d", calls)
	}
}

func TestWait_HonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := wait(ctx, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("wait should return immediately on cancel, took %v", elapsed)
	}
}

func TestWait_ZeroDurationNoop(t *testing.T) {
	if err := wait(context.Background(), 0); err != nil {
		t.Errorf("zero-duration wait should return nil, got %v", err)
	}
}
