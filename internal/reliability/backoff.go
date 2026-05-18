// Package reliability provides primitives for surviving partial
// failures in external dependencies: exponential backoff with jitter,
// retries with budget, and circuit-breaker wrappers around the
// sony/gobreaker library.
//
// These primitives are deliberately small and stdlib-only (except
// gobreaker in breaker.go). They are meant to be composed at call
// sites — there is no global state, no init() side effects.
//
// Design notes:
//
//   - All sleep paths honor ctx.Done() so a shutdown cancels in-flight
//     retries promptly. The "wait" helper centralizes that.
//   - Jitter is "full jitter" per Marc Brooker's classic AWS post:
//     random in [0, computed-backoff). Decorrelated jitter is overkill
//     for our use cases and harder to reason about.
//   - The random source is package-scoped and seeded once. Callers
//     can override via WithRand for deterministic tests.
package reliability

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"sync"
	"time"
)

// Backoff computes successive delays for retry loops. Use NewBackoff
// to construct one; Next returns the next delay and advances state.
// Reset rewinds back to the first delay (useful when a retry loop
// succeeds and the caller wants the same Backoff for a future call).
//
// Backoff is NOT safe for concurrent use. Each goroutine should own
// its instance.
type Backoff struct {
	base   time.Duration
	cap    time.Duration
	factor float64
	rng    *rand.Rand
	attempt int
}

// BackoffOption mutates a Backoff before it is returned by NewBackoff.
type BackoffOption func(*Backoff)

// WithRand replaces the internal random source. Provide a seeded
// deterministic source for tests; do not use this in production.
func WithRand(r *rand.Rand) BackoffOption {
	return func(b *Backoff) {
		if r != nil {
			b.rng = r
		}
	}
}

// WithFactor overrides the exponential multiplier. Defaults to 2.0;
// pick a smaller value (e.g. 1.5) to back off more gently.
func WithFactor(f float64) BackoffOption {
	return func(b *Backoff) {
		if f > 1.0 {
			b.factor = f
		}
	}
}

// pkgRand is the default random source. Seeded once at package init.
// math/rand is fine here — backoff jitter does not need crypto entropy.
var (
	pkgRandMu sync.Mutex
	pkgRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func sampleJitter(b *Backoff, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	if b.rng != nil {
		return time.Duration(b.rng.Int63n(int64(max)))
	}
	pkgRandMu.Lock()
	defer pkgRandMu.Unlock()
	return time.Duration(pkgRand.Int63n(int64(max)))
}

// NewBackoff constructs a Backoff with the given base and cap.
//
//	base   — first sleep, before any jitter
//	cap    — maximum sleep regardless of attempt count
//
// Callers typically use base=100ms cap=30s for network retries.
// Panics if base or cap are non-positive, or if base > cap.
func NewBackoff(base, cap time.Duration, opts ...BackoffOption) *Backoff {
	if base <= 0 || cap <= 0 || base > cap {
		panic("reliability.NewBackoff: require 0 < base <= cap")
	}
	b := &Backoff{
		base:   base,
		cap:    cap,
		factor: 2.0,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Next returns the next sleep duration and advances the attempt
// counter. The returned duration is sampled in [0, min(cap, base*factor^attempt)).
// First call (attempt=0) returns a value in [0, base).
func (b *Backoff) Next() time.Duration {
	exp := float64(b.base) * math.Pow(b.factor, float64(b.attempt))
	if exp > float64(b.cap) || math.IsInf(exp, 1) {
		exp = float64(b.cap)
	}
	b.attempt++
	return sampleJitter(b, time.Duration(exp))
}

// Reset rewinds the attempt counter to zero. Call this when a
// long-lived consumer (e.g. a NATS reconnect loop) finally succeeds,
// so the next failure starts the backoff curve over.
func (b *Backoff) Reset() {
	b.attempt = 0
}

// Attempt returns the current attempt count (zero before the first
// Next call). Useful for logging.
func (b *Backoff) Attempt() int { return b.attempt }

// ErrRetryBudgetExhausted is returned by Retry when all attempts
// failed. Use errors.Is to detect; the last wrapped error is also
// returned via the standard Unwrap chain.
var ErrRetryBudgetExhausted = errors.New("retry budget exhausted")

// Retry calls fn until it returns nil, until ctx is cancelled, or
// until attempts have been exhausted. attempts=0 means "retry forever
// (until ctx cancels)".
//
// fn should be idempotent — Retry has no way to know whether a partial
// failure already had side effects.
//
// If fn returns a non-nil error wrapping context.Canceled, Retry
// returns immediately.
func Retry(ctx context.Context, b *Backoff, attempts int, fn func(ctx context.Context) error) error {
	var lastErr error
	for i := 0; attempts == 0 || i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = fn(ctx)
		if lastErr == nil {
			return nil
		}
		if errors.Is(lastErr, context.Canceled) {
			return lastErr
		}
		// Final attempt — don't sleep, return immediately.
		if attempts > 0 && i == attempts-1 {
			break
		}
		if err := wait(ctx, b.Next()); err != nil {
			return err
		}
	}
	if lastErr == nil {
		return ErrRetryBudgetExhausted
	}
	return &retryError{last: lastErr}
}

type retryError struct{ last error }

func (e *retryError) Error() string {
	return ErrRetryBudgetExhausted.Error() + ": " + e.last.Error()
}
func (e *retryError) Unwrap() error { return e.last }
func (e *retryError) Is(target error) bool {
	return target == ErrRetryBudgetExhausted
}

// wait sleeps for d but returns early if ctx is cancelled. Returns
// ctx.Err() in that case, nil otherwise.
func wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
