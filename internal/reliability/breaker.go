package reliability

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/sony/gobreaker/v2"
)

// ErrCircuitOpen is returned when the circuit is open and Execute
// refuses to call the wrapped function. Callers can errors.Is against
// this to detect "fail fast" rejections versus genuine upstream errors.
var ErrCircuitOpen = errors.New("circuit breaker open")

// Breaker wraps gobreaker.CircuitBreaker with the project's
// conventions: ctx.Canceled is excluded from failure counts, state
// changes are logged via the supplied OnStateChange hook, and the
// open-state error is normalized to ErrCircuitOpen for caller
// matching.
//
// Construct via NewBreaker. The zero value is not usable.
type Breaker struct {
	cb            *gobreaker.CircuitBreaker[struct{}]
	totalOpens    atomic.Uint64
	totalRejects  atomic.Uint64
}

// BreakerConfig captures the knobs callers normally tune. Anything
// not set is filled with a sensible default by NewBreaker.
//
// Sensible defaults (matching upstream gobreaker defaults that work
// well for owasaka's external deps):
//
//   - MaxRequests in half-open: 1
//   - Rolling window (Interval): 60s
//   - Open→half-open timeout: 30s
//   - Trip threshold: 5 consecutive failures
type BreakerConfig struct {
	Name        string
	MaxRequests uint32
	Interval    time.Duration
	Timeout     time.Duration

	// FailureThreshold is the number of consecutive failures required
	// to trip from closed to open. Zero means "use default (5)".
	FailureThreshold uint32

	// OnStateChange is invoked synchronously on every state transition.
	// Pass a logger closure; nil to disable. Errors during the hook are
	// swallowed by gobreaker — keep it lightweight.
	OnStateChange func(name string, from, to string)
}

// NewBreaker constructs a Breaker. Name is required.
func NewBreaker(cfg BreakerConfig) *Breaker {
	if cfg.Name == "" {
		panic("reliability.NewBreaker: Name is required")
	}
	if cfg.FailureThreshold == 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.MaxRequests == 0 {
		cfg.MaxRequests = 1
	}
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	b := &Breaker{}

	settings := gobreaker.Settings{
		Name:        cfg.Name,
		MaxRequests: cfg.MaxRequests,
		Interval:    cfg.Interval,
		Timeout:     cfg.Timeout,
		ReadyToTrip: func(c gobreaker.Counts) bool {
			return c.ConsecutiveFailures >= cfg.FailureThreshold
		},
		IsExcluded: func(err error) bool {
			// ctx.Canceled is operator intent, not upstream pain.
			return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		},
		OnStateChange: func(name string, from, to gobreaker.State) {
			if to == gobreaker.StateOpen {
				b.totalOpens.Add(1)
			}
			if cfg.OnStateChange != nil {
				cfg.OnStateChange(name, from.String(), to.String())
			}
		},
	}
	b.cb = gobreaker.NewCircuitBreaker[struct{}](settings)
	return b
}

// Execute runs fn under the breaker. Returns ErrCircuitOpen if the
// breaker is open (or half-open and already saturated), otherwise
// returns fn's own error verbatim. Successful calls return nil.
//
// Any wrapped non-context error counts against the failure threshold.
// Context cancellation is excluded — it represents operator intent
// and should not trip on shutdown.
func (b *Breaker) Execute(fn func() error) error {
	_, err := b.cb.Execute(func() (struct{}, error) {
		return struct{}{}, fn()
	})
	if err == nil {
		return nil
	}
	// gobreaker uses sentinel errors for "open" and "too many requests"
	// — normalize both into our public ErrCircuitOpen so callers have
	// one thing to match.
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		b.totalRejects.Add(1)
		return fmt.Errorf("%w: %s", ErrCircuitOpen, err.Error())
	}
	return err
}

// State returns the current breaker state as a string ("closed",
// "half-open", or "open"). Useful for metrics and debug endpoints.
func (b *Breaker) State() string {
	return b.cb.State().String()
}

// Counters returns lifetime counts of (state transitions to open,
// fail-fast rejections). Useful for dashboards.
func (b *Breaker) Counters() (opens, rejects uint64) {
	return b.totalOpens.Load(), b.totalRejects.Load()
}

// Name returns the configured breaker name.
func (b *Breaker) Name() string {
	return b.cb.Name()
}
