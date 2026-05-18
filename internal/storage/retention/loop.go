package retention

import (
	"context"
	"sync"
	"time"
)

// Start spawns the background sweep goroutine. Returns a stop function
// that callers invoke on shutdown; the stop function waits for the
// current sweep (if any) to finish so a SIGTERM does not interrupt a
// retention pass mid-way.
//
// Calling Start while a previous loop is still running is a no-op
// (returns the same logical stop signal). Real production wiring
// calls Start exactly once from internal/app/app.go and Stop in the
// graceful-shutdown path.
func (e *Engine) Start(parent context.Context) (stop func()) {
	if !e.running.CompareAndSwap(false, true) {
		// Already running; return a no-op stop to keep the caller
		// path simple. The original Start owns the goroutine.
		return func() {}
	}

	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		ticker := time.NewTicker(e.cfg.SweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := e.Sweep(ctx); err != nil {
					e.logger.Warnw("retention: scheduled sweep failed",
						"error", err)
				}
			}
		}
	}()

	return func() {
		cancel()
		wg.Wait()
		e.running.Store(false)
	}
}
