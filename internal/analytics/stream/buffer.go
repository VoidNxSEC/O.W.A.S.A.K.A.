package stream

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
)

// BackpressurePolicy controls how the buffer responds when full
type BackpressurePolicy string

const (
	PolicyDropOldest BackpressurePolicy = "drop_oldest"
	PolicyDropNewest BackpressurePolicy = "drop_newest"
)

// ErrBufferFull is returned by tryPush when policy is DropNewest and capacity is reached
var ErrBufferFull = errors.New("stream buffer full")

// circularBuffer is a fixed-capacity, thread-safe ring buffer for NetworkEvents
type circularBuffer struct {
	mu       sync.RWMutex
	data     []models.NetworkEvent
	head     int
	count    int
	capacity int
	policy   BackpressurePolicy
	dropped  atomic.Uint64
}

func newCircularBuffer(capacity int, policy BackpressurePolicy) *circularBuffer {
	if capacity <= 0 {
		capacity = 10000
	}
	if policy != PolicyDropNewest {
		policy = PolicyDropOldest
	}
	return &circularBuffer{
		data:     make([]models.NetworkEvent, capacity),
		capacity: capacity,
		policy:   policy,
	}
}

// push adds an event according to the configured policy.
// Returns nil on accept, ErrBufferFull when the event was refused.
func (b *circularBuffer) push(e models.NetworkEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.count == b.capacity {
		if b.policy == PolicyDropNewest {
			b.dropped.Add(1)
			return ErrBufferFull
		}
		// DropOldest: displace the entry at head (the oldest)
		b.dropped.Add(1)
	}
	b.data[b.head] = e
	b.head = (b.head + 1) % b.capacity
	if b.count < b.capacity {
		b.count++
	}
	return nil
}

// len returns the number of stored events
func (b *circularBuffer) len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// Dropped returns the cumulative number of events refused or displaced
func (b *circularBuffer) Dropped() uint64 {
	return b.dropped.Load()
}

// snapshot returns a copy of all stored events, oldest first
func (b *circularBuffer) snapshot() []models.NetworkEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]models.NetworkEvent, b.count)
	start := (b.head - b.count + b.capacity) % b.capacity
	for i := 0; i < b.count; i++ {
		out[i] = b.data[(start+i)%b.capacity]
	}
	return out
}
