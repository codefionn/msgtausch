package stats

import (
	"sync/atomic"
)

// AtomicInt64Counter is a lock-free 64-bit integer counter
type AtomicInt64Counter int64

// Add atomically adds delta to the counter and returns the new value
func (c *AtomicInt64Counter) Add(delta int64) int64 {
	return atomic.AddInt64((*int64)(c), delta)
}

// Load atomically loads the current value
func (c *AtomicInt64Counter) Load() int64 {
	return atomic.LoadInt64((*int64)(c))
}

// Store atomically stores the value
func (c *AtomicInt64Counter) Store(value int64) {
	atomic.StoreInt64((*int64)(c), value)
}

// Swap atomically swaps the old value with new and returns the old value
func (c *AtomicInt64Counter) Swap(new int64) int64 {
	return atomic.SwapInt64((*int64)(c), new)
}

// CompareAndSwap performs atomic compare-and-swap
func (c *AtomicInt64Counter) CompareAndSwap(old, new int64) bool {
	return atomic.CompareAndSwapInt64((*int64)(c), old, new)
}

// Reset atomically resets the counter to 0 and returns the previous value
func (c *AtomicInt64Counter) Reset() int64 {
	return c.Swap(0)
}

// AtomicCounters holds multiple atomic counters for common statistics
type AtomicCounters struct {
	TotalConnections   AtomicInt64Counter
	ActiveConnections  AtomicInt64Counter
	TotalRequests      AtomicInt64Counter
	TotalErrors        AtomicInt64Counter
	BlockedRequests    AtomicInt64Counter
	AllowedRequests    AtomicInt64Counter
	TotalBytesIn       AtomicInt64Counter
	TotalBytesOut      AtomicInt64Counter
	DataTransferEvents AtomicInt64Counter
	HTTPErrors         AtomicInt64Counter
	ConnectionErrors   AtomicInt64Counter
}

// NewAtomicCounters creates a new set of atomic counters
func NewAtomicCounters() *AtomicCounters {
	return &AtomicCounters{}
}

// Snapshot returns a copy of all counter values
func (a *AtomicCounters) Snapshot() CounterSnapshot {
	return CounterSnapshot{
		TotalConnections:   a.TotalConnections.Load(),
		ActiveConnections:  a.ActiveConnections.Load(),
		TotalRequests:      a.TotalRequests.Load(),
		TotalErrors:        a.TotalErrors.Load(),
		BlockedRequests:    a.BlockedRequests.Load(),
		AllowedRequests:    a.AllowedRequests.Load(),
		TotalBytesIn:       a.TotalBytesIn.Load(),
		TotalBytesOut:      a.TotalBytesOut.Load(),
		DataTransferEvents: a.DataTransferEvents.Load(),
		HTTPErrors:         a.HTTPErrors.Load(),
		ConnectionErrors:   a.ConnectionErrors.Load(),
	}
}

// ResetAll resets all counters to 0 and returns the previous values
func (a *AtomicCounters) ResetAll() CounterSnapshot {
	return CounterSnapshot{
		TotalConnections:   a.TotalConnections.Reset(),
		ActiveConnections:  a.ActiveConnections.Reset(),
		TotalRequests:      a.TotalRequests.Reset(),
		TotalErrors:        a.TotalErrors.Reset(),
		BlockedRequests:    a.BlockedRequests.Reset(),
		AllowedRequests:    a.AllowedRequests.Reset(),
		TotalBytesIn:       a.TotalBytesIn.Reset(),
		TotalBytesOut:      a.TotalBytesOut.Reset(),
		DataTransferEvents: a.DataTransferEvents.Reset(),
		HTTPErrors:         a.HTTPErrors.Reset(),
		ConnectionErrors:   a.ConnectionErrors.Reset(),
	}
}

// CounterSnapshot represents a snapshot of counter values
type CounterSnapshot struct {
	TotalConnections   int64
	ActiveConnections  int64
	TotalRequests      int64
	TotalErrors        int64
	BlockedRequests    int64
	AllowedRequests    int64
	TotalBytesIn       int64
	TotalBytesOut      int64
	DataTransferEvents int64
	HTTPErrors         int64
	ConnectionErrors   int64
}

// Add adds another snapshot to this one
func (s *CounterSnapshot) Add(other CounterSnapshot) {
	s.TotalConnections += other.TotalConnections
	s.ActiveConnections += other.ActiveConnections
	s.TotalRequests += other.TotalRequests
	s.TotalErrors += other.TotalErrors
	s.BlockedRequests += other.BlockedRequests
	s.AllowedRequests += other.AllowedRequests
	s.TotalBytesIn += other.TotalBytesIn
	s.TotalBytesOut += other.TotalBytesOut
	s.DataTransferEvents += other.DataTransferEvents
	s.HTTPErrors += other.HTTPErrors
	s.ConnectionErrors += other.ConnectionErrors
}

// AtomicBool is a lock-free boolean flag
type AtomicBool int32

// Set atomically sets the boolean value
func (b *AtomicBool) Set(value bool) {
	var i int32 = 0
	if value {
		i = 1
	}
	atomic.StoreInt32((*int32)(b), i)
}

// Load atomically loads the boolean value
func (b *AtomicBool) Load() bool {
	return atomic.LoadInt32((*int32)(b)) != 0
}

// CompareAndSwap performs atomic compare-and-swap
func (b *AtomicBool) CompareAndSwap(old, new bool) bool {
	var oldInt, newInt int32 = 0, 0
	if old {
		oldInt = 1
	}
	if new {
		newInt = 1
	}
	return atomic.CompareAndSwapInt32((*int32)(b), oldInt, newInt)
}

// AtomicString is a lock-free string pointer
type AtomicString struct {
	v atomic.Value
}

// Store atomically stores a string value
func (s *AtomicString) Store(value string) {
	s.v.Store(value)
}

// Load atomically loads a string value
func (s *AtomicString) Load() string {
	if v := s.v.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// CompareAndSwap performs atomic compare-and-swap for strings
func (s *AtomicString) CompareAndSwap(old, new string) bool {
	return s.v.CompareAndSwap(old, new)
}
