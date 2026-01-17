package proxy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
)

// trackedConn is a wrapper around net.Conn that tracks connection statistics.
type trackedConn struct {
	net.Conn
	collector     stats.Collector
	connectionID  int64
	bytesSent     int64 // accessed atomically
	bytesReceived int64 // accessed atomically
	startTime     time.Time
	ctx           context.Context
	// internal synchronization for periodic flush and end-of-connection recording
	flushSent     int64 // accessed atomically
	flushReceived int64 // accessed atomically
	endOnce       sync.Once
}

// newTrackedConn creates a new tracked connection.
func newTrackedConn(ctx context.Context, conn net.Conn, collector stats.Collector, connectionID int64) *trackedConn {
	return &trackedConn{
		Conn:         conn,
		collector:    collector,
		connectionID: connectionID,
		startTime:    time.Now(),
		ctx:          ctx,
	}
}

// Read reads data from the connection, tracking the number of bytes received.
func (c *trackedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		var toReportSent, toReportRecv int64
		// Use atomic operations for lock-free byte counting
		newBytesReceived := atomic.AddInt64(&c.bytesReceived, int64(n))

		// Record periodic data transfer for long connections.
		// Report deltas since the last flush to avoid double-counting.
		if newBytesReceived%10240 == 0 { // Check every ~10KB of received data
			// Atomically get current sent bytes and calculate deltas
			currentSent := atomic.LoadInt64(&c.bytesSent)
			currentFlushSent := atomic.LoadInt64(&c.flushSent)
			currentFlushReceived := atomic.LoadInt64(&c.flushReceived)

			toReportSent = currentSent - currentFlushSent
			toReportRecv = newBytesReceived - currentFlushReceived

			// Update flush counters atomically
			if toReportSent > 0 || toReportRecv > 0 {
				atomic.StoreInt64(&c.flushSent, currentSent)
				atomic.StoreInt64(&c.flushReceived, newBytesReceived)
			}
		}
		if toReportSent > 0 || toReportRecv > 0 {
			_ = c.collector.RecordDataTransfer(c.ctx, c.connectionID, toReportSent, toReportRecv)
		}
	}
	return n, err
}

// Write writes data to the connection, tracking the number of bytes sent.
func (c *trackedConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		var toReportSent, toReportRecv int64
		// Use atomic operations for lock-free byte counting
		newBytesSent := atomic.AddInt64(&c.bytesSent, int64(n))

		// Record periodic data transfer for long connections.
		// Report deltas since the last flush to avoid double-counting.
		if newBytesSent%10240 == 0 { // Check every ~10KB of sent data
			// Atomically get current received bytes and calculate deltas
			currentReceived := atomic.LoadInt64(&c.bytesReceived)
			currentFlushSent := atomic.LoadInt64(&c.flushSent)
			currentFlushReceived := atomic.LoadInt64(&c.flushReceived)

			toReportSent = newBytesSent - currentFlushSent
			toReportRecv = currentReceived - currentFlushReceived

			// Update flush counters atomically
			if toReportSent > 0 || toReportRecv > 0 {
				atomic.StoreInt64(&c.flushSent, newBytesSent)
				atomic.StoreInt64(&c.flushReceived, currentReceived)
			}
		}
		if toReportSent > 0 || toReportRecv > 0 {
			_ = c.collector.RecordDataTransfer(c.ctx, c.connectionID, toReportSent, toReportRecv)
		}
	}
	return n, err
}

// Close closes the connection and records the final statistics.
func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	duration := time.Since(c.startTime)
	// Use a meaningful close reason for downstream stats. Only record once.
	closeReason := "normal"
	if err != nil {
		closeReason = err.Error()
	}
	c.endOnce.Do(func() {
		// Final flush of any unreported deltas before ending
		var toReportSent, toReportRecv int64
		// Use atomic operations for final byte counts
		finalSent := atomic.LoadInt64(&c.bytesSent)
		finalReceived := atomic.LoadInt64(&c.bytesReceived)
		currentFlushSent := atomic.LoadInt64(&c.flushSent)
		currentFlushReceived := atomic.LoadInt64(&c.flushReceived)

		toReportSent = finalSent - currentFlushSent
		toReportRecv = finalReceived - currentFlushReceived

		// Update flush counters atomically
		if toReportSent > 0 || toReportRecv > 0 {
			atomic.StoreInt64(&c.flushSent, finalSent)
			atomic.StoreInt64(&c.flushReceived, finalReceived)
		}

		if toReportSent > 0 || toReportRecv > 0 {
			_ = c.collector.RecordDataTransfer(c.ctx, c.connectionID, toReportSent, toReportRecv)
		}
		_ = c.collector.EndConnection(c.ctx, c.connectionID, finalSent, finalReceived, duration, closeReason)
	})
	return err
}
