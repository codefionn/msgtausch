package proxy

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
)

// trackedConn is a wrapper around net.Conn that tracks connection statistics.
type trackedConn struct {
	net.Conn
	collector     stats.Collector
	connectionID  int64
	bytesSent     int64
	bytesReceived int64
	startTime     time.Time
	ctx           context.Context
	// internal synchronization for periodic flush and end-of-connection recording
	mu            sync.Mutex
	flushSent     int64
	flushReceived int64
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
		c.mu.Lock()
		c.bytesReceived += int64(n)
		// Record periodic data transfer for long connections.
		// Report deltas since the last flush to avoid double-counting.
		if (c.bytesSent+c.bytesReceived)%10240 == 0 { // Every ~10KB combined
			toReportSent = c.bytesSent - c.flushSent
			toReportRecv = c.bytesReceived - c.flushReceived
			c.flushSent = c.bytesSent
			c.flushReceived = c.bytesReceived
		}
		c.mu.Unlock()
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
		c.mu.Lock()
		c.bytesSent += int64(n)
		// Record periodic data transfer for long connections.
		// Report deltas since the last flush to avoid double-counting.
		if (c.bytesSent+c.bytesReceived)%10240 == 0 { // Every ~10KB combined
			toReportSent = c.bytesSent - c.flushSent
			toReportRecv = c.bytesReceived - c.flushReceived
			c.flushSent = c.bytesSent
			c.flushReceived = c.bytesReceived
		}
		c.mu.Unlock()
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
		c.mu.Lock()
		toReportSent = c.bytesSent - c.flushSent
		toReportRecv = c.bytesReceived - c.flushReceived
		c.flushSent = c.bytesSent
		c.flushReceived = c.bytesReceived
		c.mu.Unlock()
		if toReportSent > 0 || toReportRecv > 0 {
			_ = c.collector.RecordDataTransfer(c.ctx, c.connectionID, toReportSent, toReportRecv)
		}
		_ = c.collector.EndConnection(c.ctx, c.connectionID, c.bytesSent, c.bytesReceived, duration, closeReason)
	})
	return err
}
