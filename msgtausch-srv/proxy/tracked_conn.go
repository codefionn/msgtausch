package proxy

import (
	"context"
	"net"
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
		c.bytesReceived += int64(n)
		// Record periodic data transfer for long connections
		if (c.bytesSent+c.bytesReceived)%10240 == 0 { // Every 10KB
			_ = c.collector.RecordDataTransfer(c.ctx, c.connectionID, c.bytesSent, c.bytesReceived)
		}
	}
	return n, err
}

// Write writes data to the connection, tracking the number of bytes sent.
func (c *trackedConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.bytesSent += int64(n)
		// Record periodic data transfer for long connections
		if (c.bytesSent+c.bytesReceived)%10240 == 0 { // Every 10KB
			_ = c.collector.RecordDataTransfer(c.ctx, c.connectionID, c.bytesSent, c.bytesReceived)
		}
	}
	return n, err
}

// Close closes the connection and records the final statistics.
func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	duration := time.Since(c.startTime)
	closeReason := ""
	if err != nil {
		closeReason = err.Error()
	}

	_ = c.collector.EndConnection(c.ctx, c.connectionID, c.bytesSent, c.bytesReceived, duration, closeReason)
	return err
}
