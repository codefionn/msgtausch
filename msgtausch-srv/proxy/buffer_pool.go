package proxy

import (
	"io"
	"sync"
)

const (
	// DefaultBufferSize is the default size for pooled buffers (32KB)
	// This matches the internal buffer size used by io.Copy
	DefaultBufferSize = 32 * 1024
)

// bufferPool is a global pool of byte slices used for copying data
// between connections. This reduces GC pressure by reusing buffers.
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, DefaultBufferSize)
		return &buf
	},
}

// getBuffer retrieves a buffer from the pool.
// The caller must return the buffer using putBuffer when done.
func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// putBuffer returns a buffer to the pool for reuse.
func putBuffer(buf *[]byte) {
	if buf != nil {
		bufferPool.Put(buf)
	}
}

// copyBuffer copies from src to dst using a pooled buffer.
// This is a drop-in replacement for io.Copy that uses buffer pooling.
func copyBuffer(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := getBuffer()
	defer putBuffer(buf)
	return io.CopyBuffer(dst, src, *buf)
}
