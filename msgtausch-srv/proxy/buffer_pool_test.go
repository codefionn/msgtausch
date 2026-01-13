package proxy

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAndPutBuffer(t *testing.T) {
	buf := getBuffer()
	require.NotNil(t, buf)
	assert.Equal(t, DefaultBufferSize, len(*buf))

	// Modify buffer to verify reuse
	(*buf)[0] = 42

	// Return to pool
	putBuffer(buf)

	// Get another buffer - might be the same one or a new one
	buf2 := getBuffer()
	require.NotNil(t, buf2)
	assert.Equal(t, DefaultBufferSize, len(*buf2))

	putBuffer(buf2)
}

func TestPutBufferNil(t *testing.T) {
	// Should not panic
	putBuffer(nil)
}

func TestCopyBuffer(t *testing.T) {
	testData := "Hello, World! This is a test of the buffer pooling system."
	src := strings.NewReader(testData)
	dst := &bytes.Buffer{}

	n, err := copyBuffer(dst, src)
	require.NoError(t, err)
	assert.Equal(t, int64(len(testData)), n)
	assert.Equal(t, testData, dst.String())
}

func TestCopyBufferLargeData(t *testing.T) {
	// Test with data larger than buffer size
	testData := strings.Repeat("A", DefaultBufferSize*2+1000)
	src := strings.NewReader(testData)
	dst := &bytes.Buffer{}

	n, err := copyBuffer(dst, src)
	require.NoError(t, err)
	assert.Equal(t, int64(len(testData)), n)
	assert.Equal(t, testData, dst.String())
}

func TestCopyBufferConcurrent(t *testing.T) {
	// Test concurrent access to buffer pool
	const numGoroutines = 100
	const dataSize = 10000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(iteration int) {
			defer wg.Done()

			testData := strings.Repeat("X", dataSize)
			src := strings.NewReader(testData)
			dst := &bytes.Buffer{}

			n, err := copyBuffer(dst, src)
			if err != nil {
				t.Errorf("Iteration %d: unexpected error: %v", iteration, err)
				return
			}
			if n != int64(dataSize) {
				t.Errorf("Iteration %d: expected %d bytes, got %d", iteration, dataSize, n)
				return
			}
			if dst.String() != testData {
				t.Errorf("Iteration %d: data mismatch", iteration)
			}
		}(i)
	}

	wg.Wait()
}

func TestCopyBufferEmptyReader(t *testing.T) {
	src := strings.NewReader("")
	dst := &bytes.Buffer{}

	n, err := copyBuffer(dst, src)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
	assert.Equal(t, "", dst.String())
}

func TestCopyBufferReaderError(t *testing.T) {
	// Create a reader that returns an error after some data
	src := &errorReader{data: []byte("test"), err: io.ErrUnexpectedEOF}
	dst := &bytes.Buffer{}

	_, err := copyBuffer(dst, src)
	assert.Error(t, err)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
}

// errorReader is a test helper that returns an error after reading its data
type errorReader struct {
	data []byte
	err  error
	pos  int
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, r.err
	}
	return n, nil
}

func BenchmarkCopyBufferPooled(b *testing.B) {
	data := strings.Repeat("A", DefaultBufferSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		src := strings.NewReader(data)
		dst := io.Discard
		_, _ = copyBuffer(dst, src)
	}
}

func BenchmarkCopyBufferStandard(b *testing.B) {
	data := strings.Repeat("A", DefaultBufferSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		src := strings.NewReader(data)
		dst := io.Discard
		_, _ = io.Copy(dst, src)
	}
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := getBuffer()
		putBuffer(buf)
	}
}

func BenchmarkBufferAllocate(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, DefaultBufferSize)
		_ = buf
	}
}
