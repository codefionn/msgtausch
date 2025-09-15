package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockConn is a mock implementation of net.Conn for testing
type mockConn struct {
	readData   [][]byte
	readIndex  int
	writeData  [][]byte
	readError  error
	writeError error
	closeError error
	closed     bool
	mu         sync.Mutex
}

func newMockConn() *mockConn {
	return &mockConn{
		readData:  make([][]byte, 0),
		writeData: make([][]byte, 0),
	}
}

func (m *mockConn) Read(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.readError != nil {
		return 0, m.readError
	}

	if m.readIndex >= len(m.readData) {
		return 0, errors.New("EOF")
	}

	data := m.readData[m.readIndex]
	m.readIndex++

	n := copy(b, data)
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writeError != nil {
		return 0, m.writeError
	}

	dataCopy := make([]byte, len(b))
	copy(dataCopy, b)
	m.writeData = append(m.writeData, dataCopy)

	return len(b), nil
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	return m.closeError
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) addReadData(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readData = append(m.readData, data)
}

func (m *mockConn) getWrittenData() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([][]byte, len(m.writeData))
	copy(result, m.writeData)
	return result
}

// mockCollector is a mock implementation of stats.Collector for testing
type mockCollector struct {
	mock.Mock
}

// Satisfy new full HTTP record API for mockCollector
func (m *mockCollector) RecordFullHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string,
	requestHeaders map[string][]string, requestBody []byte, timestamp time.Time) error {
	return nil
}

func (m *mockCollector) RecordFullHTTPResponse(ctx context.Context, connectionID int64, statusCode int,
	responseHeaders map[string][]string, responseBody []byte, timestamp time.Time) error {
	return nil
}

func (m *mockCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	args := m.Called(ctx, clientIP, targetHost, targetPort, protocol)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockCollector) EndConnection(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	args := m.Called(ctx, connectionID, bytesSent, bytesReceived, duration, closeReason)
	return args.Error(0)
}

func (m *mockCollector) RecordDataTransfer(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64) error {
	args := m.Called(ctx, connectionID, bytesSent, bytesReceived)
	return args.Error(0)
}

func (m *mockCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	args := m.Called(ctx, connectionID, method, url, host, userAgent, contentLength)
	return args.Error(0)
}

func (m *mockCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	args := m.Called(ctx, connectionID, statusCode, contentLength)
	return args.Error(0)
}

func (m *mockCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	args := m.Called(ctx, connectionID, method, url, host, userAgent, contentLength, headerSize)
	return args.Error(0)
}

func (m *mockCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	args := m.Called(ctx, connectionID, statusCode, contentLength, headerSize)
	return args.Error(0)
}

func (m *mockCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	args := m.Called(ctx, connectionID, errorType, errorMessage)
	return args.Error(0)
}

func (m *mockCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	args := m.Called(ctx, clientIP, targetHost, reason)
	return args.Error(0)
}

func (m *mockCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	args := m.Called(ctx, clientIP, targetHost)
	return args.Error(0)
}

func (m *mockCollector) GetOverviewStats(ctx context.Context) (*stats.OverviewStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*stats.OverviewStats), args.Error(1)
}

func (m *mockCollector) GetTopDomains(ctx context.Context, limit int) ([]stats.DomainStats, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]stats.DomainStats), args.Error(1)
}

func (m *mockCollector) GetSecurityEvents(ctx context.Context, limit int) ([]stats.SecurityEventInfo, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]stats.SecurityEventInfo), args.Error(1)
}

func (m *mockCollector) GetRecentErrors(ctx context.Context, limit int) ([]stats.ErrorSummary, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]stats.ErrorSummary), args.Error(1)
}

func (m *mockCollector) GetBandwidthStats(ctx context.Context, days int) (*stats.BandwidthStats, error) {
	args := m.Called(ctx, days)
	return args.Get(0).(*stats.BandwidthStats), args.Error(1)
}

func (m *mockCollector) GetSystemStats(ctx context.Context) (*stats.SystemStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*stats.SystemStats), args.Error(1)
}

func (m *mockCollector) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockCollector) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewTrackedConn(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	assert.NotNil(t, tracked)
	assert.Equal(t, mockConn, tracked.Conn)
	assert.Equal(t, mockCollector, tracked.collector)
	assert.Equal(t, connectionID, tracked.connectionID)
	assert.Equal(t, ctx, tracked.ctx)
	assert.Equal(t, int64(0), tracked.bytesSent)
	assert.Equal(t, int64(0), tracked.bytesReceived)
	assert.WithinDuration(t, time.Now(), tracked.startTime, time.Second)
}

func TestTrackedConn_Read(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	// Add test data to mock connection
	testData := []byte("hello world")
	mockConn.addReadData(testData)

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	buffer := make([]byte, 1024)
	n, err := tracked.Read(buffer)

	require.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, testData, buffer[:n])
	assert.Equal(t, int64(len(testData)), tracked.bytesReceived)
	assert.Equal(t, int64(0), tracked.bytesSent)
}

func TestTrackedConn_Write(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	testData := []byte("hello world")
	n, err := tracked.Write(testData)

	require.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, int64(len(testData)), tracked.bytesSent)
	assert.Equal(t, int64(0), tracked.bytesReceived)

	writtenData := mockConn.getWrittenData()
	require.Len(t, writtenData, 1)
	assert.Equal(t, testData, writtenData[0])
}

func TestTrackedConn_PeriodicDataTransferReporting(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	// Set up expectations for periodic reporting (every ~10KB)
	mockCollector.On("RecordDataTransfer", ctx, connectionID, int64(10240), int64(0)).Return(nil).Once()

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	// Write exactly 10KB to trigger periodic reporting
	data := make([]byte, 10240)
	for i := range data {
		data[i] = byte(i % 256)
	}

	n, err := tracked.Write(data)
	require.NoError(t, err)
	assert.Equal(t, 10240, n)

	mockCollector.AssertExpectations(t)
}

func TestTrackedConn_PeriodicDataTransferReporting_ReadAndWrite(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	// Add data for reading
	readData := make([]byte, 5120)
	mockConn.addReadData(readData)

	// Set up expectations for periodic reporting when combined read+write reaches 10KB
	mockCollector.On("RecordDataTransfer", ctx, connectionID, int64(5120), int64(5120)).Return(nil).Once()

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	// Write 5KB
	writeData := make([]byte, 5120)
	_, err := tracked.Write(writeData)
	require.NoError(t, err)

	// Read 5KB - this should trigger reporting because total is now 10KB
	buffer := make([]byte, 5120)
	_, err = tracked.Read(buffer)
	require.NoError(t, err)

	mockCollector.AssertExpectations(t)
}

func TestTrackedConn_Close_Normal(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	// Write some data first
	testData := []byte("hello")
	_, err := tracked.Write(testData)
	require.NoError(t, err)

	// Set up expectations for final reporting
	mockCollector.On("RecordDataTransfer", ctx, connectionID, int64(5), int64(0)).Return(nil).Once()
	mockCollector.On("EndConnection", ctx, connectionID, int64(5), int64(0), mock.AnythingOfType("time.Duration"), "normal").Return(nil).Once()

	err = tracked.Close()
	assert.NoError(t, err)
	assert.True(t, mockConn.closed)

	mockCollector.AssertExpectations(t)
}

func TestTrackedConn_Close_WithError(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	closeError := errors.New("connection reset")
	mockConn.closeError = closeError

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	// Set up expectations for final reporting with error
	// Note: RecordDataTransfer is not called when no bytes are transferred
	mockCollector.On("EndConnection", ctx, connectionID, int64(0), int64(0), mock.AnythingOfType("time.Duration"), closeError.Error()).Return(nil).Once()

	err := tracked.Close()
	assert.Equal(t, closeError, err)
	assert.True(t, mockConn.closed)

	mockCollector.AssertExpectations(t)
}

func TestTrackedConn_Close_OnlyOnce(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	// Set up expectations - should only be called once despite multiple Close() calls
	// Note: RecordDataTransfer is not called when no bytes are transferred
	mockCollector.On("EndConnection", ctx, connectionID, int64(0), int64(0), mock.AnythingOfType("time.Duration"), "normal").Return(nil).Once()

	// Call Close multiple times
	err1 := tracked.Close()
	err2 := tracked.Close()
	err3 := tracked.Close()

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NoError(t, err3)

	mockCollector.AssertExpectations(t)
}

func TestTrackedConn_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	// Add data for reading
	for i := 0; i < 100; i++ {
		mockConn.addReadData([]byte("data"))
	}

	// Allow any number of RecordDataTransfer calls
	mockCollector.On("RecordDataTransfer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockCollector.On("EndConnection", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	var wg sync.WaitGroup

	// Start multiple goroutines doing reads and writes
	for i := 0; i < 10; i++ {
		wg.Add(2)

		// Reader goroutine
		go func() {
			defer wg.Done()
			buffer := make([]byte, 4)
			for j := 0; j < 10; j++ {
				_, _ = tracked.Read(buffer)
			}
		}()

		// Writer goroutine
		go func() {
			defer wg.Done()
			data := []byte("test")
			for j := 0; j < 10; j++ {
				_, _ = tracked.Write(data)
			}
		}()
	}

	wg.Wait()

	// Close the connection
	err := tracked.Close()
	assert.NoError(t, err)

	// Verify that the byte counters are consistent
	// With 10 goroutines each doing 10 writes of 4 bytes = 400 bytes sent
	// With 10 goroutines each doing 10 reads of 4 bytes = 400 bytes received
	assert.Equal(t, int64(400), tracked.bytesSent)
	assert.Equal(t, int64(400), tracked.bytesReceived)
}

func TestTrackedConn_ReadError(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	readError := errors.New("read failed")
	mockConn.readError = readError

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	buffer := make([]byte, 1024)
	n, err := tracked.Read(buffer)

	assert.Equal(t, readError, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, int64(0), tracked.bytesReceived)
}

func TestTrackedConn_WriteError(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	writeError := errors.New("write failed")
	mockConn.writeError = writeError

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	testData := []byte("hello")
	n, err := tracked.Write(testData)

	assert.Equal(t, writeError, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, int64(0), tracked.bytesSent)
}

func TestTrackedConn_FlushLogic(t *testing.T) {
	ctx := context.Background()
	mockConn := newMockConn()
	mockCollector := &mockCollector{}
	connectionID := int64(123)

	tracked := newTrackedConn(ctx, mockConn, mockCollector, connectionID)

	// Set up expectations for multiple flushes
	// First flush at 10KB
	mockCollector.On("RecordDataTransfer", ctx, connectionID, int64(10240), int64(0)).Return(nil).Once()
	// Second flush at 20KB (delta should be 10KB)
	mockCollector.On("RecordDataTransfer", ctx, connectionID, int64(10240), int64(0)).Return(nil).Once()
	// Final flush on close (delta should be remaining bytes)
	mockCollector.On("RecordDataTransfer", ctx, connectionID, int64(1024), int64(0)).Return(nil).Once()
	mockCollector.On("EndConnection", ctx, connectionID, int64(21504), int64(0), mock.AnythingOfType("time.Duration"), "normal").Return(nil).Once()

	// Write data to trigger multiple flushes
	data1 := make([]byte, 10240) // First flush
	_, err := tracked.Write(data1)
	require.NoError(t, err)

	data2 := make([]byte, 10240) // Second flush
	_, err = tracked.Write(data2)
	require.NoError(t, err)

	data3 := make([]byte, 1024) // Remaining data
	_, err = tracked.Write(data3)
	require.NoError(t, err)

	err = tracked.Close()
	require.NoError(t, err)

	mockCollector.AssertExpectations(t)
}
