package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

// buildTestClient returns an http.Client with a Transport that provides DialContext.
func buildTestClient() *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("test dial not used")
		},
	}
	return &http.Client{Transport: tr}
}

// Test that CONNECT handling does not panic when server.proxy is nil.
func TestHandleConnect_NoProxy_NoPanic(t *testing.T) {
	srv := &Server{
		config: &config.Config{
			TimeoutSeconds: 1,
			Interception:   config.InterceptionConfig{Enabled: false},
		},
		// intentionally no proxy set (nil)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:1", nil)
	req.Host = "127.0.0.1:1"
	req.RemoteAddr = "127.0.0.1:54321"

	ctx := WithClient(req.Context(), buildTestClient())
	ctx = WithClientIP(ctx, "127.0.0.1")
	req = req.WithContext(ctx)

	// Should not panic; expect a 502 Bad Gateway due to failed upstream dial
	srv.handleConnect(rr, req, 0, "127.0.0.1", "127.0.0.1", 1)

	if rr.Code == 0 {
		t.Fatalf("no response written; expected status code")
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway, got %d", rr.Code)
	}
}

// Test that CONNECT handling does not panic when proxy.Collector is nil.
func TestHandleConnect_CollectorNil_NoPanic(t *testing.T) {
	cfg := &config.Config{TimeoutSeconds: 1, Interception: config.InterceptionConfig{Enabled: false}}
	p := &Proxy{config: cfg /* Collector intentionally nil */}

	srv := &Server{
		config: cfg,
		proxy:  p,
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:1", nil)
	req.Host = "127.0.0.1:1"
	req.RemoteAddr = "127.0.0.1:54321"

	ctx := WithClient(req.Context(), buildTestClient())
	ctx = WithClientIP(ctx, "127.0.0.1")
	req = req.WithContext(ctx)

	// Should not panic; expect a 502 Bad Gateway due to failed upstream dial
	srv.handleConnect(rr, req, 0, "127.0.0.1", "127.0.0.1", 1)

	if rr.Code == 0 {
		t.Fatalf("no response written; expected status code")
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway, got %d", rr.Code)
	}
}
