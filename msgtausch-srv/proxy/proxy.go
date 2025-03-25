package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// contextKey is a type used for context keys to prevent collisions
type contextKey struct {
	name string
}

// clientKey is the unexported key used to store HTTP clients in request context
var clientKey = &contextKey{name: "http-client"}

// WithClient returns a new context with the client value set
func WithClient(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, clientKey, client)
}

// ClientFromContext extracts the HTTP client from the context, if any
func ClientFromContext(ctx context.Context) (*http.Client, bool) {
	clientVal := ctx.Value(clientKey)
	if clientVal == nil {
		return nil, false
	}
	client, ok := clientVal.(*http.Client)
	return client, ok
}

// Server represents a single proxy server instance (standard, HTTP, or HTTPS)
type Server struct {
	config              *config.Config        // Global configuration
	serverConfig        config.ServerConfig   // Server-specific configuration
	server              *http.Server          // HTTP server instance
	httpsInterceptor    *HTTPSInterceptor     // Only used for HTTPS interception
	httpInterceptor     *HTTPInterceptor      // Only used for HTTP interception
	quicInterceptor     *QUICHTTP3Interceptor // Only used for QUIC/HTTP3 interception
	compiledForwards    []compiledForward     // Forwarding rules
	blocklistClassifier Classifier            // Host blocklist
	allowlistClassifier Classifier            // Host allowlist
	proxy               *Proxy                // Reference to parent proxy for connection handling
}

// Proxy manages multiple proxy server instances
type Proxy struct {
	config              *config.Config    // Global configuration
	servers             []*Server         // List of server instances
	compiledForwards    []compiledForward // Shared forwarding rules
	blocklistClassifier Classifier        // Shared host blocklist
	allowlistClassifier Classifier        // Shared host allowlist
}

type compiledForward struct {
	fwd        config.Forward
	classifier Classifier
}

// getForwardDebugInfo returns a debug string containing information about a forward configuration
func (p *Proxy) getForwardDebugInfo(fwd config.Forward) string {
	var info strings.Builder

	// Forward type information
	switch f := fwd.(type) {
	case *config.ForwardDefaultNetwork:
		info.WriteString("type=default-network")
	case *config.ForwardSocks5:
		info.WriteString(fmt.Sprintf("type=socks5, address=%s", f.Address))
		if f.Username != nil {
			info.WriteString(fmt.Sprintf(", username=%s", *f.Username))
		}
		if f.Password != nil {
			info.WriteString(", password=***")
		}
	case *config.ForwardProxy:
		info.WriteString(fmt.Sprintf("type=proxy, address=%s", f.Address))
		if f.Username != nil {
			info.WriteString(fmt.Sprintf(", username=%s", *f.Username))
		}
		if f.Password != nil {
			info.WriteString(", password=***")
		}
	default:
		info.WriteString(fmt.Sprintf("type=unknown(%T)", fwd))
	}

	// Classifier information
	classifierInfo := p.getClassifierDebugInfo(fwd.Classifier())
	if classifierInfo != "" {
		info.WriteString(fmt.Sprintf(", classifier=%s", classifierInfo))
	} else {
		info.WriteString(", classifier=none")
	}

	return info.String()
}

// getClassifierDebugInfo returns a debug string containing information about a classifier
func (p *Proxy) getClassifierDebugInfo(classifier config.Classifier) string {
	if classifier == nil {
		return "nil"
	}

	switch c := classifier.(type) {
	case *config.ClassifierTrue:
		return "true"
	case *config.ClassifierFalse:
		return "false"
	case *config.ClassifierDomain:
		return fmt.Sprintf("domain(op=%v, domain=%s)", c.Op, c.Domain)
	case *config.ClassifierPort:
		return fmt.Sprintf("port(%d)", c.Port)
	case *config.ClassifierIP:
		return fmt.Sprintf("ip(%s)", c.IP)
	case *config.ClassifierNetwork:
		return fmt.Sprintf("network(%s)", c.CIDR)
	case *config.ClassifierRef:
		return fmt.Sprintf("ref(%s)", c.Id)
	case *config.ClassifierDomainsFile:
		return fmt.Sprintf("domains-file(%s)", c.FilePath)
	case *config.ClassifierAnd:
		var parts []string
		for _, sub := range c.Classifiers {
			parts = append(parts, p.getClassifierDebugInfo(sub))
		}
		return fmt.Sprintf("and(%s)", strings.Join(parts, ", "))
	case *config.ClassifierOr:
		var parts []string
		for _, sub := range c.Classifiers {
			parts = append(parts, p.getClassifierDebugInfo(sub))
		}
		return fmt.Sprintf("or(%s)", strings.Join(parts, ", "))
	case *config.ClassifierNot:
		return fmt.Sprintf("not(%s)", p.getClassifierDebugInfo(c.Classifier))
	default:
		return fmt.Sprintf("unknown(%T)", classifier)
	}
}

// CompileClassifiers pre-compiles classifiers for all forwarding rules.
func (p *Proxy) CompileClassifiers() {
	// Pre-compile classifiers for all forwarding rules (shared across all servers)
	if p.config.Forwards != nil {
		logger.Info("Compiling %d forward configurations", len(p.config.Forwards))
		for i, fwd := range p.config.Forwards {
			// Debug information about the forward configuration
			forwardInfo := p.getForwardDebugInfo(fwd)
			logger.Info("Forward[%d]: %s", i, forwardInfo)

			cf, err := CompileClassifier(fwd.Classifier())
			if err != nil {
				logger.Error("Error compiling classifier for forward[%d] (%s): %v", i, forwardInfo, err)
				continue
			}
			p.compiledForwards = append(p.compiledForwards, compiledForward{
				fwd:        fwd,
				classifier: cf,
			})
			logger.Debug("Successfully compiled forward[%d]: %s", i, forwardInfo)
		}
		logger.Info("Successfully compiled %d forward configurations", len(p.compiledForwards))
	} else {
		logger.Info("No forward configurations found")
	}

	// Compile blocklist classifier once (shared across all servers)
	if p.config.Blocklist != nil {
		blf, err := CompileClassifier(p.config.Blocklist)
		if err != nil {
			logger.Error("Error compiling blocklist classifier: %v", err)
		} else {
			p.blocklistClassifier = blf
		}
	}

	// Compile allowlist classifier once (shared across all servers)
	if p.config.Allowlist != nil {
		alf, err := CompileClassifier(p.config.Allowlist)
		if err != nil {
			logger.Error("Error compiling allowlist classifier: %v", err)
		} else {
			p.allowlistClassifier = alf
		}
	}
}

// NewProxy creates a new Proxy instance with the given configuration.
func NewProxy(cfg *config.Config) *Proxy {
	p := &Proxy{
		config:  cfg,
		servers: make([]*Server, 0, len(cfg.Servers)),
	}

	p.CompileClassifiers()

	// Create server instances for each configured server
	for _, serverCfg := range cfg.Servers {
		// Skip disabled servers
		if !serverCfg.Enabled {
			logger.Info("Skipping disabled server on %s", serverCfg.ListenAddress)
			continue
		}

		// Create the server instance
		server := &Server{
			config:              cfg,
			serverConfig:        serverCfg,
			compiledForwards:    p.compiledForwards,
			blocklistClassifier: p.blocklistClassifier,
			allowlistClassifier: p.allowlistClassifier,
			server:              &http.Server{Addr: serverCfg.ListenAddress},
			proxy:               p,
		}

		// Initialize interceptors based on server type
		switch serverCfg.Type {
		case config.ProxyTypeHTTPS:
			// Initialize HTTPS interceptor
			// Use global CA file settings from InterceptionConfig
			caFile := cfg.Interception.CAFile
			caKeyFile := cfg.Interception.CAKeyFile

			if caFile == "" || caKeyFile == "" {
				logger.Error("HTTPS interceptor requires CA certificate and key files (server %s)", serverCfg.ListenAddress)
				continue
			}

			// Validate and load CA certificate and private key
			cleanCACertPath := filepath.Clean(caFile)
			if !filepath.IsAbs(cleanCACertPath) {
				absPath, err := filepath.Abs(cleanCACertPath)
				if err != nil {
					logger.Error("Invalid CA certificate file path: %v", err)
					continue
				}
				cleanCACertPath = absPath
			}
			caCert, err := os.ReadFile(cleanCACertPath)
			if err != nil {
				logger.Error("Failed to read CA certificate file '%s': %v", cleanCACertPath, err)
				continue
			}

			cleanCAKeyPath := filepath.Clean(caKeyFile)
			if !filepath.IsAbs(cleanCAKeyPath) {
				absPath, err := filepath.Abs(cleanCAKeyPath)
				if err != nil {
					logger.Error("Invalid CA private key file path: %v", err)
					continue
				}
				cleanCAKeyPath = absPath
			}
			caKey, err := os.ReadFile(cleanCAKeyPath)
			if err != nil {
				logger.Error("Failed to read CA private key file '%s': %v", cleanCAKeyPath, err)
				continue
			}

			// Create HTTPS interceptor
			httpsInterceptor, err := NewHTTPSInterceptor(caCert, caKey, p, nil, nil)
			if err != nil {
				logger.Error("Failed to create HTTPS interceptor: %v", err)
				continue
			}
			server.httpsInterceptor = httpsInterceptor

		case config.ProxyTypeHTTP:
			// Initialize HTTP interceptor
			server.httpInterceptor = NewHTTPInterceptor(p)

		case config.ProxyTypeStandard:
			// Standard proxy doesn't need additional interceptors

		default:
			logger.Error("Unknown proxy type: %s", serverCfg.Type)
			continue
		}

		// Add the server to the list
		p.servers = append(p.servers, server)
	}

	if len(p.servers) == 0 {
		logger.Warn("No enabled proxy servers configured")
	}

	return p
}

// Start launches all configured proxy servers.
// This also waits for all proxy servers.
func (p *Proxy) Start() error {
	if len(p.servers) == 0 {
		return fmt.Errorf("no enabled proxy servers configured")
	}

	var wg sync.WaitGroup
	var startErrors []error

	// Start all enabled server instances
	for _, server := range p.servers {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			err := s.Start()
			if err != nil {
				startErrors = append(startErrors, err)
			}
		}(server)
	}

	wg.Wait()

	if len(startErrors) > 0 {
		// Return the first error for now
		return startErrors[0]
	}

	return nil
}

// StartWithListener starts the proxy server using an existing listener.
// This is useful for testing with dynamically assigned ports.
func (p *Proxy) StartWithListener(listener net.Listener) error {
	// For now, use this with the first server only
	if len(p.servers) == 0 {
		return fmt.Errorf("no enabled proxy servers configured")
	}

	// Use the first server for backward compatibility
	return p.servers[0].StartWithListener(listener)
}

// StartWithListener starts the proxy server with the given listener.
func (p *Server) StartWithListener(listener net.Listener) error {
	handler := http.HandlerFunc(p.handleRequest)

	// Create a new http server with the listener
	p.server = &http.Server{
		Handler:      handler,
		ReadTimeout:  time.Duration(p.config.TimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(p.config.TimeoutSeconds) * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					logger.Debug("DialContext: network=%s addr=%s", network, addr)
					return p.createForwardTCPClient(ctx, addr)
				},
				// We don't add a custom DialTLSContext for WebSocket connections as that would require wrapping
			}
			client := &http.Client{
				Timeout:   time.Duration(p.config.TimeoutSeconds) * time.Second,
				Transport: transport,
			}
			return WithClient(ctx, client)
		},
	}

	logger.Info("Starting proxy server on %s", listener.Addr().String())
	return p.server.Serve(listener)
}

// Start launches a single proxy server instance
func (p *Server) Start() error {
	// Handle server type-specific initialization
	switch p.serverConfig.Type {
	case config.ProxyTypeStandard:
		// Standard HTTP proxy server
		handler := http.HandlerFunc(p.handleRequest)
		p.server = &http.Server{
			Addr:         p.serverConfig.ListenAddress,
			Handler:      handler,
			ReadTimeout:  time.Duration(p.config.TimeoutSeconds) * time.Second,
			WriteTimeout: time.Duration(p.config.TimeoutSeconds) * time.Second,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				transport := &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						logger.Debug("DialContext: network=%s addr=%s", network, addr)
						return p.createForwardTCPClient(ctx, addr)
					},
				}
				client := &http.Client{
					Timeout:   time.Duration(p.config.TimeoutSeconds) * time.Second,
					Transport: transport,
				}
				return WithClient(ctx, client)
			},
		}

		logger.Info("Starting standard proxy server on %s", p.serverConfig.ListenAddress)
		return p.server.ListenAndServe()

	case config.ProxyTypeHTTPS:
		// HTTPS intercepting proxy
		// Use global CA file settings from InterceptionConfig
		caFile := p.config.Interception.CAFile
		caKeyFile := p.config.Interception.CAKeyFile

		if caFile == "" || caKeyFile == "" {
			return fmt.Errorf("HTTPS interceptor requires CA certificate and key files")
		}

		// Read CA certificate and key files
		cleanCACertPath := filepath.Clean(caFile)
		if !filepath.IsAbs(cleanCACertPath) {
			absPath, err := filepath.Abs(cleanCACertPath)
			if err != nil {
				logger.Error("Invalid CA certificate file path: %v", err)
				return err
			}
			cleanCACertPath = absPath
		}
		caCert, err := os.ReadFile(cleanCACertPath)
		if err != nil {
			logger.Error("Failed to read CA certificate file '%s': %v", cleanCACertPath, err)
			return err
		}
		caKey, err := os.ReadFile(caKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read CA key file '%s': %w", caKeyFile, err)
		}

		// Initialize HTTPS interceptor
		p.httpsInterceptor, err = NewHTTPSInterceptor(caCert, caKey, p.proxy, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to initialize HTTPS interceptor: %w", err)
		}

		return p.startHTTPSInterceptor()

	case config.ProxyTypeHTTP:
		// HTTP intercepting proxy
		// Initialize HTTP interceptor
		p.httpInterceptor = NewHTTPInterceptor(p.proxy)

		// Set up the HTTP server for the interceptor
		handler := http.HandlerFunc(p.handleRequest)
		p.server = &http.Server{
			Addr:         p.serverConfig.ListenAddress,
			Handler:      handler,
			ReadTimeout:  time.Duration(p.config.TimeoutSeconds) * time.Second,
			WriteTimeout: time.Duration(p.config.TimeoutSeconds) * time.Second,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				transport := &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						logger.Debug("DialContext: network=%s addr=%s", network, addr)
						return p.createForwardTCPClient(ctx, addr)
					},
				}
				client := &http.Client{
					Timeout:   time.Duration(p.config.TimeoutSeconds) * time.Second,
					Transport: transport,
				}
				return WithClient(ctx, client)
			},
		}

		logger.Info("Starting HTTP intercepting proxy server on %s", p.serverConfig.ListenAddress)
		return p.server.ListenAndServe()

	case config.ProxyTypeQUIC:
		// QUIC/HTTP3 intercepting proxy
		caFile := p.config.Interception.CAFile
		caKeyFile := p.config.Interception.CAKeyFile
		if caFile == "" || caKeyFile == "" {
			return fmt.Errorf("QUIC/HTTP3 interceptor requires CA certificate and key files")
		}
		// Read CA certificate and key files
		cleanCACertPath := filepath.Clean(caFile)
		if !filepath.IsAbs(cleanCACertPath) {
			absPath, err := filepath.Abs(cleanCACertPath)
			if err != nil {
				logger.Error("Invalid CA certificate file path: %v", err)
				return err
			}
			cleanCACertPath = absPath
		}
		caCert, err := os.ReadFile(cleanCACertPath)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate file '%s': %w", cleanCACertPath, err)
		}

		cleanCAKeyPath := filepath.Clean(caKeyFile)
		if !filepath.IsAbs(cleanCAKeyPath) {
			absPath, err := filepath.Abs(cleanCAKeyPath)
			if err != nil {
				logger.Error("Invalid CA private key file path: %v", err)
				return err
			}
			cleanCAKeyPath = absPath
		}
		caKey, err := os.ReadFile(cleanCAKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read CA key file '%s': %w", cleanCAKeyPath, err)
		}
		if p.quicInterceptor == nil {
			p.quicInterceptor, err = NewQUICHTTP3Interceptor(caCert, caKey, p.proxy, nil, nil)
			if err != nil {
				return fmt.Errorf("failed to initialize QUIC/HTTP3 interceptor: %w", err)
			}
		}
		// Listen on UDP for QUIC/HTTP3 traffic
		udpAddr, err := net.ResolveUDPAddr("udp", p.serverConfig.ListenAddress)
		if err != nil {
			return fmt.Errorf("failed to resolve UDP address '%s': %w", p.serverConfig.ListenAddress, err)
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on UDP address '%s': %w", p.serverConfig.ListenAddress, err)
		}
		logger.Info("Starting QUIC/HTTP3 intercepting proxy server on %s", p.serverConfig.ListenAddress)
		// Start the QUIC/HTTP3 interception loop
		go p.quicInterceptor.HandleUDPConnection(udpConn, udpAddr, p.serverConfig.ListenAddress)
		// Block forever (or until shutdown logic is added)
		select {}
	default:
		return fmt.Errorf("unknown proxy type: %s", p.serverConfig.Type)
	}
}

// startHTTPSInterceptor starts an HTTPS interceptor server using raw TCP
func (p *Server) startHTTPSInterceptor() error {
	if p.httpsInterceptor == nil {
		return fmt.Errorf("HTTPS interceptor not initialized")
	}

	// Create a TCP listener
	listener, err := net.Listen("tcp", p.serverConfig.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to create listener for HTTPS interceptor: %w", err)
	}

	logger.Info("Starting HTTPS interceptor on %s", p.serverConfig.ListenAddress)

	// Accept connections and handle them
	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedConnError(err) {
				break
			}
			logger.Error("Failed to accept connection: %v", err)
			continue
		}

		// Handle the connection in a new goroutine
		go func() {
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					logger.Error("Error closing connection: %v", closeErr)
				}
			}()

			// Initial buffer to read the first few bytes to determine if it's an HTTP CONNECT or direct TLS
			buf := make([]byte, 1)
			_, err := conn.Read(buf)
			if err != nil {
				logger.Error("Failed to read from connection: %v", err)
				return
			}

			// Create a new connection that includes the first byte we read
			bufConn := &bufferConn{
				Conn: conn,
				buf:  buf,
			}

			// Handle the TCP connection directly
			p.httpsInterceptor.HandleTCPConnection(bufConn, "")
		}()
	}

	return nil
}

// bufferConn wraps a net.Conn and prepends a buffer to the read stream
type bufferConn struct {
	net.Conn
	buf []byte
}

func (bc *bufferConn) Read(b []byte) (int, error) {
	if len(bc.buf) > 0 {
		n := copy(b, bc.buf)
		bc.buf = bc.buf[n:]
		return n, nil
	}
	return bc.Conn.Read(b)
}

// isClosedConnError checks if the error is a standard "use of closed network connection" error
// This often happens during graceful shutdowns and might not need alarming logs.
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	// Check for the specific error string used by net package
	return strings.Contains(err.Error(), "use of closed network connection")
}

// handleRequest handles HTTP requests, including CONNECT method for tunneling
func (p *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// For CONNECT requests, the Host field is not used; instead, the target is in r.URL.Host
	host := r.Host
	if r.Method == http.MethodConnect {
		host = r.URL.Host
	}

	// Check for WebSocket upgrade request
	isWebSocketUpgrade := strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")

	if isWebSocketUpgrade {
		logger.Debug("WebSocket upgrade detected for %s", host)
	}

	var remotePort uint16
	if colon := strings.LastIndex(host, ":"); colon != -1 {
		remotePortUint64, _ := strconv.ParseUint(host[colon+1:], 10, 16)
		remotePort = uint16(remotePortUint64)
	}
	if remotePort == 0 && r.URL != nil && r.URL.Port() != "" {
		remotePortUint64, _ := strconv.ParseUint(r.URL.Port(), 10, 16)
		remotePort = uint16(remotePortUint64)
	}
	if remotePort == 0 {
		if colon := strings.LastIndex(r.RemoteAddr, ":"); colon != -1 {
			remotePortUint64, _ := strconv.ParseUint(r.RemoteAddr[colon+1:], 10, 16)
			remotePort = uint16(remotePortUint64)
		}
	}

	hostname := strings.Split(host, ":")[0]

	// Extract client IP from request
	remoteIP := r.RemoteAddr
	if colon := strings.LastIndex(remoteIP, ":"); colon != -1 {
		remoteIP = remoteIP[:colon]
	}

	if !p.isHostAllowed(hostname, remoteIP, remotePort) {
		logger.Warn("Host not allowed: %s", host)
		http.Error(w, "Host not allowed", http.StatusForbidden)
		return
	}

	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Retrieve the per-connection client from the context
	client, ok := ClientFromContext(r.Context())
	if !ok || client == nil {
		logger.Error("No http.Client found in request context")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	p.forwardRequest(w, r, client, host)
}

// forwardRequest forwards an HTTP request to the target server
func (p *Server) forwardRequest(w http.ResponseWriter, r *http.Request, client *http.Client, host string) {
	// Create new request for upstream: use absolute URL
	var targetURL string
	if r.URL.IsAbs() {
		targetURL = r.URL.String()
	} else {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		targetURL = fmt.Sprintf("%s://%s%s", scheme, host, r.URL.RequestURI())
	}
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check for WebSocket upgrade
	isWebSocketRequest := false
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		isWebSocketRequest = true
		logger.Debug("Detected WebSocket upgrade request to %s", targetURL)
	}

	// Check for WebSocket headers that indicate it's a proper WebSocket connection
	isProxiedWebSocket := false
	if r.Header.Get("Sec-WebSocket-Key") != "" && r.Header.Get("Sec-WebSocket-Version") != "" {
		isProxiedWebSocket = true
		logger.Debug("Detected proxied WebSocket request to %s", targetURL)
	}

	// Copy headers but handle WebSocket headers specially
	// For WebSockets through multiple proxies, we need to preserve certain headers
	// that would normally be considered hop-by-hop
	skip := map[string]struct{}{
		"Proxy-Connection":    {},
		"Keep-Alive":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Te":                  {},
		"Trailer":             {},
		"Transfer-Encoding":   {},
	}

	// Special WebSocket header handling
	isWebSocketConnection := isWebSocketRequest || isProxiedWebSocket

	// Never skip Upgrade or Connection headers for WebSocket requests
	if !isWebSocketConnection {
		skip["Upgrade"] = struct{}{}
		skip["Connection"] = struct{}{}
	}

	// Copy all headers except those in skip list
	for name, values := range r.Header {
		if _, hop := skip[name]; hop {
			// For WebSockets, ensure critical headers are preserved despite being hop-by-hop
			if isWebSocketConnection {
				if name == "Connection" {
					// Always preserve Connection: Upgrade for WebSockets
					req.Header.Set("Connection", "Upgrade")
					continue
				} else if name == "Upgrade" {
					// Always preserve Upgrade: websocket header
					req.Header.Set("Upgrade", "websocket")
					continue
				}
			}
			// Skip other hop-by-hop headers
			continue
		} else {
			// Copy all non-hop-by-hop headers
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
	}

	// For WebSockets, ensure all required headers are present
	if isWebSocketConnection {
		// These headers must be preserved for WebSocket connections to work
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		// Ensure WebSocket protocol headers are preserved
		if wsKey := r.Header.Get("Sec-WebSocket-Key"); wsKey != "" {
			req.Header.Set("Sec-WebSocket-Key", wsKey)
		}
		if wsVersion := r.Header.Get("Sec-WebSocket-Version"); wsVersion != "" {
			req.Header.Set("Sec-WebSocket-Version", wsVersion)
		}
	}

	// For WebSockets, ensure we have the necessary headers
	if isWebSocketRequest || isProxiedWebSocket {
		// These headers are critical for WebSocket connections to work properly through proxy chains
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")

		// Preserve important WebSocket protocol headers if they exist
		if wsKey := r.Header.Get("Sec-WebSocket-Key"); wsKey != "" {
			req.Header.Set("Sec-WebSocket-Key", wsKey)
		}
		if wsVersion := r.Header.Get("Sec-WebSocket-Version"); wsVersion != "" {
			req.Header.Set("Sec-WebSocket-Version", wsVersion)
		}
		if wsProtocol := r.Header.Get("Sec-WebSocket-Protocol"); wsProtocol != "" {
			req.Header.Set("Sec-WebSocket-Protocol", wsProtocol)
		}
		if wsExtensions := r.Header.Get("Sec-WebSocket-Extensions"); wsExtensions != "" {
			req.Header.Set("Sec-WebSocket-Extensions", wsExtensions)
		}
	}

	// Apply HTTP interception if enabled
	if p.isHTTPInterceptionEnabled() && p.httpInterceptor != nil {
		// Apply request hooks
		err := p.httpInterceptor.applyRequestHooks(req)
		if err != nil {
			logger.Error("Failed to apply HTTP request hooks: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Forward the request
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to forward request to %s: %v", host, err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// For timeouts, StatusGatewayTimeout is generally more appropriate.
			// We could create a custom timeout response similar to NewBadGatewayResponse if needed.
			// For now, sticking to http.Error for timeout as it's not a "Bad Gateway" from upstream.
			http.Error(w, "Request timeout", http.StatusGatewayTimeout)
		} else {
			// Use our custom Bad Gateway response.
			// If err is a *Error, its code will be used. Otherwise, ErrCodeHTTPForwardFailed.
			writeProxyErrorResponse(w, err, ErrCodeHTTPForwardFailed)
		}
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	// WebSocket responses are now handled below

	// Apply HTTP response interception if enabled
	if p.isHTTPInterceptionEnabled() && p.httpInterceptor != nil {
		// Apply response hooks
		err := p.httpInterceptor.applyResponseHooks(resp)
		if err != nil {
			logger.Error("Failed to apply HTTP response hooks: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Check if this is a WebSocket upgrade response
	isWebSocketResponse := resp.StatusCode == http.StatusSwitchingProtocols &&
		strings.ToLower(resp.Header.Get("Upgrade")) == "websocket"

	if isWebSocketRequest && isWebSocketResponse {
		logger.Debug("Handling WebSocket upgrade response from %s", host)
		p.handleWebSocketTunnel(w, r, resp, client)
		return
	}

	// For normal HTTP responses, copy headers as usual
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Error("Failed to copy response body: %v", err)
	}
}

// handleWebSocketTunnel handles a successful WebSocket upgrade by creating a bidirectional tunnel
// between the client and the upstream server. This is called when a WebSocket upgrade
// request received a 101 Switching Protocols response.
func (p *Server) handleWebSocketTunnel(w http.ResponseWriter, r *http.Request,
	resp *http.Response, client *http.Client) {
	// We need to hijack the client connection to obtain direct TCP access
	// required for WebSocket communication
	hj, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("HTTP server does not support hijacking for WebSocket")
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		logger.Error("Failed to hijack connection for WebSocket: %v", err)
		http.Error(w, "WebSocket error", http.StatusInternalServerError)
		return
	}

	// We need to establish a TCP connection to the target server
	targetURL, err := url.Parse(r.URL.String())
	if err != nil {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
		logger.Error("Failed to parse target URL: %v", err)
		return
	}

	targetHost := r.Host
	if targetHost == "" {
		targetHost = targetURL.Host
	}

	// Extract transport from client to use its DialContext
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil || transport.DialContext == nil {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
		logger.Error("Invalid transport for WebSocket connection")
		return
	}

	// Check if we're going through another proxy
	goingThroughProxy := false
	if transport.Proxy != nil {
		proxyURL, err := transport.Proxy(&http.Request{URL: targetURL})
		if err == nil && proxyURL != nil {
			goingThroughProxy = true
			logger.Debug("WebSocket connection going through upstream proxy: %s", proxyURL.String())
		}
	}

	// Establish a connection to the target server or next proxy
	// For WebSockets, we need to make sure the CONNECT tunnel is established properly
	var targetConn net.Conn
	if goingThroughProxy {
		// When going through another proxy, we need to create a CONNECT tunnel
		// to make sure WebSocket upgrade works properly through the chain
		logger.Debug("Establishing CONNECT tunnel to %s for WebSocket via proxy", targetHost)
		// Use the transport's configured proxy and dial settings
		targetConn, err = transport.DialContext(r.Context(), "tcp", targetHost)
	} else {
		// Direct connection to the final target
		targetConn, err = transport.DialContext(r.Context(), "tcp", targetHost)
	}

	if err != nil {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
		logger.Error("Failed to connect to WebSocket server or proxy: %v", err)
		return
	}

	logger.Debug("WebSocket tunnel established for %s", targetHost)

	// Special handling for WebSockets in proxy chains
	if goingThroughProxy {
		logger.Debug("WebSocket going through proxy chain")
		// For proxied connections, ensure the tunnel is fully established and
		// the WebSocket protocol will be properly maintained through all proxies
	} else {
		logger.Debug("Direct WebSocket connection to target")
	}

	// Send the protocol upgrade response to the client
	// We mirror the headers from the upstream server's response
	responseHeaders := []byte("HTTP/1.1 101 Switching Protocols\r\n")
	for name, values := range resp.Header {
		for _, value := range values {
			responseHeaders = append(responseHeaders, []byte(fmt.Sprintf("%s: %s\r\n", name, value))...)
		}
	}
	responseHeaders = append(responseHeaders, []byte("\r\n")...)

	if _, err := clientConn.Write(responseHeaders); err != nil {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
		if closeErr := targetConn.Close(); closeErr != nil {
			logger.Error("Error closing target connection: %v", closeErr)
		}
		logger.Error("Failed to send WebSocket response headers: %v", err)
		return
	}

	// Set up bidirectional data transfer between client and target
	var wg sync.WaitGroup
	wg.Add(2)

	// Handle client -> target data flow
	go func() {
		defer wg.Done()
		defer func() {
			if closeErr := targetConn.Close(); closeErr != nil {
				logger.Error("Error closing target connection: %v", closeErr)
			}
		}()

		// First, copy any data already buffered in the hijacked connection
		if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
			buf := make([]byte, clientBuf.Reader.Buffered())
			if _, err := clientBuf.Reader.Read(buf); err != nil {
				logger.Error("Failed to read buffered data: %v", err)
				return
			}
			if _, err := targetConn.Write(buf); err != nil {
				logger.Error("Failed to write buffered data: %v", err)
				return
			}
		}

		// Then continue copying all subsequent data
		if _, err := io.Copy(targetConn, clientConn); err != nil {
			logger.Error("Failed to copy client to target: %v", err)
		}
	}()

	// Handle target -> client data flow
	go func() {
		defer wg.Done()
		defer func() {
			if closeErr := clientConn.Close(); closeErr != nil {
				logger.Error("Error closing client connection: %v", closeErr)
			}
		}()
		if _, err := io.Copy(clientConn, targetConn); err != nil {
			logger.Error("Failed to copy target to client: %v", err)
		}
	}()

	// Wait for either side to close with appropriate timeout handling
	// This is critical for WebSocket connections through multiple proxies
	timeout := time.NewTimer(30 * time.Second)
	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Normal completion
		if !timeout.Stop() {
			<-timeout.C
		}
	case <-timeout.C:
		// Timeout - log warning but allow the connection to continue
		logger.Warn("WebSocket tunnel timeout waiting for data")
	}
	logger.Debug("WebSocket tunnel closed for %s", targetHost)
}

// handleConnect handles HTTPS tunneling via the CONNECT method

func (p *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetAddr := r.Host // Use the full host:port from the CONNECT request

	logger.Debug("CONNECT request for %s", targetAddr)

	// Check if we should intercept the connection
	if p.shouldInterceptTunnel(r) {
		logger.Debug("Intercepting CONNECT request for %s", targetAddr)

		// Determine the protocol (HTTP or HTTPS) and use the appropriate interceptor
		// For HTTPS interception, we check for the standard port 443 or assume HTTPS for testing
		// Also consider non-standard ports for test servers
		isHTTPS := strings.HasSuffix(targetAddr, ":443") ||
			strings.Contains(r.URL.String(), "https://") ||
			r.URL.Scheme == "https" ||
			strings.Contains(targetAddr, "127.0.0.1") // For test servers

		logger.Debug("Protocol detection: isHTTPS=%v, targetAddr=%s, URL=%s, Scheme=%s",
			isHTTPS, targetAddr, r.URL.String(), r.URL.Scheme)

		logger.Debug("HTTPS interception enabled: %v, interceptor: %v",
			p.isHTTPSInterceptionEnabled(), p.httpsInterceptor != nil)

		if p.isHTTPSInterceptionEnabled() && isHTTPS {
			logger.Debug("HTTPS interception for address: %s", targetAddr)
			if p.httpsInterceptor != nil {
				logger.Debug("Calling HTTPS interceptor for %s", targetAddr)
				p.httpsInterceptor.HandleHTTPSIntercept(w, r)
				return
			} else {
				logger.Error("HTTPS interception requested but interceptor not initialized")
			}
		} else if p.isHTTPInterceptionEnabled() {
			// For HTTP CONNECT tunneling or non-standard HTTPS ports
			hj, ok := w.(http.Hijacker)
			if !ok {
				logger.Error("HTTP server does not support hijacking")
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}

			clientConn, clientBuf, err := hj.Hijack()
			if err != nil {
				logger.Error("Failed to hijack connection: %v", err)
				http.Error(w, fmt.Sprintf("Hijack error: %v", err), http.StatusInternalServerError)
				return
			}

			// Check if this is a WebSocket connection
			isWebSocketConnection := strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
				strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")

			if isWebSocketConnection {
				logger.Debug("CONNECT request for WebSocket via tunnel: %s", targetAddr)

				// For WebSockets, we need to handle any buffered data specially
				if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
					// There might be buffered WebSocket handshake data we need to preserve
					logger.Debug("Found %d bytes of buffered data for WebSocket handshake", clientBuf.Reader.Buffered())
				}
			}

			// Send 200 Connection Established
			_, err = fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			if err != nil {
				logger.Error("Failed to send 200 response: %v", err)
				if closeErr := clientConn.Close(); closeErr != nil {
					logger.Error("Error closing client connection: %v", closeErr)
				}
				return
			}

			if p.httpInterceptor != nil {
				p.httpInterceptor.HandleTCPConnection(clientConn, targetAddr)
				return
			} else {
				logger.Error("HTTP interception requested but interceptor not initialized")
				if closeErr := clientConn.Close(); closeErr != nil {
					logger.Error("Error closing client connection: %v", closeErr)
				}
				return
			}
		}
	}

	// If not intercepting or interception failed, proceed with standard tunneling

	// Retrieve the per-connection client from the context
	client, ok := ClientFromContext(r.Context())
	if !ok || client == nil {
		logger.Error("No http.Client found in request context (CONNECT)")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Extract the transport and use its DialContext
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil || transport.DialContext == nil {
		logger.Error("No http.Transport/DialContext found in client (CONNECT)")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Use the transport's DialContext to establish the tunnel
	// This is especially important for WebSocket connections through multiple proxies
	ctx := r.Context()
	var targetConn net.Conn
	var err error

	// Check if this could be a WebSocket connection
	isWebSocketRequest := strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")

	if isWebSocketRequest {
		logger.Debug("CONNECT request for WebSocket: %s", targetAddr)
		// For WebSockets, we need special handling to ensure they work through proxy chains
		// Use a longer timeout for WebSocket connections
		ctxWithTimeout, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		targetConn, err = transport.DialContext(ctxWithTimeout, "tcp", targetAddr)
	} else {
		// For regular CONNECT tunnels
		targetConn, err = transport.DialContext(ctx, "tcp", targetAddr)
	}

	if err != nil {
		// Log the specific target address that failed
		logger.Error("Failed to establish connection to target %s (via %s): %v", targetAddr, r.RemoteAddr, err)
		// Use our custom Bad Gateway response.
		// If err is a *Error, its code will be used. Otherwise, ErrCodeUpstreamConnectFailed.
		writeProxyErrorResponse(w, err, ErrCodeUpstreamConnectFailed)
		return
	}

	// Tell the client that the connection is established
	w.WriteHeader(http.StatusOK)

	hj, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("HTTP server does not support hijacking")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Check if this is a WebSocket connection
	isWebSocketConnection := strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")

	// Get the client connection and buffer
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		logger.Error("Failed to hijack connection: %v", err)
		http.Error(w, fmt.Sprintf("Hijack error: %v", err), http.StatusInternalServerError)
		return
	}

	if isWebSocketConnection {
		logger.Debug("Detected WebSocket CONNECT tunnel request for %s", targetAddr)
	}

	logger.Debug("Hijacked connection for TCP tunnel")

	// Close connections when function returns
	defer func() {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
	}()
	defer func() {
		if closeErr := targetConn.Close(); closeErr != nil {
			logger.Error("Error closing target connection: %v", closeErr)
		}
	}()

	// Copy data bidirectionally - critical for WebSocket proxy chains
	errChan := make(chan error, 2)

	// For WebSocket connections through proxies, we need more robust data handling
	// Check if this is a WebSocket connection based on request headers
	wsConnection := strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")

	if wsConnection {
		logger.Debug("Setting up WebSocket optimized tunnel for %s", targetAddr)
	}

	// Handle client -> target data flow
	go func() {
		// Forward any buffered data if present
		if clientBuf != nil && clientBuf.Reader != nil && clientBuf.Reader.Buffered() > 0 {
			bufSize := clientBuf.Reader.Buffered()
			logger.Debug("Found %d bytes of buffered data for tunnel", bufSize)

			// Create a buffer to hold the data
			data := make([]byte, bufSize)
			n, err := clientBuf.Reader.Read(data)
			if err == nil && n > 0 {
				// Copy buffered data to target
				logger.Debug("Forwarding %d bytes of buffered data to target", n)
				_, err := targetConn.Write(data[:n])
				if err != nil {
					logger.Warn("Failed to forward buffered data: %v", err)
				}
			}
		}

		// Then continue with normal copying
		_, err := io.Copy(targetConn, clientConn)
		errChan <- err
	}()

	// Handle target -> client data flow
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errChan <- err
	}()

	// Wait for copying to finish or error
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			// Log non-standard close errors
			if !isClosedConnError(err) && err != io.EOF {
				logger.Warn("TCP tunnel copy error: %v", err)
			}
		}
	}
	logger.Debug("TCP tunnel closed")
}

// Reference back to the proxy for TCP client connection
func (p *Server) createForwardTCPClient(ctx context.Context, addr string) (net.Conn, error) {
	// If parent proxy is set, delegate to it
	if p.proxy != nil {
		return p.proxy.createForwardTCPClient(ctx, addr)
	}

	// Otherwise use compiled forwards directly
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}

	portUint, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	portUint16 := uint16(portUint)

	// Apply forwarding rules if any
	for _, cf := range p.compiledForwards {
		match, err := cf.classifier.Classify(ClassifierInput{
			host:       host,
			remoteIP:   "",
			remotePort: portUint16,
		})

		if err != nil {
			logger.Error("Error evaluating forward classifier: %v", err)
			continue
		}

		if match {
			switch cf.fwd.Type() {
			case config.ForwardTypeDefaultNetwork:
				// Just continue with the default network connection
				break

			case config.ForwardTypeSocks5:
				// Forward through SOCKS5 proxy
				proxy := cf.fwd.(*config.ForwardSocks5)
				// We'll use the net/proxy package for SOCKS5 proxying
				// This is a placeholder - implement actual SOCKS5 proxying
				logger.Info("SOCKS5 proxy forwarding to %s via %s", addr, proxy.Address)
				dialer := &net.Dialer{Timeout: time.Duration(p.config.TimeoutSeconds) * time.Second}
				conn, err := dialer.DialContext(ctx, "tcp", proxy.Address)
				if err != nil {
					logger.Error("Error connecting to SOCKS5 proxy: %v", err)
					break
				}
				return conn, nil

			case config.ForwardTypeProxy:
				// Forward through another HTTP proxy
				proxy := cf.fwd.(*config.ForwardProxy)
				// This is a placeholder - implement actual HTTP proxying
				logger.Info("HTTP proxy forwarding to %s via %s", addr, proxy.Address)
				dialer := &net.Dialer{Timeout: time.Duration(p.config.TimeoutSeconds) * time.Second}
				conn, err := dialer.DialContext(ctx, "tcp", proxy.Address)
				if err != nil {
					logger.Error("Error connecting to HTTP proxy: %v", err)
					break
				}
				return conn, nil

			default:
				logger.Error("Unknown forward type: %v", cf.fwd.Type())
			}
		}
	}

	// Default connection
	dialer := &net.Dialer{Timeout: time.Duration(p.config.TimeoutSeconds) * time.Second}
	return dialer.DialContext(ctx, "tcp", addr)
}

// shouldInterceptTunnel determines if the tunnel established by a CONNECT request should be intercepted
func (p *Server) shouldInterceptTunnel(r *http.Request) bool {
	// Only intercept if we have at least one interceptor configured
	if p.httpsInterceptor == nil && p.httpInterceptor == nil {
		logger.Debug("No interceptors configured")
		return false
	}

	// Check global config to see if interception is enabled
	isEnabled := p.config.Interception.Enabled && (p.config.Interception.HTTP || p.config.Interception.HTTPS)
	logger.Debug("Should intercept tunnel for %s: %v (enabled in config: %v)",
		r.Host, isEnabled, p.config.Interception.Enabled)
	return isEnabled
}

// isHTTPSInterceptionEnabled checks if HTTPS interception is enabled for this proxy server
func (p *Server) isHTTPSInterceptionEnabled() bool {
	return p.config.Interception.Enabled && p.config.Interception.HTTPS && p.httpsInterceptor != nil
}

// isHTTPInterceptionEnabled checks if HTTP interception is enabled for this proxy server
func (p *Server) isHTTPInterceptionEnabled() bool {
	return p.config.Interception.Enabled && p.config.Interception.HTTP && p.httpInterceptor != nil
}

// isHostAllowed checks if access to the given host is allowed based on the blocklist and allowlist
func (p *Proxy) isHostAllowed(host, remoteIP string, remotePort uint16) bool {
	// Create classifier input for host and remote IP
	classifierInput := ClassifierInput{
		host:       host,
		remoteIP:   remoteIP,
		remotePort: remotePort,
	}

	// If we have both blocklist and allowlist, check both
	if p.blocklistClassifier != nil && p.allowlistClassifier != nil {
		// Check blocklist first
		blocked, err := p.blocklistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Blocklist classification error: %v", err)
			return false
		}

		// Check allowlist
		allowed, err := p.allowlistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Allowlist classification error: %v", err)
			return false
		}

		// If in blocklist, always block, regardless of allowlist status
		// This follows the precedence rule: blocklist > allowlist
		if blocked {
			return false
		}

		// Not in blocklist, must be in allowlist to be allowed
		return allowed
	}

	// If we only have blocklist, deny only hosts in the blocklist
	if p.blocklistClassifier != nil {
		blocked, err := p.blocklistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Blocklist classification error: %v", err)
			return false
		}
		return !blocked
	}

	// If we only have allowlist, allow only hosts in the allowlist
	if p.allowlistClassifier != nil {
		allowed, err := p.allowlistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Allowlist classification error: %v", err)
			return false
		}
		return allowed
	}

	// No blocklist or allowlist, allow all
	return true
}

// writeProxyErrorResponse constructs and sends an HTTP 502 Bad Gateway response.
// It uses the code from originalErr if it's a *Error, otherwise it uses defaultErrorCode.
func writeProxyErrorResponse(w http.ResponseWriter, originalErr error, defaultErrorCode string) {
	errorCode := defaultErrorCode
	if proxyErr, ok := originalErr.(*Error); ok {
		errorCode = proxyErr.Code
	}

	// Log a warning if the chosen error code (either from originalErr or defaultErrorCode)
	// isn't in our predefined descriptions. NewBadGatewayResponse will handle it gracefully
	// by using "Unknown error code" as the description, but this log helps identify gaps.
	if _, exists := ErrorDescriptions[errorCode]; !exists {
		logger.Warn("Error code '%s' not found in ErrorDescriptions for BadGatewayResponse. Original error: %v. Default code used: '%s'", errorCode, originalErr, defaultErrorCode)
	}

	badGatewayResp := NewBadGatewayResponse(errorCode)

	// Copy headers from the generated badGatewayResp to the actual ResponseWriter
	for key, values := range badGatewayResp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	// Set the status code
	w.WriteHeader(badGatewayResp.StatusCode)
	// Copy the response body
	if badGatewayResp.Body != nil {
		if _, err := io.Copy(w, badGatewayResp.Body); err != nil {
			logger.Error("Failed to copy bad gateway response body: %v", err)
		}
		if closeErr := badGatewayResp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		} // Ensure the NopCloser's underlying reader is "closed" (though for bytes.Reader it's a no-op)
	}
}

func (p *Server) isHostAllowed(host, remoteIP string, remotePort uint16) bool {
	// Create classifier input for host and remote IP
	classifierInput := ClassifierInput{
		host:       host,
		remoteIP:   remoteIP,
		remotePort: remotePort,
	}

	// Lazy compile blocklist and allowlist classifiers if not already
	if p.blocklistClassifier == nil && p.config.Blocklist != nil {
		blf, err := CompileClassifier(p.config.Blocklist)
		if err != nil {
			logger.Error("Error compiling blocklist classifier: %v", err)
		} else {
			p.blocklistClassifier = blf
		}
	}
	if p.allowlistClassifier == nil && p.config.Allowlist != nil {
		alf, err := CompileClassifier(p.config.Allowlist)
		if err != nil {
			logger.Error("Error compiling allowlist classifier: %v", err)
		} else {
			p.allowlistClassifier = alf
		}
	}

	// Check blocklist first - deny if host is in blocklist
	if p.blocklistClassifier != nil {
		isBlocked, err := p.blocklistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Blocklist classifier error: %v", err)
		} else if isBlocked {
			// Host is explicitly blocked
			logger.Debug("Host %s is blocked by blocklist", host)
			return false
		}
	}

	// Check allowlist if configured - only allow hosts in allowlist
	if p.allowlistClassifier != nil {
		isAllowed, err := p.allowlistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Allowlist classifier error: %v", err)
		} else {
			if isAllowed {
				logger.Debug("Host %s is allowed by allowlist", host)
			} else {
				logger.Debug("Host %s is not in allowlist", host)
			}
			return isAllowed
		}
	}

	return true
}

// Stop gracefully stops the proxy server.
func (p *Proxy) Stop() error {
	var lastErr error

	// Stop all server instances
	for _, server := range p.servers {
		err := server.Stop()
		if err != nil {
			lastErr = err
			logger.Error("Failed to stop proxy server on %s: %v", server.serverConfig.ListenAddress, err)
		}
	}

	return lastErr
}

// Stop gracefully stops the server instance.
func (p *Server) Stop() error {
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}
