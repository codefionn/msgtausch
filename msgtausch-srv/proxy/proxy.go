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
	"github.com/codefionn/msgtausch/msgtausch-srv/dashboard"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type contextKey struct {
	name string
}

var clientKey = &contextKey{name: "http-client"}
var clientIPKey = &contextKey{name: "client-ip"}

func WithClient(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, clientKey, client)
}

func ClientFromContext(ctx context.Context) (*http.Client, bool) {
	clientVal := ctx.Value(clientKey)
	if clientVal == nil {
		return nil, false
	}
	client, ok := clientVal.(*http.Client)
	return client, ok
}

func WithClientIP(ctx context.Context, clientIP string) context.Context {
	return context.WithValue(ctx, clientIPKey, clientIP)
}

func ClientIPFromContext(ctx context.Context) (string, bool) {
	clientIPVal := ctx.Value(clientIPKey)
	if clientIPVal == nil {
		return "", false
	}
	clientIP, ok := clientIPVal.(string)
	return clientIP, ok
}

type Server struct {
	config              *config.Config
	serverConfig        config.ServerConfig
	server              *http.Server
	httpsInterceptor    *HTTPSInterceptor
	httpInterceptor     *HTTPInterceptor
	quicInterceptor     *QUICHTTP3Interceptor
	compiledForwards    []compiledForward
	blocklistClassifier Classifier
	allowlistClassifier Classifier
	proxy               *Proxy
}

type Proxy struct {
	config              *config.Config
	servers             []*Server
	compiledForwards    []compiledForward
	blocklistClassifier Classifier
	allowlistClassifier Classifier
	portal              *dashboard.Portal
	stats.Collector
}

type compiledForward struct {
	fwd        config.Forward
	classifier Classifier
}

func (p *Proxy) getForwardDebugInfo(fwd config.Forward) string {
	var info strings.Builder

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

	classifierInfo := p.getClassifierDebugInfo(fwd.Classifier())
	if classifierInfo != "" {
		info.WriteString(fmt.Sprintf(", classifier=%s", classifierInfo))
	} else {
		info.WriteString(", classifier=none")
	}

	return info.String()
}

func (p *Proxy) GetConfig() *config.Config {
	return p.config
}

func (p *Proxy) GetServerInfo() []dashboard.ServerInfo {
	info := make([]dashboard.ServerInfo, 0, len(p.servers))
	for _, server := range p.servers {
		info = append(info, dashboard.ServerInfo{
			Type:                 string(server.serverConfig.Type),
			ListenAddress:        server.serverConfig.ListenAddress,
			Enabled:              server.serverConfig.Enabled,
			MaxConnections:       server.serverConfig.MaxConnections,
			ConnectionsPerClient: server.serverConfig.ConnectionsPerClient,
		})
	}
	return info
}

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

func (p *Proxy) CompileClassifiers() {
	if p.config.Forwards != nil {
		logger.Info("Compiling %d forward configurations", len(p.config.Forwards))
		for i, fwd := range p.config.Forwards {
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

	if p.config.Blocklist != nil {
		blf, err := CompileClassifier(p.config.Blocklist)
		if err != nil {
			logger.Error("Error compiling blocklist classifier: %v", err)
		} else {
			p.blocklistClassifier = blf
		}
	}

	if p.config.Allowlist != nil {
		alf, err := CompileClassifier(p.config.Allowlist)
		if err != nil {
			logger.Error("Error compiling allowlist classifier: %v", err)
		} else {
			p.allowlistClassifier = alf
		}
	}
}

func NewProxy(cfg *config.Config) *Proxy {
	p := &Proxy{
		config:  cfg,
		servers: make([]*Server, 0, len(cfg.Servers)),
	}

	p.CompileClassifiers()

	if cfg.Statistics.Enabled {
		var err error
		factory := stats.NewCollectorFactory()
		p.Collector, err = factory.CreateCollector(cfg.Statistics)
		if err != nil {
			logger.Error("Failed to initialize statistics collector: %v", err)
		}
	} else {
		p.Collector = stats.NewDummyCollector()
	}

	p.portal = dashboard.NewPortal(cfg, p, p)

	for _, serverCfg := range cfg.Servers {
		if !serverCfg.Enabled {
			logger.Info("Skipping disabled server on %s", serverCfg.ListenAddress)
			continue
		}

		server := &Server{
			config:              cfg,
			serverConfig:        serverCfg,
			compiledForwards:    p.compiledForwards,
			blocklistClassifier: p.blocklistClassifier,
			allowlistClassifier: p.allowlistClassifier,
			server:              &http.Server{Addr: serverCfg.ListenAddress},
			proxy:               p,
		}

		switch serverCfg.Type {
		case config.ProxyTypeHTTPS:
			caFile := cfg.Interception.CAFile
			caKeyFile := cfg.Interception.CAKeyFile

			if caFile == "" || caKeyFile == "" {
				logger.Error("HTTPS interceptor requires CA certificate and key files (server %s)", serverCfg.ListenAddress)
				continue
			}

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

			httpsInterceptor, err := NewHTTPSInterceptor(caCert, caKey, p, nil, nil)
			if err != nil {
				logger.Error("Failed to create HTTPS interceptor: %v", err)
				continue
			}
			server.httpsInterceptor = httpsInterceptor

		case config.ProxyTypeHTTP:
			server.httpInterceptor = NewHTTPInterceptor(p)

		case config.ProxyTypeStandard:

		default:
			logger.Error("Unknown proxy type: %s", serverCfg.Type)
			continue
		}

		p.servers = append(p.servers, server)
	}

	if len(p.servers) == 0 {
		logger.Warn("No enabled proxy servers configured")
	}

	return p
}

func (p *Proxy) Start() error {
	if len(p.servers) == 0 {
		return fmt.Errorf("no enabled proxy servers configured")
	}

	var wg sync.WaitGroup
	var startErrors []error

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
		return startErrors[0]
	}
	return nil
}

func (p *Proxy) StartWithListener(listener net.Listener) error {
	if len(p.servers) == 0 {
		return fmt.Errorf("no enabled proxy servers configured")
	}

	return p.servers[0].StartWithListener(listener)
}

func (p *Server) StartWithListener(listener net.Listener) error {
	handler := http.HandlerFunc(p.handleRequest)

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
				DisableKeepAlives:     false,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
			client := &http.Client{
				Timeout:   time.Duration(p.config.TimeoutSeconds) * time.Second,
				Transport: transport,
			}
			clientIP, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			ctx = WithClient(ctx, client)
			ctx = WithClientIP(ctx, clientIP)
			return ctx
		},
	}

	logger.Info("Starting proxy server on %s", listener.Addr().String())
	return p.server.Serve(listener)
}

func (p *Server) Start() error {
	switch p.serverConfig.Type {
	case config.ProxyTypeStandard:
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
					DisableKeepAlives:     false,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   10,
					IdleConnTimeout:       90 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				}
				client := &http.Client{
					Timeout:   time.Duration(p.config.TimeoutSeconds) * time.Second,
					Transport: transport,
				}
				clientIP, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				ctx = WithClient(ctx, client)
				ctx = WithClientIP(ctx, clientIP)
				return ctx
			},
		}

		logger.Info("Starting standard proxy server on %s", p.serverConfig.ListenAddress)
		return p.server.ListenAndServe()

	case config.ProxyTypeHTTPS:
		caFile := p.config.Interception.CAFile
		caKeyFile := p.config.Interception.CAKeyFile

		if caFile == "" || caKeyFile == "" {
			return fmt.Errorf("HTTPS interceptor requires CA certificate and key files")
		}

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

		p.httpsInterceptor, err = NewHTTPSInterceptor(caCert, caKey, p.proxy, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to initialize HTTPS interceptor: %w", err)
		}

		return p.startHTTPSInterceptor()

	case config.ProxyTypeHTTP:
		p.httpInterceptor = NewHTTPInterceptor(p.proxy)

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
					DisableKeepAlives:     false,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   10,
					IdleConnTimeout:       90 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				}
				client := &http.Client{
					Timeout:   time.Duration(p.config.TimeoutSeconds) * time.Second,
					Transport: transport,
				}
				clientIP, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				ctx = WithClient(ctx, client)
				ctx = WithClientIP(ctx, clientIP)
				return ctx
			},
		}

		logger.Info("Starting HTTP intercepting proxy server on %s", p.serverConfig.ListenAddress)
		return p.server.ListenAndServe()

	case config.ProxyTypeQUIC:
		caFile := p.config.Interception.CAFile
		caKeyFile := p.config.Interception.CAKeyFile
		if caFile == "" || caKeyFile == "" {
			return fmt.Errorf("QUIC/HTTP3 interceptor requires CA certificate and key files")
		}
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
		udpAddr, err := net.ResolveUDPAddr("udp", p.serverConfig.ListenAddress)
		if err != nil {
			return fmt.Errorf("failed to resolve UDP address '%s': %w", p.serverConfig.ListenAddress, err)
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on UDP address '%s': %w", p.serverConfig.ListenAddress, err)
		}
		logger.Info("Starting QUIC/HTTP3 intercepting proxy server on %s", p.serverConfig.ListenAddress)
		go p.quicInterceptor.HandleUDPConnection(udpConn, udpAddr, p.serverConfig.ListenAddress)
		select {}
	default:
		return fmt.Errorf("unknown proxy type: %s", p.serverConfig.Type)
	}
}

func (p *Server) startHTTPSInterceptor() error {
	if p.httpsInterceptor == nil {
		return fmt.Errorf("HTTPS interceptor not initialized")
	}

	listener, err := net.Listen("tcp", p.serverConfig.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to create listener for HTTPS interceptor: %w", err)
	}

	logger.Info("Starting HTTPS interceptor on %s", p.serverConfig.ListenAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedConnError(err) {
				break
			}
			logger.Error("Failed to accept connection: %v", err)
			continue
		}

		go func() {
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					logger.Error("Error closing connection: %v", closeErr)
				}
			}()

			buf := make([]byte, 1)
			_, err := conn.Read(buf)
			if err != nil {
				logger.Error("Failed to read from connection: %v", err)
				return
			}

			bufConn := &bufferConn{
				Conn: conn,
				buf:  buf,
			}

			p.httpsInterceptor.HandleTCPConnection(bufConn, "")
		}()
	}

	return nil
}

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

func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

func (p *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetAddr := r.Host
	logger.Debug("CONNECT request for %s", targetAddr)

	if p.proxy.portal.IsPortalRequest(r) {
		p.proxy.portal.ServeHTTP(w, r)
		return
	}

	host := r.Host
	if r.Method == http.MethodConnect {
		host = r.URL.Host
	}

	isWebSocketUpgrade := strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")

	if isWebSocketUpgrade {
		logger.Debug("WebSocket upgrade detected for %s", host)
	}

	var remotePort uint16
	hostname, portStr, err := net.SplitHostPort(host)
	if err != nil {
		// If parsing fails, use the original host as hostname (it might not have a port)
		hostname = host
		logger.Debug("No port found in host, using default: %s", host)
	} else {
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			logger.Error("Error parsing port: %v", err)
		} else {
			remotePort = uint16(port)
		}
	}
	if remotePort == 0 {
		if colon := strings.LastIndex(host, ":"); colon != -1 {
			remotePortUint64, _ := strconv.ParseUint(host[colon+1:], 10, 16)
			remotePort = uint16(remotePortUint64)
			// If we found a port this way and hostname is still the full host, extract just the hostname
			if hostname == host {
				hostname = host[:colon]
			}
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
	}

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	var connectionID int64
	var startErr error

	if p.proxy.Collector != nil {
		connectionID, startErr = p.proxy.Collector.StartConnection(ctx, clientIP, hostname, int(remotePort), "http")
		if startErr != nil {
			logger.Error("Failed to record connection start: %v", err)
		}
	}

	if !p.isHostAllowed(hostname, clientIP, remotePort) {
		logger.Warn("Host not allowed: %s", host)
		if p.proxy.Collector != nil {
			if err := p.proxy.Collector.RecordBlockedRequest(ctx, clientIP, hostname, "host_not_allowed"); err != nil {
				logger.Error("Failed to record blocked request: %v", err)
			}
		}
		http.Error(w, "Host not allowed", http.StatusForbidden)
		if p.proxy.Collector != nil && connectionID > 0 {
			_ = p.proxy.Collector.EndConnection(ctx, connectionID, 0, 0, 0, "blocked")
		}
		return
	}

	if p.proxy.Collector != nil {
		if err := p.proxy.Collector.RecordAllowedRequest(ctx, clientIP, hostname); err != nil {
			logger.Error("Failed to record allowed request: %v", err)
		}
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, connectionID, clientIP, hostname, int(remotePort))
		return
	}

	client, ok := ClientFromContext(r.Context())
	if !ok || client == nil {
		logger.Error("No http.Client found in request context")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	p.forwardRequest(w, r, client, host, connectionID)
}

func (p *Server) forwardRequest(w http.ResponseWriter, r *http.Request, client *http.Client, targetHost string, connectionID int64) {
	ctx := r.Context()

	var targetURL string
	if r.URL.IsAbs() {
		targetURL = r.URL.String()
	} else {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		targetURL = fmt.Sprintf("%s://%s%s", scheme, targetHost, r.URL.RequestURI())
	}
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		if p.proxy.Collector != nil && connectionID > 0 {
			_ = p.proxy.Collector.RecordError(r.Context(), connectionID, "request_creation_error", err.Error())
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	isWebSocketRequest := false
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		isWebSocketRequest = true
		logger.Debug("Detected WebSocket upgrade request to %s", targetURL)
	}

	isProxiedWebSocket := false
	if r.Header.Get("Sec-WebSocket-Key") != "" && r.Header.Get("Sec-WebSocket-Version") != "" {
		isProxiedWebSocket = true
		logger.Debug("Detected proxied WebSocket request to %s", targetURL)
	}

	skip := map[string]struct{}{
		"Proxy-Connection":    {},
		"Keep-Alive":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Te":                  {},
		"Trailer":             {},
		"Transfer-Encoding":   {},
	}

	isWebSocketConnection := isWebSocketRequest || isProxiedWebSocket

	if !isWebSocketConnection {
		skip["Upgrade"] = struct{}{}
		skip["Connection"] = struct{}{}
	}

	for name, values := range r.Header {
		if _, hop := skip[name]; hop {
			if isWebSocketConnection {
				if name == "Connection" {
					req.Header.Set("Connection", "Upgrade")
					continue
				} else if name == "Upgrade" {
					req.Header.Set("Upgrade", "websocket")
					continue
				}
			}
			continue
		} else {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
	}

	if isWebSocketConnection {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		if wsKey := r.Header.Get("Sec-WebSocket-Key"); wsKey != "" {
			req.Header.Set("Sec-WebSocket-Key", wsKey)
		}
		if wsVersion := r.Header.Get("Sec-WebSocket-Version"); wsVersion != "" {
			req.Header.Set("Sec-WebSocket-Version", wsVersion)
		}
	}

	if isWebSocketRequest || isProxiedWebSocket {
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")

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

	if p.isHTTPInterceptionEnabled() && p.httpInterceptor != nil {
		err := p.httpInterceptor.applyRequestHooks(req)
		if err != nil {
			logger.Error("Failed to apply HTTP request hooks: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to forward request to %s: %v", targetHost, err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			http.Error(w, "Request timeout", http.StatusGatewayTimeout)
		} else {
			if p.proxy.Collector != nil && connectionID > 0 {
				_ = p.proxy.Collector.RecordError(r.Context(), connectionID, "http_forward_error", err.Error())
			}
			writeProxyErrorResponse(w, err, ErrCodeHTTPForwardFailed)
		}
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	if p.isHTTPInterceptionEnabled() && p.httpInterceptor != nil {
		err := p.httpInterceptor.applyResponseHooks(resp)
		if err != nil {
			logger.Error("Failed to apply HTTP response hooks: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	isWebSocketResponse := resp.StatusCode == http.StatusSwitchingProtocols &&
		strings.ToLower(resp.Header.Get("Upgrade")) == "websocket"

	if isWebSocketRequest && isWebSocketResponse {
		logger.Debug("Handling WebSocket upgrade response from %s", targetHost)
		p.handleWebSocketTunnel(w, r, resp, client, connectionID)
		return
	}

	if p.proxy.Collector != nil && connectionID > 0 {
		responseHeaderSize := estimateHTTPResponseHeaderSize(resp)
		if err := p.proxy.Collector.RecordHTTPResponseWithHeaders(r.Context(), connectionID, resp.StatusCode, resp.ContentLength, responseHeaderSize); err != nil {
			logger.Error("Failed to record HTTP response: %v", err)
		}
	}

	if p.proxy.Collector != nil && connectionID > 0 {
		contentLength := r.ContentLength
		if contentLength < 0 {
			contentLength = 0
		}
		requestHeaderSize := estimateHTTPRequestHeaderSize(r)
		if err := p.proxy.Collector.RecordHTTPRequestWithHeaders(ctx, connectionID, r.Method, r.URL.RequestURI(), targetHost, r.UserAgent(), contentLength, requestHeaderSize); err != nil {
			logger.Error("Failed to record HTTP request: %v", err)
		}
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Error("Failed to copy response body: %v", err)
	}
}

func (p *Server) handleWebSocketTunnel(w http.ResponseWriter, r *http.Request, resp *http.Response, client *http.Client, connectionID int64) {
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

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil || transport.DialContext == nil {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
		logger.Error("Invalid transport for WebSocket connection")
		return
	}

	goingThroughProxy := false
	if transport.Proxy != nil {
		proxyURL, err := transport.Proxy(&http.Request{URL: targetURL})
		if err == nil && proxyURL != nil {
			goingThroughProxy = true
			logger.Debug("WebSocket connection going through upstream proxy: %s", proxyURL.String())
		}
	}

	var targetConn net.Conn
	if goingThroughProxy {
		logger.Debug("Establishing CONNECT tunnel to %s for WebSocket via proxy", targetHost)
		targetConn, err = transport.DialContext(r.Context(), "tcp", targetHost)
	} else {
		targetConn, err = transport.DialContext(r.Context(), "tcp", targetHost)
	}

	if err != nil {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
		logger.Error("Failed to connect to WebSocket server or proxy: %v", err)
		return
	}
	targetConn = newTrackedConn(r.Context(), targetConn, p.proxy, connectionID)

	logger.Debug("WebSocket tunnel established for %s", targetHost)

	if goingThroughProxy {
		logger.Debug("WebSocket going through proxy chain")
	} else {
		logger.Debug("Direct WebSocket connection to target")
	}

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

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer func() {
			if closeErr := targetConn.Close(); closeErr != nil {
				logger.Error("Error closing target connection: %v", closeErr)
			}
		}()

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

		_, err := io.Copy(targetConn, clientConn)
		if err != nil && !isClosedConnError(err) {
			logger.Error("Failed to copy client to target: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer func() {
			if closeErr := clientConn.Close(); closeErr != nil {
				logger.Error("Error closing client connection: %v", closeErr)
			}
		}()
		_, err := io.Copy(clientConn, targetConn)
		if err != nil && !isClosedConnError(err) {
			logger.Error("Failed to copy target to client: %v", err)
		}
	}()

	wg.Wait()
	logger.Debug("WebSocket tunnel closed for %s", targetHost)
}

func (p *Server) handleConnect(w http.ResponseWriter, r *http.Request, connectionID int64, _, _ string, _ int) {
	targetAddr := r.Host

	logger.Debug("CONNECT request for %s", targetAddr)

	if p.shouldInterceptTunnel(r) {
		logger.Debug("Intercepting CONNECT request for %s", targetAddr)

		isHTTPS := strings.HasSuffix(targetAddr, ":443") ||
			strings.Contains(r.URL.String(), "https://") ||
			r.URL.Scheme == "https" ||
			strings.Contains(targetAddr, "127.0.0.1")

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

			isWebSocketConnection := strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
				strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")

			if isWebSocketConnection {
				logger.Debug("CONNECT request for WebSocket via tunnel: %s", targetAddr)

				if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
					logger.Debug("Found %d bytes of buffered data for WebSocket handshake", clientBuf.Reader.Buffered())
				}
			}

			_, err = fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			if err != nil {
				logger.Error("Failed to send 200 response: %v", err)
				if p.proxy.Collector != nil && connectionID > 0 {
					if err := p.proxy.Collector.EndConnection(r.Context(), connectionID, 0, 0, 0, "error"); err != nil {
						logger.Error("Failed to end connection: %v", err)
					}
				}
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

	client, ok := ClientFromContext(r.Context())
	if !ok || client == nil {
		logger.Error("No http.Client found in request context (CONNECT)")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil || transport.DialContext == nil {
		logger.Error("No http.Transport/DialContext found in client (CONNECT)")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	targetConn, err := p.proxy.createForwardTCPClient(r.Context(), targetAddr)

	if err != nil {
		logger.Error("Failed to establish connection to target %s (via %s): %v", targetAddr, r.RemoteAddr, err)
		writeProxyErrorResponse(w, err, ErrCodeUpstreamConnectFailed)
		return
	}

	w.WriteHeader(http.StatusOK)

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

	isWebSocketConnection := strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
	if isWebSocketConnection {
		logger.Debug("Detected WebSocket CONNECT tunnel request for %s", targetAddr)
	}

	logger.Debug("Hijacked connection for TCP tunnel")

	defer clientConn.Close()
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Create a context to coordinate tunnel shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		defer wg.Done()
		defer cancel() // Cancel context when this goroutine exits
		if clientBuf != nil && clientBuf.Reader != nil && clientBuf.Reader.Buffered() > 0 {
			if _, err := clientBuf.WriteTo(targetConn); err != nil {
				if !isClosedConnError(err) {
					logger.Error("Failed to write buffered data to target: %v", err)
				}
				return
			}
		}
		if _, err := io.Copy(targetConn, clientConn); err != nil {
			if !isClosedConnError(err) {
				logger.Warn("TCP tunnel copy error (client to target): %v", err)
			}
		}
		// Close the target connection to signal completion
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		defer cancel() // Cancel context when this goroutine exits
		if _, err := io.Copy(clientConn, targetConn); err != nil {
			if !isClosedConnError(err) {
				logger.Warn("TCP tunnel copy error (target to client): %v", err)
			}
		}
		// Close the client connection to signal completion
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Wait for context cancellation or goroutines to complete
	go func() {
		<-ctx.Done()
		// Force close connections when context is cancelled
		clientConn.Close()
		targetConn.Close()
	}()

	wg.Wait()
	logger.Debug("TCP tunnel closed")
}

func (p *Server) createForwardTCPClient(ctx context.Context, addr string) (net.Conn, error) {
	if p.proxy != nil {
		return p.proxy.createForwardTCPClient(ctx, addr)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}

	portUint, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	portUint16 := uint16(portUint)

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
				fwd := cf.fwd.(*config.ForwardDefaultNetwork)
				network := "tcp"
				if fwd.ForceIPv4 {
					network = "tcp4"
					logger.Debug("Forcing IPv4 for default network forward to %s", addr)
				}
				dialer := &net.Dialer{
					Timeout: time.Duration(p.config.TimeoutSeconds) * time.Second,
				}
				if fwd.ForceIPv4 {
					dialer.FallbackDelay = -1
				}
				return dialer.DialContext(ctx, network, addr)

			case config.ForwardTypeSocks5:
				proxy := cf.fwd.(*config.ForwardSocks5)
				logger.Info("SOCKS5 proxy forwarding to %s via %s", addr, proxy.Address)
				network := "tcp"
				if proxy.ForceIPv4 {
					network = "tcp4"
					logger.Debug("Forcing IPv4 for SOCKS5 forward to %s", addr)
				}
				dialer := &net.Dialer{Timeout: time.Duration(p.config.TimeoutSeconds) * time.Second}
				if proxy.ForceIPv4 {
					dialer.FallbackDelay = -1
				}
				conn, err := dialer.DialContext(ctx, network, proxy.Address)
				if err != nil {
					logger.Error("Error connecting to SOCKS5 proxy: %v", err)
					break
				}
				return conn, nil

			case config.ForwardTypeProxy:
				proxy := cf.fwd.(*config.ForwardProxy)
				logger.Info("HTTP proxy forwarding to %s via %s", addr, proxy.Address)
				network := "tcp"
				if proxy.ForceIPv4 {
					network = "tcp4"
					logger.Debug("Forcing IPv4 for HTTP proxy forward to %s", addr)
				}
				dialer := &net.Dialer{Timeout: time.Duration(p.config.TimeoutSeconds) * time.Second}
				if proxy.ForceIPv4 {
					dialer.FallbackDelay = -1
				}
				conn, err := dialer.DialContext(ctx, network, proxy.Address)
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

	dialer := &net.Dialer{Timeout: time.Duration(p.config.TimeoutSeconds) * time.Second}
	return dialer.DialContext(ctx, "tcp", addr)
}

func (p *Server) shouldInterceptTunnel(r *http.Request) bool {
	if p.httpsInterceptor == nil && p.httpInterceptor == nil {
		logger.Debug("No interceptors configured")
		return false
	}

	isEnabled := p.config.Interception.Enabled && (p.config.Interception.HTTP || p.config.Interception.HTTPS)
	logger.Debug("Should intercept tunnel for %s: %v (enabled in config: %v)",
		r.Host, isEnabled, p.config.Interception.Enabled)
	return isEnabled
}

func (p *Server) isHTTPSInterceptionEnabled() bool {
	return p.config.Interception.Enabled && p.config.Interception.HTTPS && p.httpsInterceptor != nil
}

func (p *Server) isHTTPInterceptionEnabled() bool {
	return p.config.Interception.Enabled && p.config.Interception.HTTP && p.httpInterceptor != nil
}

func (p *Proxy) isHostAllowed(host, remoteIP string, remotePort uint16) bool {
	classifierInput := ClassifierInput{
		host:       host,
		remoteIP:   remoteIP,
		remotePort: remotePort,
	}

	if p.blocklistClassifier != nil && p.allowlistClassifier != nil {
		blocked, err := p.blocklistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Blocklist classification error: %v", err)
			return false
		}

		allowed, err := p.allowlistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Allowlist classification error: %v", err)
			return false
		}

		if blocked {
			return false
		}

		return allowed
	}

	if p.blocklistClassifier != nil {
		blocked, err := p.blocklistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Blocklist classification error: %v", err)
			return false
		}
		return !blocked
	}

	if p.allowlistClassifier != nil {
		allowed, err := p.allowlistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Allowlist classification error: %v", err)
			return false
		}
		return allowed
	}

	return true
}

func writeProxyErrorResponse(w http.ResponseWriter, originalErr error, defaultErrorCode string) {
	errorCode := defaultErrorCode
	if proxyErr, ok := originalErr.(*Error); ok {
		errorCode = proxyErr.Code
	}

	if _, exists := ErrorDescriptions[errorCode]; !exists {
		logger.Warn("Error code '%s' not found in ErrorDescriptions for BadGatewayResponse. Original error: %v. Default code used: '%s'", errorCode, originalErr, defaultErrorCode)
	}

	badGatewayResp := NewBadGatewayResponse(errorCode)
	defer func() {
		if badGatewayResp.Body != nil {
			badGatewayResp.Body.Close()
		}
	}()

	for key, values := range badGatewayResp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(badGatewayResp.StatusCode)
	if badGatewayResp.Body != nil {
		if _, err := io.Copy(w, badGatewayResp.Body); err != nil {
			logger.Error("Failed to copy bad gateway response body: %v", err)
		}
	}
}

func (p *Server) isHostAllowed(host, remoteIP string, remotePort uint16) bool {
	classifierInput := ClassifierInput{
		host:       host,
		remoteIP:   remoteIP,
		remotePort: remotePort,
	}

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

	if p.blocklistClassifier != nil {
		isBlocked, err := p.blocklistClassifier.Classify(classifierInput)
		if err != nil {
			logger.Error("Blocklist classifier error: %v", err)
		} else if isBlocked {
			logger.Debug("Host %s is blocked by blocklist", host)
			return false
		}
	}

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

func (p *Proxy) Stop() error {
	var lastErr error

	for _, server := range p.servers {
		err := server.Stop()
		if err != nil {
			lastErr = err
			logger.Error("Failed to stop proxy server on %s: %v", server.serverConfig.ListenAddress, err)
		}
	}

	return lastErr
}

func (p *Server) Stop() error {
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

// estimateHTTPRequestHeaderSize calculates the approximate size of HTTP request headers
func estimateHTTPRequestHeaderSize(r *http.Request) int64 {
	if r == nil {
		return 0
	}

	// Start with request line: "METHOD /path HTTP/1.1\r\n"
	requestLine := r.Method + " " + r.URL.RequestURI() + " HTTP/1.1\r\n"
	size := len(requestLine)

	// Add Host header if present
	if r.Host != "" {
		size += len("Host: " + r.Host + "\r\n")
	}

	// Add all other headers
	for name, values := range r.Header {
		for _, value := range values {
			size += len(name + ": " + value + "\r\n")
		}
	}

	// Add final CRLF to end headers
	size += 2 // "\r\n"

	return int64(size)
}

// estimateHTTPResponseHeaderSize calculates the approximate size of HTTP response headers
func estimateHTTPResponseHeaderSize(resp *http.Response) int64 {
	if resp == nil {
		return 0
	}

	// Start with status line: "HTTP/1.1 200 OK\r\n"
	statusLine := resp.Proto + " " + resp.Status + "\r\n"
	size := len(statusLine)

	// Add all headers
	for name, values := range resp.Header {
		for _, value := range values {
			size += len(name + ": " + value + "\r\n")
		}
	}

	// Add final CRLF to end headers
	size += 2 // "\r\n"

	return int64(size)
}
