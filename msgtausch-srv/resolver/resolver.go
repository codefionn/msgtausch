package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

var (
	customResolver *Resolver
	resolverMutex  sync.RWMutex
	resolverConfig config.DNSConfig
)

// Resolver represents a custom DNS resolver that supports UDP, TCP, and DoT.
type Resolver struct {
	dnsConfig     config.DNSConfig
	currentIdx    int
	mutex         sync.Mutex
	defaultDialer *net.Dialer
	tlsConfig     *tls.Config
}

// NewResolver creates a new Resolver with the given DNS configuration.
func NewResolver(cfg config.DNSConfig) *Resolver {
	return &Resolver{
		dnsConfig: cfg,
		defaultDialer: &net.Dialer{
			Timeout: 10 * time.Second,
		},
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"dot"},
		},
	}
}

// GetResolver returns a net.Resolver instance.
// If custom DNS is configured and enabled, it uses the custom resolver.
// Otherwise, it uses the system's default DNS resolver.
// This function is safe to call multiple times with different configurations.
func GetResolver(dnsConfig config.DNSConfig) *net.Resolver {
	resolverMutex.RLock()
	needsInit := customResolver == nil
	resolverMutex.RUnlock()

	// Check if we need to initialize or reconfigure
	needsReconfig := !needsInit && !configsEqual(resolverConfig, dnsConfig)

	if needsReconfig {
		resolverMutex.Lock()
		// Double-check after acquiring write lock
		if !configsEqual(resolverConfig, dnsConfig) {
			// Reconfigure
			logger.Info("DNS configuration changed, reinitializing resolver")
			resolverConfig = dnsConfig
			if dnsConfig.Enabled && len(dnsConfig.Servers) > 0 {
				customResolver = NewResolver(dnsConfig)
				logger.Info("Custom DNS resolver reinitialized with %d server(s)", len(dnsConfig.Servers))
				for i, server := range dnsConfig.Servers {
					logger.Info("  DNS Server %d: %s (%s)", i, server.Address, server.Type)
				}
			} else {
				customResolver = nil
				logger.Info("Switching to system default DNS resolver")
			}
		}
		resolverMutex.Unlock()
	} else if needsInit {
		resolverMutex.Lock()
		// Double-check after acquiring write lock
		if customResolver == nil {
			resolverConfig = dnsConfig
			if dnsConfig.Enabled && len(dnsConfig.Servers) > 0 {
				customResolver = NewResolver(dnsConfig)
				logger.Info("Custom DNS resolver initialized with %d server(s)", len(dnsConfig.Servers))
				for i, server := range dnsConfig.Servers {
					logger.Info("  DNS Server %d: %s (%s)", i, server.Address, server.Type)
				}
			} else {
				customResolver = nil
				logger.Info("Using system default DNS resolver")
			}
		}
		resolverMutex.Unlock()
	}

	// If custom DNS is configured and enabled, use it
	resolverMutex.RLock()
	if customResolver != nil {
		resolverMutex.RUnlock()
		return &net.Resolver{
			PreferGo: true,
			Dial:     customResolver.Dial,
		}
	}
	resolverMutex.RUnlock()

	// Otherwise use system default
	return &net.Resolver{
		PreferGo: true,
	}
}

// configsEqual checks if two DNSConfig are equivalent
func configsEqual(a, b config.DNSConfig) bool {
	if a.Enabled != b.Enabled {
		return false
	}
	if len(a.Servers) != len(b.Servers) {
		return false
	}
	for i := range a.Servers {
		if a.Servers[i].Address != b.Servers[i].Address ||
			a.Servers[i].Type != b.Servers[i].Type ||
			a.Servers[i].TimeoutSeconds != b.Servers[i].TimeoutSeconds ||
			a.Servers[i].TLSHost != b.Servers[i].TLSHost {
			return false
		}
	}
	return true
}

// Dial is the custom dial function for DNS resolution.
func (r *Resolver) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mutex.Lock()
	serverIdx := r.currentIdx
	r.currentIdx = (r.currentIdx + 1) % len(r.dnsConfig.Servers)
	r.mutex.Unlock()

	dnsServer := r.dnsConfig.Servers[serverIdx]
	logger.Debug("Using DNS server %d: %s (%s)", serverIdx, dnsServer.Address, dnsServer.Type)

	switch dnsServer.Type {
	case config.DNSTypeUDP, config.DNSTypeTCP:
		// For standard DNS (UDP/TCP), dial the specified server
		dialer := &net.Dialer{
			Timeout: dnsServer.GetTimeoutDuration(),
		}
		dialNetwork := string(dnsServer.Type)
		return dialer.DialContext(ctx, dialNetwork, dnsServer.Address)

	case config.DNSTypeDoT:
		// For DNS over TLS, first establish TCP connection then wrap in TLS
		dialer := &net.Dialer{
			Timeout: dnsServer.GetTimeoutDuration(),
		}
		tcpConn, err := dialer.DialContext(ctx, "tcp", dnsServer.Address)
		if err != nil {
			logger.Error("Failed to establish TCP connection to DoT server %s: %v", dnsServer.Address, err)
			return nil, fmt.Errorf("DoT TCP connection failed: %w", err)
		}

		// Create TLS config, using custom ServerName if TLSHost is specified
		tlsConfig := r.tlsConfig.Clone()
		if dnsServer.TLSHost != "" {
			tlsConfig.ServerName = dnsServer.TLSHost
			logger.Debug("Using custom TLS hostname for SNI: %s", dnsServer.TLSHost)
		}

		// Wrap TCP connection in TLS
		tlsConn := tls.Client(tcpConn, tlsConfig)
		// Perform TLS handshake with timeout
		handshakeCtx, cancel := context.WithTimeout(ctx, dnsServer.GetTimeoutDuration())
		defer cancel()
		err = tlsConn.HandshakeContext(handshakeCtx)
		if err != nil {
			tcpConn.Close()
			logger.Error("TLS handshake failed with DoT server %s: %v", dnsServer.Address, err)
			return nil, fmt.Errorf("DoT TLS handshake failed: %w", err)
		}

		logger.Debug("Successfully established DoT connection to %s", dnsServer.Address)
		return tlsConn, nil

	default:
		return nil, fmt.Errorf("unsupported DNS server type: %s", dnsServer.Type)
	}
}
