package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

var (
	defaultResolver *net.Resolver
	once            sync.Once
)

// GetResolver returns a singleton instance of the net.Resolver.
func GetResolver() *net.Resolver {
	once.Do(func() {
		defaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 10 * time.Second,
				}
				// In the future, we can add logic here to select a DNS server
				// from the configuration. For now, it uses the system's default.
				// Example for custom DNS server:
				// return d.DialContext(ctx, "udp", "1.1.1.1:53")
				conn, err := d.DialContext(ctx, network, address)
				if err != nil {
					logger.Error("DNS dial error: %v", err)
				}
				return conn, err
			},
		}
		logger.Info("Custom DNS resolver initialized.")
	})
	return defaultResolver
}
