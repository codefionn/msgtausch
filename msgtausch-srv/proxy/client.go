package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"golang.org/x/net/proxy"
)

// createForwardTCPClient establishes a TCP connection to the target address,
// applying forwarding rules (SOCKS5, HTTP Proxy) if configured and matched.
// It returns the established connection or an error (which will be a *Error on failure).
func (p *Proxy) createForwardTCPClient(ctx context.Context, addr string) (net.Conn, error) {
	targetHostname := strings.Split(addr, ":")[0]

	var targetConn net.Conn
	var err error

	var selectedForward config.Forward = nil // Track the selected forward rule

	// 1. Iterate through precompiled forwards and evaluate classifiers
	for _, cf := range p.compiledForwards {
		matched, evalErr := cf.classifier.Classify(ClassifierInput{host: targetHostname})
		if evalErr != nil {
			// Log and potentially return a specific error for classifier failure
			logger.Error("Error evaluating classifier for forward type %T: %v", cf.fwd, evalErr)
			// For now, continue, but this could be a point to return ErrCodeForwardRuleError
			continue // Or return immediately: return nil, err
		}
		if matched {
			logger.Debug("Matched forward rule type %T for %s", cf.fwd, addr)
			selectedForward = cf.fwd
			break
		}
	}
	// If a classifier evaluation resulted in an error and we decided to continue,
	// 'err' might be non-nil here. We should decide if this error is terminal.
	// For now, assuming we proceed if no rule matched or if a rule matched despite a prior classifier error.

	// 2. Establish connection based on selected forward (or default)
	dialerCtx := &net.Dialer{
		Timeout: time.Duration(p.config.TimeoutSeconds) * time.Second,
	}

	if selectedForward != nil {
		switch fwd := selectedForward.(type) {
		case *config.ForwardDefaultNetwork:
			logger.Debug("Using default network forward for %s", addr)
			targetConn, err = dialerCtx.DialContext(ctx, "tcp", addr)
			if err != nil {
				err = NewConnectionError(ErrCodeDialFailed, GetErrorDescription(ErrCodeDialFailed), fmt.Errorf("default network dial to %s: %w", addr, err))
			}
		case *config.ForwardSocks5:
			logger.Debug("Using SOCKS5 forward (%s) for %s", fwd.Address, addr)
			targetConn, err = p.dialSocks5(ctx, dialerCtx, fwd, addr) // dialSocks5 returns *Error or standard error
		case *config.ForwardProxy:
			logger.Debug("Using Proxy forward (%s) for %s", fwd.Address, addr)
			targetConn, err = p.dialHttpProxy(ctx, dialerCtx, fwd, addr) // dialHttpProxy returns *Error or standard error
		default:
			logger.Error("Unknown forward type selected: %T", selectedForward)
			err = NewInternalError(ErrCodeUnknownProxyType, fmt.Sprintf("unknown forward type %T selected for %s", selectedForward, addr), nil)
		}
	} else {
		// Default: Direct connection if no forward rule matched
		logger.Debug("No matching forward rule, using direct connection for %s", addr)
		targetConn, err = dialerCtx.DialContext(ctx, "tcp", addr)
		if err != nil {
			err = NewConnectionError(ErrCodeDialFailed, GetErrorDescription(ErrCodeDialFailed), fmt.Errorf("direct dial to %s: %w", addr, err))
		}
	}

	// Handle connection errors
	if err != nil {
		// The error from Dial, dialSocks5, or dialHttpProxy is already a *Error or a wrapped standard error.
		// Logging it here will include the specific error code if it's a Error.
		logger.Error("Failed to establish connection to target %s (via %T): %v", addr, selectedForward, err)
		return nil, err // Return the original error, which might be a *Error
	}

	// 3. Connection established, proceed with TCP tunnel
	logger.Debug("Successfully established connection to %s (via %T)", addr, selectedForward)
	return targetConn, nil
}

// dialSocks5 establishes a connection to the target via a SOCKS5 proxy
func (p *Proxy) dialSocks5(ctx context.Context, dialerCtx *net.Dialer, fwd *config.ForwardSocks5, targetHostPort string) (net.Conn, error) {
	var auth *proxy.Auth = nil
	if fwd.Username != nil && fwd.Password != nil {
		auth = &proxy.Auth{
			User:     *fwd.Username,
			Password: *fwd.Password,
		}
	} else if fwd.Username != nil {
		// Password might be optional depending on SOCKS server config
		auth = &proxy.Auth{User: *fwd.Username}
	}

	// Create a context-aware dialer for SOCKS5
	contextDialer := &net.Dialer{
		Timeout:   dialerCtx.Timeout,
		KeepAlive: dialerCtx.KeepAlive,
	}

	socksDialer, err := proxy.SOCKS5("tcp", fwd.Address, auth, contextDialer)
	if err != nil {
		return nil, NewProxyChainError(ErrCodeSOCKS5DialerFailed, GetErrorDescription(ErrCodeSOCKS5DialerFailed), fmt.Errorf("proxy %s: %w", fwd.Address, err))
	}

	// Use a channel to handle the connection with proper context cancellation
	type result struct {
		conn net.Conn
		err  error
	}

	resultChan := make(chan result, 1)

	go func() {
		// Try DialContext first if available
		type contextDialer interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		}

		var conn net.Conn
		var err error

		if ctxDialer, ok := socksDialer.(contextDialer); ok {
			conn, err = ctxDialer.DialContext(ctx, "tcp", targetHostPort)
		} else {
			// Fallback to regular Dial
			conn, err = socksDialer.Dial("tcp", targetHostPort)
		}

		resultChan <- result{conn: conn, err: err}
	}()

	// Wait for either the connection to complete or context cancellation
	select {
	case res := <-resultChan:
		if res.err != nil {
			return nil, NewProxyChainError(ErrCodeSOCKS5ConnectFailed, GetErrorDescription(ErrCodeSOCKS5ConnectFailed), fmt.Errorf("target %s via SOCKS5 proxy %s: %w", targetHostPort, fwd.Address, res.err))
		}
		return res.conn, nil
	case <-ctx.Done():
		// Context was cancelled - the goroutine will eventually finish but the connection will be cleaned up
		return nil, NewProxyChainError(ErrCodeSOCKS5ConnectFailed, GetErrorDescription(ErrCodeSOCKS5ConnectFailed), fmt.Errorf("target %s via SOCKS5 proxy %s: %w", targetHostPort, fwd.Address, ctx.Err()))
	}
}

// dialHttpProxy establishes a connection to the target via an HTTP/S proxy using CONNECT
func (p *Proxy) dialHttpProxy(ctx context.Context, dialerCtx *net.Dialer, fwd *config.ForwardProxy, targetHostPort string) (net.Conn, error) {
	logger.Debug("Dialing HTTP proxy %s to reach %s", fwd.Address, targetHostPort)

	// 1. Dial the proxy server itself
	proxyConn, err := dialerCtx.DialContext(ctx, "tcp", fwd.Address)
	if err != nil {
		return nil, NewProxyChainError(ErrCodeHTTPProxyDialFailed, GetErrorDescription(ErrCodeHTTPProxyDialFailed), fmt.Errorf("proxy server %s: %w", fwd.Address, err))
	}

	// 2. Send a CONNECT request to the proxy
	connectReq, err := http.NewRequest("CONNECT", "http://"+targetHostPort, http.NoBody) // URL is dummy for CONNECT
	if err != nil {
		proxyConn.Close()
		return nil, NewProxyChainError(ErrCodeCONNECTRequestFailed, GetErrorDescription(ErrCodeCONNECTRequestFailed), fmt.Errorf("creating for target %s: %w", targetHostPort, err))
	}
	connectReq.Host = targetHostPort                           // Set the Host header correctly
	connectReq.Header.Set("User-Agent", "msgtausch-proxy/1.0") // Optional: Identify our client
	connectReq.Header.Set("Proxy-Connection", "keep-alive")    // Hint for proxy

	// 3. Add Proxy-Authorization header if credentials are provided
	if fwd.Username != nil && fwd.Password != nil {
		proxyAuth := *fwd.Username + ":" + *fwd.Password
		authEncoded := base64.StdEncoding.EncodeToString([]byte(proxyAuth))
		connectReq.Header.Set("Proxy-Authorization", "Basic "+authEncoded)
		logger.Debug("Added Proxy-Authorization header for user %s", *fwd.Username)
	} else if fwd.Username != nil {
		// Handle case where only username might be needed (less common for Basic Auth)
		logger.Warn("Proxy username provided without password for %s", fwd.Address)
		// Depending on proxy config, might still add header or just log
	}

	// Write the CONNECT request to the proxy connection
	err = connectReq.Write(proxyConn)
	if err != nil {
		proxyConn.Close()
		return nil, NewProxyChainError(ErrCodeCONNECTRequestFailed, GetErrorDescription(ErrCodeCONNECTRequestFailed), fmt.Errorf("sending to proxy %s: %w", fwd.Address, err))
	}

	// 4. Read the response from the proxy
	// Use bufio.Reader for easier header parsing
	proxyReader := bufio.NewReader(proxyConn)
	connectResp, err := http.ReadResponse(proxyReader, connectReq)
	if err != nil {
		proxyConn.Close()
		return nil, NewProxyChainError(ErrCodeCONNECTResponseFailed, GetErrorDescription(ErrCodeCONNECTResponseFailed), fmt.Errorf("reading from proxy %s: %w", fwd.Address, err))
	}
	defer connectResp.Body.Close() // Ensure body is closed even if not read

	// 5. Check if the response status is 200 OK
	if connectResp.StatusCode != http.StatusOK {
		proxyConn.Close()
		// Try to read the response body for more error details (optional)
		bodyBytes, _ := io.ReadAll(io.LimitReader(connectResp.Body, 512)) // Limit read size
		errMsg := fmt.Sprintf("proxy %s denied CONNECT to %s with status %s. Body: %s", fwd.Address, targetHostPort, connectResp.Status, string(bodyBytes))
		logger.Error("%s", errMsg) // Log with more context
		return nil, NewProxyChainError(ErrCodeProxyDenied, GetErrorDescription(ErrCodeProxyDenied), fmt.Errorf("%s", errMsg))
	}

	// 6. If status is 200 OK, the connection is now tunneled.
	// The proxyConn is now directly connected to the targetHostPort.
	logger.Debug("CONNECT tunnel established via proxy %s to %s", fwd.Address, targetHostPort)
	return proxyConn, nil

	// Note: We don't need to worry about leftover data in proxyReader because
	// http.ReadResponse consumes only the headers and status line for a successful CONNECT.
	// The proxyConn is now ready for raw TCP tunneling.
}
