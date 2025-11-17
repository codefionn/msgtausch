package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// Error represents a proxy-specific error with a code and description
type Error struct {
	Code        string
	Description string
	Cause       error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Description, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Description)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

// NewProxyError creates a new Error with the given code and description
func NewProxyError(code, description string, cause error) *Error {
	return &Error{
		Code:        code,
		Description: description,
		Cause:       cause,
	}
}

// Proxy Error Codes
const (
	// Configuration and Initialization Errors (E1000-E1999)
	ErrCodeNoEnabledServers      = "E1001"
	ErrCodeInvalidCAFile         = "E1002"
	ErrCodeInvalidCAKey          = "E1003"
	ErrCodeCAKeyNotRSA           = "E1004"
	ErrCodeCADecodeFailed        = "E1005"
	ErrCodeCAParseFailed         = "E1006"
	ErrCodeUnknownProxyType      = "E1007"
	ErrCodeListenerCreateFailed  = "E1008"
	ErrCodeInterceptorInitFailed = "E1009"
	ErrCodeInvalidServerConfig   = "E1010"

	// Connection and Network Errors (E2000-E2999)
	ErrCodeConnectionFailed      = "E2001"
	ErrCodeConnectionTimeout     = "E2002"
	ErrCodeConnectionRefused     = "E2003"
	ErrCodeHostUnreachable       = "E2004"
	ErrCodeNetworkUnreachable    = "E2005"
	ErrCodeInvalidAddress        = "E2006"
	ErrCodeInvalidPort           = "E2007"
	ErrCodeConnectionClosed      = "E2008"
	ErrCodeDialFailed            = "E2009"
	ErrCodeUpstreamConnectFailed = "E2010"

	// TLS and Certificate Errors (E3000-E3999)
	ErrCodeTLSHandshakeFailed   = "E3001"
	ErrCodeCertGenerationFailed = "E3002"
	ErrCodeCertCacheFailed      = "E3003"
	ErrCodeNoSNIHostname        = "E3004"
	ErrCodePrivateKeyGenFailed  = "E3005"
	ErrCodeX509KeyPairFailed    = "E3006"
	ErrCodeTLSUpstreamFailed    = "E3007"
	ErrCodeCertValidationFailed = "E3008"

	// HTTP/HTTPS Processing Errors (E4000-E4999)
	ErrCodeHTTPRequestReadFailed   = "E4001"
	ErrCodeHTTPResponseReadFailed  = "E4002"
	ErrCodeHTTPRequestWriteFailed  = "E4003"
	ErrCodeHTTPResponseWriteFailed = "E4004"
	ErrCodeHTTPBodyReadFailed      = "E4005"
	ErrCodeHTTPBodyWriteFailed     = "E4006"
	ErrCodeHTTPForwardFailed       = "E4007"
	ErrCodeHTTPHijackFailed        = "E4008"
	ErrCodeHTTPHijackNotSupported  = "E4009"
	ErrCodeHTTPClientNotFound      = "E4010"
	ErrCodeHTTPUpgradeFailed       = "E4011"

	// WebSocket Errors (E5000-E5999)
	ErrCodeWebSocketUpgradeFailed = "E5001"
	ErrCodeWebSocketReadFailed    = "E5002"
	ErrCodeWebSocketWriteFailed   = "E5003"
	ErrCodeWebSocketClientError   = "E5004"
	ErrCodeWebSocketUpstreamError = "E5005"
	ErrCodeWebSocketTunnelFailed  = "E5006"

	// Proxy Chain and Forwarding Errors (E6000-E6999)
	ErrCodeSOCKS5DialerFailed     = "E6001"
	ErrCodeSOCKS5ConnectFailed    = "E6002"
	ErrCodeHTTPProxyDialFailed    = "E6003"
	ErrCodeHTTPProxyConnectFailed = "E6004"
	ErrCodeCONNECTRequestFailed   = "E6005"
	ErrCodeCONNECTResponseFailed  = "E6006"
	ErrCodeProxyAuthFailed        = "E6007"
	ErrCodeProxyDenied            = "E6008"
	ErrCodeForwardRuleError       = "E6009"

	// Access Control and Security Errors (E7000-E7999)
	ErrCodeHostNotAllowed          = "E7001"
	ErrCodeBlocklistMatch          = "E7002"
	ErrCodeAllowlistMismatch       = "E7003"
	ErrCodeClassifierError         = "E7004"
	ErrCodeAuthenticationFailed    = "E7005"
	ErrCodeAuthorizationFailed     = "E7006"
	ErrCodeSecurityPolicyViolation = "E7007"

	// Interception and Modification Errors (E8000-E8999)
	ErrCodeInterceptionDisabled    = "E8001"
	ErrCodeRequestHookFailed       = "E8002"
	ErrCodeResponseHookFailed      = "E8003"
	ErrCodeInterceptorNotFound     = "E8004"
	ErrCodeInterceptionSetupFailed = "E8005"
	ErrCodeRequestModifyFailed     = "E8006"
	ErrCodeResponseModifyFailed    = "E8007"

	// Resource and Limit Errors (E9000-E9999)
	ErrCodeMemoryLimitExceeded     = "E9002"
	ErrCodeTimeoutExceeded         = "E9003"
	ErrCodeBufferOverflow          = "E9004"
	ErrCodeResourceExhausted       = "E9005"
	ErrCodeConcurrencyLimitReached = "E9006"

	// Internal and System Errors (E9900-E9999)
	ErrCodeInternalError      = "E9901"
	ErrCodeUnexpectedError    = "E9902"
	ErrCodePanicRecovered     = "E9903"
	ErrCodeSystemError        = "E9904"
	ErrCodeConfigurationError = "E9905"
)

// ErrorDescriptions maps error codes to human-readable descriptions.
var ErrorDescriptions = map[string]string{
	// Configuration and Initialization Errors
	ErrCodeNoEnabledServers:      "No enabled proxy servers configured",
	ErrCodeInvalidCAFile:         "Invalid or unreadable CA certificate file",
	ErrCodeInvalidCAKey:          "Invalid or unreadable CA private key file",
	ErrCodeCAKeyNotRSA:           "CA private key is not an RSA key",
	ErrCodeCADecodeFailed:        "Failed to decode CA certificate or key PEM",
	ErrCodeCAParseFailed:         "Failed to parse CA certificate or key",
	ErrCodeUnknownProxyType:      "Unknown or unsupported proxy type",
	ErrCodeListenerCreateFailed:  "Failed to create network listener",
	ErrCodeInterceptorInitFailed: "Failed to initialize traffic interceptor",
	ErrCodeInvalidServerConfig:   "Invalid server configuration",

	// Connection and Network Errors
	ErrCodeConnectionFailed:      "Failed to establish network connection",
	ErrCodeConnectionTimeout:     "Connection attempt timed out",
	ErrCodeConnectionRefused:     "Connection refused by target server",
	ErrCodeHostUnreachable:       "Target host is unreachable",
	ErrCodeNetworkUnreachable:    "Target network is unreachable",
	ErrCodeInvalidAddress:        "Invalid network address format",
	ErrCodeInvalidPort:           "Invalid port number",
	ErrCodeConnectionClosed:      "Connection closed unexpectedly",
	ErrCodeDialFailed:            "Failed to dial target address",
	ErrCodeUpstreamConnectFailed: "Failed to connect to upstream server",

	// TLS and Certificate Errors
	ErrCodeTLSHandshakeFailed:   "TLS handshake failed",
	ErrCodeCertGenerationFailed: "Failed to generate SSL certificate",
	ErrCodeCertCacheFailed:      "Failed to cache SSL certificate",
	ErrCodeNoSNIHostname:        "No SNI hostname provided in TLS handshake",
	ErrCodePrivateKeyGenFailed:  "Failed to generate private key",
	ErrCodeX509KeyPairFailed:    "Failed to create X.509 key pair",
	ErrCodeTLSUpstreamFailed:    "TLS handshake with upstream server failed",
	ErrCodeCertValidationFailed: "Certificate validation failed",

	// HTTP/HTTPS Processing Errors
	ErrCodeHTTPRequestReadFailed:   "Failed to read HTTP request",
	ErrCodeHTTPResponseReadFailed:  "Failed to read HTTP response",
	ErrCodeHTTPRequestWriteFailed:  "Failed to write HTTP request",
	ErrCodeHTTPResponseWriteFailed: "Failed to write HTTP response",
	ErrCodeHTTPBodyReadFailed:      "Failed to read HTTP message body",
	ErrCodeHTTPBodyWriteFailed:     "Failed to write HTTP message body",
	ErrCodeHTTPForwardFailed:       "Failed to forward HTTP request",
	ErrCodeHTTPHijackFailed:        "Failed to hijack HTTP connection",
	ErrCodeHTTPHijackNotSupported:  "HTTP connection hijacking not supported",
	ErrCodeHTTPClientNotFound:      "HTTP client not found in request context",
	ErrCodeHTTPUpgradeFailed:       "HTTP protocol upgrade failed",

	// WebSocket Errors
	ErrCodeWebSocketUpgradeFailed: "WebSocket protocol upgrade failed",
	ErrCodeWebSocketReadFailed:    "Failed to read WebSocket message",
	ErrCodeWebSocketWriteFailed:   "Failed to write WebSocket message",
	ErrCodeWebSocketClientError:   "WebSocket client connection error",
	ErrCodeWebSocketUpstreamError: "WebSocket upstream connection error",
	ErrCodeWebSocketTunnelFailed:  "WebSocket tunnel establishment failed",

	// Proxy Chain and Forwarding Errors
	ErrCodeSOCKS5DialerFailed:     "Failed to create SOCKS5 dialer",
	ErrCodeSOCKS5ConnectFailed:    "SOCKS5 connection failed",
	ErrCodeHTTPProxyDialFailed:    "Failed to dial HTTP proxy server",
	ErrCodeHTTPProxyConnectFailed: "HTTP proxy connection failed",
	ErrCodeCONNECTRequestFailed:   "Failed to send CONNECT request",
	ErrCodeCONNECTResponseFailed:  "Failed to read CONNECT response",
	ErrCodeProxyAuthFailed:        "Proxy authentication failed",
	ErrCodeProxyDenied:            "Proxy request denied",
	ErrCodeForwardRuleError:       "Error in forwarding rule evaluation",

	// Access Control and Security Errors
	ErrCodeHostNotAllowed:          "Host access denied by policy",
	ErrCodeBlocklistMatch:          "Host matches blocklist entry",
	ErrCodeAllowlistMismatch:       "Host not found in allowlist",
	ErrCodeClassifierError:         "Error in access control classifier",
	ErrCodeAuthenticationFailed:    "Authentication failed",
	ErrCodeAuthorizationFailed:     "Authorization failed",
	ErrCodeSecurityPolicyViolation: "Security policy violation",

	// Interception and Modification Errors
	ErrCodeInterceptionDisabled:    "Traffic interception is disabled",
	ErrCodeRequestHookFailed:       "Request modification hook failed",
	ErrCodeResponseHookFailed:      "Response modification hook failed",
	ErrCodeInterceptorNotFound:     "Traffic interceptor not found",
	ErrCodeInterceptionSetupFailed: "Failed to setup traffic interception",
	ErrCodeRequestModifyFailed:     "Failed to modify request",
	ErrCodeResponseModifyFailed:    "Failed to modify response",

	// Resource and Limit Errors
	ErrCodeMemoryLimitExceeded:     "Memory limit exceeded",
	ErrCodeTimeoutExceeded:         "Operation timeout exceeded",
	ErrCodeBufferOverflow:          "Buffer overflow detected",
	ErrCodeResourceExhausted:       "System resources exhausted",
	ErrCodeConcurrencyLimitReached: "Concurrency limit reached",

	// Internal and System Errors
	ErrCodeInternalError:      "Internal proxy error",
	ErrCodeUnexpectedError:    "Unexpected error occurred",
	ErrCodePanicRecovered:     "Recovered from panic condition",
	ErrCodeSystemError:        "System-level error",
	ErrCodeConfigurationError: "Configuration error",
}

// Helper functions to create common errors

// NewConfigurationError creates a configuration-related error
func NewConfigurationError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewConnectionError creates a connection-related error
func NewConnectionError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewTLSError creates a TLS-related error
func NewTLSError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewHTTPError creates an HTTP-related error
func NewHTTPError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewWebSocketError creates a WebSocket-related error
func NewWebSocketError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewProxyChainError creates a proxy chain-related error
func NewProxyChainError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewAccessControlError creates an access control-related error
func NewAccessControlError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewInterceptionError creates an interception-related error
func NewInterceptionError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewResourceError creates a resource-related error
func NewResourceError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// NewInternalError creates an internal error
func NewInternalError(code, description string, cause error) *Error {
	return NewProxyError(code, description, cause)
}

// GetErrorDescription returns the description for a given error code
func GetErrorDescription(code string) string {
	if desc, exists := ErrorDescriptions[code]; exists {
		return desc
	}
	return "Unknown error code"
}

// IsConnectionError checks if the error is connection-related
func IsConnectionError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E2000" && proxyErr.Code < "E3000"
	}
	return false
}

// NewBadGatewayResponse creates an HTTP 502 Bad Gateway response from an error code.
// It populates the response body with the error code and its description in HTML format.
func NewBadGatewayResponse(errorCode string) *http.Response {
	description := GetErrorDescription(errorCode)
	title := "502 Bad Gateway"
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f4; color: #333; }
        .container { background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #d9534f; }
        p { font-size: 1.1em; }
        .error-code { font-weight: bold; color: #c9302c; }
    </style>
</head>
<body>
    <div class="container">
        <h1>%s</h1>
        <p>The server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed in attempting to fulfill the request.</p>
        <p><span class="error-code">Error Code:</span> %s</p>
        <p><span class="error-code">Description:</span> %s</p>
    </div>
</body>
</html>`, title, title, errorCode, description)

	bodyBytes := []byte(htmlBody)

	header := make(http.Header)
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	header.Set("X-Proxy-Error", errorCode)

	return &http.Response{
		Status:        fmt.Sprintf("%d %s", http.StatusBadGateway, http.StatusText(http.StatusBadGateway)),
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(bodyBytes)),
		ContentLength: int64(len(bodyBytes)),
	}
}

// IsTLSError checks if the error is TLS-related
func IsTLSError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E3000" && proxyErr.Code < "E4000"
	}
	return false
}

// IsHTTPError checks if the error is HTTP-related
func IsHTTPError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E4000" && proxyErr.Code < "E6000"
	}
	return false
}

// IsWebSocketError checks if the error is WebSocket-related
func IsWebSocketError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E5000" && proxyErr.Code < "E6000"
	}
	return false
}

// IsProxyChainError checks if the error is proxy chain-related
func IsProxyChainError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E6000" && proxyErr.Code < "E7000"
	}
	return false
}

// IsAccessControlError checks if the error is access control-related
func IsAccessControlError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E7000" && proxyErr.Code < "E8000"
	}
	return false
}

// IsInterceptionError checks if the error is interception-related
func IsInterceptionError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E8000" && proxyErr.Code < "E9000"
	}
	return false
}

// IsResourceError checks if the error is resource-related
func IsResourceError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E9000" && proxyErr.Code < "E9900"
	}
	return false
}

// IsInternalError checks if the error is internal/system-related
func IsInternalError(err error) bool {
	if proxyErr, ok := err.(*Error); ok {
		return proxyErr.Code >= "E9900"
	}
	return false
}
