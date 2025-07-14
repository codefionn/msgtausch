package dashboard

import (
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTSessionManagement(t *testing.T) {
	// Create a portal instance
	portal := &Portal{
		jwtSecret: []byte("test-secret-key"),
	}

	// Test JWT token creation
	username := "testuser"
	token, err := portal.createJWTSession(username)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Test JWT token parsing and validation
	parsedToken, err := portal.parseJWTToken(token)
	require.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	// Verify claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, username, claims["username"])
	assert.NotEmpty(t, claims["exp"])
	assert.NotEmpty(t, claims["iat"])

	// Test expired token
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(-1 * time.Hour).Unix(),
		"iat":      time.Now().Add(-2 * time.Hour).Unix(),
	})
	expiredTokenString, err := expiredToken.SignedString(portal.jwtSecret)
	require.NoError(t, err)

	_, err = portal.parseJWTToken(expiredTokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")

	// Test invalid token
	_, err = portal.parseJWTToken("invalid.token.here")
	assert.Error(t, err)

	// Test token with wrong signature
	wrongSecret := []byte("wrong-secret")
	wrongToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString(wrongSecret)
	require.NoError(t, err)

	_, err = portal.parseJWTToken(wrongToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature is invalid")
}

func TestJWTSecretGeneration(t *testing.T) {
	// Test that each portal gets a unique secret
	mockConfig := &config.Config{
		Statistics: config.StatisticsConfig{
			Enabled: false,
		},
		Portal: config.PortalConfig{},
	}
	portal1 := NewPortal(mockConfig, nil, nil)
	portal2 := NewPortal(mockConfig, nil, nil)

	assert.NotEqual(t, portal1.jwtSecret, portal2.jwtSecret)
	assert.Len(t, portal1.jwtSecret, 32)
	assert.Len(t, portal2.jwtSecret, 32)
}
