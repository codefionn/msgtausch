package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPassword = "testpassword"

func TestDecryptPEMKeyComprehensive(t *testing.T) {
	testDataDir := filepath.Join("testdata")

	tests := []struct {
		name        string
		keyFile     string
		password    string
		shouldError bool
		description string
	}{
		{
			name:        "unencrypted_rsa_key",
			keyFile:     "rsa_unencrypted.pem",
			password:    "",
			shouldError: false,
			description: "Unencrypted RSA private key should work without password",
		},
		{
			name:        "unencrypted_rsa_key_with_password",
			keyFile:     "rsa_unencrypted.pem",
			password:    testPassword,
			shouldError: false,
			description: "Unencrypted RSA private key should work even with password provided",
		},
		{
			name:        "aes128_encrypted_ec_key",
			keyFile:     "ec_aes128.pem",
			password:    testPassword,
			shouldError: false,
			description: "AES-128-CBC encrypted EC private key should decrypt successfully",
		},
		{
			name:        "aes128_encrypted_ec_key_wrong_password",
			keyFile:     "ec_aes128.pem",
			password:    "wrongpassword",
			shouldError: true,
			description: "AES-128-CBC encrypted EC private key should fail with wrong password",
		},
		{
			name:        "aes128_encrypted_ec_key_no_password",
			keyFile:     "ec_aes128.pem",
			password:    "",
			shouldError: false, // Should return encrypted key as-is
			description: "AES-128-CBC encrypted EC private key without password should return encrypted key",
		},
		{
			name:        "aes256_encrypted_rsa_legacy",
			keyFile:     "rsa_aes256_legacy.pem",
			password:    testPassword,
			shouldError: false,
			description: "Legacy AES-256-CBC encrypted RSA private key should decrypt successfully",
		},
		{
			name:        "aes256_encrypted_rsa_legacy_wrong_password",
			keyFile:     "rsa_aes256_legacy.pem",
			password:    "wrongpassword",
			shouldError: true,
			description: "Legacy AES-256-CBC encrypted RSA private key should fail with wrong password",
		},
		{
			name:        "pkcs8_encrypted_rsa",
			keyFile:     "rsa_aes256.pem",
			password:    testPassword,
			shouldError: false,
			description: "PKCS#8 encrypted RSA private key should decrypt successfully",
		},
		{
			name:        "pkcs8_encrypted_rsa_wrong_password",
			keyFile:     "rsa_aes256.pem",
			password:    "wrongpassword",
			shouldError: true,
			description: "PKCS#8 encrypted RSA private key should fail with wrong password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(testDataDir, tt.keyFile)

			// Check if the key file exists
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				t.Skipf("Test key file %s does not exist", keyPath)
				return
			}

			// Read the key file
			keyPEM, err := os.ReadFile(keyPath)
			require.NoError(t, err, "Failed to read key file: %s", keyPath)

			// Test the decryption
			decryptedPEM, err := decryptPEMKey(keyPEM, tt.password)

			if tt.shouldError {
				assert.Error(t, err, "Expected error for %s", tt.description)
				return
			}

			assert.NoError(t, err, "Unexpected error for %s: %v", tt.description, err)
			assert.NotEmpty(t, decryptedPEM, "Decrypted PEM should not be empty for %s", tt.description)

			// If we provided a password and the key was encrypted, verify it's now unencrypted
			if tt.password != "" && isEncryptedPEM(keyPEM) {
				// Parse the decrypted PEM to ensure it's valid
				block, _ := pem.Decode(decryptedPEM)
				require.NotNil(t, block, "Failed to decode decrypted PEM for %s", tt.description)

				// The decrypted key should not have encryption headers
				assert.Empty(t, block.Headers["Proc-Type"], "Decrypted PEM should not have Proc-Type header")
				assert.Empty(t, block.Headers["DEK-Info"], "Decrypted PEM should not have DEK-Info header")

				// Try to parse the private key to ensure it's valid
				switch block.Type {
				case "PRIVATE KEY":
					// PKCS#8 format
					_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
					assert.NoError(t, err, "Failed to parse decrypted PKCS#8 private key for %s", tt.description)
				case "RSA PRIVATE KEY":
					// PKCS#1 RSA format
					_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
					assert.NoError(t, err, "Failed to parse decrypted RSA private key for %s", tt.description)
				case "EC PRIVATE KEY":
					// EC format
					_, err := x509.ParseECPrivateKey(block.Bytes)
					assert.NoError(t, err, "Failed to parse decrypted EC private key for %s", tt.description)
				}
			}
		})
	}
}

func TestDecryptLegacyPEMBlock_UnsupportedAlgorithms(t *testing.T) {
	tests := []struct {
		name        string
		procType    string
		dekInfo     string
		expectedErr string
	}{
		{
			name:        "unsupported_algorithm",
			procType:    "4,ENCRYPTED",
			dekInfo:     "UNSUPPORTED-ALGORITHM,0123456789ABCDEF",
			expectedErr: "unsupported encryption algorithm: UNSUPPORTED-ALGORITHM",
		},
		{
			name:        "invalid_proc_type",
			procType:    "4,PLAIN",
			dekInfo:     "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF",
			expectedErr: "PEM block does not have encrypted proc type",
		},
		{
			name:        "missing_dek_info",
			procType:    "4,ENCRYPTED",
			dekInfo:     "",
			expectedErr: "PEM block does not have DEK-Info header",
		},
		{
			name:        "invalid_dek_info_format",
			procType:    "4,ENCRYPTED",
			dekInfo:     "AES-128-CBC",
			expectedErr: "invalid DEK-Info format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := &pem.Block{
				Type: "RSA PRIVATE KEY",
				Headers: map[string]string{
					"Proc-Type": tt.procType,
				},
				Bytes: []byte("dummy encrypted data"),
			}

			if tt.dekInfo != "" {
				block.Headers["DEK-Info"] = tt.dekInfo
			}

			_, err := decryptLegacyPEMBlock(block, []byte(testPassword))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestDecryptLegacyPEMBlock_InvalidIVLength(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		iv          string
		expectedErr string
	}{
		{
			name:        "aes128_short_iv",
			algorithm:   "AES-128-CBC",
			iv:          "0123456789ABCDEF", // Too short
			expectedErr: "invalid IV length for AES-128-CBC: expected 32, got 16",
		},
		{
			name:        "aes256_short_iv",
			algorithm:   "AES-256-CBC",
			iv:          "0123456789ABCDEF", // Too short
			expectedErr: "invalid IV length for AES-256-CBC: expected 32, got 16",
		},
		{
			name:        "des_short_iv",
			algorithm:   "DES-CBC",
			iv:          "01234567", // Too short
			expectedErr: "invalid IV length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := &pem.Block{
				Type: "RSA PRIVATE KEY",
				Headers: map[string]string{
					"Proc-Type": "4,ENCRYPTED",
					"DEK-Info":  tt.algorithm + "," + tt.iv,
				},
				Bytes: []byte("dummy encrypted data"),
			}

			_, err := decryptLegacyPEMBlock(block, []byte(testPassword))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestIsLegacyEncryptedPEMBlock(t *testing.T) {
	tests := []struct {
		name     string
		block    *pem.Block
		expected bool
	}{
		{
			name: "encrypted_block",
			block: &pem.Block{
				Headers: map[string]string{
					"Proc-Type": "4,ENCRYPTED",
					"DEK-Info":  "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF",
				},
			},
			expected: true,
		},
		{
			name: "unencrypted_block",
			block: &pem.Block{
				Headers: map[string]string{},
			},
			expected: false,
		},
		{
			name: "missing_proc_type",
			block: &pem.Block{
				Headers: map[string]string{
					"DEK-Info": "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF",
				},
			},
			expected: false,
		},
		{
			name: "missing_dek_info",
			block: &pem.Block{
				Headers: map[string]string{
					"Proc-Type": "4,ENCRYPTED",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLegacyEncryptedPEMBlock(tt.block)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// isEncryptedPEM checks if a PEM contains encrypted data
func isEncryptedPEM(pemData []byte) bool {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return false
	}

	// Check for PKCS#8 encrypted format
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return true
	}

	// Check for legacy encrypted format
	return isLegacyEncryptedPEMBlock(block)
}

func BenchmarkDecryptPEMKey(b *testing.B) {
	testDataDir := filepath.Join("testdata")
	keyPath := filepath.Join(testDataDir, "ec_aes128.pem")

	// Check if the key file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		b.Skipf("Test key file %s does not exist", keyPath)
		return
	}

	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decryptPEMKey(keyPEM, testPassword)
		require.NoError(b, err)
	}
}
