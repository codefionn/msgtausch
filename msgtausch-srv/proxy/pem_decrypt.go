package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // nolint:gosec // Legacy PEM decryption for backward compatibility
	"crypto/md5" // nolint:gosec // Legacy PEM decryption for backward compatibility
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	pkcs8 "github.com/youmark/pkcs8"
)

// isLegacyEncryptedPEMBlock checks if a PEM block is encrypted using legacy RFC 1423 encryption
func isLegacyEncryptedPEMBlock(block *pem.Block) bool {
	_, hasInfo := block.Headers["Proc-Type"]
	_, hasKey := block.Headers["DEK-Info"]
	return hasInfo && hasKey
}

// decryptLegacyPEMBlock decrypts a legacy encrypted PEM block (RFC 1423)
// WARNING: This is insecure and only provided for backward compatibility
func decryptLegacyPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
	procType, ok := block.Headers["Proc-Type"]
	if !ok || procType != "4,ENCRYPTED" {
		return nil, errors.New("PEM block does not have encrypted proc type")
	}

	dekInfo, ok := block.Headers["DEK-Info"]
	if !ok {
		return nil, errors.New("PEM block does not have DEK-Info header")
	}

	// Parse DEK-Info header (e.g., "DES-CBC,IV")
	parts := strings.Split(dekInfo, ",")
	if len(parts) != 2 {
		return nil, errors.New("invalid DEK-Info format")
	}

	alg := parts[0]

	// Handle various AES algorithms
	if strings.HasPrefix(alg, "AES-") && strings.HasSuffix(alg, "-CBC") {
		var keySize int
		var expectedIVLen int
		switch alg {
		case "AES-128-CBC":
			keySize = 16       // 128 bits = 16 bytes
			expectedIVLen = 32 // 16 bytes = 32 hex chars
		case "AES-192-CBC":
			keySize = 24       // 192 bits = 24 bytes
			expectedIVLen = 32 // 16 bytes = 32 hex chars
		case "AES-256-CBC":
			keySize = 32       // 256 bits = 32 bytes
			expectedIVLen = 32 // 16 bytes = 32 hex chars
		default:
			return nil, fmt.Errorf("unsupported AES algorithm: %s", alg)
		}

		iv := make([]byte, aes.BlockSize)
		if len(parts[1]) != expectedIVLen {
			return nil, fmt.Errorf("invalid IV length for %s: expected %d, got %d", alg, expectedIVLen, len(parts[1]))
		}
		for i := 0; i < expectedIVLen; i += 2 {
			var b byte
			_, err := fmt.Sscanf(parts[1][i:i+2], "%02x", &b)
			if err != nil {
				return nil, fmt.Errorf("invalid IV hex: %w", err)
			}
			iv[i/2] = b
		}

		// Derive key using EVP_BytesToKey method (legacy OpenSSL method)
		// This is the algorithm used by OpenSSL for legacy PEM encryption
		key := make([]byte, keySize)
		d := []byte{}
		for len(d) < keySize {
			h := md5.New() // nolint:gosec // Legacy PEM decryption for backward compatibility
			if len(d) > 0 {
				h.Write(d)
			}
			h.Write(password)
			h.Write(iv[:8]) // Only use first 8 bytes of IV (salt)
			d = h.Sum(d)
		}
		copy(key, d[:keySize])

		blockCipher, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}

		// Decrypt using CBC mode
		if len(block.Bytes)%aes.BlockSize != 0 {
			return nil, errors.New("ciphertext is not a multiple of the block size")
		}
		decrypted := make([]byte, len(block.Bytes))
		cbc := cipher.NewCBCDecrypter(blockCipher, iv)
		cbc.CryptBlocks(decrypted, block.Bytes)

		if len(decrypted) == 0 {
			return nil, errors.New("decryption produced empty plaintext")
		}

		// Remove PKCS#5 padding
		padLen := int(decrypted[len(decrypted)-1])
		if padLen > aes.BlockSize || padLen == 0 {
			return nil, errors.New("invalid padding")
		}
		for i := len(decrypted) - padLen; i < len(decrypted); i++ {
			if decrypted[i] != byte(padLen) {
				return nil, errors.New("invalid padding")
			}
		}

		return decrypted[:len(decrypted)-padLen], nil
	}

	if alg != "DES-CBC" {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}

	// Original DES-CBC implementation (keep as-is for backward compatibility)
	// Decode IV from hex
	iv := make([]byte, des.BlockSize)
	if len(parts[1]) != 16 {
		return nil, errors.New("invalid IV length")
	}
	for i := 0; i < 16; i += 2 {
		var b byte
		_, err := fmt.Sscanf(parts[1][i:i+2], "%02x", &b)
		if err != nil {
			return nil, fmt.Errorf("invalid IV hex: %w", err)
		}
		iv[i/2] = b
	}

	// Derive key using EVP_BytesToKey method (legacy OpenSSL method)
	key := make([]byte, 8) // DES key is 8 bytes
	h := md5.New()         // nolint:gosec // Legacy PEM decryption for backward compatibility
	h.Write(password)
	h.Write(iv) // For DES, use the full IV as salt
	copy(key, h.Sum(nil))

	// Decrypt using DES-CBC (legacy PEM encryption)
	blockCipher, err := des.NewCipher(key) // nolint:gosec // Legacy PEM decryption for backward compatibility
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher: %w", err)
	}

	if len(block.Bytes)%des.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	decrypted := make([]byte, len(block.Bytes))
	cbc := cipher.NewCBCDecrypter(blockCipher, iv)
	cbc.CryptBlocks(decrypted, block.Bytes)

	if len(decrypted) == 0 {
		return nil, errors.New("decryption produced empty plaintext")
	}

	// Remove PKCS#5/PKCS#7 padding
	padLen := int(decrypted[len(decrypted)-1])
	if padLen == 0 || padLen > des.BlockSize || padLen > len(decrypted) {
		return nil, errors.New("invalid padding")
	}
	for i := len(decrypted) - padLen; i < len(decrypted); i++ {
		if decrypted[i] != byte(padLen) {
			return nil, errors.New("invalid padding")
		}
	}

	return decrypted[:len(decrypted)-padLen], nil
}

// decryptPEMKey decrypts a password-protected PEM private key.
// If password is empty, it assumes the key is not encrypted and returns the original PEM data.
func decryptPEMKey(keyPEM []byte, password string) ([]byte, error) {
	if password == "" {
		// No password provided, assume key is not encrypted
		return keyPEM, nil
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Support for PKCS#8 encrypted private keys: "BEGIN ENCRYPTED PRIVATE KEY"
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		// Use PKCS#8 decryption with the provided password
		key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt PKCS#8 encrypted private key: %w", err)
		}

		logger.Debug("Successfully decrypted PKCS#8 encrypted private key")

		// Re-encode as unencrypted PKCS#8 (PRIVATE KEY) so downstream parsing works
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal decrypted private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}

	// Check if the key is encrypted using legacy RFC 1423 method
	if !isLegacyEncryptedPEMBlock(block) {
		// Key is not encrypted, return original PEM
		return keyPEM, nil
	}

	// Decrypt the PEM block using legacy method (INSECURE - for backward compatibility only)
	decryptedBytes, err := decryptLegacyPEMBlock(block, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt legacy PEM block: %w", err)
	}

	logger.Debug("Successfully decrypted legacy encrypted PEM private key")

	// Re-encode as unencrypted PEM
	decryptedBlock := &pem.Block{
		Type:  block.Type,
		Bytes: decryptedBytes,
	}

	return pem.EncodeToMemory(decryptedBlock), nil
}
