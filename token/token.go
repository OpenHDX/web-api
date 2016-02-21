// HDX token
package token

import (
	"strings"

	// Encryption
	"crypto/hmac"
	"crypto/sha256"

	// Encoding
	"encoding/base64"
)

// Token Generator
//
// HDX Token should have this format:
//   clientFingerprint + "." message + "." + signature
// The signature is a encryption of fingerprint + domain + message using SHA256
func New(fingerprint, domain, message, secret string) string {
	// Initialize SHA256 encryption using secret string
	mac := hmac.New(sha256.New, []byte(secret))

	// Write signature
	mac.Write([]byte(fingerprint + domain + message))

	// Return token
	return fingerprint +
		"." + base64.RawURLEncoding.EncodeToString([]byte(message)) +
		"." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Get token message
func Get(fingerprint, domain, token, secret string) string {
	// Check whether token empty
	if "" != token {
		// Split parts
		parts := strings.Split(token, ".")

		// Token parts should be 3 and the first part should equal fingerprint
		if 3 == len(parts) && parts[0] == fingerprint {
			// Get the message
			message, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				// Message can not be decoded, return empty message
				return ""
			}

			// Generate token from fingerprint and message and then validate it
			if validToken := New(fingerprint, domain, string(message), secret); validToken != token {
				// Invalid token, return empty message
				return ""
			}

			// If everything when right, then return message
			return string(message)
		}
	}

	// Invalid token, return empty message
	return ""
}
